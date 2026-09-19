"""Tests for chapter.digest.weekly builder.

Covers:
  * build_digest: aggregates counts + top-N highlights per category
  * window filtering (rows outside [start, end) are excluded)
  * top_n_intents / new_members / federation_changes
    shape + ordering invariants
  * LLM fallback path (no LLM wired → deterministic headline)
  * publish_digest emits chapter.digest.weekly and returns the
    persisted event_id from event_bus.publish

The event_bus is mocked at module-level so tests don't hit Postgres.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

import digest as digest_mod
import event_bus


def _iso(days_ago: float) -> str:
    """ISO-8601 UTC timestamp for ``days_ago`` days before now.

    Returning a relative-to-now timestamp keeps the digest window
    fixtures inside the 7-day window indefinitely — the previous
    hardcoded ``2026-05-08``-style dates aged out of the window and
    spuriously failed the suite after a few days. The very-old
    out-of-window row stays absolute (3 years ago) because the
    invariant we're testing is "well outside any reasonable window";
    relative drift on that row is fine.
    """
    return (datetime.now(UTC) - timedelta(days=days_ago)).isoformat()


@pytest.fixture(autouse=True)
def _reset():
    digest_mod._pg_request = None
    digest_mod._chapter_id = ""
    digest_mod._chapter_name = ""
    digest_mod._llm = None
    event_bus._pg_request = None
    event_bus._chapter_id = ""
    yield
    digest_mod._pg_request = None
    digest_mod._chapter_id = ""
    digest_mod._chapter_name = ""
    digest_mod._llm = None
    event_bus._pg_request = None
    event_bus._chapter_id = ""


def _sample_rows() -> list[dict]:
    """A varied 1-week event_log snapshot the builder will aggregate.

    Six in-window rows spread across the last 5 days; one out-of-window
    row well in the past. Timestamps are relative-to-now so the suite
    keeps passing regardless of when it runs (the old fixture used
    hardcoded ``2026-05-08``-style dates that aged out of the
    seven-day window the digest filters on).
    """
    return [
        {
            "id": 1,
            "event_type": "member.joined",
            "publisher_agent_id": "bayarea-nanda-chapter",
            "payload": {"agent_id": "alice", "name": "Alice", "origin": "sovereign", "skills": ["python"]},
            "created_at": _iso(5),
        },
        {
            "id": 2,
            "event_type": "intent.published",
            "publisher_agent_id": "bayarea-nanda-chapter",
            "payload": {
                "intent_id": "i1",
                "submitter_agent_id": "alice",
                "text": "Looking for a Rust mentor",
                "tags": ["rust", "mentorship"],
            },
            "created_at": _iso(4),
        },
        {
            "id": 3,
            "event_type": "intent.matched",
            "publisher_agent_id": "bayarea-nanda-chapter",
            "payload": {
                "intent_id": "i1",
                "submitter_agent_id": "alice",
                "matched_agent_ids": ["bob"],
                "match_score": 0.82,
            },
            "created_at": _iso(3.9),
        },
        {
            "id": 6,
            "event_type": "federation.peer.online",
            "publisher_agent_id": "bayarea-nanda-chapter",
            "payload": {"peer_chapter_id": "boston-chapter", "peer_endpoint": "https://x", "member_count": 12},
            "created_at": _iso(2.8),
        },
        # Out-of-window row — must NOT appear in the digest aggregates.
        # Three years ago is well outside any reasonable window;
        # absolute timestamp is fine here because the invariant is
        # "outside the window," not "exactly N days ago."
        {
            "id": 7,
            "event_type": "member.joined",
            "publisher_agent_id": "bayarea-nanda-chapter",
            "payload": {"agent_id": "stale", "name": "Stale"},
            "created_at": "2023-01-01T00:00:00+00:00",
        },
    ]


class FakePostgres:
    def __init__(self, *, return_value: Any = None) -> None:
        self.calls: list[tuple] = []
        self._return_value = return_value

    async def __call__(self, method, table, params=None, body=None):
        self.calls.append((method, table, params, body))
        return self._return_value


# ── build_digest ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_build_digest_counts_by_event_type() -> None:
    sb = FakePostgres(return_value=_sample_rows())
    digest_mod.init(sb, "bayarea-nanda-chapter", "Bay Area")

    payload = await digest_mod.build_digest(window_days=7)

    # Only in-window rows should count; the 2025 row is out of window.
    assert payload["new_member_count"] == 1
    assert payload["intent_published_count"] == 1
    assert payload["intent_matched_count"] == 1


@pytest.mark.asyncio
async def test_build_digest_top_intents_shape() -> None:
    sb = FakePostgres(return_value=_sample_rows())
    digest_mod.init(sb, "bayarea-nanda-chapter", "Bay Area")

    payload = await digest_mod.build_digest()
    intents = payload["top_intents"]

    assert len(intents) == 1
    assert intents[0]["intent_id"] == "i1"
    assert intents[0]["submitter"] == "alice"
    assert intents[0]["text"].startswith("Looking for")
    assert intents[0]["tags"] == ["rust", "mentorship"]


@pytest.mark.asyncio
async def test_build_digest_federation_changes_normalised() -> None:
    sb = FakePostgres(return_value=_sample_rows())
    digest_mod.init(sb, "bayarea-nanda-chapter", "Bay Area")

    payload = await digest_mod.build_digest()
    fed = payload["federation_changes"]

    assert len(fed) == 1
    # "federation.peer.online" → just "online" for the digest consumer
    assert fed[0]["type"] == "online"
    assert fed[0]["peer_chapter_id"] == "boston-chapter"


@pytest.mark.asyncio
async def test_build_digest_uses_fallback_when_no_llm() -> None:
    """No LLM wired → deterministic headline (not blank, not error)."""
    sb = FakePostgres(return_value=_sample_rows())
    digest_mod.init(sb, "bayarea-nanda-chapter", "Bay Area")  # llm=None default

    payload = await digest_mod.build_digest()

    assert payload["headline"]
    assert "Bay Area" in payload["headline"]
    assert payload["summary_markdown"]


@pytest.mark.asyncio
async def test_build_digest_empty_window_returns_empty_payload() -> None:
    """No events in the window → counts all zero, headline still composed."""
    sb = FakePostgres(return_value=[])
    digest_mod.init(sb, "bayarea-nanda-chapter", "Bay Area")

    payload = await digest_mod.build_digest()

    assert payload["new_member_count"] == 0
    assert payload["top_intents"] == []
    assert "No standout activity" in payload["summary_markdown"]


# ── publish_digest ───────────────────────────────────────────────────


class FakeEventBusPostgres:
    """Returns a single row with id=999 from POST event_log."""

    async def __call__(self, method, table, params=None, body=None):
        if method == "POST" and table == "event_log":
            return [{**(body or {}), "id": 999}]
        return _sample_rows() if table == "event_log" else None


@pytest.mark.asyncio
async def test_publish_digest_emits_event_and_returns_id() -> None:
    sb = FakeEventBusPostgres()
    digest_mod.init(sb, "bayarea-nanda-chapter", "Bay Area")
    event_bus.init(sb, "bayarea-nanda-chapter")

    event_id = await digest_mod.publish_digest(window_days=7)

    assert event_id == 999


# ── catalog parity (defensive: every payload field is serialisable) ──


@pytest.mark.asyncio
async def test_built_payload_validates_against_pydantic_schema() -> None:
    """The digest builder's output MUST validate against
    ChapterDigestWeeklyPayload — otherwise event_bus.publish would
    reject it at runtime."""
    from event_types import ChapterDigestWeeklyPayload

    sb = FakePostgres(return_value=_sample_rows())
    digest_mod.init(sb, "bayarea-nanda-chapter", "Bay Area")

    payload = await digest_mod.build_digest()
    # Should NOT raise.
    ChapterDigestWeeklyPayload.model_validate(payload)
