"""Tests for event_bus.publish() (EB-2).

publish() is the only sanctioned entry point to the event_log. Wrong
behavior here means events either silently disappear (bad) or 5xx
through to the user (worse). Cover the contract:

  * unknown event_type rejected (catalog enforcement)
  * malformed payload rejected (closed-schema enforcement)
  * happy path persists, returns the bigserial id
  * Postgres failure surfaces as None (not a raise)
  * not-initialised drops the event with a warning, never raises
  * safe_publish swallows EVERY error including ValueError
"""

from __future__ import annotations

from typing import Any

import pytest

import event_bus


@pytest.fixture(autouse=True)
def _reset_event_bus():
    """Each test starts with the bus uninitialized; reset after."""
    event_bus._pg_request = None
    event_bus._chapter_id = ""
    yield
    event_bus._pg_request = None
    event_bus._chapter_id = ""


class FakePostgres:
    """In-memory recorder for the pg_request callable.

    Default behaviour: return a one-row list with an auto-incrementing
    id, mimicking PostgREST `Prefer: return=representation`.
    """

    def __init__(self, *, return_value: Any = "AUTO") -> None:
        self.calls: list[tuple[str, str, dict | None, dict | list | None]] = []
        self._next_id = 1
        self._return_value = return_value

    async def __call__(
        self,
        method: str,
        table: str,
        params: dict | None = None,
        body: dict | list | None = None,
    ) -> Any:
        self.calls.append((method, table, params, body))
        if self._return_value == "AUTO":
            row = {**(body or {}), "id": self._next_id}
            self._next_id += 1
            return [row]
        return self._return_value


# ── init / state ─────────────────────────────────────────────────────


def test_is_initialized_false_before_init() -> None:
    assert event_bus.is_initialized() is False


def test_is_initialized_true_after_init() -> None:
    event_bus.init(FakePostgres(), "chapter-x")
    assert event_bus.is_initialized() is True


# ── publish() — happy path ───────────────────────────────────────────


@pytest.mark.asyncio
async def test_publish_happy_path_returns_event_id() -> None:
    sb = FakePostgres()
    event_bus.init(sb, "chapter-x")

    event_id = await event_bus.publish(
        "member.joined",
        {
            "agent_id": "alice",
            "did_key": "did:key:z6Mk",
            "name": "Alice",
            "skills": ["python"],
            "origin": "sovereign",
            "trust_score": 0.0,
        },
    )

    assert event_id == 1
    assert len(sb.calls) == 1
    method, table, _, body = sb.calls[0]
    assert (method, table) == ("POST", "event_log")
    assert body is not None and isinstance(body, dict)
    assert body["event_type"] == "member.joined"
    assert body["publisher_agent_id"] == "chapter-x"  # defaults to chapter_id
    assert body["payload"]["agent_id"] == "alice"
    assert "trace" not in body  # not requested


@pytest.mark.asyncio
async def test_publish_explicit_publisher_overrides_chapter_id() -> None:
    sb = FakePostgres()
    event_bus.init(sb, "chapter-x")

    await event_bus.publish(
        "member.joined",
        {"agent_id": "alice", "did_key": "did:key:z6Mk"},
        publisher_agent_id="some-other-agent",
    )

    assert sb.calls[0][3]["publisher_agent_id"] == "some-other-agent"


@pytest.mark.asyncio
async def test_publish_includes_trace_when_provided() -> None:
    sb = FakePostgres()
    event_bus.init(sb, "chapter-x")

    await event_bus.publish(
        "member.joined",
        {"agent_id": "alice", "did_key": "did:key:z6Mk"},
        trace="onboarding/2026-05-10",
    )

    assert sb.calls[0][3]["trace"] == "onboarding/2026-05-10"


@pytest.mark.asyncio
async def test_publish_accepts_payload_model_directly() -> None:
    """Callers may pass the already-built Pydantic model; we re-validate."""
    from event_types import MemberJoinedPayload

    sb = FakePostgres()
    event_bus.init(sb, "chapter-x")

    payload = MemberJoinedPayload(agent_id="alice", did_key="did:key:z6Mk")
    event_id = await event_bus.publish("member.joined", payload)

    assert event_id == 1


# ── publish() — closed-set enforcement ───────────────────────────────


@pytest.mark.asyncio
async def test_publish_rejects_unknown_event_type() -> None:
    sb = FakePostgres()
    event_bus.init(sb, "chapter-x")

    with pytest.raises(ValueError, match="Unknown event_type"):
        await event_bus.publish("totally.fake", {})

    assert sb.calls == []  # nothing persisted


@pytest.mark.asyncio
async def test_publish_rejects_malformed_payload() -> None:
    """Pydantic raises ValidationError, which subclasses ValueError."""
    sb = FakePostgres()
    event_bus.init(sb, "chapter-x")

    with pytest.raises(ValueError):
        # member.joined requires agent_id + did_key
        await event_bus.publish("member.joined", {"agent_id": "alice"})

    assert sb.calls == []


# ── publish() — uninitialised + supabase failure ─────────────────────


@pytest.mark.asyncio
async def test_publish_returns_none_when_bus_not_initialized() -> None:
    # No init() called.
    event_id = await event_bus.publish(
        "member.joined",
        {"agent_id": "alice", "did_key": "did:key:z6Mk"},
    )
    assert event_id is None


@pytest.mark.asyncio
async def test_publish_returns_none_when_supabase_returns_none() -> None:
    """pg_request returns None on its internal failure path."""
    sb = FakePostgres(return_value=None)
    event_bus.init(sb, "chapter-x")

    event_id = await event_bus.publish(
        "member.joined",
        {"agent_id": "alice", "did_key": "did:key:z6Mk"},
    )
    assert event_id is None


@pytest.mark.asyncio
async def test_publish_returns_none_when_row_lacks_id() -> None:
    """Defensive: PostgREST gave us a row but no id field."""
    sb = FakePostgres(return_value=[{"event_type": "member.joined"}])
    event_bus.init(sb, "chapter-x")

    event_id = await event_bus.publish(
        "member.joined",
        {"agent_id": "alice", "did_key": "did:key:z6Mk"},
    )
    assert event_id is None


# ── safe_publish() — fire-and-forget envelope ────────────────────────


@pytest.mark.asyncio
async def test_safe_publish_swallows_validation_error() -> None:
    sb = FakePostgres()
    event_bus.init(sb, "chapter-x")

    # Bad event_type — publish() would raise ValueError; safe_publish must not.
    result = await event_bus.safe_publish("totally.fake", {})
    assert result is None


@pytest.mark.asyncio
async def test_safe_publish_swallows_supabase_exception() -> None:
    class BoomPostgres:
        async def __call__(self, *args, **kwargs):
            raise RuntimeError("network exploded")

    event_bus.init(BoomPostgres(), "chapter-x")
    result = await event_bus.safe_publish(
        "member.joined",
        {"agent_id": "alice", "did_key": "did:key:z6Mk"},
    )
    assert result is None


@pytest.mark.asyncio
async def test_safe_publish_returns_event_id_on_happy_path() -> None:
    """Same return contract as publish() when nothing goes wrong."""
    sb = FakePostgres()
    event_bus.init(sb, "chapter-x")

    event_id = await event_bus.safe_publish(
        "member.joined",
        {"agent_id": "alice", "did_key": "did:key:z6Mk"},
    )
    assert event_id == 1
