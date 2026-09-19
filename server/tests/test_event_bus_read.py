"""Tests for the read side of event_bus (EB-4 backends).

Covers:
  * events_since(last_id, topics) — PostgREST query shape, ordering,
    limit, empty-on-failure, empty-on-uninitialised
  * format_sse_event(row) — SSE wire format compliance

The SSE endpoint integration is in test_subscription_stream_endpoint.py.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

import event_bus


@pytest.fixture(autouse=True)
def _reset_event_bus():
    event_bus._pg_request = None
    event_bus._chapter_id = ""
    yield
    event_bus._pg_request = None
    event_bus._chapter_id = ""


class FakePostgres:
    def __init__(self, *, return_value: Any = None) -> None:
        self.calls: list[tuple[str, str, dict | None, Any]] = []
        self._return_value = return_value

    async def __call__(self, method, table, params=None, body=None):
        self.calls.append((method, table, params, body))
        return self._return_value


# ── events_since() — query shape ─────────────────────────────────────


@pytest.mark.asyncio
async def test_events_since_builds_correct_postgrest_query() -> None:
    rows = [
        {"id": 5, "event_type": "member.joined", "payload": {"agent_id": "alice"}},
        {"id": 7, "event_type": "intent.published", "payload": {"intent_id": "i1"}},
    ]
    sb = FakePostgres(return_value=rows)
    event_bus.init(sb, "chapter-x")

    result = await event_bus.events_since(3, ["member.joined", "intent.published"])

    assert result == rows
    method, table, params, _ = sb.calls[0]
    assert (method, table) == ("GET", "event_log")
    assert params["id"] == "gt.3"
    assert params["event_type"] == "in.(member.joined,intent.published)"
    assert params["order"] == "id.asc"
    assert params["limit"] == "100"  # default


@pytest.mark.asyncio
async def test_events_since_respects_custom_limit() -> None:
    sb = FakePostgres(return_value=[])
    event_bus.init(sb, "chapter-x")

    await event_bus.events_since(0, ["member.joined"], limit=25)
    assert sb.calls[0][2]["limit"] == "25"


@pytest.mark.asyncio
async def test_events_since_returns_empty_when_uninitialised() -> None:
    """No init() call — must not crash, just return []. The endpoint
    layer might call this before startup completes."""
    assert await event_bus.events_since(0, ["member.joined"]) == []


@pytest.mark.asyncio
async def test_events_since_returns_empty_for_empty_topics() -> None:
    """A subscription with zero topics shouldn't query Postgres at all
    — every row would be filtered out anyway. The DB CHECK constraint
    forbids this state but defense in depth."""
    sb = FakePostgres(return_value=[{"id": 1}])
    event_bus.init(sb, "chapter-x")

    result = await event_bus.events_since(0, [])
    assert result == []
    assert sb.calls == []  # no Postgres round-trip


@pytest.mark.asyncio
async def test_events_since_returns_empty_on_supabase_failure() -> None:
    """Postgres wrapper returns None on failure — events_since must
    surface as [] so the SSE loop doesn't crash."""
    sb = FakePostgres(return_value=None)
    event_bus.init(sb, "chapter-x")

    result = await event_bus.events_since(0, ["member.joined"])
    assert result == []


@pytest.mark.asyncio
async def test_events_since_filters_non_dict_rows_defensively() -> None:
    """If PostgREST returns a malformed row (string, null), don't
    propagate it — the SSE formatter would crash on .get()."""
    sb = FakePostgres(return_value=[{"id": 1, "event_type": "member.joined"}, "garbage", None])
    event_bus.init(sb, "chapter-x")

    result = await event_bus.events_since(0, ["member.joined"])
    assert len(result) == 1
    assert result[0]["id"] == 1


# ── format_sse_event() — wire format ─────────────────────────────────


def test_format_sse_event_full_row() -> None:
    row = {
        "id": 42,
        "event_type": "member.joined",
        "payload": {"agent_id": "alice", "did_key": "did:key:zA"},
    }
    out = event_bus.format_sse_event(row)
    # SSE spec: id, event, data, blank line
    assert out.startswith("id: 42\nevent: member.joined\ndata: ")
    assert out.endswith("\n\n")
    # Data is JSON
    data_line = [line for line in out.splitlines() if line.startswith("data: ")][0]
    payload = json.loads(data_line[len("data: ") :])
    assert payload == {"agent_id": "alice", "did_key": "did:key:zA"}


def test_format_sse_event_missing_payload_defaults_to_empty_object() -> None:
    """Don't 500 on a malformed row — emit {} so the client at least
    sees the id and event_type."""
    out = event_bus.format_sse_event({"id": 1, "event_type": "x"})
    data_line = [line for line in out.splitlines() if line.startswith("data: ")][0]
    assert data_line == "data: {}"


def test_format_sse_event_unknown_event_type_uses_fallback() -> None:
    out = event_bus.format_sse_event({"id": 1, "payload": {}})
    assert "event: unknown\n" in out


def test_format_sse_event_data_is_compact_json_no_spaces() -> None:
    """Bytes-per-event matters at scale. Compact separators only."""
    out = event_bus.format_sse_event({"id": 1, "event_type": "x", "payload": {"a": 1, "b": 2}})
    assert 'data: {"a":1,"b":2}\n' in out
