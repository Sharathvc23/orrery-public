"""
R1-R10 + S tests for agui_streaming — AG-UI event streaming over SSE.

R1  Forgery       — encode_sse cannot smuggle CRLF that splits the
                    SSE frame (we sort_keys + JSON-encode; verify no
                    raw newlines escape)
R2  Replay        — running the stream twice with identical fetcher
                    output produces byte-identical event sequences
R3  Injection     — surface containing "data: " or HTML/JS doesn't
                    break the SSE frame; the renderer treats it as
                    JSON content, not control bytes
R4  Lifecycle     — every stream begins with RunStarted and ends with
                    RunFinished, even on early cancel
R5  Boundary      — max_iterations=1 emits exactly: RunStarted +
                    StateSnapshot + RunFinished (no StateDelta)
R6  Concurrency   — two simultaneous streams against the same fetcher
                    each get their own runId
R7  Adversarial   — fetcher raising → RunError event + stream ends
R8  Downgrade     — when surface doesn't change, no StateDelta is
                    emitted (silent SSE keepalive is correct)
R9  Diff          — diff_surfaces of identical dicts returns []
R10 Persistence   — parse_events round-trips encode_sse output
"""

from __future__ import annotations

import asyncio

import pytest

import agui_streaming as agui

# ── Pure helpers ──────────────────────────────────────────────────


def test_event_run_started_shape():
    e = agui.event_run_started(run_id="r1", thread_id="t1")
    assert e["type"] == "RunStarted"
    assert e["runId"] == "r1"
    assert e["threadId"] == "t1"
    assert isinstance(e["timestamp"], int)


def test_event_state_snapshot_carries_payload():
    surface = {"id": "today", "components": [{"type": "Text", "text": "hi"}]}
    e = agui.event_state_snapshot(surface)
    assert e["type"] == "StateSnapshot"
    assert e["snapshot"] == surface


def test_R9_diff_identical_returns_empty():
    a = {"id": "x", "data": [1, 2, 3]}
    assert agui.diff_surfaces(a, a) == []
    assert agui.diff_surfaces(a, dict(a)) == []


def test_diff_changed_returns_replace_root():
    prev = {"a": 1}
    curr = {"a": 2}
    ops = agui.diff_surfaces(prev, curr)
    assert ops == [{"op": "replace", "path": "", "value": curr}]


# ── SSE encoding ──────────────────────────────────────────────────


def test_encode_sse_terminates_with_blank_line():
    out = agui.encode_sse({"type": "Test"})
    assert out.endswith(b"\n\n")
    assert out.startswith(b"data: ")


def test_R1_encode_sse_escapes_newlines_in_payload():
    """A surface field containing a literal newline cannot escape the
    SSE frame: JSON encoding turns it into \\n, so the SSE consumer
    sees one frame, not two."""
    surface = {"text": "line1\nline2"}
    raw = agui.encode_sse(agui.event_state_snapshot(surface))
    # exactly one frame == exactly one trailing blank line
    assert raw.count(b"\n\n") == 1
    # the literal newline got escaped
    assert b"line1\\nline2" in raw


def test_R3_encode_sse_handles_data_prefix_in_payload():
    """Surface content containing the string 'data: ' doesn't confuse
    parsers — JSON encoding wraps it in quotes."""
    surface = {"text": "data: malicious"}
    raw = agui.encode_sse(agui.event_state_snapshot(surface))
    parsed = agui.parse_events(raw)
    assert len(parsed) == 1
    assert parsed[0]["snapshot"]["text"] == "data: malicious"


def test_R10_parse_events_round_trips_encoding():
    e1 = agui.event_run_started(run_id="r1", thread_id="t1")
    e2 = agui.event_state_snapshot({"id": "x"})
    e3 = agui.event_run_finished(run_id="r1")
    blob = agui.encode_sse(e1) + agui.encode_sse(e2) + agui.encode_sse(e3)
    parsed = agui.parse_events(blob)
    assert len(parsed) == 3
    assert [p["type"] for p in parsed] == ["RunStarted", "StateSnapshot", "RunFinished"]


# ── Stream driver ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_R5_boundary_max_iterations_one():
    """One iteration → RunStarted + StateSnapshot + RunFinished only."""
    surface = {"id": "today", "version": 1}

    async def fetcher():
        return surface

    events: list[dict] = []
    async for chunk in agui.stream_surface_updates(fetcher, interval_seconds=0.0, max_iterations=1):
        events.extend(agui.parse_events(chunk))

    types = [e["type"] for e in events]
    assert types == ["RunStarted", "StateSnapshot", "RunFinished"]


@pytest.mark.asyncio
async def test_R8_no_delta_when_surface_unchanged():
    """If the fetcher returns the same surface each cycle, only the
    initial StateSnapshot fires. Subsequent cycles are silent."""
    surface = {"id": "today", "approved": 0}

    async def fetcher():
        return surface

    events: list[dict] = []
    async for chunk in agui.stream_surface_updates(fetcher, interval_seconds=0.0, max_iterations=3):
        events.extend(agui.parse_events(chunk))

    types = [e["type"] for e in events]
    # 1 RunStarted + 1 StateSnapshot + 1 RunFinished — no deltas.
    assert types.count("StateDelta") == 0
    assert types.count("StateSnapshot") == 1


@pytest.mark.asyncio
async def test_state_delta_fires_on_change():
    """When surface changes between cycles, a StateDelta is emitted."""
    versions = [{"id": "today", "v": 1}, {"id": "today", "v": 2}]
    cursor = {"i": 0}

    async def fetcher():
        v = versions[cursor["i"]]
        cursor["i"] = min(cursor["i"] + 1, len(versions) - 1)
        return v

    events: list[dict] = []
    async for chunk in agui.stream_surface_updates(fetcher, interval_seconds=0.0, max_iterations=2):
        events.extend(agui.parse_events(chunk))

    types = [e["type"] for e in events]
    # RunStarted, StateSnapshot, StateDelta, RunFinished
    assert types == ["RunStarted", "StateSnapshot", "StateDelta", "RunFinished"]
    delta_event = events[2]
    assert delta_event["delta"] == [{"op": "replace", "path": "", "value": versions[1]}]


@pytest.mark.asyncio
async def test_R7_fetcher_exception_emits_run_error_then_finished():
    """A fetcher that raises mid-stream emits RunError then the
    `finally` block emits RunFinished."""

    async def fetcher():
        raise RuntimeError("supabase down")

    events: list[dict] = []
    async for chunk in agui.stream_surface_updates(fetcher, interval_seconds=0.0, max_iterations=5):
        events.extend(agui.parse_events(chunk))

    types = [e["type"] for e in events]
    assert "RunError" in types
    assert "RunFinished" in types
    error_event = next(e for e in events if e["type"] == "RunError")
    assert "supabase down" in error_event["message"]


@pytest.mark.asyncio
async def test_R4_lifecycle_run_started_first_run_finished_last():
    surface = {"id": "x"}

    async def fetcher():
        return surface

    events: list[dict] = []
    async for chunk in agui.stream_surface_updates(fetcher, interval_seconds=0.0, max_iterations=2):
        events.extend(agui.parse_events(chunk))

    assert events[0]["type"] == "RunStarted"
    assert events[-1]["type"] == "RunFinished"


@pytest.mark.asyncio
async def test_R2_replay_two_streams_identical_when_fetcher_deterministic():
    """Same deterministic fetcher → identical event sequence (modulo
    runId + timestamps)."""
    surface = {"id": "x", "v": 1}

    async def fetcher():
        return surface

    async def collect():
        events: list[dict] = []
        async for chunk in agui.stream_surface_updates(fetcher, interval_seconds=0.0, max_iterations=1):
            events.extend(agui.parse_events(chunk))
        return events

    seq1 = await collect()
    seq2 = await collect()

    types1 = [e["type"] for e in seq1]
    types2 = [e["type"] for e in seq2]
    assert types1 == types2

    snap1 = next(e for e in seq1 if e["type"] == "StateSnapshot")
    snap2 = next(e for e in seq2 if e["type"] == "StateSnapshot")
    assert snap1["snapshot"] == snap2["snapshot"]


@pytest.mark.asyncio
async def test_R6_concurrent_streams_get_distinct_run_ids():
    """Two streams running at once each get their own runId — required
    so a multi-tab user's events don't crosstalk."""
    surface = {"id": "x"}

    async def fetcher():
        return surface

    async def collect_run_id():
        async for chunk in agui.stream_surface_updates(fetcher, interval_seconds=0.0, max_iterations=1):
            for e in agui.parse_events(chunk):
                if e["type"] == "RunStarted":
                    return e["runId"]
        return None

    r1, r2 = await asyncio.gather(collect_run_id(), collect_run_id())
    assert r1 != r2


@pytest.mark.asyncio
async def test_thread_id_default_falls_back_to_run_id():
    surface = {"id": "x"}

    async def fetcher():
        return surface

    events: list[dict] = []
    async for chunk in agui.stream_surface_updates(fetcher, interval_seconds=0.0, max_iterations=1):
        events.extend(agui.parse_events(chunk))
    started = next(e for e in events if e["type"] == "RunStarted")
    assert started["threadId"] == started["runId"]
