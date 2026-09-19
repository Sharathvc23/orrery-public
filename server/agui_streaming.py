"""AG-UI streaming — event helpers for /api/surfaces/{pageId}/stream.

AG-UI (Agent-User Interaction) is an open event-based protocol that
standardizes the runtime channel between an agentic backend and a
user-facing app. We already speak A2UI v0.9 as our declarative UI
spec; AG-UI is the streaming wire between agent and renderer.

This module ships the **minimum subset** needed to push live surface
updates over Server-Sent Events:

  * RunStarted    — begins a surface stream
  * StateSnapshot — emits the full surface JSON
  * StateDelta    — emits JSON-Patch operations for incremental updates
  * RunFinished   — surface stream is done

Future work can extend with the full 17 AG-UI event types (text
message streaming, tool call begin/args/end, step begin/end). For
the v0 spike, a snapshot-then-deltas loop is enough to replace
30s polling on the digest + graduations + trust history surfaces.

Wire format (per AG-UI protocol):

  data: {"type": "RunStarted", "runId": "<uuid>", "threadId": "<thread>"}
  data: {"type": "StateSnapshot", "snapshot": {...A2UI surface...}}
  data: {"type": "StateDelta", "delta": [json-patch-ops]}
  data: {"type": "RunFinished", "runId": "<uuid>"}

Each event is one JSON object on a single SSE `data:` line, terminated
with a blank line — same shape SSE consumers across the AG-UI ecosystem
expect.
"""

from __future__ import annotations

import json
import time
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable

# AG-UI event names (subset — see https://docs.ag-ui.com/concepts/events
# for the full 17). Keep identifiers stable: AG-UI clients pattern-match
# on these strings.
EVENT_RUN_STARTED = "RunStarted"
EVENT_RUN_FINISHED = "RunFinished"
EVENT_RUN_ERROR = "RunError"
EVENT_STATE_SNAPSHOT = "StateSnapshot"
EVENT_STATE_DELTA = "StateDelta"


def encode_sse(event: dict) -> bytes:
    """Encode one AG-UI event as an SSE `data:` line + blank-line terminator.

    Returns bytes (so the FastAPI streaming response can yield without
    a per-chunk encode). The JSON serialization uses sorted keys so the
    wire is canonical — useful for replay tests and downstream caches.
    """
    payload = json.dumps(event, sort_keys=True, default=str)
    return f"data: {payload}\n\n".encode()


def event_run_started(*, run_id: str, thread_id: str) -> dict:
    return {
        "type": EVENT_RUN_STARTED,
        "runId": run_id,
        "threadId": thread_id,
        "timestamp": int(time.time() * 1000),
    }


def event_run_finished(*, run_id: str) -> dict:
    return {
        "type": EVENT_RUN_FINISHED,
        "runId": run_id,
        "timestamp": int(time.time() * 1000),
    }


def event_run_error(*, run_id: str, message: str, code: str | None = None) -> dict:
    return {
        "type": EVENT_RUN_ERROR,
        "runId": run_id,
        "message": message[:500],
        "code": code,
        "timestamp": int(time.time() * 1000),
    }


def event_state_snapshot(snapshot: dict) -> dict:
    return {
        "type": EVENT_STATE_SNAPSHOT,
        "snapshot": snapshot,
        "timestamp": int(time.time() * 1000),
    }


def event_state_delta(operations: list[dict]) -> dict:
    """`operations` is a list of RFC-6902 JSON Patch ops — each is
    `{"op": "add"|"replace"|"remove", "path": "/foo/0/bar", "value": ...}`."""
    return {
        "type": EVENT_STATE_DELTA,
        "delta": operations,
        "timestamp": int(time.time() * 1000),
    }


# ── JSON-Patch diff ─────────────────────────────────────────────────


def diff_surfaces(prev: dict | None, curr: dict) -> list[dict]:
    """Compute a minimal RFC-6902 JSON Patch from `prev` → `curr`.

    The implementation is intentionally simple: for the snapshot-then-
    delta loop we mostly emit a single `replace /` op when anything
    deep changes, which lets the renderer handle apply naively. A
    smarter diff (per-key replace) is a follow-up if bandwidth becomes
    a concern.

    Returns an empty list iff `prev == curr`.
    """
    if prev == curr:
        return []
    return [{"op": "replace", "path": "", "value": curr}]


# ── Stream driver ───────────────────────────────────────────────────


SurfaceFetcher = Callable[[], Awaitable[dict]]


async def stream_surface_updates(
    fetcher: SurfaceFetcher,
    *,
    thread_id: str | None = None,
    interval_seconds: float = 5.0,
    max_iterations: int | None = None,
) -> AsyncIterator[bytes]:
    """Yield AG-UI events for one surface over time.

    Wire sequence:
      1. RunStarted
      2. StateSnapshot          (initial full surface)
      3. StateDelta * N         (only when surface changes)
      4. RunFinished            (only after max_iterations or caller cancellation)

    The fetcher is awaited on every cycle. If the fetched surface is
    identical to the previous, no event is emitted (clients see
    silence — that's correct: the SSE connection stays open). If it
    raises, a RunError event is emitted and the stream terminates.

    Cancellation: when the consumer disconnects, the generator is
    closed by FastAPI's StreamingResponse — the loop exits cleanly.
    """
    run_id = str(uuid.uuid4())
    yield encode_sse(event_run_started(run_id=run_id, thread_id=thread_id or run_id))

    last_snapshot: dict | None = None
    iteration = 0
    try:
        while True:
            try:
                surface = await fetcher()
            except Exception as e:  # noqa: BLE001 — surface fetcher failures end the run
                yield encode_sse(event_run_error(run_id=run_id, message=f"{type(e).__name__}: {e}"))
                return

            if last_snapshot is None:
                yield encode_sse(event_state_snapshot(surface))
            else:
                ops = diff_surfaces(last_snapshot, surface)
                if ops:
                    yield encode_sse(event_state_delta(ops))
            last_snapshot = surface

            iteration += 1
            if max_iterations is not None and iteration >= max_iterations:
                break

            # asyncio.sleep at module scope to avoid pytest fixture
            # complications. Imported lazily.
            import asyncio

            await asyncio.sleep(interval_seconds)
    finally:
        yield encode_sse(event_run_finished(run_id=run_id))


def parse_events(stream_bytes: bytes) -> list[dict]:
    """Parse an SSE byte stream into AG-UI event dicts. Used by tests
    and by clients that buffer the whole stream before parsing."""
    events: list[dict] = []
    text = stream_bytes.decode("utf-8")
    for chunk in text.split("\n\n"):
        chunk = chunk.strip()
        if not chunk:
            continue
        for line in chunk.splitlines():
            if line.startswith("data: "):
                payload = line[len("data: ") :]
                events.append(json.loads(payload))
    return events
