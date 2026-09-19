"""
Prosecution-grade tests for A2A streaming (tasks/sendSubscribe + resubscribe).

Thesis:
  1. Every SSE frame is a well-formed JSON-RPC response wrapping either
     TaskStatusUpdateEvent or TaskArtifactUpdateEvent.
  2. Exactly one frame has `status.final: true` per stream.
  3. The stream emits state transitions in the correct order:
     submitted → working → (artifact?) → terminal-status.
  4. Failures abort the stream with a terminal `failed` status — the
     stream closes cleanly, never hangs.
  5. Resubscribe rebuilds a terminal view without re-dispatching the tool.
  6. Envelope errors (bad method, bad params) come through as SSE frames,
     not as raw 500s that would hang the client.

Classification: HAPPY / EDGE / FAILURE / ADVERSARIAL
"""

from __future__ import annotations

import json

import pytest

from community_member import a2a_rpc as rpc
from community_member.task_store import TaskStore

# These tests drive the dispatcher directly, so they supply the verified caller
# the route would have derived from the request headers. Sends require one —
# see ``a2a_auth.METHOD_ACCESS`` — and the gate itself is tested in
# ``tests/test_a2a_surface_auth.py`` rather than re-asserted at every call here.
# Passed uniformly at these call sites, including for reads that do NOT require
# it — tasks/get, tasks/cancel and tasks/resubscribe are open. Do not read its
# presence here as the classification; the classification is a2a_auth.METHOD_ACCESS
# and it is pinned in tests/test_a2a_surface_auth.py.
PEER = rpc.a2a_auth.CallerIdentity(agent_id="peer-agent", did_key="did:key:zPeerTest")


def _parse_sse(text: str) -> list[dict]:
    """Parse SSE 'data: {...}\\n\\n' frames into a list of dicts."""
    events = []
    for block in text.split("\n\n"):
        block = block.strip()
        if not block:
            continue
        # Every block in our stream has exactly one 'data:' line.
        for line in block.splitlines():
            if line.startswith("data:"):
                events.append(json.loads(line[len("data:") :].strip()))
    return events


def _user_msg_with_tool(tool: str, args: dict) -> dict:
    return {
        "role": "user",
        "parts": [{"type": "data", "data": {"tool": tool, "args": args}}],
    }


@pytest.fixture
def tmp_store(tmp_path):
    return TaskStore(path=tmp_path / "tasks.jsonl")


@pytest.fixture
def fake_dispatcher():
    async def dispatch(name: str, args: dict) -> str:
        if name == "boom":
            raise RuntimeError("synthetic failure")
        if name == "unknown_tool":
            raise KeyError(name)
        return json.dumps({"tool": name, "args": args})

    return dispatch


@pytest.fixture
def handler(tmp_store, fake_dispatcher):
    return rpc.A2ARPCHandler(store=tmp_store, dispatcher=fake_dispatcher)


async def _collect(gen):
    frames = []
    async for frame in gen:
        frames.append(frame)
    return "".join(frames)


# ═══════════════════════════════════════════════════════
# HAPPY — frame shape + ordering
# ═══════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_stream_emits_submitted_working_artifact_completed(handler):
    raw = await _collect(
        handler.stream(
            {
                "jsonrpc": "2.0",
                "id": "r1",
                "method": "tasks/sendSubscribe",
                "params": {
                    "id": "t-stream-happy",
                    "message": _user_msg_with_tool("search_chapter", {"query": "x"}),
                },
            },
            caller=PEER,
        )
    )
    events = _parse_sse(raw)

    # Every frame is a valid JSON-RPC envelope with the same id
    assert len(events) >= 3
    for e in events:
        assert e["jsonrpc"] == "2.0"
        assert e["id"] == "r1"
        assert "result" in e

    # State transitions in order
    states = [e["result"]["status"]["state"] for e in events if "status" in e["result"]]
    assert states[0] == "submitted"
    assert states[-1] == "completed"
    assert "working" in states

    # Exactly one `final: true` frame, and it's the last one
    finals = [e for e in events if "status" in e["result"] and e["result"].get("final") is True]
    assert len(finals) == 1
    assert finals[0] == events[-1]

    # Artifact emitted before the terminal status
    artifact_events = [e for e in events if "artifact" in e["result"]]
    assert len(artifact_events) == 1
    artifact_idx = events.index(artifact_events[0])
    terminal_idx = events.index(finals[0])
    assert artifact_idx < terminal_idx


@pytest.mark.asyncio
async def test_streaming_completed_task_has_artifact_payload(handler):
    raw = await _collect(
        handler.stream(
            {
                "jsonrpc": "2.0",
                "id": "r1",
                "method": "tasks/sendSubscribe",
                "params": {
                    "id": "t-payload",
                    "message": _user_msg_with_tool("search_chapter", {"q": "rust"}),
                },
            },
            caller=PEER,
        )
    )
    events = _parse_sse(raw)
    artifact = next(e["result"]["artifact"] for e in events if "artifact" in e["result"])
    # The tool's raw return survives intact inside the artifact's DataPart
    data_parts = [p for p in artifact["parts"] if p["type"] == "data"]
    assert data_parts
    assert data_parts[0]["data"]["tool"] == "search_chapter"


# ═══════════════════════════════════════════════════════
# FAILURE — tool errors terminate the stream
# ═══════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_tool_exception_emits_failed_terminal_status(handler):
    raw = await _collect(
        handler.stream(
            {
                "jsonrpc": "2.0",
                "id": "r1",
                "method": "tasks/sendSubscribe",
                "params": {"id": "t-boom", "message": _user_msg_with_tool("boom", {})},
            },
            caller=PEER,
        )
    )
    events = _parse_sse(raw)
    # No artifact, last event is failed+final
    assert not any("artifact" in e["result"] for e in events)
    last = events[-1]
    assert last["result"]["status"]["state"] == "failed"
    assert last["result"]["final"] is True


@pytest.mark.asyncio
async def test_unknown_tool_emits_failed_terminal_status(handler):
    raw = await _collect(
        handler.stream(
            {
                "jsonrpc": "2.0",
                "id": "r1",
                "method": "tasks/sendSubscribe",
                "params": {"id": "t-u", "message": _user_msg_with_tool("unknown_tool", {})},
            },
            caller=PEER,
        )
    )
    events = _parse_sse(raw)
    last = events[-1]
    assert last["result"]["status"]["state"] == "failed"
    assert last["result"]["final"] is True


@pytest.mark.asyncio
async def test_text_only_message_emits_input_required_terminal(handler):
    """EDGE: client subscribes with a text part. We still emit a valid
    stream that terminates on input-required — no hang."""
    raw = await _collect(
        handler.stream(
            {
                "jsonrpc": "2.0",
                "id": "r1",
                "method": "tasks/sendSubscribe",
                "params": {
                    "id": "t-text",
                    "message": {"role": "user", "parts": [{"type": "text", "text": "hi"}]},
                },
            },
            caller=PEER,
        )
    )
    events = _parse_sse(raw)
    last = events[-1]
    assert last["result"]["status"]["state"] == "input-required"
    assert last["result"]["final"] is True


# ═══════════════════════════════════════════════════════
# FAILURE — envelope errors come through as SSE
# ═══════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_bad_envelope_streams_one_error_frame_and_closes(handler):
    raw = await _collect(handler.stream({"not": "jsonrpc"}, caller=PEER))
    events = _parse_sse(raw)
    assert len(events) == 1
    assert events[0]["error"]["code"] == rpc.ERROR_INVALID_REQUEST


@pytest.mark.asyncio
async def test_unknown_streaming_method_closes_cleanly(handler):
    raw = await _collect(
        handler.stream({"jsonrpc": "2.0", "id": 1, "method": "tasks/unknown", "params": {}}, caller=PEER)
    )
    events = _parse_sse(raw)
    assert len(events) == 1
    assert events[0]["error"]["code"] == rpc.ERROR_METHOD_NOT_FOUND


@pytest.mark.asyncio
async def test_a_streaming_send_without_an_id_is_assigned_one(handler):
    """Inverted for the same reason as its non-streaming twin: the current spec
    removed the caller-supplied task id and the server assigns it. Every frame
    must then name the task the server chose."""
    raw = await _collect(
        handler.stream(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tasks/sendSubscribe",
                "params": {"message": _user_msg_with_tool("search_chapter", {})},
            },
            caller=PEER,
        )
    )
    events = _parse_sse(raw)
    assert all("error" not in e for e in events), f"a streaming send with no id was refused: {events[0]}"
    ids = {e["result"]["id"] for e in events if "result" in e}
    assert len(ids) == 1 and ids.pop(), "the stream did not name exactly one server-assigned task"


# ═══════════════════════════════════════════════════════
# HAPPY — resubscribe
# ═══════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_resubscribe_to_completed_task_replays_state(handler, fake_dispatcher):
    # First, create+complete a task via the non-streaming path
    await handler.handle(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tasks/send",
            "params": {
                "id": "t-done",
                "message": _user_msg_with_tool("search_chapter", {"q": "x"}),
            },
        },
        caller=PEER,
    )
    # Now resubscribe
    raw = await _collect(
        handler.stream(
            {"jsonrpc": "2.0", "id": 2, "method": "tasks/resubscribe", "params": {"id": "t-done"}}, caller=PEER
        )
    )
    events = _parse_sse(raw)
    # Artifact from the completed task, then final completed status
    kinds = [("artifact" in e["result"]) for e in events]
    assert kinds[0] is True  # artifact first
    assert events[-1]["result"]["status"]["state"] == "completed"
    assert events[-1]["result"]["final"] is True


@pytest.mark.asyncio
async def test_resubscribe_unknown_task_emits_task_not_found(handler):
    raw = await _collect(
        handler.stream(
            {"jsonrpc": "2.0", "id": 1, "method": "tasks/resubscribe", "params": {"id": "nope"}}, caller=PEER
        )
    )
    events = _parse_sse(raw)
    assert events[0]["error"]["code"] == rpc.ERROR_TASK_NOT_FOUND


# ═══════════════════════════════════════════════════════
# ADVERSARIAL — dispatcher called exactly once in streaming
# ═══════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_streaming_calls_dispatcher_exactly_once(tmp_store):
    """ADVERSARIAL: verify the streaming path doesn't double-fire the tool.
    The most common streaming bug is emitting 'working' by re-invoking the
    dispatcher instead of pre-emitting the state."""
    count = [0]

    async def counting(name, args):
        count[0] += 1
        return json.dumps({"x": 1})

    h = rpc.A2ARPCHandler(tmp_store, counting)
    await _collect(
        h.stream(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tasks/sendSubscribe",
                "params": {
                    "id": "t-once",
                    "message": _user_msg_with_tool("search_chapter", {}),
                },
            },
            caller=PEER,
        )
    )
    assert count[0] == 1


# ═══════════════════════════════════════════════════════
# HAPPY — full server end-to-end via SSE
# ═══════════════════════════════════════════════════════


@pytest.fixture
def app_client(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from community_member import task_store as ts_mod
    from community_member.config import Config
    from community_member.crypto import generate_keypair
    from community_member.server import create_app

    monkeypatch.setattr(ts_mod, "TASK_STORE_PATH", tmp_path / "tasks.jsonl")

    cfg = Config()
    cfg.agent_id = "alice"
    cfg.name = "Alice"
    cfg.chapter_url = "https://chapter.example"
    cfg.api_key = "x" * 32
    kp = generate_keypair()
    cfg.private_key = kp["private_key"]
    cfg.public_key = kp["public_key"]

    class FakeAgent:
        AGENT_TOOLS = [
            {"type": "function", "function": {"name": "search_chapter", "description": ""}},
        ]

        async def execute_tool(self, name, args):
            return json.dumps({"tool": name, "args": args})

    return TestClient(create_app(cfg, agent=FakeAgent()))


def _signed(body: str) -> dict[str, str]:
    """Headers a genuine peer sends, built with the SDK's own signing helper.

    A streaming send is caller-required, so driving this route over real HTTP
    needs a real signature — which makes this the end-to-end proof that the gate
    ADMITS a legitimate caller, not only that it refuses an anonymous one.
    """
    from community_member.a2a_client_v2 import _signed_headers
    from community_member.crypto import generate_ed25519_keypair

    kp = generate_ed25519_keypair()
    return _signed_headers(body, "peer-agent", kp["private_key"], kp["public_key"], scheme="ed25519")


def test_http_streaming_end_to_end(app_client):
    payload = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": "r1",
            "method": "tasks/sendSubscribe",
            "params": {
                "id": "t-e2e",
                "message": {
                    "role": "user",
                    "parts": [{"type": "data", "data": {"tool": "search_chapter", "args": {}}}],
                },
            },
        }
    )
    with app_client.stream("POST", "/", content=payload, headers=_signed(payload)) as response:
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/event-stream")
        body = b"".join(response.iter_bytes()).decode()

    events = _parse_sse(body)
    assert events[-1]["result"]["status"]["state"] == "completed"
    assert events[-1]["result"]["final"] is True
