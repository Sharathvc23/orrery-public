"""
Prosecution-grade tests for A2A JSON-RPC dispatcher.

Thesis:
  1. JSON-RPC envelope conformance — every response has jsonrpc:2.0 + id.
  2. tasks/send is the *only* way to create state; tasks/get and
     tasks/cancel can't create tasks.
  3. Tool invocation goes through the dispatcher exactly once per
     tasks/send; no double-fire on retries.
  4. Unknown tools / tool failures return typed JSON-RPC errors (not
     500s, not silent success).
  5. Task persistence survives process restarts — state stored as JSONL.
  6. Concurrent tasks/send calls don't interleave partial state in the
     file (RLock + atomic line writes).
  7. Replay of the JSONL log reconstructs identical state.

Classification: HAPPY / EDGE / FAILURE / ADVERSARIAL
"""

from __future__ import annotations

import json

import pytest

from community_member import a2a_rpc as rpc
from community_member.a2a_models import (
    DataPart,
    JSONRPCResponse,
    Message,
    Task,
    TextPart,
)
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


# ─── Fixtures ─────────────────────────────────────────────


@pytest.fixture
def tmp_store(tmp_path):
    return TaskStore(path=tmp_path / "tasks.jsonl")


@pytest.fixture
def fake_dispatcher():
    """Records every invocation so we can count them."""
    calls: list[tuple[str, dict]] = []

    async def dispatch(name: str, args: dict) -> str:
        calls.append((name, args))
        if name == "boom":
            raise RuntimeError("synthetic failure")
        if name == "unknown_tool":
            raise KeyError(name)
        return json.dumps({"echo": {"tool": name, "args": args}})

    dispatch.calls = calls  # type: ignore[attr-defined]
    return dispatch


@pytest.fixture
def handler(tmp_store, fake_dispatcher):
    return rpc.A2ARPCHandler(store=tmp_store, dispatcher=fake_dispatcher)


def _user_msg_with_tool(tool: str, args: dict) -> dict:
    return {
        "role": "user",
        "parts": [{"type": "data", "data": {"tool": tool, "args": args}}],
    }


# ═══════════════════════════════════════════════════════
# HAPPY — envelope conformance
# ═══════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_envelope_always_has_jsonrpc_2_and_id(handler):
    resp = await handler.handle(
        {
            "jsonrpc": "2.0",
            "id": "abc-123",
            "method": "tasks/send",
            "params": {"id": "t1", "message": _user_msg_with_tool("search_chapter", {"q": "x"})},
        },
        caller=PEER,
    )
    assert resp["jsonrpc"] == "2.0"
    assert resp["id"] == "abc-123"
    # And the response model round-trips
    JSONRPCResponse.model_validate(resp)


@pytest.mark.asyncio
async def test_unknown_method_returns_method_not_found(handler):
    resp = await handler.handle({"jsonrpc": "2.0", "id": 1, "method": "tasks/nope", "params": {}}, caller=PEER)
    assert resp["error"]["code"] == rpc.ERROR_METHOD_NOT_FOUND


@pytest.mark.asyncio
async def test_malformed_envelope_returns_invalid_request(handler):
    resp = await handler.handle({"not": "json-rpc"}, caller=PEER)
    assert resp["error"]["code"] == rpc.ERROR_INVALID_REQUEST


# ═══════════════════════════════════════════════════════
# HAPPY — tasks/send invocation
# ═══════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_tasks_send_invokes_dispatcher_once(handler, fake_dispatcher):
    resp = await handler.handle(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tasks/send",
            "params": {
                "id": "t-single",
                "message": _user_msg_with_tool("search_chapter", {"query": "rust"}),
            },
        },
        caller=PEER,
    )
    assert resp["result"]["status"]["state"] == "completed"
    assert len(fake_dispatcher.calls) == 1
    assert fake_dispatcher.calls[0] == ("search_chapter", {"query": "rust"})


@pytest.mark.asyncio
async def test_tasks_send_returns_task_with_artifact(handler):
    resp = await handler.handle(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tasks/send",
            "params": {
                "id": "t-artifact",
                "message": _user_msg_with_tool("search_chapter", {"query": "x"}),
            },
        },
        caller=PEER,
    )
    task = Task.model_validate(resp["result"])
    assert len(task.artifacts) == 1
    assert task.artifacts[0].name == "tool-result:search_chapter"
    # Artifact carries a DataPart whose `result` is the tool's raw return.
    part = task.artifacts[0].parts[0]
    assert isinstance(part, DataPart)
    assert json.loads(part.data["result"])["echo"]["tool"] == "search_chapter"


# ═══════════════════════════════════════════════════════
# HAPPY — tasks/send with no tool part returns input-required
# ═══════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_text_only_message_returns_input_required(handler, fake_dispatcher):
    """The spec-conformant signal for "I need different input": input-required.
    The task is created (so the caller can tasks/send again on the same id)
    but no tool was dispatched."""
    resp = await handler.handle(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tasks/send",
            "params": {
                "id": "t-text",
                "message": {"role": "user", "parts": [{"type": "text", "text": "help me"}]},
            },
        },
        caller=PEER,
    )
    assert resp["result"]["status"]["state"] == "input-required"
    assert len(fake_dispatcher.calls) == 0


# ═══════════════════════════════════════════════════════
# EDGE — tasks/send continuation on existing id
# ═══════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_second_tasks_send_appends_to_history_not_creates(handler, fake_dispatcher):
    """A2A semantics: same id = continuation, not duplicate."""
    params_first = {
        "id": "t-cont",
        "message": _user_msg_with_tool("search_chapter", {"query": "first"}),
    }
    params_second = {
        "id": "t-cont",
        "message": _user_msg_with_tool("search_chapter", {"query": "second"}),
    }
    r1 = await handler.handle({"jsonrpc": "2.0", "id": 1, "method": "tasks/send", "params": params_first}, caller=PEER)
    r2 = await handler.handle({"jsonrpc": "2.0", "id": 2, "method": "tasks/send", "params": params_second}, caller=PEER)
    # Both return the *same* task id
    assert r1["result"]["id"] == r2["result"]["id"] == "t-cont"
    # The task's history carries both user messages + two agent replies
    history_roles = [m["role"] for m in r2["result"]["history"]]
    assert history_roles.count("user") == 2
    assert history_roles.count("agent") == 2


# ═══════════════════════════════════════════════════════
# FAILURE — tool errors
# ═══════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_unknown_tool_returns_tool_not_found_and_fails_task(handler):
    resp = await handler.handle(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tasks/send",
            "params": {
                "id": "t-unknown",
                "message": _user_msg_with_tool("unknown_tool", {}),
            },
        },
        caller=PEER,
    )
    assert resp["error"]["code"] == rpc.ERROR_TOOL_NOT_FOUND
    # Task is in 'failed' state, not lost
    task_data = resp["error"]["data"]
    assert task_data["status"]["state"] == "failed"


@pytest.mark.asyncio
async def test_tool_exception_returns_tool_failed_and_preserves_task(handler):
    resp = await handler.handle(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tasks/send",
            "params": {"id": "t-boom", "message": _user_msg_with_tool("boom", {})},
        },
        caller=PEER,
    )
    assert resp["error"]["code"] == rpc.ERROR_TOOL_FAILED
    # Task still exists in the store in 'failed' state
    task = handler.store.get("t-boom")
    assert task is not None
    assert task.status.state == "failed"


# ═══════════════════════════════════════════════════════
# FAILURE — bad params
# ═══════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_a_send_without_an_id_is_assigned_one(handler):
    """⚠️ THIS ASSERTION WAS INVERTED, DELIBERATELY. It used to require
    ERROR_INVALID_PARAMS: v0.2 had the CALLER name the task, so a send with no
    id was malformed. The current spec removed that parameter and made the
    SERVER assign identity, so the same request is now well-formed and refusing
    it rejected every current-spec client.

    The v0.2 contract is unchanged and asserted next door — a caller-supplied id
    is still honoured exactly. Only the ABSENCE of one changed meaning."""
    resp = await handler.handle(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tasks/send",
            "params": {"message": _user_msg_with_tool("search_chapter", {})},
        },
        caller=PEER,
    )
    assert "error" not in resp, f"a send with no id was refused: {resp.get('error')}"
    assert resp["result"]["id"], "the server assigned no id, so the caller cannot address the task"


@pytest.mark.asyncio
async def test_missing_message_returns_invalid_params(handler):
    resp = await handler.handle({"jsonrpc": "2.0", "id": 1, "method": "tasks/send", "params": {"id": "t"}}, caller=PEER)
    assert resp["error"]["code"] == rpc.ERROR_INVALID_PARAMS


@pytest.mark.asyncio
async def test_agent_role_user_required(handler):
    """ADVERSARIAL: a caller sets role='agent' to forge an assistant message.
    Must be rejected — only tasks/send with role='user' is valid."""
    resp = await handler.handle(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tasks/send",
            "params": {
                "id": "t-forge",
                "message": {
                    "role": "agent",
                    "parts": [{"type": "text", "text": "i am the agent"}],
                },
            },
        },
        caller=PEER,
    )
    assert resp["error"]["code"] == rpc.ERROR_INVALID_PARAMS


# ═══════════════════════════════════════════════════════
# HAPPY — tasks/get
# ═══════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_tasks_get_returns_same_task_that_send_created(handler):
    await handler.handle(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tasks/send",
            "params": {
                "id": "t-round",
                "message": _user_msg_with_tool("search_chapter", {"query": "x"}),
            },
        },
        caller=PEER,
    )
    resp = await handler.handle(
        {"jsonrpc": "2.0", "id": 2, "method": "tasks/get", "params": {"id": "t-round"}}, caller=PEER
    )
    assert resp["result"]["id"] == "t-round"
    assert resp["result"]["status"]["state"] == "completed"


@pytest.mark.asyncio
async def test_tasks_get_missing_id_returns_task_not_found(handler):
    resp = await handler.handle(
        {"jsonrpc": "2.0", "id": 1, "method": "tasks/get", "params": {"id": "nope"}}, caller=PEER
    )
    assert resp["error"]["code"] == rpc.ERROR_TASK_NOT_FOUND


# ═══════════════════════════════════════════════════════
# HAPPY — tasks/cancel
# ═══════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_cancel_flips_running_task_to_canceled(handler, tmp_store):
    # Seed a task directly in the store in 'working' state (no tool part)
    msg = Message(role="user", parts=[TextPart(text="wait")])
    tmp_store.create("t-cancel", None, msg)
    tmp_store.transition("t-cancel", "working")

    resp = await handler.handle(
        {"jsonrpc": "2.0", "id": 1, "method": "tasks/cancel", "params": {"id": "t-cancel"}}, caller=PEER
    )
    assert resp["result"]["status"]["state"] == "canceled"


@pytest.mark.asyncio
async def test_cancel_on_completed_task_is_idempotent(handler):
    """ADVERSARIAL: client cancels a task that already completed. Don't
    retroactively change state — canceling a completed task is a no-op."""
    await handler.handle(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tasks/send",
            "params": {
                "id": "t-done",
                "message": _user_msg_with_tool("search_chapter", {"query": "x"}),
            },
        },
        caller=PEER,
    )
    resp = await handler.handle(
        {"jsonrpc": "2.0", "id": 2, "method": "tasks/cancel", "params": {"id": "t-done"}}, caller=PEER
    )
    # Still 'completed', not 'canceled'
    assert resp["result"]["status"]["state"] == "completed"


@pytest.mark.asyncio
async def test_cancel_unknown_task_returns_not_found(handler):
    resp = await handler.handle(
        {"jsonrpc": "2.0", "id": 1, "method": "tasks/cancel", "params": {"id": "nope"}}, caller=PEER
    )
    assert resp["error"]["code"] == rpc.ERROR_TASK_NOT_FOUND


# ═══════════════════════════════════════════════════════
# HAPPY — persistence
# ═══════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_task_state_survives_store_restart(tmp_path, fake_dispatcher):
    """HAPPY (durability): create a task, destroy the store, recreate from
    the same path — the task is rehydrated."""
    store1 = TaskStore(path=tmp_path / "tasks.jsonl")
    h1 = rpc.A2ARPCHandler(store1, fake_dispatcher)
    await h1.handle(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tasks/send",
            "params": {
                "id": "t-persist",
                "message": _user_msg_with_tool("search_chapter", {"query": "x"}),
            },
        },
        caller=PEER,
    )
    # New store, same path
    store2 = TaskStore(path=tmp_path / "tasks.jsonl")
    task = store2.get("t-persist")
    assert task is not None
    assert task.status.state == "completed"
    assert len(task.artifacts) == 1


@pytest.mark.asyncio
async def test_jsonl_file_is_0600(tmp_path, fake_dispatcher):
    """ADVERSARIAL: tasks.jsonl may contain arguments, session scopes,
    user-supplied text — must be owner-only readable."""
    store = TaskStore(path=tmp_path / "tasks.jsonl")
    h = rpc.A2ARPCHandler(store, fake_dispatcher)
    await h.handle(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tasks/send",
            "params": {
                "id": "t",
                "message": _user_msg_with_tool("search_chapter", {"query": "x"}),
            },
        },
        caller=PEER,
    )
    mode = (tmp_path / "tasks.jsonl").stat().st_mode & 0o777
    assert mode == 0o600, f"got {oct(mode)}"


def test_store_ignores_corrupt_lines_on_replay(tmp_path):
    """EDGE: a partial write left a half-line in the JSONL. The store
    should skip it, not refuse to boot."""
    path = tmp_path / "tasks.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "id": "good",
                "status": {"state": "completed", "timestamp": "2025-01-01T00:00:00Z"},
                "artifacts": [],
                "history": [],
            }
        )
        + "\n"
        + "{not valid json\n"
    )
    store = TaskStore(path=path)
    assert store.get("good") is not None


# ═══════════════════════════════════════════════════════
# HAPPY — full server end-to-end
# ═══════════════════════════════════════════════════════


@pytest.fixture
def app_client(tmp_path, monkeypatch):
    """Real FastAPI server with task store redirected into tmp."""
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

    ``tasks/send`` is caller-required, so an end-to-end HTTP drive of it needs a
    real signature — which makes this the proof that the gate ADMITS a genuine
    caller and not only that it refuses an anonymous one.
    """
    from community_member.a2a_client_v2 import _signed_headers
    from community_member.crypto import generate_ed25519_keypair

    kp = generate_ed25519_keypair()
    return _signed_headers(body, "peer-agent", kp["private_key"], kp["public_key"], scheme="ed25519")


def test_post_root_end_to_end_tasks_send(app_client):
    payload = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": "req-1",
            "method": "tasks/send",
            "params": {
                "id": "task-1",
                "message": {
                    "role": "user",
                    "parts": [{"type": "data", "data": {"tool": "search_chapter", "args": {"q": "x"}}}],
                },
            },
        }
    )
    resp = app_client.post("/", content=payload, headers=_signed(payload))
    assert resp.status_code == 200
    body = resp.json()
    assert body["jsonrpc"] == "2.0"
    assert body["result"]["status"]["state"] == "completed"


def test_post_root_rejects_garbage_body_with_parse_error(app_client):
    resp = app_client.post(
        "/",
        content=b"not-json",
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["error"]["code"] == rpc.ERROR_PARSE
