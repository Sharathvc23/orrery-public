"""
W12 integration test — a fully A2A-conformant member.

Runs two code paths end-to-end against the real FastAPI app:

  1. Card fetch: client GETs /.well-known/agent.json and discovers the
     agent's capabilities. Chooses a skill, chooses a tool.
  2. Tasks/send: client POSTs a JSON-RPC tasks/send with a DataPart
     carrying {tool, args}. Server dispatches to the agent, returns a
     Task with a completed status and a tool-result artifact.
  3. Tasks/sendSubscribe: client POSTs the same shape but as a stream.
     Client parses SSE frames and watches state transitions.
  4. Tasks/get + tasks/cancel: lifecycle coverage.
  5. Envelope errors are typed JSON-RPC errors, not HTTP 500s.

These are the kind of cross-module regressions unit tests can miss —
this test holds all 4 days' output together.

Classification: HAPPY / EDGE / ADVERSARIAL
"""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from community_member.a2a_client_v2 import A2AClient, A2AClientError
from community_member.a2a_models import AgentCard, Task


@pytest.fixture
def wired_app(tmp_path, monkeypatch):
    """Real server wired to a fake agent. Monkeypatches the task store
    path so one test's state doesn't bleed into the next."""
    from community_member import task_store as ts_mod
    from community_member.config import Config
    from community_member.crypto import generate_keypair
    from community_member.server import create_app

    monkeypatch.setattr(ts_mod, "TASK_STORE_PATH", tmp_path / "tasks.jsonl")

    cfg = Config()
    cfg.agent_id = "alice"
    cfg.name = "Alice"
    cfg.description = "A test member"
    cfg.skills = ["rust", "distributed-systems"]
    cfg.chapter_url = "https://chapter.example"
    cfg.api_key = "x" * 32
    kp = generate_keypair()
    cfg.private_key = kp["private_key"]
    cfg.public_key = kp["public_key"]

    class FakeAgent:
        AGENT_TOOLS = [
            {
                "type": "function",
                "function": {"name": "search_chapter", "description": "find peers"},
            },
            {
                "type": "function",
                "function": {"name": "submit_intent", "description": "post an intent"},
            },
        ]

        async def execute_tool(self, name, args):
            return json.dumps({"tool": name, "args": args, "ok": True})

    return TestClient(create_app(cfg, agent=FakeAgent()))


class _TestClientAdapter:
    """Thin shim so A2AClient's code (which uses httpx.Client methods)
    works against FastAPI's TestClient. The two have compatible APIs but
    the constructor differs — we reroute the base_url."""

    def __init__(self, tc: TestClient) -> None:
        self._tc = tc

    def get(self, url, **kw):
        return self._tc.get(url, **kw)

    def post(self, url, **kw):
        # Strip the base from the url
        return self._tc.post(_path_of(url), **kw)

    def stream(self, method, url, **kw):
        return self._tc.stream(method, _path_of(url), **kw)

    def close(self):
        pass


def _path_of(url: str) -> str:
    """Extract just the path+query from a possibly-absolute URL."""
    if url.startswith("http://") or url.startswith("https://"):
        # Testing environment: cut everything up to the 3rd slash
        parts = url.split("/", 3)
        return "/" + (parts[3] if len(parts) > 3 else "")
    return url


@pytest.fixture
def client(wired_app):
    """Build an A2AClient wired through the FastAPI TestClient transport.

    ⚠️ NOW CREDENTIALED, AND THAT IS THE INTEROP RESULT THIS FILE REPORTS.
    Sends are caller-required, so an unsigned client of ours is refused by a
    peer of ours exactly as a stock client is. Giving it a real Ed25519 keypair
    is not a test workaround — it is what a member agent calling a peer has to
    do now, and driving the whole loop that way is the proof our own client can
    still complete it.
    """
    from community_member.crypto import generate_ed25519_keypair

    kp = generate_ed25519_keypair()
    c = A2AClient(
        "http://testserver",
        agent_id="peer-agent",
        private_key=kp["private_key"],
        public_key=kp["public_key"],
        sig_scheme="ed25519",
    )
    c._client = _TestClientAdapter(wired_app)  # type: ignore[assignment]
    return c


# ═══════════════════════════════════════════════════════
# HAPPY — full discovery → invocation
# ═══════════════════════════════════════════════════════


def test_discovery_then_invocation_end_to_end(client):
    """The whole A2A loop: card fetch → skill pick → tasks/send → task result."""
    # 1) Discovery
    card = client.fetch_agent_card()
    assert isinstance(card, AgentCard)
    assert card.name == "Alice"
    # The Agent Card must carry at least the skills our tools advertise
    skill_ids = {s.id for s in card.skills}
    assert "skill.discovery" in skill_ids

    # 2) Invocation
    result = client.send_task("search_chapter", {"query": "rust"})
    task = Task.model_validate(result)
    assert task.status.state == "completed"
    assert len(task.artifacts) == 1
    # The artifact contains our agent's tool result
    data_part = task.artifacts[0].parts[0]
    assert data_part.data["tool"] == "search_chapter"


def test_streaming_end_to_end_emits_ordered_state_events(client):
    """The full streaming path through HTTP — parse each SSE frame and
    confirm we see the expected state machine (submitted → working →
    artifact → completed/final)."""
    events = list(client.stream_task("search_chapter", {"query": "rust"}))
    # Every event is a valid JSON-RPC envelope
    for e in events:
        assert e["jsonrpc"] == "2.0"
        assert "result" in e
    states = [e["result"]["status"]["state"] for e in events if "status" in e["result"]]
    assert states[0] == "submitted"
    assert "working" in states
    assert states[-1] == "completed"
    # Last event carries final: true
    assert events[-1]["result"]["final"] is True


# ═══════════════════════════════════════════════════════
# HAPPY — tasks/get + tasks/cancel round trip
# ═══════════════════════════════════════════════════════


def test_tasks_get_returns_existing_task(client):
    sent = client.send_task("search_chapter", {"query": "x"}, task_id="t-lookup")
    fetched = client.get_task("t-lookup")
    assert fetched["id"] == sent["id"]


def test_tasks_cancel_after_completion_is_idempotent(client):
    client.send_task("search_chapter", {"query": "x"}, task_id="t-can")
    canceled = client.cancel_task("t-can")
    # The task completed before cancel landed, so state is still 'completed'
    assert canceled["status"]["state"] == "completed"


# ═══════════════════════════════════════════════════════
# FAILURE — typed errors
# ═══════════════════════════════════════════════════════


def test_unknown_tool_raises_typed_client_error(client):
    with pytest.raises(A2AClientError) as excinfo:
        client.send_task("tool_that_does_not_exist", {})
    assert excinfo.value.code == -32002  # ERROR_TOOL_NOT_FOUND


def test_tasks_get_missing_raises_task_not_found(client):
    with pytest.raises(A2AClientError) as excinfo:
        client.get_task("never-existed")
    assert excinfo.value.code == -32001  # ERROR_TASK_NOT_FOUND


# ═══════════════════════════════════════════════════════
# ADVERSARIAL — protocol conformance
# ═══════════════════════════════════════════════════════


def test_agent_card_round_trips_through_wire(client):
    """ADVERSARIAL: the card we serve must validate back as an AgentCard
    using only the public (A2A-spec) schema — no hidden required fields
    that only a sibling implementation would know about."""
    # Fetch the raw JSON (bypassing our client's validation)
    raw = client._client.get(client.base_url + "/.well-known/agent.json")
    assert raw.status_code == 200
    # Round-trips through the Pydantic model
    AgentCard.model_validate(raw.json())


def test_streaming_terminates_on_tool_failure(client):
    """ADVERSARIAL: even when the tool fails, the stream must terminate
    cleanly with a failed+final frame — never leave the client hanging."""
    events = list(client.stream_task("tool_that_does_not_exist", {}))
    last = events[-1]
    assert last["result"]["status"]["state"] == "failed"
    assert last["result"]["final"] is True


def test_continuation_on_same_task_id_appends_history(client):
    """HAPPY: second tasks/send with the same id is a continuation.
    Confirmed end-to-end through the HTTP layer."""
    client.send_task("search_chapter", {"query": "first"}, task_id="t-cont")
    second = client.send_task("search_chapter", {"query": "second"}, task_id="t-cont")
    roles = [m["role"] for m in second["history"]]
    assert roles.count("user") == 2
