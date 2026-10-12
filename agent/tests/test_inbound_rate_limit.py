"""How much work one caller may create on this agent, per window.

``a2a_auth`` stops at attribution: it proves possession of a key and says
outright that it "is not an allowlist". Anyone can mint an Ed25519 keypair, so a
listed agent holding a provider key can be driven by a stranger — one signed
send at a time, without limit. Its own docstring names the stake ("it spends
their money") and stops at identifying who is spending it. These tests cover
the control that bounds how fast.
"""

from __future__ import annotations

import pytest

from community_member import a2a_auth, inbound_rate


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    for var in (inbound_rate.MAX_ENV_VAR, inbound_rate.WINDOW_ENV_VAR):
        monkeypatch.delenv(var, raising=False)
    inbound_rate.reset()
    yield
    inbound_rate.reset()


def test_a_caller_is_allowed_up_to_the_limit_then_refused(monkeypatch):
    monkeypatch.setenv(inbound_rate.MAX_ENV_VAR, "3")
    for i in range(3):
        allowed, remaining, retry = inbound_rate.check("key:peer-a", now=100.0)
        assert allowed, f"request {i + 1} should be allowed"
        assert remaining == 2 - i
        assert retry == 0.0

    allowed, remaining, retry = inbound_rate.check("key:peer-a", now=100.0)
    assert not allowed
    assert remaining == 0
    assert retry > 0, "a refusal must say when to come back"


def test_a_refused_request_is_not_counted(monkeypatch):
    """Otherwise every retry extends the window and a 60s limit becomes an
    indefinite ban whose length depends on the attacker's patience."""
    monkeypatch.setenv(inbound_rate.MAX_ENV_VAR, "1")
    monkeypatch.setenv(inbound_rate.WINDOW_ENV_VAR, "10")
    assert inbound_rate.check("key:peer-a", now=0.0)[0] is True
    for _ in range(5):
        assert inbound_rate.check("key:peer-a", now=1.0)[0] is False
    # The single counted hit ages out at t=10 regardless of the five refusals.
    assert inbound_rate.check("key:peer-a", now=10.1)[0] is True


def test_the_window_slides(monkeypatch):
    monkeypatch.setenv(inbound_rate.MAX_ENV_VAR, "2")
    monkeypatch.setenv(inbound_rate.WINDOW_ENV_VAR, "60")
    assert inbound_rate.check("key:p", now=0.0)[0] is True
    assert inbound_rate.check("key:p", now=30.0)[0] is True
    assert inbound_rate.check("key:p", now=31.0)[0] is False
    # t=61 drops the t=0 hit only.
    assert inbound_rate.check("key:p", now=61.0)[0] is True
    assert inbound_rate.check("key:p", now=62.0)[0] is False


def test_one_caller_cannot_exhaust_another(monkeypatch):
    """A stranger can only ever occupy their own bucket. If this fails, the
    limiter becomes a denial-of-service tool against legitimate peers."""
    monkeypatch.setenv(inbound_rate.MAX_ENV_VAR, "1")
    assert inbound_rate.check("key:attacker", now=0.0)[0] is True
    assert inbound_rate.check("key:attacker", now=0.0)[0] is False
    assert inbound_rate.check("key:honest-peer", now=0.0)[0] is True


def test_a_claimed_agent_id_cannot_key_a_bucket():
    """The bucket is keyed on the PROVEN did_key. agent_id travels alongside it
    unverified, so keying on it would let a caller spend somebody else's quota
    — or dodge their own by claiming a new name each request."""
    proven = inbound_rate.caller_bucket("did:key:zProven", "1.2.3.4")
    assert proven == "key:did:key:zProven"
    # No key: falls back to the peer address, and the two namespaces cannot
    # collide even if an address were echoed as a key.
    assert inbound_rate.caller_bucket(None, "1.2.3.4") == "peer:1.2.3.4"
    assert inbound_rate.caller_bucket("", None) == "peer:unknown"


def test_unidentifiable_callers_share_a_bucket_rather_than_being_waved_through():
    """Requests with neither identity are indistinguishable from each other;
    counting them together is the honest reading, and counting them not at all
    would be a hole wide enough to drive the whole attack through."""
    assert inbound_rate.caller_bucket(None, None) == "peer:unknown"


def test_reads_are_not_rate_limited_and_sends_are():
    """The same axis a2a_auth draws its line on: reads cost no provider credit
    and are a legitimate peer's polling flow; a send runs tools and spends. If
    this inverts, either the limiter protects nothing or polling breaks."""
    assert a2a_auth.requires_caller("tasks/send") is True
    assert a2a_auth.requires_caller("tasks/sendSubscribe") is True
    assert a2a_auth.requires_caller("tasks/get") is False
    assert a2a_auth.requires_caller("tasks/resubscribe") is False


def test_a_typo_in_the_limit_falls_back_rather_than_disabling_the_control(monkeypatch):
    monkeypatch.setenv(inbound_rate.MAX_ENV_VAR, "not-a-number")
    assert inbound_rate.limits()[0] == inbound_rate.DEFAULT_MAX_REQUESTS
    monkeypatch.setenv(inbound_rate.MAX_ENV_VAR, "0")
    assert inbound_rate.limits()[0] == inbound_rate.DEFAULT_MAX_REQUESTS
    monkeypatch.setenv(inbound_rate.MAX_ENV_VAR, "-5")
    assert inbound_rate.limits()[0] == inbound_rate.DEFAULT_MAX_REQUESTS
    monkeypatch.setenv(inbound_rate.WINDOW_ENV_VAR, "nope")
    assert inbound_rate.limits()[1] == inbound_rate.DEFAULT_WINDOW_S


def test_the_bucket_map_cannot_grow_without_bound(monkeypatch):
    """An attacker rotating keys must not turn the limiter into the memory leak
    it was added to prevent."""
    monkeypatch.setenv(inbound_rate.MAX_ENV_VAR, "1")
    monkeypatch.setenv(inbound_rate.WINDOW_ENV_VAR, "1")
    for i in range(inbound_rate._MAX_BUCKETS + 200):
        inbound_rate.check(f"key:rotating-{i}", now=float(i))
    assert len(inbound_rate._hits) <= inbound_rate._MAX_BUCKETS


# ── end to end, over HTTP, through the real endpoint ────────────────────────


@pytest.fixture
def rpc_client(tmp_path, monkeypatch):
    """The real app, with the task store redirected into tmp.

    Mirrors the fixture in test_a2a_rpc.py. Driven over HTTP because the limiter
    has to sit in front of the dispatcher: a unit test of the counter cannot
    show that a refused request never reached the tools it would have run.
    """
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

    executed: list[str] = []

    class FakeAgent:
        AGENT_TOOLS = [{"type": "function", "function": {"name": "search_chapter", "description": ""}}]

        async def execute_tool(self, name, args):
            # Recorded so a refusal can be shown to have run NO work — the
            # whole point of refusing before the dispatcher.
            executed.append(name)
            return "{}"

    client = TestClient(create_app(cfg, agent=FakeAgent()))
    client.executed = executed  # type: ignore[attr-defined]
    return client


def _one_peer_signer():
    """Headers from ONE fixed peer, reused across requests.

    The helper in test_a2a_rpc.py mints a fresh keypair per call, which would
    put every request in its own bucket and show nothing.
    """
    from community_member.a2a_client_v2 import _signed_headers
    from community_member.crypto import generate_ed25519_keypair

    kp = generate_ed25519_keypair()

    def sign(body: str) -> dict[str, str]:
        return _signed_headers(body, "peer-agent", kp["private_key"], kp["public_key"], scheme="ed25519")

    return sign


def _send_payload(task_id: str) -> str:
    import json

    return json.dumps(
        {
            "jsonrpc": "2.0",
            "id": task_id,
            "method": "tasks/send",
            "params": {
                "id": task_id,
                "message": {
                    "role": "user",
                    "parts": [{"type": "data", "data": {"tool": "search_chapter", "args": {"q": "x"}}}],
                },
            },
        }
    )


def test_a_genuine_peer_is_served_up_to_the_limit_then_gets_429(rpc_client, monkeypatch):
    """The failure this prevents: a stranger mints a keypair, signs, and drives
    the agent's tools — and its provider credit — without limit."""
    from community_member.a2a_rpc import ERROR_RATE_LIMITED

    monkeypatch.setenv(inbound_rate.MAX_ENV_VAR, "2")
    inbound_rate.reset()
    sign = _one_peer_signer()

    for i in range(2):
        payload = _send_payload(f"task-{i}")
        resp = rpc_client.post("/", content=payload, headers=sign(payload))
        assert resp.status_code == 200, resp.text
        assert resp.json()["result"]["status"]["state"] == "completed"

    payload = _send_payload("task-over")
    resp = rpc_client.post("/", content=payload, headers=sign(payload))
    assert resp.status_code == 429
    assert resp.headers.get("Retry-After"), "an HTTP client needs to be told when to retry"
    body = resp.json()
    assert body["error"]["code"] == ERROR_RATE_LIMITED, "an A2A peer parses the envelope, not the status"
    assert "rate limit" in body["error"]["message"]

    # The refused request ran nothing: the limiter sits in FRONT of the
    # dispatcher, so no tool executed and no provider credit could be spent.
    assert rpc_client.executed == ["search_chapter", "search_chapter"]


def test_reads_keep_working_while_a_sender_is_throttled(rpc_client, monkeypatch):
    """A throttled peer must still be able to poll. If a read were limited too,
    the limiter would break the flow the open-read decision exists to serve."""
    import json

    monkeypatch.setenv(inbound_rate.MAX_ENV_VAR, "1")
    inbound_rate.reset()
    sign = _one_peer_signer()

    payload = _send_payload("task-a")
    assert rpc_client.post("/", content=payload, headers=sign(payload)).status_code == 200
    payload2 = _send_payload("task-b")
    assert rpc_client.post("/", content=payload2, headers=sign(payload2)).status_code == 429

    read = json.dumps({"jsonrpc": "2.0", "id": "r1", "method": "tasks/get", "params": {"id": "task-a"}})
    resp = rpc_client.post("/", content=read)
    assert resp.status_code == 200, "an unauthenticated read is open by decision and must stay served"
