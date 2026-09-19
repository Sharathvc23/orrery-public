"""P0/M-O1 — intents surface PII-enumeration + IDOR holes (same class as that change).

The fix covered POST /api/intents/respond but the sibling routes kept
the same vuln class:

  * GET /api/intents/introductions/{agent_id} — unauthenticated; reaches
    consent_gate.get_introductions -> check_mutual_consent (the identity/PII
    boundary). A principal may read ONLY their own introductions.
  * GET /api/intents/{intent_id} — unauthenticated full-intent disclosure
    (requester_agent_id + raw intent_text). Must require auth and authorize the
    caller against the intent (requester or a matched responder).
  * DELETE /api/intents/{intent_id} — IDOR: trusted the ?agent_id query param
    as the owner. Must derive the owner from the verified caller.
  * GET /api/intents/pending/{agent_id} — same path-param-no-auth pattern.

Classification: ADVERSARIAL (unauth PII enumeration / cross-principal cancel).
"""

from __future__ import annotations

import os

os.environ.setdefault("AGENT_ID", "test-chapter")
os.environ.setdefault("AGENT_NAME", "Test Chapter")

import json  # noqa: E402

import pytest  # noqa: E402

import chapter_agent  # noqa: E402
import intents as intents_mod  # noqa: E402


def _status(resp) -> int:
    return getattr(resp, "status_code", 200)


def _body(resp) -> dict:
    if isinstance(resp, dict):
        return resp
    b = resp.body
    return json.loads(b.decode() if isinstance(b, bytes) else b)


class _State:
    def __init__(self, agent_id=""):
        self.agent_id = agent_id


class _Req:
    def __init__(self, state_agent_id="", header_agent_id=""):
        self.state = _State(state_agent_id)
        self.headers = {"X-Agent-ID": header_agent_id} if header_agent_id else {}


# ── introductions: own-only, verified caller ─────────────────────────


@pytest.mark.asyncio
async def test_introductions_unauth_rejected(monkeypatch):
    hit = {"n": 0}

    async def fake_get(_aid):
        hit["n"] += 1
        return []

    monkeypatch.setattr(chapter_agent.consent_gate, "get_introductions", fake_get)
    resp = await chapter_agent.get_introductions_endpoint("victim", _Req(header_agent_id="victim"))
    assert _status(resp) == 401
    assert hit["n"] == 0, "reached the PII-reveal code without a verified caller"


@pytest.mark.asyncio
async def test_introductions_uses_caller_not_path(monkeypatch):
    seen = {}

    async def fake_get(aid):
        seen["aid"] = aid
        return [{"intro": "x"}]

    monkeypatch.setattr(chapter_agent.consent_gate, "get_introductions", fake_get)
    # path says 'victim', verified caller is 'alice' — must use alice
    await chapter_agent.get_introductions_endpoint("victim", _Req(state_agent_id="alice"))
    assert seen["aid"] == "alice"


# ── pending: own-only, verified caller ───────────────────────────────


@pytest.mark.asyncio
async def test_pending_unauth_rejected(monkeypatch):
    hit = {"n": 0}

    async def fake_pending(_aid):
        hit["n"] += 1
        return []

    monkeypatch.setattr(chapter_agent.consent_gate, "get_pending_for_agent", fake_pending)
    resp = await chapter_agent.get_pending_intents("victim", _Req(header_agent_id="victim"))
    assert _status(resp) == 401
    assert hit["n"] == 0


@pytest.mark.asyncio
async def test_pending_uses_caller_not_path(monkeypatch):
    seen = {}

    async def fake_pending(aid):
        seen["aid"] = aid
        return []

    monkeypatch.setattr(chapter_agent.consent_gate, "get_pending_for_agent", fake_pending)
    await chapter_agent.get_pending_intents("victim", _Req(state_agent_id="alice"))
    assert seen["aid"] == "alice"


# ── GET /api/intents/{id}: auth + authorize against the intent ───────


@pytest.mark.asyncio
async def test_get_intent_detail_endpoint_unauth_rejected(monkeypatch):
    hit = {"n": 0}

    async def fake_detail(_iid, _caller):
        hit["n"] += 1
        return {}

    monkeypatch.setattr(chapter_agent.intents, "get_intent_detail", fake_detail)
    resp = await chapter_agent.get_intent_detail("intent-1", _Req(header_agent_id="victim"))
    assert _status(resp) == 401
    assert hit["n"] == 0


@pytest.mark.asyncio
async def test_get_intent_detail_authorizes_requester(monkeypatch):
    async def fake_supabase(method, table, params=None, body=None):
        if table == "agent_intents":
            return [{"id": "i1", "requester_agent_id": "alice", "intent_text": "secret"}]
        if table == "agent_intent_responses":
            return [{"response": "pending", "responder_agent_id": "bob", "responder_chapter_id": "c", "created_at": "t"}]
        return None

    monkeypatch.setattr(intents_mod, "_pg_request", fake_supabase)
    # requester sees it
    out = await intents_mod.get_intent_detail("i1", "alice")
    assert out.get("intent_text") == "secret"
    # responder sees it
    out2 = await intents_mod.get_intent_detail("i1", "bob")
    assert out2.get("intent_text") == "secret"


@pytest.mark.asyncio
async def test_get_intent_detail_blocks_unrelated_caller(monkeypatch):
    async def fake_supabase(method, table, params=None, body=None):
        if table == "agent_intents":
            return [{"id": "i1", "requester_agent_id": "alice", "intent_text": "secret", "linkedin_url": "x"}]
        if table == "agent_intent_responses":
            return [{"response": "pending", "responder_agent_id": "bob", "responder_chapter_id": "c", "created_at": "t"}]
        return None

    monkeypatch.setattr(intents_mod, "_pg_request", fake_supabase)
    out = await intents_mod.get_intent_detail("i1", "mallory")
    assert "intent_text" not in out, "leaked intent to an unrelated caller"
    assert out.get("error")


@pytest.mark.asyncio
async def test_get_intent_detail_does_not_leak_responder_ids(monkeypatch):
    async def fake_supabase(method, table, params=None, body=None):
        if table == "agent_intents":
            return [{"id": "i1", "requester_agent_id": "alice", "intent_text": "secret"}]
        if table == "agent_intent_responses":
            return [{"response": "pending", "responder_agent_id": "bob", "responder_chapter_id": "c", "created_at": "t"}]
        return None

    monkeypatch.setattr(intents_mod, "_pg_request", fake_supabase)
    out = await intents_mod.get_intent_detail("i1", "alice")
    assert all("responder_agent_id" not in r for r in out["responses"])


# ── DELETE /api/intents/{id}: owner = verified caller, not ?agent_id ──


@pytest.mark.asyncio
async def test_cancel_endpoint_unauth_rejected(monkeypatch):
    hit = {"n": 0}

    async def fake_cancel(_iid, _aid):
        hit["n"] += 1
        return {}

    monkeypatch.setattr(chapter_agent.intents, "cancel_intent", fake_cancel)
    resp = await chapter_agent.cancel_intent_endpoint("intent-1", _Req(header_agent_id="victim"))
    assert _status(resp) == 401
    assert hit["n"] == 0


@pytest.mark.asyncio
async def test_cancel_endpoint_uses_verified_caller_not_query(monkeypatch):
    seen = {}

    async def fake_cancel(iid, aid):
        seen["aid"] = aid
        return {"cancelled": True}

    monkeypatch.setattr(chapter_agent.intents, "cancel_intent", fake_cancel)
    # verified caller is alice; the IDOR would pass a victim id — must use alice
    await chapter_agent.cancel_intent_endpoint("intent-1", _Req(state_agent_id="alice"))
    assert seen["aid"] == "alice"
