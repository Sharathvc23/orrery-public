"""P0 — consent/PII bypass on /api/intents/respond.

`check_mutual_consent` is "the ONLY place where identity crosses the privacy
boundary" (requester name / interests / linkedin_url). Two holes let any
registered agent walk through it:

  1. the endpoint took the responder from the request BODY, never reconciling
     it with the signed caller — so you could respond *as* anyone; and
  2. `respond_to_intent` hardcoded ``mutual_consent: True`` on any ``accept``
     with no check that the responder was ever matched to the intent — so you
     could accept an arbitrary intent and unlock its requester's PII.

Contract locked here:
  * the responder is the VERIFIED caller (request.state.agent_id), never the
    body;
  * consent (and therefore identity reveal) is granted only to a responder who
    was genuinely matched to the intent (a response row exists) and accepts;
  * an unmatched responder gets no consent and no PII.

Classification: ADVERSARIAL (attacker harvests requester PII for arbitrary intents).
"""

from __future__ import annotations

import os

os.environ.setdefault("AGENT_ID", "test-chapter")
os.environ.setdefault("AGENT_NAME", "Test Chapter")

import json  # noqa: E402

import pytest  # noqa: E402

import chapter_agent  # noqa: E402
import consent_gate  # noqa: E402


def _status(resp) -> int:
    return getattr(resp, "status_code", 200)


def _read_body(resp) -> dict:
    if isinstance(resp, dict):
        return resp
    body = resp.body
    if isinstance(body, bytes):
        body = body.decode()
    return json.loads(body)


class _State:
    def __init__(self, agent_id: str = "") -> None:
        self.agent_id = agent_id


class _Req:
    def __init__(self, state_agent_id: str = "", header_agent_id: str = "") -> None:
        self.state = _State(state_agent_id)
        self.headers = {"X-Agent-ID": header_agent_id} if header_agent_id else {}


# ── consent_gate.respond_to_intent — matched-responder gate ──────────


@pytest.mark.asyncio
async def test_respond_rejects_unmatched_responder(monkeypatch):
    """An agent who was never matched to the intent (no response row) gets no
    consent — and we must NOT PATCH or reveal anything."""
    calls = {"get": [], "patch": []}

    async def fake_supabase(method, table, params=None, body=None):
        if method == "GET":
            calls["get"].append((table, params))
            return []  # no matching response row for this responder
        if method == "PATCH":
            calls["patch"].append((table, body))
        return None

    monkeypatch.setattr(consent_gate, "_pg_request", fake_supabase)

    result = await consent_gate.respond_to_intent("intent-1", "attacker", "accept")
    assert result.get("mutual_consent") is False
    assert calls["patch"] == [], "must not mutate state for an unmatched responder"


@pytest.mark.asyncio
async def test_respond_accept_by_matched_responder_grants_consent(monkeypatch):
    """A genuinely-matched responder who accepts achieves mutual consent."""
    async def fake_supabase(method, table, params=None, body=None):
        if method == "GET":
            return [{"id": "resp-1", "response": "pending"}]  # matched
        return None

    monkeypatch.setattr(consent_gate, "_pg_request", fake_supabase)

    result = await consent_gate.respond_to_intent("intent-1", "matched-bob", "accept")
    assert result.get("mutual_consent") is True


@pytest.mark.asyncio
async def test_decline_by_matched_responder_does_not_grant_consent(monkeypatch):
    async def fake_supabase(method, table, params=None, body=None):
        if method == "GET":
            return [{"id": "resp-1", "response": "pending"}]
        return None

    monkeypatch.setattr(consent_gate, "_pg_request", fake_supabase)

    result = await consent_gate.respond_to_intent("intent-1", "matched-bob", "decline")
    assert result.get("mutual_consent") is False


# ── endpoint — responder is the verified caller, not the body ────────


@pytest.mark.asyncio
async def test_respond_endpoint_uses_verified_caller_not_body(monkeypatch):
    """Spoofing responder_agent_id in the body must not work — the responder
    passed downstream is the verified caller."""
    seen = {}

    async def fake_respond(intent_id, responder_agent_id, response, counter_text=""):
        seen["responder"] = responder_agent_id
        return {"mutual_consent": False, "response": response}

    monkeypatch.setattr(chapter_agent.consent_gate, "respond_to_intent", fake_respond)

    req = chapter_agent.ConsentResponse(
        intent_id="intent-1", responder_agent_id="victim", response="accept"
    )
    request = _Req(state_agent_id="alice", header_agent_id="victim")
    await chapter_agent.respond_to_intent_endpoint(req, request)

    assert seen["responder"] == "alice", "endpoint trusted the body responder, not the verified caller"


@pytest.mark.asyncio
async def test_respond_endpoint_401_without_verified_caller(monkeypatch):
    called = {"hit": False}

    async def fake_respond(*a, **k):
        called["hit"] = True
        return {"mutual_consent": False}

    monkeypatch.setattr(chapter_agent.consent_gate, "respond_to_intent", fake_respond)

    req = chapter_agent.ConsentResponse(
        intent_id="intent-1", responder_agent_id="victim", response="accept"
    )
    request = _Req(state_agent_id="", header_agent_id="victim")  # spoofed header, no verified state
    resp = await chapter_agent.respond_to_intent_endpoint(req, request)

    assert _status(resp) == 401
    assert called["hit"] is False, "must not reach the consent gate without a verified caller"
