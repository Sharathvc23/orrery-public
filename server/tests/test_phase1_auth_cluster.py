"""Phase-1 auth cluster — verified-caller attribution + private-chronicle gate.

Each handler here used to trust a body-claimed / header-claimed identity, or
served a member's private action log to any caller. All three now derive the
actor ONLY from the middleware-set ``request.state.agent_id`` (populated after a
valid Ed25519 signature), via ``_resolve_caller``.

  C3  POST /api/feedback           — feedback is attributed to the verified
                                      caller, NOT the body's ``agent_id`` (else a
                                      member forges receipts in another's ledger).
  C5  GET  /api/agents/{id}/aae-events
                                    — an 'internal' (non-public) chronicle is the
                                      agent's private log: owner or admin only. A
                                      'public' chronicle is an explicit opt-in and
                                      stays open.
  C6  POST /api/projection/update  — a projection edit must come from the agent
                                      itself; an empty/mismatched caller is 403
                                      (the spoofable X-Agent-ID fallback is gone).

Classification: ADVERSARIAL (attacker asserts another principal's identity).

Each test is written to FAIL on the pre-fix code (body/header-trusting) and pass
only once identity is taken from the verified state.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest


def _req(caller: str, *, headers: dict | None = None):
    """A stand-in Request whose verified identity is ``caller`` (empty = unsigned).

    Mirrors the middleware contract: ``request.state.agent_id`` is set ONLY on a
    valid signature. ``headers`` carries anything a client could spoof.
    """
    req = MagicMock()
    req.state.agent_id = caller
    req.headers = headers or {}
    return req


# ── C3 — feedback is attributed to the verified caller, not the body ──


@pytest.mark.asyncio
async def test_C3_feedback_attributed_to_verified_caller_not_body(monkeypatch):
    """A signed ``attacker`` submits feedback whose body claims to be ``victim``.
    The recorded actor must be ``attacker`` (the verified caller)."""
    import chapter_agent

    captured: dict = {}

    async def fake_record_feedback(action_id, action_type, signal, actor, meta):
        captured["actor"] = actor

    monkeypatch.setattr(chapter_agent.outcome_tracker, "record_feedback", fake_record_feedback)

    body = chapter_agent.FeedbackSubmission(
        action_id="act-1",
        action_type="intro",
        signal="positive",
        agent_id="victim",  # spoofed body claim
    )
    result = await chapter_agent.submit_feedback(body, _req("attacker"))

    assert result["recorded"] is True
    assert captured["actor"] == "attacker", "feedback was attributed to the body-claimed id, not the verified caller"


@pytest.mark.asyncio
async def test_C3_unsigned_feedback_is_rejected_and_records_nothing(monkeypatch):
    """No verified caller → 401, and NOTHING is recorded. The middleware already
    gates POST /api/feedback (requires_auth=True); this is the handler's own
    defense-in-depth, kept consistent with the C6 projection gate so the two
    per-agent writes agree on the empty-caller case."""
    from fastapi.responses import JSONResponse

    import chapter_agent

    captured: dict = {}

    async def fake_record_feedback(action_id, action_type, signal, actor, meta):
        captured["actor"] = actor  # must never be reached

    monkeypatch.setattr(chapter_agent.outcome_tracker, "record_feedback", fake_record_feedback)

    body = chapter_agent.FeedbackSubmission(action_id="a", action_type="t", signal="positive", agent_id="victim")
    resp = await chapter_agent.submit_feedback(body, _req(""))
    assert isinstance(resp, JSONResponse)
    assert resp.status_code == 401
    assert "actor" not in captured, "unsigned feedback was recorded despite no verified caller"


# ── C5 — private (internal) chronicle is owner/admin-only; public stays open ──


def _mock_aae_deps(monkeypatch, *, chronicle_public: bool):
    """Give the aae-events handler a known did:key and a config row carrying the
    requested visibility, with no receipts (the gate fires before the fetch)."""
    import arp
    import chapter_agent

    monkeypatch.setattr(arp, "did_key_for_member", lambda aid: f"did:key:{aid}")

    async def fake_pg_request(method, table, params=None, body=None):
        if table == "agents":
            return [{"config": {"chronicle_public": chronicle_public}}]
        return []  # arp_receipts

    monkeypatch.setattr(chapter_agent, "pg_request", fake_pg_request)


@pytest.mark.asyncio
async def test_C5_internal_chronicle_rejects_non_owner(monkeypatch):
    """attacker reading victim's non-public chronicle gets the UNKNOWN-AGENT
    answer — an empty list, not a 403 that confirms the chronicle exists."""
    import chapter_agent

    _mock_aae_deps(monkeypatch, chronicle_public=False)
    monkeypatch.setattr(chapter_agent.auth_verify, "check_admin_token_header", lambda h: False)

    result = await chapter_agent.agent_aae_events("victim", _req("attacker"), limit=50)
    assert result == {"events": [], "total": 0, "agent_id": "victim"}
    assert "principal_did" not in result and "classification" not in result


@pytest.mark.asyncio
async def test_C5_internal_chronicle_rejects_anonymous(monkeypatch):
    """No verified caller reading a non-public chronicle: same empty answer an
    unknown id gets. The earlier 403 ("this agent's chronicle is internal")
    told a stranger the id exists and has a private log, while an unknown id
    answered 200 and empty — a membership oracle by status code."""
    import chapter_agent

    _mock_aae_deps(monkeypatch, chronicle_public=False)
    monkeypatch.setattr(chapter_agent.auth_verify, "check_admin_token_header", lambda h: False)

    result = await chapter_agent.agent_aae_events("victim", _req(""), limit=50)
    assert result == {"events": [], "total": 0, "agent_id": "victim"}


@pytest.mark.asyncio
async def test_C5_internal_chronicle_allows_owner(monkeypatch):
    """The agent reading its OWN non-public chronicle → 200."""
    import chapter_agent

    _mock_aae_deps(monkeypatch, chronicle_public=False)
    monkeypatch.setattr(chapter_agent.auth_verify, "check_admin_token_header", lambda h: False)

    result = await chapter_agent.agent_aae_events("alice", _req("alice"), limit=50)
    assert result["agent_id"] == "alice"
    assert result["classification"] == "internal"


@pytest.mark.asyncio
async def test_C5_internal_chronicle_allows_admin(monkeypatch):
    """A valid admin token reads any non-public chronicle → 200 (break-glass)."""
    import chapter_agent

    _mock_aae_deps(monkeypatch, chronicle_public=False)
    monkeypatch.setattr(chapter_agent.auth_verify, "check_admin_token_header", lambda h: True)

    result = await chapter_agent.agent_aae_events("victim", _req("operator"), limit=50)
    assert result["agent_id"] == "victim"


@pytest.mark.asyncio
async def test_C5_public_chronicle_stays_open(monkeypatch):
    """A PUBLIC chronicle is an explicit opt-in — any caller (even anonymous)
    may read it. The gate must NOT fire when chronicle_public is true."""
    import chapter_agent

    _mock_aae_deps(monkeypatch, chronicle_public=True)
    monkeypatch.setattr(chapter_agent.auth_verify, "check_admin_token_header", lambda h: False)

    result = await chapter_agent.agent_aae_events("alice", _req(""), limit=50)
    assert result["agent_id"] == "alice"
    assert result["classification"] == "public"


# ── C6 — projection update requires the verified agent itself ──


@pytest.mark.asyncio
async def test_C6_projection_update_rejects_cross_agent(monkeypatch):
    """A signed attacker editing victim's projection → 403 mismatch."""
    from fastapi.responses import JSONResponse

    import chapter_agent

    body = chapter_agent.ProjectionUpdate(agent_id="victim", availability="always")
    resp = await chapter_agent.update_projection_endpoint(body, _req("attacker"))
    assert isinstance(resp, JSONResponse)
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_C6_projection_update_rejects_anonymous(monkeypatch):
    """No verified caller → 403, never a fall-through to the body's agent_id."""
    from fastapi.responses import JSONResponse

    import chapter_agent

    body = chapter_agent.ProjectionUpdate(agent_id="victim", availability="always")
    resp = await chapter_agent.update_projection_endpoint(body, _req(""))
    assert isinstance(resp, JSONResponse)
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_C6_projection_update_allows_self(monkeypatch):
    """The agent editing its OWN projection passes the auth gate (it then hits
    the member lookup — a 404 here proves we got PAST the 403, which is the point
    of this test: self is not rejected on identity)."""
    import chapter_agent

    body = chapter_agent.ProjectionUpdate(agent_id="alice", availability="always")
    resp = await chapter_agent.update_projection_endpoint(body, _req("alice"))
    status = getattr(resp, "status_code", 200)
    assert status != 403, "the agent was rejected editing its own projection"
