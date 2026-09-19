"""Skill-registry mutations must bind to the AUTH-VERIFIED caller, not a
body-claimed actor id.

Regression for the body-claim-authz vuln class across the 5 skill endpoints —
review, revoke, attest, revoke-attestation, record-use. Each derived its authz
subject (reviewer/revoker/attestor/requester/used-by) from a request-BODY field,
so any signed member could act under another identity (revoke any skill, pass the
trust-tier gate, spoof revenue attribution) by naming a privileged id in the body.
The fix binds the actor to ``request.state.agent_id`` (``_resolve_caller``); the
body field is now accepted-but-ignored. Every one of these is "actor acts on
itself", so caller-binding breaks no legitimate flow.

Mirrors test_governance_body_claim_authz.py: handlers are called directly with a
``_request(caller)`` MagicMock (auth middleware sets ``request.state.agent_id``).
"""

from __future__ import annotations

import sys
from unittest.mock import MagicMock

import pytest

import attestations  # noqa: F401  (in sys.modules for the live monkeypatch)
import chapter_agent
import governance  # noqa: F401
import skill_registry  # noqa: F401
import skill_revenue  # noqa: F401
from routes import skills


def _request(caller: str) -> MagicMock:
    req = MagicMock()
    req.state.agent_id = caller
    return req


# ── record_skill_use (revenue attribution) ──────────────────────────


@pytest.mark.asyncio
async def test_record_skill_use_unauthenticated():
    body = chapter_agent.SkillUseRequest(
        skill_version="1.0.0", used_by_agent_id="alice", tool_name="t", idempotency_key="k1"
    )
    with pytest.raises(chapter_agent.HTTPException) as exc:
        await chapter_agent.record_skill_use_endpoint("demo@1.0.0", body, _request(""))
    assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_record_skill_use_binds_to_caller(monkeypatch):
    """Revenue is attributed to the verified caller, never the body claim."""
    captured: dict = {}

    async def _rec(**k):
        captured.update(k)
        return {"billed": True}

    monkeypatch.setattr(sys.modules["skill_revenue"], "record_skill_use", _rec)
    body = chapter_agent.SkillUseRequest(
        skill_version="1.0.0", used_by_agent_id="mallory-claims-bob", tool_name="t", idempotency_key="k1"
    )
    await chapter_agent.record_skill_use_endpoint("demo@1.0.0", body, _request("alice"))
    assert captured["used_by_agent_id"] == "alice"  # caller, not the body-claimed id


# ── skill_revoke (author/leader gate) ───────────────────────────────


@pytest.mark.asyncio
async def test_skill_revoke_unauthenticated():
    body = skills.SkillRevokeRequest(revoked_by_agent_id="admin")
    with pytest.raises(chapter_agent.HTTPException) as exc:
        await skills.skill_revoke("demo@1.0.0", body, _request(""))
    assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_skill_revoke_rejects_body_claimed_leader(monkeypatch):
    """A plain member naming an admin/the author in the body cannot revoke — 403."""

    async def _get(_id):
        return {"id": "demo@1.0.0", "author_agent_id": "carol", "author_did": "did:key:zCarol"}

    revoked: list = []

    async def _rev(**k):
        revoked.append(k)
        return {}

    monkeypatch.setattr(sys.modules["skill_registry"], "get_skill", _get)
    monkeypatch.setattr(sys.modules["skill_registry"], "revoke_skill", _rev)
    monkeypatch.setattr(chapter_agent, "members", {})  # caller is an unknown plain member

    body = skills.SkillRevokeRequest(revoked_by_agent_id="admin")
    with pytest.raises(chapter_agent.HTTPException) as exc:
        await skills.skill_revoke("demo@1.0.0", body, _request("mallory"))
    assert exc.value.status_code == 403
    assert revoked == []  # the revoke never ran


# ── skill_review (identity binding) ─────────────────────────────────


@pytest.mark.asyncio
async def test_skill_review_unauthenticated():
    body = skills.SkillReviewRequest(reviewer_agent_id="bob", rating=5, signed_install_proof="proof")
    with pytest.raises(chapter_agent.HTTPException) as exc:
        await skills.skill_review("demo@1.0.0", body, _request(""))
    assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_skill_review_binds_to_caller(monkeypatch):
    """The review is recorded under the verified caller, not the body claim."""
    captured: dict = {}

    async def _review(**k):
        captured.update(k)
        return {"id": 1}

    monkeypatch.setattr(sys.modules["skill_registry"], "review_skill", _review)
    body = skills.SkillReviewRequest(reviewer_agent_id="bob", rating=5, signed_install_proof="proof")
    await skills.skill_review("demo@1.0.0", body, _request("alice"))
    assert captured["reviewer_agent_id"] == "alice"


# ── attest_skill (trust-tier gate bypass) ───────────────────────────


@pytest.mark.asyncio
async def test_attest_skill_unauthenticated():
    body = chapter_agent.SkillAttestRequest(
        attestor_agent_id="trusted-bob",
        attestor_did="did:key:zBob",
        attestor_public_key_b64="pk",
        attestation_sig_b64="sig",
        created_unix=1700000000,
    )
    with pytest.raises(chapter_agent.HTTPException) as exc:
        await chapter_agent.attest_skill("demo@1.0.0", body, _request(""))
    assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_attest_skill_tier_gate_checks_caller(monkeypatch):
    """The trust-tier gate evaluates the verified caller — not a body-claimed
    trusted id signed with the caller's own key (the bypass this closes)."""

    async def _get(_id):
        return {"id": "demo@1.0.0", "version": "1.0.0", "content_sha256": "x", "author_did": "did:key:zAuthor"}

    async def _tier(aid):
        assert aid == "mallory"  # the gate sees the CALLER, not body "trusted-bob"
        return (False, "not_trusted_tier", None)

    recorded: list = []

    async def _record(**k):
        recorded.append(k)
        return {}

    monkeypatch.setattr(sys.modules["skill_registry"], "get_skill", _get)
    monkeypatch.setattr(sys.modules["governance"], "require_trusted_tier", _tier)
    monkeypatch.setattr(sys.modules["attestations"], "record_attestation", _record)

    body = chapter_agent.SkillAttestRequest(
        attestor_agent_id="trusted-bob",
        attestor_did="did:key:zBob",
        attestor_public_key_b64="pk",
        attestation_sig_b64="sig",
        created_unix=1700000000,
    )
    with pytest.raises(chapter_agent.HTTPException) as exc:
        await chapter_agent.attest_skill("demo@1.0.0", body, _request("mallory"))
    assert exc.value.status_code == 403
    assert recorded == []  # no attestation minted


# ── revoke_skill_attestation (leader/self gate) ─────────────────────


@pytest.mark.asyncio
async def test_revoke_attestation_unauthenticated():
    body = chapter_agent.SkillRevokeAttestationRequest(attestor_agent_id="leader-bob")
    with pytest.raises(chapter_agent.HTTPException) as exc:
        await chapter_agent.revoke_skill_attestation("demo@1.0.0", "did:key:zX", body, _request(""))
    assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_revoke_attestation_rejects_body_claimed_leader(monkeypatch):
    """A plain member naming a leader in the body cannot revoke another's
    attestation — 403 (not self, not leader as the VERIFIED caller)."""

    async def _get(_id):
        return {"id": "demo@1.0.0", "version": "1.0.0"}

    revoked: list = []

    async def _rev(**k):
        revoked.append(k)
        return {}

    monkeypatch.setattr(sys.modules["skill_registry"], "get_skill", _get)
    monkeypatch.setattr(sys.modules["attestations"], "revoke_attestation", _rev)
    monkeypatch.setattr(chapter_agent, "members", {})  # caller is an unknown plain member

    body = chapter_agent.SkillRevokeAttestationRequest(attestor_agent_id="leader-bob")
    with pytest.raises(chapter_agent.HTTPException) as exc:
        await chapter_agent.revoke_skill_attestation("demo@1.0.0", "did:key:zOther", body, _request("mallory"))
    assert exc.value.status_code == 403
    assert revoked == []  # the revoke never ran
