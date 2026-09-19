"""Trust / reputation scoring-path integrity guards.

Two real gaps the audit found at POST /api/receipts, plus the frozen
trust-event-delta contract:

  That change — a member could inject receipts into ANY other principal's ledger
         (principal != issuer went unguarded), inflating the target's
         nanda-rep/0.1 (default) score.
  That change — a replay of a receipt_id returned 503 (looked like an outage) instead
         of the documented 409 idempotent.

Receipts are built at test time with the deterministic conformance vector
generator (seeded keys — no hardcoded signatures/DIDs).

Classification: ADVERSARIAL / CONTRACT.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import uuid

os.environ.setdefault("AGENT_ID", "test-chapter")
os.environ.setdefault("AGENT_NAME", "Test Chapter")

import pytest
from conformance.arp._vector_gen import ISSUER_DID, ISSUER_SK, PRINCIPAL_DID, base_receipt, sign_receipt

import arp


def _rid(name: str) -> str:
    return str(uuid.UUID(bytes=hashlib.sha256(name.encode()).digest()[:16], version=4))


class _FakePg:
    def __init__(self):
        self.rows: list[dict] = []

    async def __call__(self, method, table, params=None, body=None):
        t = table.split("?")[0]
        if t != "arp_receipts":
            return []
        if method == "GET":
            rows = list(self.rows)
            for k, v in (params or {}).items():
                if k in ("select", "order", "limit"):
                    continue
                if isinstance(v, str) and v.startswith("eq."):
                    rows = [r for r in rows if str(r.get(k, "")) == v[3:]]
            return rows[: int((params or {}).get("limit", 999))]
        if method == "POST":
            self.rows.append(dict(body or {}))
            return [body]
        return None


@pytest.fixture
def arp_env(monkeypatch):
    pg = _FakePg()
    monkeypatch.setattr(arp, "_pg_request", pg)
    monkeypatch.setattr(arp, "_offline", False)
    # no chapter keypair → foreign-issuer tolerant chain mode, no self-did match
    monkeypatch.setattr(arp, "_chapter_keypair_bytes", lambda: None)
    return pg


def _signed(rid: str, *, principal: str) -> dict:
    r = base_receipt(
        receipt_id=rid,
        issued_at="2026-01-01T00:00:00Z",
        category="message_sent",
        human_summary="audit",
    )
    r["principal_did"] = principal
    r["action"]["counterparty_did"] = PRINCIPAL_DID
    return sign_receipt(ISSUER_SK, r)


# ── That change: principal must equal issuer for member submits ──


def test_cross_principal_receipt_is_rejected(arp_env):
    """ADVERSARIAL: issuer X, principal Y → rejected when the HTTP layer
    passes require_principal_match=issuer_did."""
    r = _signed(_rid("cross"), principal="did:key:zSomeoneElse")
    res = asyncio.run(arp.emit(r, require_principal_match=ISSUER_DID))
    assert not res.ok and res.stage == "schema"
    assert arp_env.rows == []  # nothing written to the victim's ledger


def test_self_principal_receipt_is_accepted(arp_env):
    """HAPPY: principal == issuer (a member vouching for its OWN action) is fine."""
    r = _signed(_rid("self"), principal=ISSUER_DID)
    res = asyncio.run(arp.emit(r, require_principal_match=ISSUER_DID))
    assert res.ok, res.detail
    assert len(arp_env.rows) == 1


# ── That change: replay is an idempotent 409, not a 503 ──


def test_replay_is_flagged_duplicate_not_persistence_failure(arp_env):
    r = _signed(_rid("replay"), principal=ISSUER_DID)
    first = asyncio.run(arp.emit(r, require_principal_match=ISSUER_DID))
    assert first.ok
    second = asyncio.run(arp.emit(r, require_principal_match=ISSUER_DID))
    assert not second.ok
    assert second.stage == "duplicate", f"replay must be 'duplicate' (→409), got {second.stage!r}"
    assert len(arp_env.rows) == 1  # no double-write


def test_duplicate_stage_is_distinct_from_accepted(arp_env):
    """The endpoint maps stage=='accepted'+persistence → 503 and
    stage=='duplicate' → 409; they must not collide."""
    r = _signed(_rid("distinct"), principal=ISSUER_DID)
    asyncio.run(arp.emit(r, require_principal_match=ISSUER_DID))
    dup = asyncio.run(arp.emit(r, require_principal_match=ISSUER_DID))
    assert dup.stage == "duplicate"
    assert "persistence" not in dup.detail


# ── frozen trust-event delta contract (CLAUDE.md "what never changes silently") ──


def test_trust_event_deltas_are_the_frozen_values():
    """The trust-event delta VALUES are server-set + immutable per major. Pin
    them so a silent edit is caught (CLAUDE.md: trust deltas never change
    silently)."""
    from decimal import Decimal

    import trust_events

    assert trust_events.EVENT_DELTAS == {
        "intent_match_accepted": Decimal("0.5"),
        "intent_response_useful": Decimal("1.0"),
        "call_response_accepted": Decimal("0.5"),
        "conversation_completed_positive": Decimal("1.0"),
        "skill_attested_by_trusted": Decimal("2.0"),
        "endorsement_received": Decimal("0.5"),
        "tenure_milestone_30d": Decimal("1.0"),
        "tenure_milestone_90d": Decimal("2.0"),
        "tenure_milestone_180d": Decimal("5.0"),
        "tenure_milestone_365d": Decimal("10.0"),
        "revocation_received": Decimal("-1.0"),
        "complaint_validated": Decimal("-3.0"),
        "inactive_decay": Decimal("-1.0"),
    }


def test_record_ignores_any_client_supplied_delta(monkeypatch):
    """The delta is read from EVENT_DELTAS, never from caller input — record()
    has no delta parameter, so a client cannot set one."""
    import inspect

    import trust_events

    assert "delta" not in inspect.signature(trust_events.record).parameters


# ── the actual that change fix is at the HTTP endpoint (wiring emit's guard) ──


@pytest.mark.asyncio
async def test_endpoint_passes_require_principal_match_and_maps_duplicate(monkeypatch):
    """The bug was the ENDPOINT calling emit() without require_principal_match
    and having no 409 path. Lock both: the handler must pass
    require_principal_match=issuer_did and map stage=='duplicate' → 409."""
    import chapter_agent

    seen = {}

    async def fake_emit(body, *, require_principal_match=None):
        seen["rpm"] = require_principal_match
        return arp.VerificationResult(False, "duplicate", "receipt already recorded (idempotent re-submit)")

    monkeypatch.setattr("arp.emit", fake_emit)

    class _Req:
        async def json(self):
            return {"receipt_id": "r1", "issuer_did": "did:key:zIssuer", "principal_did": "did:key:zIssuer"}

    resp = await chapter_agent.submit_receipt_endpoint(_Req())
    assert seen["rpm"] == "did:key:zIssuer", "endpoint must enforce principal==issuer"
    assert resp.status_code == 409, "an idempotent re-submit must be 409, not 503"
    import json as _json

    assert _json.loads(bytes(resp.body))["idempotent"] is True
