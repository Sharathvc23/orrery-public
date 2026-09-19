"""That change — org self-attestation never worked, and the reason was thrown away.

`POST /admin/api/audit/attest` returned 503 "cannot sign attestation — chapter
keypair unavailable or persistence failed" on all three deployed orgs. That
message names two causes and reports neither, which is worse than a bare 500
because it looks diagnostic.

The keypair was fine. The real cause, found only by surfacing the discarded
`VerificationResult`: `emit_audit_chain_snapshot` built its receipt with
`action.category = "audit.chain.snapshot"`, which is NOT in ARP's closed
category enum, so every attestation failed the SCHEMA gate and was dropped. The
endpoint has therefore never once succeeded on a deployed org.

`attestation_issued` is the spec's category for exactly this — an org issuing an
attestation about its own chain state. The specific kind moves to
`machine_payload.attestation_type`, so nothing is lost and the ARP category enum
(which is the spec's, not ours) does not have to change.
"""

from __future__ import annotations

import datetime
import uuid

import base58
import nacl.signing
import pytest

import arp as arp_mod
from _arp_verify import verify_receipt

VALID_CATEGORIES = {
    "purchase", "payment_sent", "payment_received", "message_sent", "message_received",
    "decision_made", "data_shared", "appointment_booked", "appointment_cancelled",
    "subscription_changed", "record_filed", "account_created", "account_closed",
    "attestation_issued", "attestation_received", "commitment_entered",
    "commitment_fulfilled", "commitment_breached", "vote_cast", "authority_granted",
    "authority_revoked", "other",
}


def _signed(category: str) -> dict:
    sk = nacl.signing.SigningKey.generate()
    did = "did:key:z" + base58.b58encode(b"\xed\x01" + bytes(sk.verify_key)).decode()
    r = {
        "version": "arp/0.1",
        "receipt_id": str(uuid.uuid4()),
        "issuer_did": did,
        "principal_did": did,
        "issued_at": datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "action": {
            "category": category,
            "human_summary": "Audit chain snapshot — 0 events",
            "outcome": "completed",
            "machine_payload": {
                "tip_sha256": "", "chain_length": 0,
                "snapshot_at": "2026-08-02T23:00:00Z",
                "attestation_type": "audit.chain.snapshot",
            },
        },
    }
    arp_arp = arp_mod
    arp_arp._sign_receipt(bytes(sk), r)
    return r


def test_FAILING_BEFORE_the_old_category_is_schema_invalid():
    """The exact cause, pinned. This is what every attestation did in production."""
    res = verify_receipt(_signed("audit.chain.snapshot"), mode="strict", prior_receipts={})
    assert not res.ok
    assert res.stage == "schema", res.stage
    assert "audit.chain.snapshot" in res.detail


def test_the_attestation_category_now_verifies():
    res = verify_receipt(_signed("attestation_issued"), mode="strict", prior_receipts={})
    assert res.ok, f"{res.stage}: {res.detail}"


def test_the_emitter_uses_a_category_the_schema_accepts():
    """Pin the emitter itself, not just a hand-built receipt.

    A future edit that reintroduces a category outside the enum would otherwise
    fail only in production, silently, exactly as this did.
    """
    import inspect

    src = inspect.getsource(arp_mod.emit_audit_chain_snapshot)
    assert '"category": "attestation_issued"' in src, "emitter category changed"
    assert '"category": "audit.chain.snapshot"' not in src, "the schema-invalid category is back"


def test_the_snapshot_kind_is_still_recoverable():
    """Moving the category must not lose what kind of attestation this is."""
    import inspect

    src = inspect.getsource(arp_mod.emit_audit_chain_snapshot)
    assert 'machine_payload["attestation_type"] = "audit.chain.snapshot"' in src


def test_every_category_the_emitter_uses_is_in_the_enum():
    """The general form of the bug, so it cannot come back through another path."""
    import inspect
    import re

    src = inspect.getsource(arp_mod)
    for cat in re.findall(r'"category":\s*"([a-z._]+)"', src):
        assert cat in VALID_CATEGORIES, f"arp.py emits category {cat!r}, outside the ARP enum"


# ── The refusal must carry its reason ────────────────────────────────────────


def test_AttestationRefused_carries_stage_and_detail():
    """The whole reason the bug was invisible: the reason was discarded."""
    exc = arp_mod.AttestationRefused(stage="schema", detail="bad category")
    assert exc.stage == "schema"
    assert exc.detail == "bad category"
    assert "schema" in str(exc) and "bad category" in str(exc)


async def test_emitter_raises_with_the_reason_instead_of_returning_None(monkeypatch):
    """A refused attestation must RAISE with the cause, not return None.

    Returning None is what let the HTTP layer answer "keypair unavailable or
    persistence failed" without knowing which.
    """
    from _arp_verify import VerificationResult

    monkeypatch.setattr(arp_mod, "_pg_request", lambda *a, **k: None)
    sk = nacl.signing.SigningKey.generate()
    did = "did:key:z" + base58.b58encode(b"\xed\x01" + bytes(sk.verify_key)).decode()
    monkeypatch.setattr(arp_mod, "_chapter_keypair_bytes", lambda: (bytes(sk), did))

    async def refuse(receipt, **kw):
        return VerificationResult(False, stage="schema", detail="synthetic refusal")

    monkeypatch.setattr(arp_mod, "emit", refuse)

    with pytest.raises(arp_mod.AttestationRefused) as e:
        await arp_mod.emit_audit_chain_snapshot(
            tip_sha256="abc", chain_length=1, snapshot_at="2026-08-02T23:00:00Z"
        )
    assert e.value.stage == "schema"
    assert "synthetic refusal" in e.value.detail


async def test_a_refused_attestation_is_never_reported_as_success(monkeypatch):
    """No fallback to an unsigned or unpersisted receipt.

    A signed receipt nobody recorded is worse than a refusal: the caller believes
    an audit artifact exists.
    """
    from _arp_verify import VerificationResult

    sk = nacl.signing.SigningKey.generate()
    did = "did:key:z" + base58.b58encode(b"\xed\x01" + bytes(sk.verify_key)).decode()
    monkeypatch.setattr(arp_mod, "_pg_request", lambda *a, **k: None)
    monkeypatch.setattr(arp_mod, "_chapter_keypair_bytes", lambda: (bytes(sk), did))

    async def refuse(receipt, **kw):
        return VerificationResult(False, stage="signature", detail="nope")

    monkeypatch.setattr(arp_mod, "emit", refuse)
    with pytest.raises(arp_mod.AttestationRefused):
        await arp_mod.emit_audit_chain_snapshot(
            tip_sha256="a", chain_length=1, snapshot_at="2026-08-02T23:00:00Z"
        )
