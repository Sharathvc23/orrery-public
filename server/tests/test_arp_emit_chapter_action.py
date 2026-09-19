"""R1-R10 tests for chapter.arp.emit_chapter_action() and the
instrumented action paths.

R1  Forgery       — chapter keypair missing → emit returns False, no persist
R2  Replay        — re-emit same logical action produces a NEW receipt_id (uniqueness gate is per (issuer, receipt_id), not per content)
R3  Injection     — human_summary > 280 chars is truncated, not rejected
R4  Authz         — emit fails gracefully when supabase or principal_did missing
R5  Boundary      — categories at the spec enum boundary all accepted
R7  Adversarial   — exception inside emit path doesn't propagate to caller
R10 Persistence   — emitted receipt round-trips: signature verifies under issuer_did
"""

from __future__ import annotations

import os

os.environ.setdefault("AGENT_ID", "test-chapter")
os.environ.setdefault("AGENT_NAME", "Test Chapter")

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

# ── Fake Postgres ──────────────────────────────────────────────────


class _FakePostgres:
    def __init__(self) -> None:
        self.arp_receipts: list[dict] = []
        self.fail_writes: bool = False

    async def __call__(self, method, table, params=None, body=None):
        t = table.split("?")[0]
        if method == "GET" and t == "arp_receipts":
            rows = list(self.arp_receipts)
            for k, v in (params or {}).items():
                if k in ("select", "order", "limit"):
                    continue
                wanted = v.replace("eq.", "")
                rows = [r for r in rows if str(r.get(k, "")) == wanted]
            return rows
        if method == "POST" and t == "arp_receipts":
            if self.fail_writes:
                return None
            if any(
                r["issuer_did"] == body["issuer_did"] and r["receipt_id"] == body["receipt_id"]
                for r in self.arp_receipts
            ):
                raise RuntimeError("duplicate key value violates unique constraint")
            row = dict(body)
            self.arp_receipts.append(row)
            return [row]
        return None


# ── Helpers ────────────────────────────────────────────────────────


def _seed_chapter_keypair(chapter_id: str = "test-chapter"):
    """Generate a deterministic Ed25519 keypair for the chapter and seed
    sovereign_identity._ed25519_keypairs so emit_chapter_action finds it."""
    import sovereign_identity

    sk = Ed25519PrivateKey.from_private_bytes(b"test-chapter-keypair-seed-32by!a")
    pk_bytes = sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    sk_bytes = sk.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    sovereign_identity._ed25519_keypairs[chapter_id] = {
        "private_key": sk_bytes,
        "public_key": pk_bytes,
    }
    return sk_bytes, pk_bytes


@pytest.fixture
def supabase():
    import arp as arp_mod

    s = _FakePostgres()
    arp_mod.init(pg_request=s, chapter_id="test-chapter")
    _seed_chapter_keypair("test-chapter")
    return s


# ══════════════════════════════════════════════════════════════════════
# R1 — Forgery: missing chapter keypair → emit returns False, no persist
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_R1_no_chapter_keypair_emit_returns_false(supabase):
    import arp as arp_mod
    import sovereign_identity

    # Wipe the keypair to simulate uninitialised chapter
    sovereign_identity._ed25519_keypairs.pop("test-chapter", None)

    ok = await arp_mod.emit_chapter_action(
        principal_did="did:key:z6MkhmkanDrL2wpF7VmmcRZC3nWWtJwtT8BboZU4HaZ3cXuX",
        category="message_sent",
        human_summary="testing",
    )
    assert ok is False
    assert supabase.arp_receipts == []


# ══════════════════════════════════════════════════════════════════════
# R2 — Replay: two emits with the same logical action produce distinct
#               receipt_ids (UUIDv4 is generated per call)
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_R2_two_emits_same_action_produce_distinct_receipt_ids(supabase):
    import arp as arp_mod

    ok1 = await arp_mod.emit_chapter_action(
        principal_did="did:key:z6MkhmkanDrL2wpF7VmmcRZC3nWWtJwtT8BboZU4HaZ3cXuX",
        category="message_sent",
        human_summary="ping",
    )
    ok2 = await arp_mod.emit_chapter_action(
        principal_did="did:key:z6MkhmkanDrL2wpF7VmmcRZC3nWWtJwtT8BboZU4HaZ3cXuX",
        category="message_sent",
        human_summary="ping",
    )
    assert ok1 and ok2
    assert len(supabase.arp_receipts) == 2
    assert supabase.arp_receipts[0]["receipt_id"] != supabase.arp_receipts[1]["receipt_id"]


# ══════════════════════════════════════════════════════════════════════
# R3 — Injection: oversized human_summary is truncated, not rejected
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_R3_oversized_summary_truncated_not_rejected(supabase):
    import arp as arp_mod

    summary = "x" * 500
    ok = await arp_mod.emit_chapter_action(
        principal_did="did:key:z6MkhmkanDrL2wpF7VmmcRZC3nWWtJwtT8BboZU4HaZ3cXuX",
        category="message_sent",
        human_summary=summary,
    )
    assert ok
    persisted_summary = supabase.arp_receipts[0]["receipt_json"]["action"]["human_summary"]
    assert len(persisted_summary) <= 280
    assert persisted_summary.endswith("...")


# ══════════════════════════════════════════════════════════════════════
# R4 — Authz: missing principal_did or pg_request → False
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_R4_missing_principal_did_returns_false(supabase):
    import arp as arp_mod

    ok = await arp_mod.emit_chapter_action(
        principal_did="",
        category="message_sent",
        human_summary="testing",
    )
    assert ok is False
    assert supabase.arp_receipts == []


@pytest.mark.asyncio
async def test_R4_uninitialized_module_returns_false():
    import arp as arp_mod

    # Re-init with None pg_request
    arp_mod.init(pg_request=None, chapter_id="test-chapter")
    _seed_chapter_keypair("test-chapter")
    ok = await arp_mod.emit_chapter_action(
        principal_did="did:key:z6MkhmkanDrL2wpF7VmmcRZC3nWWtJwtT8BboZU4HaZ3cXuX",
        category="message_sent",
        human_summary="testing",
    )
    assert ok is False


# ══════════════════════════════════════════════════════════════════════
# R7 — Adversarial: exception inside signing path doesn't propagate
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_R7_signing_failure_returns_false_not_raises(supabase, monkeypatch):
    import arp as arp_mod

    def broken_sign(*_args, **_kw):
        raise RuntimeError("simulated signing crash")

    monkeypatch.setattr(arp_mod, "_sign_receipt", broken_sign)

    # MUST return False, not raise
    ok = await arp_mod.emit_chapter_action(
        principal_did="did:key:z6MkhmkanDrL2wpF7VmmcRZC3nWWtJwtT8BboZU4HaZ3cXuX",
        category="message_sent",
        human_summary="testing",
    )
    assert ok is False


# ══════════════════════════════════════════════════════════════════════
# R10 — Persistence: emitted receipt signature verifies under issuer_did
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_R10_emitted_receipt_signature_verifies(supabase):
    """Round-trip the receipt through the verifier: signature MUST verify
    under the chapter's did:key. This is the headline guarantee."""
    from conformance.arp import verify_receipt

    import arp as arp_mod

    ok = await arp_mod.emit_chapter_action(
        principal_did="did:key:z6MkhmkanDrL2wpF7VmmcRZC3nWWtJwtT8BboZU4HaZ3cXuX",
        category="commitment_entered",
        human_summary="Matched your intent with 2 members.",
        counterparty_did="did:key:z6MkfTBd5dPYbWZRZkVz4ZBz1ymuepAQ4HEHYSF1H8quG5GL",
        counterparty_label="bob",
        machine_payload={"intent_id": "i-123"},
    )
    assert ok
    assert len(supabase.arp_receipts) == 1
    persisted = supabase.arp_receipts[0]["receipt_json"]
    result = verify_receipt(persisted, mode="strict")
    assert result.ok, f"verification failed at {result.stage}: {result.detail}"


@pytest.mark.asyncio
async def test_R10_receipt_includes_optional_fields(supabase):
    import arp as arp_mod

    await arp_mod.emit_chapter_action(
        principal_did="did:key:z6MkhmkanDrL2wpF7VmmcRZC3nWWtJwtT8BboZU4HaZ3cXuX",
        category="record_filed",
        human_summary="Filed W-9 for the consulting engagement.",
        jurisdiction={"principal_residence": "US-MA", "applicable_regimes": ["irs"]},
        accessibility={"summary_language": "en-US", "complexity_level": "complex", "requires_review": True},
        machine_payload={"form_id": "IRS-W9"},
    )
    persisted = supabase.arp_receipts[0]["receipt_json"]
    assert persisted["jurisdiction"]["principal_residence"] == "US-MA"
    assert persisted["accessibility"]["requires_review"] is True
    assert persisted["action"]["machine_payload"]["form_id"] == "IRS-W9"


# ══════════════════════════════════════════════════════════════════════
# did_key_for_member resolver
# ══════════════════════════════════════════════════════════════════════


def test_did_key_for_member_returns_empty_when_no_stored_pubkey(monkeypatch):
    import arp as arp_mod
    import auth_verify

    monkeypatch.setattr(auth_verify, "_agent_keys", {}, raising=False)
    assert arp_mod.did_key_for_member("nobody") == ""


def test_did_key_for_member_resolves_when_stored(monkeypatch):
    import arp as arp_mod
    import auth_verify
    import sovereign_identity as si

    monkeypatch.setattr(
        auth_verify,
        "_agent_keys",
        {"alice": {"ed25519_pubkey": "PUBKEY-B64"}},
        raising=False,
    )
    monkeypatch.setattr(
        si,
        "build_did_key_from_ed25519",
        lambda pk: "did:key:zResolved" if pk == "PUBKEY-B64" else "",
    )
    assert arp_mod.did_key_for_member("alice") == "did:key:zResolved"
