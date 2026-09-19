"""R1-R10 tests for chapter.arp — Agency Receipt Protocol issuer log.

R1  Forgery      — receipt body tampered after signing → emit() rejects at signature
R2  Replay       — same receipt_id under same issuer → conflict (uniqueness)
R3  Injection    — receipt fields containing JSON-special characters survive
                   the JCS canonicalization round-trip and verify
R4  Authz        — require_principal_match rejects mismatched principal_did
R5  Boundary     — list_for_principal returns 0 when no rows; limit=1 honoured
R7  Adversarial  — receipt with valid schema but signature from wrong key fails
R10 Persistence  — round-trip emit → list_for_principal → returns same JSON
"""

from __future__ import annotations

import base64
import os

os.environ.setdefault("AGENT_ID", "test-chapter")
os.environ.setdefault("AGENT_NAME", "Test Chapter")

import jcs  # noqa: E402
import pytest  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: E402
    Ed25519PrivateKey,
)

# ── Fake Postgres backend ──────────────────────────────────────────────


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
            # Apply order desc + limit
            order = (params or {}).get("order", "")
            if order.endswith(".desc"):
                col = order.split(".")[0]
                rows = sorted(rows, key=lambda r: r.get(col, ""), reverse=True)
            limit = (params or {}).get("limit")
            if limit:
                rows = rows[: int(limit)]
            return rows
        if method == "POST" and t == "arp_receipts":
            if self.fail_writes:
                return None
            # Uniqueness simulation
            if any(
                r["issuer_did"] == body["issuer_did"] and r["receipt_id"] == body["receipt_id"]
                for r in self.arp_receipts
            ):
                raise RuntimeError("duplicate key value violates unique constraint")
            row = dict(body)
            self.arp_receipts.append(row)
            return [row]
        return None


# ── Crypto + DID helpers ───────────────────────────────────────────────


def _did_from_pk_bytes(pk_bytes: bytes) -> str:
    import base58

    return "did:key:z" + base58.b58encode(b"\xed\x01" + pk_bytes).decode("ascii")


def _make_identity(seed: bytes) -> tuple[Ed25519PrivateKey, str]:
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    pk_bytes = sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return sk, _did_from_pk_bytes(pk_bytes)


def _sign(sk: Ed25519PrivateKey, receipt: dict) -> dict:
    body = {k: v for k, v in receipt.items() if k != "signature"}
    sig = sk.sign(jcs.canonicalize(body))
    receipt["signature"] = base64.b64encode(sig).decode("ascii")
    return receipt


ISSUER_SK, ISSUER_DID = _make_identity(b"test-arp-issuer-seed-32-bytes!!a")
PRINCIPAL_SK, PRINCIPAL_DID = _make_identity(b"test-arp-principal-seed-32byte!a")
OTHER_PRINCIPAL_DID = _make_identity(b"test-arp-other-principal-seed-32")[1]


def _base_receipt(rid: str = "11111111-1111-4111-8111-111111111111") -> dict:
    return {
        "version": "arp/0.1",
        "receipt_id": rid,
        "issuer_did": ISSUER_DID,
        "principal_did": PRINCIPAL_DID,
        "issued_at": "2026-05-21T14:23:01Z",
        "action": {
            "category": "message_sent",
            "human_summary": "Sent a test message.",
            "outcome": "completed",
        },
    }


# ── fixture ────────────────────────────────────────────────────────────


@pytest.fixture
def supabase() -> _FakePostgres:
    import arp as arp_mod

    s = _FakePostgres()
    arp_mod.init(pg_request=s, chapter_id="test-chapter")
    return s


# ══════════════════════════════════════════════════════════════════════
# R1 — Forgery: body tampered after signing → reject at signature
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_R1_forgery_body_tampered_after_signing_fails(supabase):
    import arp as arp_mod

    r = _base_receipt()
    _sign(ISSUER_SK, r)
    # Tamper AFTER signing
    r["action"]["human_summary"] = "Now claims something else."

    result = await arp_mod.emit(r)

    assert not result.ok
    assert result.stage == "signature"
    assert supabase.arp_receipts == []  # nothing persisted


# ══════════════════════════════════════════════════════════════════════
# R2 — Replay: same receipt_id under same issuer twice → second rejected
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_R2_replay_duplicate_receipt_id_under_same_issuer_rejected(supabase):
    import arp as arp_mod

    r = _base_receipt()
    _sign(ISSUER_SK, r)
    first = await arp_mod.emit(r)
    assert first.ok

    # Re-emit the SAME receipt (identical body, identical signature). That change:
    # emit now detects the (issuer_did, receipt_id) duplicate BEFORE insert and
    # returns a distinct ``duplicate`` result (the HTTP layer maps it to 409),
    # instead of letting the UNIQUE violation surface as a persistence error.
    second = await arp_mod.emit(r)
    assert not second.ok
    assert second.stage == "duplicate"


# ══════════════════════════════════════════════════════════════════════
# R3 — Injection: weird chars in human_summary survive canonicalization
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_R3_injection_special_chars_survive_canonicalization(supabase):
    import arp as arp_mod

    r = _base_receipt()
    r["action"]["human_summary"] = 'Sent a quote: "It\'s 3:14am" — embedded \\backslash, newline\\n, tab\\t.'
    _sign(ISSUER_SK, r)
    result = await arp_mod.emit(r)
    assert result.ok, f"expected pass, got {result.stage}: {result.detail}"
    assert len(supabase.arp_receipts) == 1
    assert supabase.arp_receipts[0]["receipt_json"]["action"]["human_summary"] == (
        'Sent a quote: "It\'s 3:14am" — embedded \\backslash, newline\\n, tab\\t.'
    )


# ══════════════════════════════════════════════════════════════════════
# R4 — Authz: require_principal_match rejects mismatched principal
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_R4_authz_require_principal_match_rejects_mismatch(supabase):
    import arp as arp_mod

    r = _base_receipt()
    _sign(ISSUER_SK, r)
    # The receipt names PRINCIPAL_DID, but we authenticate as OTHER_PRINCIPAL_DID
    result = await arp_mod.emit(r, require_principal_match=OTHER_PRINCIPAL_DID)
    assert not result.ok
    assert "principal_did does not match" in result.detail
    assert supabase.arp_receipts == []


@pytest.mark.asyncio
async def test_R4_authz_require_principal_match_passes_correct(supabase):
    import arp as arp_mod

    r = _base_receipt()
    _sign(ISSUER_SK, r)
    result = await arp_mod.emit(r, require_principal_match=PRINCIPAL_DID)
    assert result.ok


# ══════════════════════════════════════════════════════════════════════
# R5 — Boundary: list_for_principal returns [] when nothing stored
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_R5_boundary_list_for_principal_empty(supabase):
    import arp as arp_mod

    rows = await arp_mod.list_for_principal("did:key:zAnyEmptyResult")
    assert rows == []


@pytest.mark.asyncio
async def test_R5_boundary_list_for_principal_honors_limit(supabase):
    import arp as arp_mod

    # Insert 3 receipts
    for i in range(3):
        r = _base_receipt(rid=f"22222222-2222-4222-8222-22222222222{i}")
        r["issued_at"] = f"2026-05-21T14:{20 + i:02d}:00Z"
        _sign(ISSUER_SK, r)
        await arp_mod.emit(r)

    rows = await arp_mod.list_for_principal(PRINCIPAL_DID, limit=2)
    assert len(rows) == 2


# ══════════════════════════════════════════════════════════════════════
# R7 — Adversarial: signed by wrong key → schema OK, signature fails
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_R7_adversarial_signature_from_wrong_key_fails(supabase):
    import arp as arp_mod

    other_sk = Ed25519PrivateKey.from_private_bytes(b"unauthorized-attacker-32-byte!!a")
    r = _base_receipt()  # claims ISSUER_DID
    _sign(other_sk, r)  # but signs with attacker's key
    result = await arp_mod.emit(r)
    assert not result.ok
    assert result.stage == "signature"
    assert supabase.arp_receipts == []


# ══════════════════════════════════════════════════════════════════════
# R10 — Persistence: emit → list_for_principal returns same body
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_R10_persistence_round_trip(supabase):
    import arp as arp_mod

    r = _base_receipt()
    r["jurisdiction"] = {"principal_residence": "US-MA", "action_locus": "US-MA"}
    r["accessibility"] = {"summary_language": "en-US", "complexity_level": "simple"}
    _sign(ISSUER_SK, r)

    emit_result = await arp_mod.emit(r)
    assert emit_result.ok

    rows = await arp_mod.list_for_principal(PRINCIPAL_DID)
    assert len(rows) == 1
    assert rows[0]["receipt_id"] == r["receipt_id"]
    assert rows[0]["jurisdiction"]["principal_residence"] == "US-MA"
    assert rows[0]["accessibility"]["summary_language"] == "en-US"
    assert rows[0]["signature"] == r["signature"]


# ══════════════════════════════════════════════════════════════════════
# Chain link semantics: emit two linked receipts, verify chain
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_hash_chain_links_resolve_against_stored_prior(supabase):
    import arp as arp_mod

    genesis = _base_receipt(rid="33333333-3333-4333-8333-333333333333")
    _sign(ISSUER_SK, genesis)
    res1 = await arp_mod.emit(genesis)
    assert res1.ok

    # Compute the link the chapter just persisted
    chain_link = arp_mod.compute_chain_link(genesis)

    # Second receipt declares the prior link
    linked = _base_receipt(rid="44444444-4444-4444-8444-444444444444")
    linked["issued_at"] = "2026-05-21T14:24:01Z"
    linked["previous_receipt_hash"] = chain_link
    _sign(ISSUER_SK, linked)

    res2 = await arp_mod.emit(linked)
    assert res2.ok, f"linked receipt failed: {res2.detail}"


@pytest.mark.asyncio
async def test_hash_chain_with_missing_prior_strict_rejects(supabase):
    """For the chapter's OWN receipts, a previous_receipt_hash pointing at a
    chain link the chapter has never seen MUST be rejected (strict mode).

    Per spec/arp/0.2 §0.6, strict chain verification applies to the issuer's own
    chain. We seed the chapter keypair to match the receipt's issuer so the orphan
    is chapter-issued; foreign-issuer tolerance is covered in
    test_arp_tolerant_ingest.py.
    """
    import arp as arp_mod
    import sovereign_identity

    # Make the chapter's own identity == ISSUER, so this orphan is OUR chain.
    # Restore the prior keypair state afterwards so we don't pollute other tests
    # (the suite may run in random order).
    _prev = sovereign_identity._ed25519_keypairs.get("test-chapter")
    sovereign_identity._ed25519_keypairs["test-chapter"] = {
        "private_key": b"test-arp-issuer-seed-32-bytes!!a",
        "public_key": ISSUER_SK.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ),
    }
    try:
        assert arp_mod._chapter_keypair_bytes()[1] == ISSUER_DID  # sanity: own_did == issuer

        orphan = _base_receipt(rid="55555555-5555-4555-8555-555555555555")
        orphan["previous_receipt_hash"] = "sha256:" + "0" * 64  # nothing matches
        _sign(ISSUER_SK, orphan)

        result = await arp_mod.emit(orphan)
        assert not result.ok
        assert result.stage == "hash_chain"
    finally:
        if _prev is None:
            sovereign_identity._ed25519_keypairs.pop("test-chapter", None)
        else:
            sovereign_identity._ed25519_keypairs["test-chapter"] = _prev


@pytest.mark.asyncio
async def test_persistence_failure_is_logged_not_silent(supabase, caplog):
    """A1a: a persistence failure (supabase write returns None — outage or a
    missing arp_receipts table) must be LOUD, not a silent drop."""
    import logging

    import arp as arp_mod

    supabase.fail_writes = True
    r = _base_receipt("22222222-2222-4222-8222-222222222222")
    _sign(ISSUER_SK, r)
    with caplog.at_level(logging.WARNING):
        res = await arp_mod.emit(r)
    assert not res.ok
    assert res.detail == "verified but persistence failed"
    assert any("NOT persisted" in rec.getMessage() for rec in caplog.records), "persistence failure must log a WARNING"
