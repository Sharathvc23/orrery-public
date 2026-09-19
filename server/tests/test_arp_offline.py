"""Offline Issuer Log (SQLite) — the chapter persists + serves receipts with no
Postgres configured, so they are viewable locally exactly as in production.

R10  Persistence  — emit → list_for_principal round-trips the full receipt JSON
R1   Forgery      — a tampered receipt still writes nothing in offline mode
Shape — todays_rows_local returns the flat surface-row shape the chronicle builder reads
Flag  — is_offline() reflects the configured mode
"""

from __future__ import annotations

import base64
import json as _json
import os
from unittest.mock import MagicMock

os.environ.setdefault("AGENT_ID", "test-chapter")
os.environ.setdefault("AGENT_NAME", "Test Chapter")
os.environ.setdefault("XAI_API_KEY", "test-key")

import jcs  # noqa: E402
import pytest  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402


def _mock_request(query: dict | None = None):
    req = MagicMock()
    req.query_params = query or {}
    return req


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
    receipt["signature"] = base64.b64encode(sk.sign(jcs.canonicalize(body))).decode("ascii")
    return receipt


ISSUER_SK, ISSUER_DID = _make_identity(b"test-arp-issuer-seed-32-bytes!!a")
_, PRINCIPAL_DID = _make_identity(b"test-arp-principal-seed-32byte!a")


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


@pytest.fixture
def offline_arp(tmp_path):
    """Re-init the arp module in offline mode against a fresh temp SQLite log.

    Saves and restores the module's global state on teardown so offline mode
    does not leak into other tests that share the (module-global) arp wiring.
    """
    import arp as arp_mod

    saved = (arp_mod._pg_request, arp_mod._chapter_id, arp_mod._offline, arp_mod._local_log)

    async def _noop(*_a, **_k):
        return None

    arp_mod.init(
        pg_request=_noop,
        chapter_id="test-chapter",
        offline=True,
        local_log_home=tmp_path,
    )
    try:
        yield arp_mod
    finally:
        (
            arp_mod._pg_request,
            arp_mod._chapter_id,
            arp_mod._offline,
            arp_mod._local_log,
        ) = saved


@pytest.mark.asyncio
async def test_offline_is_offline_flag(offline_arp):
    assert offline_arp.is_offline() is True


@pytest.mark.asyncio
async def test_offline_emit_persists_and_round_trips(offline_arp):
    r = _base_receipt()
    _sign(ISSUER_SK, r)

    res = await offline_arp.emit(r)
    assert res.ok, res

    rows = await offline_arp.list_for_principal(PRINCIPAL_DID)
    assert len(rows) == 1
    assert rows[0]["receipt_id"] == r["receipt_id"]
    # Full receipt (incl. signature) round-trips through SQLite.
    assert rows[0]["signature"] == r["signature"]


@pytest.mark.asyncio
async def test_offline_todays_rows_flat_shape(offline_arp):
    r = _base_receipt()
    _sign(ISSUER_SK, r)
    await offline_arp.emit(r)

    day_iso = r["issued_at"][:10]
    rows = await offline_arp.todays_rows_local(day_iso, PRINCIPAL_DID)
    assert rows, "today rows should be non-empty for the receipt's own day"
    row = rows[0]
    # The flat shape the chronicle surface builder consumes.
    assert row["action_category"] == r["action"]["category"]
    assert row["action_outcome"] == r["action"]["outcome"]
    assert row["human_summary"] == r["action"]["human_summary"]
    assert "receipt_json" in row


@pytest.mark.asyncio
async def test_offline_tampered_receipt_writes_nothing(offline_arp):
    r = _base_receipt()
    _sign(ISSUER_SK, r)
    # Tamper AFTER signing — signature no longer covers the body.
    r["action"]["human_summary"] = "tampered after signing"

    res = await offline_arp.emit(r)
    assert not res.ok

    rows = await offline_arp.list_for_principal(PRINCIPAL_DID)
    assert rows == []  # nothing persisted on a failed verification


@pytest.mark.asyncio
async def test_list_principals_with_receipts_dedupes(offline_arp):
    """The leaderboard's data source: distinct principal_dids with receipts.
    A principal with multiple receipts appears once."""
    _, p2 = _make_identity(bytes([2]) * 32)
    for rid, pdid in [
        ("aaaaaaaa-1111-4111-8111-111111111111", PRINCIPAL_DID),
        ("bbbbbbbb-1111-4111-8111-111111111111", PRINCIPAL_DID),
        ("cccccccc-1111-4111-8111-111111111111", p2),
    ]:
        r = _base_receipt(rid)
        r["principal_did"] = pdid
        _sign(ISSUER_SK, r)
        assert (await offline_arp.emit(r)).ok

    principals = await offline_arp.list_principals_with_receipts()
    assert set(principals) == {PRINCIPAL_DID, p2}
    assert len(principals) == 2  # deduped despite PRINCIPAL_DID having two receipts


@pytest.mark.asyncio
async def test_list_principals_with_receipts_empty_log(offline_arp):
    assert await offline_arp.list_principals_with_receipts() == []


@pytest.mark.asyncio
async def test_offline_principal_isolation(offline_arp):
    r = _base_receipt()
    _sign(ISSUER_SK, r)
    await offline_arp.emit(r)

    # A different principal sees none of it.
    other = await offline_arp.list_for_principal("did:key:z6MkOtherPrincipalDidThatHasNoReceipts")
    assert other == []


# ── The dev-only chapter-wide Receipts endpoint (powers the /receipts viewer) ──


@pytest.mark.asyncio
async def test_recent_endpoint_offline_returns_chapter_wide_log(offline_arp):
    import chapter_agent

    r = _base_receipt()
    _sign(ISSUER_SK, r)
    await offline_arp.emit(r)

    resp = await chapter_agent.recent_receipts_endpoint(_mock_request())
    assert resp.status_code == 200
    body = _json.loads(resp.body)
    assert body["mode"] == "offline"
    assert any(x["receipt_id"] == r["receipt_id"] for x in body["receipts"])


@pytest.mark.asyncio
async def test_recent_endpoint_404_when_online():
    """A real (Postgres-backed) chapter must NOT expose its Issuer Log publicly."""
    import arp as arp_mod
    import chapter_agent

    saved = arp_mod._offline
    arp_mod._offline = False
    try:
        resp = await chapter_agent.recent_receipts_endpoint(_mock_request())
        assert resp.status_code == 404
    finally:
        arp_mod._offline = saved


# ── Merkle checkpoint + inclusion proof round-trip ───────


@pytest.mark.asyncio
async def test_checkpoint_and_inclusion_proof_roundtrip(offline_arp):
    import base64

    import jcs
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )

    import merkle

    for i in range(5):
        r = _base_receipt(f"{i + 1:08d}-0000-4000-8000-000000000000")
        _sign(ISSUER_SK, r)
        assert (await offline_arp.emit(r)).ok

    receipts = sorted(
        offline_arp._local_log.list_recent(5000),
        key=lambda r: (r.get("issued_at", ""), r.get("receipt_id", "")),
    )
    signer_seed = b"checkpoint-signer-seed-32-byte!a"
    _, signer_did = _make_identity(signer_seed)
    cp = offline_arp.build_checkpoint(receipts, sk_bytes=signer_seed, signer_did=signer_did)

    # The checkpoint signature verifies over its JCS payload.
    pub = Ed25519PrivateKey.from_private_bytes(signer_seed).public_key()
    pub.verify(base64.b64decode(cp["signature"]), jcs.canonicalize(cp["payload"]))
    assert cp["payload"]["tree_size"] == 5

    root = bytes.fromhex(cp["payload"]["merkle_root"].split(":")[1])
    leaves = offline_arp.checkpoint_leaves(receipts)
    # Every receipt has an inclusion proof that verifies under the signed root.
    for idx in range(len(receipts)):
        proof = merkle.inclusion_proof(leaves, idx)
        assert merkle.verify_inclusion(leaf=leaves[idx], leaf_index=idx, tree_size=5, proof=proof, root=root)
    # A tampered leaf does not verify.
    assert not merkle.verify_inclusion(
        leaf=b"forged", leaf_index=0, tree_size=5, proof=merkle.inclusion_proof(leaves, 0), root=root
    )


# ── The auditor endpoint: re-verify the whole log + topology + Merkle root ─────


@pytest.mark.asyncio
async def test_audit_endpoint_reverifies_whole_log(offline_arp):
    import chapter_agent

    for i in range(3):
        r = _base_receipt(f"{i + 1:08d}-0000-4000-8000-000000000000")
        _sign(ISSUER_SK, r)
        assert (await offline_arp.emit(r)).ok

    resp = await chapter_agent.audit_endpoint(_mock_request())
    assert resp.status_code == 200
    body = _json.loads(resp.body)
    assert body["total_receipts"] == 3
    assert body["signatures_valid"] == 3
    assert body["signatures_invalid"] == []
    assert body["merkle_root"].startswith("sha256:")


@pytest.mark.asyncio
async def test_audit_endpoint_404_when_online():
    import arp as arp_mod
    import chapter_agent

    saved = arp_mod._offline
    arp_mod._offline = False
    try:
        resp = await chapter_agent.audit_endpoint(_mock_request())
        assert resp.status_code == 404
    finally:
        arp_mod._offline = saved
