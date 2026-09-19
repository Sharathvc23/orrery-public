"""Chapter VRP — build a signed, reputation-aware Receipts Ledger per principal.

Drives the offline Issuer Log path (no Postgres, no ``conformance.arp`` import) to
emit a few member receipts, then builds the principal's ledger and checks:
  * the ledger carries the behavioral root + nanda-rep scores;
  * the chapter ATTESTS it (Ed25519 over root+as_of) and the signature verifies;
  * the AgentFacts facet exposes the root + attested_by but NO receipt contents;
  * an empty principal yields no root and no attestation.
"""

from __future__ import annotations

import base64
import hashlib
import os

os.environ.setdefault("AGENT_ID", "test-chapter")
os.environ.setdefault("AGENT_NAME", "Test Chapter")

import base58
import jcs
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


def _did(pk: bytes) -> str:
    return "did:key:z" + base58.b58encode(b"\xed\x01" + pk).decode()


def _pubkey_from_did(did: str) -> Ed25519PublicKey:
    raw = base58.b58decode(did[len("did:key:z") :])
    return Ed25519PublicKey.from_public_bytes(raw[2:])


def _member_receipt(sk: Ed25519PrivateKey, n: int, category: str = "purchase") -> dict:
    pk = sk.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    did = _did(pk)
    r: dict = {
        "version": "arp/0.1",
        "receipt_id": f"{n:08d}-1111-4111-8111-111111111111",
        "issuer_did": did,
        "principal_did": did,
        "issued_at": f"2026-06-07T00:00:{n:02d}Z",
        "action": {"category": category, "human_summary": f"a{n}", "outcome": "completed"},
    }
    body = {k: v for k, v in r.items() if k != "signature"}
    r["signature"] = base64.b64encode(sk.sign(jcs.canonicalize(body))).decode()
    return r


@pytest.fixture
def offline_chapter(tmp_path):
    import arp as arp_mod
    import sovereign_identity

    sk = Ed25519PrivateKey.from_private_bytes(b"vrp-ledger-chapter-seed-32-byte!")
    pk_b = sk.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    sovereign_identity._ed25519_keypairs["test-chapter"] = {
        "private_key": sk.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        ),
        "public_key": pk_b,
    }
    arp_mod.init(pg_request=None, chapter_id="test-chapter", offline=True, local_log_home=tmp_path)
    chapter_did = arp_mod._chapter_keypair_bytes()[1]
    try:
        yield arp_mod, chapter_did
    finally:
        sovereign_identity._ed25519_keypairs.pop("test-chapter", None)


async def test_principal_ledger_is_attested(offline_chapter) -> None:
    arp_mod, chapter_did = offline_chapter
    import vrp as vrp_mod

    member_sk = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"vrp-member").digest())
    member_pk = member_sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    member_did = _did(member_pk)
    for i in range(3):
        res = await arp_mod.emit(_member_receipt(member_sk, i))
        assert res.ok, f"emit {i}: {res.stage} {res.detail}"

    ledger, facet = await vrp_mod.build_principal_ledger(
        member_did, ledger_uri="https://c/x", as_of="2026-06-07T01:00:00Z"
    )

    assert ledger["receipt_count"] == 3
    assert ledger["reputation_score"] == 15.0  # 3 purchases × 5
    assert ledger["validity_rate"] == 1.0
    root = ledger["behavioral_merkle_root"]
    assert root and root.startswith("sha256:")

    # The chapter attestation signs {root, as_of} and must verify under chapter_did.
    att = ledger["attestation"]
    assert att["attested_by"] == chapter_did
    payload = {"behavioral_merkle_root": root, "as_of": "2026-06-07T01:00:00Z"}
    _pubkey_from_did(chapter_did).verify(base64.b64decode(att["signature"]), jcs.canonicalize(payload))

    # Facet exposes the commitment + scores + attested_by, but NO receipt contents.
    assert facet["behavioral_merkle_root"] == root
    assert facet["attested_by"] == chapter_did
    assert "receipts" not in facet


async def test_empty_principal_has_no_root_or_attestation(offline_chapter) -> None:
    _arp_mod, _chapter_did = offline_chapter
    import vrp as vrp_mod

    ledger, facet = await vrp_mod.build_principal_ledger("did:key:zNobodyHere", ledger_uri="https://c/x")
    assert ledger["receipt_count"] == 0
    assert ledger["behavioral_merkle_root"] is None
    assert "attestation" not in ledger
    assert "attested_by" not in facet


async def test_principal_ledger_v2_method(offline_chapter) -> None:
    """VRP 0.3 wiring: build_principal_ledger threads method -> nanda-rep/0.2."""
    _arp_mod, _chapter_did = offline_chapter
    import vrp as vrp_mod

    ledger, facet = await vrp_mod.build_principal_ledger(
        "did:key:zNobodyHere", ledger_uri="https://c/x", method="nanda-rep/0.2"
    )
    assert ledger["scoring_method"] == "nanda-rep/0.2"
    assert ledger["corroboration_rate"] == 0.0
    assert facet["scoring_method"] == "nanda-rep/0.2"


def _raw_seed(sk: Ed25519PrivateKey) -> bytes:
    return sk.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _corroborated_receipt(issuer_sk: Ed25519PrivateKey, counterparty_sk: Ed25519PrivateKey, n: int) -> dict:
    """An interaction receipt the counterparty co-signed (the witness entry is
    inserted BEFORE the issuer signs, so the issuer signature covers it)."""
    from sm_arp.vrp import cosign_receipt

    ipk = issuer_sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    cpk = counterparty_sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    issuer_did, cp_did = _did(ipk), _did(cpk)
    r: dict = {
        "version": "arp/0.1",
        "receipt_id": f"{n:08d}-3333-4333-8333-333333333333",
        "issuer_did": issuer_did,
        "principal_did": issuer_did,
        "issued_at": f"2026-06-07T00:00:{n:02d}Z",
        "action": {
            "category": "purchase",
            "human_summary": f"c{n}",
            "outcome": "completed",
            "counterparty_did": cp_did,
            "counterparty_label": "B",
        },
    }
    entry = cosign_receipt(r, signing_key_bytes=_raw_seed(counterparty_sk))
    r["evidence"] = {"witness_signatures": [entry]}
    body = {k: v for k, v in r.items() if k != "signature"}
    r["signature"] = base64.b64encode(issuer_sk.sign(jcs.canonicalize(body))).decode()
    return r


async def test_corroborated_receipt_drives_v2_score_uncorroborated_earns_zero(offline_chapter) -> None:
    """The point of step 3: under nanda-rep/0.2 a COUNTERPARTY-CORROBORATED receipt
    builds reputation; an uncorroborated one verifies (validity_rate) but earns ZERO.
    Under nanda-rep/0.1 both count — proving the method selector changes the outcome."""
    arp_mod, _chapter_did = offline_chapter
    import vrp as vrp_mod

    issuer_sk = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"v2-issuer").digest())
    cp_sk = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"v2-counterparty").digest())
    issuer_did = _did(issuer_sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))

    # One corroborated receipt + one uncorroborated (plain) receipt from the same issuer.
    assert (await arp_mod.emit(_corroborated_receipt(issuer_sk, cp_sk, 1))).ok
    assert (await arp_mod.emit(_member_receipt(issuer_sk, 2))).ok

    v2, v2_facet = await vrp_mod.build_principal_ledger(issuer_did, ledger_uri="https://c/x", method="nanda-rep/0.2")
    assert v2["receipt_count"] == 2
    assert v2["validity_rate"] == 1.0  # both ARP-valid
    assert v2["corroboration_rate"] == 0.5  # only one of two is corroborated
    assert v2["reputation_score"] == 5.0  # ONLY the corroborated purchase (5); the other earns zero
    assert v2_facet["corroboration_rate"] == 0.5

    v1, _ = await vrp_mod.build_principal_ledger(issuer_did, ledger_uri="https://c/x", method="nanda-rep/0.1")
    assert v1["reputation_score"] == 10.0  # 0.1 credits BOTH purchases — the method changes the score


async def test_build_principal_ledger_rejects_unknown_method(offline_chapter) -> None:
    """Methods are not comparable (spec/vrp/0.3 §3.1) — an unknown one is an error,
    never silently coerced to a default."""
    _arp_mod, _chapter_did = offline_chapter
    import vrp as vrp_mod

    with pytest.raises(ValueError, match="unsupported scoring_method"):
        await vrp_mod.build_principal_ledger("did:key:zX", ledger_uri="https://c/x", method="nanda-rep/9.9")
