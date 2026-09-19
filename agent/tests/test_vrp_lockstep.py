"""Drift guard: the installed ``sm_arp.vrp`` (the published VRP library the member
SDK now depends on) MUST stay byte-for-byte equivalent to the canonical
``conformance/vrp``.

The SDK un-vendored its VRP core — ``cosign.py`` / ``ledger.py`` / ``server.py`` import
``sm_arp.vrp`` instead of a vendored copy. ``conformance/vrp`` remains the source of
truth: if the published library drifts, the member would compute a different
``behavioral_merkle_root`` / ``nanda-rep`` score / attestation than a chapter or an
external resolver, defeating the "everyone recomputes the same value" property. This
guard runs both implementations over fixed inputs and asserts identical output. Skips
standalone (no ``conformance/`` alongside, e.g. a bare pip install).
"""

from __future__ import annotations

import pytest

canon = pytest.importorskip("conformance.vrp", reason="canonical conformance/vrp not present")

import sm_arp.vrp as lib  # noqa: E402 — the installed published mirror under test
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat  # noqa: E402

_A = bytes([1]) * 32
_B = bytes([2]) * 32
_C = bytes([3]) * 32


def _valid(_r: dict) -> bool:
    return True


def _pub(seed: bytes) -> bytes:
    return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _did(seed: bytes) -> str:
    return canon.did_key_from_pubkey(_pub(seed))


def _receipt(issuer: str, cp: str, rid: str = "r") -> dict:
    return {
        "version": "arp/0.1",
        "receipt_id": rid,
        "issuer_did": issuer,
        "issued_at": "2026-01-01T00:00:00Z",
        "action": {"category": "message_sent", "human_summary": "x", "outcome": "completed", "counterparty_did": cp},
    }


def _corroborated(issuer_seed: bytes, cp_seed: bytes, rid: str) -> dict:
    r = _receipt(_did(issuer_seed), _did(cp_seed), rid)
    r["evidence"] = {"witness_signatures": [canon.cosign_receipt(r, signing_key_bytes=cp_seed)]}
    return r


def test_did_key_derivation_matches() -> None:
    assert lib.did_key_from_pubkey(_pub(_A)) == canon.did_key_from_pubkey(_pub(_A))
    assert lib.pubkey_from_did_key(_did(_A)) == canon.pubkey_from_did_key(_did(_A))


def test_cosign_and_corroboration_match() -> None:
    r = _receipt(_did(_A), _did(_B))
    assert lib.cosign_receipt(r, signing_key_bytes=_B) == canon.cosign_receipt(r, signing_key_bytes=_B)
    r2 = {**r, "evidence": {"witness_signatures": [canon.cosign_receipt(r, signing_key_bytes=_B)]}}
    assert lib.is_corroborated(r2) is True
    assert lib.is_corroborated(r2) == canon.is_corroborated(r2)


def test_scoring_and_root_match() -> None:
    rs = [_corroborated(_A, _B, "r1"), _receipt(_did(_A), _did(_C), "r2")]
    assert lib.behavioral_merkle_root(rs) == canon.behavioral_merkle_root(rs)
    assert lib.reputation_score(rs, is_valid=_valid) == canon.reputation_score(rs, is_valid=_valid)
    assert lib.reputation_score_v2(rs, is_valid=_valid) == canon.reputation_score_v2(rs, is_valid=_valid)
    assert lib.corroboration_rate(rs, is_valid=_valid) == canon.corroboration_rate(rs, is_valid=_valid)


def test_ledger_and_facet_match() -> None:
    rs = [_corroborated(_A, _B, "r1")]
    for method in ("nanda-rep/0.1", "nanda-rep/0.2"):
        ledger_lib = lib.build_ledger(subject=_did(_A), receipts=rs, is_valid=_valid, as_of="t", method=method)
        ledger_can = canon.build_ledger(subject=_did(_A), receipts=rs, is_valid=_valid, as_of="t", method=method)
        assert ledger_lib == ledger_can
        assert lib.facet_from_ledger(ledger_lib, ledger_uri="u") == canon.facet_from_ledger(ledger_can, ledger_uri="u")
        assert lib.verify_ledger(ledger_lib, is_valid=_valid).ok == canon.verify_ledger(ledger_can, is_valid=_valid).ok


def test_attestation_matches() -> None:
    facts = {
        "id": "did:key:zSubject",
        "verifiable_receipts": {"ledger_uri": "u", "behavioral_merkle_root": "sha256:abc"},
    }
    assert lib.facts_digest(facts) == canon.facts_digest(facts)
    att_lib = lib.build_attestation(facts_record=facts, signing_key_bytes=_A, as_of="t")
    att_can = canon.build_attestation(facts_record=facts, signing_key_bytes=_A, as_of="t")
    assert att_lib == att_can
    rec = {**facts, "attestation": att_can}
    assert lib.verify_attestation(rec).ok is True
    assert lib.verify_attestation(rec).ok == canon.verify_attestation(rec).ok
