"""VRP 0.3 — member-side counterparty corroboration + nanda-rep/0.2 export.

The member, as a COUNTERPARTY, co-signs receipts it's party to (independent evidence);
under nanda-rep/0.2 only corroborated receipts build reputation. Co-signing happens
BEFORE the issuer's final signature, so the issuer also commits to the witness.
"""

from __future__ import annotations

import hashlib

import pytest
from sm_arp.vrp import is_corroborated

from community_member.arp import AgencyLog, build_receipt, did_from_private_key, sign_receipt
from community_member.ledger import corroborate, export_ledger, verify_presented_ledger

_ISSUER_SK = hashlib.sha256(b"corrob-issuer").digest()
_CP_SK = hashlib.sha256(b"corrob-counterparty").digest()
_ISSUER_DID = did_from_private_key(_ISSUER_SK)
_CP_DID = did_from_private_key(_CP_SK)
_NOW = "2026-06-08T00:00:00Z"


def _receipt(n: int, *, corroborated: bool) -> dict:
    r = build_receipt(
        action={
            "category": "purchase",
            "human_summary": f"buy {n}",
            "outcome": "completed",
            "counterparty_did": _CP_DID,
        },
        issuer_did=_ISSUER_DID,
        principal_did=_ISSUER_DID,
        issued_at=f"2026-06-08T00:00:{n:02d}Z",
    )
    if corroborated:
        # counterparty co-signs the content, THEN the issuer signs over it.
        r.setdefault("evidence", {})["witness_signatures"] = [corroborate(r, signing_key_bytes=_CP_SK)]
    return sign_receipt(r, _ISSUER_SK)


def test_corroborate_round_trips() -> None:
    """The member-facing corroborate() yields a witness the vendored verifier accepts."""
    r = _receipt(1, corroborated=True)
    assert is_corroborated(r)


def test_export_v2_gates_uncorroborated(tmp_path) -> None:
    """nanda-rep/0.2 export: corroborated receipts build reputation, uncorroborated earn 0."""
    log = AgencyLog(tmp_path / "agency")
    for i in range(3):
        log.append(_receipt(i, corroborated=True))
    for i in range(3, 5):
        log.append(_receipt(i, corroborated=False))

    v2 = export_ledger(log, subject_did=_ISSUER_DID, as_of=_NOW, method="nanda-rep/0.2")
    assert v2["scoring_method"] == "nanda-rep/0.2"
    assert v2["reputation_score"] == 15.0  # 3 corroborated purchases × 5; the 2 uncorroborated earn 0
    assert v2["corroboration_rate"] == pytest.approx(3 / 5)
    assert v2["validity_rate"] == 1.0  # all 5 are ARP-valid
    assert verify_presented_ledger(v2).ok

    # Contrast: nanda-rep/0.1 counts all five.
    v1 = export_ledger(log, subject_did=_ISSUER_DID, as_of=_NOW)
    assert v1["scoring_method"] == "nanda-rep/0.1"
    assert v1["reputation_score"] == 25.0
    assert "corroboration_rate" not in v1
