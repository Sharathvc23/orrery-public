"""Phase 3 — the member exports its own VRP Receipts Ledger and verifies others'.

A sovereign member can publish a portable, reputation-aware Receipts Ledger from
its local Agency Log (the substrate sm-rep wraps as a credential), and — as a
resolver — recompute and verify ANY presented ledger's root + nanda-rep scores
without trusting the host that served it. Validity is the member's OWN strict ARP
verification, so the score reflects receipts that actually verify.

Classification:
  HAPPY        — export a ledger from the Agency Log (root + nanda-rep populated)
  ADVERSARIAL  — a tampered receipt in the log drops validity_rate (real verify)
  HAPPY        — round-trip: export → verify_presented_ledger accepts
  ADVERSARIAL  — tampering a presented ledger's receipt → root_mismatch
"""

from __future__ import annotations

import hashlib
import os
import tempfile

os.environ.setdefault(
    "COMMUNITY_MEMBER_HOME",
    os.path.join(tempfile.gettempdir(), "cm-ledger-tests-do-not-use"),
)

import pytest

from community_member.arp import AgencyLog, build_receipt, did_from_private_key, sign_receipt
from community_member.ledger import (
    agentfacts_facet,
    export_ledger,
    verify_presented_ledger,
)

SK = hashlib.sha256(b"ledger-member").digest()
DID = did_from_private_key(SK)
NOW = "2026-06-07T00:00:00Z"


def _signed(n: int, category: str = "message_sent") -> dict:
    r = build_receipt(
        action={"category": category, "human_summary": f"a{n}", "outcome": "completed"},
        issuer_did=DID,
        principal_did=DID,
        issued_at=f"2026-06-07T00:00:{n:02d}Z",
    )
    return sign_receipt(r, SK)


@pytest.fixture
def log(tmp_path) -> AgencyLog:
    lg = AgencyLog(tmp_path / "agency")
    for i in range(3):
        lg.append(_signed(i, "purchase"))
    return lg


def test_export_ledger_shape(log: AgencyLog) -> None:
    ledger = export_ledger(log, subject_did=DID, as_of=NOW)
    assert ledger["subject"] == DID
    assert ledger["scoring_method"] == "nanda-rep/0.1"
    assert ledger["receipt_count"] == 3
    assert ledger["validity_rate"] == 1.0
    assert ledger["reputation_score"] == 15.0  # 3 purchases × 5
    assert ledger["behavioral_merkle_root"].startswith("sha256:")


def test_tampered_receipt_drops_validity(log: AgencyLog, tmp_path) -> None:
    # Append a receipt whose signature is broken; real ARP verify must fail it.
    bad = _signed(9, "purchase")
    bad["action"]["human_summary"] = "tampered after signing"
    log.append(bad)
    ledger = export_ledger(log, subject_did=DID, as_of=NOW)
    assert ledger["receipt_count"] == 4
    assert ledger["validity_rate"] == 0.75  # 3 of 4 verify


def test_export_then_verify_round_trips(log: AgencyLog) -> None:
    ledger = export_ledger(log, subject_did=DID, as_of=NOW)
    res = verify_presented_ledger(ledger)
    assert res.ok and res.stage == "accepted"


def test_verify_presented_ledger_detects_tamper(log: AgencyLog) -> None:
    ledger = export_ledger(log, subject_did=DID, as_of=NOW)
    ledger["receipts"][0]["action"]["human_summary"] = "swapped after commitment"
    res = verify_presented_ledger(ledger)
    assert not res.ok and res.stage == "root_mismatch"


def test_facet_projection(log: AgencyLog) -> None:
    ledger = export_ledger(log, subject_did=DID, as_of=NOW)
    facet = agentfacts_facet(ledger, ledger_uri="https://me.example/ledger")
    assert facet["behavioral_merkle_root"] == ledger["behavioral_merkle_root"]
    assert facet["ledger_media_type"] == "application/vnd.nanda.receipts-ledger+json"
    assert "attested_by" not in facet  # self-published, no auditor attestation
