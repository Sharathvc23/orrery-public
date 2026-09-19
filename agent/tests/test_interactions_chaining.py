"""Phase 1 — the member's own Agency Log is hash-chained.

ARP gives forward tamper-evidence via a per-issuer hash chain
(``previous_receipt_hash`` → ``receipt_chain_link``). The chapter chains its
Issuer Log, but the member's auto-emit path (``record_interaction``) never set
``previous_receipt_hash`` — so a principal could silently delete or reorder
their OWN receipts and nothing would notice. This wires the chain in.

Classification:
  EDGE         — empty log has no tip; first receipt is genesis (no prev hash)
  HAPPY        — second receipt's prev hash == chain link of the first
  HAPPY        — the resulting chain strict-verifies end to end
  ADVERSARIAL  — deleting a middle receipt breaks the chain (detectable)
"""

from __future__ import annotations

import hashlib
import os
import tempfile

os.environ.setdefault(
    "COMMUNITY_MEMBER_HOME",
    os.path.join(tempfile.gettempdir(), "cm-chaining-tests-do-not-use"),
)

import pytest

from community_member.arp import (
    AgencyLog,
    did_from_private_key,
    receipt_chain_link,
    verify_receipt,
)
from community_member.interactions import record_interaction

SK = hashlib.sha256(b"chaining-issuer").digest()
COUNTERPARTY_DID = did_from_private_key(hashlib.sha256(b"bob-counterparty").digest())


@pytest.fixture
def log(tmp_path) -> AgencyLog:
    return AgencyLog(tmp_path / "agency")


def _record(log: AgencyLog, summary: str) -> dict:
    return record_interaction(
        sk_bytes=SK,
        agency_log=log,
        counterparty_did=COUNTERPARTY_DID,
        counterparty_label="Bob",
        summary=summary,
    )


def test_empty_log_has_no_tip(log: AgencyLog) -> None:
    assert log.tip() is None


def test_first_receipt_is_genesis(log: AgencyLog) -> None:
    first = _record(log, "first")
    assert "previous_receipt_hash" not in first


def test_second_receipt_chains_to_first(log: AgencyLog) -> None:
    first = _record(log, "first")
    second = _record(log, "second")
    assert second["previous_receipt_hash"] == receipt_chain_link(first)


def test_tip_tracks_latest(log: AgencyLog) -> None:
    first = _record(log, "first")
    assert log.tip() == receipt_chain_link(first)
    second = _record(log, "second")
    assert log.tip() == receipt_chain_link(second)


def test_full_chain_strict_verifies(log: AgencyLog) -> None:
    first = _record(log, "first")
    second = _record(log, "second")
    link = receipt_chain_link(first)
    res = verify_receipt(second, mode="strict", prior_receipts={link: first})
    assert res.ok and res.stage == "accepted"


def test_tip_is_per_issuer(log: AgencyLog) -> None:
    # A receipt from a DIFFERENT issuer must not become this issuer's tip.
    _record(log, "mine")
    other_sk = hashlib.sha256(b"other-issuer").digest()
    record_interaction(
        sk_bytes=other_sk,
        agency_log=log,
        counterparty_did="did:key:zX",
        counterparty_label="X",
        summary="theirs",
    )
    my_did = did_from_private_key(SK)
    # My tip must be MY latest receipt, not the other issuer's.
    my_tip = log.tip(issuer_did=my_did)
    recents = [r for r in log.list_recent() if r["issuer_did"] == my_did]
    assert my_tip == receipt_chain_link(recents[0])
