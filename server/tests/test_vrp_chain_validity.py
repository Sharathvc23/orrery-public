"""The flagship-loop suite regression: ledger validity is CHAIN-AWARE.

The flagship-loop e2e probe caught the server validating each pushed receipt
in isolation — any receipt carrying previous_receipt_hash (i.e. every receipt
after an agent's first) failed at the hash_chain stage, so validity_rate
DECAYED with every interaction an agent made. build_principal_ledger now
validates with the ledger's own receipt set as priors.

Receipts are generated at test time with the conformance vector generator
(deterministic seeded keys — no hardcoded signatures or DIDs).

Classification: HAPPY / ADVERSARIAL.
"""

import hashlib
import uuid

from conformance.arp._vector_gen import (  # deterministic, seeded
    ISSUER_SK,
    base_receipt,
    receipt_hash_chain_link,
    sign_receipt,
)

import vrp


def _rid(name: str) -> str:
    """Deterministic UUID4-shaped receipt id (the ARP schema requires v4)."""
    return str(uuid.UUID(bytes=hashlib.sha256(name.encode()).digest()[:16], version=4))


def _chained_pair() -> tuple[dict, dict]:
    r1 = sign_receipt(
        ISSUER_SK,
        base_receipt(
            receipt_id=_rid("chain-r1"),
            issued_at="2026-01-01T00:00:00Z",
            category="message_sent",
            human_summary="first receipt (no prior)",
        ),
    )
    r2 = sign_receipt(
        ISSUER_SK,
        base_receipt(
            receipt_id=_rid("chain-r2"),
            issued_at="2026-01-01T00:01:00Z",
            category="message_sent",
            human_summary="second receipt, chained to the first",
            previous_receipt_hash=receipt_hash_chain_link(r1),
        ),
    )
    return r1, r2


def test_isolated_validation_rejects_chained_receipt():
    """Documents the OLD failure mode: in isolation, the chained receipt is
    invalid (hash_chain unsatisfiable) — this is what decayed validity_rate."""
    r1, r2 = _chained_pair()
    assert vrp._is_valid(r1) is True
    assert vrp._is_valid(r2) is False  # why the ledger-aware closure exists


def test_ledger_aware_validation_accepts_the_whole_chain():
    """HAPPY (the fix): with the ledger's own receipts as priors, both are valid."""
    r1, r2 = _chained_pair()
    check = vrp._ledger_is_valid([r1, r2])
    assert check(r1) is True
    assert check(r2) is True


def test_ledger_aware_validation_still_rejects_broken_chain():
    """ADVERSARIAL: a receipt whose previous_receipt_hash matches NO ledger
    receipt stays invalid — chain integrity is checked, not waived."""
    r1, r2 = _chained_pair()
    orphan = sign_receipt(
        ISSUER_SK,
        base_receipt(
            receipt_id=_rid("chain-orphan"),
            issued_at="2026-01-01T00:02:00Z",
            category="message_sent",
            human_summary="chained to a receipt the ledger never saw",
            previous_receipt_hash="sha256:" + "0" * 64,
        ),
    )
    check = vrp._ledger_is_valid([r1, r2, orphan])
    assert check(r2) is True
    assert check(orphan) is False


def test_ledger_aware_validation_rejects_tampered_receipt():
    """ADVERSARIAL: priors don't weaken signature checks — tampering with a
    chained receipt still fails."""
    r1, r2 = _chained_pair()
    tampered = dict(r2)
    tampered["action"] = dict(r2["action"], human_summary="tampered")
    check = vrp._ledger_is_valid([r1, tampered])
    assert check(tampered) is False
