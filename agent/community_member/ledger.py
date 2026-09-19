"""Member-side VRP Receipts Ledger — export the member's own, verify anyone's.

The member's Agency Log is the substrate; this projects it into a portable
``application/vnd.nanda.receipts-ledger+json`` document (spec/vrp/0.1 §4)
carrying the ``behavioral_merkle_root`` + ``nanda-rep/0.1`` scores. That
document is what a new chapter (or sm-rep) consumes to make a reputation-aware
admission decision without trusting the member's host — it recomputes the root
and scores itself.

As a resolver, the member can verify ANY presented ledger the same way
(``verify_presented_ledger``). "A receipt is valid" is the member's OWN strict
ARP verification, so the published score reflects receipts that actually verify.

All commitment/scoring math is the published ``sm_arp.vrp``, drift-guarded against
canonical ``conformance/vrp`` by ``tests/test_vrp_lockstep.py``.
"""

from __future__ import annotations

from typing import Any

from sm_arp.vrp import (
    LEDGER_MEDIA_TYPE,
    SCORING_METHOD,
    AttestationVerification,
    LedgerVerification,
    behavioral_merkle_root,
    build_ledger,
    cosign_receipt,
    facet_from_ledger,
    verify_attestation,
    verify_ledger,
)

from .arp import AgencyLog, verify_receipt


def _is_valid(receipt: dict[str, Any]) -> bool:
    """A receipt counts toward nanda-rep iff it strict-verifies (schema +
    signature + chain/authority where applicable)."""
    return verify_receipt(receipt).ok


def export_ledger(
    agency_log: AgencyLog,
    *,
    subject_did: str,
    as_of: str,
    limit: int = 10_000,
    inline: bool = True,
    method: str = SCORING_METHOD,
    receipts: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build the member's Receipts Ledger from its Agency Log.

    ``as_of`` is caller-supplied (the SDK timestamps at the call site; this module
    takes no wall-clock). ``subject_did`` is the agent the ledger is about —
    normally the member's own did:key. ``method`` selects the scoring method
    (``nanda-rep/0.1`` default, or ``nanda-rep/0.2`` corroborated — spec/vrp/0.3).
    Pass ``receipts`` to commit to exactly that pre-fetched snapshot instead of
    re-reading the log — required when the caller pairs the ledger's root with
    per-receipt inclusion proofs (selective disclosure), where a second read
    could race a concurrent append and split the two.
    """
    if receipts is None:
        receipts = agency_log.list_recent(limit=limit)
    return build_ledger(
        subject=subject_did,
        receipts=receipts,
        is_valid=_is_valid,
        as_of=as_of,
        inline=inline,
        method=method,
    )


def corroborate(receipt: dict[str, Any], *, signing_key_bytes: bytes) -> dict[str, Any]:
    """Co-sign a receipt this member is the COUNTERPARTY to (VRP 0.3 §A) — independent
    evidence the interaction happened. Returns the witness entry to append to the
    receipt's ``evidence.witness_signatures``; under ``nanda-rep/0.2`` an uncorroborated
    receipt earns zero reputation, so the counterparty co-signing is what lets honest
    work count."""
    return cosign_receipt(receipt, signing_key_bytes=signing_key_bytes)


def verify_presented_ledger(ledger: dict[str, Any]) -> LedgerVerification:
    """Recompute a presented ledger's root + nanda-rep and confirm they match the
    published values — the resolver check, using the member's own ARP verifier."""
    return verify_ledger(ledger, is_valid=_is_valid)


def agentfacts_facet(
    ledger: dict[str, Any],
    *,
    ledger_uri: str,
    attested_by: str | None = None,
) -> dict[str, Any]:
    """Project a ledger into the AgentFacts ``verifiable_receipts`` facet
    (spec/vrp/0.1 §5) for publication on the member's agent card."""
    return facet_from_ledger(ledger, ledger_uri=ledger_uri, attested_by=attested_by)


def verify_presented_facts(
    facts_record: dict[str, Any],
    *,
    min_version: int | None = None,
) -> AttestationVerification:
    """Resolver check on a presented AgentFacts record's trust binding (VRP 0.2 §B
    steps 1-7): is this standing cryptographically this agent's, over this exact
    ledger, un-substituted and un-tampered?

    Returns the binding verdict; the caller still (a) decides whether it trusts the
    ``attested_by`` authority, and (b) recomputes the ledger itself via
    ``verify_presented_ledger`` (§B step 8). A score that passes the binding but not
    recomputation is still untrustworthy.
    """
    return verify_attestation(facts_record, min_version=min_version)


__all__ = [
    "LEDGER_MEDIA_TYPE",
    "SCORING_METHOD",
    "agentfacts_facet",
    "behavioral_merkle_root",
    "corroborate",
    "export_ledger",
    "verify_presented_facts",
    "verify_presented_ledger",
]
