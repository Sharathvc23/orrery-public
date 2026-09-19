"""Auto-emit ARP receipts for agent↔service interactions.

Every time the agent acts on another agent or service — an A2A call, a skill
invocation, a service query — it records a signed ARP receipt naming the
counterparty. Those receipts are the substrate a rating / auditor agent scores:
the interaction graph builds itself from real calls, instead of someone calling
``emit()`` by hand. The signed counterparty edge is what makes the resulting
reputation earned-and-witnessed rather than self-declared.

This is a thin, opinionated convenience over ``arp.emit`` that standardises the
"interaction receipt" shape. It does NOT change the ARP envelope or add
co-signing (that would be a spec change); the counterparty is recorded by DID on
the issuer's own receipt, exactly as the v0.1 schema already allows.
"""

from __future__ import annotations

from typing import Any

from .arp import (
    AgencyLog,
    _push_to_chapter,
    build_receipt,
    did_from_private_key,
    sign_receipt,
)
from .cosign import WitnessFetcher, attach_corroboration

# A2A / service calls are "message_sent" by default; callers override for
# data_shared, attestation_issued, vote_cast, etc.
DEFAULT_CATEGORY = "message_sent"


def build_interaction_receipt(
    *,
    sk_bytes: bytes,
    counterparty_did: str,
    counterparty_label: str,
    summary: str,
    agency_log: AgencyLog | None = None,
    category: str = DEFAULT_CATEGORY,
    outcome: str = "completed",
    **envelope_extras: Any,
) -> dict:
    """Assemble the **unsigned** interaction receipt — the form a counterparty
    co-signs (``spec/arp/0.2/cosign-companion.md`` §1: the issuer sends this,
    minus its signature, as the corroboration payload). Hash-chains to the
    issuer's tip in ``agency_log`` unless ``previous_receipt_hash`` is given.

    Kept separate from :func:`finalize_interaction` so the co-sign round-trip can
    run *between* build and signature — the witness entry must be inserted before
    the issuer signs (the issuer signature covers ``evidence.witness_signatures``).
    """
    issuer_did = did_from_private_key(sk_bytes)
    if "previous_receipt_hash" not in envelope_extras and agency_log is not None:
        tip = agency_log.tip(issuer_did=issuer_did)
        if tip is not None:
            envelope_extras["previous_receipt_hash"] = tip

    action = {
        "category": category,
        "human_summary": summary,
        "outcome": outcome,
        "counterparty_did": counterparty_did,
        "counterparty_label": counterparty_label,
    }
    return build_receipt(
        action=action,
        issuer_did=issuer_did,
        principal_did=issuer_did,
        **envelope_extras,
    )


def finalize_interaction(
    receipt: dict,
    *,
    sk_bytes: bytes,
    agency_log: AgencyLog | None = None,
    chapter_url: str | None = None,
    push: bool = False,
) -> dict:
    """Sign the (possibly co-signed) receipt, persist to the Agency Log, and
    optionally push to the chapter. Signing here, after any witness entry is
    attached, is what makes the issuer signature cover the corroboration."""
    sign_receipt(receipt, sk_bytes)
    if agency_log is not None:
        agency_log.append(receipt)
    if push and chapter_url:
        _push_to_chapter(receipt, chapter_url)
    return receipt


def record_interaction(
    *,
    sk_bytes: bytes,
    agency_log: AgencyLog,
    counterparty_did: str,
    counterparty_label: str,
    summary: str,
    category: str = DEFAULT_CATEGORY,
    outcome: str = "completed",
    chapter_url: str | None = None,
    push: bool = False,
    witness_fetcher: WitnessFetcher | None = None,
    **envelope_extras: Any,
) -> dict:
    """Record a signed receipt for one interaction with a counterparty.

    Returns the signed receipt. ``push=True`` also forwards it to the chapter's
    Issuer Log (``chapter_url`` required); by default the receipt is local-only
    (the principal's Agency Log is authoritative).

    When ``witness_fetcher`` is provided, the counterparty is asked to co-sign the
    receipt before it is finalized (``cosign-companion.md`` §1). A successful
    co-signature makes the receipt **corroborated** — the only form that builds
    reputation under ``nanda-rep/0.2`` (VRP 0.3 §A). A counterparty that declines
    or is unreachable yields a valid, **uncorroborated** receipt — never an error
    (§3). Exactly one receipt is emitted, by the actor; the counterparty witnesses
    but does not emit a mirror receipt (§2).

    The receipt is hash-chained to this issuer's previous receipt in the Agency
    Log (``previous_receipt_hash`` = the log's per-issuer tip). A caller may
    override by passing ``previous_receipt_hash``; the first receipt for an issuer
    is genesis (no prev hash).
    """
    receipt = build_interaction_receipt(
        sk_bytes=sk_bytes,
        counterparty_did=counterparty_did,
        counterparty_label=counterparty_label,
        summary=summary,
        agency_log=agency_log,
        category=category,
        outcome=outcome,
        **envelope_extras,
    )
    if witness_fetcher is not None:
        attach_corroboration(receipt, witness_fetcher)
    return finalize_interaction(
        receipt,
        sk_bytes=sk_bytes,
        agency_log=agency_log,
        chapter_url=chapter_url,
        push=push,
    )
