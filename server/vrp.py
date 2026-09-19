"""Chapter-side VRP — build a signed, reputation-aware Receipts Ledger per principal.

The chapter reads a principal's receipts from its Issuer Log, builds the VRP 0.1
Receipts Ledger (``behavioral_merkle_root`` + ``nanda-rep/0.1`` scores), and
ATTESTS it: the chapter signs the behavioral root with its own key, so a resolver
(or sm-rep's admission gate) can rely on the chapter-credentialed root without
trusting the chapter's live server — it verifies the signature + recomputes.

Two products:
  * the **AgentFacts ``verifiable_receipts`` facet** (root + scores + attested_by,
    NO receipt contents) — safe to publish in discovery metadata; and
  * the **full Receipts Ledger** (inline receipts) — privacy-sensitive, served
    dev/offline-only for now (production visibility tiers are a follow-up).

Validity is the chapter's own strict ARP verification (vendored ``_arp_verify``);
the commitment + scoring math is the ``sm_arp.vrp`` package (drift-guarded against
canonical ``conformance/vrp`` by ``tests/test_vrp_lockstep.py``).
"""

from __future__ import annotations

import base64
import os
from datetime import UTC, datetime
from typing import Any

import jcs
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sm_arp.vrp import build_attestation, build_ledger, facet_from_ledger

from _arp_verify import verify_receipt

# Scoring methods this server can compute + serve (spec/vrp/0.3 §3.1). Method-
# namespaced: a resolver MUST NOT compare scores across methods, so an unknown
# method is an explicit error, never silently coerced. nanda-rep/0.2 is the
# counterparty-corroborated, collusion-resistant score; 0.1 is self-attested.
SUPPORTED_SCORING_METHODS = ("nanda-rep/0.1", "nanda-rep/0.2")


def _resolve_default_scoring_method() -> str:
    """The scoring method this chapter PUBLISHES by default — the value the
    AgentFacts facet + ledger use when no ``?scoring_method=`` is requested.

    Defaults to ``nanda-rep/0.1`` (self-attested) so live standings are unchanged.
    A chapter "flips" to the corroborated score by setting the
    ``DEFAULT_SCORING_METHOD`` env var to ``nanda-rep/0.2`` — a deliberate,
    reversible, per-chapter ops decision (uncorroborated members then publish a
    reputation_score of 0 until co-signing accrues). An unrecognised value falls
    back to 0.1 rather than failing the chapter at boot.
    """
    method = os.environ.get("DEFAULT_SCORING_METHOD", "nanda-rep/0.1").strip()
    if method not in SUPPORTED_SCORING_METHODS:
        print(f"[vrp] ignoring unsupported DEFAULT_SCORING_METHOD={method!r}; using nanda-rep/0.1")
        return "nanda-rep/0.1"
    if method != "nanda-rep/0.1":
        print(f"[vrp] publishing {method} as the DEFAULT scoring method (flipped)")
    return method


DEFAULT_SCORING_METHOD = _resolve_default_scoring_method()


def _is_valid(receipt: dict[str, Any]) -> bool:
    return verify_receipt(receipt).ok


def _ledger_is_valid(receipts: list[dict[str, Any]]):
    """Ledger-aware validity closure: chained receipts validate against
    the ledger's OWN receipt set as priors. The flagship-loop e2e probe caught
    the isolated form rejecting every receipt after an agent's FIRST at the
    hash_chain stage — validity_rate decayed with every interaction because
    verify_receipt saw no priors."""
    from _arp_verify import compute_chain_link

    priors: dict[str, dict[str, Any]] = {}
    for r in receipts:
        try:
            priors[compute_chain_link(r)] = r
        except Exception:  # noqa: BLE001 — an unhashable receipt is simply not a usable prior
            continue

    def check(receipt: dict[str, Any]) -> bool:
        return verify_receipt(receipt, prior_receipts=priors).ok

    return check


def _now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


async def build_principal_ledger(
    principal_did: str,
    *,
    ledger_uri: str,
    as_of: str | None = None,
    limit: int = 10_000,
    method: str = "nanda-rep/0.1",
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return ``(ledger, facet)`` for ``principal_did`` from the chapter's Issuer Log.

    The ledger carries inline receipts + a chapter ``attestation`` (Ed25519 over
    the behavioral root + as_of). The facet is the lightweight, contents-free
    projection for AgentFacts. If the chapter has no keypair or the principal has
    no receipts, the ledger is returned un-attested (``attested_by`` omitted).

    ``method`` selects the scoring method (spec/vrp/0.3): ``nanda-rep/0.1`` (default,
    category weights over the principal's own valid receipts) or ``nanda-rep/0.2``
    (counterparty-corroborated, collusion-resistant — uncorroborated receipts earn
    zero). Defaulting to 0.1 keeps live standings stable until counterparty
    co-signing is adopted; flipping the default is a separate deployment decision.
    """
    import arp as _arp

    if method not in SUPPORTED_SCORING_METHODS:
        raise ValueError(f"unsupported scoring_method: {method!r}; expected one of {SUPPORTED_SCORING_METHODS}")

    as_of = as_of or _now_iso()
    receipts = await _arp.list_for_principal(principal_did, limit=limit)
    ledger = build_ledger(
        subject=principal_did, receipts=receipts, is_valid=_ledger_is_valid(receipts), as_of=as_of, method=method
    )

    attested_by: str | None = None
    keypair = _arp._chapter_keypair_bytes()
    root = ledger.get("behavioral_merkle_root")
    if keypair is not None and root is not None:
        sk_bytes, chapter_did = keypair
        payload = {"behavioral_merkle_root": root, "as_of": as_of}
        sig = Ed25519PrivateKey.from_private_bytes(sk_bytes).sign(jcs.canonicalize(payload))
        ledger["attestation"] = {
            "attested_by": chapter_did,
            "signature": base64.b64encode(sig).decode("ascii"),
        }
        attested_by = chapter_did

    facet = facet_from_ledger(ledger, ledger_uri=ledger_uri, attested_by=attested_by)
    return ledger, facet


def attest_facts_record(
    facts_record: dict[str, Any],
    *,
    as_of: str | None = None,
    version: int = 1,
    lifecycle: str = "active",
) -> dict[str, Any]:
    """Attach a VRP 0.2 AgentFacts Attestation, signed by the chapter key, to
    ``facts_record`` (in place) and return it.

    The chapter is the credentialed authority (spec/vrp/0.2 §A.1): it signs a claim
    binding the agent identity + a digest of the whole facts record + the facet's
    ``ledger_uri`` + ``behavioral_merkle_root``, so a resolver that trusts the chapter
    knows this standing is this agent's and the ledger was not substituted. Build the
    attestation LAST — ``facts_digest`` covers every other member of the record. If the
    chapter has no keypair (uninitialised/tests), the record is returned un-attested
    (a resolver then treats its standing as unverifiable, never as zero).
    """
    import arp as _arp

    keypair = _arp._chapter_keypair_bytes()
    if keypair is None:
        return facts_record
    sk_bytes, chapter_did = keypair
    facts_record["attestation"] = build_attestation(
        facts_record=facts_record,
        signing_key_bytes=sk_bytes,
        as_of=as_of or _now_iso(),
        version=version,
        lifecycle=lifecycle,
        attested_by=chapter_did,
    )
    return facts_record


__all__ = [
    "DEFAULT_SCORING_METHOD",
    "SUPPORTED_SCORING_METHODS",
    "attest_facts_record",
    "build_principal_ledger",
]
