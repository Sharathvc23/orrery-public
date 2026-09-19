"""Verifiable Receipts Profile (VRP 0.1).

The receipt + ledger commitment + scoring primitives that compose ARP receipts
into a portable, reputation-aware credential: the ``behavioral_merkle_root``, the
``nanda-rep/0.1`` scoring method, and the Receipts Ledger object. Deterministic —
any party (issuer, verifier, resolver) recomputes the same root and score.

CRITICAL: ``behavioral_merkle_root`` here is NOT an RFC 6962 inclusion-proof tree;
the two are different commitments and MUST NEVER be interchanged:

  * an RFC 6962 tree uses domain-separated leaf/node hashes (0x00 / 0x01) with odd
    nodes promoted — for inclusion/consistency proofs over an append-only log.
  * ``behavioral_merkle_root`` (here) uses plain SHA-256 of the JCS bytes for
    leaves and plain SHA-256(left||right) for nodes, with odd nodes DUPLICATED —
    the commitment a resolver recomputes from a published Receipts Ledger.

Purity: nothing here imports the ARP verifier. "A receipt is valid" is supplied
by the caller as an ``is_valid`` callable, so this module composes with any
verifier without a cross-package import.
"""

from __future__ import annotations

import base64
import binascii
import copy
import hashlib
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any

import base58
import jcs
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

SCORING_METHOD = "nanda-rep/0.1"
SCORING_METHOD_V2 = "nanda-rep/0.2"  # counterparty-corroborated, collusion-resistant
LEDGER_MEDIA_TYPE = "application/vnd.nanda.receipts-ledger+json"

# nanda-rep/0.1 per-category weights (published as part of the scoring method).
# Consequential actions count for more than routine ones; administrative/governance
# categories are reputation-neutral; a breached commitment earns nothing.
DEFAULT_CATEGORY_WEIGHTS: dict[str, float] = {
    # financial / high-consequence
    "purchase": 5.0,
    "payment_sent": 5.0,
    "payment_received": 5.0,
    # commitments
    "commitment_entered": 4.0,
    "commitment_fulfilled": 4.0,
    "commitment_breached": 0.0,
    # attestations / governance-bearing
    "attestation_issued": 2.0,
    "attestation_received": 2.0,
    "vote_cast": 2.0,
    "decision_made": 2.0,
    "data_shared": 2.0,
    # routine
    "message_sent": 1.0,
    "message_received": 1.0,
    "appointment_booked": 1.0,
    "appointment_cancelled": 1.0,
    "subscription_changed": 1.0,
    "record_filed": 1.0,
    "account_created": 1.0,
    "account_closed": 1.0,
    # administrative — reputation-neutral
    "authority_granted": 0.0,
    "authority_revoked": 0.0,
    "other": 0.0,
}


# ── behavioral Merkle root ───────────────────────────


def _ordered_leaf_hashes(receipts: Sequence[dict[str, Any]]) -> list[bytes]:
    """Leaf hashes in the canonical order: by ``issued_at`` then ``receipt_id``
    ascending. Each leaf = SHA-256 of the receipt's JCS bytes INCLUDING its
    signature."""
    ordered = sorted(receipts, key=lambda r: (r.get("issued_at", ""), r.get("receipt_id", "")))
    return [hashlib.sha256(jcs.canonicalize(r)).digest() for r in ordered]


def behavioral_merkle_root(receipts: Sequence[dict[str, Any]]) -> str | None:
    """The ``sha256:<hex>`` commitment over ``receipts``.

    Plain binary Merkle tree: node = SHA-256(left || right); at any level with an
    odd count, the final node is DUPLICATED. Returns None for an empty ledger
    (its facet SHOULD be omitted). A single receipt's root is its leaf hash.
    """
    level = _ordered_leaf_hashes(receipts)
    if not level:
        return None
    while len(level) > 1:
        if len(level) % 2 == 1:
            level = [*level, level[-1]]  # duplicate the final node
        level = [hashlib.sha256(level[i] + level[i + 1]).digest() for i in range(0, len(level), 2)]
    return "sha256:" + level[0].hex()


# ── nanda-rep/0.1 scoring ────────────────────────────

IsValid = Callable[[dict[str, Any]], bool]


def validity_rate(receipts: Sequence[dict[str, Any]], *, is_valid: IsValid) -> float:
    """Fraction (0.0-1.0) of receipts that verify under their stated rules.
    Empty ledger -> 0.0."""
    if not receipts:
        return 0.0
    valid = sum(1 for r in receipts if is_valid(r))
    return valid / len(receipts)


def reputation_score(
    receipts: Sequence[dict[str, Any]],
    *,
    is_valid: IsValid,
    weights: dict[str, float] = DEFAULT_CATEGORY_WEIGHTS,
) -> float:
    """Sum of per-category weights over the VALID receipts. Reproducible
    by anyone with the ledger + this weight table."""
    total = 0.0
    for r in receipts:
        if is_valid(r):
            category = (r.get("action") or {}).get("category", "")
            total += weights.get(category, 0.0)
    return total


# ── nanda-rep/0.2: counterparty-corroborated, collusion-resistant ──
#
# nanda-rep/0.1 weights an agent's OWN valid receipts — forgeable by self-issuance.
# 0.2 (spec/vrp/0.3) requires a receipt to be INDEPENDENTLY CORROBORATED (its
# counterparty co-signed it, §A) AND to survive collusion severance (§B) before it
# builds reputation. Both are recomputable offline from the receipts + did:keys.


def _corroboration_payload(receipt: dict[str, Any]) -> bytes:
    """JCS bytes the counterparty signs: the receipt minus the two mutable signature
    carriers — top-level ``signature`` + ``evidence.witness_signatures``."""
    r = copy.deepcopy(receipt)
    r.pop("signature", None)
    evidence = r.get("evidence")
    if isinstance(evidence, dict):
        evidence.pop("witness_signatures", None)
        if not evidence:
            r.pop("evidence", None)  # an otherwise-empty evidence == no evidence (stable bytes)
    return bytes(jcs.canonicalize(r))


def _counterparty(receipt: dict[str, Any]) -> str | None:
    """The receipt's counterparty did, iff present and distinct from the issuer."""
    cp = (receipt.get("action") or {}).get("counterparty_did")
    return cp if cp and cp != receipt.get("issuer_did") else None


def is_corroborated(receipt: dict[str, Any]) -> bool:
    """True iff a DISTINCT counterparty co-signed this receipt (VRP 0.3 §A): a
    ``witness_signatures`` entry by ``counterparty_did`` whose signature verifies over
    the corroboration payload. Independent evidence, recomputable from the receipt."""
    cp = _counterparty(receipt)
    if cp is None:
        return False
    witnesses = (receipt.get("evidence") or {}).get("witness_signatures") or []
    payload = _corroboration_payload(receipt)
    for entry in witnesses:
        if not isinstance(entry, dict) or entry.get("witness_did") != cp:
            continue
        try:
            pubkey = pubkey_from_did_key(cp)
            Ed25519PublicKey.from_public_bytes(pubkey).verify(
                base64.b64decode(str(entry.get("signature", "")), validate=True), payload
            )
            return True
        except (InvalidSignature, ValueError, TypeError, binascii.Error):
            continue
    return False


def cosign_receipt(
    receipt: dict[str, Any], *, signing_key_bytes: bytes, witness_did: str | None = None
) -> dict[str, Any]:
    """Produce a counterparty co-signature for ``receipt`` (VRP 0.3 §A): the witness
    entry to append to ``evidence.witness_signatures``. The signer SHOULD be the
    receipt's ``counterparty_did``; ``witness_did`` defaults to the signer's did:key.
    Canonical so the corroboration payload the counterparty signs is byte-identical to
    what ``is_corroborated`` verifies."""
    sk = Ed25519PrivateKey.from_private_bytes(signing_key_bytes)
    pubkey = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    did = witness_did or did_key_from_pubkey(pubkey)
    signature = sk.sign(_corroboration_payload(receipt))
    return {"witness_did": did, "signature": base64.b64encode(signature).decode("ascii")}


def _corroboration_graph(
    receipts: Sequence[dict[str, Any]], *, is_valid: IsValid
) -> dict[str, dict[str, int]]:
    """Directed graph over corroborated, ARP-valid receipts: issuer -> counterparty."""
    graph: dict[str, dict[str, int]] = {}
    for r in receipts:
        if not is_valid(r) or not is_corroborated(r):
            continue
        a, b = r.get("issuer_did", ""), _counterparty(r) or ""
        graph.setdefault(a, {})
        graph.setdefault(b, {})
        graph[a][b] = graph[a].get(b, 0) + 1
    return graph


def _sccs(graph: dict[str, dict[str, int]]) -> list[list[str]]:
    """Tarjan strongly-connected components, deterministic; largest first."""
    index: dict[str, int] = {}
    low: dict[str, int] = {}
    stack: list[str] = []
    on_stack: set[str] = set()
    comps: list[list[str]] = []
    counter = [0]

    def connect(v: str) -> None:
        index[v] = low[v] = counter[0]
        counter[0] += 1
        stack.append(v)
        on_stack.add(v)
        for w in sorted(graph.get(v, {})):
            if w not in index:
                connect(w)
                low[v] = min(low[v], low[w])
            elif w in on_stack:
                low[v] = min(low[v], index[w])
        if low[v] == index[v]:
            comp: list[str] = []
            while True:
                w = stack.pop()
                on_stack.discard(w)
                comp.append(w)
                if w == v:
                    break
            comps.append(sorted(comp))

    for v in sorted(graph):
        if v not in index:
            connect(v)
    return sorted(comps, key=lambda c: (-len(c), c))


def _internal_density(graph: dict[str, dict[str, int]], members: set[str]) -> float:
    if len(members) < 2:
        return 0.0
    edges = sum(1 for a in members for b in graph.get(a, {}) if b in members and b != a)
    possible = len(members) * (len(members) - 1)
    return edges / possible if possible else 0.0


def _cross_edges(graph: dict[str, dict[str, int]], comp: set[str], other: set[str]) -> int:
    out = sum(1 for a in comp for b in graph.get(a, {}) if b in other)
    inc = sum(1 for a in other for b in graph.get(a, {}) if b in comp)
    return out + inc


def _severed_dids(graph: dict[str, dict[str, int]]) -> set[str]:
    """Dids in collusion structure ISOLATED from the honest anchor (VRP 0.3 §B):
    dense rings (size >= 3, density >= 0.8) AND mutual-only pairs (size 2)."""
    comps = _sccs(graph)
    if not comps:
        return set()
    anchor = set(comps[0])  # the largest SCC = the honest core
    severed: set[str] = set()
    for comp in comps[1:]:
        members = set(comp)
        if _cross_edges(graph, members, anchor) > 0:
            continue  # an honest agent transacted with it — not isolated
        if len(members) >= 3 and _internal_density(graph, members) >= 0.8:
            severed |= members
        elif len(members) == 2:
            a, b = comp
            if b in graph.get(a, {}) and a in graph.get(b, {}):  # mutual-only pair
                severed |= members
    return severed


def _effective_receipts(
    receipts: Sequence[dict[str, Any]], *, is_valid: IsValid
) -> list[dict[str, Any]]:
    """ARP-valid + corroborated + not touching a severed collusion component."""
    severed = _severed_dids(_corroboration_graph(receipts, is_valid=is_valid))
    out: list[dict[str, Any]] = []
    for r in receipts:
        if not is_valid(r) or not is_corroborated(r):
            continue
        if r.get("issuer_did") in severed or _counterparty(r) in severed:
            continue
        out.append(r)
    return out


def reputation_score_v2(
    receipts: Sequence[dict[str, Any]],
    *,
    is_valid: IsValid,
    weights: dict[str, float] = DEFAULT_CATEGORY_WEIGHTS,
) -> float:
    """nanda-rep/0.2 score (VRP 0.3 §C): category weights over GATED receipts —
    ARP-valid AND corroborated AND not collusion-severed. Uncorroborated/severed
    receipts earn zero (they still count toward ``validity_rate``)."""
    return sum(
        weights.get((r.get("action") or {}).get("category", ""), 0.0)
        for r in _effective_receipts(receipts, is_valid=is_valid)
    )


def corroboration_rate(receipts: Sequence[dict[str, Any]], *, is_valid: IsValid) -> float:
    """Share of ARP-valid receipts that are corroborated and not severed. 0.0 if none."""
    valid = [r for r in receipts if is_valid(r)]
    if not valid:
        return 0.0
    return len(_effective_receipts(receipts, is_valid=is_valid)) / len(valid)


# ── Receipts Ledger ────────────────────────────────────


def build_ledger(
    *,
    subject: str,
    receipts: Sequence[dict[str, Any]],
    is_valid: IsValid,
    as_of: str,
    weights: dict[str, float] = DEFAULT_CATEGORY_WEIGHTS,
    inline: bool = True,
    method: str = SCORING_METHOD,
) -> dict[str, Any]:
    """Assemble a ``application/vnd.nanda.receipts-ledger+json`` document.

    Self-describing: carries the root + derived scores so a resolver can both
    recompute and detect divergence. ``as_of`` is caller-supplied (this module
    takes no wall-clock). With ``inline=False`` the receipts are emitted as
    ``{receipt_id, receipt_hash}`` references. ``method`` selects the scoring method:
    ``nanda-rep/0.1`` (default) or ``nanda-rep/0.2`` (corroborated, §C) — the latter
    also publishes ``corroboration_rate``.
    """
    root = behavioral_merkle_root(receipts)
    if inline:
        receipts_field: list[dict[str, Any]] = list(receipts)
    else:
        receipts_field = [
            {
                "receipt_id": r.get("receipt_id"),
                "receipt_hash": "sha256:" + hashlib.sha256(jcs.canonicalize(r)).hexdigest(),
            }
            for r in receipts
        ]
    if method == SCORING_METHOD_V2:
        rep = reputation_score_v2(receipts, is_valid=is_valid, weights=weights)
    else:
        rep = reputation_score(receipts, is_valid=is_valid, weights=weights)
    ledger: dict[str, Any] = {
        "subject": subject,
        "scoring_method": method,
        "behavioral_merkle_root": root,
        "reputation_score": rep,
        "validity_rate": validity_rate(receipts, is_valid=is_valid),
        "receipt_count": len(receipts),
        "as_of": as_of,
        "receipts": receipts_field,
    }
    if method == SCORING_METHOD_V2:
        ledger["corroboration_rate"] = corroboration_rate(receipts, is_valid=is_valid)
    return ledger


def facet_from_ledger(
    ledger: dict[str, Any],
    *,
    ledger_uri: str,
    attested_by: str | None = None,
) -> dict[str, Any]:
    """Project a Receipts Ledger into the AgentFacts ``verifiable_receipts`` facet
    - the lightweight pointer published in discovery metadata."""
    facet: dict[str, Any] = {
        "ledger_uri": ledger_uri,
        "ledger_media_type": LEDGER_MEDIA_TYPE,
        "behavioral_merkle_root": ledger.get("behavioral_merkle_root"),
        "receipt_count": ledger.get("receipt_count"),
        "reputation_score": ledger.get("reputation_score"),
        "validity_rate": ledger.get("validity_rate"),
        "scoring_method": ledger.get("scoring_method", SCORING_METHOD),
        "as_of": ledger.get("as_of"),
    }
    if ledger.get("corroboration_rate") is not None:
        facet["corroboration_rate"] = ledger.get("corroboration_rate")
    if attested_by is not None:
        facet["attested_by"] = attested_by
    return facet


@dataclass
class LedgerVerification:
    ok: bool
    stage: str  # root_mismatch | score_mismatch | count_mismatch | not_recomputable | accepted
    detail: str

    @classmethod
    def accepted(cls) -> LedgerVerification:
        return cls(True, "accepted", "ledger recomputes to its published values")


def verify_ledger(
    ledger: dict[str, Any],
    *,
    is_valid: IsValid,
    weights: dict[str, float] = DEFAULT_CATEGORY_WEIGHTS,
    score_tolerance: float = 1e-9,
) -> LedgerVerification:
    """Recompute the root + nanda-rep values from the ledger's inline receipts and
    confirm they match the published values.

    A resolver SHOULD reject/down-rank a ledger whose recomputed values diverge.
    Requires inline receipts; a ref-only ledger is ``not_recomputable`` here (the
    caller must fetch the receipts first).
    """
    receipts = ledger.get("receipts")
    if not isinstance(receipts, list) or any("action" not in r for r in receipts):
        return LedgerVerification(False, "not_recomputable", "ledger receipts are not inline")

    declared = ledger.get("receipt_count")
    if declared != len(receipts):
        return LedgerVerification(False, "count_mismatch", f"count {declared} != {len(receipts)}")

    recomputed_root = behavioral_merkle_root(receipts)
    if recomputed_root != ledger.get("behavioral_merkle_root"):
        return LedgerVerification(False, "root_mismatch", "recomputed root differs from published")

    method = ledger.get("scoring_method", SCORING_METHOD)
    if method == SCORING_METHOD_V2:
        recomputed_score = reputation_score_v2(receipts, is_valid=is_valid, weights=weights)
    else:
        recomputed_score = reputation_score(receipts, is_valid=is_valid, weights=weights)
    if abs(recomputed_score - float(ledger.get("reputation_score", 0))) > score_tolerance:
        return LedgerVerification(False, "score_mismatch", "recomputed reputation_score differs")

    recomputed_validity = validity_rate(receipts, is_valid=is_valid)
    if abs(recomputed_validity - float(ledger.get("validity_rate", 0))) > score_tolerance:
        return LedgerVerification(False, "score_mismatch", "recomputed validity_rate differs")

    if method == SCORING_METHOD_V2:
        recomputed_corr = corroboration_rate(receipts, is_valid=is_valid)
        if abs(recomputed_corr - float(ledger.get("corroboration_rate", 0))) > score_tolerance:
            return LedgerVerification(
                False, "score_mismatch", "recomputed corroboration_rate differs"
            )

    return LedgerVerification.accepted()


# ── AgentFacts Attestation (VRP 0.2) ───────────────────
#
# VRP 0.1 left the binding between a facet's standing and the agent's published
# identity "out of scope" — so a metadata path could repoint ``ledger_uri`` at a
# higher-scoring ledger (substitution) or attach another agent's standing to its own
# id (subject confusion), and recomputation would still "pass". VRP 0.2 closes this:
# a credentialed authority (the chapter, in the reference deployment) signs a
# self-describing claim that binds the agent id + a digest of its facts record + the
# facet's ledger_uri + behavioral_merkle_root + lifecycle. A resolver that trusts the
# authority then knows the standing is THIS agent's, the metadata wasn't altered, and
# the ledger wasn't swapped — before it recomputes the numbers (verify_ledger).

LIFECYCLE_STATES = ("active", "suspended", "revoked")
_ED25519_MULTICODEC = b"\xed\x01"  # multicodec varint prefix for an Ed25519 public key


def did_key_from_pubkey(pubkey: bytes) -> str:
    """``did:key`` for a 32-byte Ed25519 public key (multicodec 0xed01 + base58btc)."""
    return "did:key:z" + base58.b58encode(_ED25519_MULTICODEC + pubkey).decode("ascii")


def pubkey_from_did_key(did: str) -> bytes:
    """Inverse of ``did_key_from_pubkey``. Raises ValueError on a non-Ed25519 did:key."""
    if not did.startswith("did:key:z"):
        raise ValueError("not a did:key")
    decoded = base58.b58decode(did[len("did:key:z") :])
    if decoded[:2] != _ED25519_MULTICODEC:
        raise ValueError("not an Ed25519 did:key")
    return decoded[2:]


def facts_digest(facts_record: dict[str, Any]) -> str:
    """``"sha256:<hex>"`` over the facts record with its ``attestation`` member
    removed (RFC 8785 / JCS). Covers identity + the verifiable_receipts facet in one
    commitment, so neither can be swapped under the authority's signature."""
    record = {k: v for k, v in facts_record.items() if k != "attestation"}
    return "sha256:" + hashlib.sha256(jcs.canonicalize(record)).hexdigest()


def _attestation_claim(
    *,
    attested_by: str,
    subject: Any,
    digest: str,
    ledger_uri: str | None,
    root: str | None,
    lifecycle: str,
    version: int,
    as_of: str,
) -> dict[str, Any]:
    """The signed claim, sans signature. ``ledger_uri``/``behavioral_merkle_root`` are
    present iff the record carries a facet."""
    claim: dict[str, Any] = {
        "attested_by": attested_by,
        "subject": subject,
        "facts_digest": digest,
        "lifecycle": lifecycle,
        "revoked": lifecycle == "revoked",
        "version": version,
        "as_of": as_of,
    }
    if ledger_uri is not None:
        claim["ledger_uri"] = ledger_uri
    if root is not None:
        claim["behavioral_merkle_root"] = root
    return claim


def build_attestation(
    *,
    facts_record: dict[str, Any],
    signing_key_bytes: bytes,
    as_of: str,
    version: int = 1,
    lifecycle: str = "active",
    attested_by: str | None = None,
) -> dict[str, Any]:
    """Sign an AgentFacts Attestation over ``facts_record`` (VRP 0.2 §A).

    The authority's Ed25519 ``signing_key_bytes`` signs the JCS bytes of the claim
    (sans signature). Returns the attestation object (claim + ``signature``) to attach
    to the facts record as its ``attestation`` member. ``attested_by`` defaults to the
    did:key derived from the signing key.
    """
    if lifecycle not in LIFECYCLE_STATES:
        raise ValueError(f"lifecycle must be one of {LIFECYCLE_STATES}")
    sk = Ed25519PrivateKey.from_private_bytes(signing_key_bytes)
    pubkey = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    facet = facts_record.get("verifiable_receipts") or {}
    claim = _attestation_claim(
        attested_by=attested_by or did_key_from_pubkey(pubkey),
        subject=facts_record.get("id"),
        digest=facts_digest(facts_record),
        ledger_uri=facet.get("ledger_uri"),
        root=facet.get("behavioral_merkle_root"),
        lifecycle=lifecycle,
        version=version,
        as_of=as_of,
    )
    signature = sk.sign(jcs.canonicalize(claim))
    return {**claim, "signature": base64.b64encode(signature).decode("ascii")}


@dataclass
class AttestationVerification:
    ok: bool
    # accepted | no_claim | attestation_missing | attestation_invalid |
    # facts_digest_mismatch | subject_mismatch | facet_binding_mismatch |
    # revoked | stale_attestation
    stage: str
    detail: str

    @classmethod
    def accepted(cls) -> AttestationVerification:
        return cls(True, "accepted", "attestation binds this standing to this identity")


def verify_attestation(
    facts_record: dict[str, Any],
    *,
    min_version: int | None = None,
) -> AttestationVerification:
    """Verify the AgentFacts Attestation on ``facts_record`` (VRP 0.2 §B steps 1-7).

    Establishes that the standing was vouched for, by ``attested_by``, for this exact
    agent identity, over this exact ledger — without trusting any host. Does NOT fetch
    or recompute the ledger itself (that is ``verify_ledger``, §B step 8). The caller
    decides whether it trusts ``attested_by``.
    """
    facet = facts_record.get("verifiable_receipts")
    att = facts_record.get("attestation")

    # §B.1 — a facet that asserts standing must carry an attestation.
    if att is None:
        if facet is None:
            return AttestationVerification(True, "no_claim", "record asserts no standing")
        return AttestationVerification(False, "attestation_missing", "facet without attestation")

    # §B.2 — signature over the claim (sans signature) under attested_by.
    claim = {k: v for k, v in att.items() if k != "signature"}
    try:
        pubkey = pubkey_from_did_key(str(att.get("attested_by", "")))
        Ed25519PublicKey.from_public_bytes(pubkey).verify(
            base64.b64decode(str(att.get("signature", "")), validate=True),
            jcs.canonicalize(claim),
        )
    except (InvalidSignature, ValueError, TypeError, binascii.Error):
        return AttestationVerification(False, "attestation_invalid", "signature does not verify")

    # revoked/lifecycle internal consistency (both are inside the signed claim).
    if bool(claim.get("revoked")) != (claim.get("lifecycle") == "revoked"):
        return AttestationVerification(
            False, "attestation_invalid", "revoked/lifecycle inconsistent"
        )

    # §B.3 — facts digest still matches the record (metadata not altered post-sign).
    if claim.get("facts_digest") != facts_digest(facts_record):
        return AttestationVerification(
            False, "facts_digest_mismatch", "facts record altered after signing"
        )

    # §B.4 — subject is this record's identity.
    if claim.get("subject") != facts_record.get("id"):
        return AttestationVerification(False, "subject_mismatch", "claim subject != record id")

    # §B.5 — the claim's ledger pointer + root match the published facet.
    if facet is not None and (
        claim.get("ledger_uri") != facet.get("ledger_uri")
        or claim.get("behavioral_merkle_root") != facet.get("behavioral_merkle_root")
    ):
        return AttestationVerification(
            False, "facet_binding_mismatch", "claim facet != published facet"
        )

    # §B.6 — lifecycle gate.
    if claim.get("lifecycle") == "revoked":
        return AttestationVerification(False, "revoked", "subject is revoked")

    # §B.7 — freshness / monotonic version (caller supplies the floor it has seen).
    if min_version is not None and int(claim.get("version", 0)) < min_version:
        return AttestationVerification(
            False, "stale_attestation", "version below the floor seen for subject"
        )

    return AttestationVerification.accepted()


__all__ = [
    "DEFAULT_CATEGORY_WEIGHTS",
    "LEDGER_MEDIA_TYPE",
    "LIFECYCLE_STATES",
    "SCORING_METHOD",
    "SCORING_METHOD_V2",
    "AttestationVerification",
    "LedgerVerification",
    "behavioral_merkle_root",
    "build_attestation",
    "build_ledger",
    "corroboration_rate",
    "cosign_receipt",
    "did_key_from_pubkey",
    "facet_from_ledger",
    "facts_digest",
    "is_corroborated",
    "pubkey_from_did_key",
    "reputation_score",
    "reputation_score_v2",
    "validity_rate",
    "verify_attestation",
    "verify_ledger",
]
