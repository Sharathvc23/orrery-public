"""DAT — Delegated Authority Token (the ``dat/0.1`` companion to ARP).

ARP records *what an agent did*; a
DAT records *what it was allowed to do*. The key distinction from an ARP receipt:
a DAT is signed by the **grantor** (the principal, or a delegate already
authorized to grant), not by the acting agent — so authority is traceable, never
self-claimed.

* Ed25519 signature over the RFC 8785 (JCS) canonical body sans-``signature``.
* ``not_before`` / ``not_after`` validity window.
* scoped to a set of action categories with optional constraints.
* **sub-delegation**: a DAT may name a parent via ``granted_by``; a verifier
  walks the chain to a root, enforcing each child's scope ⊆ its parent's and
  that the child's grantor is the parent's grantee (delegation continuity), up
  to a depth limit, rejecting cycles.
* revocable: a verifier rejects any ``grant_id`` in a revocation set.

A real chain looks like operator → chapter → member. Pure/verifiable; no chapter
state required.
"""

from __future__ import annotations

import base64
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import base58
import jcs
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

DAT_VERSION = "dat/0.1"
MAX_CHAIN_DEPTH = 5
_PREFIX = b"\xed\x01"


def _now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _pubkey_from_did(did: str) -> Ed25519PublicKey:
    raw = base58.b58decode(did[len("did:key:z") :])
    if not raw.startswith(_PREFIX):
        raise ValueError("not an Ed25519 did:key")
    return Ed25519PublicKey.from_public_bytes(raw[len(_PREFIX) :])


def make_grant_id(grantor_did: str) -> str:
    return f"dat:{grantor_did}:{uuid.uuid4()}"


def build_dat(
    *,
    grantor_sk_bytes: bytes,
    grantor_did: str,
    grantee_did: str,
    action_categories: list[str],
    not_after: str,
    not_before: str | None = None,
    constraints: dict[str, Any] | None = None,
    granted_by: str | None = None,
    human_summary: str | None = None,
) -> dict[str, Any]:
    """Assemble and sign a DAT envelope with the grantor's own key."""
    issued = _now_iso()
    scope: dict[str, Any] = {"action_categories": action_categories}
    if constraints:
        scope["constraints"] = constraints
    dat: dict[str, Any] = {
        "version": DAT_VERSION,
        "grant_id": make_grant_id(grantor_did),
        "grantor_did": grantor_did,
        "grantee_did": grantee_did,
        "issued_at": issued,
        "not_before": not_before or issued,
        "not_after": not_after,
        "scope": scope,
        "human_summary": (
            human_summary
            or f"Granted {grantee_did[:24]}… authority over {', '.join(action_categories)} until {not_after}."
        )[:280],
    }
    if granted_by:
        dat["granted_by"] = granted_by
    sig = Ed25519PrivateKey.from_private_bytes(grantor_sk_bytes).sign(jcs.canonicalize(dat))
    dat["signature"] = base64.b64encode(sig).decode("ascii")
    return dat


@dataclass
class DatResult:
    ok: bool
    stage: str  # signature | window | scope | delegation | revoked | depth | accepted
    detail: str

    @classmethod
    def accepted(cls) -> DatResult:
        return cls(True, "accepted", "DAT verifies")


def verify_dat_signature(dat: dict[str, Any]) -> DatResult:
    try:
        pubkey = _pubkey_from_did(dat["grantor_did"])
        body = {k: v for k, v in dat.items() if k != "signature"}
        pubkey.verify(base64.b64decode(dat["signature"]), jcs.canonicalize(body))
    except InvalidSignature:
        return DatResult(False, "signature", "DAT signature does not verify")
    except Exception as e:
        return DatResult(False, "signature", f"unresolvable grantor/signature: {e}")
    return DatResult.accepted()


def _categories(dat: dict[str, Any]) -> set[str]:
    return set(dat.get("scope", {}).get("action_categories", []))


def verify_dat_chain(
    grant_id: str,
    *,
    dats_by_id: dict[str, dict[str, Any]],
    now: str,
    category: str | None = None,
    revocations: set[str] | None = None,
) -> DatResult:
    """Walk a DAT from ``grant_id`` to its root, enforcing the full ruleset."""
    revocations = revocations or set()
    seen: set[str] = set()
    current_id: str | None = grant_id
    child_grantor: str | None = None  # grantee the previous (child) hop expected
    depth = 0

    while current_id is not None:
        if depth >= MAX_CHAIN_DEPTH:
            return DatResult(False, "depth", f"chain exceeds depth {MAX_CHAIN_DEPTH}")
        if current_id in seen:
            return DatResult(False, "delegation", "cycle in DAT chain")
        seen.add(current_id)

        dat = dats_by_id.get(current_id)
        if dat is None:
            return DatResult(False, "delegation", f"DAT {current_id} not found")
        if current_id in revocations:
            return DatResult(False, "revoked", f"DAT {current_id} is revoked")

        sig = verify_dat_signature(dat)
        if not sig.ok:
            return sig
        if not (dat["not_before"] <= now <= dat["not_after"]):
            return DatResult(False, "window", f"{current_id} outside validity window")

        # Delegation continuity: a child's grantor must be this DAT's grantee.
        if child_grantor is not None and child_grantor != dat["grantee_did"]:
            return DatResult(False, "delegation", "grantor is not the parent's grantee")
        # Category scope is checked against the *leaf* grant only.
        if category is not None and depth == 0:
            if category not in _categories(dat) and "*" not in _categories(dat):
                return DatResult(False, "scope", f"category {category!r} outside grant scope")

        parent_id = dat.get("granted_by")
        if parent_id is not None:
            parent = dats_by_id.get(parent_id)
            if parent is None:
                return DatResult(False, "delegation", f"parent {parent_id} not found")
            # A sub-delegation may not widen scope beyond its parent.
            if "*" not in _categories(parent) and not _categories(dat) <= _categories(parent):
                return DatResult(False, "scope", "sub-delegation widens scope beyond parent")

        child_grantor = dat["grantor_did"]
        current_id = parent_id
        depth += 1

    return DatResult.accepted()


@dataclass
class ConstraintResult:
    ok: bool
    stage: str
    detail: str

    @classmethod
    def accepted(cls) -> ConstraintResult:
        return cls(True, "accepted", "constraints satisfied")


def _counterparty_matches(entry: str, receipt: dict[str, Any]) -> bool:
    """Match one allowlist entry against a receipt's counterparty.

    Forms: ``*`` (any), an exact did:key, ``did:<did>``, ``label:<name>``,
    ``domain:<host>`` (matched against counterparty_label or evidence refs).
    """
    if entry == "*":
        return True
    cp_did = receipt["action"].get("counterparty_did", "")
    cp_label = receipt["action"].get("counterparty_label", "")
    if entry.startswith("did:"):
        return entry == cp_did
    if entry.startswith("label:"):
        return entry[len("label:") :] == cp_label
    if entry.startswith("domain:"):
        host = entry[len("domain:") :]
        refs = receipt.get("evidence", {}).get("external_refs", [])
        return host in cp_label or any(host in str(x) for x in refs)
    return entry == cp_did


def evaluate_constraints(
    constraints: dict[str, Any], receipt: dict[str, Any], *, period_spent_cents: int = 0
) -> ConstraintResult:
    """Evaluate a DAT's ``scope.constraints`` against one ARP receipt.

    Constraints that don't apply to a receipt (e.g. amount caps on a no-amount
    receipt) are skipped — conservative.
    """
    amount = receipt["action"].get("amount")
    if amount is not None:
        cents = abs(int(amount.get("cents", 0)))
        currency = amount.get("currency")
        want_ccy = constraints.get("amount_currency")
        if want_ccy is not None and currency != want_ccy:
            return ConstraintResult(False, "currency", f"currency {currency} != allowed {want_ccy}")
        per_action = constraints.get("amount_cents_per_action_max")
        if per_action is not None and cents > per_action:
            return ConstraintResult(False, "amount_action", f"{cents}c exceeds per-action cap {per_action}c")
        per_period = constraints.get("amount_cents_per_period_max")
        if per_period is not None and period_spent_cents + cents > per_period:
            return ConstraintResult(
                False,
                "amount_period",
                f"period spend {period_spent_cents + cents}c exceeds cap {per_period}c",
            )

    allow = constraints.get("counterparty_allowlist")
    if allow is not None and receipt["action"].get("counterparty_did"):
        if not any(_counterparty_matches(e, receipt) for e in allow):
            return ConstraintResult(
                False,
                "counterparty",
                f"counterparty {receipt['action']['counterparty_did'][:24]}… not on allowlist",
            )

    juris = constraints.get("jurisdictions")
    if juris is not None:
        locus = receipt.get("jurisdiction", {}).get("action_locus")
        if locus is not None and locus not in juris:
            return ConstraintResult(False, "jurisdiction", f"action_locus {locus} not in {juris}")

    return ConstraintResult.accepted()
