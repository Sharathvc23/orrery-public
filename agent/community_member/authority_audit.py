"""Walk a delegated authority to its root and say where it broke.

The gate and the audit answer different questions
-------------------------------------------------
``verify_dat_chain`` answers *may this call proceed?* — it stops at the first
failure, because a caller that already knows the answer is "no" has no use for
the rest. An operator asking *why can my agent no longer act?* needs the
opposite: the whole chain, every hop, and which one severed it. Stopping at the
first problem tells them a grant is bad; it does not tell them the chapter's
authority expired two hops up while their own grant is fine.

So this module walks the chain and **reports**, where the verifier walks and
**decides**.

One source of verification truth
--------------------------------
The temptation with an audit view is to re-implement the rules so the report can
be richer. That produces two verifiers that agree until the day they do not, and
the one nobody runs in production is the one that drifts. Instead the verdict
here is :func:`verify_dat_chain`'s verdict — this module adds visibility, never a
second opinion. When the per-hop report and the verifier disagree, that
disagreement is itself reported (``verdict="disputed"``) rather than resolved in
favour of either, because a divergence between the auditor and the gate is a
finding about this code, not about the chain.

Offline, and it never calls back
--------------------------------
Same contract as ``aae_audit``: everything comes from the DATs handed in and the
revocation set handed in. No network, no resolution, nothing that could make the
audit's answer depend on who is watching.

What a walk establishes, and what it does not
---------------------------------------------
It establishes that each hop is signed by the key its child names as grantor,
that the hops form an unbroken grantor→grantee line to a root, that no hop
widens the scope it was given, and that no hop is in the revocation set supplied.

It does **not** establish that the root is the real operator — a chain to a key
nobody has attested is a well-formed chain to a stranger, and ``owner.py`` is
what binds a principal to a person. It does not establish that no revocation
exists: the set is what this member was told, and a withdrawal published
somewhere this member never read is invisible here. And it walks the **DAT**
chain (``granted_by`` / ``grant_id``), which is not the ARP receipt chain
(``granted_by_receipt_id`` / ``authority_revoked``) — two mechanisms that both
say "revoked" about different objects, so a clean walk here says nothing about
that one.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from ._dat import MAX_CHAIN_DEPTH, verify_dat_chain, verify_dat_signature

__all__ = ["NOT_ESTABLISHED", "Hop", "Walk", "walk_authority"]

NOT_ESTABLISHED = (
    "that the root grantor is the agent's real principal — a chain to an "
    "unattested key is a well-formed chain to a stranger",
    "that no revocation exists: the set walked is what this member was told, "
    "and a withdrawal published elsewhere is invisible here",
    "anything about the ARP receipt chain (granted_by_receipt_id / "
    "authority_revoked), which is a separate mechanism over different objects",
)


def _now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _categories(dat: dict[str, Any]) -> set[str]:
    return set((dat.get("scope") or {}).get("action_categories", []))


@dataclass(frozen=True)
class Hop:
    """One grant in the chain, and everything checkable about it."""

    grant_id: str
    grantor_did: str
    grantee_did: str
    not_before: str
    not_after: str
    categories: tuple[str, ...]
    signature_ok: bool
    within_window: bool
    revoked: bool
    #: Continuity with the hop below: this grant's grantee must be that grant's
    #: grantor. ``None`` on the leaf, which has nothing below it.
    continuous_with_child: bool | None = None
    #: Whether this grant stays inside the scope its parent gave it. ``None`` on
    #: a root, which was given its scope by nobody here.
    within_parent_scope: bool | None = None
    #: "" when this hop is sound. Otherwise the first thing wrong with it.
    problem: str = ""

    @property
    def ok(self) -> bool:
        return not self.problem

    def as_dict(self) -> dict[str, Any]:
        return {
            "grant_id": self.grant_id,
            "grantor_did": self.grantor_did,
            "grantee_did": self.grantee_did,
            "not_before": self.not_before,
            "not_after": self.not_after,
            "categories": list(self.categories),
            "signature_ok": self.signature_ok,
            "within_window": self.within_window,
            "revoked": self.revoked,
            "continuous_with_child": self.continuous_with_child,
            "within_parent_scope": self.within_parent_scope,
            "problem": self.problem,
        }


@dataclass(frozen=True)
class Walk:
    """The chain as walked, and what it amounts to."""

    #: intact | severed | unresolvable | disputed
    verdict: str
    hops: tuple[Hop, ...]
    root_grant_id: str | None
    #: The grant_id where the chain broke, when it did.
    severed_at: str | None
    reason: str
    not_established: tuple[str, ...] = field(default=NOT_ESTABLISHED)

    @property
    def ok(self) -> bool:
        return self.verdict == "intact"

    def as_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "reason": self.reason,
            "root_grant_id": self.root_grant_id,
            "severed_at": self.severed_at,
            "depth": len(self.hops),
            "hops": [h.as_dict() for h in self.hops],
            "not_established": list(self.not_established),
        }


def _intrinsic(dat: dict[str, Any], *, revocations: set[str], now: str) -> Hop:
    """What is checkable about one grant on its own, before its neighbours."""
    grant_id = str(dat.get("grant_id", ""))
    not_before, not_after = str(dat.get("not_before", "")), str(dat.get("not_after", ""))
    return Hop(
        grant_id=grant_id,
        grantor_did=str(dat.get("grantor_did", "")),
        grantee_did=str(dat.get("grantee_did", "")),
        not_before=not_before,
        not_after=not_after,
        categories=tuple(sorted(_categories(dat))),
        signature_ok=verify_dat_signature(dat).ok,
        within_window=bool(not_before) and bool(not_after) and not_before <= now <= not_after,
        revoked=grant_id in revocations,
    )


def _problem(hop: Hop, *, now: str) -> str:
    """The first thing wrong with a hop, ordered by what an operator can act on.

    "Revoked" comes first because it is the answer they came for when it
    applies: a grant that was withdrawn and then left to lapse would otherwise
    be reported as expired, which sends them to renew something nobody intends
    to honour.
    """
    if hop.revoked:
        return "revoked"
    if not hop.signature_ok:
        return "signature does not verify under the grantor's key"
    if not hop.within_window:
        if hop.not_after and now > hop.not_after:
            return f"expired at {hop.not_after}"
        return f"not valid until {hop.not_before}" if hop.not_before else "no validity window"
    if hop.continuous_with_child is False:
        return "the grant below names a grantor this grant never granted to"
    if hop.within_parent_scope is False:
        return "widens the scope its parent granted"
    return ""


def walk_authority(
    leaf_grant_id: str,
    *,
    dats_by_id: dict[str, dict[str, Any]],
    revocations: set[str] | None = None,
    now: str | None = None,
    category: str | None = None,
) -> Walk:
    """Walk from ``leaf_grant_id`` to its root, reporting every hop.

    Unlike the verifier this does not stop at the first problem — it keeps
    walking while there is a parent to resolve, so the report shows a chain
    severed three hops up rather than only the fact that something is wrong. It
    stops only where it genuinely cannot continue: a parent named and not
    supplied, a cycle, or the depth limit the verifier enforces.

    The verdict is the verifier's, not this function's. See the module docstring.
    """
    revocations = revocations or set()
    now = now or _now_iso()

    # 1. Resolve the chain, recording what each grant says about itself.
    resolved: list[dict[str, Any]] = []
    seen: set[str] = set()
    current_id: str | None = leaf_grant_id
    unresolvable = ""

    while current_id is not None:
        if len(resolved) >= MAX_CHAIN_DEPTH:
            unresolvable = f"chain exceeds depth {MAX_CHAIN_DEPTH}"
            break
        if current_id in seen:
            unresolvable = f"cycle in the chain at {current_id}"
            break
        seen.add(current_id)
        dat = dats_by_id.get(current_id)
        if dat is None:
            # Named by its child and not supplied. The distinction matters: a
            # chain that cannot be walked is not a chain that was withdrawn, and
            # reporting "revoked" here would be a guess dressed as a finding.
            unresolvable = f"grant {current_id} is named by the chain and was not supplied"
            break
        resolved.append(dat)
        current_id = dat.get("granted_by")

    hops = [_intrinsic(d, revocations=revocations, now=now) for d in resolved]

    # 2. The relational rules, which need a hop's neighbours. Index 0 is the
    #    leaf; each next entry is its parent.
    for i, hop in enumerate(hops):
        child = resolved[i - 1] if i > 0 else None
        parent = resolved[i + 1] if i + 1 < len(resolved) else None
        hops[i] = dataclasses.replace(
            hop,
            continuous_with_child=(None if child is None else child.get("grantor_did") == hop.grantee_did),
            within_parent_scope=(
                None
                if parent is None
                else ("*" in _categories(parent) or _categories(resolved[i]) <= _categories(parent))
            ),
        )
    hops = [dataclasses.replace(h, problem=_problem(h, now=now)) for h in hops]

    severed = next((h for h in hops if not h.ok), None)

    if unresolvable:
        return Walk(
            verdict="unresolvable",
            hops=tuple(hops),
            root_grant_id=None,
            severed_at=severed.grant_id if severed else None,
            reason=unresolvable,
        )

    # 3. The authoritative answer. Asking the verifier rather than concluding
    #    from the hops is what keeps this a view of the gate, not a rival to it.
    result = verify_dat_chain(
        leaf_grant_id,
        dats_by_id=dats_by_id,
        now=now,
        category=category,
        revocations=revocations,
    )
    root_grant_id = hops[-1].grant_id if hops else None

    if result.ok and severed is None:
        return Walk(
            verdict="intact",
            hops=tuple(hops),
            root_grant_id=root_grant_id,
            severed_at=None,
            reason=f"{len(hops)} hop(s) to root {root_grant_id}, none revoked",
        )
    if not result.ok and severed is not None:
        return Walk(
            verdict="severed",
            hops=tuple(hops),
            root_grant_id=root_grant_id,
            severed_at=severed.grant_id,
            reason=f"{severed.grant_id}: {severed.problem}",
        )

    # The two disagree. Neither is overruled here: an auditor that quietly
    # deferred to the gate would hide exactly the drift it exists to catch, and
    # one that overruled it would be a second verifier by another name.
    if result.ok:
        found = f"{severed.grant_id} {severed.problem}" if severed else "a problem it can no longer name"
        detail = f"the audit found {found} and the verifier accepted the chain"
    else:
        detail = f"every hop audits clean and the verifier refused the chain ({result.stage}: {result.detail})"
    return Walk(
        verdict="disputed",
        hops=tuple(hops),
        root_grant_id=root_grant_id,
        severed_at=severed.grant_id if severed else None,
        reason=f"{detail}; this is a divergence between the auditor and the gate, not a conclusion about the chain",
    )
