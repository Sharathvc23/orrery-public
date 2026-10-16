"""Whether an org's AI Catalog has anything to verify at all.

``catalog_canary`` asserts that every entry an org ADVERTISES resolves. That is
the right claim and it was never wrong — but it is vacuous at the bottom. An org
that advertises only its own root card resolves 1/1 and passes most
convincingly, having verified nothing about the member registry the catalog
exists to publish.

Measured live 2026-10-15: the astrocity org advertised **1 entry and omitted
24**, and the 01:21 UTC canary run printed exactly that —
``1/1 entries resolved (omittedMembers=24)`` — and then ``OK — every advertised
catalog entry resolved.`` The check observed the collapse, reported the number,
and exited 0, because resolving the org's own card is all the claim required.
This is the same shape as the unconfigured target that preceded it: a check that
cannot observe the condition it is trusted to observe.

So: a catalog whose only entry is the org's own is a FLOOR BREACH. The rule
references no org's member count, so it encodes nobody's current state and
cannot be satisfied by the estate getting worse.

THREE outcomes, not two — and the third is the one that matters. The canary runs
UNAUTHENTICATED, and an org that does not publish members publicly withholds all
of them (``withheldMembers``), so "no member entries" is the CORRECT and
complete view of a correctly configured private org. Failing that org would be a
false alarm; passing it silently would rebuild the defect this module exists to
remove. It is therefore reported as UNOBSERVABLE, by name, every run.

Stdlib only, on purpose. ``doc-guards`` installs nothing but pytest (ci.yml) and
runs ``pytest tests/``, deliberately, so a documentation-only pull request
cannot skip the guards — a guard that needed ``httpx`` would be a guard that job
could not run. The HTTP belongs to the canary; the decision belongs here, where
a test can drive it directly.
"""

from __future__ import annotations

from typing import Any

#: The floor holds — this org advertises at least one member entry.
FLOOR_OK = "ok"
#: The floor could not be evaluated. NOT a pass: say so where it is read.
FLOOR_UNOBSERVABLE = "unobservable"
#: The floor is breached — the catalog has nothing to verify.
FLOOR_FAILED = "failed"


def member_entries(doc: dict[str, Any], org_identifier: str) -> list[dict[str, Any]]:
    """The entries that are NOT the org's own root card.

    Identified by identifier rather than by position or URL shape. The server
    builds ``entries = [_org_catalog_entry()] + members`` so the org's entry is
    first today, but order is not a wire contract, and matching on
    ``{base}/.well-known/agent.json`` breaks for an org whose ``PUBLIC_URL`` is a
    custom domain while the canary probes the platform URL. ``GET /agents/root``
    serves that very entry (``server/routes/identity.py``), so the identifier is
    available from the org itself rather than guessed.
    """
    return [e for e in (doc.get("entries") or []) if e.get("identifier") != org_identifier]


def floor_verdict(doc: dict[str, Any], org_identifier: str) -> tuple[str, str]:
    """Return ``(verdict, message)``. The message is always worth printing.

    ``withheldMembers`` is checked FIRST and is not folded into the member count:
    the catalog route keeps "withheld because the caller is unauthenticated"
    separate from "omitted for want of a resolvable card" precisely so a privacy
    decision cannot be read as an unpublished card, and this function must not
    re-merge what that route took care to split.
    """
    withheld = doc.get("withheldMembers")
    if withheld is None:
        # An older deployment that does not emit the count. The canary cannot
        # tell whether it is seeing the whole population, so it must not rule on
        # it either way — reported, never assumed to be zero.
        return (
            FLOOR_UNOBSERVABLE,
            "catalog reports no withheldMembers count, so whether this view of the "
            "members is complete cannot be determined — the floor was NOT evaluated",
        )
    if withheld:
        return (
            FLOOR_UNOBSERVABLE,
            f"{withheld} member(s) withheld from this unauthenticated caller, so a "
            f"catalog with no member entries is the correct view and the floor was "
            f"NOT evaluated",
        )

    members = member_entries(doc, org_identifier)
    if members:
        return (FLOOR_OK, f"{len(members)} member entr(ies) advertised")

    omitted = doc.get("omittedMembers") or 0
    if omitted:
        return (
            FLOOR_FAILED,
            f"FLOOR BREACH — advertises NO members, only its own root card, while "
            f"omitting {omitted}. Every advertised entry resolving is therefore a "
            f"claim about one card and says nothing about the registry. Those "
            f"members have no published host39 card recorded on their member row: "
            f"publish each with scripts/publish_host39_card.py --record-on-org, or "
            f"backfill the ones whose cards already resolve with "
            f"scripts/backfill_host39_publications.py.",
        )
    return (
        FLOOR_FAILED,
        "FLOOR BREACH — advertises NO members, only its own root card, and omits "
        "none, so this org has no members at all. Either it is not the deployment "
        "this canary was meant to watch, or it was never populated. A catalog with "
        "nothing in it cannot evidence that the registry works.",
    )
