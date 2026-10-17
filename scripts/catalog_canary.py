#!/usr/bin/env python3
"""Resolve every entry each deployed org advertises in its AI Catalog.

The catalog is Orrery's public enumeration surface: a crawler reads
``/.well-known/ai-catalog.json`` and follows each ``url``. An entry that 404s
tells that crawler the registry is unreliable, which is worse than not being
listed at all.

This runs against the DEPLOYED orgs on a schedule, because the condition only
exists there. ``probe_registry_integrity`` in ci.yml runs against the hermetic
compose stack, where the same run creates and checks every entry — residue
cannot exist, so it always passes. That is a false green, not a flake: the check
cannot observe the thing that breaks the claim. Measured on 2026-08-02, the
astrocity org advertised 24 entries of which 6 resolved, with CI green.

It also enforces a FLOOR, because "every advertised entry resolves" is vacuous
at the bottom: an org advertising only its own root card resolves 1/1 and passes
having checked nothing. Measured live 2026-10-15 — astrocity advertised 1 entry
while omitting 24, and this canary printed both numbers and then said OK. See
``_catalog_floor`` for the rule and for why a withholding org is reported as
unobservable rather than failed.

And it distinguishes a card that is ABSENT from a host that is NOT YET AWAKE,
because the first run after the canaries were armed failed on three HTTP 502s
that every returned 200 when re-probed by hand minutes later. A sleeping
container is not an unpublished card, and the two have opposite remedies. Every
HTTP call here therefore goes through ``_probe_status.probe`` — including the
catalog fetch and ``GET /agents/root``, where a cold start used to read as "the
catalog is unreadable" and "the floor could not be evaluated" respectively. See
``_probe_status`` for the taxonomy and for why a PERSISTENT 502 still fails.

Exit status:
    0 — every advertised entry resolved AND every catalog had members to verify
    1 — an entry was absent, a host never became ready, a catalog was unreadable,
        or a catalog had nothing to verify at all

Targets come from ``ORGS`` (space-separated base URLs). There is NO DEFAULT, and
that is deliberate: this repository is public, and a hardcoded default would
print live hostnames into every public Actions log on a six-hourly timer, which
points strangers at running infrastructure. It would also mean a fork's
scheduled run probes hosts its owner does not operate. With ``ORGS`` unset the
canary SKIPS and says so; the operator sets the variable to run it for real.

Public URLs only — this reads nothing that is not already world-readable, so
there is no credential.
"""

from __future__ import annotations

import os
import sys
from typing import NamedTuple

import httpx

from _canary_targets import refusal, targets_are_required
from _catalog_floor import FLOOR_FAILED, FLOOR_OK, floor_verdict
from _probe_status import NOT_READY, OK, OTHER, ProbeResult, probe, remediation_for

TIMEOUT = 20.0


class Trouble(NamedTuple):
    """One finding, carrying the VERDICT that produced it.

    The verdict travels with the message because the remedy differs: an absent
    card has to be published, a host that never became ready has to be
    redeployed, and telling an operator to do the first when they have the
    second is the wrong-advice half of the 2026-10-16 false red.
    """

    verdict: str
    message: str


class OrgReport(NamedTuple):
    """One org's result. ``breach`` and ``troubles`` are deliberately separate.

    A failure means the org advertises a URL nothing backs; a breach means it
    advertises nothing at all. Different diagnoses, different remedies — see
    ``_catalog_floor``. ``woke`` holds the probes that only succeeded on a
    retry: reported because a host that cold-starts on every run is degraded,
    and a retry that leaves no trace in the log is a signal deleted.
    """

    resolved: int
    total: int
    troubles: list[Trouble]
    breach: str
    woke: int


def _orgs() -> list[str]:
    """Configured targets, or an empty list when unset. Never a default."""
    raw = os.environ.get("ORGS", "").strip()
    return [u.rstrip("/") for u in raw.split()]


def _org_identifier(client: httpx.Client, base: str) -> tuple[str, ProbeResult, str]:
    """This org's OWN catalog entry identifier, asked of the org itself.

    ``GET /agents/root`` serves exactly the entry the catalog puts first
    (``server/routes/identity.py``), so the org's identifier never has to be
    guessed from entry order or from a URL shape that a custom domain breaks.

    Returns ``("", ...)`` when the surface cannot be read, which the floor
    reports rather than silently treating every entry as a member. It is read
    through ``probe`` because an unreadable identifier fails the floor CLOSED:
    before this, a cold start on ``/agents/root`` manufactured a floor breach on
    a perfectly healthy org. The fix is to retry before reaching the fail-closed
    path — not to soften where that path leads.

    Also returns the probe itself and, when the read failed, a description of
    what was observed, so a run can tell a 404 on the root surface apart from a
    gateway that never woke.
    """
    result = probe(client.get, f"{base}/agents/root")
    if result.verdict != OK:
        return "", result, result.describe()
    try:
        identifier = str((result.response.json() or {}).get("identifier") or "").strip()
    except Exception as exc:  # noqa: BLE001 — a root entry that is not JSON IS the finding
        return "", result, f"unreadable body ({type(exc).__name__}: {exc})"
    return identifier, result, ""


def check_org(client: httpx.Client, base: str) -> OrgReport:
    """Resolve one org's catalog and rule on its floor."""
    troubles: list[Trouble] = []
    woke = 0

    catalog = probe(client.get, f"{base}/.well-known/ai-catalog.json")
    if catalog.verdict != OK:
        # Not folded into a single "catalog unreadable" string any more: a 502
        # here used to end the check for this org with a hard failure AND skip
        # the floor silently, on nothing worse than an idle container.
        return OrgReport(0, 0, [Trouble(catalog.verdict, f"{base}: catalog {catalog.describe()}")], "", 0)
    try:
        doc = catalog.response.json()
    except Exception as exc:  # noqa: BLE001 — a catalog that is not JSON IS the failure
        # No woke count on this path: the probe did answer, but a catalog that
        # cold-starts and then serves unparseable JSON has a shape bug, and
        # "1 probe needed a retry" printed beside it reads as an explanation.
        message = f"{base}: catalog unreadable ({type(exc).__name__}: {exc})"
        return OrgReport(0, 0, [Trouble(OTHER, message)], "", 0)
    woke += 1 if catalog.woke else 0

    entries = doc.get("entries") or []
    omitted = doc.get("omittedMembers")
    resolved = 0
    cold = []
    for entry in entries:
        url = (entry.get("url") or "").strip()
        ident = entry.get("identifier", "?")
        if not url:
            troubles.append(Trouble(OTHER, f"{base}: entry {ident} advertises no url"))
            continue
        result = probe(client.get, url)
        if result.verdict == OK:
            resolved += 1
            if result.woke:
                woke += 1
                cold.append(f"{ident} answered 200 on attempt {result.attempts}")
            continue
        troubles.append(Trouble(result.verdict, f"{base}: {ident} -> {url} {result.describe()}"))

    note = "" if omitted is None else f" (omittedMembers={omitted})"
    print(f"{base}: {resolved}/{len(entries)} entries resolved{note}")
    for line in cold:
        print(f"  woke: {line} — a cold start, not a missing card")

    # The floor, reported on EVERY run including when it holds or cannot be
    # evaluated. A verdict that is only printed when it fails is a verdict
    # nobody can tell apart from one that was never reached.
    # An unreadable identifier is passed through as "" rather than branched on
    # here: the floor owns that decision (and fails closed on it) so a test can
    # drive it without httpx, which the doc-guards job does not install.
    identifier, root, root_trouble = _org_identifier(client, base)
    woke += 1 if root.woke else 0
    if root_trouble:
        # Named separately from the floor's own message so a reader can tell a
        # root surface that 404s from one that never woke.
        print(f"  root: /agents/root {root_trouble} — the floor cannot be evaluated")
    elif root.woke:
        print(f"  woke: /agents/root answered 200 on attempt {root.attempts} — a cold start")
    verdict, message = floor_verdict(doc, identifier)
    label = {FLOOR_OK: "ok", FLOOR_FAILED: "FAILED"}.get(verdict, "UNOBSERVABLE")
    print(f"  floor: {label} — {message}")
    breach = f"{base}: {message}" if verdict == FLOOR_FAILED else ""
    return OrgReport(resolved, len(entries), troubles, breach, woke)


def main() -> int:
    orgs = _orgs()
    if not orgs:
        # Required HERE, a clean skip in a fork — see _canary_targets.
        if targets_are_required():
            print(refusal("read or resolved"))
            return 1
        # Skip, not fail, and never silently: a public fork must run green
        # without pointing at anyone's infrastructure. Worded so it cannot be
        # mistaken for a successful check — this run verified nothing.
        print(
            "SKIPPED — ORGS is unset, so there is nothing to check. "
            "This is NOT a pass: no catalog was read and no entry was resolved. "
            "Set ORGS to a space-separated list of org base URLs to run it."
        )
        return 0

    all_troubles: list[Trouble] = []
    breaches: list[str] = []
    retries = 0
    with httpx.Client(timeout=TIMEOUT, follow_redirects=True) as client:
        for base in orgs:
            report = check_org(client, base)
            all_troubles.extend(report.troubles)
            retries += report.woke
            if report.breach:
                breaches.append(report.breach)

    if retries:
        # On the success path too. A green run that needed retries is green AND
        # worth knowing about: it is the difference between infrastructure that
        # is healthy and infrastructure that is asleep and got woken by its own
        # monitor. Silence here would make the two indistinguishable.
        print(f"\n{retries} probe(s) needed a retry before answering — cold starts, not missing cards.")

    if not all_troubles and not breaches:
        # Both halves named, because "every advertised entry resolved" was true
        # of an org advertising nothing but itself and was the sentence that let
        # a collapsed catalog read as healthy for the length of this incident.
        print("\nOK — every advertised catalog entry resolved, and every catalog had members to verify.")
        return 0

    # Split by verdict, because a 404 and a 502 are not the same report even
    # though both are failures. Grouping them under one heading with one
    # remediation is what told an operator to publish a card for a host that
    # was merely waking up.
    not_ready = [t for t in all_troubles if t.verdict == NOT_READY]
    unresolved = [t for t in all_troubles if t.verdict != NOT_READY]

    if unresolved:
        print(f"\n{len(unresolved)} advertised entr(ies) did not resolve:", file=sys.stderr)
        for t in unresolved:
            print(f"  - {t.message}", file=sys.stderr)

    if not_ready:
        print(f"\n{len(not_ready)} host(s) answered but never became ready:", file=sys.stderr)
        for t in not_ready:
            print(f"  - {t.message}", file=sys.stderr)

    for paragraph in remediation_for(t.verdict for t in all_troubles):
        print(f"\n{paragraph}", file=sys.stderr)

    if breaches:
        print(f"\n{len(breaches)} catalog(s) had nothing to verify:", file=sys.stderr)
        for b in breaches:
            print(f"  - {b}", file=sys.stderr)
        print(
            "\nAn org that advertises only its own root card resolves 1/1 and tells you "
            "nothing about the member registry the catalog exists to publish. This is "
            "reported as a failure for the same reason the resolvable-card rule reports "
            "omissions instead of hiding them: a silently absent member is undiagnosable.",
            file=sys.stderr,
        )
    return 1


if __name__ == "__main__":
    sys.exit(main())
