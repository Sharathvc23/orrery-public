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

Exit status:
    0 — every advertised entry resolved AND every catalog had members to verify
    1 — an entry 404'd, a catalog was unreadable, or a catalog had nothing to
        verify at all

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

import httpx

from _canary_targets import refusal, targets_are_required
from _catalog_floor import FLOOR_FAILED, FLOOR_OK, floor_verdict

TIMEOUT = 20.0


def _orgs() -> list[str]:
    """Configured targets, or an empty list when unset. Never a default."""
    raw = os.environ.get("ORGS", "").strip()
    return [u.rstrip("/") for u in raw.split()]


def _org_identifier(client: httpx.Client, base: str) -> str:
    """This org's OWN catalog entry identifier, asked of the org itself.

    ``GET /agents/root`` serves exactly the entry the catalog puts first
    (``server/routes/identity.py``), so the org's identifier never has to be
    guessed from entry order or from a URL shape that a custom domain breaks.
    Returns "" when the surface cannot be read, which the floor reports rather
    than silently treating every entry as a member.
    """
    try:
        resp = client.get(f"{base}/agents/root")
        resp.raise_for_status()
        return str((resp.json() or {}).get("identifier") or "").strip()
    except Exception:  # noqa: BLE001 — handled by the caller, which names it
        return ""


def check_org(client: httpx.Client, base: str) -> tuple[int, int, list[str], str]:
    """Return (resolved, total, failures, floor_breach) for one org's catalog.

    ``floor_breach`` is "" unless the catalog had nothing to verify — see
    ``_catalog_floor``. It is kept SEPARATE from ``failures`` because the two are
    different diagnoses with different remedies: a failure means the org
    advertises a URL nothing backs, a breach means it advertises nothing at all.
    """
    failures: list[str] = []
    try:
        resp = client.get(f"{base}/.well-known/ai-catalog.json")
        resp.raise_for_status()
        doc = resp.json()
    except Exception as exc:  # noqa: BLE001 — an unreadable catalog IS the failure
        return 0, 0, [f"{base}: catalog unreadable ({type(exc).__name__}: {exc})"], ""

    entries = doc.get("entries") or []
    omitted = doc.get("omittedMembers")
    resolved = 0
    for entry in entries:
        url = (entry.get("url") or "").strip()
        ident = entry.get("identifier", "?")
        if not url:
            failures.append(f"{base}: entry {ident} advertises no url")
            continue
        try:
            r = client.get(url)
        except Exception as exc:  # noqa: BLE001
            failures.append(f"{base}: {ident} -> {url} UNREACHABLE ({type(exc).__name__})")
            continue
        if r.status_code == 200:
            resolved += 1
        else:
            failures.append(f"{base}: {ident} -> {url} HTTP {r.status_code}")

    note = "" if omitted is None else f" (omittedMembers={omitted})"
    print(f"{base}: {resolved}/{len(entries)} entries resolved{note}")

    # The floor, reported on EVERY run including when it holds or cannot be
    # evaluated. A verdict that is only printed when it fails is a verdict
    # nobody can tell apart from one that was never reached.
    org_id = _org_identifier(client, base)
    if not org_id:
        breach = (
            "GET /agents/root did not return this org's identifier, so its own entry "
            "cannot be told apart from a member's and the floor was NOT evaluated. "
            "That surface is served beside the catalog itself, so a readable catalog "
            "with an unreadable root entry is its own finding."
        )
        print(f"  floor: UNEVALUATED — {breach}")
        return resolved, len(entries), failures, f"{base}: {breach}"

    verdict, message = floor_verdict(doc, org_id)
    label = {FLOOR_OK: "ok", FLOOR_FAILED: "BREACHED"}.get(verdict, "UNOBSERVABLE")
    print(f"  floor: {label} — {message}")
    return resolved, len(entries), failures, f"{base}: {message}" if verdict == FLOOR_FAILED else ""


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

    all_failures: list[str] = []
    breaches: list[str] = []
    with httpx.Client(timeout=TIMEOUT, follow_redirects=True) as client:
        for base in orgs:
            _resolved, _total, failures, breach = check_org(client, base)
            all_failures.extend(failures)
            if breach:
                breaches.append(breach)

    if not all_failures and not breaches:
        # Both halves named, because "every advertised entry resolved" was true
        # of an org advertising nothing but itself and was the sentence that let
        # a collapsed catalog read as healthy for the length of this incident.
        print("\nOK — every advertised catalog entry resolved, and every catalog had members to verify.")
        return 0

    if all_failures:
        print(f"\n{len(all_failures)} advertised entr(ies) did not resolve:", file=sys.stderr)
        for f in all_failures:
            print(f"  - {f}", file=sys.stderr)
        print(
            "\nThe catalog is advertising URLs nothing backs. Either publish the missing "
            "cards (scripts/publish_host39_card.py --record-on-org) or the entries should "
            "be omitted — see the resolvable-card rule.",
            file=sys.stderr,
        )

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
