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

Exit status:
    0 — every advertised entry resolved
    1 — at least one entry 404'd (or a catalog was unreadable)

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

TIMEOUT = 20.0


def _orgs() -> list[str]:
    """Configured targets, or an empty list when unset. Never a default."""
    raw = os.environ.get("ORGS", "").strip()
    return [u.rstrip("/") for u in raw.split()]


def check_org(client: httpx.Client, base: str) -> tuple[int, int, list[str]]:
    """Return (resolved, total, failures) for one org's catalog."""
    failures: list[str] = []
    try:
        resp = client.get(f"{base}/.well-known/ai-catalog.json")
        resp.raise_for_status()
        doc = resp.json()
    except Exception as exc:  # noqa: BLE001 — an unreadable catalog IS the failure
        return 0, 0, [f"{base}: catalog unreadable ({type(exc).__name__}: {exc})"]

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
    return resolved, len(entries), failures


def main() -> int:
    orgs = _orgs()
    if not orgs:
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
    with httpx.Client(timeout=TIMEOUT, follow_redirects=True) as client:
        for base in orgs:
            _resolved, _total, failures = check_org(client, base)
            all_failures.extend(failures)

    if not all_failures:
        print("\nOK — every advertised catalog entry resolved.")
        return 0

    print(f"\n{len(all_failures)} advertised entr(ies) did not resolve:", file=sys.stderr)
    for f in all_failures:
        print(f"  - {f}", file=sys.stderr)
    print(
        "\nThe catalog is advertising URLs nothing backs. Either publish the missing "
        "cards (scripts/publish_host39_card.py --record-on-org) or the entries should "
        "be omitted — see the resolvable-card rule.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
