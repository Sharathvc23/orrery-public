#!/usr/bin/env python3
"""Record publication for members whose host39 card ALREADY resolves.

Why this exists. ``_member_catalog_entry`` now advertises a member's host39 card
only when the member carries a publication record. That record is new, so on the
first deploy NOTHING carries it — including the members whose cards were
published by hand and resolve fine today. Without a backfill the catalog would
correctly stop advertising the 18 dead entries and also, incorrectly in spirit,
stop advertising the 5 live ones.

So: probe each member's would-be card URL, and record publication ONLY for the
ones that actually return 200. That is the same rule the fix enforces — advertise
what resolves — applied once to existing state. It never invents a record for a
card that does not exist, which is what would put the dead entries back.

DRY RUN BY DEFAULT. It reports what it would record and writes nothing unless
``--apply`` is passed. Writing to a live org is an operator decision.

    export ORG_ADMIN_TOKEN=...
    scripts/backfill_host39_publications.py --org https://org.example.org
    scripts/backfill_host39_publications.py --org https://org.example.org --apply

Reads the org's own catalog to discover members, so it needs no database access
and no member list. Credentials come from the environment only — never argv.

ORDERING — this matters and it is not symmetric:

* **Before the fix is deployed** the recording endpoint does not exist. It
  returns 404, so a backfill run then does nothing.
* **After the fix is deployed** the live catalog has ALREADY omitted every
  member without a publication record — including the ones whose cards resolve
  perfectly well. Discovering members from the live catalog therefore finds
  nothing left to record.

So the first-time backfill needs a member list captured BEFORE the deploy:

    # before deploying
    curl -s https://org.example.org/.well-known/ai-catalog.json > snap.json
    # after deploying
    scripts/backfill_host39_publications.py --org https://org.example.org \
        --from-snapshot snap.json --apply

Afterwards the live catalog is authoritative again and ``--from-snapshot`` is
unnecessary: a member published from then on gets its record from
``publish_host39_card.py --record-on-org`` at publish time.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import sys

import httpx

TIMEOUT = 20.0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--org", required=True, help="org base URL, e.g. https://org.example.org")
    ap.add_argument(
        "--from-snapshot",
        metavar="PATH",
        help=(
            "read the member list from a catalog snapshot taken BEFORE the fix "
            "was deployed, instead of from the live catalog. Required for the "
            "first-time backfill: see the ordering note in the module docstring."
        ),
    )
    ap.add_argument(
        "--apply",
        action="store_true",
        help="actually record publications (default: dry run, writes nothing)",
    )
    args = ap.parse_args(argv)
    org = args.org.rstrip("/")

    token = os.environ.get("ORG_ADMIN_TOKEN", "").strip()
    if args.apply and not token:
        print("--apply needs ORG_ADMIN_TOKEN in the environment", file=sys.stderr)
        return 2

    with httpx.Client(timeout=TIMEOUT, follow_redirects=True) as client:
        if args.from_snapshot:
            try:
                doc = json.loads(pathlib.Path(args.from_snapshot).read_text(encoding="utf-8"))
            except Exception as exc:  # noqa: BLE001
                print(f"could not read snapshot {args.from_snapshot}: {exc}", file=sys.stderr)
                return 1
            print(f"member list from snapshot {args.from_snapshot}")
        else:
            try:
                doc = client.get(f"{org}/.well-known/ai-catalog.json").json()
            except Exception as exc:  # noqa: BLE001
                print(f"could not read {org} catalog: {exc}", file=sys.stderr)
                return 1

        entries = doc.get("entries") or []
        # The org's own self-card is not a member and has no publication record.
        members = [e for e in entries if e.get("identifier") != doc.get("identifier")]

        live: list[tuple[str, str]] = []
        dead: list[tuple[str, str]] = []
        for e in members:
            ident, url = e.get("identifier", ""), (e.get("url") or "")
            if not ident or not url or "/.well-known/agent.json" in url:
                continue  # self-served entries need no host39 record
            try:
                code = client.get(url).status_code
            except Exception:  # noqa: BLE001
                code = 0
            (live if code == 200 else dead).append((ident, url))

        print(f"{org}: {len(live)} card(s) resolve, {len(dead)} do not")
        for ident, url in live:
            print(f"  RECORD  {ident} -> {url}")
        for ident, url in dead:
            print(f"  omit    {ident} -> {url} (no card; the catalog will stop advertising it)")

        if not args.apply:
            print("\nDry run — nothing written. Re-run with --apply to record the resolving cards.")
            return 0

        failed = 0
        for ident, url in live:
            r = client.post(
                f"{org}/admin/api/host39/record-publication/{ident}",
                headers={"X-Admin-Token": token},
                json={"card_url": url},
            )
            if r.status_code >= 300:
                print(f"  FAILED {ident}: HTTP {r.status_code} {r.text[:120]}", file=sys.stderr)
                failed += 1
        print(f"\nrecorded {len(live) - failed}/{len(live)}")
        return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
