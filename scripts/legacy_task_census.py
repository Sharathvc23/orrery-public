#!/usr/bin/env python3
"""Read the creatorless-task population across the fleet, one signed call per agent.

WHY THIS EXISTS
---------------
Recording a task's creator arrived after tasks already existed, so the change
that added ``creatorDidKey`` allowed the tasks predating it and counted them, so the legacy
population would be observable before anyone flipped the default to deny. The
counter it shipped could not carry that ruling: it lived in a module-level int,
so it reset on every process start, and it counted APPENDS TO creatorless tasks
rather than creatorless tasks that EXIST. Across 15 agents that redeploy, its
zero read as "nothing to deny" whether or not anything was there to deny.

``nanda/legacyTaskCensus`` publishes both numbers under names that cannot be
confused, and this script sums the one the ruling needs across the agents an
operator names. No agent can see another's tasks, so the fleet figure is a sum
of separate reads and nothing else — there is no fleet-wide store to query.

WHAT IT DOES NOT DO
-------------------
It does not flip anything, and the census surface returns no task ids, so this
prints how many creatorless tasks exist and never which. A did:key on a task is
the key that created it; whether that key is KNOWN to anyone is a different
question this tooling does not touch.

USAGE
-----
    export ORRERY_CENSUS_AGENT_ID=<the signing agent's id>
    export ORRERY_CENSUS_PRIVATE_KEY=<base64 ed25519 seed/secret>
    export ORRERY_CENSUS_PUBLIC_KEY=<base64 ed25519 public key>
    scripts/legacy_task_census.py https://agent-a.example https://agent-b.example
    scripts/legacy_task_census.py --urls-from fleet.txt --json

The census is caller-required, so an unsigned run is refused by every agent —
which this script reports as a refusal, not as a zero.

Exit status:
    0 — every named agent answered
    1 — at least one did not; what failed is printed, and the total is reported
        as a LOWER BOUND rather than as the fleet population
    2 — nothing to do (no urls) or no signing key configured
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "agent"))

from community_member.a2a_client_v2 import A2AClientError, GoogleA2AClient  # noqa: E402


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("urls", nargs="*", help="agent base URLs")
    ap.add_argument(
        "--urls-from",
        type=Path,
        help="file of agent base URLs, one per line ('#' comments allowed)",
    )
    ap.add_argument(
        "--json",
        action="store_true",
        help="emit the raw per-agent replies instead of a table",
    )
    ap.add_argument("--timeout", type=float, default=15.0)
    return ap.parse_args(argv)


def _collect_urls(args: argparse.Namespace) -> list[str]:
    urls = list(args.urls)
    if args.urls_from:
        for line in args.urls_from.read_text().splitlines():
            line = line.split("#", 1)[0].strip()
            if line:
                urls.append(line)
    seen: set[str] = set()
    return [u for u in urls if not (u in seen or seen.add(u))]


def _census(url: str, timeout: float) -> dict:
    """One agent's reply, or a recorded failure. Never a substituted zero.

    ⚠️ AN UNREACHABLE AGENT IS NOT AN EMPTY ONE. Returning 0 for an agent that
    did not answer is the exact ambiguity this whole surface exists to remove,
    so a failure is carried as a failure and the total below is labelled a lower
    bound because of it.
    """
    with GoogleA2AClient(
        url,
        agent_id=os.environ.get("ORRERY_CENSUS_AGENT_ID"),
        private_key=os.environ.get("ORRERY_CENSUS_PRIVATE_KEY"),
        public_key=os.environ.get("ORRERY_CENSUS_PUBLIC_KEY"),
        timeout=timeout,
    ) as client:
        try:
            return {"url": url, "ok": True, "census": client.legacy_task_census()}
        except A2AClientError as e:
            return {"url": url, "ok": False, "error": f"JSON-RPC {e.code}: {e}"}
        except Exception as e:  # network, TLS, HTTP status
            return {"url": url, "ok": False, "error": f"{type(e).__name__}: {e}"}


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    urls = _collect_urls(args)
    if not urls:
        print(
            "no agent urls given; pass them as arguments or with --urls-from",
            file=sys.stderr,
        )
        return 2
    if not os.environ.get("ORRERY_CENSUS_PRIVATE_KEY"):
        print(
            "ORRERY_CENSUS_PRIVATE_KEY is unset. The census is caller-required, so an unsigned "
            "run would be refused by every agent and print zeros that mean 'refused', not 'none'.",
            file=sys.stderr,
        )
        return 2

    results = [_census(u, args.timeout) for u in urls]

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print(
            f"{'agent':<48} {'creatorless':>12} {'tasks':>8} {'unreadable':>11}  since-boot appends"
        )
        for r in results:
            if not r["ok"]:
                print(
                    f"{r['url']:<48} {'—':>12} {'—':>8} {'—':>11}  UNREACHABLE: {r['error']}"
                )
                continue
            m = r["census"]["measurement"]
            o = r["census"]["observation"]
            print(
                f"{r['url']:<48} {m['creatorless_tasks_present']:>12} {m['tasks_present']:>8} "
                f"{m['unreadable_log_lines']:>11}  {o['appends_to_creatorless_tasks_since_boot']} "
                f"(since {o['process_booted_at']})"
            )

    answered = [r for r in results if r["ok"]]
    unreachable = [r for r in results if not r["ok"]]
    total = sum(
        r["census"]["measurement"]["creatorless_tasks_present"] for r in answered
    )

    print()
    if unreachable:
        print(
            f"creatorless tasks across {len(answered)}/{len(urls)} agents: {total} — A LOWER BOUND. "
            f"{len(unreachable)} agent(s) did not answer and an unreachable agent is not an empty one."
        )
        return 1
    print(f"creatorless tasks across all {len(urls)} agents: {total}")
    if total == 0:
        print(
            "That is a MEASURED zero: every agent recounted its own on-disk log and holds no "
            "creatorless tasks. It is not a since-boot counter reading 0 because nothing has "
            "happened yet."
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
