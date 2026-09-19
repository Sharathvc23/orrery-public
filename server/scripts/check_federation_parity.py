#!/usr/bin/env python3
"""Check that every org in a federation reports the same /version.

Why this exists:
  When you run more than one org and federate them, each deploy is
  operator-triggered. The failure mode this catches: you deploy one org
  and forget the others, or a partial deploy crashes silently — and that
  version drift can go undetected for a long time.

What this script does:
  1. Fetches /version from every org in the federation
  2. Extracts git_commit from each
  3. PASS iff all report the same commit (and it's not 'unknown')
  4. FAIL otherwise, with a per-org table for the operator to fix

Exit codes:
  0 — all chapters report the same commit
  1 — drift detected
  2 — usage / config error

Usage:
  python chapter/scripts/check_federation_parity.py

  # Custom chapter set (e.g., when adding a new region):
  python chapter/scripts/check_federation_parity.py \\
      --chapter bayarea https://org.example.com \\
      --chapter boston  https://org.example.com

  # JSON output for piping into alerts / dashboards:
  python chapter/scripts/check_federation_parity.py --format json

The default chapter set is read from the FEDERATION_CHAPTERS list
below. Updating the federation membership = updating that list +
shipping a PR.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence


# Federation membership. Order is preserved in the output table.
# Updating this list = updating which chapters the cron checks.
FEDERATION_CHAPTERS: list[tuple[str, str]] = [
    ("bayarea", "https://org.example.com"),
    ("boston", "https://org.example.com"),
    ("bangalore", "https://org.example.com"),
    ("london", "https://org.example.com"),
    ("tokyo", "https://org.example.com"),
]


def _fetch_version(url: str, timeout: float = 10.0) -> dict | None:
    """GET <url>/version. Returns the parsed JSON, or None on any error."""
    full_url = url.rstrip("/") + "/version"
    try:
        req = urllib.request.Request(  # noqa: S310
            full_url, headers={"User-Agent": "federation-parity-check/1.0"}
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            if resp.status != 200:
                return None
            return json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError, TimeoutError, OSError):
        return None


def check_parity(
    chapters: Sequence[tuple[str, str]],
    *,
    head_commit: str | None = None,
    stale_threshold_days: int = 7,
) -> dict:
    """Fetch /version from every chapter and analyze for drift.

    Args:
        chapters: List of (name, base_url) tuples.
        head_commit: Short SHA (7 chars) of the canonical main branch.
            When provided, the result distinguishes between drift and
            stale (all chapters agree but lag main).
        stale_threshold_days: How many days the federation is allowed
            to lag main before being flagged as stale. Default 7.

    Returns a result dict:
        {
          "status": "pass" | "drift" | "stale" | "error",
          "chapters": [{"name": ..., "url": ..., "commit": ..., "ok": True/False, "build_timestamp": "..."}, ...],
          "unique_commits": ["c4322a6", "abc1234", ...],
          "missing_or_unreachable": ["tokyo", ...],
          "head_commit": "<7-char sha>" | None,
          "oldest_build_ts": "<iso>" | None,
          "stale_days": <float> | None,
        }

    Status semantics:
        pass   — all chapters report the same non-unknown SHA AND
                 (no head_commit given OR SHA matches head AND oldest
                 build is within stale_threshold_days)
        drift  — SHAs disagree, or any chapter reports 'unknown'
        stale  — SHAs agree but DON'T match head AND main has moved
                 within stale_threshold_days. Distinct from drift
                 because the operator needs different remediation
                 ("you need to deploy" vs "you need to redeploy SOMEthing").
        error  — any chapter unreachable; cannot make a parity claim
    """
    chapter_results: list[dict] = []
    unique_commits: set[str] = set()
    unreachable: list[str] = []
    oldest_build_ts: str | None = None

    for name, url in chapters:
        version_json = _fetch_version(url)
        if not version_json:
            chapter_results.append({"name": name, "url": url, "commit": None, "ok": False, "build_timestamp": None})
            unreachable.append(name)
            continue
        commit = version_json.get("git_commit", "unknown")
        build_ts = version_json.get("build_timestamp", "")
        chapter_results.append(
            {"name": name, "url": url, "commit": commit, "ok": True, "build_timestamp": build_ts or None}
        )
        if commit and commit != "unknown":
            unique_commits.add(commit)
        if build_ts and (oldest_build_ts is None or build_ts < oldest_build_ts):
            oldest_build_ts = build_ts

    # Layered status: error > drift > stale > pass
    if unreachable:
        status = "error"
        stale_days = None
    elif len(unique_commits) > 1 or any(c.get("commit") == "unknown" for c in chapter_results):
        status = "drift"
        stale_days = None
    elif head_commit and unique_commits and next(iter(unique_commits)) != head_commit[:7]:
        # All chapters agree on a SHA, but that SHA != HEAD of main.
        # Stale-commit detection: check how far HEAD has moved relative
        # to the chapters' build timestamp.
        from datetime import UTC, datetime

        stale_days = None
        if oldest_build_ts:
            try:
                # Tolerate both '2026-05-22T17:38:24Z' and '...+00:00'
                ts_clean = oldest_build_ts.rstrip("Z")
                if "+" not in ts_clean and "T" in ts_clean:
                    ts_clean = ts_clean + "+00:00"
                build_dt = datetime.fromisoformat(ts_clean)
                if build_dt.tzinfo is None:
                    build_dt = build_dt.replace(tzinfo=UTC)
                stale_days = (datetime.now(UTC) - build_dt).total_seconds() / 86400
            except (ValueError, TypeError):
                pass

        if stale_days is not None and stale_days > stale_threshold_days:
            status = "stale"
        else:
            # Slightly behind but within tolerance — still flag as drift
            # (a deploy is needed) but operator can prioritize.
            status = "drift"
    else:
        status = "pass"
        stale_days = None

    return {
        "status": status,
        "chapters": chapter_results,
        "unique_commits": sorted(unique_commits),
        "missing_or_unreachable": unreachable,
        "head_commit": head_commit[:7] if head_commit else None,
        "oldest_build_ts": oldest_build_ts,
        "stale_days": round(stale_days, 1) if stale_days is not None else None,
    }


def _render_text(result: dict) -> str:
    """Human-readable rendering of the parity result."""
    lines: list[str] = []
    status = result["status"]
    if status == "pass":
        commit = result["unique_commits"][0] if result["unique_commits"] else "unknown"
        lines.append(f"✓ PASS — all {len(result['chapters'])} chapters report git_commit={commit}")
        if result.get("head_commit"):
            lines.append(f"        (matches HEAD of main = {result['head_commit']})")
    elif status == "stale":
        commit = result["unique_commits"][0] if result["unique_commits"] else "?"
        head = result.get("head_commit", "?")
        days = result.get("stale_days", "?")
        lines.append(f"✗ STALE — federation is on {commit}, HEAD of main is {head}; ~{days} days of code not deployed")
    elif status == "drift":
        if result["unique_commits"]:
            lines.append(f"✗ DRIFT — {len(result['unique_commits'])} distinct commit(s) across the federation")
        else:
            lines.append("✗ DRIFT — at least one chapter is reporting git_commit='unknown'")
    elif status == "error":
        lines.append(
            f"✗ ERROR — {len(result['missing_or_unreachable'])} chapter(s) unreachable or returned no /version"
        )

    lines.append("")
    lines.append(f"  {'chapter':<14} {'commit':<10} {'build_ts':<22} status")
    lines.append(f"  {'-' * 14} {'-' * 10} {'-' * 22} -----")
    for c in result["chapters"]:
        commit = c["commit"] or "—"
        build_ts = c.get("build_timestamp") or "—"
        # Trim build_ts to second precision for table cleanliness
        if build_ts and len(build_ts) > 22:
            build_ts = build_ts[:22]
        status_str = "online" if c["ok"] else "unreachable"
        lines.append(f"  {c['name']:<14} {commit:<10} {build_ts:<22} {status_str}")
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0] if __doc__ else "")
    parser.add_argument(
        "--chapter",
        nargs=2,
        action="append",
        metavar=("NAME", "URL"),
        help="Override default chapter set. May repeat. NAME is a short label, URL is the base URL.",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format. JSON is suitable for piping into dashboards.",
    )
    parser.add_argument(
        "--head-commit",
        default=None,
        help=(
            "Short SHA (7+ chars) of the canonical main branch. When provided, the "
            "check distinguishes between drift (chapters disagree) and stale "
            "(chapters agree but lag main). The CI workflow passes "
            "${{ github.sha }} for this value."
        ),
    )
    parser.add_argument(
        "--stale-threshold-days",
        type=int,
        default=7,
        help="Days the federation is allowed to lag main before flagging as stale. Default 7.",
    )
    args = parser.parse_args(argv)

    chapters = args.chapter if args.chapter else FEDERATION_CHAPTERS
    if not chapters:
        print("✗ no chapters configured", file=sys.stderr)
        return 2

    result = check_parity(
        chapters,
        head_commit=args.head_commit,
        stale_threshold_days=args.stale_threshold_days,
    )

    if args.format == "json":
        print(json.dumps(result, indent=2))
    else:
        rendered = _render_text(result)
        if result["status"] == "pass":
            print(rendered)
        else:
            print(rendered, file=sys.stderr)

    return 0 if result["status"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
