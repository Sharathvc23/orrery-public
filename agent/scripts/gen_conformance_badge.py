#!/usr/bin/env python3
"""Generate the sovereign agent's signed conformance badge — honestly.

The badge is a signed, offline-verifiable envelope over this runtime's
signing-conformance results. Two honesty properties, and one explicit limit:

  * The ``suite_digest`` is computed from the ACTUAL signing-vector corpus —
    the script refuses to run if that corpus is absent, so a badge can never be
    minted without the corpus it claims to pin.
  * Counts from a pytest ``--junitxml`` report are a genuine run. Raw
    ``--passed/--failed`` counts are OPERATOR-ASSERTED — the suite did not run
    here — and the script warns loudly so they can't masquerade as verified.

The signature proves WHO produced the badge and that it is untampered; it does
NOT prove a third party witnessed the run. Prefer ``--junitxml``. (Deriving the
counts by running the suite in-process lands with the runnable client
signing-conformance suite, that change.)

Output is written to the agent's badge path (served at
``/.well-known/conformance.json``), or ``--out``.

Examples
--------
  # From a real pytest run that emitted junit.xml:
  python scripts/gen_conformance_badge.py \
      --vectors-root /path/to/conformance/vectors --junitxml junit.xml

  # With counts from a run done elsewhere:
  python scripts/gen_conformance_badge.py \
      --vectors-root /path/to/conformance/vectors --passed 142 --failed 0
"""

from __future__ import annotations

import argparse
import sys
from datetime import UTC, datetime
from pathlib import Path
from xml.etree import ElementTree as ET

# Allow running from the repo without installing.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from community_member.config import Config
from community_member.conformance_badge import build_self_badge, verify_badge, write_badge


def _counts_from_junit(path: Path) -> tuple[int, int, int]:
    """(passed, failed, skipped) parsed from a pytest junit.xml — real results."""
    root = ET.parse(path).getroot()
    suites = [root] if root.tag == "testsuite" else root.findall("testsuite")
    tests = failures = errors = skipped = 0
    for s in suites:
        tests += int(s.get("tests", 0))
        failures += int(s.get("failures", 0))
        errors += int(s.get("errors", 0))
        skipped += int(s.get("skipped", 0))
    failed = failures + errors
    passed = tests - failed - skipped
    return passed, failed, skipped


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument(
        "--vectors-root", required=True, type=Path, help="Path to the conformance vectors/ dir (must contain signing/)."
    )
    p.add_argument("--junitxml", type=Path, help="pytest junit.xml to read real pass/fail from.")
    p.add_argument("--passed", type=int, help="Passed count (if not using --junitxml).")
    p.add_argument("--failed", type=int, help="Failed count (if not using --junitxml).")
    p.add_argument("--skipped", type=int, default=0)
    p.add_argument("--runtime", default="orrery-agent")
    p.add_argument(
        "--protocol-version", action="append", dest="protocol_versions", help="Repeatable. Default: 0.3, 0.2."
    )
    p.add_argument("--out", type=Path, help="Badge output path (default: the agent's served badge path).")
    args = p.parse_args(argv)

    # Honesty gate 1: the corpus this badge pins must actually exist.
    signing_root = args.vectors_root / "signing"
    if not signing_root.is_dir():
        print(
            f"ERROR: no signing vectors at {signing_root} — refusing to mint a badge for a corpus that isn't here.",
            file=sys.stderr,
        )
        return 2

    from sm_conformance.badge import compute_suite_digest

    suite_digest = compute_suite_digest(signing_root)

    # Honesty gate 2: where the counts come from. --junitxml is a genuine run;
    # raw --passed/--failed are OPERATOR-ASSERTED and warned about loudly, so a
    # badge can't be silently minted from numbers nobody verified. The
    # signature only ever proves origin + integrity, never that a suite ran.
    if args.junitxml:
        passed, failed, skipped = _counts_from_junit(args.junitxml)
    elif args.passed is not None and args.failed is not None:
        passed, failed, skipped = args.passed, args.failed, args.skipped
        print(
            "WARNING: counts are operator-ASSERTED (--passed/--failed); the suite DID NOT RUN here. "
            "This badge attests numbers you supplied, not a verified run — prefer --junitxml from a real "
            "pytest run for a trustworthy badge.",
            file=sys.stderr,
        )
    else:
        print("ERROR: provide --junitxml OR both --passed and --failed (real run results).", file=sys.stderr)
        return 2

    config = Config.load()
    versions = args.protocol_versions or ["0.3", "0.2"]
    completed_at = datetime.now(UTC).isoformat()

    try:
        badge = build_self_badge(
            config,
            suite_digest=suite_digest,
            protocol_versions=versions,
            passed=passed,
            failed=failed,
            skipped=skipped,
            completed_at=completed_at,
        )
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2

    # Self-check before writing: a badge we can't verify is worse than none.
    verify_badge(badge)

    out = write_badge(badge, args.out)
    print(f"wrote signed badge -> {out}")
    print(f"  runtime={args.runtime} passed={passed} failed={failed} skipped={skipped}")
    print(f"  suite_digest={suite_digest}")
    print(f"  signed_by={badge.get('signed_by', '?')}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
