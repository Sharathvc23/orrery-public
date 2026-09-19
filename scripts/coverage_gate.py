#!/usr/bin/env python3
"""Per-module coverage gate for the security-critical modules (R1).

The global floor lives in CI as pytest's --cov-fail-under; this script
enforces an explicit, higher floor on the modules where a coverage gap is a
security gap, from the coverage JSON the test run writes.

Usage: python scripts/coverage_gate.py --suite server coverage.json

Ratchet policy: floors were set from the 2026-07-08 baseline (measured with
tests and the vendored _arp_verify mirror excluded), rounded down 1-2 points
so unrelated churn doesn't flake the gate. When a module's coverage rises,
raise its floor to just under the new measurement. Never lower a floor
without a written rationale in docs/HARDENING.md.

Baseline at floor-setting time:
  server total 69.7%  · auth_verify 93.9 · sovereign_identity 89.3 · federation_signing 85.3
  agent  total 77.4%  · consent/gate 93.3 · consent/ledger 89.1 · crypto 91.1
                      · keystore 74.6 (weakest — first ratchet target) · executor 87.8
  index  main.py 95.1%
"""

import argparse
import json
import sys

FLOORS: dict[str, dict[str, float]] = {
    "server": {
        "auth_verify.py": 92.0,
        # Ratcheted 88 -> 93 (measured 95.5% once the C11 boot refusal
        # and the seal-in-place migration were covered).
        "sovereign_identity.py": 93.0,
        "federation_signing.py": 84.0,
        # At-rest sealing (AUDIT_HARSH C11 + C1). An uncovered branch here is a
        # branch that can write a secret in the clear — the exact failure the
        # modules exist to remove — so they carry a floor from the day they land.
        # Both measured 100% when they landed; floored 2 points under per the ratchet
        # policy above.
        "secret_sealing.py": 98.0,
        "api_key_store.py": 98.0,
    },
    "agent": {
        "community_member/consent/gate.py": 92.0,
        "community_member/consent/ledger.py": 88.0,
        "community_member/crypto.py": 90.0,
        "community_member/keystore.py": 73.0,
        "community_member/executor.py": 86.0,
        # Owner principal + the listing-consent gate. A coverage gap here is a
        # gap in the check that decides whether a real person gets published to
        # a public registry, so it carries a floor from the day it landed
        # (measured 93.8% when it landed, floor set 2 points under per the ratchet
        # policy above). Ratcheted 92 -> 94 (measured 95.6% once the
        # domain-control path and its real transports were covered) — the gate
        # caught that path landing under-tested, which is the point of it.
        "community_member/owner.py": 94.0,
        # registry.py holds the gate's call site (should_announce). Floored so a
        # future edit cannot drop the consent branch out of the tested set;
        # measured 78.2% when the gate landed.
        "community_member/registry.py": 76.0,
        # The platform uninstall receiver. An uncovered branch here is a branch
        # that can transition a listing on an unverified request — a
        # denial-of-listing primitive — so it carries a floor from the day it
        # lands. Measured 97.0% at that point, floored 2 points under per the
        # ratchet policy above.
        "community_member/platform_events.py": 95.0,
    },
}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--suite", required=True, choices=sorted(FLOORS))
    ap.add_argument("coverage_json", help="path to the coverage.py JSON report")
    args = ap.parse_args()

    with open(args.coverage_json) as f:
        files = json.load(f)["files"]

    failed = False
    for mod, floor in FLOORS[args.suite].items():
        entry = files.get(mod)
        if entry is None:
            print(f"FAIL {mod}: missing from coverage data — renamed/moved? update FLOORS")
            failed = True
            continue
        pct = entry["summary"]["percent_covered"]
        ok = pct >= floor
        failed = failed or not ok
        print(f"{'ok  ' if ok else 'FAIL'} {mod}: {pct:.1f}% (floor {floor:.0f}%)")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
