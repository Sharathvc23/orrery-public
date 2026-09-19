#!/usr/bin/env python3
"""Verify each deployed org's published receipt bundle, as a stranger would.

Runs the documented recipe (docs/VERIFY_A_RECEIPT.md) against the DEPLOYED orgs
on a schedule. The property only holds in the deployed state — a hermetic CI
stack cannot tell you whether the live sample is fetchable and verifies, which is
the same reasoning as the catalog canary.

⚠️ Resolves the issuer key from each org's OWN /.well-known/did.json, never from
the bundle. A bundle that supplied its verifying key would verify for a forger.

Exit 0 if every published bundle verifies; 1 otherwise. Skips an org with no
published bundle (404) — publication is opt-in, so absence is not a failure.

Targets come from ``ORGS`` (space-separated base URLs) and there is NO DEFAULT.
This repository is public: a hardcoded default would print live hostnames into
every public Actions log on a timer, and a fork's scheduled run would probe
hosts its owner does not operate. Unset ``ORGS`` SKIPS with a message that says
plainly that nothing was verified.
"""

from __future__ import annotations

import hashlib
import os
import sys

import httpx
import sm_arp

SAMPLE = os.environ.get("SAMPLE_ID", "sample")


def _jcs(obj: dict) -> bytes:
    """RFC 8785, via the library sm-arp already depends on."""
    import jcs as _rfc8785

    return _rfc8785.canonicalize(obj)


def check(client: httpx.Client, base: str) -> tuple[str, list[str]]:
    base = base.rstrip("/")
    r = client.get(f"{base}/.well-known/receipt-disclosure/{SAMPLE}.json")
    if r.status_code == 404:
        # Reported as a distinct outcome, never as success: a canary that is
        # green because there was nothing to check is the false-green shape the resolvable-card rule
        # was about. main() requires at least one org to have published.
        # Now that every org publishes a sample, an absent bundle is a REGRESSION,
        # not an opt-out. This used to return no failure, so a run could go green
        # having verified nothing; then it required only ONE org to verify, so a
        # single org silently losing its bundle still read as success. Every
        # configured org must carry one.
        return f"{base}: NO PUBLISHED BUNDLE", [
            f"{base}: no published bundle at /.well-known/receipt-disclosure/{SAMPLE}.json — "
            f"published previously, so this is a regression rather than an opt-out"
        ]
    if r.status_code != 200:
        return f"{base}: bundle HTTP {r.status_code}", [f"{base}: bundle unreachable"]
    bundle = r.json()

    doc = client.get(f"{base}/.well-known/did.json").json()
    org_did = "did:key:" + doc["verificationMethod"][0]["publicKeyMultibase"]
    if bundle.get("issuer_did") != org_did:
        return f"{base}: ISSUER MISMATCH", [
            f"{base}: issuer_did {bundle.get('issuer_did')} != org did {org_did}"
        ]

    root = bundle["checkpoint"]["payload"]["merkle_root"].removeprefix("sha256:")
    failures = []
    for d in bundle.get("disclosed", []):
        receipt = d["receipt"]
        res = sm_arp.verify_signature(receipt)
        if not res.ok:
            failures.append(f"{base}: {receipt.get('receipt_id')} signature: {res.detail}")
            continue
        node = hashlib.sha256(b"\x00" + _jcs(receipt)).digest()
        fn, sn = d["leaf_index"], bundle["checkpoint"]["payload"]["tree_size"] - 1
        for sib_hex in d["proof"]:
            sib = bytes.fromhex(sib_hex)
            if fn & 1 or fn == sn:
                node = hashlib.sha256(b"\x01" + sib + node).digest()
                while fn != 0 and not fn & 1:
                    fn >>= 1
                    sn >>= 1
            else:
                node = hashlib.sha256(b"\x01" + node + sib).digest()
            fn >>= 1
            sn >>= 1
        if node.hex() != root or sn != 0:
            failures.append(f"{base}: {receipt.get('receipt_id')} inclusion proof does not fold")
    n = len(bundle.get("disclosed", []))
    return f"{base}: {n - len(failures)}/{n} receipt(s) verified against {org_did[:24]}…", failures


def main() -> int:
    orgs = os.environ.get("ORGS", "").split()
    if not orgs:
        # Skip, not fail, and never silently. Stated bluntly because this file
        # argues at length that a canary green with nothing to check is a false
        # green: an unset target is exactly that shape, so the message has to
        # rule out reading this run as evidence the claim still holds.
        print(
            "SKIPPED — ORGS is unset, so there is nothing to verify. "
            "This is NOT a pass: no bundle was fetched and no signature was checked. "
            "Set ORGS to a space-separated list of org base URLs to run it."
        )
        return 0

    all_failures: list[str] = []
    verified_orgs = 0
    with httpx.Client(timeout=30, follow_redirects=True) as client:
        for base in orgs:
            try:
                line, failures = check(client, base)
                if "NO PUBLISHED BUNDLE" not in line and not failures:
                    verified_orgs += 1
            except Exception as exc:  # noqa: BLE001 — an unverifiable sample IS the failure
                line, failures = f"{base}: ERROR {type(exc).__name__}: {exc}", [f"{base}: {exc}"]
            print(line)
            all_failures.extend(failures)

    if all_failures:
        print(f"\n{len(all_failures)} verification failure(s):", file=sys.stderr)
        for f in all_failures:
            print(f"  - {f}", file=sys.stderr)
        print("\nThe public verifiability claim is not holding — see docs/VERIFY_A_RECEIPT.md.", file=sys.stderr)
        return 1
    print("\nOK — every published bundle verified as a third party would check it.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
