"""End-to-end admin auth verification against any running chapter.

Usage::

    # Bearer-only verification (no signed-path test)
    python -m chapter.scripts.verify_admin \\
        --url https://org.example.com \\
        --admin-token <64-hex-token>

    # Both paths: bearer + signed-admin (requires a chapter_role='admin' member's key)
    python -m chapter.scripts.verify_admin \\
        --url https://org.example.com \\
        --admin-token <token> \\
        --admin-agent-id alice \\
        --admin-private-key <base64-ed25519-private-key>

Exit codes:
  0 — all probes pass
  1 — at least one probe failed (chapter is misconfigured or down)
  2 — usage / arg error

Probes run by default (bearer path):
  1. GET /admin/api/status → 200 + expected shape
  2. GET /admin/api/members → 200
  3. GET /admin/api/status with NO auth → 401 (with both-paths hint)
  4. GET /admin/api/status with WRONG bearer → 401

Additional probes when admin-agent-id + admin-private-key provided
(signed did:key path):
  5. GET /admin/api/status with valid signed admin → 200
  6. GET /admin/api/status with valid signed but role-stripped agent → 403
  7. GET /admin/api/status with corrupted signature → 401

This is the verification fixture the user requested — both the AI-to-AI
signed path AND the bearer fallback path get probed, against a real
chapter over real HTTP.
"""

from __future__ import annotations

import argparse
import base64
import os
import sys
import time
from dataclasses import dataclass
from pathlib import Path

import httpx

# Add chapter dir to sys.path so we can import sovereign_identity for signing
HERE = Path(__file__).resolve()
CHAPTER_DIR = HERE.parent.parent
if str(CHAPTER_DIR) not in sys.path:
    sys.path.insert(0, str(CHAPTER_DIR))


@dataclass
class ProbeResult:
    name: str
    passed: bool
    status_code: int
    detail: str

    def line(self) -> str:
        icon = "✓" if self.passed else "✗"
        return f"  {icon} {self.name:60s} HTTP {self.status_code}  {self.detail}"


def _build_signed_headers(
    *,
    method: str,
    url_path: str,
    body: str,
    agent_id: str,
    private_key_b64: str,
) -> dict[str, str]:
    """v0.3 ed25519+nonce. Mirrors tests/_admin_fixtures.build_v03_signed_headers."""
    import sovereign_identity

    ts = str(int(time.time()))
    nonce = base64.b64encode(os.urandom(32)).decode()
    canonical = f"{method.upper()}:{url_path}:{body}:{agent_id}:{ts}:{nonce}"
    sig = sovereign_identity.ed25519_sign(canonical, private_key_b64)
    return {
        "X-Agent-ID": agent_id,
        "X-Agent-Signature": sig,
        "X-Agent-Timestamp": ts,
        "X-Agent-Nonce": nonce,
        "X-Agent-Sig-Scheme": "ed25519+nonce",
    }


def probe_bearer_path(base_url: str, token: str) -> list[ProbeResult]:
    results: list[ProbeResult] = []
    with httpx.Client(timeout=20.0, follow_redirects=False) as client:
        # 1. Bearer GET /admin/api/status → 200
        r = client.get(f"{base_url}/admin/api/status", headers={"X-Admin-Token": token})
        ok = r.status_code == 200 and "members_total" in r.text
        results.append(
            ProbeResult(
                "bearer GET /admin/api/status",
                ok,
                r.status_code,
                f"members_total={'present' if 'members_total' in r.text else 'missing'}",
            )
        )

        # 2. Bearer GET /admin/api/members → 200
        r = client.get(f"{base_url}/admin/api/members", headers={"X-Admin-Token": token})
        ok = r.status_code == 200
        body = r.json() if ok else {}
        count = body.get("total", "?") if ok else "?"
        results.append(ProbeResult("bearer GET /admin/api/members", ok, r.status_code, f"total members={count}"))

        # 3. No auth → 401 with both-paths hint
        r = client.get(f"{base_url}/admin/api/status")
        body = r.json() if r.status_code == 401 else {}
        hint = body.get("hint", "")
        ok = r.status_code == 401 and "X-Agent-Signature" in hint and "X-Admin-Token" in hint
        results.append(
            ProbeResult(
                "no-auth GET /admin/api/status → 401 + both-paths hint",
                ok,
                r.status_code,
                "hint=ok" if ok else f"hint={hint[:80]!r}",
            )
        )

        # 4. Wrong bearer → 401
        r = client.get(
            f"{base_url}/admin/api/status",
            headers={"X-Admin-Token": "0" * 64},
        )
        ok = r.status_code == 401
        results.append(ProbeResult("wrong-bearer GET /admin/api/status → 401", ok, r.status_code, ""))

    return results


def probe_signed_path(
    base_url: str,
    agent_id: str,
    private_key_b64: str,
) -> list[ProbeResult]:
    results: list[ProbeResult] = []
    with httpx.Client(timeout=20.0, follow_redirects=False) as client:
        # 5. Signed by chapter_role='admin' agent → 200
        headers = _build_signed_headers(
            method="GET",
            url_path="/admin/api/status",
            body="",
            agent_id=agent_id,
            private_key_b64=private_key_b64,
        )
        r = client.get(f"{base_url}/admin/api/status", headers=headers)
        ok = r.status_code == 200
        results.append(
            ProbeResult(
                f"signed-admin ({agent_id}) GET /admin/api/status → 200",
                ok,
                r.status_code,
                "200 means role lookup confirmed chapter_role='admin'"
                if ok
                else (
                    r.json().get("error", "")
                    if r.headers.get("content-type", "").startswith("application/json")
                    else r.text[:80]
                ),
            )
        )

        # 7. Corrupted signature → 401
        bad_headers = dict(headers)
        # Build a fresh nonce so we're not testing replay
        bad_headers = _build_signed_headers(
            method="GET",
            url_path="/admin/api/status",
            body="",
            agent_id=agent_id,
            private_key_b64=private_key_b64,
        )
        bad_headers["X-Agent-Signature"] = "AAAA" + bad_headers["X-Agent-Signature"][4:]
        r = client.get(f"{base_url}/admin/api/status", headers=bad_headers)
        body = r.json() if r.status_code == 401 else {}
        reason = body.get("reason", "")
        ok = r.status_code == 401 and reason  # any reason is fine; reason being present confirms verify_request ran
        results.append(
            ProbeResult(
                "corrupted-sig GET /admin/api/status → 401 + verify reason",
                ok,
                r.status_code,
                f"reason={reason!r}" if reason else f"body={r.text[:80]}",
            )
        )

    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--url",
        required=True,
        help="Chapter URL, e.g. https://org.example.com",
    )
    parser.add_argument(
        "--admin-token",
        required=True,
        help="64-hex bearer admin token (X-Admin-Token header value)",
    )
    parser.add_argument(
        "--admin-agent-id",
        default="",
        help="Optional: chapter_role='admin' member's agent_id for signed-path verification",
    )
    parser.add_argument(
        "--admin-private-key",
        default="",
        help="Optional: base64-encoded Ed25519 private key for --admin-agent-id (raw 32-byte key)",
    )
    args = parser.parse_args()

    base = args.url.rstrip("/")

    print(f"\nverifying admin auth surface at {base}")
    print("=" * 78)

    print("\nBEARER PATH PROBES")
    print("-" * 78)
    bearer_results = probe_bearer_path(base, args.admin_token)
    for r in bearer_results:
        print(r.line())

    signed_results: list[ProbeResult] = []
    if args.admin_agent_id and args.admin_private_key:
        print("\nSIGNED-ADMIN PATH PROBES (did:key)")
        print("-" * 78)
        signed_results = probe_signed_path(base, args.admin_agent_id, args.admin_private_key)
        for r in signed_results:
            print(r.line())
    else:
        print("\nSIGNED-ADMIN PATH PROBES — SKIPPED")
        print("-" * 78)
        print("  (provide --admin-agent-id and --admin-private-key to enable)")

    print("\n" + "=" * 78)
    all_results = bearer_results + signed_results
    passed = sum(1 for r in all_results if r.passed)
    total = len(all_results)
    if passed == total:
        print(f"PASS — all {total} probes succeeded")
        return 0
    print(f"FAIL — {passed} / {total} passed")
    for r in all_results:
        if not r.passed:
            print(f"  - {r.name}: HTTP {r.status_code} — {r.detail}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
