"""Post-deploy smoke test — confirms the running chapter is the version we just shipped.

Catches the failure mode discovered in this codebase's history (PR
incident): production ran on earlier code for ~2 weeks because every
redeploy crashed silently on a missing import, while the previous
container kept serving /health. From outside it looked like deploys
were succeeding; the chapter was alive, just executing stale code.

This script makes that pattern impossible to miss:

  python -m chapter.scripts.verify_deploy \\
      --url https://org.example.com \\
      --expected-commit $(git rev-parse --short HEAD)

Exit codes:
  0 — chapter is running the expected commit
  1 — running a DIFFERENT commit than expected (deploy didn't land)
  2 — chapter unreachable or /version not exposed (old deploy or build broken)
  3 — usage / arg error

Run from CI immediately after a successful deploy. If exit != 0, fail
the deploy job loudly. Run from operator dashboards on a periodic
cadence to detect drift.
"""

from __future__ import annotations

import argparse
import sys

import httpx


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--url",
        required=True,
        help="Chapter URL, e.g. https://org.example.com",
    )
    parser.add_argument(
        "--expected-commit",
        required=True,
        help="Short git sha (7 chars) the deploy should be running",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=15.0,
        help="HTTP timeout per request (seconds, default: 15)",
    )
    parser.add_argument(
        "--poll-until",
        type=int,
        default=0,
        metavar="SECONDS",
        help=(
            "Poll /version every 10s for up to N seconds, waiting for the "
            "expected commit to appear. Use after railway up --detach when "
            "the build takes ~3 min — operator runs this and walks away. "
            "Default 0 (one-shot check)."
        ),
    )
    args = parser.parse_args()

    base = args.url.rstrip("/")
    expected = args.expected_commit.strip()

    if not expected:
        print("error: --expected-commit cannot be empty", file=sys.stderr)
        return 3

    if args.poll_until > 0:
        return _poll_until_match(base, expected, args.timeout, args.poll_until)

    try:
        with httpx.Client(timeout=args.timeout, follow_redirects=False) as client:
            r = client.get(f"{base}/version")
    except httpx.HTTPError as e:
        print(f"FAIL — {base}/version unreachable: {e}", file=sys.stderr)
        return 2

    if r.status_code == 404:
        print(
            f"FAIL — {base}/version returned 404. "
            "The running chapter does not expose /version, which means it "
            "predates PR F1. The deploy of the new build did NOT land — "
            "an older container is still serving. Investigate Railway / "
            "Docker build logs.",
            file=sys.stderr,
        )
        return 2
    if r.status_code != 200:
        print(
            f"FAIL — {base}/version returned HTTP {r.status_code}: {r.text[:200]}",
            file=sys.stderr,
        )
        return 2

    try:
        info = r.json()
    except Exception:
        print(f"FAIL — {base}/version returned non-JSON: {r.text[:200]}", file=sys.stderr)
        return 2

    running = (info.get("git_commit") or "").strip()
    branch = info.get("git_branch", "unknown")
    built_at = info.get("build_timestamp", "unknown")

    if not running or running == "unknown":
        print(
            f"FAIL — {base}/version returned git_commit={running!r}. "
            "The chapter image was not built with GIT_COMMIT baked in. "
            "Check Dockerfile + railway up --build-arg invocation.",
            file=sys.stderr,
        )
        return 2

    if running != expected:
        print(
            f"FAIL — version mismatch:\n"
            f"  Expected commit: {expected}\n"
            f"  Running commit:  {running}\n"
            f"  Branch:          {branch}\n"
            f"  Built at:        {built_at}\n"
            f"\n"
            f"The deploy did NOT land the expected code. Investigate:\n"
            f"  1. Did the Docker build complete successfully?\n"
            f"  2. Did Railway swap the old container for the new image?\n"
            f"  3. Did the new container crash on startup and Railway revert?\n"
            f"  (railway logs --service <name> --lines 100 to see startup banner)",
            file=sys.stderr,
        )
        return 1

    print(
        f"PASS — chapter at {base} is running expected commit {running}\n  Branch:    {branch}\n  Built at:  {built_at}"
    )
    return 0


def _poll_until_match(base: str, expected: str, http_timeout: float, deadline_seconds: int) -> int:
    """Poll /version every 10s until git_commit matches expected or deadline expires.

    Operator pattern: chapter/scripts/deploy_production.sh issues
    `railway up --detach`, then immediately invokes this script with
    --poll-until 600. The deploy script doesn't return until /version
    confirms the new SHA is live, OR exits non-zero after the deadline.

    Returns the same exit codes as the one-shot path. The last response
    is logged at the end so the operator can see what state we ended in.
    """
    import time

    start = time.monotonic()
    deadline = start + deadline_seconds
    print(f"polling {base}/version every 10s for expected commit={expected}, timeout={deadline_seconds}s...")

    last_status = "no response"
    while True:
        elapsed = int(time.monotonic() - start)
        try:
            with httpx.Client(timeout=http_timeout, follow_redirects=False) as client:
                r = client.get(f"{base}/version")
            if r.status_code == 404:
                last_status = "404 (no /version endpoint)"
            elif r.status_code != 200:
                last_status = f"HTTP {r.status_code}"
            else:
                try:
                    info = r.json()
                    running = (info.get("git_commit") or "").strip()
                except Exception:
                    info = {}
                    running = ""
                    last_status = "non-JSON response"

                if running == expected:
                    print(f"\n✓ matched after {elapsed}s — chapter at {base} is running expected commit {expected}")
                    print(
                        f"  Branch:    {info.get('git_branch', 'unknown')}\n"
                        f"  Built at:  {info.get('build_timestamp', 'unknown')}"
                    )
                    return 0
                last_status = f"running={running or '(empty)'}"
        except httpx.HTTPError as e:
            last_status = f"network: {type(e).__name__}"

        if time.monotonic() >= deadline:
            print(
                f"\n✗ TIMEOUT after {elapsed}s — expected commit {expected} never appeared. "
                f"Last observed: {last_status}.\n"
                f"\n"
                f"The build may have failed or the new container may have crashed at startup.\n"
                f"Investigate:\n"
                f"  railway logs --service <name> --build  --lines 30\n"
                f"  railway logs --service <name> --deployment  --lines 30",
                file=sys.stderr,
            )
            return 1

        print(f"  [{elapsed:>3}s] {last_status}")
        time.sleep(10)


if __name__ == "__main__":
    sys.exit(main())
