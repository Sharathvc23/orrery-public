#!/usr/bin/env python3
"""Scan the ENTIRE git history for secrets — every ref, every commit, every blob.

WHY THIS EXISTS SEPARATELY FROM ``secret scan (new commits)`` IN ci.yml.
That job scans the PR range (``BASE..HEAD``), which is the right shape for a
merge gate: it prevents the NEXT secret without relitigating fixtures on every
PR. But it means nothing has ever answered *what is already in there*. When a
private repo is flipped public, every commit on every branch becomes visible at
once and permanently — so "we scan new commits" and "the history is clean" are
different claims, and only the second one matters at the flip.

TWO PASSES, DELIBERATELY, because the obvious one has a blind spot:

1. **Commit walk** — ``gitleaks git --log-opts=--all``. Scans DIFFS, and
   ``git log`` does not diff merge commits by default, so content that entered
   the tree only through a merge resolution is never shown to the scanner.
   Measured on this repo: 711 commits scanned against 747 reachable.
2. **Blob sweep** — every unique blob reachable from every ref, extracted and
   scanned as a directory. Topology-independent, so it cannot miss a merge
   resolution or a file that only ever lived on a since-deleted branch. This is
   the authoritative pass; pass 1 is kept because it reports the COMMIT a
   finding lives in, which is what you need to act on one.

**HISTORY IS NOT REWRITTEN HERE**, and this script must never grow that ability.
Purge-versus-rotate on a repo whose SHAs are already cited in issues and PRs is
a judgement call with consequences no automated run can undo.

WHY A BASELINE RATHER THAN A WIDER ALLOWLIST. The history holds findings that
have been classified and accepted (see ``docs/SECRET_SCAN_BASELINE.md``). Two
ways to keep this job green were available and one of them is a trap: loosening
``.gitleaks.toml`` would weaken the *merge gate* too, because both use the same
config on purpose — a full-history scan reporting a different number than the
PR gate for the same tree would make both numbers meaningless. So the ruleset
stays exactly as strict, and the accepted findings are pinned individually by
fingerprint. A finding not in the baseline is NEW and fails. The baseline holds
no secret values, only locations.

Run locally:

    python3 scripts/full_history_secret_scan.py            # scan
    python3 scripts/full_history_secret_scan.py --update-baseline
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

# Same version and checksum as the PR-range job in ci.yml — see the docstring.
GITLEAKS_VERSION = "8.24.3"
GITLEAKS_SHA256 = "9991e0b2903da4c8f6122b5c3186448b927a5da4deef1fe45271c3793f4ee29c"
GITLEAKS_URL = (
    f"https://github.com/gitleaks/gitleaks/releases/download/v{GITLEAKS_VERSION}"
    f"/gitleaks_{GITLEAKS_VERSION}_linux_x64.tar.gz"
)

BASELINE = Path("scripts/full_history_secret_baseline.txt")


def repo_root() -> Path:
    out = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    return Path(out)


def ensure_gitleaks(workdir: Path) -> str:
    """The pinned scanner, verified before it is executed."""
    found = shutil.which("gitleaks")
    if found:
        ver = subprocess.run(
            [found, "version"], capture_output=True, text=True
        ).stdout.strip()
        if ver == GITLEAKS_VERSION:
            return found

    print(f"→ fetching gitleaks {GITLEAKS_VERSION}")
    tgz = workdir / "gitleaks.tgz"
    with urllib.request.urlopen(GITLEAKS_URL) as resp:  # noqa: S310 — pinned URL
        tgz.write_bytes(resp.read())
    digest = hashlib.sha256(tgz.read_bytes()).hexdigest()
    if digest != GITLEAKS_SHA256:
        # Refuse rather than warn: running an unverified scanner and reporting
        # its green is worse than not scanning, because it produces a claim.
        raise SystemExit(
            f"REFUSING: gitleaks checksum mismatch\n"
            f"  expected {GITLEAKS_SHA256}\n  actual   {digest}"
        )
    subprocess.run(["tar", "xzf", str(tgz), "-C", str(workdir), "gitleaks"], check=True)
    return str(workdir / "gitleaks")


def _run_gitleaks(gitleaks: str, args: list[str], report: Path, config: Path) -> list[dict]:
    # ⚠️ -c is passed EXPLICITLY, always. gitleaks AUTO-LOADS .gitleaks.toml from
    # the scan target path, so a run that omits -c to get an unconfigured
    # baseline silently loads the repo config anyway and returns the identical
    # number — which reads as "the allowlist does nothing" when in fact it was
    # applied to both runs. Anyone re-deriving these numbers needs to know that.
    subprocess.run(
        [gitleaks, *args, "--no-banner", "--redact", "-c", str(config),
         "--report-format", "json", "--report-path", str(report), "--exit-code", "0"],
        check=True,
    )
    if not report.exists() or not report.read_text().strip():
        return []
    return json.loads(report.read_text()) or []


def commit_walk(gitleaks: str, workdir: Path, config: Path) -> list[dict]:
    reachable = subprocess.run(
        ["git", "rev-list", "--all", "--count"], capture_output=True, text=True, check=True
    ).stdout.strip()
    print(f"\n══ PASS 1 — commit walk over every ref ({reachable} commits reachable)")
    findings = _run_gitleaks(
        gitleaks, ["git", ".", "--log-opts=--all"], workdir / "commits.json", config
    )
    for f in findings:
        # ⚠️ The COMMIT ID IS DELIBERATELY NOT IN THE FINGERPRINT. Commit ids do
        # not survive a history rewrite, and this project is published as a new
        # repository with a fresh squashed commit — so a commit-keyed baseline
        # would match nothing there and the first scheduled run in the published
        # repo would go red, reading as "the published repo leaks secrets".
        # Blob ids are content-addressed and DO survive, which is why the blob
        # sweep is the authoritative pass; keying the commit pass on (file, rule)
        # makes the whole baseline portable across a republish.
        #
        # The LINE NUMBER is left out for the same reason: the same finding sits
        # at a different line in an old revision than at HEAD, so a line-keyed
        # entry goes stale on the first squash. Detection does not rest on this
        # pass — a newly added secret changes the file's CONTENT, so the blob
        # sweep sees an id it has never seen and fails, with the file and line
        # intact. This pass exists to say which commit to look at, and a
        # coarser key costs nothing it was providing.
        f["_fp"] = f"commit:{f['File']}:{f['RuleID']}"
    return findings


def blob_sweep(gitleaks: str, workdir: Path, config: Path) -> list[dict]:
    print("\n══ PASS 2 — every blob reachable from every ref")
    blobs = workdir / "blobs"
    blobs.mkdir(exist_ok=True)

    listing = subprocess.run(
        ["git", "rev-list", "--objects", "--all"], capture_output=True, text=True, check=True
    ).stdout.splitlines()
    types = subprocess.run(
        ["git", "cat-file", "--batch-all-objects", "--batch-check=%(objectname) %(objecttype)"],
        capture_output=True, text=True, check=True,
    ).stdout.split()
    kind = dict(zip(types[0::2], types[1::2], strict=False))

    seen: dict[str, str] = {}
    for line in listing:
        sha, _, path = line.partition(" ")
        if path and kind.get(sha) == "blob":
            seen.setdefault(sha, path)

    # sha8 -> real repo path. Kept as a MAP rather than encoded into the
    # extracted filename: `/` had been replaced with `_`, which is not
    # reversible when the path already contains `_` — it turned
    # `test_recovery_rotation.py` into `test/recovery/rotation.py` in the
    # fingerprint, so a baseline entry named a file that does not exist.
    origin: dict[str, str] = {}
    for sha, path in seen.items():
        origin[sha[:8]] = path
        dst = blobs / sha[:8]
        dst.write_bytes(
            subprocess.run(["git", "cat-file", "blob", sha], capture_output=True).stdout
        )
    print(f"   {len(seen)} unique blobs extracted")

    findings = _run_gitleaks(gitleaks, ["dir", str(blobs)], workdir / "blobs.json", config)
    for f in findings:
        sha8 = Path(f["File"]).name
        f["_path"] = origin.get(sha8, "?")
        f["_fp"] = f"blob:{sha8}:{f['_path']}:{f['RuleID']}:{f['StartLine']}"
    return findings


def load_baseline() -> set[str]:
    if not BASELINE.exists():
        return set()
    return {
        line.split("#", 1)[0].strip()
        for line in BASELINE.read_text().splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    } - {""}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--update-baseline",
        action="store_true",
        help="rewrite the baseline from this run — only after classifying every new finding",
    )
    args = parser.parse_args()

    os.chdir(repo_root())
    config = Path(".gitleaks.toml").resolve()
    if not config.exists():
        print("REFUSING: .gitleaks.toml is missing — the PR gate and this scan "
              "must use the same ruleset or neither number means anything.", file=sys.stderr)
        return 1

    with tempfile.TemporaryDirectory() as tmp:
        workdir = Path(tmp)
        gitleaks = ensure_gitleaks(workdir)
        findings = commit_walk(gitleaks, workdir, config) + blob_sweep(gitleaks, workdir, config)

    fingerprints = {f["_fp"] for f in findings}

    if args.update_baseline:
        BASELINE.write_text(
            "# Accepted full-history secret-scan findings, pinned by LOCATION ONLY.\n"
            "# No secret values here. Classification: docs/SECRET_SCAN_BASELINE.md\n"
            "# Regenerate: python3 scripts/full_history_secret_scan.py --update-baseline\n"
            "#\n"
            "# Adding a line here ACCEPTS a finding. Do not do it to make CI green —\n"
            "# classify it first, and rotate anything live BEFORE it is accepted.\n"
            + "".join(f"{fp}\n" for fp in sorted(fingerprints))
        )
        print(f"\nbaseline rewritten: {len(fingerprints)} findings in {BASELINE}")
        return 0

    baseline = load_baseline()
    new = sorted(fingerprints - baseline)
    stale = sorted(baseline - fingerprints)

    print(f"\n══ RESULT: {len(findings)} finding(s), {len(baseline)} accepted in the baseline")

    if stale and baseline and len(stale) == len(baseline):
        # EVERY entry stale means the fingerprints describe a history this clone
        # does not have — which is exactly what publishing as a NEW repository
        # with a single squashed commit produces. Said loudly and early, because
        # the alternative is a first-ever scheduled run that goes red on day one
        # and reads as "the published repo leaks secrets".
        print(
            f"\n⚠️  ALL {len(baseline)} baseline entries matched nothing. The baseline "
            "fingerprints a history this repository does not have.\n"
            "    Expected if this tree was published as a new repository with a fresh\n"
            "    squashed commit: commit and blob ids are all different, so nothing lines up.\n"
            "    REGENERATE IT ONCE, after reviewing what the scan reports below:\n"
            "        python3 scripts/full_history_secret_scan.py --update-baseline\n"
            "    Review first. Regenerating accepts whatever is found, which is only safe\n"
            "    because the findings were classified in docs/SECRET_SCAN_BASELINE.md."
        )
    elif stale:
        # Not a failure: history is append-only, but a rescan from a different
        # clone can legitimately see fewer refs. Reported so the baseline does
        # not quietly accumulate entries that match nothing.
        print(f"\n   {len(stale)} baseline entr(ies) matched nothing this run:")
        for fp in stale[:10]:
            print(f"     - {fp}")

    if not new:
        print("\nOK — every finding in the full history is a classified, accepted one.")
        print("     What this does NOT prove: gitleaks detects neither a bare 32-byte")
        print("     base64 seed nor a low-entropy token, with or without this repo's")
        print("     config (verified both ways — see the note in .gitleaks.toml).")
        return 0

    print(f"\n::error::{len(new)} NEW finding(s) in git history, not in the baseline:", file=sys.stderr)
    for fp in new:
        print(f"  {fp}", file=sys.stderr)
    print(
        "\n  DO NOT rewrite history as a reflex, and do not add these to the baseline\n"
        "  to get a green. Classify each one first — live credential, test fixture,\n"
        "  or false positive — because the remedy differs completely:\n"
        "\n"
        "    * live credential → ROTATE IT FIRST. It is compromised from the moment\n"
        "      it was committed, and rotation is what actually closes the exposure.\n"
        "      Only then is purge-versus-leave a question worth asking, and it is a\n"
        "      human's call: rewriting invalidates SHAs already cited in issues and\n"
        "      PRs, and no PR can undo it.\n"
        "    * fixture / false positive → prefer a SHAPE allowlist in .gitleaks.toml\n"
        "      (which also protects the PR gate) over a baseline entry. Never\n"
        "      allowlist by path: a real key committed into that path would then\n"
        "      never fire again.\n",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
