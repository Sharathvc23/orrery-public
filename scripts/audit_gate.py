#!/usr/bin/env python3
"""Fail when the security audit's status claims stop being checkable.

WHY THIS EXISTS. ``AUDIT_HARSH.md`` carried the status of 62 findings in prose —
"FIXED", "still open", "residual" — and nothing compared those words to anything.
The result, measured on 2026-09-12: every Critical and High carried a verdict,
while **26 of the 35 Medium and Low findings carried no status at all**. Not
deferred, not accepted: blank. A reader cannot tell the difference between a
finding that was assessed and dismissed and one that was quietly dropped, and an
outside reader will assume the second.

``docs/CLAIMS.md`` already solved this problem for capability claims: a closed
verdict vocabulary, evidence per row, and a SHA pin so a verdict is anchored to a
tree rather than to whenever someone last read the page. This gate applies the
same discipline to the audit, because a security document that cannot be checked
is exactly the kind of claim the product exists to refuse.

WHAT IT ENFORCES

1. **No silent findings.** Every ``### C1.``-style heading in the audit document
   has an entry in ``docs/audit/findings.json``. A finding cannot be added to the
   prose and left out of the checked set.
2. **Closed status vocabulary.** No free text. ``untriaged`` is a legal value on
   purpose — the honest state for the 26 — but it is counted and reported, so it
   cannot hide.
3. **"Fixed" has to point at something.** A finding claiming ``fixed`` or
   ``mitigated`` must cite at least one evidence path, and that path must exist
   on disk. A fix with no regression test is a claim, not evidence — the same
   standard the four prose gates already hold themselves to with ``--self-test``.
4. **Scope is declared, not implied.** Every component directory in the tree
   appears in ``docs/audit/SCOPE.md``. Silence about an unexamined component is
   the failure mode that discredits an audit; an explicit "not examined, here is
   why" survives review.
5. **Staleness is visible.** The pinned SHA is reported against HEAD with the
   commit distance, so "audited" never silently means "audited four months ago".
6. **The coverage table is arithmetic, not prose.** ``SCOPE.md`` tells a reader
   the table is mechanically re-derivable and hands them the commands. Nothing
   checked that, and the table drifted from its own anchor: on 2026-09-14 five of
   thirteen rows disagreed with the pinned tree, ``index`` by 34% (1,073 listed
   against 1,437 actual). A reader who ran the documented commands got different
   numbers than the page showed — the precise credibility failure ``SCOPE.md``
   exists to prevent. The derived figures now live beside ``pinned_sha`` in
   ``findings.json`` and the gate fails when the table disagrees with them.

   **Why the numbers are stored rather than recomputed on every run.** They
   describe the PINNED tree, not HEAD, because that is the tree the verdicts were
   reached against. Recomputing them needs the pinned commit, and CI checks out
   at depth 1 — so a gate that re-derived on every run would fail in CI for want
   of an object rather than for drift. ``--rederive`` does the history-dependent
   half, is operator-run at re-pinning time, and says so; the always-on rule
   checks the table against the stored block, which needs no history and catches
   the hand-edit drift that actually happened.

``--self-test`` plants a violation of each rule in memory and asserts the check
rejects it, so a green run means "the rules hold" rather than "the checks did
nothing". Exit 0 clean, 1 on violation, 2 on a broken self-test.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
AUDIT_DOC = REPO / "AUDIT_HARSH.md"
FINDINGS = REPO / "docs" / "audit" / "findings.json"
SCOPE = REPO / "docs" / "audit" / "SCOPE.md"

# Closed vocabulary. Mirrors the spirit of docs/CLAIMS.md: each value says
# something different to a reader, and "untriaged" is legal precisely so that
# not-yet-assessed is representable instead of being left blank.
STATUSES = {
    "fixed",  # addressed; must cite evidence that exists
    "mitigated",  # partially addressed; residual named; must cite evidence
    "residual",  # accepted risk, stated rather than closed
    "overstated",  # the finding was wrong or narrower than written
    "open",  # real, unaddressed, acknowledged
    "fixed-unevidenced",  # the original audit called it fixed; no regression test
    # was found that fails if the fix is reverted. Distinct from "fixed" on
    # purpose: it preserves the fact that someone assessed it, while refusing to
    # let it count as proven. Collapsing it into "fixed" would be the lie; into
    # "untriaged" would discard real work.
    "untriaged",  # not yet assessed — counted and reported, never hidden
    "out-of-scope",  # deliberately excluded; SCOPE.md must say why
}
NEEDS_EVIDENCE = {"fixed", "mitigated"}

# Directories that are not product components and are not audit subjects.
NOT_COMPONENTS = {"docs", "tests", "schema", "vectors", "examples", "templates", "changelog.d"}


#: Components whose LOC and route counts SCOPE.md publishes. Derived at
#: ``pinned_sha`` by ``--rederive`` and stored in findings.json under
#: ``coverage``; the always-on rule compares the table to that block.
ROUTE_DECORATOR = re.compile(r"@(app|router)\.(get|post|put|patch|delete)\(")

#: One row of SCOPE.md's coverage table: | `comp` | LOC | routes | ...
SCOPE_ROW = re.compile(
    r"^\|\s*`(?P<comp>[A-Za-z0-9_-]+)`\s*\|\s*(?P<loc>[\d,]+)\s*\|\s*(?P<routes>\d+)\s*\|",
    re.M,
)


def derive_coverage(tree: str, components: list[str]) -> dict[str, dict[str, int]]:
    """LOC and route counts per component, read out of ``tree`` via git.

    ``components`` is passed in rather than taken from ``repo_components()``
    because the two sets are not the same and the difference is load-bearing:
    ``repo_components`` walks tracked DIRECTORIES, and ``orrery-up`` is a tracked
    single FILE at the repo root. Deriving only over directories silently drops
    it, leaving a row in the coverage table that nothing computed — which rule 6
    would then report as a defect in the table rather than in this function. The
    caller passes the union of the directories and whatever the table names.

    Needs the object to be present, so this is the operator-run half — see the
    module docstring on why CI cannot do it.
    """
    out: dict[str, dict[str, int]] = {}
    for comp in components:
        names = subprocess.run(
            ["git", "ls-tree", "-r", "--name-only", tree, "--", comp],
            cwd=REPO,
            capture_output=True,
            text=True,
        ).stdout.split()
        if not names:
            continue
        loc = 0
        routes = 0
        for name in names:
            blob = subprocess.run(
                ["git", "show", f"{tree}:{name}"], cwd=REPO, capture_output=True
            ).stdout
            loc += blob.count(b"\n")
            routes += len(ROUTE_DECORATOR.findall(blob.decode("utf-8", "replace")))
        out[comp] = {"loc": loc, "routes": routes}
    return out


def scope_table(scope_text: str) -> dict[str, dict[str, int]]:
    """The coverage table as SCOPE.md currently states it."""
    return {
        m.group("comp"): {
            "loc": int(m.group("loc").replace(",", "")),
            "routes": int(m.group("routes")),
        }
        for m in SCOPE_ROW.finditer(scope_text)
    }


def audit_finding_ids() -> list[str]:
    """Finding ids as they appear in the prose document."""
    if not AUDIT_DOC.exists():
        return []
    return re.findall(
        r"^### ([CHML]\d{1,2})\.", AUDIT_DOC.read_text(encoding="utf-8"), re.M
    )


def repo_components() -> list[str]:
    """Top-level component directories tracked by git."""
    out = subprocess.run(
        ["git", "ls-files"], cwd=REPO, capture_output=True, text=True, check=False
    ).stdout.splitlines()
    dirs = {p.split("/")[0] for p in out if "/" in p}
    return sorted(d for d in dirs if not d.startswith(".") and d not in NOT_COMPONENTS)


def check(
    doc: dict, prose_ids: list[str], components: list[str], scope_text: str
) -> list[str]:
    """Return a list of violations. Empty means the audit's claims are checkable."""
    problems: list[str] = []
    findings = doc.get("findings", [])
    by_id = {f.get("id"): f for f in findings}

    # 1. no silent findings
    for fid in prose_ids:
        if fid not in by_id:
            problems.append(
                f"{fid}: present in {AUDIT_DOC.name} but absent from findings.json"
            )
    for fid in by_id:
        if prose_ids and fid not in prose_ids:
            problems.append(
                f"{fid}: in findings.json but no matching heading in {AUDIT_DOC.name}"
            )

    for f in findings:
        fid = f.get("id", "?")
        st = f.get("status")
        # 2. closed vocabulary
        if st not in STATUSES:
            problems.append(f"{fid}: status {st!r} is not one of {sorted(STATUSES)}")
            continue
        # 3. a claim of remediation must point at something that exists
        if st in NEEDS_EVIDENCE:
            ev = f.get("evidence") or []
            if not ev:
                problems.append(
                    f"{fid}: status {st!r} with no evidence — a fix without a test is a claim"
                )
            for path in ev:
                target = REPO / str(path).split("::", 1)[0]
                if not target.exists():
                    problems.append(f"{fid}: evidence path does not exist: {path}")

    # 6. the coverage table is arithmetic, and must agree with the derived block
    coverage = doc.get("coverage") or {}
    if scope_text and coverage:
        stated = scope_table(scope_text)
        for comp, derived in sorted(coverage.items()):
            row = stated.get(comp)
            if row is None:
                problems.append(
                    f"{comp}: coverage derived at the pinned tree but no row in {SCOPE.name}"
                )
                continue
            for field in ("loc", "routes"):
                if row[field] != derived[field]:
                    problems.append(
                        f"{comp}: {SCOPE.name} states {field}={row[field]:,} but the pinned "
                        f"tree has {derived[field]:,} — re-derive with "
                        f"`python scripts/audit_gate.py --rederive` (needs full history)"
                    )
        for comp in sorted(set(stated) - set(coverage)):
            problems.append(
                f"{comp}: row in {SCOPE.name} with no derived coverage entry — a number "
                f"nobody computed"
            )
    elif scope_text and not coverage:
        problems.append(
            "findings.json has no `coverage` block — SCOPE.md's table would be unchecked prose"
        )

    # 4. scope declared for every component
    for comp in components:
        if not re.search(
            rf"(^|[^a-z0-9_]){re.escape(comp)}([^a-z0-9_]|$)", scope_text, re.M
        ):
            problems.append(
                f"{comp}: component not mentioned in {SCOPE.name} — scope silence"
            )

    return problems


def self_test() -> int:
    """Prove each rule can actually reject. A gate that cannot fail is decoration."""
    base = {
        "findings": [
            {
                "id": "C1",
                "severity": "critical",
                "status": "fixed",
                "evidence": ["README.md"],
            }
        ]
    }
    cases = [
        (
            "silent finding",
            base,
            ["C1", "C2"],
            [],
            "C1 C2",
            "absent from findings.json",
        ),
        (
            "coverage table disagrees with the derived block",
            {
                "findings": [
                    {"id": "C1", "status": "fixed", "evidence": ["README.md"]}
                ],
                "coverage": {"server": {"loc": 999, "routes": 7}},
            },
            ["C1"],
            [],
            "| `server` | 1,000 | 7 |",
            "but the pinned tree has",
        ),
        (
            "a coverage table row nobody computed",
            {
                "findings": [
                    {"id": "C1", "status": "fixed", "evidence": ["README.md"]}
                ],
                "coverage": {"server": {"loc": 1000, "routes": 7}},
            },
            ["C1"],
            [],
            "| `server` | 1,000 | 7 |\n| `ghost` | 5 | 0 |",
            "no derived coverage entry",
        ),
        (
            "no coverage block at all",
            {"findings": [{"id": "C1", "status": "fixed", "evidence": ["README.md"]}]},
            ["C1"],
            [],
            "| `server` | 1,000 | 7 |",
            "no `coverage` block",
        ),
        (
            "bad status",
            {"findings": [{"id": "C1", "status": "totally-fine", "evidence": []}]},
            ["C1"],
            [],
            "C1",
            "not one of",
        ),
        (
            "fixed with no evidence",
            {"findings": [{"id": "C1", "status": "fixed", "evidence": []}]},
            ["C1"],
            [],
            "C1",
            "no evidence",
        ),
        (
            "evidence path missing",
            {
                "findings": [
                    {"id": "C1", "status": "fixed", "evidence": ["does/not/exist.py"]}
                ]
            },
            ["C1"],
            [],
            "C1",
            "does not exist",
        ),
        (
            "undeclared component",
            base,
            ["C1"],
            ["smb_host"],
            "nothing here",
            "scope silence",
        ),
    ]
    for name, doc, ids, comps, scope, expect in cases:
        problems = check(doc, ids, comps, scope)
        if not any(expect in p for p in problems):
            print(
                f"SELF-TEST FAILED: {name!r} was not rejected (expected {expect!r})",
                file=sys.stderr,
            )
            print(f"  got: {problems}", file=sys.stderr)
            return 2
    # and the clean case must pass
    if check(base, ["C1"], [], "") != []:
        print("SELF-TEST FAILED: a clean input was rejected", file=sys.stderr)
        return 2
    print(
        f"self-test: {len(cases)} planted violations across the rules were all rejected, "
        f"and a clean input passes"
    )
    return 0


def rederive() -> int:
    """Recompute ``coverage`` at ``pinned_sha`` and write it into findings.json.

    Operator-run, not a CI step: it needs the pinned commit, and CI checks out at
    depth 1. It REFUSES rather than guesses when the object is absent — a
    coverage block silently derived from HEAD would describe a tree the verdicts
    were never reached against, which is worse than a stale one because it looks
    current.
    """
    doc = json.loads(FINDINGS.read_text(encoding="utf-8"))
    pinned = doc.get("pinned_sha", "")
    if not pinned:
        print("findings.json has no pinned_sha to derive against", file=sys.stderr)
        return 1
    present = subprocess.run(
        ["git", "cat-file", "-e", f"{pinned}^{{commit}}"],
        cwd=REPO,
        capture_output=True,
        check=False,
    )
    if present.returncode != 0:
        print(
            f"pinned commit {pinned[:7]} is not in this checkout — run with full history "
            f"(git fetch --unshallow). Refusing to derive against HEAD instead.",
            file=sys.stderr,
        )
        return 1

    stated = scope_table(SCOPE.read_text(encoding="utf-8") if SCOPE.exists() else "")
    derived = derive_coverage(pinned, sorted(set(repo_components()) | set(stated)))
    doc["coverage"] = derived
    FINDINGS.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    print(f"coverage re-derived at {pinned[:7]} for {len(derived)} components")
    for comp, nums in sorted(derived.items()):
        row = stated.get(comp)
        if row != nums:
            was = f"{row['loc']:,}/{row['routes']}" if row else "absent"
            print(
                f"  EDIT {SCOPE.name}: {comp} {was} -> {nums['loc']:,}/{nums['routes']}"
            )
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument(
        "--self-test", action="store_true", help="prove the checks can fail, then exit"
    )
    ap.add_argument(
        "--rederive",
        action="store_true",
        help="recompute the coverage block at pinned_sha and write it (needs full history)",
    )
    args = ap.parse_args()

    if args.rederive:
        return rederive()

    if args.self_test:
        rc = self_test()
        if rc:
            return rc

    if not FINDINGS.exists():
        print(f"missing {FINDINGS.relative_to(REPO)}", file=sys.stderr)
        return 1
    doc = json.loads(FINDINGS.read_text(encoding="utf-8"))
    scope_text = SCOPE.read_text(encoding="utf-8") if SCOPE.exists() else ""
    if not scope_text:
        print(
            f"missing {SCOPE.relative_to(REPO)} — scope must be declared, not implied",
            file=sys.stderr,
        )
        return 1

    prose_ids = audit_finding_ids()
    components = repo_components()
    problems = check(doc, prose_ids, components, scope_text)

    findings = doc.get("findings", [])
    counts = Counter(f.get("status") for f in findings)
    by_sev = Counter(f.get("severity") for f in findings)
    print(f"audit: {len(findings)} findings across {len(prose_ids)} prose headings")
    print("  by severity: " + "  ".join(f"{k}={v}" for k, v in sorted(by_sev.items())))
    print("  by status:   " + "  ".join(f"{k}={v}" for k, v in counts.most_common()))

    # 5. staleness, reported rather than enforced — a stale audit is a fact a
    # reader needs, not necessarily a build failure.
    pinned = doc.get("pinned_sha", "")
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=REPO,
        capture_output=True,
        text=True,
        check=False,
    ).stdout.strip()
    if pinned and head:
        # A failed rev-list and a distance of zero are NOT the same fact, and
        # collapsing them was a live bug: CI checks out at depth 1, the pinned
        # commit is absent, rev-list exits non-zero with empty stdout, and this
        # reported a four-commit-stale pin as "current" — the staleness signal
        # dead in the one place it runs unattended, failing in the direction
        # that flatters the audit. Distinguish them and say which.
        rev = subprocess.run(
            ["git", "rev-list", "--count", f"{pinned}..{head}"],
            cwd=REPO,
            capture_output=True,
            text=True,
            check=False,
        )
        dist = rev.stdout.strip()
        if rev.returncode != 0 or not dist:
            note = (
                "distance UNKNOWN — the pinned commit is not in this checkout "
                "(shallow clone?); staleness unverified, not verified-current"
            )
        elif dist == "0":
            note = "current"
        else:
            note = f"{dist} commits behind HEAD"
        print(f"  pinned_sha:  {pinned[:7]} ({note})")
    if doc.get("self_audit"):
        print(
            "  provenance:  SELF-AUDIT — not an independent review; stated so a reader can discount it"
        )
    untriaged = counts.get("untriaged", 0)
    if untriaged:
        print(
            f"  NOTE: {untriaged} finding(s) untriaged — legal, counted, and visible rather than blank"
        )

    if problems:
        print(f"\n{len(problems)} violation(s):", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        return 1
    print(
        "\naudit status is checkable: no silent findings, no unbacked fixes, scope declared"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
