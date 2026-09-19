"""The dependency CVE scan audits every pinned requirement file in the tree.

The job listed three files by hand. index/requirements.lock and
conformance/federation/requirements.txt were never audited, so an advisory
against a package pinned only there would not have turned the job red. This
pins the job's list to the tree: a new requirements/constraints file that is
not added to the scan is a failing test, not a silent gap.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
PIN_FILE = re.compile(r"(^|/)(requirements[^/]*\.(?:txt|lock)|constraints[^/]*\.txt)$")


def _tracked_pin_files() -> set[str]:
    out = subprocess.run(
        ["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout
    return {
        line
        for line in out.splitlines()
        if PIN_FILE.search(line) and "node_modules" not in line
    }


def _audited_files() -> set[str]:
    text = WORKFLOW.read_text(encoding="utf-8")
    m = re.search(r"pip-audit -r \"\$req\"", text)
    assert m, (
        "the CVE scan step no longer runs pip-audit over a $req loop — update this guard with it"
    )
    loops = re.findall(r"for req in ([^;]+); do", text)
    assert loops, "no `for req in …; do` loop found in ci.yml"
    return {f for loop in loops for f in loop.split()}


def test_the_tree_has_pin_files_to_audit():
    assert len(_tracked_pin_files()) >= 3


def test_every_tracked_pin_file_is_audited():
    missing = sorted(_tracked_pin_files() - _audited_files())
    assert not missing, f"pinned requirement files the CVE scan never reads: {missing}"


def test_every_audited_file_exists():
    ghosts = sorted(f for f in _audited_files() if not (ROOT / f).is_file())
    assert not ghosts, f"the CVE scan names files that are not in the tree: {ghosts}"
