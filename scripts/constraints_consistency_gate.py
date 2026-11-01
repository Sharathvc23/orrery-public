"""A constraints file must agree with the install sources beside it.

`server/constraints.txt` and `agent/constraints.txt` hold the exact `sm-*` pins.
Neither one installs anything: the locks and requirements files next to them are
what CI resolves and what the images build from. So a constraints file is a
*statement about* an install, and a statement can go stale without breaking a
build — which is exactly what happened.

**The drift this was written for.** `agent/constraints.txt` pinned
`sm-bridge==0.6.0` while `agent/requirements.lock`, in the same directory, pinned
`0.10.0`. Four releases apart, and nothing failed, because the lock is what
installs. The step that should have caught it was already called "Constraints
files stay exact and consistent" — it parsed BOTH constraints files, then
cross-checked only the server's against `server/requirements.txt` and dropped the
agent's pins on the floor. A gate that reads a file and then does not compare it
is worse than one that never opened it, because the name promises the comparison.

**The file set is derived, never listed.** Every tracked `*/constraints.txt` is
paired with every `requirements*.txt` / `requirements*.lock` beside it. A new
package directory, or a second lock added to an existing one, is covered the
moment it is tracked. The previous version of this check named its two paths by
hand, which is the same shape as the CVE scan that "once named three by hand and
missed the rest".

**Two rules, because absence and disagreement are different faults.**

* *Presence* — each pin must be matched by at least one sibling install source.
  A pin nothing installs is a claim about nothing.
* *Agreement* — no sibling may pin that package at a different version. This is
  the rule that was missing.

A sibling that does not mention the package at all is not a fault: a dev lock
carries test tooling and is not expected to resolve the runtime set. Requiring
presence in *every* sibling would redden `agent/requirements-dev.lock`, which
correctly pins no `sm-*` at all.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

#: A constraints line must be an exact `sm-*` pin and nothing else. Kept strict:
#: a range in a file whose whole purpose is exactness is itself the defect.
CONSTRAINT_LINE = re.compile(r"(sm-[a-z0-9-]+)==(\d+\.\d+\.\d+)$")

#: An install source holds ordinary pins of every shape, so this is deliberately
#: loose. Applying the strict pattern above to a lock would redden every line in
#: it that is not an `sm-*` package, which is almost all of them.
INSTALL_LINE = re.compile(r"([A-Za-z0-9._-]+)==([^\s;#\[\]]+)")

#: An install source is a sibling of the constraints file, by name.
INSTALL_SOURCE = re.compile(r"^requirements[A-Za-z0-9._-]*\.(txt|lock)$")


def tracked_files() -> list[str]:
    out = subprocess.run(
        ["git", "ls-files"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return [line for line in out.splitlines() if line]


def constraint_pins(text: str, path: str) -> tuple[dict[str, str], list[str]]:
    """Every non-comment line, or a complaint naming the line that is not a pin."""
    pins: dict[str, str] = {}
    problems: list[str] = []
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = CONSTRAINT_LINE.fullmatch(line)
        if match is None:
            problems.append(f"{path}:{number}: not an exact sm-* pin: {line!r}")
        else:
            pins[match.group(1)] = match.group(2)
    if not pins and not problems:
        problems.append(f"{path}: no sm-* pins found, so this file constrains nothing")
    return pins, problems


def install_pins(text: str) -> dict[str, str]:
    pins: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = INSTALL_LINE.match(line)
        if match is not None:
            pins[match.group(1).lower()] = match.group(2)
    return pins


def pairs(files: list[str]) -> dict[str, list[str]]:
    """Each tracked constraints file, mapped to the install sources beside it."""
    found: dict[str, list[str]] = {}
    for name in files:
        path = Path(name)
        if path.name != "constraints.txt":
            continue
        siblings = sorted(
            other
            for other in files
            if Path(other).parent == path.parent and INSTALL_SOURCE.match(Path(other).name)
        )
        found[name] = siblings
    return found


def check(read: dict[str, str], files: list[str]) -> list[str]:
    """Every complaint, in reporting order. Empty means consistent."""
    problems: list[str] = []
    for constraints, siblings in sorted(pairs(files).items()):
        pins, bad_lines = constraint_pins(read[constraints], constraints)
        problems.extend(bad_lines)
        if not siblings:
            problems.append(
                f"{constraints}: no requirements file beside it, so nothing installs what it pins"
            )
            continue
        installed = {sibling: install_pins(read[sibling]) for sibling in siblings}
        for name, version in sorted(pins.items()):
            seen_anywhere = False
            for sibling, pinned in installed.items():
                actual = pinned.get(name)
                if actual is None:
                    continue
                seen_anywhere = True
                if actual != version:
                    problems.append(
                        f"{sibling}: pins {name}=={actual}, but {constraints} says "
                        f"{version} — the install source wins, so one of them is a lie"
                    )
            if not seen_anywhere:
                problems.append(
                    f"{constraints}: pins {name}=={version}, which no install source beside it "
                    f"mentions ({', '.join(siblings)}) — nothing installs it"
                )
    return problems


def self_test() -> int:
    """Prove both rules still detect, and that the tolerated shapes stay tolerated."""
    cases: list[tuple[str, dict[str, str], list[str], bool]] = [
        (
            "agreement: a lock four releases ahead of the constraints file — the drift this exists for",
            {
                "pkg/constraints.txt": "sm-bridge==0.6.0\n",
                "pkg/requirements.lock": "sm-bridge==0.10.0\nhttpx==0.27.0\n",
            },
            ["pkg/constraints.txt", "pkg/requirements.lock"],
            True,
        ),
        (
            "presence: a pin no install source mentions",
            {
                "pkg/constraints.txt": "sm-bridge==0.10.0\n",
                "pkg/requirements.lock": "httpx==0.27.0\n",
            },
            ["pkg/constraints.txt", "pkg/requirements.lock"],
            True,
        ),
        (
            "exactness: a range in a file whose purpose is exactness",
            {
                "pkg/constraints.txt": "sm-bridge>=0.10.0\n",
                "pkg/requirements.lock": "sm-bridge==0.10.0\n",
            },
            ["pkg/constraints.txt", "pkg/requirements.lock"],
            True,
        ),
        (
            "a constraints file with no install source beside it",
            {"pkg/constraints.txt": "sm-bridge==0.10.0\n"},
            ["pkg/constraints.txt"],
            True,
        ),
        (
            "MUST NOT match: a dev lock that pins no sm-* at all is correct, not a gap",
            {
                "pkg/constraints.txt": "sm-bridge==0.10.0\n",
                "pkg/requirements.lock": "sm-bridge==0.10.0\n",
                "pkg/requirements-dev.lock": "pytest==8.0.0\n",
            },
            ["pkg/constraints.txt", "pkg/requirements.lock", "pkg/requirements-dev.lock"],
            False,
        ),
        (
            "MUST NOT match: comments and blank lines carry no pin",
            {
                "pkg/constraints.txt": "# sm-bridge==0.6.0 was here\n\nsm-bridge==0.10.0\n",
                "pkg/requirements.lock": "sm-bridge==0.10.0  # the registry endpoints\n",
            },
            ["pkg/constraints.txt", "pkg/requirements.lock"],
            False,
        ),
        (
            "MUST NOT match: a package whose name merely starts the same",
            {
                "pkg/constraints.txt": "sm-arp==0.3.2\n",
                "pkg/requirements.lock": "sm-arp==0.3.2\nsm-arp-extras==9.9.9\n",
            },
            ["pkg/constraints.txt", "pkg/requirements.lock"],
            False,
        ),
    ]

    failures = 0
    for label, read, files, should_complain in cases:
        problems = check(read, files)
        if bool(problems) is not should_complain:
            failures += 1
            want = "a complaint" if should_complain else "silence"
            print(f"SELF-TEST FAILED: {label}\n  expected {want}, got {problems}", file=sys.stderr)
    if failures:
        print(f"{failures} self-test case(s) failed — the gate is not measuring what it claims", file=sys.stderr)
        return 1
    print(f"OK: self-test — {len(cases)} cases, both rules detect and the tolerated shapes stay quiet")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="prove the rules still detect, then exit",
    )
    args = parser.parse_args()

    if args.self_test:
        return self_test()

    files = tracked_files()
    found = pairs(files)
    if len(found) < 2:
        print(
            f"REFUSING: only {len(found)} constraints file(s) enumerated. This repository has at "
            "least two (server and agent), so `git ls-files` is not reaching the tree and a clean "
            "result here would mean nothing.",
            file=sys.stderr,
        )
        return 1

    read = {
        path: Path(path).read_text(encoding="utf-8")
        for constraints, siblings in found.items()
        for path in (constraints, *siblings)
    }
    problems = check(read, files)
    if problems:
        print(f"::error::{len(problems)} constraints inconsistency(ies):", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        return 1

    checked = sum(len(siblings) for siblings in found.values())
    print(
        f"OK: {len(found)} constraints file(s) agree with the {checked} install source(s) beside them"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
