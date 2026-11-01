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

**The rules, because these are all different faults.**

* *Presence* — each pin must appear in the **authoritative runtime lock**, which
  is `requirements.lock` when the directory has one. Accepting a match in *any*
  sibling would let a non-runtime source mask a package the install actually
  omits. Where there is no `requirements.lock`, any sibling satisfies it and the
  message says which were consulted.
* *Agreement* — no sibling may pin the package at a different version.
* *Exactness in the install sources too* — an `sm-*` requirement that is a range,
  a compatible-release clause or a direct URL reference is reported even when
  some other sibling holds the matching exact pin. The constraints file being
  exact is worth nothing if the thing that installs is loose, and a direct
  artifact reference is a supply-chain decision, not a pin.
* *Completeness* — an `sm-*` package pinned in an install source with no entry in
  the constraints file beside it is reported. Checking only the names already in
  the constraints file means a newly locked package is never examined, so the
  record silently stops being the record.

A sibling that does not mention a package at all is not a fault: a dev lock
carries test tooling and is not expected to resolve the runtime set, so
`agent/requirements-dev.lock` pins no `sm-*` and stays green.

**Names are normalised per PEP 503** and extras are parsed off, so `sm_bridge`,
`SM-Bridge` and `sm-bridge[feed]==0.10.0` are all recognised as the same
distribution. Comparing raw spellings would report a consistent tree as broken,
or — worse — miss a disagreement because the two files spelled the name
differently.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

#: A constraints line must be an exact `sm-*` pin and nothing else. Kept strict:
#: a range in a file whose whole purpose is exactness is itself the defect.
CONSTRAINT_LINE = re.compile(r"(sm-[a-z0-9_.-]+)==(\d+\.\d+\.\d+)$")

#: Any requirement in an install source: name, optional extras, then either a
#: version specifier or a direct reference. Deliberately permissive about the
#: operator so that a LOOSE `sm-*` requirement is captured and reported rather
#: than skipped — skipping it is how a range slips past a gate about exactness.
INSTALL_LINE = re.compile(
    r"(?P<name>[A-Za-z0-9._-]+)\s*(?P<extras>\[[^\]]*\])?\s*(?P<op>===|==|~=|!=|>=|<=|>|<|@)\s*(?P<rest>.+)$"
)

#: An install source is a sibling of the constraints file, by name.
INSTALL_SOURCE = re.compile(r"^requirements[A-Za-z0-9._-]*\.(txt|lock)$")

#: The sibling that actually installs. Both Dockerfiles and CI run
#: `pip install -r requirements.lock` and pass no `-c`, so this is the file a
#: pin has to appear in for the claim "this is installed" to hold.
RUNTIME_LOCK = "requirements.lock"


def normalize(name: str) -> str:
    """PEP 503 normalisation, so one distribution has one name here."""
    return re.sub(r"[-_.]+", "-", name).lower()


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
            pins[normalize(match.group(1))] = match.group(2)
    if not pins and not problems:
        problems.append(f"{path}: no sm-* pins found, so this file constrains nothing")
    return pins, problems


def install_requirements(text: str) -> dict[str, tuple[str, str, str]]:
    """Each requirement as ``name -> (operator, value, raw line)``.

    Loose and direct-reference requirements are KEPT, with their operator, so a
    caller can refuse them. A parser that returned only exact pins would make a
    range indistinguishable from an absence.
    """
    found: dict[str, tuple[str, str, str]] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = INSTALL_LINE.match(line)
        if match is None:
            continue
        value = match.group("rest").split("#")[0].split(";")[0].strip()
        found[normalize(match.group("name"))] = (match.group("op"), value, line)
    return found


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

        installed = {sibling: install_requirements(read[sibling]) for sibling in siblings}
        directory = str(Path(constraints).parent)
        runtime = f"{directory}/{RUNTIME_LOCK}" if directory != "." else RUNTIME_LOCK
        authoritative = runtime if runtime in installed else None

        # Exactness and completeness, judged from the install sources themselves
        # rather than from the constraints file, so a package the record has
        # never heard of is still examined.
        for sibling, requirements in sorted(installed.items()):
            for name, (operator, value, line) in sorted(requirements.items()):
                if not name.startswith("sm-"):
                    continue
                if operator != "==":
                    kind = "a direct reference" if operator == "@" else f"a {operator!r} range"
                    problems.append(
                        f"{sibling}: {name} is {kind} ({line!r}), not an exact pin — the "
                        f"constraints file being exact buys nothing if the install is not"
                    )
                elif not re.fullmatch(r"\d+\.\d+\.\d+", value):
                    problems.append(
                        f"{sibling}: {name}=={value} is not a plain release version ({line!r})"
                    )
                if name not in pins:
                    problems.append(
                        f"{sibling}: pins {name}, which {constraints} does not mention — a "
                        f"locked sm-* package with no constraints entry is never examined"
                    )

        for name, version in sorted(pins.items()):
            seen_in: list[str] = []
            for sibling, requirements in sorted(installed.items()):
                requirement = requirements.get(name)
                if requirement is None:
                    continue
                operator, value, _ = requirement
                seen_in.append(sibling)
                if operator == "==" and value != version:
                    problems.append(
                        f"{sibling}: pins {name}=={value}, but {constraints} says "
                        f"{version} — the install source wins, so one of them is a lie"
                    )
            if authoritative is not None:
                if authoritative not in seen_in:
                    problems.append(
                        f"{authoritative}: does not install {name}, which {constraints} pins at "
                        f"{version} — that lock is what the image and CI install, so a match in "
                        f"another sibling does not make the package present"
                    )
            elif not seen_in:
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
            "MUST NOT match: a package whose name merely starts the same is a DIFFERENT "
            "distribution, not a disagreement about sm-arp",
            {
                "pkg/constraints.txt": "sm-arp==0.3.2\nsm-arp-extras==9.9.9\n",
                "pkg/requirements.lock": "sm-arp==0.3.2\nsm-arp-extras==9.9.9\n",
            },
            ["pkg/constraints.txt", "pkg/requirements.lock"],
            False,
        ),
        # ── the rules review added ──────────────────────────────────────────
        (
            "exactness: a RANGE for an sm-* package in the lock, while another sibling "
            "holds the matching exact pin — the shape that passed before",
            {
                "pkg/constraints.txt": "sm-bridge==0.10.0\n",
                "pkg/requirements.lock": "sm-bridge>=0.4.1\n",
                "pkg/requirements.txt": "sm-bridge==0.10.0\n",
            },
            ["pkg/constraints.txt", "pkg/requirements.lock", "pkg/requirements.txt"],
            True,
        ),
        (
            "exactness: a direct artifact reference is a supply-chain decision, not a pin",
            {
                "pkg/constraints.txt": "sm-bridge==0.10.0\n",
                "pkg/requirements.lock": "sm-bridge @ https://example.invalid/sm_bridge.whl\n",
            },
            ["pkg/constraints.txt", "pkg/requirements.lock"],
            True,
        ),
        (
            "completeness: an sm-* package locked with no constraints entry is never examined",
            {
                "pkg/constraints.txt": "sm-bridge==0.10.0\n",
                "pkg/requirements.lock": "sm-bridge==0.10.0\nsm-newcomer==1.0.0\n",
            },
            ["pkg/constraints.txt", "pkg/requirements.lock"],
            True,
        ),
        (
            "presence: a non-runtime sibling must not mask absence from requirements.lock",
            {
                "pkg/constraints.txt": "sm-bridge==0.10.0\n",
                "pkg/requirements.lock": "httpx==0.27.0\n",
                "pkg/requirements.txt": "sm-bridge==0.10.0\n",
            },
            ["pkg/constraints.txt", "pkg/requirements.lock", "pkg/requirements.txt"],
            True,
        ),
        (
            "MUST NOT match: PEP 503 — sm_bridge, SM-Bridge and sm-bridge are one distribution",
            {
                "pkg/constraints.txt": "sm-bridge==0.10.0\n",
                "pkg/requirements.lock": "SM_Bridge==0.10.0\n",
            },
            ["pkg/constraints.txt", "pkg/requirements.lock"],
            False,
        ),
        (
            "MUST NOT match: an extras-qualified exact pin is still an exact pin",
            {
                "pkg/constraints.txt": "sm-bridge==0.10.0\n",
                "pkg/requirements.lock": "sm-bridge[feed]==0.10.0\n",
            },
            ["pkg/constraints.txt", "pkg/requirements.lock"],
            False,
        ),
        (
            "agreement: an extras-qualified pin at the WRONG version is still caught",
            {
                "pkg/constraints.txt": "sm-bridge==0.10.0\n",
                "pkg/requirements.lock": "sm-bridge[feed]==0.6.0\n",
            },
            ["pkg/constraints.txt", "pkg/requirements.lock"],
            True,
        ),
        (
            "MUST NOT match: an environment marker on an ordinary pin is not a version",
            {
                "pkg/constraints.txt": "sm-bridge==0.10.0\n",
                "pkg/requirements.lock": 'sm-bridge==0.10.0 ; python_version >= "3.11"\n',
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
    print(f"OK: self-test — {len(cases)} cases, every rule detects and the tolerated shapes stay quiet")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="prove every rule still detects, then exit",
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
