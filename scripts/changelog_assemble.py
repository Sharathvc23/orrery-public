#!/usr/bin/env python3
"""Changelog fragments: one file per change, assembled into CHANGELOG.md at release time.

WHY THIS EXISTS

Every pull request used to prepend its entry at the same spot under
``## [Unreleased]`` in ``CHANGELOG.md``, so any two open PRs conflicted there, and
resolving those conflicts by merging ``main`` into a branch is how one squash
reverted four merged PRs in a single day. A change now records itself as
``changelog.d/<slug>.md`` — a file only it touches — and this script writes the
release section when a version is cut.

THE CONTRACT

* A fragment is a Markdown file whose first line is a ``### `` heading and whose
  body is non-empty. It reads exactly as the entry will read in CHANGELOG.md.
* ``## [Unreleased]`` in CHANGELOG.md holds only the pointer line below. It is
  not hand-edited while fragments are the mechanism; ``--check`` enforces that,
  so a merge cannot reintroduce the shared conflict spot.
* ``--release X.Y.Z`` assembles the fragments — newest first, by the commit that
  first added each file, then by filename — into a new ``## [X.Y.Z] - date``
  section directly under the pointer, and deletes them.
* ``--preview`` prints what ``--release`` would insert.

No dependency: a towncrier-shaped workflow in one file.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
CHANGELOG = REPO / "CHANGELOG.md"
FRAGMENTS = REPO / "changelog.d"
UNRELEASED = "## [Unreleased]"
POINTER = (
    "Unreleased changes are recorded as fragments under `changelog.d/` — one file per change, "
    "so pull requests do not conflict here. `python3 scripts/changelog_assemble.py --preview` "
    "renders them; `--release <version>` writes the release section."
)


class FragmentError(Exception):
    pass


def fragment_files() -> list[Path]:
    if not FRAGMENTS.is_dir():
        return []
    return sorted(
        p
        for p in FRAGMENTS.iterdir()
        if p.suffix == ".md" and not p.name.startswith(".")
    )


def validate_fragment(path: Path) -> str:
    """Return the fragment's heading, or raise naming what is wrong."""
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()
    if not lines or not lines[0].startswith("### "):
        raise FragmentError(
            f"{path.relative_to(REPO)}: first line must be a '### ' heading"
        )
    if len(lines[0]) <= 4:
        raise FragmentError(f"{path.relative_to(REPO)}: empty heading")
    if not any(ln.strip() for ln in lines[1:]):
        raise FragmentError(f"{path.relative_to(REPO)}: a heading with no body")
    if sum(1 for ln in lines if ln.startswith("## ")) > 0:
        raise FragmentError(
            f"{path.relative_to(REPO)}: a fragment holds one '### ' entry, never a '## ' release heading"
        )
    return lines[0]


def _first_commit_epoch(path: Path) -> int:
    """When the fragment was first committed; 0 for a file not yet committed."""
    try:
        out = subprocess.run(
            [
                "git",
                "log",
                "--diff-filter=A",
                "--follow",
                "--format=%ct",
                "--",
                str(path.relative_to(REPO)),
            ],
            cwd=REPO,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.split()
    except (subprocess.CalledProcessError, OSError):
        return 0
    return int(out[-1]) if out else 0


def ordered_fragments() -> list[Path]:
    """Newest first: an uncommitted fragment (epoch 0 → sorted as newest), then
    by first-commit time descending, then filename ascending so a converted set
    with a numeric prefix keeps its order."""
    files = fragment_files()
    keyed = []
    for p in files:
        epoch = _first_commit_epoch(p)
        keyed.append((0 if epoch == 0 else 1, -epoch, p.name, p))
    return [p for _, _, _, p in sorted(keyed)]


def assemble() -> str:
    parts = []
    for p in ordered_fragments():
        validate_fragment(p)
        parts.append(p.read_text(encoding="utf-8").rstrip("\n") + "\n")
    return "\n".join(parts)


def _split_unreleased(text: str) -> tuple[str, str, str]:
    """(before, unreleased-body, after) around the [Unreleased] section."""
    i = text.index(UNRELEASED)
    body_start = i + len(UNRELEASED)
    m = re.search(r"\n## \[", text[body_start:])
    body_end = body_start + m.start() + 1 if m else len(text)
    return text[:body_start], text[body_start:body_end], text[body_end:]


def check() -> list[str]:
    """Every fragment well-formed, and [Unreleased] hand-edit free."""
    problems: list[str] = []
    for p in fragment_files():
        try:
            validate_fragment(p)
        except FragmentError as e:
            problems.append(str(e))
    text = CHANGELOG.read_text(encoding="utf-8")
    if UNRELEASED not in text:
        return problems + [f"{CHANGELOG.name}: no '{UNRELEASED}' section"]
    _, body, _ = _split_unreleased(text)
    expected = "\n\n" + POINTER + "\n\n"
    if body != expected:
        stray = [ln for ln in body.splitlines() if ln.startswith("### ")]
        problems.append(
            f"{CHANGELOG.name}: the [Unreleased] section must hold only the pointer line — "
            + (
                f"it carries hand-written entries: {', '.join(stray)}"
                if stray
                else "its text differs from the pointer"
            )
            + ". Record the change as changelog.d/<slug>.md instead."
        )
    return problems


def release(version: str, date: str | None) -> str:
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise SystemExit(f"version must be X.Y.Z, got {version!r}")
    problems = check()
    if problems:
        raise SystemExit(
            "refusing to release with a broken changelog state:\n  "
            + "\n  ".join(problems)
        )
    frags = ordered_fragments()
    if not frags:
        raise SystemExit("no fragments under changelog.d/ — nothing to release")
    section = (
        f"## [{version}] - {date or _dt.date.today().isoformat()}\n\n" + assemble()
    )
    text = CHANGELOG.read_text(encoding="utf-8")
    before, body, after = _split_unreleased(text)
    CHANGELOG.write_text(before + body + section + "\n" + after, encoding="utf-8")
    for p in frags:
        p.unlink()
    return section


def self_test() -> None:
    """The checker must fail on the states it exists to catch."""
    import tempfile

    global CHANGELOG, FRAGMENTS, REPO
    saved = (CHANGELOG, FRAGMENTS, REPO)
    try:
        with tempfile.TemporaryDirectory() as d:
            REPO = Path(d)
            CHANGELOG = REPO / "CHANGELOG.md"
            FRAGMENTS = REPO / "changelog.d"
            FRAGMENTS.mkdir()
            good = (
                "# Changelog\n\n"
                + UNRELEASED
                + "\n\n"
                + POINTER
                + "\n\n## [0.3.0] - 2026-08-13\n\nold\n"
            )
            CHANGELOG.write_text(good)
            (FRAGMENTS / "a.md").write_text("### A change\n\nWhat it did.\n")
            assert check() == [], check()
            # 1. a hand-written entry under [Unreleased]
            CHANGELOG.write_text(
                good.replace(POINTER, POINTER + "\n\n### Sneaked in\n\ntext")
            )
            assert any("hand-written entries: ### Sneaked in" in p for p in check()), (
                check()
            )
            CHANGELOG.write_text(good)
            # 2. a fragment without a heading
            (FRAGMENTS / "b.md").write_text("no heading\n")
            assert any("first line must be a '### ' heading" in p for p in check()), (
                check()
            )
            (FRAGMENTS / "b.md").unlink()
            # 3. a fragment with a heading and no body
            (FRAGMENTS / "c.md").write_text("### Only a title\n")
            assert any("no body" in p for p in check()), check()
            (FRAGMENTS / "c.md").unlink()
            # 4. release assembles under [Unreleased], keeps the pointer, deletes fragments
            section = release("9.9.9", "2026-01-02")
            text = CHANGELOG.read_text()
            assert (
                "## [9.9.9] - 2026-01-02\n\n### A change" in text
                and POINTER in text
                and "## [0.3.0]" in text
            )
            assert (
                text.index(POINTER)
                < text.index("## [9.9.9]")
                < text.index("## [0.3.0]")
            )
            assert not list(FRAGMENTS.iterdir()) and "### A change" in section
            assert check() == []
    finally:
        CHANGELOG, FRAGMENTS, REPO = saved
    print("changelog_assemble self-test passed")


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument(
        "--check",
        action="store_true",
        help="fragments well-formed and [Unreleased] not hand-edited",
    )
    g.add_argument(
        "--preview", action="store_true", help="print the assembled unreleased entries"
    )
    g.add_argument(
        "--release",
        metavar="X.Y.Z",
        help="write the release section and delete the fragments",
    )
    g.add_argument("--self-test", action="store_true")
    ap.add_argument("--date", help="release date (default: today)")
    a = ap.parse_args(argv)
    if a.self_test:
        self_test()
        return 0
    if a.check:
        problems = check()
        for p in problems:
            print(f"::error::{p}")
        print(
            "changelog: "
            + (
                f"{len(problems)} problem(s)"
                if problems
                else f"{len(fragment_files())} fragment(s) well-formed, [Unreleased] clean"
            )
        )
        return 1 if problems else 0
    if a.preview:
        sys.stdout.write(assemble())
        return 0
    section = release(a.release, a.date)
    print(
        f"released {a.release}: {section.count(chr(10) + '### ')} entr(y/ies) written, fragments removed"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
