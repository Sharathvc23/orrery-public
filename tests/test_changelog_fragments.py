"""The changelog is assembled from fragments; [Unreleased] is not hand-edited.

Every pull request used to prepend its entry at the same spot in CHANGELOG.md,
so any two open PRs conflicted there, and resolving those conflicts by merging
main into a branch is how one squash reverted four merged PRs in a day. A
change now records itself as ``changelog.d/<slug>.md`` — a file only it
touches — and ``scripts/changelog_assemble.py --release`` writes the release
section. This guard fails, naming the entry, if anything is written under
``## [Unreleased]`` by hand, and fails, naming the file, for a malformed
fragment.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))

import changelog_assemble as ca  # noqa: E402


def test_fragments_are_well_formed_and_unreleased_is_not_hand_edited():
    problems = ca.check()
    assert not problems, "\n".join(problems)


def test_the_checker_catches_what_it_exists_to_catch():
    """The script's own self-test, run as a subprocess the way CI would."""
    r = subprocess.run(
        [sys.executable, "scripts/changelog_assemble.py", "--self-test"],
        cwd=REPO,
        capture_output=True,
        text=True,
    )
    assert r.returncode == 0, r.stdout + r.stderr


def test_there_is_at_least_one_fragment_or_the_pointer_is_honest():
    """A pointer that says 'fragments live here' over an empty directory is
    fine right after a release; a checked-in [Unreleased] entry never is."""
    text = ca.CHANGELOG.read_text(encoding="utf-8")
    assert ca.POINTER in text
    _, body, _ = ca._split_unreleased(text)
    assert "### " not in body
