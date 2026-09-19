"""No tracked file points a reader at the private repository.

The tree was published from `Sharathvc23/orrery` (private) as
`Sharathvc23/orrery-public`. A URL to the private repository is a 404 for
every reader of the public one: the seven `Homepage` fields, the discussions
link, the schema `$id`s and a handful of audit links all carried it at
publication. This holds them at the public home. `changelog.d/` is exempt —
it is release history and may name where a change came from.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PRIVATE = re.compile(r"github\.com/Sharathvc23/orrery(?![A-Za-z0-9_-])")
EXEMPT_PREFIXES = ("changelog.d/",)
# This file carries the pattern's own examples.
EXEMPT_FILES = {"tests/test_public_home_urls.py"}


def _tracked_text_files() -> list[str]:
    out = subprocess.run(
        ["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True
    ).stdout
    return [
        f
        for f in out.decode().split("\0")
        if f and not f.startswith(EXEMPT_PREFIXES) and f not in EXEMPT_FILES
    ]


def _hits() -> list[str]:
    hits = []
    for rel in _tracked_text_files():
        path = ROOT / rel
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, IsADirectoryError, FileNotFoundError):
            continue
        for n, line in enumerate(text.splitlines(), 1):
            if PRIVATE.search(line):
                hits.append(f"{rel}:{n}: {line.strip()[:100]}")
    return hits


def test_the_pattern_matches_the_private_home_and_not_the_public_one():
    assert PRIVATE.search("https://github.com/Sharathvc23/orrery")
    assert PRIVATE.search("https://github.com/Sharathvc23/orrery/pull/556")
    assert PRIVATE.search("https://github.com/Sharathvc23/orrery.git")
    assert not PRIVATE.search("https://github.com/Sharathvc23/orrery-public")
    assert not PRIVATE.search(
        "https://github.com/Sharathvc23/orrery-public/discussions"
    )


def test_no_tracked_file_outside_changelog_d_names_the_private_repository():
    hits = _hits()
    assert not hits, (
        "references to the private repository (a 404 for every public reader):\n  "
        + "\n  ".join(hits)
    )


def test_every_pyproject_homepage_is_the_public_home():
    for rel in sorted(ROOT.glob("*/pyproject.toml")):
        text = rel.read_text(encoding="utf-8")
        m = re.search(r'^Homepage\s*=\s*"([^"]+)"', text, re.M)
        if m:
            assert m.group(1) == "https://github.com/Sharathvc23/orrery-public", (
                f"{rel.relative_to(ROOT)}: {m.group(1)}"
            )
