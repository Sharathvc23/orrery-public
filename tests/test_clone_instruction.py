"""Every clone instruction names the public home.

The stranger drive found README's first command cloning a private repository
(`gh repo view` → isPrivate: true; unauthenticated fetch → 401), so a reader
failed at line one. The public home is `Sharathvc23/orrery-public`; this pins
every `git clone` in the reader-facing pages to it, and the `cd` that follows to
the directory that clone produces — the directory name is the Compose project
name, so a mismatch silently changes which volumes a re-run inherits.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PUBLIC_HOME = "https://github.com/Sharathvc23/orrery-public"
PAGES = ["README.md", "docs/INSTALL.md", "docs/MANUAL.md"]
CLONE = re.compile(r"^\s*git clone\s+(\S+)\s*$", re.M)


def _clone_lines(page: str) -> list[tuple[str, str]]:
    text = (ROOT / page).read_text(encoding="utf-8")
    out = []
    for m in CLONE.finditer(text):
        after = text[m.end() :].lstrip("\n").split("\n", 1)[0]
        out.append((m.group(1), after.strip()))
    return out


def test_the_pages_still_carry_a_clone_instruction():
    found = {page: _clone_lines(page) for page in PAGES}
    assert all(found.values()), f"a page lost its clone instruction: {found}"


def test_every_clone_names_the_public_home():
    for page in PAGES:
        for url, _ in _clone_lines(page):
            assert url == PUBLIC_HOME, (
                f"{page}: `git clone {url}` — the public home is {PUBLIC_HOME}"
            )


def test_the_cd_after_each_clone_matches_the_directory_the_clone_produces():
    for page in PAGES:
        for url, next_line in _clone_lines(page):
            expected = url.rstrip("/").rsplit("/", 1)[-1].removesuffix(".git")
            assert next_line == f"cd {expected}", (
                f"{page}: after `git clone {url}` comes `{next_line}`, not `cd {expected}`"
            )


def test_the_readme_says_what_the_public_home_holds_today():
    """The instruction must be true the day the repo is public AND not lie
    today: the page says the public home currently carries the project page
    and the tree is shared by invitation."""
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "shared by invitation" in text
    assert "directory named `orrery-public`" in text
