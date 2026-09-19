"""Drift guard: the chapter's in-tree ``dat.py`` MUST stay in lockstep with the
canonical ``conformance/dat``.

DAT verification was canonicalized into ``conformance/dat`` so the chapter and
the member SDK verify delegated authority identically. The chapter keeps its copy
in-tree (its Docker context already includes ``chapter/``), but that copy must
not drift from the canonical source. Bodies must match byte-for-byte; only the
module docstring may differ.
"""

from __future__ import annotations

from pathlib import Path

import pytest

_CHAPTER = Path(__file__).resolve().parent.parent / "dat.py"
_CANONICAL = Path(__file__).resolve().parents[2] / "conformance" / "dat" / "__init__.py"

_ANCHOR = "from __future__ import annotations"


def _code_body(text: str) -> str:
    lines = text.splitlines()
    start = next(i for i, line in enumerate(lines) if line.strip() == _ANCHOR)
    return "\n".join(lines[start:])


@pytest.mark.skipif(not _CANONICAL.exists(), reason="canonical conformance/dat not present")
def test_chapter_dat_matches_canonical_byte_for_byte() -> None:
    assert _code_body(_CHAPTER.read_text()) == _code_body(_CANONICAL.read_text()), (
        "chapter/dat.py has drifted from conformance/dat/__init__.py. "
        "Change DAT semantics in conformance/dat first, then re-sync both copies."
    )
