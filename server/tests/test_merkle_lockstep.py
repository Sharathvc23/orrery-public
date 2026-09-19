"""Drift guard: the chapter's in-tree ``merkle.py`` MUST stay in lockstep with the
canonical ``conformance/merkle``.

RFC 6962 Merkle verification was canonicalized into ``conformance/merkle`` so the
chapter and the member SDK verify inclusion/consistency proofs identically. The
chapter keeps its copy in-tree (Docker context includes ``chapter/``), but it must
not drift from the canonical source. Bodies must match byte-for-byte; only the
module docstring may differ.
"""

from __future__ import annotations

from pathlib import Path

import pytest

_CHAPTER = Path(__file__).resolve().parent.parent / "merkle.py"
_CANONICAL = Path(__file__).resolve().parents[2] / "conformance" / "merkle" / "__init__.py"

_ANCHOR = "from __future__ import annotations"


def _code_body(text: str) -> str:
    lines = text.splitlines()
    start = next(i for i, line in enumerate(lines) if line.strip() == _ANCHOR)
    return "\n".join(lines[start:])


@pytest.mark.skipif(not _CANONICAL.exists(), reason="canonical conformance/merkle not present")
def test_chapter_merkle_matches_canonical_byte_for_byte() -> None:
    assert _code_body(_CHAPTER.read_text()) == _code_body(_CANONICAL.read_text()), (
        "chapter/merkle.py has drifted from conformance/merkle/__init__.py. "
        "Change Merkle semantics in conformance/merkle first, then re-sync both copies."
    )
