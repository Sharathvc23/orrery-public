"""Drift guard: member-sdk's vendored ``_merkle`` MUST stay in lockstep with the
canonical ``conformance/merkle``.

Same rationale as the ARP/DAT verifier guards: the member ships as a pip package
and vendors a verbatim copy of the canonical RFC 6962 verifier. A silent drift
would let the member accept/reject inclusion proofs differently from the chapter.
Skips when run standalone (no ``conformance/`` checkout alongside).
"""

from __future__ import annotations

from pathlib import Path

import pytest

_VENDORED = Path(__file__).resolve().parent.parent / "community_member" / "_merkle" / "__init__.py"
_CANONICAL = Path(__file__).resolve().parents[2] / "conformance" / "merkle" / "__init__.py"

_ANCHOR = "from __future__ import annotations"


def _code_body(text: str) -> str:
    lines = text.splitlines()
    start = next(i for i, line in enumerate(lines) if line.strip() == _ANCHOR)
    return "\n".join(lines[start:])


@pytest.mark.skipif(not _CANONICAL.exists(), reason="canonical conformance/merkle not present (standalone install)")
def test_vendored_merkle_matches_canonical_byte_for_byte() -> None:
    assert _code_body(_VENDORED.read_text()) == _code_body(_CANONICAL.read_text()), (
        "community_member/_merkle/__init__.py has drifted from conformance/merkle/__init__.py. "
        "Re-vendor it (only the module docstring may differ)."
    )
