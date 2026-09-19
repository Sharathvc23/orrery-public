"""Drift guard: member-sdk's vendored ``_dat`` MUST stay in lockstep with the
canonical ``conformance/dat``.

Same rationale as the ARP verifier guard: the member ships as a pip package and
vendors a verbatim copy of the canonical DAT verifier. A silent divergence would
let the member accept/reject delegated authority differently from the chapter —
the exact drift this repo forbids. Skips when run standalone (no ``conformance/``).
"""

from __future__ import annotations

from pathlib import Path

import pytest

_VENDORED = Path(__file__).resolve().parent.parent / "community_member" / "_dat" / "__init__.py"
_CANONICAL = Path(__file__).resolve().parents[2] / "conformance" / "dat" / "__init__.py"

_ANCHOR = "from __future__ import annotations"


def _code_body(text: str) -> str:
    """Everything from the first real import onward — drops the (intentionally
    different) module docstring, leaving imports + all verification logic."""
    lines = text.splitlines()
    start = next(i for i, line in enumerate(lines) if line.strip() == _ANCHOR)
    return "\n".join(lines[start:])


@pytest.mark.skipif(not _CANONICAL.exists(), reason="canonical conformance/dat not present (standalone install)")
def test_vendored_dat_matches_canonical_byte_for_byte() -> None:
    assert _code_body(_VENDORED.read_text()) == _code_body(_CANONICAL.read_text()), (
        "community_member/_dat/__init__.py has drifted from conformance/dat/__init__.py. "
        "Re-vendor it (only the module docstring may differ)."
    )
