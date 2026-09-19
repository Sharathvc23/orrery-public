"""Drift guard: member-sdk's vendored ``_arp_verify`` MUST stay in lockstep
with the repo's canonical ``conformance/arp``.

The member SDK ships as a pip package and cannot import ``conformance/`` at
runtime, so it vendors a verbatim copy of the canonical strict verifier (see
``community_member/_arp_verify/__init__.py``). The repo's anti-drift law
(CLAUDE.md operating principle #2) says a vendored copy must never silently
diverge from its canonical source — otherwise the member could verify a
receipt the chapter would reject, or vice versa.

This test enforces that: the two files must be byte-identical EXCEPT for the
module docstring and the single ``SCHEMA_ROOT = ...`` line (which intentionally
differs — the member points at packaged ``./schemas/`` with per-version subdirs,
the canonical points at the repo ``schema/arp/``). The vendored receipt schemas
for EVERY supported version must also match the canonical schema set.

When the member SDK is installed standalone (no ``conformance/`` checkout alongside),
the canonical files are absent and the tests skip — full-checkout-only guards.
"""

from __future__ import annotations

from pathlib import Path

import pytest

_VENDORED = Path(__file__).resolve().parent.parent / "community_member" / "_arp_verify" / "__init__.py"
_CANONICAL = Path(__file__).resolve().parents[2] / "conformance" / "arp" / "__init__.py"

_ANCHOR = "from __future__ import annotations"


def _code_body(text: str) -> str:
    """Everything from the first real import onward, with the SCHEMA_ROOT line
    removed. This drops the (intentionally different) module docstring and the
    (intentionally different) SCHEMA_ROOT assignment, leaving the imports plus
    all verification logic — which MUST be identical across the two copies."""
    lines = text.splitlines()
    start = next(i for i, line in enumerate(lines) if line.strip() == _ANCHOR)
    kept = [line for line in lines[start:] if not line.startswith("SCHEMA_ROOT =")]
    return "\n".join(kept)


@pytest.mark.skipif(not _CANONICAL.exists(), reason="canonical conformance/arp not present (standalone install)")
def test_vendored_arp_verify_matches_canonical_byte_for_byte() -> None:
    vendored = _code_body(_VENDORED.read_text())
    canonical = _code_body(_CANONICAL.read_text())
    assert vendored == canonical, (
        "agent/community_member/_arp_verify/__init__.py has drifted from "
        "conformance/arp/__init__.py. Re-sync the vendored copy (only the "
        "docstring and SCHEMA_ROOT line may differ)."
    )


@pytest.mark.skipif(not _CANONICAL.exists(), reason="canonical conformance/arp not present (standalone install)")
def test_vendored_schema_root_is_local_package_data() -> None:
    """The vendored copy MUST resolve schemas from its own packaged ./schemas/,
    not from the repo layout — that's the whole point of vendoring."""
    text = _VENDORED.read_text()
    schema_line = next(line for line in text.splitlines() if line.startswith("SCHEMA_ROOT ="))
    assert '"schemas"' in schema_line and "parent.parent" not in schema_line


_VENDORED_SCHEMA_ROOT = _VENDORED.parent / "schemas"
_CANONICAL_SCHEMA_ROOT = Path(__file__).resolve().parents[2] / "schema" / "arp"
# Each (version, filename) the verifier actually loads. (conformance-envelope is a
# suite-only artifact, intentionally NOT vendored — see the vendoring header.)
_VENDORED_SCHEMA_FILES = sorted((p.parent.name, p.name) for p in _VENDORED_SCHEMA_ROOT.glob("*/*.schema.json"))


@pytest.mark.skipif(not _CANONICAL_SCHEMA_ROOT.exists(), reason="canonical schema/arp not present (standalone install)")
@pytest.mark.parametrize(("version", "name"), _VENDORED_SCHEMA_FILES)
def test_vendored_schema_matches_canonical(version: str, name: str) -> None:
    """Each vendored schema MUST be byte-identical to schema/arp/<version>/.

    The verifier's verdicts depend on these schemas. The member's copy is frozen
    in git and shipped in the wheel, so a drift here would make the member
    accept/reject receipts differently from the chapter, silently. Guard every
    supported version.

    This previously read "unlike the chapter (which refreshes its copy from
    source at Docker build)". That was FALSE: ``infra/Dockerfile.server`` copies
    ``server/`` wholesale and nothing re-derives the chapter's schemas, so its
    copy is frozen in git exactly like this one. The belief that it could not
    drift is the most likely reason it went unguarded — and it had in fact
    drifted (stale ``$id`` on all six 0.1 schemas). The chapter now has its own
    guard: ``server/tests/test_arp_verify_lockstep.py``.
    """
    vendored = (_VENDORED_SCHEMA_ROOT / version / name).read_bytes()
    canonical = (_CANONICAL_SCHEMA_ROOT / version / name).read_bytes()
    assert vendored == canonical, (
        f"{version}/{name} has drifted from schema/arp/{version}/{name}. Re-copy it "
        "into community_member/_arp_verify/schemas/ — the member verifier's schemas "
        "must match the canonical source exactly."
    )
