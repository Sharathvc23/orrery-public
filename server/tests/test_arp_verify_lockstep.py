"""Drift guard: the chapter's vendored ``_arp_verify`` MUST stay in lockstep
with the repo's canonical ``conformance/arp``.

Twin of ``agent/tests/test_arp_verify_lockstep.py``. That guard has existed for
the member SDK's copy since it was vendored; the chapter's copy had none, and
the asymmetry is the whole reason this file exists. One copy held to canonical
and one not is exactly how the member and the chapter come to disagree about
whether a receipt verifies — the failure the anti-drift law (CLAUDE.md operating
principle #2) exists to prevent, available on the unguarded side.

It was not hypothetical. When this guard was written the chapter's six
``schemas/0.1/*.schema.json`` had ALREADY drifted from canonical: every one
carried a stale ``$id`` of ``https://arp.dev/schemas/0.1/...`` where canonical
says ``https://stellarminds.ai/schemas/sm-arp/0.1/...``. The agent's copy was
clean, so the drift was chapter-side only and its own guard was working.

That particular drift happened to be semantically inert — measured, not assumed:
every ``$ref`` in these schemas is a RELATIVE filename, and ``_load_registry``
registers each schema under both its ``$id`` and its bare filename, so each
schema set resolves within itself and the two sets returned identical verdicts
(``ok``, ``stage`` and ``detail``) across a corpus including an accepted receipt
that traverses ``action.schema.json`` -> ``common.schema.json``. The next drift
carries no such guarantee, which is the point of guarding rather than
reconciling once.

Why the chapter's copy cannot simply import the canonical one: the server image
is built with ``server/`` as the Docker context, so ``conformance/`` never ships
with the runtime. Note also that nothing refreshes this copy at build time —
``infra/Dockerfile.server`` copies ``server/`` wholesale — so whatever is in git
is what the deployed chapters verify against.
"""

from __future__ import annotations

from pathlib import Path

import pytest

_VENDORED = Path(__file__).resolve().parent.parent / "_arp_verify" / "__init__.py"
_CANONICAL = Path(__file__).resolve().parents[2] / "conformance" / "arp" / "__init__.py"

_ANCHOR = "from __future__ import annotations"


def _code_body(text: str) -> str:
    """Everything from the first real import onward, with the SCHEMA_ROOT line
    removed — dropping the (intentionally different) module docstring and the
    (intentionally different) SCHEMA_ROOT assignment, leaving the imports plus
    all verification logic, which MUST be identical across the two copies.

    The chapter's SCHEMA_ROOT points at its own packaged ``./schemas/`` for the
    same reason the member's does: the canonical value resolves to the repo's
    ``schema/arp/``, which is not in the image.
    """
    lines = text.splitlines()
    start = next(i for i, line in enumerate(lines) if line.strip() == _ANCHOR)
    kept = [line for line in lines[start:] if not line.startswith("SCHEMA_ROOT =")]
    return "\n".join(kept)


@pytest.mark.skipif(not _CANONICAL.exists(), reason="canonical conformance/arp not present")
def test_vendored_arp_verify_matches_canonical_byte_for_byte() -> None:
    vendored = _code_body(_VENDORED.read_text())
    canonical = _code_body(_CANONICAL.read_text())
    assert vendored == canonical, (
        "server/_arp_verify/__init__.py has drifted from conformance/arp/__init__.py. "
        "Re-sync the vendored copy (only the docstring and SCHEMA_ROOT line may differ)."
    )


@pytest.mark.skipif(not _CANONICAL.exists(), reason="canonical conformance/arp not present")
def test_vendored_schema_root_is_local_package_data() -> None:
    """The vendored copy MUST resolve schemas from its own packaged ./schemas/,
    not from the repo layout — ``conformance/`` and ``schema/`` are outside the
    Docker context, so the canonical value would raise at runtime."""
    text = _VENDORED.read_text()
    schema_line = next(line for line in text.splitlines() if line.startswith("SCHEMA_ROOT ="))
    assert '"schemas"' in schema_line and "parent.parent" not in schema_line


_VENDORED_SCHEMA_ROOT = _VENDORED.parent / "schemas"
_CANONICAL_SCHEMA_ROOT = Path(__file__).resolve().parents[2] / "schema" / "arp"
_VENDORED_SCHEMA_FILES = sorted((p.parent.name, p.name) for p in _VENDORED_SCHEMA_ROOT.glob("*/*.schema.json"))


@pytest.mark.skipif(not _CANONICAL_SCHEMA_ROOT.exists(), reason="canonical schema/arp not present")
@pytest.mark.parametrize(("version", "name"), _VENDORED_SCHEMA_FILES)
def test_vendored_schema_matches_canonical(version: str, name: str) -> None:
    """Each vendored schema MUST be byte-identical to schema/arp/<version>/.

    This is the assertion that was missing. The chapter's schemas are frozen in
    git and copied into the image as-is, so a drift here changes what the
    DEPLOYED chapters accept — silently, and asymmetrically against a member SDK
    whose own copy is guarded.
    """
    vendored = (_VENDORED_SCHEMA_ROOT / version / name).read_bytes()
    canonical = (_CANONICAL_SCHEMA_ROOT / version / name).read_bytes()
    assert vendored == canonical, (
        f"{version}/{name} has drifted from schema/arp/{version}/{name}. Re-copy it into "
        "server/_arp_verify/schemas/ — the chapter verifier's schemas must match canonical exactly."
    )


@pytest.mark.skipif(not _CANONICAL_SCHEMA_ROOT.exists(), reason="canonical schema/arp not present")
def test_every_canonical_version_is_vendored() -> None:
    """A version present canonically but missing from the vendored set would make
    the chapter reject receipts the member accepts, and a per-file parametrize
    over the VENDORED set alone cannot see that — it would simply not run.
    """
    canonical_versions = {p.name for p in _CANONICAL_SCHEMA_ROOT.iterdir() if p.is_dir()}
    vendored_versions = {p.name for p in _VENDORED_SCHEMA_ROOT.iterdir() if p.is_dir()}
    assert canonical_versions <= vendored_versions, (
        f"canonical schema/arp has version(s) {sorted(canonical_versions - vendored_versions)} "
        "that the chapter does not vendor"
    )
