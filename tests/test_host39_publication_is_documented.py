"""Every script that writes host39 publication state must be findable in the docs.

A required operator step that exists only as a docstring inside its own script is
a step that gets skipped, because you read a script's docstring once you have
already decided to run it — and the whole failure is not knowing it is there.

Measured: `scripts/backfill_host39_publications.py` shipped with an excellent
docstring, a dry-run default and the full ordering trap written out, and
`grep -rln "backfill_host39" --include=*.md .` returned nothing. Two of three
deployed orgs got the step. The third did not, and its AI Catalog advertised one
entry while omitting 24 — no check went red, because the strict code was working
exactly as designed. `docs/CONFIGURATION.md` even documented
`ORG_HOST39_CARD_BASE` while describing a set base as "the host39 card path,
unchanged", which invited precisely the reading that setting it was the whole job.

The script set is DERIVED from the code — the scripts that call the recording
endpoint — and never listed here. A hand-list goes stale in the direction that
reports green: the next script to write publication state would land
undocumented and this guard would still pass. Same reasoning
`test_cve_scan_covers_every_lock` uses for lockfiles and
`test_every_canary_workflow_sets_the_flag` uses for the canaries.

Stdlib only: `doc-guards` installs nothing but pytest.
"""

from __future__ import annotations

from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_SCRIPTS = _ROOT / "scripts"

#: The endpoint that writes the record. A script that calls this is part of the
#: publication procedure, which is the thing that has to be documented.
_RECORDING_ENDPOINT = "record-publication"

_SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "changelog.d"}


def _publication_scripts() -> list[Path]:
    """Scripts that write host39 publication state — derived, never hand-listed."""
    found = [
        p
        for p in sorted(_SCRIPTS.glob("*.py"))
        if _RECORDING_ENDPOINT in p.read_text(encoding="utf-8")
    ]
    assert found, (
        f"no script references {_RECORDING_ENDPOINT!r} — the derivation broke, "
        f"not the property. If the endpoint was renamed, rename it here too."
    )
    return found


def _docs() -> list[Path]:
    """Every markdown file a reader could reach, excluding changelog fragments.

    Fragments are excluded deliberately: a fragment is consumed into CHANGELOG.md
    at release and then deleted, so a step documented only in one is documented
    only until the next release.
    """
    return [
        p
        for p in _ROOT.rglob("*.md")
        if not any(part in _SKIP_DIRS for part in p.relative_to(_ROOT).parts)
    ]


def test_every_publication_script_is_named_in_a_doc():
    docs = {p: p.read_text(encoding="utf-8") for p in _docs()}
    assert docs, "no documentation found — the derivation broke, not the property"

    for script in _publication_scripts():
        where = [p.relative_to(_ROOT).as_posix() for p, text in docs.items() if script.name in text]
        assert where, (
            f"{script.name} writes host39 publication state but is named in no "
            f"documentation, so an operator has no way to learn it must be run. "
            f"A docstring is reference material, not discovery."
        )


def test_the_ordering_trap_is_written_down_where_the_variable_is():
    """The snapshot-before-deploy requirement is the part that is unrecoverable.

    The backfill discovers members from the live catalog, which after the deploy
    has already omitted the ones it would have found, and `GET /api/members` is
    auth-gated — so an operator who learns this afterwards cannot rebuild the
    list from any open surface. It has to be readable BEFORE the deploy, next to
    the variable that triggers the behaviour.
    """
    text = (_ROOT / "docs" / "CONFIGURATION.md").read_text(encoding="utf-8")
    assert "--from-snapshot" in text, "the snapshot path is not documented"
    assert "ai-catalog.json > snap.json" in text, "the capture command is not shown"
    # The variable's own row must not read as though setting it is the whole job.
    assert "necessary but NOT sufficient" in text, (
        "ORG_HOST39_CARD_BASE must say that setting it does not publish anything"
    )
