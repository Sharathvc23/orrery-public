"""The member-catalog flag must be documented with what the Index cannot see without it.

An org with the flag off is discoverable on the NANDA Index as ONE agent, not as
its roster. That is correct — the member list was closed to anonymous callers on
purpose, and the Index's fan-out is anonymous — but it is invisible to the
operator: nothing is set, nothing errors, nothing logs, and the members are
simply never candidates. Before this guard the variable appeared in no row of
``docs/CONFIGURATION.md`` at all, which is the shape of the host39 publication
step that got skipped on one of three orgs (``test_host39_publication_is_documented``).

The variable name is DERIVED from the code — the ``*_ENV`` constant the gate
reads — so a rename cannot leave the docs describing a variable nothing reads.

Stdlib only: ``doc-guards`` installs nothing but pytest.
"""

from __future__ import annotations

import re
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_GATE_SOURCE = _ROOT / "server" / "routes" / "identity.py"
_CONFIGURATION = _ROOT / "docs" / "CONFIGURATION.md"
_SECTION = "### What the Index can see of this org"


def _gate_variable() -> str:
    match = re.search(
        r'^ORG_PUBLIC_MEMBER_CATALOG_ENV\s*=\s*"([A-Z0-9_]+)"',
        _GATE_SOURCE.read_text(encoding="utf-8"),
        re.M,
    )
    assert match, (
        f"no ORG_PUBLIC_MEMBER_CATALOG_ENV constant in {_GATE_SOURCE.relative_to(_ROOT)} — "
        f"the derivation broke, not the property. If the constant moved, follow it here."
    )
    return match.group(1)


def _section(text: str) -> str:
    start = text.find(_SECTION)
    assert start >= 0, f"{_CONFIGURATION.name} has no {_SECTION!r} section"
    end = text.find("\n## ", start)
    return text[start : end if end >= 0 else len(text)]


def test_the_gate_variable_has_a_configuration_row():
    var = _gate_variable()
    rows = [
        line
        for line in _CONFIGURATION.read_text(encoding="utf-8").splitlines()
        if line.startswith(f"| `{var}` |")
    ]
    assert rows, (
        f"{var} gates what the NANDA Index can see and has no row in docs/CONFIGURATION.md"
    )
    assert "ONE agent" in rows[0], (
        f"the {var} row must say what the Index sees with it off"
    )
    assert "NOT sufficient" in rows[0], (
        f"the {var} row must say that setting it is not the whole job"
    )


def test_the_section_gives_a_runnable_check_against_the_live_index():
    section = _section(_CONFIGURATION.read_text(encoding="utf-8"))
    for needle in (
        _gate_variable(),
        "https://api.nandaindex.org/api/v1/agentic-search",
        "orgsUnreachable",
        "/agents/search",
        "/.well-known/ai-catalog.json",
        "withheldMembers",
        ":catalog:root",
    ):
        assert needle in section, f"{_SECTION!r} no longer mentions {needle!r}"
