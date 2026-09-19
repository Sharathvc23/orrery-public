"""The host keeps every business's identity separate, and stays out of the
process-global state that would merge them.

WHY THIS FILE EXISTS. Each business on this host has its own home, vault,
identity and card, and that separation is real. It is real because every store
is reached through the tenant's own home — and it stops being real the moment a
code path reads identity from somewhere that is shared by the whole process
instead.

That is not hypothetical. Two shipped defects had exactly this shape: a registry
of installed skills that was process-global while the files were per-tenant, so
removing one business's entry removed another's; and a client that read its
signing key from process state rather than the tenant's home, so it could sign
as the wrong business. Both were invisible with one business and wrong with two.

So the guard below is DERIVED rather than a list of the modules known to be
risky today. It scans the SDK for modules that keep identity or signing state at
module level, and fails if the host reaches any of them. A module added later
with the same shape is caught without anyone remembering to add it here.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

SDK = Path(__file__).resolve().parents[1] / "agent" / "community_member"
HOST = Path(__file__).resolve().parent / "main.py"

#: Names whose module-level mutation makes one process share one identity.
#: Matched against `global <name>` declarations, which is how a module says
#: outright that the value is not per-caller.
_IDENTITY_STATE = re.compile(r"\bglobal\s+([A-Za-z_][\w, ]*)")
_IDENTITY_WORDS = ("private_key", "public_key", "did_key", "sig_scheme", "keystore_dir")


def _modules_with_process_global_identity() -> dict[str, list[str]]:
    """SDK modules that keep identity or signing state at module level."""
    found: dict[str, list[str]] = {}
    for path in sorted(SDK.glob("*.py")):
        source = path.read_text()
        names: list[str] = []
        for match in _IDENTITY_STATE.finditer(source):
            for raw in match.group(1).split(","):
                name = raw.strip().lower().lstrip("_")
                if any(word in name for word in _IDENTITY_WORDS):
                    names.append(raw.strip())
        if names:
            found[path.stem] = sorted(set(names))
    return found


def _imported_modules(source: str) -> set[str]:
    """Every module name the host imports, at any depth of the file."""
    names: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.update(alias.name.split("."))
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                names.update(node.module.split("."))
            for alias in node.names:
                names.add(alias.name)
    return names


def test_the_scan_finds_the_shared_state_it_is_looking_for():
    """A detector that finds nothing would pass every test below while checking
    nothing. It must locate the known case before its silence means anything."""
    found = _modules_with_process_global_identity()
    assert "auth" in found, (
        "the scan no longer finds the module that keeps one signing identity per "
        f"process — it has gone blind rather than clean (found: {sorted(found)})"
    )


def test_the_host_reaches_no_process_global_identity():
    """One process serves every business here, so a signing identity held at
    module level is one identity for all of them: whichever business wrote it
    last is the one the signature names."""
    hazards = _modules_with_process_global_identity()
    imported = _imported_modules(HOST.read_text())
    reached = sorted(set(hazards) & imported)
    assert not reached, (
        f"the host reaches {reached}, which keep identity at module level. "
        "Each business must be signed for with the key in its own home."
    )


@pytest.mark.parametrize(
    "call, why",
    [
        (
            "init_keys",
            "loads one signing identity for the whole process, so the last business to load one signs for all of them",
        ),
        (
            "activate_consent",
            "points a single process-wide consent record at one business, so a second "
            "business's decisions would be recorded against the first",
        ),
    ],
)
def test_the_host_never_makes_the_call_that_merges_two_businesses(call, why):
    """Both are safe today because nothing calls them. That is a fact about the
    current code, not a boundary, so it is asserted rather than assumed."""
    source = "\n".join(line.split("#")[0] for line in HOST.read_text().splitlines())
    assert f"{call}(" not in source, f"the host calls {call}(), which {why}"


def test_each_business_is_reached_only_through_its_own_home():
    """The positive half. Every store belongs to one business because it is
    opened relative to that business's home, never a shared root."""
    source = HOST.read_text()
    assert "AgentContext.load(home)" in source or "AgentContext.load(" in source, (
        "the host no longer opens each business through its own context"
    )
    assert "state.data_dir / tenant_id" in source, "a business's home is no longer derived from its own id"
