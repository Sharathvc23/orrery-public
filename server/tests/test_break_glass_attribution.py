"""An oversight decision names who made it, or says it cannot.

The break-glass admin token authenticates a secret, not a person. A record that
names this org as the approver for a decision nobody here is accountable for
looks complete and is false — the failure an auditor cannot detect, because
nothing about the row suggests the name was invented.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

import governance
from chapter_agent import _approver_from, sanitize_agent_id

SERVER = Path(governance.__file__).resolve().parent


# ── Resolving the approver ────────────────────────────────────────────


def test_a_signed_caller_is_named():
    assert _approver_from({"path": "did_key", "agent_id": "alice"}) == "alice"


def test_the_break_glass_bearer_is_recorded_as_unattributed():
    """The bearer identity carries no agent_id at all."""
    assert _approver_from({"path": "bearer"}) == governance.BREAK_GLASS_APPROVER


def test_the_bearer_is_never_recorded_as_this_org():
    """The defect: the fallback wrote the org's own id, so the record read as
    though a named party at this org had approved."""
    from chapter_agent import AGENT_ID

    assert _approver_from({"path": "bearer"}) != AGENT_ID
    assert _approver_from({}) != AGENT_ID


def test_an_empty_agent_id_does_not_become_a_name():
    for identity in ({"agent_id": ""}, {"agent_id": "   "}, {"agent_id": None}):
        assert _approver_from(identity) == governance.BREAK_GLASS_APPROVER


# ── The sentinel cannot be impersonated ───────────────────────────────


def test_no_member_id_can_equal_the_sentinel():
    """`sanitize_agent_id` strips every character outside a-zA-Z0-9-_@. — so a
    colon cannot survive it, and no member can register a name that collides."""
    assert ":" in governance.BREAK_GLASS_APPROVER
    assert ":" not in sanitize_agent_id(governance.BREAK_GLASS_APPROVER)
    for attempt in ("break-glass:unattributed", "BREAK-GLASS:UNATTRIBUTED", "break-glass%3Aunattributed"):
        assert sanitize_agent_id(attempt) != governance.BREAK_GLASS_APPROVER


def test_the_sentinel_is_recognisable_by_a_helper_not_a_literal():
    """Callers ask, rather than each comparing their own copy of the string."""
    assert governance.is_break_glass(governance.BREAK_GLASS_APPROVER)
    assert not governance.is_break_glass("alice")
    assert not governance.is_break_glass("")


# ── It follows into the receipt ───────────────────────────────────────


def test_the_receipt_does_not_look_up_a_did_for_the_break_glass_path():
    """Asking for a DID would either miss or return this org's — the same
    false attribution one artefact further on."""
    src = (SERVER / "governance.py").read_text()
    emitter = src[src.index("def _emit_approval_receipt") :]
    emitter = emitter[: emitter.index("\nasync def ") if "\nasync def " in emitter else len(emitter)]
    assert "is_break_glass(approver_agent_id)" in emitter
    assert "None if break_glass else" in emitter


def test_the_receipt_summary_does_not_name_a_person_for_break_glass():
    src = (SERVER / "governance.py").read_text()
    assert "approver_label" in src
    assert '"the break-glass token"' in src


# ── The fallback cannot come back ─────────────────────────────────────


def _approver_assignments(source: str) -> list[str]:
    """Every line that decides who to record as an approver."""
    return [line.strip() for line in source.splitlines() if re.search(r"^\s*(approver|approver_agent_id)\s*=", line)]


def test_no_approver_is_resolved_by_falling_back_to_the_org_id():
    """Derived: any assignment to an approver that reaches for AGENT_ID is the
    defect returning, whatever else changes around it."""
    src = (SERVER / "chapter_agent.py").read_text()
    offenders = [line for line in _approver_assignments(src) if "AGENT_ID" in line]
    assert not offenders, f"approver resolved from the org's own id: {offenders}"


def test_every_approver_assignment_goes_through_the_resolver():
    src = (SERVER / "chapter_agent.py").read_text()
    assignments = _approver_assignments(src)
    assert assignments, "found no approver assignment — the scan stopped matching"
    stray = [line for line in assignments if "_approver_from(" not in line]
    assert not stray, f"approver assigned without the resolver: {stray}"


def test_the_resolver_is_the_only_place_the_sentinel_is_chosen():
    """One decision point, so the two endpoints cannot diverge."""
    src = (SERVER / "chapter_agent.py").read_text()
    tree = ast.parse(src)
    users = {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and "BREAK_GLASS_APPROVER" in ast.dump(node)
    }
    assert users == {"_approver_from"}, users


@pytest.mark.parametrize("endpoint", ["approve_approval", "reject_approval"])
def test_both_decision_endpoints_use_the_resolver(endpoint):
    src = (SERVER / "chapter_agent.py").read_text()
    tree = ast.parse(src)
    fn = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef) and n.name == endpoint)
    assert "_approver_from" in ast.dump(fn), f"{endpoint} does not use the approver resolver"
