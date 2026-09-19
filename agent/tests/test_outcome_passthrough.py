"""Every outcome an action executor can produce survives the runner boundary.

`build_runners._result_to_output` converts an `ActionResult` into a
`ToolOutput`. It used to re-derive the outcome as `"ok" if ... else "fail"`,
so an action refused for want of a valid approval reached the caller as a
generic failure, indistinguishable from one that ran and errored.

The producible set is read out of `community_member/actions/`, so an outcome
added there later is covered without editing this file.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from community_member.consent.gate import ActionRequest
from community_member.executor import ToolOutput

ACTIONS_DIR = Path(__file__).resolve().parents[1] / "community_member" / "actions"

# The outcome the executor picks when it refuses. Named here because the whole
# point of the boundary change is that this value reaches the caller.
REFUSED = "denied"


def producible_outcomes() -> set[str]:
    """Every literal outcome an ActionResult is constructed with in actions/."""
    found: set[str] = set()
    for path in sorted(ACTIONS_DIR.glob("*.py")):
        for node in ast.walk(ast.parse(path.read_text())):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", "")
            if name not in ("ActionResult", "_deny", "_fail"):
                continue
            for kw in node.keywords:
                if kw.arg == "outcome" and isinstance(kw.value, ast.Constant):
                    found.add(kw.value.value)
    return found


@pytest.fixture
def result_to_output(tmp_path, monkeypatch):
    """The real `_result_to_output`, lifted out of the closure it lives in."""
    monkeypatch.setenv("COMMUNITY_MEMBER_HOME", str(tmp_path))
    from community_member.agent import LocalAgent
    from community_member.config import Config

    cfg = Config(home=tmp_path)
    cfg.agent_id = "outcome-guard"
    cfg.provider = ""
    cfg.api_key = ""
    agent = LocalAgent(cfg)

    # build_runners closes over _result_to_output; reach it through a runner's
    # own closure rather than re-implementing it here, so the test exercises
    # the shipped function.
    runner = agent.build_runners("local:outcome-guard")["net.http"]
    for cell in runner.__closure__ or ():
        candidate = cell.cell_contents
        if getattr(candidate, "__name__", "") == "_result_to_output":
            return candidate
    raise AssertionError("_result_to_output not found in the runner's closure")


class _Result:
    """Minimal stand-in with the ActionResult fields the boundary reads."""

    def __init__(self, outcome: str):
        self.outcome = outcome
        self.data = None
        self.extra = {}


def _req() -> ActionRequest:
    return ActionRequest(capability="net.http", scope="example.invalid", context="c", provenance="trusted")


def test_the_producible_set_is_not_empty():
    """Guards against the AST walk silently stopping to match actions/."""
    outcomes = producible_outcomes()
    assert outcomes, "found no ActionResult outcomes — the walk stopped matching"
    assert REFUSED in outcomes


def test_every_producible_outcome_survives_the_boundary(result_to_output):
    collapsed: list[str] = []
    for outcome in sorted(producible_outcomes()):
        got = result_to_output(_req(), _Result(outcome), source_ref=None)
        if got.outcome != outcome:
            collapsed.append(f"{outcome} -> {got.outcome}")
    assert not collapsed, f"outcomes rewritten at the runner boundary: {collapsed}"


def test_a_refusal_is_not_reported_as_a_failure(result_to_output):
    """The specific case: refused and errored must not arrive as the same word."""
    refused = result_to_output(_req(), _Result(REFUSED), source_ref=None)
    errored = result_to_output(_req(), _Result("fail"), source_ref=None)
    assert refused.outcome == REFUSED
    assert refused.outcome != errored.outcome


def test_the_boundary_agrees_with_the_sibling_refusal_path(tmp_path, monkeypatch):
    """`_denied_output` and `_result_to_output` describe the same refusal the
    same way. They diverged before: one said "denied", the other "fail"."""
    monkeypatch.setenv("COMMUNITY_MEMBER_HOME", str(tmp_path))
    from community_member.agent import LocalAgent
    from community_member.config import Config
    from community_member.consent import ledger

    ledger.init(tmp_path / "consent.db")
    cfg = Config(home=tmp_path)
    cfg.agent_id = "outcome-guard"
    cfg.provider = ""
    cfg.api_key = ""
    agent = LocalAgent(cfg)
    runner = agent.build_runners("local:outcome-guard")["net.http"]

    # No approval exists, so the runner takes the _denied_output path.
    out = runner(_req())
    assert out.outcome == REFUSED
    assert out.extra["reason"] == "no_valid_approval_at_runner"


def test_the_declared_vocabulary_covers_what_is_produced():
    """`ToolOutcome` must admit every outcome the boundary now passes through."""
    import typing

    from community_member import executor

    declared = set(typing.get_args(executor.ToolOutcome))
    missing = producible_outcomes() - declared
    assert not missing, f"actions/ produces outcomes ToolOutcome does not declare: {missing}"


def test_tooloutput_accepts_each_producible_outcome():
    for outcome in sorted(producible_outcomes()):
        assert ToolOutput(capability="net.http", scope="s", outcome=outcome).outcome == outcome
