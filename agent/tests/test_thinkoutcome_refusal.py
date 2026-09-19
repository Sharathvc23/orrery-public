"""A refused action is never counted as approved.

The four buckets name what happened to an action. `ConsentDecision.state` names
what the gate decided. Those were the same fact until a bound could refuse after
the gate approved — the sandbox policy, or a runner re-checking the approval —
and a classifier keyed on the gate's decision then reports an action that did
not happen as approved.

The refusal set comes from `executor.REFUSED_OUTCOMES` and the producible set is
read out of `community_member/actions/`, so an outcome added later is covered
without editing this file.
"""

from __future__ import annotations

import ast
import itertools
from pathlib import Path

import pytest

from community_member.consent.gate import ActionRequest, ConsentDecision
from community_member.executor import REFUSED_OUTCOMES, ExecutionResult, ToolOutput
from community_member.planner import Plan
from community_member.runtime.think_loop import make_think_outcome

ACTIONS_DIR = Path(__file__).resolve().parents[1] / "community_member" / "actions"

_DECISION_STATES = ("approved", "prompt", "reject")


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


def _result(state: str, outcome: str | None, error: str | None = None) -> ExecutionResult:
    req = ActionRequest(capability="browser.navigate", scope="https://x.test", context="c", provenance="trusted")
    output = None if outcome is None else ToolOutput(capability=req.capability, scope=req.scope, outcome=outcome)
    return ExecutionResult(
        proposal=req,
        decision=ConsentDecision(state=state, reason="r"),
        output=output,
        error=error,
    )


def _buckets(outcome) -> dict[str, int]:
    return {
        "approved": len(outcome.approved),
        "pending_approval": len(outcome.pending_approval),
        "rejected": len(outcome.rejected),
        "errored": len(outcome.errored),
    }


# ── The defect ────────────────────────────────────────────────────────


def test_a_refusal_after_the_gate_approved_is_rejected_not_approved():
    """The case the sandbox policy produces: gate says yes, policy says no."""
    result = _result("approved", "denied")
    outcome = make_think_outcome(Plan(proposals=()), (result,))
    assert _buckets(outcome) == {"approved": 0, "pending_approval": 0, "rejected": 1, "errored": 0}


@pytest.mark.parametrize("refused", sorted(REFUSED_OUTCOMES))
@pytest.mark.parametrize("state", _DECISION_STATES)
def test_no_refusal_lands_in_approved_under_any_decision_state(refused, state):
    """Derived over the refusal set and every gate decision, so a refusing
    outcome added later is covered without editing this test."""
    outcome = make_think_outcome(Plan(proposals=()), (_result(state, refused),))
    assert not outcome.approved
    assert len(outcome.rejected) == 1


def test_a_successful_action_is_still_approved():
    """The fix must not sweep working actions into rejected."""
    outcome = make_think_outcome(Plan(proposals=()), (_result("approved", "ok"),))
    assert _buckets(outcome) == {"approved": 1, "pending_approval": 0, "rejected": 0, "errored": 0}


def test_an_action_that_ran_and_failed_is_not_a_refusal():
    """`fail` means it happened and went wrong — a different fact from refused."""
    outcome = make_think_outcome(Plan(proposals=()), (_result("approved", "fail"),))
    assert not outcome.rejected
    assert len(outcome.approved) == 1


def test_an_error_still_wins_over_the_outcome():
    """A runner that raised is errored, not rejected, even if it left an output."""
    outcome = make_think_outcome(Plan(proposals=()), (_result("approved", "denied", error="boom"),))
    assert _buckets(outcome) == {"approved": 0, "pending_approval": 0, "rejected": 0, "errored": 1}


# ── The partition invariant ───────────────────────────────────────────


def test_every_combination_lands_in_exactly_one_bucket():
    """Across every decision state, every producible outcome, no-output and
    error variants — the counts must always sum to the input length."""
    outcomes: list[str | None] = [*sorted(producible_outcomes() | set(REFUSED_OUTCOMES)), "pending_approval", None]
    results = [
        _result(state, outcome, error)
        for state, outcome, error in itertools.product(_DECISION_STATES, outcomes, (None, "boom"))
    ]
    assert len(results) > 20, "the combination sweep collapsed — check producible_outcomes()"

    outcome = make_think_outcome(Plan(proposals=()), tuple(results))
    counts = _buckets(outcome)
    assert sum(counts.values()) == len(results), f"partition does not cover the input: {counts}"

    # No result may appear in two buckets.
    buckets = (outcome.approved, outcome.pending_approval, outcome.rejected, outcome.errored)
    seen = [id(r) for bucket in buckets for r in bucket]
    assert len(seen) == len(set(seen)), "a result was counted in more than one bucket"


def test_an_empty_result_set_partitions_cleanly():
    outcome = make_think_outcome(Plan(proposals=()), ())
    assert _buckets(outcome) == {"approved": 0, "pending_approval": 0, "rejected": 0, "errored": 0}


# ── The declaration ───────────────────────────────────────────────────


def test_the_refusal_set_is_not_empty():
    """Emptying it would silence the parametrized guard below rather than
    failing it — a control that reports success and checks nothing."""
    assert REFUSED_OUTCOMES, "REFUSED_OUTCOMES is empty; no outcome would classify as refused"


def test_the_refusal_set_is_a_subset_of_what_can_be_produced():
    """A refusal outcome nothing produces is a stale entry; one that is produced
    and not declared is the defect this file exists for."""
    producible = producible_outcomes()
    stale = sorted(REFUSED_OUTCOMES - producible)
    assert not stale, f"REFUSED_OUTCOMES names outcomes actions/ never produces: {stale}"


def test_the_docstring_does_not_claim_a_consumer_that_does_not_exist():
    """The previous docstring asserted a tray UI consumer. Nothing implements it,
    and a documented consumer nobody can find is how a false constraint survives."""
    from community_member.runtime import think_loop

    text = (think_loop.make_think_outcome.__doc__ or "") + (think_loop.__doc__ or "")
    assert "tray UI relies" not in text
    assert "LocalAgent.run" in text


# ── The line an operator actually watches ─────────────────────────────


def test_the_run_loop_summary_reports_a_policy_refusal_as_rejected(tmp_path, monkeypatch):
    """End to end: a real navigation refused by the sandbox policy, through the
    real executor and runners, to the counts `LocalAgent.run` prints."""
    monkeypatch.setenv("COMMUNITY_MEMBER_HOME", str(tmp_path))
    from community_member.agent import LocalAgent
    from community_member.config import Config
    from community_member.consent import gate, ledger
    from community_member.executor import execute_plan

    ledger.init(tmp_path / "consent.db")
    cfg = Config(home=tmp_path)
    cfg.agent_id = "summary"
    cfg.provider = ""
    cfg.api_key = ""

    req = ActionRequest(
        capability="browser.navigate",
        scope="https://ungranted.test",
        context="c",
        provenance="trusted",
        extra={"url": "https://ungranted.test/a"},
    )
    # Consent given; no grants file, so the policy refuses after the gate approved.
    gate.approve(req, chapter_id="local:summary", prompt_event_sha256="click")
    plan = Plan(proposals=(req,))
    results = execute_plan(plan, LocalAgent(cfg).build_runners("local:summary"), chapter_id="local:summary")

    assert results[0].decision.state == "approved"
    assert results[0].output.outcome == "denied"
    assert results[0].output.extra["reason"] == "sandbox_policy_deny"

    outcome = make_think_outcome(plan, results)
    summary = (
        f"plan={len(outcome.plan.proposals)} approved={len(outcome.approved)} "
        f"pending={len(outcome.pending_approval)} rejected={len(outcome.rejected)} "
        f"errored={len(outcome.errored)}"
    )
    assert summary == "plan=1 approved=0 pending=0 rejected=1 errored=0"
