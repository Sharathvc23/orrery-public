"""The per-cycle LLM budget, and the fact that nothing used to reset it.

``llm_runtime.CYCLE_BUDGET`` is module-level and documented as *"reset at the top
of each cycle by the caller that owns the cycle"*. No caller did, in either tree.
So the bound was never per-cycle: it was a **process-lifetime** cap of 60 calls,
and every long-running agent stopped reasoning permanently once it had made them.

Measured on 2026-09-30 across the live estate: all ten agent services and both org
servers answered every LLM-mediated request with *"this cycle has made 60 LLM
calls, its limit (LLM_MAX_CALLS_PER_CYCLE=60)"* — while the same message promised
*"Remaining work is not lost — it is left for the next cycle."* There was no next
cycle, and the reassurance was the defect's best disguise: an operator reading it
concludes the agent is pacing itself.

These tests drive the real ``LocalAgent.run`` loop rather than calling ``reset``
directly. A test that asserted ``CallBudget.reset`` works would have passed
throughout the entire period the estate was mute — the unit was never broken, the
*wiring* was, which is the same shape as the revocation gap: every piece present,
correct in isolation, and connected to nothing.
"""

from __future__ import annotations

import asyncio

import pytest

import community_member.agent as agent_mod
from community_member import llm_runtime
from community_member.agent import LocalAgent
from community_member.config import Config
from community_member.planner import Plan
from community_member.runtime.think_loop import make_think_outcome


@pytest.fixture
def agent(tmp_path, monkeypatch):
    monkeypatch.setenv("COMMUNITY_MEMBER_HOME", str(tmp_path))
    cfg = Config(home=tmp_path)
    cfg.agent_id = "budget"
    cfg.provider = "openai"
    cfg.api_key = "test-key-not-used"
    a = LocalAgent(cfg)
    a.llm_configured = True
    return a


@pytest.fixture(autouse=True)
def pristine_budget():
    """Restores the module-level budget, which every test here deliberately spends."""
    before = llm_runtime.CYCLE_BUDGET.used, llm_runtime.CYCLE_BUDGET.limit
    yield
    llm_runtime.CYCLE_BUDGET.used, llm_runtime.CYCLE_BUDGET.limit = before


def _drive(agent: LocalAgent, think, cycles: int, interval: int = 5) -> None:
    """Run the real loop for ``cycles`` iterations, then stop it."""
    seen = {"sleeps": 0}

    async def _sleep(seconds):
        # sleep(0) is the loop's one-shot yield so uvicorn can bind; not pacing.
        if not seconds:
            return
        seen["sleeps"] += 1
        if seen["sleeps"] >= cycles:
            agent.running = False

    agent.think_v2 = think
    original = agent_mod.asyncio.sleep
    agent_mod.asyncio.sleep = _sleep
    try:
        asyncio.run(agent.run(interval=interval))
    finally:
        agent_mod.asyncio.sleep = original


def test_a_cycle_that_spent_its_whole_budget_does_not_starve_the_next_one(agent, monkeypatch):
    """The defect, stated as the property it broke.

    Cycle one exhausts the allowance. Cycle two must be able to spend again — on
    the unfixed loop it could not, for the lifetime of the process.
    """
    monkeypatch.setenv(llm_runtime.CALLS_PER_CYCLE_ENV, "3")
    llm_runtime.CYCLE_BUDGET.reset(3)
    remaining_at_cycle_start: list[int] = []

    def think():
        remaining_at_cycle_start.append(llm_runtime.CYCLE_BUDGET.remaining)
        for _ in range(3):
            llm_runtime.CYCLE_BUDGET.spend()
        return make_think_outcome(Plan(proposals=()), ())

    _drive(agent, think, cycles=3)

    assert remaining_at_cycle_start == [3, 3, 3], (
        "each cycle must begin with its full allowance; "
        f"got {remaining_at_cycle_start} — a later cycle started already spent"
    )


def test_a_cycle_cannot_spend_past_its_limit(agent, monkeypatch):
    """The reset restores the allowance; it does not remove the bound."""
    monkeypatch.setenv(llm_runtime.CALLS_PER_CYCLE_ENV, "2")
    llm_runtime.CYCLE_BUDGET.reset(2)
    refusals: list[str] = []

    def think():
        for _ in range(2):
            llm_runtime.CYCLE_BUDGET.spend()
        try:
            llm_runtime.CYCLE_BUDGET.spend()
        except llm_runtime.LLMCallBudgetExceeded as exc:
            refusals.append(str(exc))
        return make_think_outcome(Plan(proposals=()), ())

    _drive(agent, think, cycles=2)

    assert len(refusals) == 2, "the third call in each cycle must still be refused"
    assert "its limit" in refusals[0]


def test_the_limit_is_re_read_so_an_operator_need_not_redeploy(agent, monkeypatch):
    """Raising the variable takes effect on the next cycle, not the next deploy.

    The budget is constructed at import from the environment as it was then. If
    the reset reused ``budget.limit`` instead of re-reading, a change to
    ``LLM_MAX_CALLS_PER_CYCLE`` would need a process restart — and a restart is
    what an operator would reach for anyway to clear the stuck cap, which would
    make the real defect look like a configuration mistake they had fixed.
    """
    monkeypatch.setenv(llm_runtime.CALLS_PER_CYCLE_ENV, "1")
    llm_runtime.CYCLE_BUDGET.reset(1)
    limits: list[int] = []

    def think():
        limits.append(llm_runtime.CYCLE_BUDGET.limit)
        # The operator raises it between the first and second cycle.
        monkeypatch.setenv(llm_runtime.CALLS_PER_CYCLE_ENV, "9")
        return make_think_outcome(Plan(proposals=()), ())

    _drive(agent, think, cycles=2)

    assert limits == [1, 9], f"the limit must be re-read each cycle; got {limits}"


def test_the_reset_happens_before_the_cycle_does_any_work(agent, monkeypatch):
    """Ordering matters: a reset after the work would clear the count too late.

    The budget is reset at the top of the loop body, ahead of ``_drain_inbound``
    and ``think_v2``, so everything a cycle does is charged against that cycle's
    own allowance rather than against whatever the previous one left.
    """
    monkeypatch.setenv(llm_runtime.CALLS_PER_CYCLE_ENV, "5")
    llm_runtime.CYCLE_BUDGET.reset(5)
    llm_runtime.CYCLE_BUDGET.used = 5  # as if a previous cycle had spent it all
    observed: list[int] = []

    def think():
        observed.append(llm_runtime.CYCLE_BUDGET.used)
        return make_think_outcome(Plan(proposals=()), ())

    _drive(agent, think, cycles=1)

    assert observed == [0], f"the cycle began with {observed} spent — the reset ran too late"
