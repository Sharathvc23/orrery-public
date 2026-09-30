"""The org server's cycle owner resets the LLM budget. It used to not.

``think_cycle.run_cycle`` IS the "caller that owns the cycle" that
``llm_runtime.CYCLE_BUDGET`` is documented as being reset by. It never reset it,
so the bound was a process-lifetime cap: both live org servers answered every
LLM-mediated request with *"this cycle has made 60 LLM calls, its limit"* on
2026-09-30, while promising the work was left for the next cycle.

The companion test in the agent tree covers ``LocalAgent.run``. Both trees carry
their own copy of ``llm_runtime`` and their own cycle owner, so a fix to one is
not a fix to the other — which is why there are two tests and not one.
"""

from __future__ import annotations

import asyncio

import pytest

import llm_runtime
import think_cycle


@pytest.fixture(autouse=True)
def pristine_budget():
    before = llm_runtime.CYCLE_BUDGET.used, llm_runtime.CYCLE_BUDGET.limit
    yield
    llm_runtime.CYCLE_BUDGET.used, llm_runtime.CYCLE_BUDGET.limit = before


@pytest.fixture(autouse=True)
def no_thinking(monkeypatch):
    """Every cycle type stubbed out. This measures the boundary, not the work."""
    async def nothing(*_a, **_k):
        return None

    for name in dir(think_cycle):
        if name.startswith("think_"):
            attr = getattr(think_cycle, name)
            if callable(attr):
                monkeypatch.setattr(think_cycle, name, nothing, raising=False)
    # Lazily loaded, and None in a bare test process. Guarded rather than
    # asserted: the point of this file is the cycle BOUNDARY, and a cycle type
    # that cannot run in a test process must not decide whether the boundary is
    # measurable.
    if think_cycle.sovereign_runtime_mod is not None:
        monkeypatch.setattr(
            think_cycle.sovereign_runtime_mod, "think_sovereign_cycle", nothing, raising=False
        )


def test_each_cycle_begins_with_its_full_allowance(monkeypatch):
    monkeypatch.setenv(llm_runtime.CALLS_PER_CYCLE_ENV, "4")
    llm_runtime.CYCLE_BUDGET.reset(4)

    for _ in range(3):
        llm_runtime.CYCLE_BUDGET.used = 4  # as if the previous cycle spent it all
        asyncio.run(think_cycle.run_cycle())
        assert llm_runtime.CYCLE_BUDGET.remaining == 4, (
            "a cycle started with a spent budget — nothing reset it, which is the "
            "defect that made both org servers permanently mute"
        )


def test_the_limit_is_re_read_so_an_operator_need_not_redeploy(monkeypatch):
    monkeypatch.setenv(llm_runtime.CALLS_PER_CYCLE_ENV, "2")
    asyncio.run(think_cycle.run_cycle())
    assert llm_runtime.CYCLE_BUDGET.limit == 2

    # A restart is what an operator would reach for to clear a stuck cap, which
    # would make the real defect look like a configuration mistake they had fixed.
    monkeypatch.setenv(llm_runtime.CALLS_PER_CYCLE_ENV, "11")
    asyncio.run(think_cycle.run_cycle())
    assert llm_runtime.CYCLE_BUDGET.limit == 11


def test_the_bound_still_bounds(monkeypatch):
    """The reset restores the allowance; it does not remove the limit."""
    monkeypatch.setenv(llm_runtime.CALLS_PER_CYCLE_ENV, "1")
    asyncio.run(think_cycle.run_cycle())

    llm_runtime.CYCLE_BUDGET.spend()
    with pytest.raises(llm_runtime.LLMCallBudgetExceeded, match="its limit"):
        llm_runtime.CYCLE_BUDGET.spend()
