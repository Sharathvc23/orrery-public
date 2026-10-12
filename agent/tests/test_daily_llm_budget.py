"""How much this agent may spend in a day, across cycles and restarts.

``llm_runtime.CYCLE_BUDGET`` bounds one think cycle and resets at the top of the
next one — and on every restart. So N cycles cost N times the cap and nothing
bounded the total. That mattered less while the agent talked only to its own
org; it matters now that the deployed agents are listed in a public index with
provider keys, and ``a2a_auth`` is explicit that a verified caller "is not an
allowlist".
"""

from __future__ import annotations

import json

import pytest

from community_member import llm_runtime

daily_budget = llm_runtime.DAILY_BUDGET


@pytest.fixture(autouse=True)
def _home(tmp_path, monkeypatch):
    monkeypatch.setenv("COMMUNITY_MEMBER_HOME", str(tmp_path))
    monkeypatch.delenv(llm_runtime.CALLS_PER_DAY_ENV, raising=False)
    daily_budget.reset()
    daily_budget.reset()
    yield
    daily_budget.reset()


def test_calls_are_counted_up_to_the_cap_then_refused(monkeypatch):
    monkeypatch.setenv(llm_runtime.CALLS_PER_DAY_ENV, "3")
    for _ in range(3):
        daily_budget.spend()
    assert daily_budget.state()["remaining"] == 0
    with pytest.raises(llm_runtime.DailyBudgetExceeded) as caught:
        daily_budget.spend()
    msg = str(caught.value)
    assert llm_runtime.CALLS_PER_DAY_ENV in msg, "the refusal must name the knob that changes it"
    assert "UTC day" in msg, "and when it lifts"


def test_the_count_survives_a_restart(monkeypatch, tmp_path):
    """THE POINT OF BEING DURABLE. A crash-loop must not reset the day's spend
    at exactly the moment something is going wrong — that turns the cap into no
    cap. This is the opposite of inbound_rate, where a restart forgiving a
    burst is correct."""
    monkeypatch.setenv(llm_runtime.CALLS_PER_DAY_ENV, "2")
    daily_budget.spend()
    stored = json.loads((tmp_path / "llm_daily_budget.json").read_text())
    assert stored["used"] == 1

    # A "restart" is just another process reading the same home.
    daily_budget.spend()
    with pytest.raises(llm_runtime.DailyBudgetExceeded):
        daily_budget.spend()


def test_the_day_rolls_over_by_date_not_by_uptime(monkeypatch, tmp_path):
    """A process up for three days must not still be spending Monday's budget."""
    monkeypatch.setenv(llm_runtime.CALLS_PER_DAY_ENV, "1")
    daily_budget.spend()
    with pytest.raises(llm_runtime.DailyBudgetExceeded):
        daily_budget.spend()

    # Yesterday's row is not today's count.
    (tmp_path / "llm_daily_budget.json").write_text(json.dumps({"day": "1999-01-01", "used": 999}))
    daily_budget.spend()
    assert daily_budget.state()["used"] == 1


def test_zero_disables_and_an_unset_variable_does_not(monkeypatch):
    """Unset must still enforce: a cost control that exists only when somebody
    remembered a variable is not a control. Disabling is a deliberate act."""
    assert llm_runtime.calls_per_day() == llm_runtime.DEFAULT_CALLS_PER_DAY
    assert daily_budget.state()["enforced"] is True

    monkeypatch.setenv(llm_runtime.CALLS_PER_DAY_ENV, "0")
    assert llm_runtime.calls_per_day() == 0
    assert daily_budget.state()["enforced"] is False
    for _ in range(50):
        daily_budget.spend()  # no cap, no refusal, nothing recorded
    assert daily_budget.state()["remaining"] is None


def test_a_typo_falls_back_rather_than_removing_the_cap(monkeypatch):
    monkeypatch.setenv(llm_runtime.CALLS_PER_DAY_ENV, "two thousand")
    assert llm_runtime.calls_per_day() == llm_runtime.DEFAULT_CALLS_PER_DAY
    monkeypatch.setenv(llm_runtime.CALLS_PER_DAY_ENV, "-1")
    assert llm_runtime.calls_per_day() == llm_runtime.DEFAULT_CALLS_PER_DAY


def test_an_unwritable_home_does_not_take_the_agent_off_the_air(monkeypatch, tmp_path):
    """Degrades to a weaker bound rather than refusing to work. state() reports
    it so the weakening is visible instead of assumed."""
    monkeypatch.setenv(llm_runtime.CALLS_PER_DAY_ENV, "5")
    monkeypatch.setenv(llm_runtime.DAILY_BUDGET_PATH_ENV, str(tmp_path / "nope" / "x.json"))
    monkeypatch.setattr(type(daily_budget), "_write", lambda *_a, **_k: None)
    daily_budget.spend()  # must not raise
    assert daily_budget.state()["used"] == 0, "nothing was persisted, and state says so"


def test_the_default_is_well_clear_of_a_normal_day():
    """The autonomous loop alone makes ~288 calls/day at the 300s default. A cap
    a working agent trips is a cap somebody switches off."""
    from community_member import DEFAULT_THINK_INTERVAL_SECONDS

    autonomous_per_day = 86400 / DEFAULT_THINK_INTERVAL_SECONDS
    assert llm_runtime.DEFAULT_CALLS_PER_DAY > autonomous_per_day * 5


def test_the_cap_sits_on_the_one_sanctioned_client_seam():
    """Enforced in the factory, so it bounds every caller. The AST guard forbids
    constructing OpenAI() anywhere else, so there is no client that escapes it —
    the same argument the per-cycle budget is placed on."""
    import inspect

    from community_member import llm_runtime

    src = inspect.getsource(llm_runtime._BudgetedCompletions.create)
    assert "DAILY_BUDGET.spend()" in src
    assert src.index("DAILY_BUDGET.spend()") < src.index("self._budget.spend()"), (
        "the day is the more absolute statement and must answer first"
    )
