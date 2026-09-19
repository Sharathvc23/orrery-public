"""The think interval, and backing off a cycle that cannot succeed.

Two properties. The interval is read from one place, so the `community-member`
command and the container entrypoint cannot honour the variable on one path and
ignore it on the other. And a cycle whose every action was refused widens the
wait, because repeating it spends a model call on a plan that will meet the same
refusal until an operator changes something outside the loop.
"""

from __future__ import annotations

import asyncio

import pytest

import community_member
from community_member import retry_policy
from community_member.consent.gate import ActionRequest, ConsentDecision
from community_member.executor import ExecutionResult, ToolOutput
from community_member.planner import Plan
from community_member.runtime.think_loop import ThinkOutcome, make_think_outcome

ENV = community_member.THINK_INTERVAL_ENV_VAR
DEFAULT = community_member.DEFAULT_THINK_INTERVAL_SECONDS


def _result(state: str, outcome: str | None, error: str | None = None) -> ExecutionResult:
    req = ActionRequest(capability="browser.navigate", scope="https://x.test", context="c", provenance="trusted")
    out = None if outcome is None else ToolOutput(capability=req.capability, scope=req.scope, outcome=outcome)
    return ExecutionResult(proposal=req, decision=ConsentDecision(state=state, reason="r"), output=out, error=error)


def _outcome(*results: ExecutionResult) -> ThinkOutcome:
    return make_think_outcome(Plan(proposals=()), results)


# ── The interval, read from one place ─────────────────────────────────


def test_the_interval_defaults_to_the_documented_value(monkeypatch):
    monkeypatch.delenv(ENV, raising=False)
    assert community_member.think_interval_seconds() == DEFAULT == 300


def test_the_interval_is_read_from_the_environment(monkeypatch):
    monkeypatch.setenv(ENV, "45")
    assert community_member.think_interval_seconds() == 45


@pytest.mark.parametrize("bad", ["0", "-5", "", "   ", "not-a-number", "12.5"])
def test_an_unusable_interval_falls_back_rather_than_spinning(monkeypatch, bad):
    """Zero or negative would busy-loop; a non-integer would crash the loop."""
    monkeypatch.setenv(ENV, bad)
    assert community_member.think_interval_seconds() == DEFAULT


def test_both_entry_points_read_the_same_helper():
    """The defect this replaces: serve.py honoured the variable and cli.py
    hardcoded 300, so the path the wizard sets up ignored it silently."""
    from pathlib import Path

    agent_dir = Path(community_member.__file__).resolve().parents[1]
    cli = (agent_dir / "community_member" / "cli.py").read_text()
    serve = (agent_dir / "serve.py").read_text()

    for name, source in (("cli.py", cli), ("serve.py", serve)):
        assert "think_interval_seconds()" in source, f"{name} does not read the shared helper"
        assert ENV not in source, f"{name} reads the environment variable directly instead of the helper"
    assert "interval=300" not in cli, "cli.py still hardcodes an interval"


# ── What counts as a cycle that cannot succeed ────────────────────────


def test_a_cycle_with_every_action_refused_produced_nothing():
    assert _outcome(_result("approved", "denied"), _result("reject", None)).produced_nothing


def test_a_cycle_awaiting_a_human_produced_nothing():
    """WIDENED, and the reason the old exclusion was wrong.

    ``fully_refused`` excluded this on the argument that backing off would make
    an attended agent "sluggish exactly when someone is about to approve".
    Approval does not go through this loop: ``POST /api/local/consent/approve``
    runs the action immediately through the agent's runners and tombstones the
    approval so the loop cannot re-fire it. So the exclusion bought no
    responsiveness and cost a full model call per interval re-proposing what a
    human has not answered yet.
    """
    assert _outcome(_result("prompt", "pending_approval")).produced_nothing


def test_a_mix_of_pending_and_refused_produced_nothing():
    assert _outcome(_result("approved", "denied"), _result("prompt", "pending_approval")).produced_nothing


def test_an_empty_cycle_produced_nothing():
    """WIDENED. The planner proposing nothing is indeed a different condition
    from the runtime refusing everything — and the caller is not asking which
    condition it was, it is asking whether the model call bought anything."""
    assert _outcome().produced_nothing


def test_a_cycle_with_work_done_did_produce_something():
    """The predicate has to be able to answer False, or it is not a predicate."""
    assert not _outcome(_result("approved", "ok"), _result("approved", "denied")).produced_nothing


def test_an_errored_cycle_is_not_counted_as_producing_nothing():
    """Deliberately NOT widened. An error is a different condition with its own
    handling on the retryable path, and attempting work that failed is not the
    same as having no work to attempt."""
    assert not _outcome(_result("approved", None, error="boom")).produced_nothing


# ── The backoff curve is the one that already exists ──────────────────


def test_the_backoff_reuses_the_shared_curve():
    """One curve in this codebase, shared with the retryable-failure path and
    the outbox, so an operator reading two logs sees one behaviour."""
    assert [retry_policy.backoff_seconds(n) for n in (1, 2, 3, 4)] == [10, 20, 40, 80]


def test_the_backoff_never_shortens_the_configured_interval():
    """An operator who set a long interval must not be sped up by a refusal."""
    interval = 600
    for n in range(1, 8):
        assert max(interval, retry_policy.backoff_seconds(n)) >= interval


# ── The loop: backs off, recovers, and says so ────────────────────────


class _Recorder:
    """Drives LocalAgent.run for a fixed number of cycles, capturing the sleep
    each cycle asked for."""

    def __init__(self, agent, outcomes):
        self.agent = agent
        self.outcomes = list(outcomes)
        # Captured up front: `outcomes` is consumed by _think below, so
        # comparing against its live length would stop the loop early.
        self.cycles = len(self.outcomes)
        self.sleeps: list[float] = []

    async def run(self, interval: int) -> None:
        async def _sleep(seconds):
            # sleep(0) is the loop's one-shot yield so uvicorn can bind; it is
            # not pacing and is not what this test is measuring.
            if seconds:
                self.sleeps.append(seconds)
            if len(self.sleeps) >= self.cycles:
                self.agent.running = False

        def _think():
            return self.outcomes.pop(0)

        self.agent.think_v2 = _think
        import community_member.agent as agent_mod

        original = agent_mod.asyncio.sleep
        agent_mod.asyncio.sleep = _sleep
        try:
            await self.agent.run(interval=interval)
        finally:
            agent_mod.asyncio.sleep = original


@pytest.fixture
def agent(tmp_path, monkeypatch):
    monkeypatch.setenv("COMMUNITY_MEMBER_HOME", str(tmp_path))
    from community_member.agent import LocalAgent
    from community_member.config import Config

    cfg = Config(home=tmp_path)
    cfg.agent_id = "backoff"
    cfg.provider = "openai"
    cfg.api_key = "test-key-not-used"
    a = LocalAgent(cfg)
    a.llm_configured = True
    return a


def test_consecutive_refused_cycles_widen_the_wait(agent, capsys):
    refused = _outcome(_result("approved", "denied"))
    rec = _Recorder(agent, [refused, refused, refused])
    asyncio.run(rec.run(interval=30))

    assert rec.sleeps == [30, 30, 40], rec.sleeps  # max(interval, 10/20/40)
    out = capsys.readouterr().out
    assert "produced no work" in out


def test_the_first_non_refused_cycle_restores_the_interval(agent):
    """An operator who has just written their first grant must not wait out a
    backoff to see it take effect."""
    refused = _outcome(_result("approved", "denied"))
    worked = _outcome(_result("approved", "ok"))
    rec = _Recorder(agent, [refused, refused, refused, refused, worked, refused])
    asyncio.run(rec.run(interval=5))

    assert rec.sleeps == [10, 20, 40, 80, 5, 10], rec.sleeps


def test_an_attended_cycle_backs_off_like_any_other_barren_cycle(agent):
    """INVERTED, deliberately. This asserted that prompts every cycle must keep
    the loop at full pace, on the reasoning that an attended agent is about to
    be approved. But approval runs through
    ``POST /api/local/consent/approve``, which executes immediately and
    tombstones — it never waits for this loop. So the old behaviour bought no
    responsiveness and spent a model call per interval re-proposing an
    unanswered prompt, which is the shape this unit exists to stop."""
    pending = _outcome(_result("prompt", "pending_approval"))
    rec = _Recorder(agent, [pending] * 4)
    asyncio.run(rec.run(interval=7))

    assert rec.sleeps == [10, 20, 40, 80], rec.sleeps


def test_answering_the_prompt_returns_the_loop_to_its_pace(agent):
    """The other half: backing off must not strand an agent whose human just
    answered. Any cycle that produces work restores the configured interval."""
    pending = _outcome(_result("prompt", "pending_approval"))
    worked = _outcome(_result("approved", "ok"))
    rec = _Recorder(agent, [pending, pending, worked, pending])
    asyncio.run(rec.run(interval=6))

    assert rec.sleeps == [10, 20, 6, 10], rec.sleeps


def test_the_backing_off_state_is_distinguishable_from_a_working_one(agent, capsys):
    """A silent backoff would be indistinguishable from a healthy agent.

    The contrast is now productive-vs-barren rather than refused-vs-empty: an
    empty cycle is itself a backoff under ``produced_nothing``, so a working
    cycle is the only honest quiet case."""
    barren = _outcome(_result("approved", "denied"))
    worked = _outcome(_result("approved", "ok"))
    asyncio.run(_Recorder(agent, [worked]).run(interval=5))
    quiet = capsys.readouterr().out

    asyncio.run(_Recorder(agent, [barren]).run(interval=5))
    backing_off = capsys.readouterr().out

    assert "produced no work" not in quiet
    assert "produced no work" in backing_off
    assert "next attempt in" in backing_off


def test_the_backoff_is_recorded_on_the_thought_stream(agent, monkeypatch):
    """Visible on the dashboard surface, not only in the terminal — the
    terminal is not where an unattended agent is watched from."""
    logged: list[str] = []
    from community_member import server as server_mod

    monkeypatch.setattr(server_mod, "log_thought", lambda msg: logged.append(msg))

    refused = _outcome(_result("approved", "denied"))
    asyncio.run(_Recorder(agent, [refused]).run(interval=5))

    assert any("produced nothing, backing off" in m for m in logged), logged
