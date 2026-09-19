"""Stop paying for a refusal that cannot clear.

The machinery was already correct and already unreachable. ``retry_policy``
returns the right terminal verdict, ``agent_scheduler.after_failure`` acts on it
correctly, and nothing called either — ``run_cycle`` returned normally on every
exception, so the scheduler recorded a success after each failure and the
cadence never widened. A sustained 401 cost 418 org calls a day, forever.

These tests pin reachability and the verdict, not the arithmetic — the curve
itself is already covered where it is defined.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

import agent_scheduler
import retry_policy


class _Status(Exception):
    """An exception carrying an HTTP status, the way provider SDKs do."""

    def __init__(self, status_code: int) -> None:
        super().__init__(f"HTTP {status_code}")
        self.status_code = status_code


NOW = datetime(2026, 8, 24, 12, 0, tzinfo=UTC)


# ── the verdict the loop acts on ─────────────────────────────────────────────


def test_a_sustained_401_halts_rather_than_backing_off():
    """The measured failure: 418 org calls a day, forever, on a key that no
    delay makes valid. A longer interval is not the fix — stopping is."""
    decision = agent_scheduler.after_failure(_Status(401), now=NOW, consecutive_failures=0, rand=0.5)
    assert decision.paused
    assert decision.next_run_at is None, "a halted cycle must not be scheduled at all"


def test_a_429_backs_off_instead_of_halting():
    """The other side of the line, and the reason it is drawn in retry_policy
    rather than at a call site: a rate limit clears on its own, and halting a
    chapter on one would be a worse failure than the one being fixed."""
    decision = agent_scheduler.after_failure(_Status(429), now=NOW, consecutive_failures=0, rand=0.5)
    assert not decision.paused
    assert decision.next_run_at is not None
    assert decision.next_run_at > NOW


def test_the_backoff_widens_with_consecutive_failures():
    delays = [
        (agent_scheduler.after_failure(_Status(503), now=NOW, consecutive_failures=n, rand=0.5).next_run_at - NOW)
        for n in range(3)
    ]
    assert delays[0] < delays[1] < delays[2]


def test_an_unrecognised_failure_halts_by_the_shared_default():
    """retry_policy documents TERMINAL as the default for anything it cannot
    classify, because an unknown exception here is most often our own bug and
    retrying a bug forever is the failure the module exists to end."""
    assert retry_policy.classify(AttributeError("bug in a rare branch")) is retry_policy.Decision.TERMINAL
    assert agent_scheduler.after_failure(
        AttributeError("bug"), now=NOW, consecutive_failures=0, rand=0.5
    ).paused


# ── reachability: the property the unit tests could not assert ───────────────


def test_run_cycle_surfaces_its_failure_to_the_caller():
    """``run_cycle`` used to catch every exception and return normally. While it
    did, no failure could reach the scheduler and the failure half was dead code
    with passing unit tests."""
    import inspect

    import think_cycle

    source = inspect.getsource(think_cycle.run_cycle)
    body = "\n".join(line.split("#")[0] for line in source.splitlines())
    assert "raise" in body, "run_cycle swallows its exceptions again — the scheduler cannot see a failure"


def test_the_loop_routes_failures_and_successes_to_different_halves():
    """Both halves reachable from the one call site that runs the cycle."""
    import inspect

    import chapter_agent

    source = inspect.getsource(chapter_agent.heartbeat_loop)
    assert "_record_think_failure(" in source, "a failed cycle is not routed to after_failure"
    assert "_record_think_schedule()" in source, "a successful cycle no longer records its schedule"


@pytest.mark.asyncio
async def test_a_terminal_failure_stops_the_cycle_and_an_operator_can_restart_it(monkeypatch):
    """The halt is real (the loop stops calling run_cycle) and it is clearable
    only by a human — auto-resuming on a timer would be retrying by another
    name."""
    import chapter_agent

    monkeypatch.setattr(chapter_agent.agent_scheduler, "record", _async_true)
    monkeypatch.setattr(chapter_agent, "_think_paused_reason", None)
    monkeypatch.setattr(chapter_agent, "_consecutive_think_failures", 0)

    await chapter_agent._record_think_failure(_Status(401))
    assert chapter_agent._think_paused_reason is not None, "a terminal failure did not halt the cycle"

    # Nothing on a timer clears it.
    await chapter_agent._record_think_failure(_Status(401))
    assert chapter_agent._think_paused_reason is not None


@pytest.mark.asyncio
async def test_a_retryable_failure_does_not_halt_the_cycle(monkeypatch):
    """The guard has to be able to answer 'keep going', not only 'stop'."""
    import chapter_agent

    monkeypatch.setattr(chapter_agent.agent_scheduler, "record", _async_true)
    monkeypatch.setattr(chapter_agent, "_think_paused_reason", None)
    monkeypatch.setattr(chapter_agent, "_consecutive_think_failures", 0)

    await chapter_agent._record_think_failure(_Status(503))
    assert chapter_agent._think_paused_reason is None
    assert chapter_agent._consecutive_think_failures == 1


async def _async_true(*_args, **_kwargs) -> bool:
    return True


# ── the interval is parsed once, and cannot crash the container ──────────────


def test_a_non_integer_interval_falls_back_instead_of_raising():
    """It used to be ``int(os.environ.get(...))`` at import, so one typo made
    the container unstartable with a traceback naming neither the variable nor
    the value."""
    assert agent_scheduler.interval_seconds({"THINK_CYCLE_INTERVAL": "abc"}) == agent_scheduler.DEFAULT_INTERVAL_S
    assert agent_scheduler.interval_seconds({"THINK_CYCLE_INTERVAL": "12.5"}) == 12.5
    assert agent_scheduler.interval_seconds({"THINK_CYCLE_INTERVAL": "0"}) == agent_scheduler.DEFAULT_INTERVAL_S
    assert agent_scheduler.interval_seconds({"THINK_CYCLE_INTERVAL": "-5"}) == agent_scheduler.DEFAULT_INTERVAL_S


def test_the_checked_in_federation_interval_survives_the_floor():
    """⚠️ THE FLOOR IS 5s, NOT 300. infra/compose.e2e-federation.yml checks in
    15, and a floor above it would quietly run the federation e2e at a cadence
    nobody configured while appearing to honour the setting."""
    assert agent_scheduler.interval_seconds({"THINK_CYCLE_INTERVAL": "15"}) == 15.0
    assert agent_scheduler.MIN_INTERVAL_S <= 15.0


def test_the_compose_file_still_sets_an_interval_above_the_floor():
    """Read the actual file rather than restating its value here — a test that
    asserts its own copy of a constant cannot notice the file changing."""
    from pathlib import Path

    compose = (Path(__file__).resolve().parents[2] / "infra" / "compose.e2e-federation.yml").read_text()
    configured = [
        int(line.split(":")[1].strip().strip('"'))
        for line in compose.splitlines()
        if "THINK_CYCLE_INTERVAL:" in line
    ]
    assert configured, "compose.e2e-federation.yml no longer sets THINK_CYCLE_INTERVAL"
    for value in configured:
        assert value >= agent_scheduler.MIN_INTERVAL_S, (
            f"compose configures {value}s, below the {agent_scheduler.MIN_INTERVAL_S}s floor — "
            "the e2e would silently run slower than configured"
        )


def test_both_interval_names_reach_one_parser():
    """Two names because the two sides grew separately; one parser so they
    cannot drift into two disciplines."""
    assert agent_scheduler.INTERVAL_ENV_VARS == ("THINK_CYCLE_INTERVAL", "COMMUNITY_MEMBER_THINK_INTERVAL")
    assert agent_scheduler.interval_seconds({"COMMUNITY_MEMBER_THINK_INTERVAL": "45"}) == 45.0


def test_the_org_interval_is_not_parsed_a_second_time():
    """The defect was a private ``int()`` beside a guarded parser."""
    from pathlib import Path

    source = (Path(__file__).resolve().parents[1] / "chapter_agent.py").read_text()
    code = "\n".join(line.split("#")[0] for line in source.splitlines())
    assert 'int(os.environ.get("THINK_CYCLE_INTERVAL"' not in code
    assert "agent_scheduler.interval_seconds()" in code
