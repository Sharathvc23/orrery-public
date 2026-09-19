"""Retry discipline on the LLM path (PR3).

A keyless-install spike measured the think loop retrying a permanent 400 at full
rate, forever — 14 failures in ~60s, ~17k/day/agent. PR2 stopped the
*unconfigured* case from starting at all. This covers the other half: a
provider IS configured and the call fails anyway.

The load-bearing assertion in this file is not the backoff curve — it is that a
terminal 4xx **does not retry at all**. Backoff on a non-retryable error is
still an infinite loop, just a politer one, and it still burns quota forever on
something that cannot succeed.

Classification: ADVERSARIAL (control) + HAPPY (curve parity).
"""

from __future__ import annotations

import asyncio

import pytest

from community_member import outbox, retry_policy
from community_member.retry_policy import Decision


class _Err(Exception):
    """Provider-shaped error carrying an HTTP status, as the SDKs do."""

    def __init__(self, status: int, msg: str = "boom") -> None:
        super().__init__(msg)
        self.status_code = status


class TestTerminalNeverRetries:
    """The point of the PR."""

    @pytest.mark.parametrize("status", [400, 401, 402, 403, 404, 413, 422])
    def test_permanent_4xx_is_terminal(self, status: int) -> None:
        assert retry_policy.classify(_Err(status)) is Decision.TERMINAL

    def test_the_status_that_actually_bit_is_terminal(self) -> None:
        """The spike's observed failure verbatim: xAI's 400 'Incorrect API key'.
        Under a backoff-only fix this would still retry forever."""
        exc = _Err(400, "Incorrect API key provided. You can obtain an API key from ...")
        assert retry_policy.classify(exc) is Decision.TERMINAL

    @pytest.mark.parametrize("status", [405, 410, 418, 451])
    def test_unlisted_4xx_defaults_to_terminal(self, status: int) -> None:
        """A 4xx we have not enumerated is still a client error — ours to fix."""
        assert retry_policy.classify(_Err(status)) is Decision.TERMINAL

    def test_unclassifiable_exception_is_terminal(self) -> None:
        """An AttributeError from our own planner must not become an infinite
        polite retry. Stopping surfaces the bug; the caller degrades rather
        than dying, so being wrong here is cheap and being wrong the other way
        is unbounded."""
        assert retry_policy.classify(AttributeError("no attribute 'x'")) is Decision.TERMINAL


class TestRetryableStillRetries:
    @pytest.mark.parametrize("status", [408, 409, 425, 429, 500, 502, 503, 504])
    def test_transient_statuses_are_retryable(self, status: int) -> None:
        assert retry_policy.classify(_Err(status)) is Decision.RETRYABLE

    @pytest.mark.parametrize("status", [507, 599])
    def test_unlisted_5xx_is_retryable(self, status: int) -> None:
        assert retry_policy.classify(_Err(status)) is Decision.RETRYABLE

    @pytest.mark.parametrize("exc", [TimeoutError("t"), ConnectionError("c")])
    def test_transport_failures_are_retryable(self, exc: BaseException) -> None:
        assert retry_policy.classify(exc) is Decision.RETRYABLE

    def test_sdk_exception_names_are_matched_without_importing_the_sdk(self) -> None:
        """Matched by NAME so the module stays dependency-free and the server
        can vendor it unchanged."""
        api_conn = type("APIConnectionError", (Exception,), {})("down")
        auth = type("AuthenticationError", (Exception,), {})("bad key")
        assert retry_policy.classify(api_conn) is Decision.RETRYABLE
        assert retry_policy.classify(auth) is Decision.TERMINAL


class TestStatusWinsOverName:
    def test_a_generic_status_error_is_read_from_its_status(self) -> None:
        """A provider's generic `APIStatusError` says nothing in its name; the
        status carries the real answer, so status must be checked first."""
        exc = type("APIStatusError", (Exception,), {})("x")
        exc.status_code = 429  # type: ignore[attr-defined]
        assert retry_policy.classify(exc) is Decision.RETRYABLE
        exc.status_code = 401  # type: ignore[attr-defined]
        assert retry_policy.classify(exc) is Decision.TERMINAL

    def test_status_is_read_off_a_nested_response(self) -> None:
        exc = Exception("wrapped")
        exc.response = type("R", (), {"status_code": 503})()  # type: ignore[attr-defined]
        assert retry_policy.classify(exc) is Decision.RETRYABLE

    def test_a_number_in_the_message_is_not_parsed(self) -> None:
        """`model claude-400-x not found` must not read as a 400. A substring
        match on a number is how a message becomes a retry decision."""
        assert retry_policy.classify(Exception("model claude-503-preview not found")) is (Decision.TERMINAL)


class TestCurveParityWithOutbox:
    """One discipline, not two — the whole premise of the PR."""

    def test_matches_outbox_constants(self) -> None:
        assert retry_policy.BACKOFF_BASE_SEC == outbox._BACKOFF_BASE_SEC
        assert retry_policy.BACKOFF_CAP_SEC == outbox._BACKOFF_CAP_SEC

    def test_the_documented_curve(self) -> None:
        assert [retry_policy.backoff_seconds(n) for n in (1, 2, 3, 4)] == [10, 20, 40, 80]

    def test_caps_at_ten_minutes_and_stays_there(self) -> None:
        assert retry_policy.backoff_seconds(50) == 600
        assert retry_policy.backoff_seconds(10_000) == 600

    def test_matches_outbox_formula_exactly(self) -> None:
        for n in range(1, 15):
            expected = min(outbox._BACKOFF_BASE_SEC * (2 ** min(n - 1, 8)), outbox._BACKOFF_CAP_SEC)
            assert retry_policy.backoff_seconds(n) == expected

    def test_first_failure_waits_the_base_not_zero(self) -> None:
        assert retry_policy.backoff_seconds(1) == 10
        assert retry_policy.backoff_seconds(0) == 10  # defensive


class TestDescribeLeaksNothing:
    def test_reason_is_operator_readable(self) -> None:
        text = retry_policy.describe(_Err(429, "slow down"), Decision.RETRYABLE)
        assert "HTTP 429" in text and "will retry" in text

    def test_terminal_says_retrying_cannot_help(self) -> None:
        text = retry_policy.describe(_Err(401, "bad key"), Decision.TERMINAL)
        assert "STOPPING" in text


# ── the loop behaviour, which is what actually protects the third party ──


def _agent(monkeypatch):
    from community_member.agent import LocalAgent
    from community_member.config import Config

    cfg = Config()
    cfg.agent_id = "svc"
    cfg.provider = "anthropic"
    cfg.api_key = "sk-test"
    return LocalAgent(cfg)


@pytest.mark.asyncio
async def test_terminal_failure_halts_the_loop_after_exactly_one_call(monkeypatch) -> None:
    """The regression that matters. Under the old code this called forever;
    under a backoff-only fix it would still call forever, just slower."""
    agent = _agent(monkeypatch)
    calls = {"n": 0}

    def _boom():
        calls["n"] += 1
        raise _Err(400, "Incorrect API key provided")

    agent.think_v2 = _boom  # type: ignore[method-assign]
    agent._drain_inbound = lambda: None  # type: ignore[method-assign]
    agent.running = True

    # The degraded loop runs forever by design, so stop it from outside.
    async def _stop_soon():
        await asyncio.sleep(0.05)
        agent.running = False

    await asyncio.gather(agent.run(interval=0), _stop_soon())

    assert calls["n"] == 1, f"terminal error retried {calls['n']} times — must be exactly 1"
    assert agent.think_halted_reason is not None
    assert "STOPPING" in agent.think_halted_reason


@pytest.mark.asyncio
async def test_retryable_failure_backs_off_and_keeps_going(monkeypatch) -> None:
    agent = _agent(monkeypatch)
    calls = {"n": 0}
    waits: list[float] = []

    def _flaky():
        calls["n"] += 1
        if calls["n"] >= 3:
            agent.running = False
        raise _Err(503, "upstream down")

    async def _fake_sleep(seconds):
        waits.append(seconds)

    agent.think_v2 = _flaky  # type: ignore[method-assign]
    agent._drain_inbound = lambda: None  # type: ignore[method-assign]
    agent.running = True
    monkeypatch.setattr(asyncio, "sleep", _fake_sleep)

    await agent.run(interval=0)

    assert calls["n"] == 3, "a retryable error must not halt the loop"
    assert agent.think_halted_reason is None
    backoffs = [w for w in waits if w in (10, 20, 40)]
    assert backoffs[:3] == [10, 20, 40], f"backoff curve was {backoffs[:3]}"


@pytest.mark.asyncio
async def test_success_resets_the_backoff(monkeypatch) -> None:
    """A blip followed by recovery must not leave the agent permanently slow."""
    agent = _agent(monkeypatch)
    seq = [_Err(503), _Err(503), None, _Err(503)]
    waits: list[float] = []
    calls = {"n": 0}

    def _mixed():
        i = calls["n"]
        calls["n"] += 1
        if i >= len(seq):
            agent.running = False
            return None
        exc = seq[i]
        if exc is not None:
            raise exc
        return None

    async def _fake_sleep(seconds):
        waits.append(seconds)

    agent.think_v2 = _mixed  # type: ignore[method-assign]
    agent._drain_inbound = lambda: None  # type: ignore[method-assign]
    agent.running = True
    monkeypatch.setattr(asyncio, "sleep", _fake_sleep)

    await agent.run(interval=0)

    backoffs = [w for w in waits if w in (10, 20, 40, 80)]
    # 10, 20 … success … then back to 10, not 40.
    assert backoffs[:3] == [10, 20, 10], f"backoff did not reset after success: {backoffs[:4]}"
