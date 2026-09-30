"""The clock that keeps an agent's index name from lapsing.

A v3 record lives three days and ``announce_to_index`` ran once, at startup. So
an agent stayed resolvable for exactly as long as it had been running, and on the
fourth day its name expired — at which point a counterparty that requires an
index-resolvable caller refuses it.

Measured on the live estate before this: every record expired within 61 hours of
being read, and the only reason nothing had broken was that deploys kept
restarting the clock. A demo that works because somebody deploys it often is not
working.
"""

from __future__ import annotations

import asyncio
import logging

import pytest

from community_member import index_boot


class _Clock:
    """A sleep that runs the loop a fixed number of times, then stops it."""

    def __init__(self, ticks: int):
        self.remaining = ticks
        self.slept: list[float] = []

    async def __call__(self, seconds: float) -> None:
        # Cancel BEFORE recording, so a run of N ticks records exactly N sleeps.
        if self.remaining <= 0:
            raise asyncio.CancelledError
        self.remaining -= 1
        self.slept.append(seconds)


def _run(monkeypatch, announce, *, ticks: int = 3, interval: float = 3600.0) -> _Clock:
    monkeypatch.setattr(index_boot, "announce_to_index", announce)
    clock = _Clock(ticks)

    async def scenario():
        with pytest.raises(asyncio.CancelledError):
            await index_boot.renew_forever(object(), interval=interval, sleep=clock)

    asyncio.run(scenario())
    return clock


def test_the_registration_is_rechecked_on_a_clock(monkeypatch):
    calls = []
    clock = _run(monkeypatch, lambda _c: calls.append(1) or {"action": "current"}, ticks=3)
    assert len(calls) == 3
    assert clock.slept == [3600.0, 3600.0, 3600.0]


def test_it_sleeps_before_the_first_recheck(monkeypatch):
    """Boot already announced. Resolving a record written seconds ago is a
    request that can only return what was just written."""
    calls = []
    _run(monkeypatch, lambda _c: calls.append(1), ticks=0)
    assert calls == []


def test_an_unreachable_index_does_not_stop_the_loop(monkeypatch):
    """An index that is down is somebody else's outage. Turning it into this
    agent's crash would take it off the air for the reason renewal prevents."""
    attempts = []

    def flaky(_config):
        attempts.append(1)
        if len(attempts) < 3:
            raise OSError("connection refused")
        return {"action": "renewed", "seq": 2}

    _run(monkeypatch, flaky, ticks=4)
    assert len(attempts) == 4, "the loop gave up after a failure"


def test_registration_being_off_is_not_an_error(monkeypatch, caplog):
    """`announce_to_index` returns None when no index is configured. An agent
    with none is correctly configured, not failing."""
    caplog.set_level(logging.WARNING)
    _run(monkeypatch, lambda _c: None, ticks=3)
    assert "renewal" not in caplog.text


def test_a_renewal_is_announced(monkeypatch, caplog):
    caplog.set_level(logging.INFO)
    _run(monkeypatch, lambda _c: {"action": "renewed", "seq": 7, "expires_at": "2026-10-06T00:00:00Z"}, ticks=1)
    assert "renewed" in caplog.text and "seq=7" in caplog.text


def test_a_current_record_is_not_announced(monkeypatch, caplog):
    """A line every hour saying nothing happened is a log nobody reads."""
    caplog.set_level(logging.INFO)
    _run(monkeypatch, lambda _c: {"action": "current", "seq": 1}, ticks=3)
    assert "[index]" not in caplog.text


def test_a_failure_is_reported(monkeypatch, caplog):
    caplog.set_level(logging.WARNING)
    _run(monkeypatch, lambda _c: {"action": "failed", "detail": "index refused"}, ticks=1)
    assert "index refused" in caplog.text


def test_the_interval_leaves_margin_for_an_index_being_down():
    """A record lives three days and is renewed inside the last twelve hours. A
    tick that only just keeps up has no margin for an index being unreachable."""
    assert index_boot.RENEW_INTERVAL_SECONDS <= 12 * 3600 / 4
