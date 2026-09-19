"""Bounded, atomic process-local rate-limit state.

The limiter keeps one sliding-window bucket per client key.  These tests pin the
security boundary: key churn cannot grow that store without limit, cannot reset
live quotas, and cannot race past either the per-key ceiling or store capacity.
"""

from __future__ import annotations

import os
import threading
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("AGENT_ID", "test-rate-limit-bound")
os.environ.setdefault("AGENT_NAME", "Test Rate Limit Bound")

import chapter_agent  # noqa: E402
import metrics  # noqa: E402

DEFAULT_RATE_LIMIT_KEY_CAP = chapter_agent.RATE_LIMIT_KEY_CAP


@pytest.fixture(autouse=True)
def _isolated_limiter(monkeypatch: pytest.MonkeyPatch):
    """Use a tiny store and reset process-local state around every test."""
    chapter_agent._rate_limit_store.clear()
    metrics.reset_for_tests()
    monkeypatch.setattr(chapter_agent, "RATE_LIMIT_KEY_CAP", 2, raising=False)
    yield
    chapter_agent._rate_limit_store.clear()
    metrics.reset_for_tests()


def _set_clock(monkeypatch: pytest.MonkeyPatch, *instants: float) -> None:
    clock = iter(instants)
    monkeypatch.setattr(chapter_agent.time_mod, "monotonic", lambda: next(clock))


def _capacity_metric(chapter_id: str = "test") -> str:
    name = "nanda_chapter_rate_limit_capacity_rejections_total"
    return next(line for line in metrics.render(chapter_id=chapter_id).splitlines() if line.startswith(name))


def test_default_key_cap_is_the_reviewed_10_000_bucket_policy() -> None:
    """Changing the fixed security bound requires an explicit policy review."""
    assert DEFAULT_RATE_LIMIT_KEY_CAP == 10_000


def test_unique_live_keys_stop_at_the_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    """A third live key must be refused and must never enter a two-slot store."""
    _set_clock(monkeypatch, 100.0, 101.0, 102.0)

    assert chapter_agent.check_rate_limit("alice") is True
    assert chapter_agent.check_rate_limit("bob") is True
    assert chapter_agent.check_rate_limit("mallory") is False

    assert list(chapter_agent._rate_limit_store) == ["alice", "bob"]
    assert len(chapter_agent._rate_limit_store) == 2
    assert _capacity_metric() == (
        'nanda_chapter_rate_limit_capacity_rejections_total{chapter_id="test"} 1'
    )


def test_live_buckets_are_not_evicted_or_quota_reset_by_key_churn(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A new key cannot buy space by evicting a live, already-full bucket."""
    _set_clock(monkeypatch, 100.0, 101.0, 102.0, 103.0, 104.0)

    assert chapter_agent.check_rate_limit("alice", max_requests=2) is True
    assert chapter_agent.check_rate_limit("alice", max_requests=2) is True
    assert chapter_agent.check_rate_limit("bob", max_requests=2) is True
    assert chapter_agent.check_rate_limit("mallory", max_requests=2) is False
    assert chapter_agent.check_rate_limit("alice", max_requests=2) is False

    assert list(chapter_agent._rate_limit_store) == ["alice", "bob"]
    assert len(chapter_agent._rate_limit_store["alice"]) == 2
    assert _capacity_metric().endswith(" 1")


def test_expired_oldest_bucket_is_reclaimed_but_newer_live_bucket_remains(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """At capacity, only the oldest expired bucket is replaced by a new key."""
    _set_clock(monkeypatch, 0.0, 1.0, 60.5)

    assert chapter_agent.check_rate_limit("oldest") is True
    assert chapter_agent.check_rate_limit("newer") is True
    assert chapter_agent.check_rate_limit("newcomer") is True

    assert list(chapter_agent._rate_limit_store) == ["newer", "newcomer"]
    assert _capacity_metric().endswith(" 0")


def test_denied_existing_probe_does_not_change_last_admitted_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A denial is not activity: it cannot protect an expired bucket from reclaim."""
    _set_clock(monkeypatch, 0.0, 1.0, 2.0, 60.5)

    assert chapter_agent.check_rate_limit("oldest", max_requests=1) is True
    assert chapter_agent.check_rate_limit("newer", max_requests=1) is True
    assert chapter_agent.check_rate_limit("oldest", max_requests=1) is False
    assert list(chapter_agent._rate_limit_store) == ["oldest", "newer"]

    assert chapter_agent.check_rate_limit("newcomer", max_requests=1) is True
    assert list(chapter_agent._rate_limit_store) == ["newer", "newcomer"]


def test_known_key_at_capacity_remains_usable_and_refresh_moves_it_to_tail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The key cap blocks only unseen keys; a known key below quota still proceeds."""
    _set_clock(monkeypatch, 100.0, 101.0, 102.0)

    assert chapter_agent.check_rate_limit("alice", max_requests=2) is True
    assert chapter_agent.check_rate_limit("bob", max_requests=2) is True
    assert list(chapter_agent._rate_limit_store) == ["alice", "bob"]

    assert chapter_agent.check_rate_limit("alice", max_requests=2) is True
    assert list(chapter_agent._rate_limit_store) == ["bob", "alice"]
    assert len(chapter_agent._rate_limit_store["alice"]) == 2
    assert _capacity_metric().endswith(" 0")


class _RacingGetStore(OrderedDict[str, list[float]]):
    """Make two unlocked reads of one bucket observe the same old value."""

    def __init__(self) -> None:
        super().__init__()
        self._first_read = threading.Event()
        self._release_first = threading.Event()

    def get(self, key: str, default=None):  # type: ignore[no-untyped-def]
        value = list(super().get(key, default or []))
        if key == "shared":
            if not self._first_read.is_set():
                self._first_read.set()
                # With the production lock, the second caller cannot enter and
                # this bounded wait expires.  Without it, caller two releases us
                # after both captured the same pre-admission value.
                self._release_first.wait(timeout=0.2)
            else:
                self._release_first.set()
        return value


def test_concurrent_calls_cannot_exceed_one_keys_ceiling(monkeypatch: pytest.MonkeyPatch) -> None:
    """Two simultaneous first requests to a one-request bucket admit exactly one."""
    store = _RacingGetStore()
    monkeypatch.setattr(chapter_agent, "_rate_limit_store", store)
    monkeypatch.setattr(chapter_agent.time_mod, "monotonic", lambda: 100.0)
    start = threading.Barrier(3)

    def attempt() -> bool:
        start.wait(timeout=1)
        return chapter_agent.check_rate_limit("shared", max_requests=1)

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(attempt) for _ in range(2)]
        start.wait(timeout=1)
        admitted = [future.result(timeout=2) for future in futures]

    assert admitted.count(True) == 1
    assert len(store["shared"]) == 1


class _RacingCapacityStore(OrderedDict[str, list[float]]):
    """Make two unlocked capacity checks observe the same free slot."""

    def __init__(self) -> None:
        super().__init__()
        self._first_check = threading.Event()
        self._release_first = threading.Event()

    def __len__(self) -> int:
        size = super().__len__()
        if size == 1 and threading.current_thread() is not threading.main_thread():
            if not self._first_check.is_set():
                self._first_check.set()
                self._release_first.wait(timeout=0.2)
            else:
                self._release_first.set()
        return size


def test_concurrent_new_keys_cannot_race_past_store_capacity(monkeypatch: pytest.MonkeyPatch) -> None:
    """From cap-minus-one, two simultaneous new keys fill only the one free slot."""
    store = _RacingCapacityStore()
    store["existing"] = [100.0]
    monkeypatch.setattr(chapter_agent, "_rate_limit_store", store)
    monkeypatch.setattr(chapter_agent.time_mod, "monotonic", lambda: 101.0)
    start = threading.Barrier(3)

    def attempt(key: str) -> bool:
        start.wait(timeout=1)
        return chapter_agent.check_rate_limit(key)

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(attempt, key) for key in ("new-a", "new-b")]
        start.wait(timeout=1)
        admitted = [future.result(timeout=2) for future in futures]

    assert admitted.count(True) == 1
    assert len(store) == chapter_agent.RATE_LIMIT_KEY_CAP


def test_concurrent_capacity_denials_each_increment_the_bounded_metric(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Concurrent unseen-key refusals are counted without attacker labels or loss."""
    monkeypatch.setattr(chapter_agent, "RATE_LIMIT_KEY_CAP", 1)
    monkeypatch.setattr(chapter_agent.time_mod, "monotonic", lambda: 101.0)
    chapter_agent._rate_limit_store["existing"] = [100.0]
    start = threading.Barrier(5)

    def attempt(key: str) -> bool:
        start.wait(timeout=1)
        return chapter_agent.check_rate_limit(key)

    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = [pool.submit(attempt, f"new-{index}") for index in range(4)]
        start.wait(timeout=1)
        admitted = [future.result(timeout=2) for future in futures]

    assert admitted == [False, False, False, False]
    assert _capacity_metric() == (
        'nanda_chapter_rate_limit_capacity_rejections_total{chapter_id="test"} 4'
    )


def test_per_key_quota_denial_does_not_increment_capacity_metric(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The new metric distinguishes store saturation from an ordinary quota 429."""
    _set_clock(monkeypatch, 100.0, 101.0)

    assert chapter_agent.check_rate_limit("alice", max_requests=1) is True
    assert chapter_agent.check_rate_limit("alice", max_requests=1) is False
    assert _capacity_metric().endswith(" 0")


def test_capacity_saturation_keeps_existing_middleware_429_shape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Store saturation is surfaced through the same stable write-rate response."""
    monkeypatch.setattr(chapter_agent, "RATE_LIMIT_KEY_CAP", 1)
    monkeypatch.setattr(chapter_agent.time_mod, "monotonic", lambda: 101.0)
    chapter_agent._rate_limit_store["occupied"] = [100.0]

    response = TestClient(chapter_agent.app).post("/api/members", json={})

    assert response.status_code == 429
    assert response.json() == {
        "error": "Rate limit exceeded.",
        "limit_per_window": chapter_agent.RATE_LIMIT_MAX,
        "window_seconds": chapter_agent.RATE_LIMIT_WINDOW,
    }
    assert response.headers["Retry-After"] == str(chapter_agent.RATE_LIMIT_WINDOW)
