"""Tests for trust-tier gating at delivery time (EB-5).

The whole point: a subscriber with trust_score < threshold for an
event type does NOT receive events of that type. Pre-existing
event_log entries are NOT replayed when the subscriber gets promoted
(no backfill — that would be a security regression).

  * filter_events_for_trust: per-event threshold drop, closed-set
    semantics (unknown event_type → drop), boundary at threshold,
    multiple tiers in one batch
  * get_subscriber_trust_score: PostgREST query shape, default 0.0
    on missing row / null column / Postgres failure, cache TTL behaviour
"""

from __future__ import annotations

import time
from typing import Any

import pytest

import trust_gate
from event_types import EventType


@pytest.fixture(autouse=True)
def _reset_trust_gate():
    trust_gate._pg_request = None
    trust_gate._clear_cache_for_tests()
    yield
    trust_gate._pg_request = None
    trust_gate._clear_cache_for_tests()


class FakePostgres:
    def __init__(self, *, return_value: Any = None) -> None:
        self.calls: list[tuple] = []
        self._return_value = return_value

    async def __call__(self, method, table, params=None, body=None):
        self.calls.append((method, table, params, body))
        if callable(self._return_value):
            return self._return_value()
        return self._return_value


# ── filter_events_for_trust() — the core gating function ─────────────


def test_filter_drops_above_threshold() -> None:
    """Subscriber at trust 0 must NOT receive intent.matched (tier 25)."""
    rows = [
        {"id": 1, "event_type": "member.joined"},  # tier 0
        {"id": 2, "event_type": "intent.matched"},  # tier 25
    ]
    out = trust_gate.filter_events_for_trust(rows, 0.0)
    assert [r["id"] for r in out] == [1]


def test_filter_passes_at_threshold() -> None:
    """Boundary: trust_score == threshold MUST pass. 'min trust' is
    inclusive — a verified member at 25 sees verified-tier events."""
    rows = [{"id": 1, "event_type": "intent.matched"}]  # tier 25
    out = trust_gate.filter_events_for_trust(rows, 25.0)
    assert len(out) == 1


def test_filter_passes_above_threshold() -> None:
    rows = [{"id": 1, "event_type": "intent.matched"}]  # tier 25
    out = trust_gate.filter_events_for_trust(rows, 99.9)
    assert len(out) == 1


def test_filter_keeps_only_authorized_events_in_mixed_batch() -> None:
    """Realistic SSE batch — multiple event types at different tiers."""
    rows = [
        {"id": 1, "event_type": "member.joined"},  # tier 0
        {"id": 2, "event_type": "intent.published"},  # tier 0
        {"id": 3, "event_type": "intent.matched"},  # tier 25
        {"id": 4, "event_type": "member.left"},  # tier 25
        {"id": 5, "event_type": "chapter.broadcast"},  # tier 25
    ]
    # Anonymous subscriber at 0 sees only tier-0, NOT tier-25
    anon = trust_gate.filter_events_for_trust(rows, 0.0)
    assert [r["id"] for r in anon] == [1, 2]
    # Verified member at 25 sees tier-0 + tier-25
    out = trust_gate.filter_events_for_trust(rows, 25.0)
    assert [r["id"] for r in out] == [1, 2, 3, 4, 5]


def test_filter_drops_unknown_event_type_safely() -> None:
    """Defensive — an event_type the catalog doesn't know about gets
    dropped, NOT passed through. Safe-by-default failure mode."""
    rows = [
        {"id": 1, "event_type": "member.joined"},  # known
        {"id": 2, "event_type": "future.unknown.type"},  # unknown
    ]
    out = trust_gate.filter_events_for_trust(rows, 100.0)
    assert [r["id"] for r in out] == [1]


def test_filter_empty_batch_returns_empty() -> None:
    assert trust_gate.filter_events_for_trust([], 0.0) == []


def test_filter_every_event_type_has_a_threshold_in_table() -> None:
    """Catalog parity proof — if a future EventType lands without a
    MIN_TRUST_TO_SUBSCRIBE entry, the filter drops it (safe). The
    test_event_types.py suite enforces the inverse at the table layer;
    this one proves filter behaviour stays safe even if that test is
    accidentally weakened."""
    for et in EventType:
        rows = [{"id": 1, "event_type": et.value}]
        # A leader-tier subscriber (75) sees every documented event type
        out = trust_gate.filter_events_for_trust(rows, 75.0)
        assert len(out) == 1, f"{et.value} should be visible at trust 75"


# ── get_subscriber_trust_score() — Postgres + cache ──────────────────


@pytest.mark.asyncio
async def test_get_score_reads_from_agents_table() -> None:
    sb = FakePostgres(return_value=[{"trust_score": 42.5}])
    trust_gate.init(sb)

    score = await trust_gate.get_subscriber_trust_score("alice")

    assert score == 42.5
    method, table, params, _ = sb.calls[0]
    assert (method, table) == ("GET", "agents")
    assert params["agent_id"] == "eq.alice"
    assert params["select"] == "trust_score"
    assert params["limit"] == "1"


@pytest.mark.asyncio
async def test_get_score_defaults_to_zero_when_agent_missing() -> None:
    """A subscriber whose row doesn't exist (race condition, deleted
    member) gets trust 0 — they only see public events. Safer than
    crashing the stream."""
    sb = FakePostgres(return_value=[])
    trust_gate.init(sb)

    score = await trust_gate.get_subscriber_trust_score("ghost")
    assert score == 0.0


@pytest.mark.asyncio
async def test_get_score_defaults_to_zero_on_null_column() -> None:
    sb = FakePostgres(return_value=[{"trust_score": None}])
    trust_gate.init(sb)
    assert await trust_gate.get_subscriber_trust_score("alice") == 0.0


@pytest.mark.asyncio
async def test_get_score_defaults_to_zero_on_supabase_failure() -> None:
    sb = FakePostgres(return_value=None)
    trust_gate.init(sb)
    assert await trust_gate.get_subscriber_trust_score("alice") == 0.0


@pytest.mark.asyncio
async def test_get_score_defaults_to_zero_on_exception() -> None:
    """Postgres exception (network error, timeout) must NOT crash the
    stream — surface 0.0 and the keepalive loop continues."""

    async def _boom(*args, **kwargs):
        raise RuntimeError("network exploded")

    trust_gate.init(_boom)
    score = await trust_gate.get_subscriber_trust_score("alice")
    assert score == 0.0


@pytest.mark.asyncio
async def test_get_score_caches_for_ttl() -> None:
    """Two reads in quick succession must hit Postgres exactly once."""
    sb = FakePostgres(return_value=[{"trust_score": 50.0}])
    trust_gate.init(sb)

    s1 = await trust_gate.get_subscriber_trust_score("alice")
    s2 = await trust_gate.get_subscriber_trust_score("alice")
    assert s1 == s2 == 50.0
    assert len(sb.calls) == 1, "cache must absorb the second read"


@pytest.mark.asyncio
async def test_get_score_re_reads_after_ttl_expires() -> None:
    sb = FakePostgres(return_value=[{"trust_score": 50.0}])
    trust_gate.init(sb)

    await trust_gate.get_subscriber_trust_score("alice", cache_ttl_s=0.0)
    # Force expiry — TTL=0 means cache is stale by the time the next call
    # happens. Sleep 1ns to ensure time.time() advances.
    time.sleep(0.01)
    await trust_gate.get_subscriber_trust_score("alice", cache_ttl_s=0.0)
    assert len(sb.calls) == 2, "expired cache should trigger re-read"


@pytest.mark.asyncio
async def test_get_score_returns_zero_when_uninitialised() -> None:
    """No init() called — safe default 0.0, no crash."""
    assert await trust_gate.get_subscriber_trust_score("alice") == 0.0
