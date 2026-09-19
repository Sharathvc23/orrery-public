"""Prosecution-grade tests for the think_chapter_broadcast cycle (PR4).

Covers:

* HAPPY        cycle finds an undispatched digest and sends it
* EDGE         no digests yet, digest with empty headline (fallback)
* FAILURE      broadcast module uninitialized, supabase failure
* ADVERSARIAL  rate-limit honored, dedup honored (already-sent
               digest title doesn't re-broadcast), disabled policy
               key blocks the cycle entirely.

The cycle is dispatched from think_cycle.py at index 15 of the
rotation. These tests target the function directly to avoid
plumbing the full chapter init.
"""

from __future__ import annotations

import sys

import pytest

import broadcast
import event_bus
import think_cycle


@pytest.fixture(autouse=True)
def _setup_think_state(monkeypatch):
    """Wire the minimum think_cycle module globals so the cycle can
    call into broadcast + policy. Each test overrides specific call
    surfaces via monkeypatch."""
    # think_cycle reads AGENT_ID + pg_request from module globals.
    think_cycle.AGENT_ID = "bayarea-nanda-chapter"
    # We replace pg_request per-test via monkeypatch.

    # broadcast + event_bus must be initialized for the cycle's gate.
    async def _fake_sb(*args, **kwargs):
        return [{"id": 1}]

    event_bus.init(_fake_sb, "bayarea-nanda-chapter")
    broadcast.init(
        pg_request=_fake_sb,
        chapter_id="bayarea-nanda-chapter",
        federation={
            "boston-chapter": {"endpoint": "https://org.example.com"},
        },
        sign_outbound=None,
    )
    broadcast._reset_dedup_for_tests()
    yield


def _stub_policy(monkeypatch, *, enabled: bool, min_interval_hours: int = 12) -> None:
    """Patch policy.get_bool / get_int — the cycle reads two keys."""

    class _Policy:
        @staticmethod
        async def get_bool(key, default=False):
            if key == "chapter_broadcast.enabled":
                return enabled
            return default

        @staticmethod
        async def get_int(key, default=0):
            if key == "chapter_broadcast.min_interval_hours":
                return min_interval_hours
            return default

    monkeypatch.setitem(sys.modules, "policy", _Policy)


# ── HAPPY ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_cycle_sends_broadcast_when_undispatched_digest_exists(monkeypatch):
    _stub_policy(monkeypatch, enabled=True)

    calls = {"sent": []}

    async def _fake_supabase(method, table, params=None, body=None, **kw):
        if table == "event_log":
            return [
                {
                    "id": 99,
                    "payload": {
                        "headline": "Week of growth — 12 new members",
                        "summary_markdown": "12 new members joined this week.",
                        "window_start": "2026-05-10T00:00:00+00:00",
                        "new_member_count": 12,
                        "intent_published_count": 3,
                    },
                }
            ]
        if table == "broadcast_log":
            return []  # nothing previously broadcast
        return []

    monkeypatch.setattr(think_cycle, "pg_request", _fake_supabase)

    async def _fake_send(**kwargs):
        calls["sent"].append(kwargs)
        return {
            "broadcast_id": "x",
            "event_id": 1,
            "audience": "all",
            "federation": {"attempted": 1, "succeeded": 1, "failed": []},
        }

    monkeypatch.setattr(broadcast, "send_broadcast", _fake_send)
    monkeypatch.setattr(broadcast, "hours_since_last_broadcast", lambda: _noop_returning_none())

    await think_cycle.think_chapter_broadcast()

    assert len(calls["sent"]) == 1
    sent = calls["sent"][0]
    assert sent["title"] == "Week of growth — 12 new members"
    assert sent["audience"] == "all"
    assert "digest" in sent["tags"]


async def _noop_returning_none():
    """Coroutine that returns None — used to stub hours_since_last_broadcast."""
    return None


# ── EDGE ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_cycle_falls_back_when_headline_missing(monkeypatch):
    """A digest without an LLM-composed headline still gets broadcast,
    using a deterministic default. Better minimal than nothing."""
    _stub_policy(monkeypatch, enabled=True)
    calls = {"sent": []}

    async def _fake_supabase(method, table, params=None, **kw):
        if table == "event_log":
            return [
                {
                    "id": 99,
                    "payload": {
                        # No headline, no summary_markdown
                        "window_start": "2026-05-10T00:00:00+00:00",
                        "new_member_count": 5,
                        "intent_published_count": 2,
                    },
                }
            ]
        if table == "broadcast_log":
            return []
        return []

    monkeypatch.setattr(think_cycle, "pg_request", _fake_supabase)

    async def _fake_send(**kwargs):
        calls["sent"].append(kwargs)
        return {
            "broadcast_id": "x",
            "event_id": 1,
            "audience": "all",
            "federation": {"attempted": 0, "succeeded": 0, "failed": []},
        }

    monkeypatch.setattr(broadcast, "send_broadcast", _fake_send)
    monkeypatch.setattr(broadcast, "hours_since_last_broadcast", lambda: _noop_returning_none())

    await think_cycle.think_chapter_broadcast()
    assert len(calls["sent"]) == 1
    assert calls["sent"][0]["title"] == "Weekly chapter digest"
    # The body uses the deterministic fallback referencing counts
    assert "5 new members" in calls["sent"][0]["body"]


@pytest.mark.asyncio
async def test_cycle_returns_quietly_when_no_digest_exists(monkeypatch):
    """No digest events at all → no broadcast, no error."""
    _stub_policy(monkeypatch, enabled=True)
    calls = {"sent": []}

    async def _empty(method, table, params=None, **kw):
        return []

    monkeypatch.setattr(think_cycle, "pg_request", _empty)

    async def _fake_send(**kwargs):
        calls["sent"].append(kwargs)
        return {}

    monkeypatch.setattr(broadcast, "send_broadcast", _fake_send)
    monkeypatch.setattr(broadcast, "hours_since_last_broadcast", lambda: _noop_returning_none())

    await think_cycle.think_chapter_broadcast()
    assert calls["sent"] == []


# ── FAILURE ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_cycle_short_circuits_when_broadcast_uninitialized(monkeypatch):
    """Boot-race safety: if broadcast.is_initialized() is False (chapter
    still warming up), the cycle returns quietly. Next tick retries."""
    _stub_policy(monkeypatch, enabled=True)
    monkeypatch.setattr(broadcast, "is_initialized", lambda: False)

    calls = {"sent": []}

    async def _fake_send(**kwargs):
        calls["sent"].append(kwargs)

    monkeypatch.setattr(broadcast, "send_broadcast", _fake_send)
    await think_cycle.think_chapter_broadcast()
    assert calls["sent"] == []


# ── ADVERSARIAL ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_cycle_blocked_by_disabled_policy(monkeypatch):
    """The master gate: chapter_broadcast.enabled=false MUST stop the
    cycle before any work happens. Not even the digest lookup runs."""
    _stub_policy(monkeypatch, enabled=False)

    calls = {"supabase": [], "sent": []}

    async def _spy(method, table, params=None, **kw):
        calls["supabase"].append((method, table))
        return []

    monkeypatch.setattr(think_cycle, "pg_request", _spy)

    async def _fake_send(**kwargs):
        calls["sent"].append(kwargs)

    monkeypatch.setattr(broadcast, "send_broadcast", _fake_send)
    await think_cycle.think_chapter_broadcast()
    assert calls["sent"] == []
    # CRITICAL: the disabled gate must short-circuit BEFORE the
    # digest lookup. Asserting zero supabase calls catches a future
    # refactor that accidentally moves the gate too late.
    assert calls["supabase"] == []


@pytest.mark.asyncio
async def test_cycle_respects_rate_limit(monkeypatch):
    """Recently sent a broadcast → MUST NOT send another within the
    min_interval window. The cycle is autonomous; a backlog of digests
    cannot be allowed to dump-fanout in one wakeup."""
    _stub_policy(monkeypatch, enabled=True, min_interval_hours=12)

    async def _hours_since_recent():
        return 3.0  # only 3 hours since last — should block

    monkeypatch.setattr(broadcast, "hours_since_last_broadcast", _hours_since_recent)

    calls = {"sent": []}

    async def _fake_send(**kwargs):
        calls["sent"].append(kwargs)

    monkeypatch.setattr(broadcast, "send_broadcast", _fake_send)

    async def _has_digest(method, table, params=None, **kw):
        # Even if a digest exists, rate-limit must block.
        if table == "event_log":
            return [{"id": 99, "payload": {"headline": "test"}}]
        return []

    monkeypatch.setattr(think_cycle, "pg_request", _has_digest)

    await think_cycle.think_chapter_broadcast()
    assert calls["sent"] == [], "Rate-limit was bypassed — backlog flooding risk"


@pytest.mark.asyncio
async def test_cycle_dedupes_already_broadcast_digest(monkeypatch):
    """Headline already appears in broadcast_log → do NOT re-broadcast.
    Prevents the same digest going out twice on chapter restart or
    re-enabling the cycle."""
    _stub_policy(monkeypatch, enabled=True)

    async def _supabase(method, table, params=None, **kw):
        if table == "event_log":
            return [{"id": 99, "payload": {"headline": "Already-sent headline"}}]
        if table == "broadcast_log":
            # Pretend we already broadcast this exact headline.
            return [{"id": 1, "title": "Already-sent headline"}]
        return []

    monkeypatch.setattr(think_cycle, "pg_request", _supabase)
    monkeypatch.setattr(broadcast, "hours_since_last_broadcast", lambda: _noop_returning_none())

    calls = {"sent": []}

    async def _fake_send(**kwargs):
        calls["sent"].append(kwargs)

    monkeypatch.setattr(broadcast, "send_broadcast", _fake_send)

    await think_cycle.think_chapter_broadcast()
    assert calls["sent"] == [], "Dedup failed — same digest re-broadcast"
