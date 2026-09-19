"""Weekly digest gate inside ``think_digest``.

The legacy ``think_digest`` writes to ``agent_digests`` + ``agent_thoughts``
on its existing 24h gate. THIS test pins the additional behavior that was
added so subscribers see a fresh ``chapter.digest.weekly`` event at most
once per chapter per 7 days:

  - last event in event_log is None         → publish_digest IS called
  - last event in event_log was 8 days ago  → publish_digest IS called
  - last event in event_log was 1 day ago   → publish_digest is NOT called
  - publish_digest raises                   → think_digest does NOT raise

The 24h legacy gate runs FIRST and short-circuits the cycle when a
recent digest exists. The tests below disable that legacy gate (no
``agent_digests`` rows) so the weekly bus logic always runs.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

os.environ.setdefault("AGENT_ID", "test-chapter")
os.environ.setdefault("AGENT_NAME", "Test Chapter")

import pytest  # noqa: E402

import think_cycle  # noqa: E402

# ── Test scaffolding ────────────────────────────────────────────────


class _FakePostgres:
    """Pluggable async stand-in for ``pg_request``.

    Records every call so tests can assert which queries fired. Each
    test seeds ``event_log_response`` to control what the weekly gate
    sees on read.
    """

    def __init__(self, event_log_response: list[dict] | None = None):
        self.event_log_response = event_log_response or []
        self.calls: list[tuple[str, str, dict]] = []

    async def __call__(self, method: str, table: str, **kwargs):
        self.calls.append((method, table, kwargs))
        # Legacy 24h gate read — return empty so it doesn't short-circuit.
        if table == "agent_digests" and method == "GET":
            return []
        if table == "event_log" and method == "GET":
            return list(self.event_log_response)
        if table == "agent_thoughts" and method == "GET":
            return []
        if table == "startup_ideas" and method == "GET":
            return []
        # Writes — accept silently.
        return [{"id": "noop"}]


class _StubLLM:
    """xAI/OpenAI-shaped client stub so the cycle's narrative-gen call
    doesn't try to hit the network."""

    class _Chat:
        class _Completions:
            @staticmethod
            def create(**_kw):
                class _Msg:
                    content = "stub digest summary"

                class _Choice:
                    message = _Msg()

                class _Resp:
                    choices = [_Choice()]

                return _Resp()

        completions = _Completions()

    chat = _Chat()


@pytest.fixture
def cycle(monkeypatch):
    """Install minimal state so ``think_digest`` runs end-to-end."""

    # Helpers / injected hooks — async no-ops, since we're testing the
    # publish gate, not the legacy digest content.
    async def _aiono_op(*_a, **_kw):
        return None

    monkeypatch.setattr(think_cycle, "log_agent_thought", _aiono_op)
    monkeypatch.setattr(think_cycle, "AGENT_ID", "test-chapter")
    monkeypatch.setattr(think_cycle, "AGENT_NAME", "Test Chapter")
    monkeypatch.setattr(think_cycle, "AGENT_FOCUS", "testing")
    monkeypatch.setattr(think_cycle, "AGENT_DESCRIPTION", "test")
    monkeypatch.setattr(think_cycle, "DEFAULT_LLM_MODEL", "stub")
    monkeypatch.setattr(think_cycle, "llm", _StubLLM())
    monkeypatch.setattr(think_cycle, "members", {"m1": {"name": "Alice"}})
    monkeypatch.setattr(think_cycle, "federation", {})
    return think_cycle


# ── HAPPY: no prior weekly event ────────────────────────────────────


@pytest.mark.asyncio
async def test_publish_called_when_no_prior_weekly_event(cycle, monkeypatch):
    """First ever digest cycle has nothing in event_log → publishes."""
    fake_sb = _FakePostgres(event_log_response=[])
    monkeypatch.setattr(cycle, "pg_request", fake_sb)

    publish_calls: list[int] = []

    async def _fake_publish(window_days: int = 7):
        publish_calls.append(window_days)
        return 42

    import digest as digest_mod

    monkeypatch.setattr(digest_mod, "publish_digest", _fake_publish)

    await cycle.think_digest()

    assert publish_calls == [7], "weekly publish must fire with window_days=7"
    event_log_reads = [c for c in fake_sb.calls if c[1] == "event_log"]
    assert event_log_reads, "must consult event_log for last weekly publish timestamp"


# ── EDGE: prior event is older than 7 days ──────────────────────────


@pytest.mark.asyncio
async def test_publish_called_when_prior_weekly_is_stale(cycle, monkeypatch):
    """Last weekly was 8 days ago → window has elapsed → publishes again."""
    eight_days_ago = (datetime.now(UTC) - timedelta(days=8)).isoformat().replace("+00:00", "Z")
    fake_sb = _FakePostgres(event_log_response=[{"id": 7, "created_at": eight_days_ago}])
    monkeypatch.setattr(cycle, "pg_request", fake_sb)

    publish_calls: list[int] = []

    async def _fake_publish(window_days: int = 7):
        publish_calls.append(window_days)
        return 99

    import digest as digest_mod

    monkeypatch.setattr(digest_mod, "publish_digest", _fake_publish)

    await cycle.think_digest()

    assert publish_calls == [7], "stale prior weekly must allow republish"


# ── FAILURE: prior event is fresh ───────────────────────────────────


@pytest.mark.asyncio
async def test_publish_suppressed_when_prior_weekly_is_fresh(cycle, monkeypatch):
    """Last weekly was 1 day ago → still inside 7d window → suppresses."""
    one_day_ago = (datetime.now(UTC) - timedelta(days=1)).isoformat().replace("+00:00", "Z")
    fake_sb = _FakePostgres(event_log_response=[{"id": 7, "created_at": one_day_ago}])
    monkeypatch.setattr(cycle, "pg_request", fake_sb)

    publish_calls: list[int] = []

    async def _fake_publish(window_days: int = 7):
        publish_calls.append(window_days)
        return 100

    import digest as digest_mod

    monkeypatch.setattr(digest_mod, "publish_digest", _fake_publish)

    await cycle.think_digest()

    assert publish_calls == [], "weekly publish must be suppressed when last weekly event is <7d old"


# ── REGRESSION: legacy 24h gate must NOT block the bus publish ──────


@pytest.mark.asyncio
async def test_legacy_24h_gate_does_not_block_bus_publish(cycle, monkeypatch):
    """The crux of the decoupling. When the legacy ``agent_digests``
    table has a row from <24h ago, the legacy code path early-returns.
    But the event-bus publish is INDEPENDENT — it must still evaluate
    its own 7-day gate and fire when applicable.

    This pins the bug found on prod 2026-05-11: original PR
    nested the bus publish under the legacy gate, so the bus stayed
    silent for ~24h after every legacy digest write.
    """
    # Force the legacy 24h gate to FIRE (return value is non-empty +
    # recent), so the legacy code path early-returns. The fake supabase
    # only returns this row for agent_digests GETs.
    recent_legacy = (datetime.now(UTC) - timedelta(hours=2)).isoformat().replace("+00:00", "Z")

    class _LegacyFreshPostgres(_FakePostgres):
        async def __call__(self, method, table, **kwargs):
            self.calls.append((method, table, kwargs))
            if table == "agent_digests" and method == "GET":
                # Recent → triggers legacy early-return
                return [{"id": "x", "created_at": recent_legacy}]
            if table == "event_log" and method == "GET":
                return list(self.event_log_response)
            return [{"id": "noop"}]

    fake_sb = _LegacyFreshPostgres(event_log_response=[])  # empty event_log → bus should publish
    monkeypatch.setattr(cycle, "pg_request", fake_sb)

    publish_calls: list[int] = []

    async def _fake_publish(window_days: int = 7):
        publish_calls.append(window_days)
        return 555

    import digest as digest_mod

    monkeypatch.setattr(digest_mod, "publish_digest", _fake_publish)

    await cycle.think_digest()

    assert publish_calls == [7], (
        "Bus publish must fire even when the legacy 24h gate forces an "
        "early return. The two gates govern different cadences."
    )


# ── ADVERSARIAL: publish_digest raises ──────────────────────────────


@pytest.mark.asyncio
async def test_publish_failure_does_not_wedge_cycle(cycle, monkeypatch):
    """digest_mod.publish_digest raising must NOT propagate out of
    think_digest. The legacy agent_digests write is the source of truth;
    the event-bus broadcast is additive and best-effort."""
    fake_sb = _FakePostgres(event_log_response=[])
    monkeypatch.setattr(cycle, "pg_request", fake_sb)

    async def _boom(window_days: int = 7):
        raise RuntimeError("LLM credit exhausted")

    import digest as digest_mod

    monkeypatch.setattr(digest_mod, "publish_digest", _boom)

    # Must NOT raise. (Asserting absence of exception is the whole point.)
    await cycle.think_digest()
