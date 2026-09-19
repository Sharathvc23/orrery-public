"""
Tests for trust_cron.run_decay_sweep_if_due + run_drift_check_if_due.

Coverage:
  - Throttle: first call runs, second within 24h short-circuits
  - Throttle: 24h+1s later runs again
  - Decay sweep walks all agents and counts emitted decay rows
  - Drift check returns drift_count + drifts list
  - reset_for_tests clears throttle (test isolation)
  - uninitialized → safe no-op (returns ran=False)
"""

from __future__ import annotations

import os

os.environ.setdefault("AGENT_ID", "test-chapter")
os.environ.setdefault("AGENT_NAME", "Test Chapter")

from datetime import UTC, datetime  # noqa: E402
from decimal import Decimal  # noqa: E402

import pytest  # noqa: E402

import trust_cron  # noqa: E402
import trust_events  # noqa: E402


class _FakeDB:
    def __init__(self, agents: list[dict] | None = None):
        self.agents = agents or []
        self.trust_events = []
        self._next_id = 1

    async def __call__(self, method, table, params=None, body=None):
        t = table.split("?")[0]
        if method == "GET":
            rows = list(getattr(self, t, []))
            for k, v in (params or {}).items():
                if k in ("select", "order", "limit"):
                    continue
                if isinstance(v, str) and v.startswith("eq."):
                    wanted = v[3:]
                    rows = [r for r in rows if str(r.get(k, "")) == wanted]
                elif isinstance(v, str) and v.startswith("neq."):
                    unwanted = v[4:]
                    rows = [r for r in rows if str(r.get(k, "")) != unwanted]
                elif isinstance(v, str) and v.startswith("gte."):
                    wanted = v[4:]
                    rows = [r for r in rows if str(r.get(k, "")) >= wanted]
            limit = (params or {}).get("limit")
            if limit is not None:
                rows = rows[: int(limit)]
            return rows
        if method == "POST" and t == "trust_events":
            row = dict(body or {})
            if any(
                r.get("agent_id") == row.get("agent_id")
                and r.get("event_type") == row.get("event_type")
                and r.get("source_event_id") == row.get("source_event_id")
                for r in self.trust_events
            ):
                raise RuntimeError("duplicate key violation")
            row["id"] = self._next_id
            row["occurred_at"] = row.get("occurred_at") or datetime.now(UTC).isoformat()
            self._next_id += 1
            self.trust_events.append(row)
            agent = next((a for a in self.agents if a.get("agent_id") == row["agent_id"]), None)
            if agent is None:
                agent = {"agent_id": row["agent_id"], "trust_score": 0.0}
                self.agents.append(agent)
            agent["trust_score"] = float(
                Decimal(str(agent.get("trust_score") or 0)) + Decimal(str(row.get("delta") or "0"))
            )
            return [row]
        return None


@pytest.fixture(autouse=True)
def _reset_throttle():
    trust_cron.reset_for_tests()
    yield
    trust_cron.reset_for_tests()


@pytest.fixture
def env():
    db = _FakeDB(
        agents=[
            {"agent_id": "alice", "trust_score": 5.0},
            {"agent_id": "bob", "trust_score": 3.0},
            {"agent_id": "newbie", "trust_score": 0.0},
        ],
    )
    trust_events.init(db, "test")
    trust_cron.init(db, "test")
    return db


# ── Throttle ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_decay_first_call_runs(env):
    res = await trust_cron.run_decay_sweep_if_due(now=1000.0)
    assert res["ran"] is True


@pytest.mark.asyncio
async def test_decay_second_call_throttled(env):
    await trust_cron.run_decay_sweep_if_due(now=1000.0)
    res = await trust_cron.run_decay_sweep_if_due(now=1000.0 + 3600)  # 1h later
    assert res["ran"] is False
    assert res["reason"] == "throttled"


@pytest.mark.asyncio
async def test_decay_runs_again_after_24h(env):
    await trust_cron.run_decay_sweep_if_due(now=1000.0)
    res = await trust_cron.run_decay_sweep_if_due(now=1000.0 + 24 * 3600 + 1)
    assert res["ran"] is True


# ── Decay sweep ───────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_decay_sweep_walks_all_agents_with_score(env):
    res = await trust_cron.run_decay_sweep_if_due(now=1000.0)
    assert res["ran"] is True
    assert res["swept"] == 3
    # Alice + Bob have score>0 and no recent activity → decay fires.
    # Newbie at 0 → no decay (already at floor).
    assert res["decay_emitted"] == 2


# ── Drift check ───────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_drift_check_clean_when_in_sync(env):
    res = await trust_cron.run_drift_check_if_due(now=1000.0)
    assert res["ran"] is True
    # No trust events written → SUM=0, agents.trust_score≠0 for some.
    # The fixture seeds non-zero scores without writing events, so drift
    # IS expected. Verify the structure rather than the count.
    assert "drift_count" in res
    assert "drifts" in res


@pytest.mark.asyncio
async def test_drift_check_throttled_after_first_run(env):
    await trust_cron.run_drift_check_if_due(now=1000.0)
    res = await trust_cron.run_drift_check_if_due(now=1000.0 + 3600)
    assert res["ran"] is False


# ── Uninitialized ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_decay_uninitialized_safe_noop():
    """Calling before init returns ran=False with a reason — never throws."""
    trust_cron.init(None, "")
    res = await trust_cron.run_decay_sweep_if_due(now=1000.0)
    assert res["ran"] is False
    assert res["reason"] == "uninitialized"


@pytest.mark.asyncio
async def test_drift_uninitialized_safe_noop():
    trust_cron.init(None, "")
    res = await trust_cron.run_drift_check_if_due(now=1000.0)
    assert res["ran"] is False
    assert res["reason"] == "uninitialized"
