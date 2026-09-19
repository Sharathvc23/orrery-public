"""Durable per-agent scheduler.

Classification: HAPPY / EDGE / FAILURE / ADVERSARIAL

The three properties under test are the three the crude timer lacked:
durability across restart, spread across a fleet, and structural inability to
become the busy loop PR3 removed from the LLM path. The last one carries the
most tests, because "retries a permanent error forever" is the failure that
already happened once and it was invisible until someone counted requests.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

import agent_scheduler
import retry_policy

NOW = datetime(2026, 8, 5, 12, 0, 0, tzinfo=UTC)


class _Boom(Exception):
    """Stand-in for a provider error carrying an HTTP status."""

    def __init__(self, status: int):
        self.status_code = status
        super().__init__(f"HTTP {status}")


# ── The shared discipline is SHARED, not re-derived ────────────────


def test_retry_policy_is_byte_identical_to_the_agent_copy():
    """dev's PR3 module says: "import or copy this file whole; do not re-derive
    the table". A copy that drifts is two disciplines wearing one name, which
    is the thing the instruction exists to prevent."""
    repo = Path(__file__).resolve().parents[2]
    vendored = (repo / "server" / "retry_policy.py").read_bytes()
    upstream = (repo / "agent" / "community_member" / "retry_policy.py").read_bytes()
    assert vendored == upstream, (
        "server/retry_policy.py has drifted from agent/community_member/retry_policy.py — "
        "re-copy it whole rather than editing one side"
    )


def test_the_scheduler_does_not_define_its_own_status_table():
    """A second opinion about whether a 402 is retryable is exactly the drift
    PR3 warned about."""
    src = (Path(__file__).resolve().parents[2] / "server" / "agent_scheduler.py").read_text()
    for leaked in ("429", "RETRYABLE_STATUSES = ", "TERMINAL_STATUSES = "):
        assert leaked not in src, f"agent_scheduler re-derives retry policy ({leaked!r})"


# ── ADVERSARIAL: it must not be able to spin ───────────────────────


@pytest.mark.parametrize("status", [400, 401, 402, 403, 404, 413, 422])
def test_a_terminal_failure_stops_the_agent_rather_than_backing_off(status):
    """THE PR3 REGRESSION, one layer up. A permanent error retried on a
    ten-minute cadence is still an infinite loop — just a politer one that
    still bills forever. Terminal means STOP."""
    d = agent_scheduler.after_failure(_Boom(status), now=NOW, consecutive_failures=0, rand=0.5)
    assert d.paused, f"HTTP {status} must pause the agent, not reschedule it"
    assert d.next_run_at is None, "a paused agent must have no next run time at all"
    assert str(status) in d.paused_reason or "STOPPING" in d.paused_reason


@pytest.mark.parametrize("status", [429, 500, 502, 503, 504, 408])
def test_a_retryable_failure_backs_off_instead_of_stopping(status):
    d = agent_scheduler.after_failure(_Boom(status), now=NOW, consecutive_failures=0, rand=0.5)
    assert not d.paused
    assert d.next_run_at > NOW


def test_backoff_grows_and_is_capped():
    delays = []
    for n in range(0, 12):
        d = agent_scheduler.after_failure(_Boom(503), now=NOW, consecutive_failures=n, rand=0.5)
        delays.append((d.next_run_at - NOW).total_seconds())
    assert delays[0] < delays[1] < delays[2], "backoff must grow"
    assert max(delays) <= retry_policy.BACKOFF_CAP_SEC * (1 + agent_scheduler.JITTER_FRACTION) + 1


def test_an_unclassifiable_error_stops_rather_than_retries():
    """PR3's deliberate default: an unrecognised exception here is usually OUR
    bug, and retrying our own bug forever is the failure being removed."""
    d = agent_scheduler.after_failure(
        AttributeError("planner contract changed"), now=NOW, consecutive_failures=0, rand=0.5
    )
    assert d.paused


@pytest.mark.parametrize("raw", ["0", "-5", "abc", "", "   ", "0.0"])
def test_a_bad_interval_never_produces_a_zero_delay(raw):
    """A scheduler that reads THINK_INTERVAL=abc and decides to run
    continuously has turned a typo into a billing incident."""
    assert agent_scheduler.interval_seconds({"COMMUNITY_MEMBER_THINK_INTERVAL": raw}) >= agent_scheduler.MIN_INTERVAL_S


def test_jitter_can_never_return_a_non_positive_delay():
    """rand=0.0 is maximum negative jitter; on a small interval that must still
    not reach zero, or the loop stops yielding."""
    for interval in (1.0, 1.5, 5.0, 300.0):
        assert agent_scheduler.jittered(interval, rand=0.0) >= agent_scheduler.MIN_INTERVAL_S


def test_a_paused_agent_is_not_resumed_by_time_alone():
    """Auto-resuming a terminal failure on a timer is retrying by another
    name — the condition cannot clear on its own."""
    d = agent_scheduler.after_failure(_Boom(401), now=NOW, consecutive_failures=3, rand=0.5)
    assert d.next_run_at is None
    # and the only way back is the explicit operator call
    assert hasattr(agent_scheduler, "resume")


# ── Thundering herd ────────────────────────────────────────────────


def test_agents_that_booted_together_do_not_stay_phase_locked():
    """N agents from one `docker compose up` share a start instant. With a
    fixed interval they stay together forever, hitting the provider in a burst
    every cycle."""
    runs = [agent_scheduler.after_success(now=NOW, interval_s=300.0, rand=i / 20).next_run_at for i in range(20)]
    assert len(set(runs)) > 1, "a fixed interval leaves the fleet synchronised"
    spread = (max(runs) - min(runs)).total_seconds()
    assert spread > 300.0 * agent_scheduler.JITTER_FRACTION, f"spread {spread}s is too tight to decorrelate"


def test_jitter_stays_within_the_declared_band():
    """Spread must not be so wide that a 5-minute cadence stops being one."""
    for rand in (0.0, 0.25, 0.5, 0.75, 1.0):
        delay = agent_scheduler.jittered(300.0, rand=rand)
        assert 300.0 * 0.85 - 0.01 <= delay <= 300.0 * 1.15 + 0.01


def test_backoff_is_jittered_too():
    """A provider outage fails every agent at once; an unjittered shared curve
    marches the whole fleet back in lockstep."""
    delays = {
        agent_scheduler.after_failure(_Boom(503), now=NOW, consecutive_failures=2, rand=i / 10).next_run_at
        for i in range(10)
    }
    assert len(delays) > 1


# ── Durability ─────────────────────────────────────────────────────


def test_success_resets_the_failure_count():
    """Otherwise an agent that failed twice yesterday stays slow forever."""
    assert agent_scheduler.after_success(now=NOW, interval_s=300.0, rand=0.5).consecutive_failures == 0


class _FakePg:
    def __init__(self, fail: bool = False):
        self.fail = fail
        self.calls: list[tuple] = []
        self.rows: list[dict] = []

    async def __call__(self, method, table, params=None, body=None):
        self.calls.append((method, table, params, body))
        if self.fail:
            return None  # pg_request SWALLOWS configured-db failures
        if method == "GET":
            return list(self.rows)
        return [body or {}]


@pytest.mark.asyncio
async def test_a_swallowed_write_failure_is_reported_as_failure():
    """pg_request returns None on a configured-db failure rather than raising.
    A try/except would report every failed write as a success — and an agent
    whose failure was never recorded retries at full rate next tick."""
    agent_scheduler.init(_FakePg(fail=True))
    d = agent_scheduler.after_success(now=NOW, interval_s=300.0, rand=0.5)
    assert await agent_scheduler.record("svc-1", d) is False


@pytest.mark.asyncio
async def test_a_successful_write_is_reported_as_success():
    agent_scheduler.init(_FakePg())
    d = agent_scheduler.after_success(now=NOW, interval_s=300.0, rand=0.5)
    assert await agent_scheduler.record("svc-1", d) is True


@pytest.mark.asyncio
async def test_the_due_query_excludes_paused_agents_and_uses_no_unsupported_syntax():
    """The direct-Postgres layer implements a SUBSET of the PostgREST dialect:
    no on_conflict, no headers, and `_order` drops a `nullsfirst` suffix
    silently. A query written for full PostgREST would fail or, worse, order
    wrongly while looking right."""
    pg = _FakePg()
    agent_scheduler.init(pg)
    await agent_scheduler.due_agents(now=NOW)
    _method, table, params, _body = pg.calls[0]
    assert table == "agent_schedule"
    assert params["paused_reason"] == "is.null"
    assert params["next_run_at"].startswith("lte.")
    assert "nullsfirst" not in params["order"]
    assert "on_conflict" not in params


@pytest.mark.asyncio
async def test_a_store_error_skips_the_tick_rather_than_killing_the_loop():
    """A scheduler that raises out of its own tick stops scheduling
    everything, which is worse than missing one round."""

    async def boom(*a, **k):
        raise RuntimeError("db down")

    agent_scheduler.init(boom)
    assert await agent_scheduler.due_agents(now=NOW) == []


@pytest.mark.asyncio
async def test_record_never_writes_on_conflict_or_headers():
    """POST already upserts on the table's primary key; passing either is a
    TypeError against this transport."""
    pg = _FakePg()
    agent_scheduler.init(pg)
    await agent_scheduler.record("svc-1", agent_scheduler.after_success(now=NOW, interval_s=300.0, rand=0.5))
    _method, _table, params, body = pg.calls[0]
    assert params is None or "on_conflict" not in params
    assert body["agent_id"] == "svc-1"


def test_the_schema_ships_the_table_and_the_migration_carries_it():
    """A schedule table that exists only in code is a scheduler that cannot
    persist — and init.sql never reaches an existing database."""
    repo = Path(__file__).resolve().parents[2]
    init_sql = (repo / "infra" / "init.sql").read_text()
    assert "agent_schedule" in init_sql
    assert "next_run_at" in init_sql
    migration = repo / "infra" / "migrations" / "0002_agent_schedule.sql"
    assert migration.exists(), "existing databases need the table too"
    assert "CREATE TABLE IF NOT EXISTS" in migration.read_text(), "migrations must be idempotent"


# ── The reachability fix: restart-resume, now that the scheduler actually runs ─────


class _StoreBackedPg:
    """A persistent agent_schedule table across simulated restarts."""

    def __init__(self):
        self.rows: dict[str, dict] = {}

    async def __call__(self, method, table, params=None, body=None):
        assert table == "agent_schedule"
        if method == "GET":
            aid = (params or {}).get("agent_id", "")
            if aid.startswith("eq."):
                row = self.rows.get(aid[3:])
                return [row] if row else []
            # due query: not paused and next_run_at <= stamp
            stamp = (params or {}).get("next_run_at", "lte.").removeprefix("lte.")
            return [
                r for r in self.rows.values() if not r.get("paused_reason") and str(r.get("next_run_at", "")) <= stamp
            ]
        if method == "POST":
            self.rows[body["agent_id"]] = {**self.rows.get(body["agent_id"], {}), **body}
            return [body]
        if method == "PATCH":
            aid = (params or {}).get("agent_id", "").removeprefix("eq.")
            if aid in self.rows:
                self.rows[aid].update(body or {})
            return [self.rows.get(aid, {})]
        raise AssertionError(method)


@pytest.mark.asyncio
async def test_a_schedule_written_before_a_restart_is_still_there_after_one():
    """THE DURABILITY CLAIM, exercised rather than asserted from the code.

    The store outlives the module state, which is what a process restart looks
    like from the database's side.
    """
    store = _StoreBackedPg()
    agent_scheduler.init(store)
    decision = agent_scheduler.after_success(now=NOW, interval_s=300.0, rand=0.5)
    assert await agent_scheduler.record("org-1", decision) is True

    # "Restart": fresh init, no in-process memory of the schedule.
    agent_scheduler.init(store)
    rows = await store("GET", "agent_schedule", params={"agent_id": "eq.org-1"})
    assert rows and rows[0]["next_run_at"] == decision.next_run_at.isoformat(), (
        "the schedule did not survive the restart"
    )


@pytest.mark.asyncio
async def test_a_future_schedule_is_not_due_but_a_past_one_is():
    """Resume must wait out the remainder rather than firing immediately —
    otherwise a restart resets the cadence to 'now', which is the stampede."""
    store = _StoreBackedPg()
    agent_scheduler.init(store)
    await agent_scheduler.record("future", agent_scheduler.after_success(now=NOW, interval_s=300.0, rand=0.5))
    assert await agent_scheduler.due_agents(now=NOW) == [], "a future schedule must not be due"
    later = NOW + timedelta(seconds=3600)
    due = await agent_scheduler.due_agents(now=later)
    assert [r["agent_id"] for r in due] == ["future"], "an elapsed schedule must become due"


@pytest.mark.asyncio
async def test_a_paused_agent_is_never_returned_as_due():
    store = _StoreBackedPg()
    agent_scheduler.init(store)
    await agent_scheduler.record(
        "stopped", agent_scheduler.after_failure(_Boom(401), now=NOW, consecutive_failures=0, rand=0.5)
    )
    assert await agent_scheduler.due_agents(now=NOW + timedelta(days=7)) == []
    assert await agent_scheduler.resume("stopped", now=NOW) is True
    assert [r["agent_id"] for r in await agent_scheduler.due_agents(now=NOW + timedelta(seconds=1))] == ["stopped"]
