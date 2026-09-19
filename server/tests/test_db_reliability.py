"""DB failures are observable (not silent), the pool self-heals (no permanent
latch), and a member whose row fails to persist is durably outboxed + replayed.

Classification: FAILURE / RELIABILITY.
"""

from __future__ import annotations

import os
import sys

os.environ.setdefault("AGENT_ID", "test-dbrel-chapter")
os.environ.setdefault("AGENT_NAME", "Test DBRel Chapter")

import pytest

import metrics
import pg_store


@pytest.fixture(autouse=True)
def _reset():
    metrics.reset_for_tests()
    pg_store._pool = None
    pg_store._pool_unavailable_until = 0.0
    yield
    pg_store._pool = None
    pg_store._pool_unavailable_until = 0.0


def _db_failures() -> int:
    return sum(
        v for (name, _labels), v in metrics._labelled_counters.items()
        if name == "nanda_chapter_db_failures_total"
    )


# ── Part 1: operation failure is observable, distinct from not-configured ────────


@pytest.mark.asyncio
async def test_operation_failure_emits_metric_and_structured_log(monkeypatch, capsys):
    """A CONFIGURED-DB op that fails bumps the metric + logs a structured event —
    never a silent bare print/return-None."""
    monkeypatch.setenv("DATABASE_URL", "postgres://x")

    class _Pool:
        async def fetch(self, *a, **k):
            raise RuntimeError("boom")

    async def _pool():
        return _Pool()

    monkeypatch.setattr(pg_store, "_get_pool", _pool)
    assert await pg_store.pg_request("GET", "agents", params={"select": "*"}) is None
    assert _db_failures() >= 1
    assert "db.operation_failed" in capsys.readouterr().err


@pytest.mark.asyncio
async def test_not_configured_is_quiet_none_no_metric(monkeypatch):
    """No DATABASE_URL is NOT a failure — quiet None, no metric (distinct from above)."""
    monkeypatch.delenv("DATABASE_URL", raising=False)
    assert await pg_store.pg_request("GET", "agents") is None
    assert _db_failures() == 0


@pytest.mark.asyncio
async def test_execute_strict_raises_typed_error_on_failure(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgres://x")

    async def _none(*a, **k):
        return None

    monkeypatch.setattr(pg_store, "pg_request", _none)
    with pytest.raises(pg_store.DatabaseError):
        await pg_store.pg_execute_strict("POST", "agents", body={"agent_id": "a"})


@pytest.mark.asyncio
async def test_execute_strict_is_none_when_no_db(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    assert await pg_store.pg_execute_strict("POST", "agents", body={}) is None


# ── Part 2: a failed pool creation backs off + retries, never permanently latches ─


@pytest.mark.asyncio
async def test_pool_failure_backs_off_then_retries_not_permanent_latch(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgres://bad")
    calls = {"n": 0}

    class _FakeAsyncpg:
        @staticmethod
        async def create_pool(*a, **k):
            calls["n"] += 1
            raise RuntimeError("cannot connect")

    monkeypatch.setitem(sys.modules, "asyncpg", _FakeAsyncpg)
    clock = {"now": 1000.0}
    monkeypatch.setattr(pg_store.time, "monotonic", lambda: clock["now"])

    # first call attempts + fails → cooldown set, metric bumped
    assert await pg_store._get_pool() is None
    assert calls["n"] == 1
    assert _db_failures() >= 1

    # within cooldown: fail fast WITHOUT another create_pool attempt (no hammering)
    assert await pg_store._get_pool() is None
    assert calls["n"] == 1

    # after cooldown: it retries (self-heals when the DB returns) — NOT a permanent latch
    clock["now"] += pg_store._POOL_RETRY_COOLDOWN_S + 1
    assert await pg_store._get_pool() is None
    assert calls["n"] == 2


# ── Part 3: member persist-exhaustion is durably outboxed + replayed at boot ──────


@pytest.mark.asyncio
async def test_persist_exhaustion_outboxes_then_replay_repersists(monkeypatch, tmp_path):
    import chapter_agent as ca

    outbox = tmp_path / "member_outbox.jsonl"
    monkeypatch.setattr(ca, "_MEMBER_OUTBOX_PATH", outbox)
    monkeypatch.setattr(ca, "_HAS_DATABASE", True)
    monkeypatch.setattr(ca, "_PERSIST_MAX_ATTEMPTS", 1)  # no backoff sleeps in the test

    async def _always_fail(*a, **k):
        return None

    monkeypatch.setattr(ca, "pg_request", _always_fail)
    await ca._persist_member_to_db("alice", {"name": "Alice", "public_key": ""}, "sovereign")

    # the member was NOT lost — it is durably outboxed for boot replay
    assert outbox.exists()
    assert "alice" in outbox.read_text()

    # at boot, the outbox replays against a now-healthy DB and the member persists
    persisted: list[str] = []

    async def _ok(method, table, body=None, **k):
        persisted.append(body["agent_id"])
        return [body]

    monkeypatch.setattr(ca, "pg_request", _ok)
    assert await ca.replay_member_persist_outbox() == 1
    assert "alice" in persisted
    assert not outbox.exists()  # cleared once every row re-persisted


@pytest.mark.asyncio
async def test_replay_keeps_rows_that_still_fail(monkeypatch, tmp_path):
    import chapter_agent as ca

    outbox = tmp_path / "member_outbox.jsonl"
    outbox.write_text('{"table": "agents", "row": {"agent_id": "bob", "name": "Bob"}}\n')
    monkeypatch.setattr(ca, "_MEMBER_OUTBOX_PATH", outbox)
    monkeypatch.setattr(ca, "_HAS_DATABASE", True)

    async def _still_fail(*a, **k):
        return None

    monkeypatch.setattr(ca, "pg_request", _still_fail)
    assert await ca.replay_member_persist_outbox() == 0
    # the row is retained for the NEXT boot — not dropped
    assert outbox.exists()
    assert "bob" in outbox.read_text()
