"""P2 — member persist is fire-and-forget; make a dropped row recover + observable.

A registration writes the in-memory bridge then fire-and-forgets the Postgres
upsert. A transient failure (PostgREST schema-cache warmup race on a fresh boot,
a 5xx, a network blip) silently dropped the row, so the member directory diverged
from the bridge with no signal. Now the persist retries with linear backoff and,
on final failure, bumps a metric.

Classification: FAILURE / EDGE.
"""

from __future__ import annotations

import os

os.environ.setdefault("AGENT_ID", "test-chapter")
os.environ.setdefault("AGENT_NAME", "Test Chapter")

import pytest  # noqa: E402

import chapter_agent  # noqa: E402

_MEMBER = {"name": "Alice", "description": "", "skills": [], "public_key": ""}


@pytest.fixture(autouse=True)
def _fast_retry(monkeypatch):
    monkeypatch.setattr(chapter_agent, "_PERSIST_RETRY_DELAY_S", 0)
    monkeypatch.setattr(chapter_agent, "_HAS_DATABASE", True)


@pytest.mark.asyncio
async def test_persist_retries_then_succeeds(monkeypatch):
    calls = {"n": 0}

    async def flaky(method, table, params=None, body=None, **kw):
        calls["n"] += 1
        return None if calls["n"] < 2 else [{"id": "1"}]  # fail once, then succeed

    fails = []
    monkeypatch.setattr(chapter_agent, "pg_request", flaky)
    monkeypatch.setattr(chapter_agent.metrics, "record_member_persist_failure", lambda: fails.append(1))

    await chapter_agent._persist_member_to_db("alice", _MEMBER, "sovereign")
    assert calls["n"] == 2, "did not retry the transient failure"
    assert fails == [], "recorded a failure even though the retry succeeded"


@pytest.mark.asyncio
async def test_persist_records_failure_after_max_attempts(monkeypatch):
    calls = {"n": 0}

    async def always_fail(method, table, params=None, body=None, **kw):
        calls["n"] += 1
        return None

    fails = []
    monkeypatch.setattr(chapter_agent, "pg_request", always_fail)
    monkeypatch.setattr(chapter_agent.metrics, "record_member_persist_failure", lambda: fails.append(1))

    await chapter_agent._persist_member_to_db("alice", _MEMBER, "sovereign")
    assert calls["n"] == chapter_agent._PERSIST_MAX_ATTEMPTS
    assert fails == [1], "a persistent persist failure was not surfaced as a metric"


@pytest.mark.asyncio
async def test_persist_does_not_retry_in_local_dev(monkeypatch):
    """No SUPABASE creds = local dev; a None is 'nothing to persist', not a
    failure — don't retry and don't record a metric."""
    monkeypatch.setattr(chapter_agent, "_HAS_DATABASE", False)
    calls = {"n": 0}

    async def fail(method, table, params=None, body=None, **kw):
        calls["n"] += 1
        return None

    fails = []
    monkeypatch.setattr(chapter_agent, "pg_request", fail)
    monkeypatch.setattr(chapter_agent.metrics, "record_member_persist_failure", lambda: fails.append(1))

    await chapter_agent._persist_member_to_db("alice", _MEMBER, "sovereign")
    assert calls["n"] == 1, "retried in local dev where there is nothing to persist"
    assert fails == []
