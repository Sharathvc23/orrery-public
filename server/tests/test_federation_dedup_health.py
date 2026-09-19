"""the persistent restart-replay dedup store (federation_inbound_seen)
must be OBSERVABLE, not silently fail-open.

The S2S audit found the guard is baked into init.sql only, with
no boot DDL / migration runner — so a DB provisioned before it is missing it,
and _seen_persisted silently degrades to the in-memory ring. dedup_store_healthy
surfaces that condition so a degraded guard is loud, not hidden.

Classification: HEALTH / OBSERVABILITY.
"""

from __future__ import annotations

import os

os.environ.setdefault("AGENT_ID", "test-dedup-health")
os.environ.setdefault("AGENT_NAME", "Test Dedup Health")

import pytest

import broadcast


@pytest.mark.asyncio
async def test_healthy_when_table_queryable(monkeypatch):
    async def ok_pg(method, table, params=None, body=None):
        assert table == "federation_inbound_seen"
        return []

    monkeypatch.setattr(broadcast, "_pg_request", ok_pg)
    healthy, detail = await broadcast.dedup_store_healthy()
    assert healthy is True and detail == "ok"


@pytest.mark.asyncio
async def test_degraded_when_table_missing(monkeypatch):
    """A missing table (or any store error) → reported degraded, with a
    reason — the silent-fail-open condition is now visible."""

    async def erroring_pg(method, table, params=None, body=None):
        raise RuntimeError('relation "federation_inbound_seen" does not exist')

    monkeypatch.setattr(broadcast, "_pg_request", erroring_pg)
    healthy, detail = await broadcast.dedup_store_healthy()
    assert healthy is False
    assert "does not exist" in detail


@pytest.mark.asyncio
async def test_degraded_when_no_pg(monkeypatch):
    monkeypatch.setattr(broadcast, "_pg_request", None)
    healthy, detail = await broadcast.dedup_store_healthy()
    assert healthy is False and detail == "no_pg_request"


@pytest.mark.asyncio
async def test_probe_never_raises(monkeypatch):
    """The boot probe must never crash startup, whatever the store does."""

    async def boom(method, table, params=None, body=None):
        raise ValueError("catastrophic")

    monkeypatch.setattr(broadcast, "_pg_request", boom)
    healthy, _ = await broadcast.dedup_store_healthy()  # must not raise
    assert healthy is False
