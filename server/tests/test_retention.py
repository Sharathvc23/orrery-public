"""Tests for chapter/retention.py — retention policy + sweeper.

Classification: HAPPY / EDGE / FAILURE / ADVERSARIAL.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock

os.environ.setdefault("AGENT_ID", "test-retention-chapter")
os.environ.setdefault("AGENT_NAME", "Test Retention Chapter")

import pytest

import retention


@pytest.fixture(autouse=True)
def clear_env(monkeypatch):
    """Each test starts from the stock defaults: sweep enabled, dry-run off."""
    for var in (
        "CHAPTER_RETENTION_SWEEP_ENABLED",
        "ORG_RETENTION_SWEEP_ENABLED",
        "CHAPTER_RETENTION_SWEEP_DRY_RUN",
        "ORG_RETENTION_SWEEP_DRY_RUN",
    ):
        monkeypatch.delenv(var, raising=False)


# ══════════════════════════════════════════════════════════════════════
# is_sweep_enabled
# ══════════════════════════════════════════════════════════════════════


def test_HAPPY_is_sweep_enabled_default_true():
    assert retention.is_sweep_enabled() is True


@pytest.mark.parametrize("val", ["0", "false", "no", "off", ""])
def test_EDGE_explicit_false_values_disable_sweep(monkeypatch, val):
    monkeypatch.setenv("CHAPTER_RETENTION_SWEEP_ENABLED", val)
    assert retention.is_sweep_enabled() is False


@pytest.mark.parametrize("val", ["1", "true", "yes", "on"])
def test_HAPPY_explicit_true_values_enable_sweep(monkeypatch, val):
    monkeypatch.setenv("CHAPTER_RETENTION_SWEEP_ENABLED", val)
    assert retention.is_sweep_enabled() is True


# ══════════════════════════════════════════════════════════════════════
# is_dry_run_mode (that change: GA enforces by default; dry-run is opt-in)
# ══════════════════════════════════════════════════════════════════════


def test_HAPPY_is_dry_run_default_false(monkeypatch):
    """a stock deployment (no env set) ENFORCES retention — real
    deletes. Dry-run is an explicit per-chapter opt-in, not the default;
    otherwise the sweeper advertises data-minimization while deleting
    nothing."""
    monkeypatch.delenv("ORG_RETENTION_SWEEP_DRY_RUN", raising=False)
    monkeypatch.delenv("CHAPTER_RETENTION_SWEEP_DRY_RUN", raising=False)
    assert retention.is_dry_run_mode() is False


@pytest.mark.parametrize("val", ["1", "true", "yes", "on"])
def test_HAPPY_explicit_true_values_enable_dry_run(monkeypatch, val):
    """Operators opt IN to a review period with DRY_RUN=true."""
    monkeypatch.setenv("CHAPTER_RETENTION_SWEEP_DRY_RUN", val)
    assert retention.is_dry_run_mode() is True


@pytest.mark.parametrize("val", ["0", "false", "no", "off"])
def test_HAPPY_explicit_false_values_disable_dry_run(monkeypatch, val):
    monkeypatch.setenv("CHAPTER_RETENTION_SWEEP_DRY_RUN", val)
    assert retention.is_dry_run_mode() is False


def test_HAPPY_org_var_can_force_dry_run_on(monkeypatch):
    """ORG_* is canonical and can force a dry-run review period on even
    though the stock default now enforces."""
    monkeypatch.delenv("CHAPTER_RETENTION_SWEEP_DRY_RUN", raising=False)
    monkeypatch.setenv("ORG_RETENTION_SWEEP_DRY_RUN", "true")
    assert retention.is_dry_run_mode() is True


# ══════════════════════════════════════════════════════════════════════
# resolve_retention_policy
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_HAPPY_policy_falls_back_to_defaults_when_no_override():
    async def empty_supabase(*_a, **_kw):
        return []

    policy = await retention.resolve_retention_policy(
        AsyncMock(side_effect=empty_supabase),
        "test-chapter",
    )
    assert policy == retention.DEFAULT_RETENTION_DAYS


@pytest.mark.asyncio
async def test_HAPPY_policy_applies_operator_override():
    async def with_override(*_a, **_kw):
        return [{"value": {"arp_receipts": 30, "agent_intents": 7}}]

    policy = await retention.resolve_retention_policy(
        AsyncMock(side_effect=with_override),
        "test-chapter",
    )
    assert policy["arp_receipts"] == 30
    assert policy["agent_intents"] == 7
    # Non-overridden tables keep defaults
    assert policy["chapter_audit_events"] == retention.DEFAULT_RETENTION_DAYS["chapter_audit_events"]


@pytest.mark.asyncio
async def test_EDGE_override_for_unknown_table_ignored():
    """An operator override for a table we don't recognize gets dropped
    — we only sweep known tables."""

    async def bogus_override(*_a, **_kw):
        return [{"value": {"not_a_real_table": 1}}]

    policy = await retention.resolve_retention_policy(
        AsyncMock(side_effect=bogus_override),
        "test-chapter",
    )
    assert "not_a_real_table" not in policy


@pytest.mark.asyncio
async def test_EDGE_negative_or_zero_override_ignored():
    """A zero or negative TTL doesn't make sense — keep the default."""

    async def bad_values(*_a, **_kw):
        return [{"value": {"arp_receipts": 0, "agent_intents": -5}}]

    policy = await retention.resolve_retention_policy(
        AsyncMock(side_effect=bad_values),
        "test-chapter",
    )
    assert policy["arp_receipts"] == retention.DEFAULT_RETENTION_DAYS["arp_receipts"]
    assert policy["agent_intents"] == retention.DEFAULT_RETENTION_DAYS["agent_intents"]


@pytest.mark.asyncio
async def test_EDGE_missing_policy_table_falls_back_to_defaults():
    async def raises(*_a, **_kw):
        raise RuntimeError("chapter_policy table missing")

    policy = await retention.resolve_retention_policy(
        AsyncMock(side_effect=raises),
        "test-chapter",
    )
    assert policy == retention.DEFAULT_RETENTION_DAYS


# ══════════════════════════════════════════════════════════════════════
# sweep_once
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_HAPPY_sweep_deletes_expired_rows():
    """Per-table DELETE called with the correct ts_column LT cutoff."""
    deletes: list[tuple[str, dict]] = []

    async def fake(method, table, params=None, body=None):
        if method == "GET":
            return []  # no policy override
        if method == "DELETE":
            deletes.append((table, dict(params or {})))
            # Pretend 3 rows came back per table
            return [{"id": str(i)} for i in range(3)]
        return None

    result = await retention.sweep_once(AsyncMock(side_effect=fake), "test-chapter")
    assert result["total_deleted"] == 3 * len(retention.DEFAULT_RETENTION_DAYS)
    # Every catalogued table got a DELETE call
    deleted_tables = [t for t, _ in deletes]
    assert "arp_receipts" in deleted_tables
    assert "chronicles" in deleted_tables


@pytest.mark.asyncio
async def test_HAPPY_sweep_uses_correct_cutoff_for_each_table():
    """The DELETE query uses lt.<cutoff_iso> where cutoff = now - TTL_days."""
    captured: list[tuple[str, str]] = []

    async def fake(method, table, params=None, body=None):
        if method == "GET":
            return []
        if method == "DELETE":
            # Extract cutoff from the lt.<ts> filter
            for k, v in (params or {}).items():
                if isinstance(v, str) and v.startswith("lt."):
                    captured.append((table, v[3:]))
            return []
        return None

    now = datetime.now(UTC)
    await retention.sweep_once(AsyncMock(side_effect=fake), "test-chapter")

    # Check cutoff for arp_receipts (default 7 years)
    arp_entries = [(t, c) for t, c in captured if t == "arp_receipts"]
    assert len(arp_entries) == 1
    cutoff_dt = datetime.fromisoformat(arp_entries[0][1])
    expected = now - timedelta(days=retention.DEFAULT_RETENTION_DAYS["arp_receipts"])
    # Within 60 seconds of expected (test execution time)
    assert abs((cutoff_dt - expected).total_seconds()) < 60


@pytest.mark.asyncio
async def test_HAPPY_stock_env_sweep_enforces_not_noop(monkeypatch):
    """That change regression: with the stock env (nothing set), the sweeper runs
    in ENFORCE mode (dry_run=False) and issues real DELETEs. This is the
    end-to-end guard against the sweep silently no-op'ing by default."""
    monkeypatch.delenv("ORG_RETENTION_SWEEP_DRY_RUN", raising=False)
    monkeypatch.delenv("CHAPTER_RETENTION_SWEEP_DRY_RUN", raising=False)
    deletes: list[str] = []

    async def fake(method, table, params=None, body=None):
        if method == "GET":
            return []
        if method == "DELETE":
            deletes.append(table)
            return [{"id": "1"}]
        return None

    result = await retention.sweep_once(
        AsyncMock(side_effect=fake),
        "test-chapter",
        dry_run=retention.is_dry_run_mode(),
    )
    assert result["dry_run"] is False
    assert deletes, "stock env must enforce retention (real DELETEs), not dry-run no-op"
    assert result["total_deleted"] > 0


@pytest.mark.asyncio
async def test_HAPPY_dry_run_computes_policy_without_deleting():
    delete_calls = 0

    async def fake(method, table, params=None, body=None):
        nonlocal delete_calls
        if method == "DELETE":
            delete_calls += 1
        return []

    result = await retention.sweep_once(
        AsyncMock(side_effect=fake),
        "test-chapter",
        dry_run=True,
    )
    assert result["dry_run"] is True
    assert result["total_deleted"] == 0
    assert delete_calls == 0
    # But the policy and cutoffs ARE computed
    assert result["policy"]
    for table_outcome in result["results"].values():
        assert table_outcome["cutoff"]
        assert table_outcome["deleted"] == 0
        assert table_outcome["error"] is None


# ══════════════════════════════════════════════════════════════════════
# Failure handling
# ══════════════════════════════════════════════════════════════════════


def test_trust_events_sweeps_on_occurred_at_not_created_at():
    """P1: trust_events has no `created_at` column — its timestamp is
    `occurred_at`. The wrong column made every DELETE a PostgREST 400 that
    pg_request swallowed to None, so the privacy-TTL purge silently never
    ran while logging deleted:0/error:None (looked like 'nothing to purge')."""
    assert retention.TIMESTAMP_COLUMN["trust_events"] == "occurred_at"


@pytest.mark.asyncio
async def test_FAILURE_none_response_is_marked_as_error_not_silent_zero():
    """pg_request returns None on a non-2xx (e.g. unknown column) instead
    of raising. A swept-but-FAILED table must be visibly distinct from a
    swept-CLEAN one, otherwise a broken sweep reads as healthy."""

    async def fake(method, table, params=None, body=None):
        if method == "GET":
            return []
        if method == "DELETE":
            return None  # PostgREST rejected the query; pg_request -> None
        return None

    result = await retention.sweep_once(AsyncMock(side_effect=fake), "test-chapter")
    for table, outcome in result["results"].items():
        assert outcome["error"] is not None, f"{table}: failed DELETE was recorded as clean"
        assert outcome["deleted"] == 0


@pytest.mark.asyncio
async def test_FAILURE_single_table_error_does_not_abort_sweep():
    """If DELETE on one table raises, the others still run."""

    async def selective_fail(method, table, params=None, body=None):
        if method == "GET":
            return []
        if method == "DELETE":
            if table == "arp_receipts":
                raise RuntimeError("simulated supabase 500")
            return [{"id": "1"}]  # success on others
        return None

    result = await retention.sweep_once(AsyncMock(side_effect=selective_fail), "test-chapter")
    assert result["results"]["arp_receipts"]["error"] is not None
    # Other tables succeeded
    assert result["results"]["chronicles"]["error"] is None
    assert result["results"]["chronicles"]["deleted"] == 1
