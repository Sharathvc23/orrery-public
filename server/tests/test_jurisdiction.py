"""Tests for chapter/jurisdiction.py — per-region compliance defaults."""

from __future__ import annotations

import os
from unittest.mock import AsyncMock

os.environ.setdefault("AGENT_ID", "test-jurisdiction-chapter")
os.environ.setdefault("AGENT_NAME", "Test Jurisdiction Chapter")

import pytest

import jurisdiction


@pytest.fixture(autouse=True)
def clear_env(monkeypatch):
    monkeypatch.delenv("CHAPTER_JURISDICTION", raising=False)


# ══════════════════════════════════════════════════════════════════════
# resolve_jurisdiction
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_HAPPY_env_var_wins(monkeypatch):
    monkeypatch.setenv("CHAPTER_JURISDICTION", "US-CA")
    result = await jurisdiction.resolve_jurisdiction(None, "c1")
    assert result == "US-CA"


@pytest.mark.asyncio
async def test_HAPPY_env_var_normalized_to_uppercase(monkeypatch):
    monkeypatch.setenv("CHAPTER_JURISDICTION", "us-fed")
    result = await jurisdiction.resolve_jurisdiction(None, "c1")
    assert result == "US-FED"


@pytest.mark.asyncio
async def test_HAPPY_falls_back_to_db_when_no_env():
    """No env var → query the chapter_policy row keyed `jurisdiction`.

    The fake returns the KEY/VALUE shape the table actually has. It used to
    return a `jurisdiction` column, which the code asked for and the database
    has never had — so this test passed while the read failed in production.
    """

    async def fake(method, table, params=None, body=None):
        if table == "chapter_policy" and (params or {}).get("key") == "eq.jurisdiction":
            return [{"value": "EU"}]
        return []

    result = await jurisdiction.resolve_jurisdiction(AsyncMock(side_effect=fake), "c1")
    assert result == "EU"


@pytest.mark.asyncio
async def test_EDGE_falls_back_to_default_when_no_env_no_supabase():
    result = await jurisdiction.resolve_jurisdiction(None, "c1")
    assert result == jurisdiction.DEFAULT_JURISDICTION
    assert result == "US"


@pytest.mark.asyncio
async def test_EDGE_supabase_error_falls_back_to_default():
    async def raises(*_a, **_kw):
        raise RuntimeError("no chapter_policy table")

    result = await jurisdiction.resolve_jurisdiction(AsyncMock(side_effect=raises), "c1")
    assert result == jurisdiction.DEFAULT_JURISDICTION


# ══════════════════════════════════════════════════════════════════════
# retention_overrides_for
# ══════════════════════════════════════════════════════════════════════


def test_HAPPY_ca_has_stricter_intent_retention():
    """CCPA pushes 'intents' from 90 default down to 30 — a CEILING."""
    overrides = jurisdiction.retention_overrides_for("US-CA")
    assert overrides["agent_intents"].days == 30
    assert overrides["agent_intents"].direction is jurisdiction.CEILING


def test_HAPPY_eu_has_aggressive_minimization():
    """GDPR minimization pushes most retention to 1 year or less."""
    overrides = jurisdiction.retention_overrides_for("EU")
    assert overrides["arp_receipts"].days == 365  # vs 7 years default
    assert overrides["agent_intents"].days == 30
    assert all(r.direction is jurisdiction.CEILING for r in overrides.values()), (
        "GDPR is a storage-limitation regime; nothing in it may LENGTHEN retention"
    )


def test_HAPPY_us_dod_has_longer_audit_retention():
    """DoD context keeps audit logs 7 years for incident review — a FLOOR."""
    overrides = jurisdiction.retention_overrides_for("US-DOD")
    assert overrides["chapter_audit_events"].days == 7 * 365
    assert overrides["chapter_audit_events"].direction is jurisdiction.FLOOR


def test_HAPPY_hipaa_has_6_year_record_retention():
    """HIPAA mandates a 6-year MINIMUM for medical records. The module default
    is 7 years, so the correct resolution keeps 7 — declaring US-HIPAA must not
    delete a year of receipts in the name of a minimum."""
    overrides = jurisdiction.retention_overrides_for("US-HIPAA")
    assert overrides["arp_receipts"].days == 6 * 365
    assert overrides["arp_receipts"].direction is jurisdiction.FLOOR


def test_EDGE_unknown_jurisdiction_returns_empty():
    """Unknown region → no overrides, retention.py defaults apply."""
    overrides = jurisdiction.retention_overrides_for("XX-FAKE")
    assert overrides == {}


def test_EDGE_lowercase_jurisdiction_normalized():
    overrides = jurisdiction.retention_overrides_for("eu")
    assert overrides["agent_intents"].days == 30


# ══════════════════════════════════════════════════════════════════════
# applicable_regimes_for
# ══════════════════════════════════════════════════════════════════════


def test_HAPPY_us_ca_lists_ccpa_cpra():
    regimes = jurisdiction.applicable_regimes_for("US-CA")
    acronyms = [r["acronym"] for r in regimes]
    assert "CCPA" in acronyms
    assert "CPRA" in acronyms


def test_HAPPY_us_co_includes_caia_for_2026():
    regimes = jurisdiction.applicable_regimes_for("US-CO")
    acronyms = [r["acronym"] for r in regimes]
    assert "CAIA" in acronyms


def test_HAPPY_us_dod_lists_cmmc_and_fedramp():
    regimes = jurisdiction.applicable_regimes_for("US-DOD")
    acronyms = [r["acronym"] for r in regimes]
    assert any(a.startswith("CMMC") for a in acronyms)
    assert any(a.startswith("FedRAMP") for a in acronyms)
    assert "NIST-800-171" in acronyms


def test_HAPPY_eu_lists_gdpr_and_ai_act():
    regimes = jurisdiction.applicable_regimes_for("EU")
    acronyms = [r["acronym"] for r in regimes]
    assert "GDPR" in acronyms
    assert "EU-AI-Act" in acronyms


def test_EDGE_unknown_jurisdiction_falls_back_to_us_baseline():
    regimes = jurisdiction.applicable_regimes_for("XX-FAKE")
    acronyms = [r["acronym"] for r in regimes]
    assert "FTC-S5" in acronyms


# ══════════════════════════════════════════════════════════════════════
# effective_retention_policy — layered: defaults + jurisdiction + operator
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_HAPPY_eu_jurisdiction_applies_aggressive_defaults(monkeypatch):
    monkeypatch.setenv("CHAPTER_JURISDICTION", "EU")
    policy = await jurisdiction.effective_retention_policy(None, "c1")
    # EU pushes arp_receipts from 7 years (default) down to 1 year
    assert policy["arp_receipts"] == 365


@pytest.mark.asyncio
async def test_HAPPY_operator_override_beats_jurisdiction(monkeypatch):
    """Operator-set chapter_policy.retention_days_by_category wins
    over jurisdiction defaults."""
    monkeypatch.setenv("CHAPTER_JURISDICTION", "EU")

    async def fake(method, table, params=None, body=None):
        # ⚠️ chapter_policy is a KEY/VALUE table — (chapter_id, key, value jsonb).
        # This fake previously modelled it as a WIDE table with `jurisdiction`
        # and `retention_days_by_category` COLUMNS, because that is what the code
        # asked for. Both reads were rejected by PostgREST in production and
        # swallowed by a bare `except`, so this test was green against a shape
        # the database has never had — the fake agreed with the code instead of
        # with the schema, which is exactly the failure this suite exists
        # to catch, committed inside the suite itself.
        key = (params or {}).get("key", "")
        if key == "eq.jurisdiction":
            return [{"value": "EU"}]
        if key == "eq.retention_days_by_category":
            return [{"value": {"arp_receipts": 9999}}]
        return []

    policy = await jurisdiction.effective_retention_policy(AsyncMock(side_effect=fake), "c1")
    # EU jurisdiction would push to 365; operator override wins → 9999
    assert policy["arp_receipts"] == 9999


@pytest.mark.asyncio
async def test_HAPPY_default_us_keeps_module_defaults(monkeypatch):
    """US baseline (no jurisdiction overrides) → module defaults apply.

    Skips when retention.py isn't yet in main (PR ordering)."""
    monkeypatch.setenv("CHAPTER_JURISDICTION", "US")
    try:
        import retention
    except ImportError:
        pytest.skip("retention.py not yet in main")
    policy = await jurisdiction.effective_retention_policy(None, "c1")
    assert policy == retention.DEFAULT_RETENTION_DAYS


@pytest.mark.asyncio
async def test_EDGE_unknown_jurisdiction_keeps_module_defaults(monkeypatch):
    monkeypatch.setenv("CHAPTER_JURISDICTION", "XX-FAKE")
    try:
        import retention
    except ImportError:
        pytest.skip("retention.py not yet in main")
    policy = await jurisdiction.effective_retention_policy(None, "c1")
    assert policy == retention.DEFAULT_RETENTION_DAYS


# ══════════════════════════════════════════════════════════════════════
# THE WIRING — behavioural, through the sweeper that actually deletes.
#
# `jurisdiction.py` was a complete, tested module that nothing imported (the reachability fix's
# shape). Asserting "retention.py contains the string 'jurisdiction'" would have
# passed before this change too, because retention.py's docstring already
# claimed to be jurisdiction-aware. These assert what the SWEEPER DOES.
# ══════════════════════════════════════════════════════════════════════


def _cutoff_days(result, table):
    """How many days back the sweeper actually cut, from its own report."""
    from datetime import datetime

    cutoff = datetime.fromisoformat(result["results"][table]["cutoff"])
    now = datetime.fromisoformat(result["swept_at"])
    return round((now - cutoff).days)


@pytest.mark.asyncio
async def test_the_sweeper_honours_a_declared_jurisdiction(monkeypatch):
    """EU shortens arp_receipts from the 7-year default to 1 year. Before the
    wiring the sweeper used 2555 days regardless of what the operator declared,
    so an EU deployment retained receipts six years past GDPR minimisation."""
    import retention

    monkeypatch.setenv("ORG_JURISDICTION", "EU")

    async def fake(method, table, params=None, body=None):
        return []

    result = await retention.sweep_once(AsyncMock(side_effect=fake), "c1", dry_run=True)
    assert result["policy"]["arp_receipts"] == 365
    assert _cutoff_days(result, "arp_receipts") == 365


@pytest.mark.asyncio
async def test_the_sweeper_honours_a_LONGER_statutory_floor(monkeypatch):
    """⚠️ THE CASE THIS TEST USED TO ROUTE AROUND. It asserted US-DOD's
    agent_intents — a SHORTENING — and its own docstring said the US-FED audit
    floor "happens to be longer", which is precisely why it had to be asserted
    and precisely what was broken: the floor was applied as an assignment, so
    declaring US-FED cut chapter_audit_events from 2555 days to 1095 and the
    sweeper deleted the four years in between. A test that steps around the
    asymmetric case cannot see the asymmetry.

    NIST 800-171 says *at least* three years. The module default already keeps
    seven. The correct resolution is seven."""
    import retention

    monkeypatch.setenv("ORG_JURISDICTION", "US-FED")

    async def fake(method, table, params=None, body=None):
        return []

    result = await retention.sweep_once(AsyncMock(side_effect=fake), "c1", dry_run=True)
    assert jurisdiction.RETENTION_OVERRIDES["US-FED"]["chapter_audit_events"].days == 3 * 365
    assert retention.DEFAULT_RETENTION_DAYS["chapter_audit_events"] == 7 * 365
    assert result["policy"]["chapter_audit_events"] == 2555, "a statutory MINIMUM shortened the retention it protects"
    assert _cutoff_days(result, "chapter_audit_events") == 2555


@pytest.mark.asyncio
async def test_the_sweeper_still_honours_a_SHORTENING_jurisdiction(monkeypatch):
    """The other half of the asymmetry, kept from the test above rather than
    dropped: US-DOD's CUI minimisation is a CEILING and must still shorten."""
    import retention

    monkeypatch.setenv("ORG_JURISDICTION", "US-DOD")

    async def fake(method, table, params=None, body=None):
        return []

    result = await retention.sweep_once(AsyncMock(side_effect=fake), "c1", dry_run=True)
    # DoD: intents carry CUI → 60 days, down from the 90-day default.
    assert retention.DEFAULT_RETENTION_DAYS["agent_intents"] == 90
    assert result["policy"]["agent_intents"] == 60
    assert _cutoff_days(result, "agent_intents") == 60
    # ...while the audit floor in the same profile does not shorten anything.
    assert result["policy"]["chapter_audit_events"] == 2555


@pytest.mark.asyncio
async def test_a_six_year_minimum_does_not_shorten_a_seven_year_default(monkeypatch):
    """HIPAA's 6-year floor under a 7-year default. Same shape as US-FED and
    stated separately because it is a different statute: declaring US-HIPAA
    deleted a year of receipts and audit events before the floor-versus-ceiling fix."""
    import retention

    monkeypatch.setenv("ORG_JURISDICTION", "US-HIPAA")

    async def fake(method, table, params=None, body=None):
        return []

    result = await retention.sweep_once(AsyncMock(side_effect=fake), "c1", dry_run=True)
    assert result["policy"]["arp_receipts"] == 2555
    assert result["policy"]["chapter_audit_events"] == 2555
    # The minimisation entries in the same profile still bind downward.
    assert result["policy"]["agent_intents"] == 30


@pytest.mark.asyncio
async def test_an_undeclared_jurisdiction_changes_nothing_at_all(monkeypatch):
    """⚠️ THE SAFETY PROPERTY THAT MADE THIS LANDABLE. RETENTION_OVERRIDES["US"]
    is empty and US is the default, so every org that never declared a
    jurisdiction sweeps byte-identically to before. A retention change that
    silently altered what gets DELETED on live orgs would not be a tidy-up."""
    import retention

    monkeypatch.delenv("ORG_JURISDICTION", raising=False)
    monkeypatch.delenv("CHAPTER_JURISDICTION", raising=False)

    async def fake(method, table, params=None, body=None):
        return []

    result = await retention.sweep_once(AsyncMock(side_effect=fake), "c1", dry_run=True)
    assert result["policy"] == retention.DEFAULT_RETENTION_DAYS


@pytest.mark.asyncio
async def test_the_operator_override_still_outranks_the_jurisdiction(monkeypatch):
    """A jurisdiction is a floor the regime imposes, not a ceiling on the
    operator's own policy — and this is the layer the old duplicate
    implementation silently dropped by reading the wrong table shape."""
    import retention

    monkeypatch.setenv("ORG_JURISDICTION", "EU")

    async def fake(method, table, params=None, body=None):
        if (params or {}).get("key") == "eq.retention_days_by_category":
            return [{"value": {"arp_receipts": 9999}}]
        return []

    result = await retention.sweep_once(AsyncMock(side_effect=fake), "c1", dry_run=True)
    assert result["policy"]["arp_receipts"] == 9999


@pytest.mark.asyncio
async def test_a_broken_jurisdiction_layer_leaves_the_defaults_intact(monkeypatch):
    """FAILURE: the sweeper DELETES, so a fault in the jurisdiction layer must
    never widen what it removes. It degrades to module defaults and says so."""
    import retention

    monkeypatch.setenv("ORG_JURISDICTION", "EU")
    monkeypatch.setattr(
        jurisdiction, "retention_overrides_for", lambda code: (_ for _ in ()).throw(RuntimeError("boom"))
    )

    async def fake(method, table, params=None, body=None):
        return []

    result = await retention.sweep_once(AsyncMock(side_effect=fake), "c1", dry_run=True)
    assert result["policy"] == retention.DEFAULT_RETENTION_DAYS


@pytest.mark.asyncio
async def test_the_database_jurisdiction_read_matches_the_real_schema():
    """The read that never worked. chapter_policy is key/value, so a `jurisdiction`
    COLUMN select was rejected every time and swallowed — an operator who set the
    policy row silently got the default."""
    seen: list[dict] = []

    async def fake(method, table, params=None, body=None):
        seen.append(params or {})
        if (params or {}).get("key") == "eq.jurisdiction":
            return [{"value": "US-CA"}]
        return []

    code = await jurisdiction.resolve_jurisdiction(AsyncMock(side_effect=fake), "c1")
    assert code == "US-CA"
    assert seen and seen[0].get("key") == "eq.jurisdiction"
    assert seen[0].get("select") == "value"
    assert "jurisdiction" not in seen[0].get("select", ""), "still selecting a column that does not exist"
