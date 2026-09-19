"""The floor-versus-ceiling fix — a jurisdiction's number is a FLOOR or a CEILING, never an assignment.

``retention.resolve_retention_policy`` applied every jurisdiction override as
``policy[table] = days``. That is neither of the two things a regime can mean:
NIST 800-171 hands you 1095 saying "at least this", GDPR hands you 365 saying
"at most this", and the same assignment serves one and inverts the other. The
observable consequence was a deletion: ``ORG_JURISDICTION=US-FED`` cut
``chapter_audit_events`` from the 2555-day default to the three-year *minimum*
of 1095, and the sweeper DELETED the four years in between to comply with a
floor.

Three layers here, each worthless without the ones beside it:

  STRUCTURAL   every entry in the table declares a direction, enumerated FROM
               the table rather than from a list of entries someone remembered
               to write down. An override added later without one is a hard
               error at load, proved by adding one and watching it fail.
  BEHAVIOURAL  the direction is exercised through the ACTUAL SWEEPER against a
               fake that holds rows and honours the cutoff, not through the
               resolver's return value. A resolver-only assertion cannot tell a
               wired sweeper from an unwired one.
  LOAD-BEARING each direction is planted wrong in the checked-in table and this
               file goes red. Independent of the resolution-table assertions in
               test_jurisdiction.py, so neither can cover for the other.
"""

from __future__ import annotations

import ast
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import AsyncMock

os.environ.setdefault("AGENT_ID", "test-retention-direction")
os.environ.setdefault("AGENT_NAME", "Test Retention Direction")

import pytest

import jurisdiction
import retention

SERVER = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def clear_env(monkeypatch):
    for var in (
        "ORG_JURISDICTION",
        "CHAPTER_JURISDICTION",
        "ORG_RETENTION_SWEEP_DRY_RUN",
        "CHAPTER_RETENTION_SWEEP_DRY_RUN",
    ):
        monkeypatch.delenv(var, raising=False)


# ══════════════════════════════════════════════════════════════════════
# STRUCTURAL — derived from the table, never from a list
# ══════════════════════════════════════════════════════════════════════


def _every_entry():
    """Enumerate (code, table, rule) across the whole override table.

    A hand-listed set of "entries that need a direction" would be a mirror of
    this table maintained by memory, and the entry someone forgets to add is
    exactly the one that deletes to the wrong side of a statute.
    """
    for code, overrides in jurisdiction.RETENTION_OVERRIDES.items():
        for table, rule in overrides.items():
            yield code, table, rule


def test_every_override_declares_a_direction():
    entries = list(_every_entry())
    assert entries, "the override table is empty — this guard would be vacuous"
    for code, table, rule in entries:
        assert isinstance(rule, jurisdiction.RetentionRule), f"{code}/{table} is a bare {type(rule).__name__}"
        assert isinstance(rule.direction, jurisdiction.Direction), f"{code}/{table} declares no direction"
        assert rule.basis, f"{code}/{table} declares no basis for its direction"


def test_both_directions_are_actually_used():
    """If every entry were a FLOOR the enum would be decoration and a CEILING
    could regress unnoticed — and vice versa. Derived, so it keeps holding as
    the table grows."""
    used = {rule.direction for _, _, rule in _every_entry()}
    assert used == set(jurisdiction.Direction), f"unused direction(s): {set(jurisdiction.Direction) - used}"


def test_an_override_added_without_a_direction_FAILS_AT_LOAD():
    """The proof that the structural rule binds: add one the way an author
    would in six months — a bare integer, the earlier shape — and the table
    is refused rather than defaulted."""
    table = {code: dict(entries) for code, entries in jurisdiction.RETENTION_OVERRIDES.items()}
    table["US-CA"]["chronicles"] = 45  # a plain int: no direction, no basis

    with pytest.raises(jurisdiction.RetentionDirectionError) as excinfo:
        jurisdiction.validate_retention_overrides(table)
    assert "chronicles" in str(excinfo.value)


@pytest.mark.parametrize(
    "bad",
    [
        pytest.param(jurisdiction.RetentionRule(0, jurisdiction.CEILING, "zero"), id="zero-days"),
        pytest.param(jurisdiction.RetentionRule(-5, jurisdiction.FLOOR, "negative"), id="negative-days"),
        pytest.param(jurisdiction.RetentionRule(90, "floor", "a string, not a Direction"), id="stringly-typed"),
        pytest.param(jurisdiction.RetentionRule(90, jurisdiction.FLOOR, ""), id="no-basis"),
    ],
)
def test_a_malformed_rule_is_refused(bad):
    table = {"US-CA": {"chronicles": bad}}
    with pytest.raises(jurisdiction.RetentionDirectionError):
        jurisdiction.validate_retention_overrides(table)


def test_the_checked_in_table_is_validated_at_import():
    """Validation the caller has to remember to invoke is not a load-time
    error. Asserted from the AST so deleting the call is caught even though
    the checked-in table is valid and nothing would raise."""
    tree = ast.parse((SERVER / "jurisdiction.py").read_text())
    module_level_calls = {
        node.value.func.id
        for node in tree.body
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name)
    }
    assert "validate_retention_overrides" in module_level_calls, (
        "jurisdiction.py no longer validates RETENTION_OVERRIDES at import"
    )


@pytest.mark.asyncio
async def test_a_directionless_entry_reaches_the_resolver_as_a_refusal_not_an_assignment(monkeypatch):
    """And it must not fall back to the old behaviour on the way through. The
    sweeper degrades to module defaults — the safe side of a delete path, since
    the defaults are longer — and does NOT apply the bare number."""
    patched = {code: dict(entries) for code, entries in jurisdiction.RETENTION_OVERRIDES.items()}
    patched["EU"]["chronicles"] = 7
    monkeypatch.setattr(jurisdiction, "RETENTION_OVERRIDES", patched)
    monkeypatch.setenv("ORG_JURISDICTION", "EU")

    with pytest.raises(jurisdiction.RetentionDirectionError):
        jurisdiction.retention_overrides_for("EU")

    async def fake(method, table, params=None, body=None):
        return []

    policy = await retention.resolve_retention_policy(AsyncMock(side_effect=fake), "c1")
    assert policy == retention.DEFAULT_RETENTION_DAYS
    assert policy["chronicles"] != 7


def test_no_jurisdiction_now_deletes_MORE_than_the_assignment_did():
    """THE SAFETY PROPERTY THAT MAKES THIS LANDABLE ON A LIVE MESH, enumerated
    rather than argued. For every entry in the table, the resolved TTL is at
    least what the earlier assignment produced — a FLOOR by ``max`` can only
    lengthen, and every CEILING entry is already at or below its default, so
    ``min`` returns the same number it assigned. No org, whatever it declared,
    sweeps anything this change did not already sweep."""
    for code, table, rule in _every_entry():
        default = retention.DEFAULT_RETENTION_DAYS.get(table)
        if default is None:
            continue
        assert rule.apply(default) >= rule.days, f"{code}/{table} would delete more than it did before"


# ══════════════════════════════════════════════════════════════════════
# BEHAVIOURAL — through the sweeper that actually DELETEs
# ══════════════════════════════════════════════════════════════════════


class _RowStore:
    """A fake pg_request that HOLDS ROWS and honours the sweeper's own cutoff.

    The point is to measure deletion at a boundary rather than to read the
    policy dict back out of the sweeper's report. A sweeper wired to the
    resolver and one that computes a policy it never applies produce identical
    reports; only rows can tell them apart.
    """

    def __init__(self, table: str, ages_in_days: list[int]) -> None:
        now = datetime.now(UTC)
        self.table = table
        self.rows = {age: now - timedelta(days=age) for age in ages_in_days}
        self.deleted: list[int] = []

    async def __call__(self, method, table, params=None, body=None):
        if method == "GET":
            return []  # no operator override
        if method != "DELETE" or table != self.table:
            return []
        column = retention.TIMESTAMP_COLUMN[table]
        raw = (params or {}).get(column, "")
        assert raw.startswith("lt."), f"unexpected filter {raw!r}"
        cutoff = datetime.fromisoformat(raw[3:])
        gone = [age for age, ts in self.rows.items() if ts < cutoff]
        for age in gone:
            del self.rows[age]
        self.deleted.extend(gone)
        return [{"age_days": age} for age in gone]

    @property
    def surviving(self) -> set[int]:
        return set(self.rows)


# Rows either side of the two boundaries that matter: GDPR's 365-day ceiling,
# and the 1095-day line the US-FED floor was cutting at when it was applied as
# an assignment. 1200 is the row that only survives if a floor cannot shorten.
AGES = [364, 366, 1200, 3000]


@pytest.mark.asyncio
async def test_a_CEILING_makes_the_sweeper_delete_at_the_shortened_boundary(monkeypatch):
    """EU: GDPR storage limitation pulls chapter_audit_events from 2555 days to
    365, and rows past the shortened boundary are really removed."""
    monkeypatch.setenv("ORG_JURISDICTION", "EU")
    store = _RowStore("chapter_audit_events", AGES)

    result = await retention.sweep_once(store, "c1")

    assert result["policy"]["chapter_audit_events"] == 365
    assert store.surviving == {364}, "a minimisation ceiling did not shorten what the sweeper deletes"
    assert sorted(store.deleted) == [366, 1200, 3000]


@pytest.mark.asyncio
async def test_a_FLOOR_does_NOT_let_the_sweeper_shorten(monkeypatch):
    """US-FED: NIST 800-171's three-year MINIMUM against a seven-year default.
    The row at 1200 days is the whole test — it is past the 1095-day floor and
    inside the 2555-day default, so it is deleted if and only if the floor is
    being applied as an assignment, which is what the floor-versus-ceiling fix was."""
    monkeypatch.setenv("ORG_JURISDICTION", "US-FED")
    store = _RowStore("chapter_audit_events", AGES)

    result = await retention.sweep_once(store, "c1")

    assert result["policy"]["chapter_audit_events"] == 2555
    assert 1200 in store.surviving, "a statutory MINIMUM deleted records it exists to preserve"
    assert store.surviving == {364, 366, 1200}
    assert store.deleted == [3000], "the module default must still be enforced"


@pytest.mark.asyncio
async def test_an_undeclared_jurisdiction_sweeps_exactly_the_module_default(monkeypatch):
    """No ORG_JURISDICTION — every live org today. Byte-identical to a run with
    no jurisdiction layer at all, measured in rows rather than asserted of the
    policy dict."""
    store = _RowStore("chapter_audit_events", AGES)

    result = await retention.sweep_once(store, "c1")

    assert result["policy"] == retention.DEFAULT_RETENTION_DAYS
    assert store.deleted == [3000]
    assert store.surviving == {364, 366, 1200}


@pytest.mark.asyncio
async def test_the_operator_override_still_outranks_both_directions(monkeypatch):
    """The operator's own policy is the TOP layer — an assignment, deliberately,
    including one that goes below a floor. A jurisdiction is what the regime
    imposes, not a cap on the operator."""
    monkeypatch.setenv("ORG_JURISDICTION", "US-FED")
    store = _RowStore("chapter_audit_events", AGES)

    async def with_operator_policy(method, table, params=None, body=None):
        if method == "GET" and (params or {}).get("key") == "eq.retention_days_by_category":
            return [{"value": {"chapter_audit_events": 400}}]
        return await store(method, table, params, body)

    result = await retention.sweep_once(with_operator_policy, "c1")

    assert result["policy"]["chapter_audit_events"] == 400
    # 400 days is well below the US-FED floor of 1095 and the operator gets it
    # anyway: rows past 400 days go, the two inside it stay.
    assert store.surviving == {364, 366}
    assert sorted(store.deleted) == [1200, 3000]
