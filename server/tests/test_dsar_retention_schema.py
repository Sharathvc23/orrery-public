"""That change — schema-conformance gate for DSAR + retention.

The GDPR ship-stopper was that dsar.py and retention.py queried tables and columns
that DO NOT EXIST in the real schema (``intents`` vs ``agent_intents``,
``agents.did_key`` vs the DID in ``agent_facts``, ``trust_events.subject_agent_id``
vs ``agent_id``, ``chapter_policy.retention_days_by_category`` vs a key/value row).
pg_request swallowed the resulting errors and returned None, so erasure/export
silently skipped almost all PII while unit tests (which MOCKED the missing schema)
stayed green — the exact "mocked tests passing while spec drifts" anti-pattern.

This test parses ``infra/init.sql`` and asserts every (table, column) the two modules
reference is real. It fails loudly the instant a query drifts from the schema again.

Classification: SCHEMA-CONFORMANCE.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

os.environ.setdefault("AGENT_ID", "test-dsar-schema")
os.environ.setdefault("AGENT_NAME", "Test DSAR Schema")

import dsar
import retention

INIT_SQL = Path(__file__).resolve().parents[2] / "infra" / "init.sql"


def _parse_schema(sql: str) -> dict[str, set[str]]:
    """Parse ``CREATE TABLE public.<name> ( ... );`` blocks into
    ``{table: {column, ...}}``. Column = the first identifier on a body line that
    is not a table constraint (CONSTRAINT/PRIMARY/FOREIGN/UNIQUE/CHECK)."""
    schema: dict[str, set[str]] = {}
    for m in re.finditer(r"CREATE TABLE public\.(\w+)\s*\((.*?)\n\);", sql, re.DOTALL):
        table, body = m.group(1), m.group(2)
        cols: set[str] = set()
        for raw in body.splitlines():
            line = raw.strip()
            if not line or line.startswith(("CONSTRAINT", "PRIMARY", "FOREIGN", "UNIQUE", "CHECK")):
                continue
            col = re.match(r"(\w+)", line)
            if col:
                cols.add(col.group(1))
        schema[table] = cols
    return schema


SCHEMA = _parse_schema(INIT_SQL.read_text())


def _assert(table: str, column: str, source: str) -> None:
    assert table in SCHEMA, f"{source} references table {table!r} which is not in init.sql"
    assert column in SCHEMA[table], (
        f"{source} references {table}.{column} which is not a column of {table} "
        f"(columns: {sorted(SCHEMA[table])})"
    )


def test_schema_parser_found_the_core_tables():
    """Guard the parser itself — if it silently found nothing, every check below
    would vacuously pass."""
    for t in ("agents", "agent_intents", "trust_events", "arp_receipts", "chapter_policy"):
        assert t in SCHEMA and SCHEMA[t], f"parser failed to extract {t}"


def test_dsar_inventory_columns_exist():
    """Every (table, subject-field) pair DSAR queries must exist in the schema."""
    for table, primary, secondary, agent_field in dsar.DSAR_DATA_INVENTORY:
        for field in (primary, secondary, agent_field):
            if field:
                _assert(table, field, f"dsar.DSAR_DATA_INVENTORY[{table}]")


def test_dsar_did_resolution_columns_exist():
    """The DID→agent_id resolver reads agents.agent_id + agents.agent_facts."""
    _assert("agents", "agent_id", "dsar._resolve_agent_id_from_did")
    _assert("agents", "agent_facts", "dsar._resolve_agent_id_from_did")


def test_retention_tables_and_timestamp_columns_exist():
    """Every retention target table + its TTL timestamp column must be real."""
    for table, ts_col in retention.TIMESTAMP_COLUMN.items():
        _assert(table, ts_col, f"retention.TIMESTAMP_COLUMN[{table}]")
    # DEFAULT_RETENTION_DAYS and TIMESTAMP_COLUMN must cover the same tables.
    assert set(retention.DEFAULT_RETENTION_DAYS) == set(retention.TIMESTAMP_COLUMN), (
        "retention DEFAULT_RETENTION_DAYS and TIMESTAMP_COLUMN cover different tables"
    )


def test_retention_policy_override_columns_exist():
    """resolve_retention_policy reads chapter_policy.chapter_id/key/value."""
    for col in ("chapter_id", "key", "value"):
        _assert("chapter_policy", col, "retention.resolve_retention_policy")


def test_no_reference_to_the_known_phantom_columns():
    """Explicit regression guards for the exact drifts that change fixed."""
    tables = {t for t, *_ in dsar.DSAR_DATA_INVENTORY}
    assert "intents" not in tables and "agent_intents" in tables
    assert "did_key" not in SCHEMA.get("agents", set()), "unexpected agents.did_key — resolver assumes it's absent"
    trust_fields = {a for t, _, _, a in dsar.DSAR_DATA_INVENTORY if t == "trust_events"}
    assert "subject_agent_id" not in trust_fields
