"""Tests for server/dsar.py — DSAR export + cascading deletion.

That change DE-MOCK: the old fixture stubbed a ``did_key`` lookup and an ``intents`` table
that don't exist in the real schema, so the tests were green while erasure was broken.
This version drives a schema-ACCURATE in-memory Postgres: it resolves the subject via
``agent_facts->provider->did`` (as the real resolver now does), keys ``agent_intents``
on ``requester_agent_id`` and ``trust_events`` on ``agent_id``, and — crucially —
VALIDATES every queried table/column against ``infra/init.sql`` so a future drift to a
phantom column fails here instead of silently under-deleting.

Classification: HAPPY / EDGE / FAILURE / ADVERSARIAL / SCHEMA.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

os.environ.setdefault("AGENT_ID", "test-dsar-chapter")
os.environ.setdefault("AGENT_NAME", "Test DSAR Chapter")

import pytest

import dsar

_INIT_SQL = Path(__file__).resolve().parents[2] / "infra" / "init.sql"


def _parse_schema(sql: str) -> dict[str, set[str]]:
    schema: dict[str, set[str]] = {}
    for m in re.finditer(r"CREATE TABLE public\.(\w+)\s*\((.*?)\n\);", sql, re.DOTALL):
        cols: set[str] = set()
        for raw in m.group(2).splitlines():
            line = raw.strip()
            if not line or line.startswith(("CONSTRAINT", "PRIMARY", "FOREIGN", "UNIQUE", "CHECK")):
                continue
            c = re.match(r"(\w+)", line)
            if c:
                cols.add(c.group(1))
        schema[m.group(1)] = cols
    return schema


_SCHEMA = _parse_schema(_INIT_SQL.read_text())

SUBJECT_DID = "did:key:zMember123"
RESOLVED_AGENT_ID = "alice"


class SchemaValidatingPg:
    """An in-memory pg_request that (1) serves per-table rows and (2) asserts every
    queried filter column is a REAL column of a REAL table in init.sql — so a mocked
    phantom schema can never make a broken query look healthy again."""

    def __init__(self) -> None:
        self.db: dict[str, list[dict]] = {
            "agents": [
                {"agent_id": RESOLVED_AGENT_ID, "name": "Alice",
                 "agent_facts": {"provider": {"did": SUBJECT_DID}}},
                {"agent_id": "bob", "name": "Bob",
                 "agent_facts": {"provider": {"did": "did:key:zBobOther"}}},
            ],
            "arp_receipts": [
                {"id": "a1", "receipt_id": "r1", "principal_did": SUBJECT_DID, "issued_at": "2026-05-22T01:00:00Z"},
                {"id": "a2", "receipt_id": "r2", "principal_did": SUBJECT_DID, "issued_at": "2026-05-22T02:00:00Z"},
            ],
            "chronicles": [{"principal_did": SUBJECT_DID, "chronicle_date": "2026-05-22", "narrative": "x"}],
            "chapter_audit_events": [{"id": "e1", "actor_agent_id": RESOLVED_AGENT_ID, "action": "intent.submit"}],
            "agent_intents": [{"id": "i1", "requester_agent_id": RESOLVED_AGENT_ID, "intent_text": "hi"}],
            "agent_action_outcomes": [{"id": "o1", "agent_id": RESOLVED_AGENT_ID, "action_id": "x", "action_type": "t", "signal": "positive"}],
            "trust_events": [{"id": 1, "agent_id": RESOLVED_AGENT_ID, "event_type": "e", "delta": 1}],
            "chapter_role_nominations": [{"id": "n1", "nominee_agent_id": RESOLVED_AGENT_ID, "nominator_agent_id": "bob", "chapter_id": "c", "target_role": "leader"}],
        }
        self.deletion_log: list[tuple[str, str, str]] = []

    def _check_col(self, table: str, col: str) -> None:
        assert table in _SCHEMA, f"query hit table {table!r} not in init.sql"
        assert col in _SCHEMA[table], f"query filtered {table}.{col!r} which is not a real column"

    async def __call__(self, method, table, params=None, body=None):
        params = params or {}
        filters = {k: v for k, v in params.items() if k not in ("select", "limit", "order")}
        for k in filters:
            self._check_col(table, k)  # every filter column must be real
        rows = self.db.get(table, [])

        if method == "GET":
            out = list(rows)
            for k, v in filters.items():
                if isinstance(v, str) and v.startswith("eq."):
                    out = [r for r in out if str(r.get(k)) == v[3:]]
                elif isinstance(v, str) and v == "not.is.null":
                    out = [r for r in out if r.get(k) is not None]
            return out

        if method == "DELETE":
            removed: list[dict] = []
            for k, v in filters.items():
                if isinstance(v, str) and v.startswith("eq."):
                    keep, gone = [], []
                    for r in rows:
                        (gone if str(r.get(k)) == v[3:] else keep).append(r)
                    self.db[table] = keep
                    removed.extend(gone)
                    self.deletion_log.append((table, k, v[3:]))
            return removed
        return None


@pytest.fixture
def pg():
    return SchemaValidatingPg()


# ── resolution ────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_resolves_did_via_agent_facts(pg):
    """The subject DID is resolved from agent_facts->provider->did (no did_key col)."""
    assert await dsar._resolve_agent_id_from_did(pg, SUBJECT_DID) == RESOLVED_AGENT_ID


@pytest.mark.asyncio
async def test_unknown_did_resolves_to_none(pg):
    assert await dsar._resolve_agent_id_from_did(pg, "did:key:zNobody") is None


# ── export ─────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_export_returns_archive_across_real_tables(pg):
    archive = await dsar.export_subject_data(pg, SUBJECT_DID)
    assert archive["subject_did"] == SUBJECT_DID
    assert archive["resolved_agent_id"] == RESOLVED_AGENT_ID
    assert archive["tables"]["arp_receipts"]["count"] == 2
    assert archive["tables"]["chronicles"]["count"] == 1


@pytest.mark.asyncio
async def test_export_includes_agent_keyed_tables_when_resolved(pg):
    """agent_intents (requester_agent_id) + audit events resolve via the DID→agent_id
    step — the exact path that was dead before that change."""
    archive = await dsar.export_subject_data(pg, SUBJECT_DID)
    assert archive["tables"]["agent_intents"]["count"] == 1
    assert archive["tables"]["chapter_audit_events"]["count"] == 1
    assert archive["tables"]["agent_action_outcomes"]["count"] == 1
    assert archive["tables"]["trust_events"]["count"] == 1


@pytest.mark.asyncio
async def test_export_unknown_subject_is_empty(pg):
    archive = await dsar.export_subject_data(pg, "did:key:zNobody")
    assert archive["resolved_agent_id"] is None
    for info in archive["tables"].values():
        assert info["count"] == 0


# ── delete ──────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_delete_cascades_across_every_pii_table(pg):
    result = await dsar.delete_subject_data(pg, SUBJECT_DID)
    assert result["tables"]["arp_receipts"]["deleted"] == 2
    # the member's rows in the previously-dead agent-keyed tables are now removed
    assert result["tables"]["agent_intents"]["deleted"] == 1
    assert result["tables"]["trust_events"]["deleted"] == 1
    assert result["tables"]["agent_action_outcomes"]["deleted"] == 1
    assert result["tables"]["chapter_audit_events"]["deleted"] == 1
    assert result["tables"]["chapter_role_nominations"]["deleted"] == 1
    assert result["tables"]["agents"]["deleted"] == 1
    # ...and nothing belonging to the OTHER member (bob) was touched.
    assert any(r["agent_id"] == "bob" for r in pg.db["agents"])


@pytest.mark.asyncio
async def test_delete_reports_every_catalogued_table(pg):
    result = await dsar.delete_subject_data(pg, SUBJECT_DID)
    for table, *_ in dsar.DSAR_DATA_INVENTORY:
        assert table in result["tables"] and "deleted" in result["tables"][table]


@pytest.mark.asyncio
async def test_delete_actually_empties_the_rows(pg):
    """After a delete the subject's rows are GONE from the store (a real erasure,
    not just a reported count)."""
    await dsar.delete_subject_data(pg, SUBJECT_DID)
    assert [r for r in pg.db["arp_receipts"] if r["principal_did"] == SUBJECT_DID] == []
    assert [r for r in pg.db["agent_intents"] if r["requester_agent_id"] == RESOLVED_AGENT_ID] == []
    assert [r for r in pg.db["trust_events"] if r["agent_id"] == RESOLVED_AGENT_ID] == []


@pytest.mark.asyncio
async def test_failure_in_one_table_does_not_abort_cascade():
    class OneTableFails(SchemaValidatingPg):
        async def __call__(self, method, table, params=None, body=None):
            if method == "DELETE" and table == "arp_receipts":
                raise RuntimeError("simulated DB 500")
            return await super().__call__(method, table, params, body)

    pg = OneTableFails()
    result = await dsar.delete_subject_data(pg, SUBJECT_DID)
    assert "simulated DB 500" in (result["tables"]["arp_receipts"]["error"] or "")
    assert result["tables"]["agent_intents"]["error"] is None
    assert result["tables"]["agent_intents"]["deleted"] == 1


# ── inventory ────────────────────────────────────────────────────────────────────


def test_inventory_lists_real_tables():
    names = [i["table"] for i in dsar.inventory()]
    assert "agent_intents" in names and "intents" not in names
    assert "arp_receipts" in names and "agents" in names
