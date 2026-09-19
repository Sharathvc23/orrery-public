"""Self-host drift guard: server-critical tables MUST be baked into init.sql.

The self-host / Railway stack boots its schema from ``infra/init.sql`` (a pg_dump
of the lean agent-native public schema). A server-critical table dropping out of
it is silently absent on a fresh deploy — which is exactly how ``chapter_keys``
once went missing and made the org's Ed25519 signing keypair EPHEMERAL across
restarts (breaks did/receipt continuity).

This guard fails loudly if any server-critical table drops out of the baked
init.sql, so the drift can't recur unnoticed. Runtime keypair logic is covered
separately by test_chapter_keypair_persistence.py.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

_INIT_SQL = Path(__file__).resolve().parents[2] / "infra" / "init.sql"

# Tables the headless org server depends on at runtime that are easy to strand.
# chapter_keys is the one that actually drifted.
_REQUIRED_TABLES = ["chapter_keys", "agents", "pending_approvals", "org_invites", "federation_inbound_seen"]


@pytest.fixture(scope="module")
def init_sql() -> str:
    assert _INIT_SQL.exists(), f"baked init.sql missing at {_INIT_SQL}"
    return _INIT_SQL.read_text(encoding="utf-8").lower()


def _create_table(init_sql: str, table: str) -> re.Match | None:
    """Locate a table's CREATE — init.sql is a pg_dump (``create table public.<t> (``);
    the older ``create table if not exists <t>`` form is tolerated too."""
    return re.search(rf"create table (?:if not exists )?(?:public\.)?{re.escape(table)}\b", init_sql)


@pytest.mark.parametrize("table", _REQUIRED_TABLES)
def test_required_table_is_baked_into_init_sql(init_sql: str, table: str) -> None:
    assert _create_table(init_sql, table), (
        f"{table} is not CREATE-d in the baked infra/init.sql — a fresh self-host/"
        f"Railway deploy will be missing it. Regenerate the lean schema (boot db, "
        f"strip RLS, pg_dump --schema=public) with this table present."
    )


def test_chapter_keys_has_signing_key_columns(init_sql: str) -> None:
    """chapter_keys must carry the persisted keypair columns, not just the table."""
    m = _create_table(init_sql, "chapter_keys")
    assert m, "chapter_keys missing from init.sql"
    block = init_sql[m.start() : m.start() + 600]
    for col in ("chapter_id", "secret_b64", "public_b64"):
        assert col in block, f"chapter_keys is missing the {col} column in init.sql"
