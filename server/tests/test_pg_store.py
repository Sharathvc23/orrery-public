"""Unit tests for the direct-Postgres builder (pg_store) — pure, no DB needed.

The builder reproduces the PostgREST dialect the 45 callers use; `_lit` is the
SQL-injection boundary, so it gets adversarial coverage. Execution (asyncpg) is
covered by the docker e2e, not here.
"""

from __future__ import annotations

import pg_store as pg

# ── _lit: the injection boundary ──────────────────────────────────────────────


def test_lit_primitives():
    assert pg._lit(None) == "NULL"
    assert pg._lit(True) == "TRUE"
    assert pg._lit(False) == "FALSE"
    assert pg._lit(50) == "50"
    assert pg._lit("hello") == "'hello'"


def test_lit_escapes_single_quotes():
    assert pg._lit("o'brien") == "'o''brien'"


def test_lit_neutralizes_injection():
    # The classic: a value that tries to break out of the string + run SQL.
    evil = "x'; DROP TABLE agents; --"
    out = pg._lit(evil)
    # Every embedded quote is doubled, so the payload stays a single string literal.
    assert out == "'x''; DROP TABLE agents; --'"
    assert out.count("'") % 2 == 0  # balanced → no escape


def test_lit_json_columns():
    assert pg._lit({"a": 1}) == "'{\"a\": 1}'::jsonb"
    assert pg._lit([1, 2]) == "'[1, 2]'::jsonb"


def test_ident_rejects_unsafe():
    assert pg._ident("agent_id") == '"agent_id"'
    import pytest

    with pytest.raises(ValueError):
        pg._ident("a; drop table x")


# ── filter dialect ────────────────────────────────────────────────────────────


def test_filter_operators():
    assert pg._filter("agent_id", "eq.regentix-ceo") == "\"agent_id\" = 'regentix-ceo'"
    assert pg._filter("trust_score", "gte.50") == "\"trust_score\" >= '50'"
    assert pg._filter("n", "neq.3") == "\"n\" <> '3'"
    assert pg._filter("n", "lt.10") == "\"n\" < '10'"


def test_filter_is_null_and_bool():
    assert pg._filter("revoked_at", "is.null") == '"revoked_at" IS NULL'
    assert pg._filter("active", "is.true") == '"active" IS TRUE'


def test_filter_not_is_null():
    assert pg._filter("revoked_at", "not.is.null") == 'NOT ("revoked_at" IS NULL)'


def test_filter_in_list():
    assert pg._filter("status", "in.(active,pending)") == "\"status\" IN ('active', 'pending')"


# ── compound and/or filters (PostgREST `and=(...)` / `or=(...)`) ───────────────


def test_compound_and_single_predicate():
    # The real caller: chronicle/surfaces pass {"and": "(issued_at.lt.<ts>)"} —
    # a value that itself contains dots (the ISO timestamp).
    sql = pg.build_select("arp_receipts", {"and": "(issued_at.lt.2026-07-03T00:00:00Z)"})
    assert sql == 'SELECT * FROM "arp_receipts" WHERE ("issued_at" < \'2026-07-03T00:00:00Z\')'


def test_compound_and_multi_predicate():
    where = pg._where({"and": "(issued_at.gte.2026-01-01,issued_at.lt.2026-02-01)"})
    assert where == ' WHERE ("issued_at" >= \'2026-01-01\' AND "issued_at" < \'2026-02-01\')'


def test_compound_or_predicate():
    assert pg._compound("or", "(status.eq.active,status.eq.pending)") == (
        "(\"status\" = 'active' OR \"status\" = 'pending')"
    )


def test_compound_preserves_nested_in_list():
    # A comma inside a member's in.(...) must not split the member.
    assert pg._split_top_commas("a.lt.1,b.in.(x,y)") == ["a.lt.1", "b.in.(x,y)"]


# ── vector (pgvector) columns ──────────────────────────────────────────────────


def test_lit_for_vector_column():
    # A float embedding must cast to the column's vector type, NOT jsonb.
    assert pg._lit_for([0.1, 0.2, 0.3], "vector") == "'[0.1,0.2,0.3]'::vector"


def test_lit_for_vector_schema_qualified_and_dimensioned():
    # format_type may report extensions.vector or vector(1536); cast to it verbatim.
    assert pg._lit_for([1.0, 2.0], "extensions.vector") == "'[1.0,2.0]'::extensions.vector"
    assert pg._lit_for([1.0], "vector(1536)") == "'[1.0]'::vector(1536)"


def test_lit_for_non_vector_list_still_jsonb():
    assert pg._lit_for([1, 2], "jsonb") == "'[1, 2]'::jsonb"


def test_base_type_strips_schema_and_modifier():
    assert pg._base_type("extensions.vector") == "vector"
    assert pg._base_type("vector(1536)") == "vector"
    assert pg._base_type("numeric(10,2)") == "numeric"
    assert pg._base_type(None) == ""


# ── _rows: coerce asyncpg-native types to PostgREST's JSON shapes ─────────────


def test_rows_coerces_datetime_to_isoformat():
    import datetime as _dt

    ts = _dt.datetime(2026, 7, 3, 17, 30, tzinfo=_dt.timezone.utc)
    rows = pg._rows([{"id": 1, "created_at": ts}])
    assert rows[0]["created_at"] == "2026-07-03T17:30:00+00:00"
    # A returned timestamp must be string-comparable to an ISO window bound —
    # the exact operation the digest window filter does.
    assert "2026-07-01T00:00:00+00:00" <= rows[0]["created_at"] < "2026-07-08T00:00:00+00:00"


def test_rows_coerces_uuid_and_decimal():
    import decimal as _dec
    import uuid as _uuid

    u = _uuid.UUID("550e8400-e29b-41d4-a716-446655440000")
    rows = pg._rows([{"id": u, "score": _dec.Decimal("5.5")}])
    assert rows[0]["id"] == "550e8400-e29b-41d4-a716-446655440000"
    assert rows[0]["score"] == 5.5


def test_rows_still_parses_jsonb_text_and_leaves_plain_strings():
    rows = pg._rows([{"config": '{"a": 1}', "name": "alice", "tags": "[1, 2]"}])
    assert rows[0]["config"] == {"a": 1}
    assert rows[0]["tags"] == [1, 2]
    assert rows[0]["name"] == "alice"


# ── RPC (PostgREST POST /rpc/<fn> → Postgres function call) ───────────────────


def test_build_rpc_named_args():
    # invites.consume: POST rpc/consume_org_invite {p_token, p_agent_id}
    sql = pg.build_rpc("consume_org_invite", {"p_token": "abc", "p_agent_id": "alice"})
    assert sql == "SELECT * FROM \"consume_org_invite\"(p_token => 'abc', p_agent_id => 'alice')"


def test_build_rpc_no_args():
    assert pg.build_rpc("replay_scores_all", {}) == 'SELECT * FROM "replay_scores_all"()'
    assert pg.build_rpc("replay_scores_all", None) == 'SELECT * FROM "replay_scores_all"()'


def test_build_rpc_escapes_values():
    sql = pg.build_rpc("f", {"p": "a' OR '1'='1"})
    assert sql == "SELECT * FROM \"f\"(p => 'a'' OR ''1''=''1')"


def test_build_rpc_rejects_unsafe_arg_name():
    import pytest

    with pytest.raises(ValueError):
        pg.build_rpc("f", {"p; DROP TABLE x": "v"})


# ── statement builders ────────────────────────────────────────────────────────


def test_build_select_star_and_filters():
    sql = pg.build_select("agents", {"agent_id": "eq.x", "select": "id", "limit": "1"})
    assert sql == "SELECT \"id\" FROM \"agents\" WHERE \"agent_id\" = 'x' LIMIT 1"


def test_build_select_order():
    sql = pg.build_select("thoughts", {"select": "*", "order": "created_at.desc", "limit": "5"})
    assert sql == 'SELECT * FROM "thoughts" ORDER BY "created_at" DESC LIMIT 5'


def test_build_upsert_with_pk():
    sql = pg.build_upsert("agents", {"agent_id": "ceo", "trust_score": 10}, ["agent_id"])
    assert sql == (
        'INSERT INTO "agents" ("agent_id", "trust_score") VALUES (\'ceo\', 10) '
        'ON CONFLICT ("agent_id") DO UPDATE SET "trust_score" = EXCLUDED."trust_score" '
        "RETURNING *"
    )


def test_build_upsert_pk_only_does_nothing():
    sql = pg.build_upsert("joins", {"a": "1", "b": "2"}, ["a", "b"])
    assert "ON CONFLICT (\"a\", \"b\") DO NOTHING" in sql


def test_build_upsert_merges_a_jsonb_column_instead_of_replacing_it():
    """`merge_jsonb` must emit `col = <table>.col || EXCLUDED.col`, so keys the
    writer does not supply survive the conflict. Replacing the column instead is
    what destroyed a member's Listing consent and host39 publication record on
    every re-registration, once the upsert started landing at all."""
    sql = pg.build_upsert(
        "agents",
        {"agent_id": "ceo", "name": "CEO", "config": {"voice": "helpful"}},
        ["agent_id"],
        None,
        ["config"],
    )
    assert '"config" = "agents"."config" || EXCLUDED."config"' in sql
    # A column NOT named for merging is still replaced outright.
    assert '"name" = EXCLUDED."name"' in sql


def test_build_upsert_without_merge_still_replaces_jsonb():
    """The negative control: merging is opt-in, so the default is unchanged."""
    sql = pg.build_upsert("agents", {"agent_id": "ceo", "config": {"a": 1}}, ["agent_id"])
    assert '"config" = EXCLUDED."config"' in sql
    assert "||" not in sql


def test_build_upsert_conflict_target_is_whatever_it_is_given():
    """The whole defect in one assertion. `agents` has a surrogate `id` primary
    key and a separate unique on `agent_id`; a member row never carries `id`, so
    targeting the PRIMARY KEY generates a fresh uuid, never trips ON CONFLICT,
    and dies on `agents_agent_id_key`. The caller names the natural key instead."""
    sql = pg.build_upsert("agents", {"agent_id": "ceo", "name": "CEO"}, ["agent_id"])
    assert 'ON CONFLICT ("agent_id")' in sql
    assert '"agent_id" = EXCLUDED' not in sql  # never SET the conflict key itself


def test_build_update():
    sql = pg.build_update("agents", {"agent_id": "eq.ceo"}, {"trust_score": 20})
    assert sql == 'UPDATE "agents" SET "trust_score" = 20 WHERE "agent_id" = \'ceo\' RETURNING *'


def test_build_delete():
    sql = pg.build_delete("members", {"agent_id": "eq.gone"})
    assert sql == 'DELETE FROM "members" WHERE "agent_id" = \'gone\' RETURNING *'


# ── type-aware rendering (regression: text[] columns must not be sent as jsonb) ─


def test_lit_for_text_array_column():
    # The boot bug: skills is text[], not jsonb.
    assert pg._lit_for(["python", "go"], "text[]") == "ARRAY['python', 'go']::text[]"
    assert pg._lit_for([], "text[]") == "ARRAY[]::text[]"


def test_lit_for_jsonb_column():
    assert pg._lit_for({"a": 1}, "jsonb") == "'{\"a\": 1}'::jsonb"


def test_lit_for_scalar_and_null():
    assert pg._lit_for("ceo", "text") == "'ceo'"
    assert pg._lit_for(None, "text[]") == "NULL"


def test_build_upsert_renders_array_column_as_text_array():
    sql = pg.build_upsert(
        "agents", {"agent_id": "ceo", "skills": ["python", "go"]}, ["agent_id"], {"skills": "text[]"}
    )
    assert "ARRAY['python', 'go']::text[]" in sql
    assert "::jsonb" not in sql  # the bug rendered text[] as jsonb
