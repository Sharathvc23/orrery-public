"""The application role migration: what it grants, and what it withholds.

These assert the migration's SQL and the configuration that uses it. They do not
substitute for driving the application against a database as the role — a
permission gap does not appear as a startup failure, it appears as one endpoint
failing on a path no unit test runs. That was done separately against a real
Postgres; what is checked here is what a unit suite can check, so that the file
cannot be edited into something weaker without a signal.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
MIGRATION = REPO / "infra" / "migrations" / "0006_app_role.sql"
COMPOSE = (REPO / "docker-compose.yml").read_text()
SQL = MIGRATION.read_text()

#: The SQL with `--` comments removed. The file explains at length what it does
#: NOT grant, so a check run over the raw text matches its own prose.
STATEMENTS = "\n".join(line.split("--")[0] for line in SQL.splitlines())


def test_the_role_is_created_without_superuser_or_bypassrls():
    """NOSUPERUSER is the change. NOBYPASSRLS is stated for the same reason: a
    role with it is exempt from row policies exactly as a superuser is."""
    for attribute in ("NOSUPERUSER", "NOCREATEDB", "NOCREATEROLE", "NOREPLICATION", "NOBYPASSRLS"):
        assert attribute in SQL, f"the role is created without {attribute}"


def test_the_grants_are_derived_from_the_catalog_not_listed():
    """`ON ALL TABLES IN SCHEMA` enumerates at execution time. A hand-written
    list of 114 tables would omit one, and the omission would surface as a
    failure on whichever path reads it."""
    assert "ON ALL TABLES IN SCHEMA public" in SQL
    assert "ON ALL SEQUENCES IN SCHEMA public" in SQL
    assert "ON ALL FUNCTIONS IN SCHEMA public" in SQL
    # No object name should appear in a GRANT: that would be the hand list. The
    # GRANT clause of an ALTER DEFAULT PRIVILEGES names a KIND (TABLES,
    # SEQUENCES, FUNCTIONS), not an object, so those statements are read whole
    # rather than line by line.
    body = re.sub(r"ALTER DEFAULT PRIVILEGES[^;]*;", "", STATEMENTS, flags=re.S | re.I)
    for statement in body.split(";"):
        collapsed = " ".join(statement.split())
        if not collapsed.upper().startswith("GRANT"):
            continue
        assert "ON ALL " in collapsed.upper() or "ON SCHEMA PUBLIC" in collapsed.upper(), (
            f"a GRANT names an object: {collapsed}"
        )


def test_future_tables_are_covered_by_default_privileges():
    """Without this, a table added by a later migration is invisible to the app
    until someone remembers to re-run this file."""
    assert SQL.count("ALTER DEFAULT PRIVILEGES") >= 3


def test_the_role_is_not_granted_create_on_the_schema():
    """The application issues no DDL against Postgres. The one runtime
    CREATE TABLE in the tree is SQLite, in the offline issuer log."""
    for statement in STATEMENTS.split(";"):
        collapsed = " ".join(statement.split()).upper()
        if collapsed.startswith("GRANT") and "ON SCHEMA PUBLIC" in collapsed:
            assert "CREATE" not in collapsed, f"CREATE granted on the schema: {collapsed}"


def test_the_migration_refuses_to_report_success_on_an_empty_schema():
    """`granted = present` is satisfied trivially by 0 = 0, which is what a run
    against a database whose schema has not loaded yet produces."""
    assert "has no tables" in SQL
    assert "grant coverage is incomplete" in SQL


def test_the_migration_is_idempotent_in_shape():
    """Re-running must be a no-op, so the role creation is conditional and the
    attributes are re-asserted rather than assumed."""
    assert "IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'orrery_app')" in SQL
    assert "ALTER ROLE orrery_app" in SQL


def test_the_migration_documents_the_way_back():
    assert "Reversing it" in SQL
    assert "DROP ROLE orrery_app" in SQL


def test_compose_connects_the_server_as_the_app_role_not_the_superuser():
    dsn = [line for line in COMPOSE.splitlines() if "DATABASE_URL:" in line]
    assert dsn, "no DATABASE_URL in docker-compose.yml"
    assert "APP_DB_USER:-orrery_app" in dsn[0], dsn[0]
    assert "POSTGRES_USER" not in dsn[0], f"the server still connects as the superuser: {dsn[0]}"


def test_compose_still_gives_the_database_service_its_superuser():
    """The superuser is not removed — it initialises the database and applies
    migrations. It is no longer what serves requests."""
    assert "POSTGRES_USER: ${POSTGRES_USER:-postgres}" in COMPOSE


def test_the_role_sql_is_not_mounted_where_the_entrypoint_would_run_it():
    """Postgres runs every *.sql in /docker-entrypoint-initdb.d in filename
    order, and 0006_app_role.sql sorts before 01-schema.sql — so a copy placed
    there runs against an empty database and grants nothing. It is mounted
    outside that directory and invoked by the hook instead."""
    assert "/opt/orrery/0006_app_role.sql" in COMPOSE
    assert "/docker-entrypoint-initdb.d/0006_app_role.sql" not in COMPOSE
    dockerfile = (REPO / "infra" / "Dockerfile.db").read_text()
    assert "/opt/orrery/0006_app_role.sql" in dockerfile
    assert "/docker-entrypoint-initdb.d/0006_app_role.sql" not in dockerfile


def test_the_fresh_install_hook_requires_a_password():
    """A role created with no password cannot log in. Failing the database init
    is better than a stack that starts and cannot reach its own database."""
    hook = (REPO / "infra" / "03-app-role.sh").read_text()
    assert "APP_DB_PASSWORD" in hook
    assert "exit 1" in hook


def test_an_authentication_failure_names_both_causes():
    """Postgres answers SQLSTATE 28P01 for a wrong password AND for a role that
    does not exist — measured, and deliberate on its part. A remedy naming only
    one of them sends the reader to the wrong place."""
    pg_store = (REPO / "server" / "pg_store.py").read_text()
    assert '"28P01"' in pg_store
    assert "0006_app_role.sql" in pg_store
    assert "does not exist" in pg_store and "password" in pg_store
