-- 0006 — a non-superuser application role
--
-- The application connects to Postgres as `postgres`, a superuser. A superuser
-- can DROP any table, read `pg_shadow`, and `COPY FROM PROGRAM` — arbitrary
-- command execution on the database host. Nothing in the application needs any
-- of that: it issues SELECT, INSERT, UPDATE and DELETE, and no DDL (the one
-- runtime `CREATE TABLE` in the tree is SQLite, in the offline issuer log).
--
-- This file creates a role with exactly those four privileges and no others.
-- The superuser is still required to APPLY this file and future migrations; it
-- is no longer required to serve requests.
--
-- Separately, and not the reason to do it: PostgreSQL exempts superusers from
-- every row policy unconditionally, so no row-level policy can have any effect
-- while the application connects as one. This migration writes no policies. See
-- docs/audit/C4_RLS_SCOPE.md.
--
-- ── Applying it ────────────────────────────────────────────────────────────
--
--   psql "$SUPERUSER_DATABASE_URL" -v ON_ERROR_STOP=1 -f infra/migrations/0006_app_role.sql
--
-- and set the password, either in the same call:
--
--   PGOPTIONS="-c orrery.app_password=$APP_DB_PASSWORD" \
--     psql "$SUPERUSER_DATABASE_URL" -v ON_ERROR_STOP=1 -f infra/migrations/0006_app_role.sql
--
-- or afterwards by hand:
--
--   ALTER ROLE orrery_app PASSWORD '…';
--
-- Without a password the role exists and cannot connect, which fails closed.
-- The migration says so rather than leaving it to be discovered.
--
-- ── Reversing it ───────────────────────────────────────────────────────────
--
-- Point DATABASE_URL back at the superuser and restart. The role can then be
-- left in place; it holds no objects. To remove it entirely:
--
--   REVOKE ALL ON ALL TABLES IN SCHEMA public FROM orrery_app;
--   REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM orrery_app;
--   REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM orrery_app;
--   REVOKE USAGE ON SCHEMA public FROM orrery_app;
--   ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON TABLES FROM orrery_app;
--   ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON SEQUENCES FROM orrery_app;
--   ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON FUNCTIONS FROM orrery_app;
--   DROP ROLE orrery_app;
--
-- Idempotent: safe to re-run. Re-running re-derives the grants from the schema
-- as it stands at that moment, which is how a table added later gets covered.

\set ON_ERROR_STOP on

-- ── The role ───────────────────────────────────────────────────────────────
--
-- NOSUPERUSER is the point of the change. NOBYPASSRLS matters for the same
-- reason and is stated explicitly rather than left to the default: a role with
-- BYPASSRLS is exempt from row policies exactly as a superuser is, so acquiring
-- it later would undo this change without looking like it had.

DO $$
DECLARE
    supplied_password text := current_setting('orrery.app_password', true);
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'orrery_app') THEN
        EXECUTE 'CREATE ROLE orrery_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE '
                'NOREPLICATION NOBYPASSRLS';
        RAISE NOTICE 'created role orrery_app';
    ELSE
        -- Re-assert the attributes rather than assuming them: a role that
        -- already exists may have been granted more since it was created.
        EXECUTE 'ALTER ROLE orrery_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE '
                'NOREPLICATION NOBYPASSRLS';
        RAISE NOTICE 'role orrery_app already present; attributes re-asserted';
    END IF;

    IF supplied_password IS NOT NULL AND supplied_password <> '' THEN
        EXECUTE format('ALTER ROLE orrery_app PASSWORD %L', supplied_password);
        RAISE NOTICE 'password set from orrery.app_password';
    ELSIF NOT EXISTS (
        SELECT 1 FROM pg_authid WHERE rolname = 'orrery_app' AND rolpassword IS NOT NULL
    ) THEN
        RAISE NOTICE 'orrery_app has NO PASSWORD and cannot connect. Set one with: '
                     'ALTER ROLE orrery_app PASSWORD ''…'';';
    END IF;
END
$$;

-- ── The grants, derived from the schema ────────────────────────────────────
--
-- `ON ALL TABLES IN SCHEMA public` enumerates the catalog at execution time, so
-- it covers every table and view present when it runs — 114 tables and views
-- when this was written, and whatever is there when it is next run.
-- A hand-written list would omit one, and the omission would surface as a 500
-- on whichever rarely-exercised path reads it.
--
-- ALTER DEFAULT PRIVILEGES covers objects created LATER by the role running
-- this migration, which is the superuser that applies every migration. Without
-- it, a table added by a future migration would be invisible to the app until
-- someone remembered to re-run this file.

GRANT USAGE ON SCHEMA public TO orrery_app;

GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO orrery_app;

-- USAGE for nextval, SELECT for currval, UPDATE for setval. A role with INSERT
-- but no sequence privilege fails on the row that first needs a generated id,
-- not at startup.
GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO orrery_app;

GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO orrery_app;

ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO orrery_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO orrery_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT EXECUTE ON FUNCTIONS TO orrery_app;

-- Deliberately NOT granted:
--   CREATE ON SCHEMA public — the application issues no DDL.
--   TRUNCATE, REFERENCES, TRIGGER — unused, and TRUNCATE bypasses DELETE rules.
--   Ownership of any object — an owner can ALTER and DROP what it owns, and is
--   exempt from row policies unless the table carries FORCE.

-- ── What was actually granted ──────────────────────────────────────────────
-- Printed so the operator sees the count rather than trusting that the grant
-- statement matched anything at all.

DO $$
DECLARE
    granted_tables int;
    total_tables int;
BEGIN
    SELECT count(*) INTO total_tables
      FROM information_schema.tables
     WHERE table_schema = 'public' AND table_type IN ('BASE TABLE', 'VIEW');

    SELECT count(DISTINCT table_name) INTO granted_tables
      FROM information_schema.role_table_grants
     WHERE table_schema = 'public' AND grantee = 'orrery_app';

    RAISE NOTICE 'orrery_app: % of % tables and views in schema public are granted',
        granted_tables, total_tables;

    -- An empty schema satisfies "granted = present" trivially, so the equality
    -- alone would report success against a database with nothing in it — which
    -- is what happens if this runs before the schema is loaded.
    IF total_tables = 0 THEN
        RAISE EXCEPTION 'schema public has no tables: this ran before the schema was loaded, and granted nothing';
    END IF;

    IF granted_tables <> total_tables THEN
        RAISE EXCEPTION 'grant coverage is incomplete: % granted, % present', granted_tables, total_tables;
    END IF;
END
$$;
