-- 0008 — rate-limiter state that survives a restart
--
-- The per-IP limiter kept its buckets in one process-local OrderedDict keyed on
-- `time.monotonic()`. Monotonic time is meaningless across processes, so a
-- restart did not merely lose the buckets — there was no representation in which
-- they could have been carried over. Every client's quota reset to full on every
-- deploy, crash and restart, and the code already said so: the ceiling comment
-- on /api/surfaces/compose notes the window is "per-source and per-process".
--
-- This table is the durable half. The in-memory store stays authoritative for
-- the request path — a limiter that needs a database round trip per request puts
-- the database on the critical path of every unauthenticated call, and a
-- database blip then either fails the request or disables the limiter, both
-- worse than what it fixes. Instead the process snapshots its buckets
-- periodically and rehydrates them at boot.
--
-- WHAT IS AND IS NOT FIXED. Restarts: fixed, to within one flush interval.
-- Horizontal replicas: NOT fixed. Each process still decides alone and now also
-- overwrites the other's snapshot, so N replicas still admit up to N times the
-- configured ceiling. That needs a shared authority (a Redis INCR, or a
-- Postgres-authoritative counter) and is a different change; this table does not
-- pretend to it.
--
-- BUCKET KEYS ARE HASHED, AND THAT IS NOT DECORATION. The key is a client IP.
-- Before this table no schema in the tree stored one — `grep -i ip` over
-- init.sql and every migration returns nothing — so persisting them raw would
-- introduce visitor IP addresses at rest as a new category of data, in a
-- product whose audit scope document enumerates exactly this kind of thing. The
-- limiter never needs the key back; it only needs equality. So what is stored is
-- HMAC-SHA256(salt, key), with the salt held in the org data directory and NOT
-- in this database: a dump of this table alone does not reveal who was throttled.
--
-- Optional by design. Without this table the limiter still limits; it just
-- forgets across restarts, which is exactly today's behaviour. The boot ensure
-- therefore refuses to turn a working install into a non-booting one — same
-- policy, and the same reasoning, as 0005's federation feed.
--
-- WHO CAN CREATE IT, measured rather than assumed. 0006 deliberately withholds
-- CREATE on schema public from the application role, so the boot ensure CANNOT
-- create this table on a least-privilege install — verified against a real
-- Postgres: `permission denied for schema public`. What that means per install:
--
--   * Fresh compose install — created by init.sql as the superuser at database
--     init, and 0006's ALTER DEFAULT PRIVILEGES then grants the app role
--     SELECT/INSERT/UPDATE/DELETE on it. Works with no operator step — PROVIDED
--     the boot ensure looks before it issues DDL. Postgres refuses CREATE TABLE
--     IF NOT EXISTS for want of CREATE on the schema even when the table
--     exists, so an ensure that runs the DDL first is refused on every boot of
--     the default install and reports persistence off over a statement that
--     had nothing to do. That was the shipped behaviour until the ensure was
--     made to probe the table first (server/rate_limit_persistence.py).
--   * Existing install — init.sql does not re-run, and the app role cannot
--     create it. Persistence stays OFF until an operator applies this file as
--     superuser. Nothing breaks; the limiter behaves exactly as it did before.
--   * Running as the superuser — the ensure creates it on first boot.
--
-- Because that degradation is silent by design, `/health` reports
-- `rate_limit_persistence` as a boolean of what THIS process actually has.
-- Reading a boot log of a process that has since been replaced is how
-- TRUSTED_PROXY_HOPS stayed wrong in production for the life of the setting.

CREATE TABLE IF NOT EXISTS public.rate_limit_buckets (
    scope      text        NOT NULL PRIMARY KEY,
    buckets    jsonb       NOT NULL DEFAULT '{}'::jsonb,
    saved_at   timestamptz NOT NULL DEFAULT now()
);

COMMENT ON TABLE public.rate_limit_buckets IS
    'Periodic snapshot of the in-memory per-client rate-limit buckets, so a '
    'restart does not hand every client a fresh quota. One row per org scope. '
    'Keys are HMAC-SHA256 of the client key under a salt stored outside this '
    'database. Entries older than the limiter window are discarded on restore.';
