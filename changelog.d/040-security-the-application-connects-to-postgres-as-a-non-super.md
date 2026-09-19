### Security — the application connects to Postgres as a non-superuser role

The server connected as `postgres`. A superuser can `DROP` any table, read
`pg_shadow`, and `COPY FROM PROGRAM`, which runs arbitrary commands on the
database host. The application needs none of that: it issues `SELECT`, `INSERT`,
`UPDATE` and `DELETE`, and no DDL against Postgres.

`infra/migrations/0006_app_role.sql` creates `orrery_app` with `NOSUPERUSER`,
`NOCREATEDB`, `NOCREATEROLE`, `NOREPLICATION` and `NOBYPASSRLS`, and grants it
those four privileges plus sequence and function usage. The grants are derived
from the catalog at execution time rather than listed, so they cover every table
present when the migration runs — 114 tables and views at the time of writing —
and `ALTER DEFAULT PRIVILEGES` covers tables a later migration adds. `CREATE` on
the schema is deliberately not granted.

The migration is idempotent and documents its own reversal. It refuses to report
success against an empty schema, because "granted equals present" is satisfied
by zero and zero.

Fresh installs get the role during database initialisation via
`infra/03-app-role.sh`, which runs the same migration file rather than a second
copy of the grant list. **Existing databases must apply the migration before
`DATABASE_URL` is pointed at the role**; `infra/migrations/README.md` gives the
command. A server whose authentication is refused now logs the remedy, naming
both possible causes — Postgres reports the same error for a role that does not
exist and for a wrong password.

`APP_DB_PASSWORD` is a new required variable for the `db` service and the server.

Verified by driving the application against a real Postgres as the role:
registration, a signed directory read, an intent write, an audit-ledger append
with its hash-chain read, a retention sweep that deletes across every catalogued
table, and the federation feed's read and log write. Separately, the role is
refused `pg_shadow`, `DROP TABLE`, `COPY TO PROGRAM`, `CREATE TABLE` and
`ALTER TABLE`.

Not included: row-level security policies. No policy can have any effect while
the application connects as a superuser, so this is the prerequisite — but it
stands on its own, and is not a partial implementation of anything.
