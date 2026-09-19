# C4 — Row-Level Security: runtime role added, policies still open

**Policy scope only. No RLS implementation.** Per-table RLS across a hundred
tables is a schema-wide change with a real chance of silently breaking
production reads. The first prerequisite identified here landed separately:
a pre-release change, landed 2026-08-15,
changed the Compose default for the server database connection to a
non-superuser runtime role. This document preserves the corrections to the
original finding and records what remains before the database enforces row
isolation.

Current facts are from `infra/init.sql`, `infra/migrations/0006_app_role.sql`,
`docker-compose.yml`, and `server/tests/test_app_role_migration.py` as of
2026-09-10.

## The headline: Compose defaults to the app role; RLS is not implemented

Postgres still initializes and applies migrations as its superuser, but Compose
defaults the request-serving application to `orrery_app`:

```yaml
POSTGRES_USER: ${POSTGRES_USER:-postgres}
DATABASE_URL: postgres://${APP_DB_USER:-orrery_app}:...@db:5432/...
```

`infra/migrations/0006_app_role.sql` creates that role with `NOSUPERUSER` and
`NOBYPASSRLS`, grants row-wide `SELECT`, `INSERT`, `UPDATE`, and `DELETE`, and
grants sequence and function access without transferring object ownership.
Operators can override `APP_DB_USER` or the whole `DATABASE_URL`, so the role is
a repository and Compose default, not proof of every deployment's state.
PostgreSQL exempts superusers and roles with `BYPASSRLS` from every row-security
policy, so removing those attributes from the default runtime path was the
prerequisite for meaningful policies.

The repository now provides that prerequisite and Compose defaults to it. Policy
implementation is not present: the schema has no `CREATE POLICY` and no
`ENABLE ROW LEVEL SECURITY`, plus no request identity plumbing for policies to
read. The application role therefore retains row-wide access wherever its table
grants permit it, and application-layer authorization still carries the whole
per-member isolation boundary.

**Answer to the brief's question — "is RLS meaningful under a single pooled
application role?"** Under `orrery_app`, it can be meaningful but remains
limited — see "What policies could key on" below. The role was a prerequisite,
not a policy implementation.

## Two corrections to the finding as written

**1. `init.sql:24` is not a global disable.** The audit reads
`SET row_security = off` as the database being configured with RLS off. It is a
per-session GUC, and it sits in the middle of `pg_dump`'s standard prologue:

```sql
SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;      -- ← line 24
```

Every line around it is dump boilerplate. It applies to the restoring session
only and has no effect on the running server or on later connections. Removing
it would change nothing. The finding should not cite it as the mechanism.

**2. `agent_private_memory` does not have working RLS either.** The audit says
it is the one table with `FORCE RLS`. It has exactly one line:

```sql
ALTER TABLE ONLY public.agent_private_memory FORCE ROW LEVEL SECURITY;
```

There is no `ENABLE ROW LEVEL SECURITY` and no `CREATE POLICY` anywhere in the
schema. `FORCE` without `ENABLE` does nothing; `ENABLE` with no policies would
deny all access to non-exempt roles. So the coverage today is **zero tables**,
not one — and the one table cited as protected is protected by a line that is
inoperative.

Both corrections remain important when reading the original finding: RLS
coverage is zero tables. The application-role change removes the blanket bypass
that would have made future policies inert; it does not add coverage.

## Scale

**111 tables** (`CREATE TABLE` count), not "60+".

The audit's "at minimum" set — tables holding keys, tokens, credentials or
personal data — resolves to roughly:

| Class | Tables |
|---|---|
| Keys / tokens / credentials | `agent_api_keys`, `chapter_keys`, `member_key_rotations`, `agent_calendar_connections`, `agent_sessions`, `agent_settings` |
| Private agent state | `agent_private_memory`, `agent_memory`, `agent_knowledge`, `agent_thoughts`, `agent_conversations`, `agent_conversation_threads` |
| Person-identifying | `agents`, `chapter_members`, `member_expertise_tags`, `member_looking_for`, `member_offering`, `committee_members`, `group_members`, `research_team_members`, `user_roles` |
| Accountability record | `arp_receipts`, `agent_authority_scope`, `agent_authority_usage`, `agent_action_outcomes` |

That is ~25 tables for a first pass, not 111 — the rest are scoped by `chapter_id` or
derived data where row-level isolation buys little.

## What policies could key on

The application is one process holding one pooled connection set. It does not
open a connection per member, so there is no natural `current_user` to key on.
The two workable shapes:

1. **`SET LOCAL` a request identity per transaction**, and have policies read it
   (`current_setting('orrery.agent_id', true)`). This is the standard pattern
   for a pooled app role. It requires every data path in `pg_store` to set the
   variable inside the transaction, and it is only as strong as the weakest call
   site — a query that forgets the `SET LOCAL` sees either everything or
   nothing, depending on policy default.
2. **Separate roles per trust boundary** (e.g. a read-only reporting role).
   Coarser, far less code, and it composes with (1) rather than competing.

Both presuppose the application is *not* a superuser. The Compose default now
satisfies that prerequisite; an operator override may not. Neither policy shape
or its required `pg_store` plumbing is implemented.

## Recommended sequencing

RLS is defence in depth *behind* the application-layer authorisation that
currently carries the whole load. It is worth having, and it is worth having in
this order:

1. **Complete in the Compose default — create a non-superuser runtime role and
   default `DATABASE_URL` to it.** A pre-release change
   landed this on 2026-08-15. `0006_app_role.sql` gives the role broad CRUD,
   sequence, and function grants while withholding superuser, `BYPASSRLS`,
   schema `CREATE`, and object ownership. This reduces cluster and DDL
   privileges even though no policy is written. Operators can select another
   role or URL, so deployment conformance remains an operator fact.
2. Make `agent_private_memory` actually enforce: `ENABLE ROW LEVEL SECURITY` plus
   a real policy. One table, the most sensitive one, as the pattern to copy.
3. Introduce the `SET LOCAL` identity plumbing in `pg_store` with policies on the
   keys/tokens set (6 tables).
4. Widen to the rest of the ~25-table set only after (3) has survived contact.

Policies written before step 1 would have been inert, untested, and
indistinguishable from working. With the role available and defaulted in
Compose, the remaining policy work can now be tested against the intended
request-serving role.

## Bottom line for the register

C4 is real, but it is mis-stated in three ways: the cited mechanism
(`row_security = off`) is inert dump boilerplate; the one table cited as
protected is not; and the scale is 111 tables, not 60+. The non-superuser role
and Compose default landed in a pre-release change
on 2026-08-15. The remaining actionable finding is:

> The application role has row-wide DML grants, no row-level-security policies
> exist, and the database does not enforce per-row isolation.

The `orrery_app` default reduces cluster and DDL privileges relative to
`postgres` and makes future policies enforceable when that role is used. It does
not itself close C4; sequencing steps 2 through 4 remain open.
