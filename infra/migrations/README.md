# Schema migrations

`infra/init.sql` is the schema for a **fresh** database — Postgres runs it only
on first initialisation. A change made there never reaches a database that
already exists.

These files carry those changes to existing databases. **There is no runner and
nothing applies them automatically.** They are applied by hand:

```bash
psql "$DATABASE_URL" -f infra/migrations/0001_service_role.sql
```

Stated plainly because the alternative is worse: a migration directory that
looks automatic, and a schema change that silently never lands on the one
database that matters. Every file here must be idempotent so a re-run is safe
and so "did this already run?" never needs answering from memory.

When adding a schema change, change **both** `init.sql` (so fresh installs are
correct) and add a numbered file here (so existing installs can catch up). A
change in only one of the two produces installs that disagree about their own
schema.

## 0006 needs two steps, and the order matters

`0006_app_role.sql` creates the role the application connects as. On an existing
database, apply it **before** pointing `DATABASE_URL` at that role — the two are
separate actions and doing them in the other order means a running server that
cannot authenticate.

```bash
PGOPTIONS="-c orrery.app_password=$APP_DB_PASSWORD" \
  psql "$SUPERUSER_DATABASE_URL" -v ON_ERROR_STOP=1 -f infra/migrations/0006_app_role.sql
# then set APP_DB_PASSWORD in .env and restart the server
```

Postgres reports the same error for a role that does not exist and for a wrong
password, so a server that cannot connect after this cannot tell you which it
was. The log names both.

A fresh install needs neither step: `infra/03-app-role.sh` runs the same file
during database initialisation.

## 0009 drops only what is empty, and refuses by name otherwise

`0009_drop_unreferenced_tables.sql` removes forty-five tables that no non-test
source in this repository reads — the fossil of the product this codebase was
before it became an agent-native org — plus the two triggers, one foreign key,
eight functions and two enum types that existed only to serve them. A fresh
install never creates them any more; `tests/test_init_sql_has_no_dead_tables.py`
fails, naming the table, if one is ever added back without a reader.

On an existing database the migration **counts every one of the tables
first**. If any holds a row it raises, naming each such table with its row
count, and drops nothing: a table with data in a live org is a finding for the
operator, not something a migration deletes. Export or delete those rows by
hand, then re-run. A table that is already absent is skipped, so a re-run is
safe. Apply as the superuser — the application role has no `DROP`:

```bash
psql "$SUPERUSER_DATABASE_URL" -v ON_ERROR_STOP=1 -f infra/migrations/0009_drop_unreferenced_tables.sql
```

## 0010 removes the last SECURITY DEFINER functions

`0010_no_security_definer.sql` drops five functions no trigger or code path
reaches — orphans of an earlier hosting platform, one of which called
`auth.uid()` and one of which would have violated a foreign key the first time
anything inserted a profile — and makes the one that stays,
`update_updated_at_column`, `SECURITY INVOKER`. Independent of 0009 (every
statement is guarded; apply in either order). Apply as the superuser.
