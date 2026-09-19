### No function in the schema runs as the table owner

`init.sql` declared thirteen `SECURITY DEFINER` functions. Such a function
executes as the role that created it — the superuser that ran `init.sql` —
rather than as the caller, so any flaw in its body is a flaw with full
table-owner access, and the application role's least-privilege grants do not
apply inside it. The audit had recorded them as open, unassessed.

Each is now assessed. Seven served only the forty-five dead tables and went
with them. Five were orphans of the earlier hosting platform: no trigger or code
path reaches them, `update_last_active` calls `auth.uid()`, which does not exist
in this database, and the profile auto-join trigger inserted a hard-coded
organisation id that would have violated a foreign key the first time anything
inserted a profile. Migration `0010` drops those five and their one trigger.
The sixth, `update_updated_at_column` — a generic `updated_at` bump on five
triggers that touches no table — is kept as `SECURITY INVOKER`. The schema now
declares none, and a guard fails by name if one is added. Verified on Postgres
15: a database migrated from the old schema (0010 applied before 0009, then
0009) and one created from the new `init.sql` agree on every function's
security mode, every column and every trigger.

Guarded: a `SECURITY DEFINER` function planted into `init.sql` reddens the guard
naming it; the tree clean after the revert.
