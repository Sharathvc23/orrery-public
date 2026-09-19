### Rate-limit persistence engages on the default install

A fresh `./orrery-up` install with a database logged
`[rate-limit] persistence unavailable (InsufficientPrivilegeError: permission
denied for schema public) — limiter is in-memory only` and `/health` read
`rate_limit_persistence: false`. Found on a stranger drive of the shipped
installer, which is the install every new operator runs.

The table was there. `infra/init.sql` creates `rate_limit_buckets` as the
superuser on every fresh install and the application-role migration grants that
role DML on it. But the boot ensure ran `CREATE TABLE IF NOT EXISTS`
unconditionally, and Postgres refuses that for want of CREATE on the schema
**even when the table exists** — measured against a real Postgres with the
application role: the CREATE is refused, the `COMMENT ON` is refused, and an
`INSERT` into the same table a moment later succeeds. The ensure read the
refusal as "no table". The migration's own header had claimed the fresh-install
path "works with no operator step"; it now says what the step was.

**The ensure now looks before it issues DDL.** It is handed a probe — a one-row
read of the table through the same request path the runtime uses — and consults
it first; the DDL is attempted only when the table is absent, which on a default
install is never. The federation feed's ensure already had this shape for the
same reason. No grant on the application role is widened; the degrade message
now names the migration and the superuser.

**The installer asserts it.** The sign-of-life drill polls `/health` for
`rate_limit_persistence` being exactly `true`, so the installer job goes red if
a default install ever boots with persistence off again — the field was on the
endpoint the whole time and nothing looked.

Guarded, each planted and observed reddening by name, the tree clean after each
revert: the ensure ignoring the probe and running DDL first (the shipped
defect — the module test and the boot-wiring test through the real lifespan);
the boot handing the ensure no probe (the wiring test); `init.sql` no longer
declaring the table (the parity test against the migration); the drill
loosening its assertion to "the field is present" (the installer guard).
Verified end to end against a real Postgres carrying the application role:
old shape `False` with the stranger's exact log line, new shape `True`,
snapshot written and read back.
