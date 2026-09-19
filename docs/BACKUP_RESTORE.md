# Backup & restore

All durable org state — the org **signing key** (its `did:key` identity),
members, ARP receipts, the trust ledger — lives in
the Postgres database, on the named Docker volume **`db-data`**. Lose that volume
without a backup and you lose the org's cryptographic identity **irrecoverably**:
there is no certificate authority to re-issue a `did:key`, and every receipt and
federation signature the org ever made was signed by that key. A new key is a
new, unrelated org.

> ⚠️ **`did:key` loss is unrecoverable.** Treat a database backup as protecting
> the org's *identity*, not just its data. And see
> [The signing key needs one more thing](#the-signing-key-needs-one-more-thing)
> — with `ORRERY_KEY_SECRET` set, the database backup alone is not enough.

This runbook covers a logical `pg_dump`/`pg_restore` backup, an optional
scheduled-dump sidecar, and a restore procedure that is verified end-to-end by
`scripts/backup_restore_check.sh`.

---

## What to back up

| Item | Where it lives | In the DB dump? |
| --- | --- | --- |
| Signing key, members, receipts, trust ledger, memory receipts | Postgres (`db-data` volume) | ✅ yes |
| `ORRERY_KEY_SECRET` (seals the signing key at rest) | your `.env` / secret store | ❌ **no — back up separately** |
| First-run org config + issuer log | `server-data` volume (`server/.org`) | ❌ regenerated / mirrors the DB; optional |

The database dump is the one that matters. The two notes below are the ways a
dump can still leave you unable to restore a *working* identity.

### The signing key needs one more thing

`ORRERY_KEY_SECRET` is [required to start the server](./CONFIGURATION.md), so the
signing key is **sealed** (AES-256-GCM) in its `chapter_keys` database row.
That is deliberate — a leaked database dump is then *not* forgery material. But
it also means **the dump cannot be restored to a working org without the same
`ORRERY_KEY_SECRET`.** (To change it, set the new value and put the old one in
`ORRERY_KEY_SECRET_PREVIOUS` for one restart — see `CONFIGURATION.md`; a backup
taken before the rotation needs the secret it was sealed under.) Back that secret
up separately, in your secret manager,
and just as carefully as the database. A dump plus a lost `ORRERY_KEY_SECRET` is
the same outcome as a lost volume: unrecoverable identity.

---

## Manual backup

A single compressed, custom-format dump (restores with `pg_restore`):

```bash
# From the host, against the running compose stack:
docker compose exec -T db \
  pg_dump --format=custom --no-owner --no-privileges \
          -U "$POSTGRES_USER" "$POSTGRES_DB" \
  > "orrery-$(date -u +%Y%m%dT%H%M%SZ).dump"
```

Or use the bundled script (the same one the sidecar runs), which adds a
timestamped filename, an empty-dump guard, and retention pruning:

```bash
docker compose exec -T -e BACKUP_DIR=/tmp db sh /dev/stdin < infra/backup.sh
docker compose cp db:/tmp/backups ./backups     # copy the dump out to the host
```

Store the dump **off the host** (object storage, another machine). A backup that
lives only on the same disk as `db-data` does not survive the failure you are
backing up against.

---

## Scheduled backups (optional sidecar)

An opt-in `db-backup` sidecar runs `infra/backup.sh` on an interval. It is behind
the `backup` compose profile, so a default `docker compose up` is unchanged:

```bash
docker compose --profile backup up -d
```

Configure via `.env` (all optional):

| Variable | Default | Meaning |
| --- | --- | --- |
| `BACKUP_INTERVAL_SECONDS` | `86400` (daily) | Seconds between dumps |
| `BACKUP_RETENTION_DAYS` | `14` | Prune dumps older than this (`0` = keep all) |

Dumps land in the `db-backups` volume. For real durability, mount that volume to
a host path you replicate offsite, e.g. in an override file:

```yaml
services:
  db-backup:
    volumes:
      - /srv/orrery-backups:/backups
```

The sidecar backs up the **database only** — remember the
[`ORRERY_KEY_SECRET` caveat](#the-signing-key-needs-one-more-thing).

---

## Restore

Restore into a **fresh** stack (a new/empty `db-data` volume) using the **same**
`ORRERY_KEY_SECRET` the dump was taken with.

```bash
# 1. Bring up ONLY the database on a clean volume (server stays down).
docker compose up -d db

# 2. Wait until it is really ready (TCP, not the socket-only init server).
until docker compose exec -T db pg_isready -h 127.0.0.1 -U "$POSTGRES_USER" -d "$POSTGRES_DB"; do sleep 2; done

# 3. Restore the dump. --clean --if-exists makes it idempotent over the
#    init.sql-created schema; the dump's own data wins.
docker compose cp ./orrery-YYYYMMDDTHHMMSSZ.dump db:/tmp/restore.dump
docker compose exec -T db \
  pg_restore --clean --if-exists --no-owner --no-privileges \
             -U "$POSTGRES_USER" -d "$POSTGRES_DB" /tmp/restore.dump

# 4. Bring the rest of the org up. Migrations (server/migrations.py) run on boot
#    and no-op on an already-current schema.
docker compose up -d
```

Then confirm the identity is intact:

```bash
curl -s localhost:${SERVER_PORT:-7000}/.well-known/agent-facts.json | grep -i did:key
```

The `did:key` must match the org's previous identity. If it does not, you
restored without the matching `ORRERY_KEY_SECRET` (or into the wrong dump) —
stop and fix that before serving traffic.

---

## Verify it actually round-trips

Don't trust an untested backup. `scripts/backup_restore_check.sh` proves the full
loop on a **throwaway** Postgres (no real deployment touched): it loads
`infra/init.sql`, writes a sentinel signing-key row, dumps via `infra/backup.sh`,
**drops the database**, restores from the dump, and asserts the signing key came
back byte-identical.

```bash
scripts/backup_restore_check.sh
# ...
# PASS: org signing key + schema round-tripped through pg_dump/pg_restore.
```

Run it after any change to the schema or the backup tooling.

---

## Production checklist

- [ ] Scheduled backups running (`docker compose --profile backup up -d`) **or**
      an external managed-Postgres backup, writing **off-host**.
- [ ] `ORRERY_KEY_SECRET` backed up in a secret manager, **separately** from the
      database dump (a sealed dump is useless without it).
- [ ] A restore has been rehearsed on a scratch stack (`scripts/backup_restore_check.sh`
      at minimum; ideally a full restore drill from a real dump).
- [ ] Backups are retained long enough to survive a *late-noticed* corruption,
      not just the last cycle.
