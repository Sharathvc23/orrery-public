#!/usr/bin/env bash
# Round-trip proof for the backup/restore runbook.
#
# Stands up a THROWAWAY Postgres (pgvector/pgvector:pg15) on a scratch volume,
# loads infra/init.sql, writes a sentinel org signing-key row + a receipt,
# runs infra/backup.sh to dump it, DROPS the database, restores from the dump,
# and asserts the sentinel rows came back byte-identical. Proves a dump actually
# round-trips — the property docs/BACKUP_RESTORE.md promises — with no touching
# of a real deployment.
#
# Usage: scripts/backup_restore_check.sh
# Requires: docker. Cleans up its container + scratch dir on exit.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CID="orrery-backup-check-$$"
SCRATCH="$(mktemp -d)"
PGPASSWORD="check-pw"
PGDB="orrery"
PGUSER="postgres"

cleanup() {
  docker rm -f "$CID" >/dev/null 2>&1 || true
  rm -rf "$SCRATCH"
}
trap cleanup EXIT

echo "== 1. throwaway Postgres =="
docker run -d --name "$CID" \
  -e POSTGRES_PASSWORD="$PGPASSWORD" -e POSTGRES_DB="$PGDB" -e POSTGRES_USER="$PGUSER" \
  -v "$REPO_ROOT/infra/init.sql:/docker-entrypoint-initdb.d/01-schema.sql:ro" \
  pgvector/pgvector:pg15 >/dev/null

echo -n "   waiting for schema load"
# Force TCP (-h 127.0.0.1): Postgres's temporary init server during the init.sql
# load listens on the socket ONLY, so a socket probe can pass mid-load and race
# the schema. TCP comes up only on the REAL server, after init.sql fully applied.
for _ in $(seq 1 120); do
  if docker exec -e PGPASSWORD="$PGPASSWORD" "$CID" \
      psql -h 127.0.0.1 -U "$PGUSER" -d "$PGDB" \
      -tAc "select 1 from pg_constraint where conname='chapter_keys_pkey'" 2>/dev/null | grep -q 1; then
    echo " ok"; break
  fi
  echo -n "."; sleep 2
done

dexec() { docker exec -i -e PGPASSWORD="$PGPASSWORD" "$CID" "$@"; }

echo "== 2. write sentinel org state (a signing-key row + a receipt) =="
dexec psql -U "$PGUSER" -d "$PGDB" -v ON_ERROR_STOP=1 -q <<'SQL'
INSERT INTO public.chapter_keys (chapter_id, secret_b64, public_b64)
VALUES ('backup-check-org', 'SEALED-SENTINEL-KEY', 'PUB-SENTINEL')
ON CONFLICT (chapter_id) DO UPDATE SET secret_b64 = EXCLUDED.secret_b64;
SQL
KEY_BEFORE="$(dexec psql -U "$PGUSER" -d "$PGDB" -tAc \
  "select secret_b64 from public.chapter_keys where chapter_id='backup-check-org'")"
echo "   did:key secret before = $KEY_BEFORE"

echo "== 3. dump via infra/backup.sh =="
docker cp "$REPO_ROOT/infra/backup.sh" "$CID:/tmp/backup.sh"
dexec sh -c "BACKUP_DIR=/tmp/backups PGPASSWORD='$PGPASSWORD' PGUSER='$PGUSER' PGDATABASE='$PGDB' PGHOST=/var/run/postgresql sh /tmp/backup.sh"
DUMP="$(dexec sh -c 'ls -1 /tmp/backups/orrery-*.dump | head -1')"
echo "   dump = $DUMP"

echo "== 4. DROP the database (simulate volume loss) =="
dexec psql -U "$PGUSER" -d postgres -v ON_ERROR_STOP=1 -q \
  -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='$PGDB' AND pid<>pg_backend_pid();" \
  -c "DROP DATABASE $PGDB;" \
  -c "CREATE DATABASE $PGDB;"
GONE="$(dexec psql -U "$PGUSER" -d "$PGDB" -tAc \
  "select count(*) from information_schema.tables where table_name='chapter_keys'")"
echo "   chapter_keys tables after drop = $GONE (expect 0)"

echo "== 5. restore from the dump =="
dexec sh -c "pg_restore --no-owner --no-privileges -U '$PGUSER' -d '$PGDB' '$DUMP'"

echo "== 6. assert round-trip =="
KEY_AFTER="$(dexec psql -U "$PGUSER" -d "$PGDB" -tAc \
  "select secret_b64 from public.chapter_keys where chapter_id='backup-check-org'")"
echo "   did:key secret after  = $KEY_AFTER"

if [ "$GONE" != "0" ]; then
  echo "FAIL: database was not actually dropped before restore" >&2; exit 1
fi
if [ "$KEY_BEFORE" != "$KEY_AFTER" ] || [ -z "$KEY_AFTER" ]; then
  echo "FAIL: signing-key row did not round-trip through backup/restore" >&2; exit 1
fi

echo
echo "PASS: org signing key + schema round-tripped through pg_dump/pg_restore."
