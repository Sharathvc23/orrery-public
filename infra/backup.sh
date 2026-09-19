#!/usr/bin/env sh
# Orrery database backup.
#
# One logical pg_dump of the org database — the single source of durable org
# state (signing key, members, receipts, trust ledger). Custom format (-Fc) so
# it restores with pg_restore and is compressed. Timestamped, with optional
# retention pruning.
#
# Usable two ways, same script:
#   * manually            — `sh infra/backup.sh` (reads DATABASE_URL or PG* env)
#   * as the sidecar loop  — the `db-backup` compose service (profile "backup")
#     calls it on an interval.
#
# LOUD ON FAILURE: `set -e` + explicit checks. A backup that cannot be written
# exits non-zero so a scheduler/operator sees it — never a silent no-backup.
#
# IMPORTANT: the dump captures the org signing key row. When ORRERY_KEY_SECRET
# is set the key is SEALED in the dump (a leaked dump is not forgery material) —
# but that also means the dump is USELESS without ORRERY_KEY_SECRET. Back up
# ORRERY_KEY_SECRET separately and just as carefully. See docs/BACKUP_RESTORE.md.

set -eu

BACKUP_DIR="${BACKUP_DIR:-/backups}"
# Days to keep. 0 disables pruning (keep everything).
RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-14}"

# Connection: prefer a full DATABASE_URL, else assemble from PG*/POSTGRES_* env
# (the names docker-compose already exports for the db service).
if [ -n "${DATABASE_URL:-}" ]; then
  CONN="$DATABASE_URL"
else
  PGHOST="${PGHOST:-db}"
  PGPORT="${PGPORT:-5432}"
  PGUSER="${PGUSER:-${POSTGRES_USER:-postgres}}"
  PGDATABASE="${PGDATABASE:-${POSTGRES_DB:-orrery}}"
  # PGPASSWORD is read from the environment by pg_dump directly.
  export PGPASSWORD="${PGPASSWORD:-${POSTGRES_PASSWORD:-}}"
  CONN=""  # use discrete PG* vars below
fi

mkdir -p "$BACKUP_DIR"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="$BACKUP_DIR/orrery-${STAMP}.dump"

echo "[backup] dumping org database -> ${OUT}"
if [ -n "$CONN" ]; then
  pg_dump --format=custom --no-owner --no-privileges --dbname="$CONN" --file="$OUT"
else
  pg_dump --format=custom --no-owner --no-privileges \
    --host="$PGHOST" --port="$PGPORT" --username="$PGUSER" \
    "$PGDATABASE" --file="$OUT"
fi

# Never claim success on an empty/missing file.
if [ ! -s "$OUT" ]; then
  echo "[backup] FAILED: dump file is missing or empty: $OUT" >&2
  exit 1
fi
echo "[backup] wrote $(wc -c < "$OUT") bytes"

# Retention: prune old dumps (best-effort; a prune failure must not fail the
# backup that already succeeded).
if [ "$RETENTION_DAYS" -gt 0 ] 2>/dev/null; then
  find "$BACKUP_DIR" -name 'orrery-*.dump' -type f -mtime "+${RETENTION_DAYS}" -print -delete 2>/dev/null || true
fi

echo "[backup] done."
