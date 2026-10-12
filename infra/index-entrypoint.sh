#!/bin/sh
# Adopt the index's data directory, then drop privileges and exec the index.
#
# WHY THIS EXISTS. The image declared USER orrery (uid 10001) and the platform
# mounts a volume over /data owned by root, so sqlite could not write and EVERY
# index write failed with
#
#     sqlite3.OperationalError: attempt to write a readonly database
#
# That failure was invisible for months because two other errors masked it: the
# index answered 503 to writes while INDEX_WRITE_TOKEN was unset, and 401 to the
# writers that presented no token. Only once both were fixed did the request
# reach the storage layer and surface the real fault. Meanwhile reads worked, so
# three orgs resolved in an index whose records could not change — a frozen
# registry is indistinguishable from a working one from the outside.
#
# A build-time chown cannot fix a runtime mount: at build time /data is an empty
# directory in the image, and at runtime the volume is mounted over it carrying
# whatever ownership the writer had. The ownership has to be adjusted after the
# mount and before privileges drop, which is what this script is for. Same
# reasoning, same mechanism and the same base image as infra/agent-entrypoint.sh
# — see that file for the incident that established the pattern.
#
# It is NOT a way back to running as root. The index process still runs as
# orrery; only this preamble is privileged, and it execs so no root process
# survives it.

set -eu

DB_PATH="${INDEX_DB_PATH:-/data/index.db}"
DB_DIR="$(dirname "$DB_PATH")"
INDEX_UID="${INDEX_UID:-10001}"
INDEX_GID="${INDEX_GID:-10001}"

log() { printf 'entrypoint: %s\n' "$*" >&2; }

# Fail rather than start when the index cannot write. Starting anyway is worse
# than a crash: reads keep answering, so the service presents as healthy while
# every registration and every refresh is silently rejected — which is exactly
# the state this fixes, and it lasted because nothing refused to boot.
assert_writable() {
    if setpriv --reuid="$INDEX_UID" --regid="$INDEX_GID" --clear-groups \
        sh -c "test -w '$DB_DIR' && { test ! -e '$DB_PATH' || test -w '$DB_PATH'; }"; then
        return 0
    fi
    log "FATAL: ${DB_PATH} is not writable by uid ${INDEX_UID} after adopting ${DB_DIR}."
    log "The volume is most likely mounted read-only. Refusing to start: an index that"
    log "serves reads while refusing every write looks healthy and is not."
    exit 1
}

if [ "$(id -u)" = "0" ]; then
    mkdir -p "$DB_DIR"

    # NOT RECURSIVE, DELIBERATELY. $DB_DIR is normally /data — the mount root,
    # which is not this image's to rewrite: an operator may keep other subtrees
    # there, and recursively changing ownership of a whole mounted volume is a
    # destructive act on data this service does not own. sqlite needs the
    # directory writable (for -wal/-journal) plus its own files, and that is all
    # that is taken.
    owner="$(stat -c '%u' "$DB_DIR")"
    if [ "$owner" = "$INDEX_UID" ]; then
        :
    else
        log "adopting ${DB_DIR}: owned by uid ${owner}, index runs as ${INDEX_UID}"
        if ! chown "${INDEX_UID}:${INDEX_GID}" "$DB_DIR"; then
            log "FATAL: could not change ownership of ${DB_DIR} (read-only mount?)."
            exit 1
        fi
    fi
    for f in "$DB_PATH" "${DB_PATH}-wal" "${DB_PATH}-shm" "${DB_PATH}-journal"; do
        [ -e "$f" ] || continue
        chown "${INDEX_UID}:${INDEX_GID}" "$f" || log "WARNING: could not adopt ${f}"
    done

    assert_writable
    # setpriv changes the uid and nothing else, so the environment it hands on
    # is still root's — including HOME=/root, which uid 10001 cannot write.
    # Under the USER instruction this replaces, Docker set HOME from
    # /etc/passwd. Restore it explicitly.
    HOME="${INDEX_HOME:-/home/orrery}"
    export HOME
    # exec, so no privileged process outlives this preamble.
    exec setpriv --reuid="$INDEX_UID" --regid="$INDEX_GID" --init-groups -- "$@"
fi

# Not root: the platform pinned a uid of its own. Nothing to adopt and nothing
# to drop, so say so and verify the volume is usable rather than discovering it
# on the first write.
log "running as uid $(id -u); ownership was not adjusted"
assert_writable
exec "$@"
