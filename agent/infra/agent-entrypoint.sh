#!/bin/sh
# Adopt the identity volume, then drop privileges and exec the agent.
#
# WHY THIS EXISTS. The image declares USER orrery (uid 10001) and the Dockerfile
# used to chown /data at BUILD time, with a comment claiming a mounted volume
# would "inherit the right uid". It does not: at build time /data is an empty
# directory in the image, and at runtime the platform mounts a volume OVER it
# carrying whatever ownership the writer had. Agents shipped before the non-root
# change ran as root and wrote keystore.enc as root:root mode 0600, so uid 10001
# could not read it and the container crashed on boot with
#
#     PermissionError: [Errno 13] Permission denied:
#     '/data/.community-member/keystore.enc'
#
# A build-time chown cannot fix a runtime mount. The ownership has to be
# adjusted after the volume is mounted and before privileges drop, which is what
# this script is for.
#
# It is NOT a way back to running as root. The agent process still runs as
# orrery; only this preamble is privileged, and it execs so no root process
# survives it.

set -eu

HOME_DIR="${COMMUNITY_MEMBER_HOME:-/data/.community-member}"
AGENT_UID="${AGENT_UID:-10001}"
AGENT_GID="${AGENT_GID:-10001}"
VAULT="${HOME_DIR}/keystore.enc"

log() { printf 'entrypoint: %s\n' "$*" >&2; }

# Fail rather than proceed when the agent could not read its own identity. The
# alternative is worse than a crash: an unreadable vault that presented as an
# absent one would mint a fresh did:key and orphan every registration the old
# identity holds.
assert_readable() {
    [ -e "$VAULT" ] || return 0
    if setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups test -r "$VAULT"; then
        return 0
    fi
    log "FATAL: ${VAULT} is not readable by uid ${AGENT_UID} after adopting ${HOME_DIR}."
    log "The identity volume is owned by a uid this container cannot read and could not"
    log "be adopted — most likely the volume is mounted read-only. Refusing to start:"
    log "continuing would mint a new did:key and orphan this agent's registrations."
    exit 1
}

if [ "$(id -u)" = "0" ]; then
    # SCOPED TO COMMUNITY_MEMBER_HOME, NOT /data, DELIBERATELY.
    #
    # /data is the mount root and is not this image's to rewrite. An operator may
    # keep other subtrees there — backups, another service sharing the volume —
    # and recursively changing ownership of a whole mounted volume is a
    # destructive act on data this agent does not own. COMMUNITY_MEMBER_HOME is
    # the one directory the agent owns by contract. It is also the cheap choice:
    # chown -R over an arbitrarily large volume on every boot is not free.
    mkdir -p "$HOME_DIR"

    # Idempotent and cheap on the normal path: a directory already owned by the
    # agent is left alone, so a correctly-owned volume costs one stat per boot
    # rather than a recursive walk.
    owner="$(stat -c '%u' "$HOME_DIR")"
    if [ "$owner" = "$AGENT_UID" ]; then
        :
    else
        log "adopting ${HOME_DIR}: owned by uid ${owner}, agent runs as ${AGENT_UID}"
        if ! chown -R "${AGENT_UID}:${AGENT_GID}" "$HOME_DIR"; then
            log "FATAL: could not change ownership of ${HOME_DIR}."
            log "The volume is most likely mounted read-only. Refusing to start rather than"
            log "failing later on the first read of the identity vault."
            exit 1
        fi
    fi

    assert_readable
    # setpriv changes the uid and nothing else, so the environment it hands on is
    # still root's — including HOME=/root, which uid 10001 cannot write. Under the
    # USER instruction this replaces, Docker set HOME from /etc/passwd, so the
    # agent saw HOME=/home/orrery. Restore that explicitly rather than leaving
    # anything that resolves "~" pointed at root's home.
    HOME="${AGENT_HOME:-/home/orrery}"
    export HOME
    # exec, so no privileged process outlives this preamble.
    exec setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --init-groups -- "$@"
fi

# Not root: the platform pinned a uid of its own. There is nothing to adopt and
# nothing to drop, so verify the volume is usable and say so plainly if it is
# not, rather than starting and failing on the first vault read.
log "running as uid $(id -u); ownership was not adjusted"
assert_readable
exec "$@"
