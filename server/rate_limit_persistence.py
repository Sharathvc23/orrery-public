"""Durable half of the per-client rate limiter: snapshot, restore, boot ensure.

WHY THIS EXISTS

``chapter_agent.check_rate_limit`` keeps buckets in a process-local
``OrderedDict`` timestamped with ``time.monotonic()``. Monotonic time is a
process-local clock, so the buckets were not merely lost on restart — there was
no representation in which they could have survived one. Every client's quota
reset to full on every deploy, crash and restart.

WHAT THIS DOES NOT FIX, SAID FIRST

Horizontal replicas. Each process still decides alone, and now also overwrites
the other's snapshot, so N replicas still admit up to N times the configured
ceiling. Fixing that needs a shared authority — a Redis ``INCR``, or a
Postgres-authoritative counter — and a different set of tradeoffs (a database
round trip on the path of every unauthenticated request). This module is
deliberately not that, and the docstrings do not imply otherwise.

THE SHAPE

The in-memory store stays authoritative for the request path. A background task
snapshots it every ``PERSIST_INTERVAL_S``; boot restores it. Worst case, a
restart hands back one flush interval of budget instead of the whole window.

Timestamps cross the process boundary as WALL CLOCK seconds, because monotonic
values from a dead process mean nothing in a new one. ``restore_buckets``
converts each back into the current process's monotonic frame by age, so the
live store keeps the monotonic semantics the limiter was written against —
including immunity to the wall clock being adjusted while the process runs.

KEYS ARE HASHED

The bucket key is a client IP. No table in this tree stored one before this
change. The limiter only ever needs equality, never the original, so what is
persisted is ``HMAC-SHA256(salt, key)`` under a salt kept OUTSIDE the database
— a dump of the table alone does not reveal who was throttled. A salt that is
not the one the snapshot was written under harmlessly orphans it: buckets fail
toward empty, never toward unlimited-but-believed-limited.

THE SALT HAS TO SURVIVE THE BOOT TOO, AND THAT IS A SEPARATE FACT

Restore matches by equality of the hashed key, so the snapshot is only worth
anything if the NEXT process hashes with the SAME salt. The first version of
this module kept the salt in a file under the org data directory and nothing
else. On a container platform where the server service mounts no volume, that
file is minted fresh on every boot, every restored hash fails to match, and the
limiter starts empty — the pre-persistence behaviour, with the table writable
and the health flag reading true. Measured on a live deployment, three
processes, all three reporting persistence on.

So the salt now has a NAMED SOURCE (``resolve_salt``), the source decides
whether it is durable, and ``/health`` reports the source beside the table
flag rather than folding the two into one boolean. ``ORRERY_RATE_LIMIT_SALT``
is the operator-held source for a service without persistent storage; the
file remains the source for an install whose data directory persists, and it
is only reported durable once it has actually been observed to survive a boot.
The salt is never stored beside the hashes in either case.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import time
from collections import OrderedDict
from collections.abc import Callable
from pathlib import Path
from typing import Any

TABLE = "rate_limit_buckets"


#: Seconds between snapshots. The upper bound on how much budget a restart hands
#: back, so it trades database writes against precision. Ten seconds against a
#: sixty-second window returns at most a sixth of a bucket.
def _tunable(raw: str, default: float, *, floor: float, name: str) -> float:
    """A tuning knob for an OPTIONAL feature: a bad value degrades to the default.

    Deliberately not a hard failure. ``ensure_schema`` already refuses to turn a
    working install into a non-booting one for the sake of this feature, and a
    typo in a snapshot interval has no better claim to stopping the server than
    a missing table does. Matches ``TRUSTED_PROXY_HOPS``, which falls back the
    same way for the same reason.

    Takes the VALUE, not the variable name, so the ``os.environ.get`` call keeps
    its string literal at the read site. ``test_env_flags_convention`` resolves
    environment reads statically; a name that only exists as a call argument is
    invisible to it, and an unclassifiable read is exactly what that guard is
    for.
    """
    raw = (raw or "").strip()
    if not raw:
        return default
    try:
        return max(floor, float(raw))
    except ValueError:
        print(f"[rate-limit] {name}={raw!r} is not a number — using {default}")
        return default


PERSIST_INTERVAL_S = _tunable(
    os.environ.get("ORRERY_RATE_LIMIT_PERSIST_INTERVAL_S", ""),
    10.0,
    floor=1.0,
    name="ORRERY_RATE_LIMIT_PERSIST_INTERVAL_S",
)

PERSIST_MAX_KEYS = int(
    _tunable(
        os.environ.get("ORRERY_RATE_LIMIT_PERSIST_MAX_KEYS", ""),
        2000.0,
        floor=1.0,
        name="ORRERY_RATE_LIMIT_PERSIST_MAX_KEYS",
    )
)

_SALT_FILENAME = "rate-limit-salt"
_SALT_BYTES = 32
SALT_ENV = "ORRERY_RATE_LIMIT_SALT"
#: Fewest characters accepted from the environment. The file salt is 32 random
#: bytes and refuses anything under 16; a short operator value is worse than a
#: file one because it is guessable, and the hashes it produces are then a
#: dictionary attack away from the client IPs they exist to hide.
SALT_ENV_MIN_CHARS = 16

# ── key hashing ──────────────────────────────────────────────────────

#: Where the salt came from. Each is a distinct fact about whether the NEXT
#: process will hash with the same bytes — which is the only thing that decides
#: whether a snapshot restores anything.
SOURCE_ENV = "env"  #: ORRERY_RATE_LIMIT_SALT. Same on every boot until the operator changes it.
SOURCE_FILE = "file"  #: Read from a file a previous boot wrote — observed to survive at least one boot.
SOURCE_FILE_NEW = "file-new"  #: Minted this boot and written. Not yet shown to survive one; on a volume-less service this is EVERY boot.
SOURCE_EPHEMERAL = "ephemeral"  #: Minted this boot and could not be written. Dies with the process.
SOURCE_ENV_REJECTED = "env-rejected"  #: ORRERY_RATE_LIMIT_SALT set but unusable; an ephemeral salt is in use instead.
SOURCE_UNRESOLVED = "unresolved"  #: Boot has not resolved a salt yet — the import-time placeholder.

#: The sources under which the salt is the same bytes the previous process
#: hashed with. Everything else was minted by THIS process, so nothing in the
#: snapshot table can have been written under it.
DURABLE_SALT_SOURCES = frozenset({SOURCE_ENV, SOURCE_FILE})


def salt_durable(source: str) -> bool:
    """Whether a snapshot written by the previous process can match under this salt.

    Answered from the SOURCE rather than assumed: a salt this process minted —
    a new file, an unwritable file, a rejected operator value — cannot be what
    any stored hash was computed with. That is the check the original health
    flag lacked: it reported the table writable and said nothing about this.
    """
    return source in DURABLE_SALT_SOURCES


def resolve_salt(org_dir: Path) -> tuple[bytes, str]:
    """The HMAC salt and the NAME of where it came from.

    Precedence: ``ORRERY_RATE_LIMIT_SALT`` if set, else the org data directory
    file, created on first use. The environment wins because setting it is an
    explicit operator decision, and because it is the only source that survives
    a boot on a service with no persistent filesystem — the deployed shape this
    exists for. An install whose data directory persists needs nothing set: the
    file is read back on the second boot and reported as such.

    Kept out of the database on purpose, whichever source: the point of hashing
    the keys is that someone holding a dump of ``rate_limit_buckets`` cannot
    recover the client IPs, and a salt stored beside the hashes would defeat
    that.

    Every failure path returns a USABLE salt with a source that says what
    happened. An operator value too short to be a salt is reported as rejected
    rather than silently replaced by the file: the operator chose the
    environment, and the health field should show that choice failing, not a
    fallback quietly succeeding. A file that cannot be read or written is
    ``ephemeral``. None of these stop the limiter — worst case, no carry-over,
    which was the behaviour before persistence existed.
    """
    raw = os.environ.get(SALT_ENV, "").strip()
    if raw:
        if len(raw) >= SALT_ENV_MIN_CHARS:
            return raw.encode("utf-8"), SOURCE_ENV
        print(
            f"[rate-limit] {SALT_ENV} is {len(raw)} character(s); at least {SALT_ENV_MIN_CHARS} are required "
            "— ignoring it, buckets will not be restored after a restart"
        )
        return secrets.token_bytes(_SALT_BYTES), SOURCE_ENV_REJECTED

    path = Path(org_dir) / _SALT_FILENAME
    try:
        existing = path.read_bytes()
        if len(existing) >= 16:
            return existing, SOURCE_FILE
    except OSError:
        pass
    salt = secrets.token_bytes(_SALT_BYTES)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(salt)
        os.chmod(path, 0o600)
    except OSError:
        # Cannot persist it — the salt is still usable for this process; the
        # snapshot simply will not be readable by the next one.
        return salt, SOURCE_EPHEMERAL
    return salt, SOURCE_FILE_NEW


def bucket_key(salt: bytes, key: str) -> str:
    """Stable, salted, one-way bucket id for a client key. Equality is all the limiter needs.

    THE ONLY PLACE a client key becomes a bucket id. Applied once at the
    middleware edge, so the store, the snapshot and the restore all deal in
    final keys. Hashing at persist time instead would leave the live store
    holding raw IPs, and every future reader of that store would then be a fresh
    decision about whether to hash.
    """
    return hmac.new(salt, key.encode("utf-8"), hashlib.sha256).hexdigest()


# ── snapshot / restore ───────────────────────────────────────────────


def snapshot_buckets(
    store: OrderedDict[str, list[float]],
    *,
    now_monotonic: float,
    now_wall: float,
    window: float,
    max_keys: int = PERSIST_MAX_KEYS,
) -> dict[str, list[float]]:
    """Convert the live store into wall-clock form for persistence.

    The store's keys are ALREADY the salted hashes — ``bucket_key`` is applied
    once, at the middleware edge, so there is exactly one place where a client
    key becomes a bucket id and nothing downstream can forget to hash. This
    function therefore copies keys through untouched.

    Only live timestamps are written: an entry already outside the window would
    be discarded on restore anyway, and writing it inflates the row for nothing.
    Empty buckets are dropped entirely.
    """
    cutoff = now_monotonic - window
    live: list[tuple[int, str, list[float]]] = []
    for key, stamps in store.items():
        fresh = [t for t in stamps if t > cutoff]
        if not fresh:
            continue
        # monotonic -> wall clock, by age. Both clocks are read once by the
        # caller so every entry converts against the same instant.
        wall = [round(now_wall - (now_monotonic - t), 3) for t in fresh]
        live.append((len(wall), key, wall))

    # Fullest first — see PERSIST_MAX_KEYS.
    live.sort(key=lambda item: item[0], reverse=True)
    return {key: wall for _count, key, wall in live[:max_keys]}


def restore_buckets(
    persisted: dict[str, Any],
    *,
    now_monotonic: float,
    now_wall: float,
    window: float,
    key_cap: int,
) -> OrderedDict[str, list[float]]:
    """Rebuild a live store from a snapshot, in THIS process's monotonic frame.

    Entries older than the window are dropped, so a snapshot that sat in the
    database over a long outage restores nothing rather than everything.

    Keys come back exactly as stored — the salted hashes the live limiter looks
    up, because ``bucket_key`` hashed them on the way in. Nothing here can
    recover an IP, and nothing needs to.

    A malformed row restores as far as it can rather than raising: this runs at
    boot, and refusing to start because a cache row is odd would trade a lost
    optimisation for an outage.
    """
    out: OrderedDict[str, list[float]] = OrderedDict()
    if not isinstance(persisted, dict):
        return out
    scored: list[tuple[float, str, list[float]]] = []
    for key, stamps in persisted.items():
        if not isinstance(key, str) or not isinstance(stamps, list):
            continue
        live: list[float] = []
        for raw in stamps:
            if not isinstance(raw, (int, float)) or isinstance(raw, bool):
                continue
            age = now_wall - float(raw)
            # A negative age means the snapshot claims a timestamp in this
            # process's future — a clock that moved backwards, or a doctored
            # row. Treat it as "now" rather than trusting it forward: it can
            # only shorten the attacker's remaining budget, never extend it.
            if age < 0:
                age = 0.0
            if age >= window:
                continue
            live.append(now_monotonic - age)
        if live:
            live.sort()
            scored.append((live[-1], key, live))

    # Newest-active last, so the OrderedDict's front is the coldest bucket —
    # the eviction order check_rate_limit relies on.
    scored.sort(key=lambda item: item[0])
    for _newest, key, live in scored[-key_cap:]:
        out[key] = live
    return out


# ── database ─────────────────────────────────────────────────────────


def ddl() -> str:
    """The table DDL, read from the migration that ships to operators.

    Read rather than restated so a fresh install, an operator applying the
    migration, and this boot ensure cannot be three different statements.
    """
    path = Path(__file__).resolve().parents[1] / "infra" / "migrations" / "0008_rate_limit_persistence.sql"
    return path.read_text(encoding="utf-8")


async def ensure_schema(
    execute_ddl: Callable[[str], Any],
    *,
    has_database: bool,
    table_usable: Callable[[], Any] | None = None,
) -> bool:
    """Make the table available. Returns whether persistence is available.

    ORDER MATTERS, AND IT IS THE FIX FOR THE DEFAULT INSTALL. The table is
    created by ``infra/init.sql`` as the superuser on every fresh install, and
    0006 grants the application role DML on it. The first version of this
    function nevertheless ran ``CREATE TABLE IF NOT EXISTS`` unconditionally,
    and Postgres refuses that for want of CREATE on the schema **even when the
    table exists** — measured: ``permission denied for schema public`` against
    a table the same role could INSERT into a moment later. So every default
    install reported persistence unavailable over a statement that had nothing
    to do. ``table_usable`` is consulted FIRST; the DDL is attempted only when
    the table is absent, which on a default install is never.

    Failure policy follows 0005's, and for the same reason: this table is
    OPTIONAL. Without it the limiter still limits — it forgets across restarts,
    which is exactly the behaviour that exists today. Orrery is self-hosted by
    strangers, and running the app under a least-privilege role with no DDL
    rights is normal. Turning someone's working install into a non-booting one
    to add a durability optimisation is strictly worse than the optimisation
    being absent, so every failure here degrades instead of raising.
    """
    if not has_database:
        return False
    if table_usable is not None and await table_usable():
        return True
    try:
        await execute_ddl(ddl())
        return True
    except Exception as exc:  # noqa: BLE001 — see the docstring: degrade, never raise
        print(
            f"[rate-limit] persistence unavailable ({type(exc).__name__}: {exc}) — limiter is in-memory only. "
            f"The application role cannot create {TABLE}; apply "
            "infra/migrations/0008_rate_limit_persistence.sql as the superuser."
        )
        return False


async def save(pg_request: Callable[..., Any], scope: str, buckets: dict[str, list[float]]) -> bool:
    """Upsert the snapshot. Best-effort: a failure is logged by the caller, never raised."""
    rows = await pg_request(
        "POST",
        TABLE,
        body={
            "scope": scope,
            "buckets": json.dumps(buckets),
            "saved_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        },
        on_conflict=["scope"],
    )
    return rows is not None


async def load(pg_request: Callable[..., Any], scope: str) -> dict[str, Any]:
    """Read the snapshot back. Returns {} for absent, unreadable, or malformed."""
    rows = await pg_request("GET", TABLE, params={"scope": f"eq.{scope}", "select": "buckets", "limit": "1"})
    if not rows:
        return {}
    raw = (rows[0] or {}).get("buckets") if isinstance(rows, list) else None
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except (ValueError, TypeError):
            return {}
    return raw if isinstance(raw, dict) else {}
