"""Direct-Postgres data layer — the agent-native replacement for the PostgREST transport.

``pg_request(method, table, params, body)`` reproduces the SUBSET of the PostgREST
query dialect the server actually uses (surveyed across all 45 callers): the
operators ``eq/neq/in/gt/gte/lt/lte/is/not``, a plain ``select`` column list (or
``*``), ``order``, ``limit``, and POST upsert. There are NO embedded joins and NO
``offset`` in the codebase, so this layer deliberately does not implement them.

``on_conflict`` IS now implemented, and this comment used to say it was not.
PostgREST inferred an upsert's conflict target from whichever unique constraint
the payload actually collided with; this layer originally hardcoded the PRIMARY
key, which is not the same thing and is silently wrong for the common shape of a
surrogate ``id uuid DEFAULT gen_random_uuid()`` primary key alongside a natural
unique. Such a row never carries ``id``, so it gets a fresh uuid, never trips
``ON CONFLICT (id)``, and dies on the natural key's unique violation instead —
the write is DROPPED. Nine POSTed tables have that shape; ``agents`` is the one
repaired so far (see ``_persist_member_to_db``).

The parameter is EXPLICIT rather than inferred on purpose. Restoring PostgREST's
inference globally would silently turn "duplicate refused" into "existing row
overwritten" for every table with a natural unique, and some of those rows must
not be overwritable: ``arp_receipts`` is unique on ``(receipt_id, issuer_did)``
and a receipt that can be silently replaced after issuance is not a receipt,
while ``trust_events`` deltas are server-set and immutable per protocol major.
Naming the key at each call site keeps overwriting a decision someone made
rather than one they inherited.

Same signature + return shape as the old ``pg_request`` (``list[dict] |
dict | None``) so the 45 callers are unchanged — only the transport moves from
HTTP→PostgREST to asyncpg→Postgres, and PostgREST + the anon/service-role/JWT
machinery can be dropped.

Type fidelity: PostgREST builds a TEXT SQL query and lets Postgres coerce string
literals to the column type (``trust_score = '50'`` → int). asyncpg's binary
params would instead infer ``$1`` as int and reject the string, so we match
PostgREST by building text SQL with rigorously-escaped literals. ``_lit`` is the
ONLY place a value enters SQL; it is the security boundary and is unit-tested
against injection. standard_conforming_strings is on by default in PG15, so
single-quote doubling is the complete escape (no backslash handling needed).
"""

from __future__ import annotations

import datetime
import decimal
import json
import os
import sys
import time
import uuid
from typing import Any


class DatabaseError(RuntimeError):
    """A configured database operation FAILED — distinct from 'no database
    configured' (which is a quiet None, expected in unit tests). Callers that must
    not silently under-persist raise/propagate this instead of treating a failure
    as an empty result."""


def _db_log(event: str, **fields: Any) -> None:
    """Structured (JSON) error log for a DB failure — replaces bare prints so a
    failure is greppable/alertable, never a silent return-None."""
    print(json.dumps({"level": "error", "event": event, **fields}, default=str), file=sys.stderr, flush=True)


def _record_db_failure(operation: str) -> None:
    """Bump the DB-failure metric (best-effort; metrics import is lazy to avoid any
    import cycle and never let telemetry break the data path)."""
    try:
        import metrics

        metrics.record_db_failure(operation)
    except Exception:  # noqa: BLE001 — telemetry must never break the caller
        pass

# ── Literal rendering — the single SQL-injection boundary ─────────────────────


def _lit(v: Any) -> str:
    """Render a Python value as a safe SQL literal Postgres will coerce."""
    if v is None:
        return "NULL"
    if isinstance(v, bool):
        return "TRUE" if v else "FALSE"
    if isinstance(v, (int, float)):
        return repr(v)
    if isinstance(v, (dict, list)):
        return "'" + json.dumps(v).replace("'", "''") + "'::jsonb"
    return "'" + str(v).replace("'", "''") + "'"


def _base_type(coltype: str | None) -> str:
    """Bare type name — strip a schema prefix (``extensions.vector``) and any
    modifier (``vector(1536)``, ``numeric(10,2)``) — for type-family dispatch."""
    if not coltype:
        return ""
    return coltype.split("(", 1)[0].rsplit(".", 1)[-1]


def _lit_for(v: Any, coltype: str | None) -> str:
    """Render a body value for a column of KNOWN Postgres type, so a Python list
    lands as ``text[]`` vs ``jsonb`` vs ``vector`` correctly (PostgREST knows
    column types; we introspect them — see ``_col_types``). Falls back to
    ``_lit`` when unknown."""
    if v is None:
        return "NULL"
    if coltype and coltype.endswith("[]"):
        items = v if isinstance(v, (list, tuple)) else [v]
        return f"ARRAY[{', '.join(_lit(x) for x in items)}]::{coltype}"
    if _base_type(coltype) == "vector" and isinstance(v, (list, tuple)):
        # pgvector: an embedding is a float list and MUST cast to the column's
        # own vector type — rendering it as jsonb (the _lit default for a list)
        # makes Postgres reject "type vector but expression is of type jsonb".
        # Cast to the exact coltype so a schema-qualified/dimensioned type
        # (extensions.vector, vector(1536)) matches without a search_path assumption.
        inner = ",".join(repr(float(x)) for x in v)
        return f"'[{inner}]'::{coltype}"
    if coltype in ("jsonb", "json") and isinstance(v, (dict, list)):
        return "'" + json.dumps(v).replace("'", "''") + f"'::{coltype}"
    return _lit(v)


def _ident(name: str) -> str:
    """Quote an identifier (table/column). Reject anything not a plain
    identifier — every name in this codebase is a literal string, never
    user-controlled, so an unexpected shape is a bug, not input to sanitize."""
    if not name.replace("_", "").isalnum():
        raise ValueError(f"unsafe SQL identifier: {name!r}")
    return f'"{name}"'


# ── PostgREST filter dialect → SQL ────────────────────────────────────────────

_OPS = {"eq": "=", "neq": "<>", "gt": ">", "gte": ">=", "lt": "<", "lte": "<="}


def _filter(col: str, raw: str) -> str:
    """Translate one ``col=<op>.<value>`` PostgREST filter to a SQL predicate."""
    c = _ident(col)
    op, _, val = raw.partition(".")
    if op == "not":
        # not.<op>.<value> — only forms in use are not.is.null and negated ops.
        return f"NOT ({_filter(col, val)})"
    if op == "is":
        low = val.lower()
        if low == "null":
            return f"{c} IS NULL"
        if low in ("true", "false"):
            return f"{c} IS {low.upper()}"
        return f"{c} IS {_lit(val)}"
    if op == "in":
        inner = val[1:-1] if val.startswith("(") and val.endswith(")") else val
        items = [s for s in inner.split(",") if s != ""]
        rendered = ", ".join(_lit(s) for s in items) or "NULL"
        return f"{c} IN ({rendered})"
    if op in _OPS:
        return f"{c} {_OPS[op]} {_lit(val)}"
    raise ValueError(f"unsupported PostgREST operator {op!r} in {raw!r}")


def _split_top_commas(s: str) -> list[str]:
    """Split on commas NOT nested inside parentheses — so a compound predicate
    list ``a.lt.1,b.in.(x,y)`` splits into its two members, not four."""
    out, depth, start = [], 0, 0
    for i, ch in enumerate(s):
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif ch == "," and depth == 0:
            out.append(s[start:i])
            start = i + 1
    out.append(s[start:])
    return [p for p in out if p != ""]


def _compound(kind: str, raw: str) -> str:
    """Translate a PostgREST ``and=(...)`` / ``or=(...)`` group into a
    parenthesised SQL predicate. Each member is ``col.op.value`` (the value may
    itself contain dots, e.g. an ISO timestamp)."""
    inner = raw[1:-1] if raw.startswith("(") and raw.endswith(")") else raw
    preds = []
    for part in _split_top_commas(inner):
        col, _, rest = part.partition(".")
        preds.append(_filter(col, rest))
    joiner = " OR " if kind == "or" else " AND "
    return "(" + joiner.join(preds) + ")"


_RESERVED = {"select", "order", "limit", "offset"}
_COMPOUND = {"and", "or"}


def _where(params: dict | None) -> str:
    if not params:
        return ""
    preds = []
    for k, v in params.items():
        if k in _RESERVED:
            continue
        if k in _COMPOUND:
            preds.append(_compound(k, str(v)))
        else:
            preds.append(_filter(k, str(v)))
    return (" WHERE " + " AND ".join(preds)) if preds else ""


def _order(params: dict | None) -> str:
    spec = (params or {}).get("order")
    if not spec:
        return ""
    cols = []
    for part in str(spec).split(","):
        name, _, direction = part.partition(".")
        d = "DESC" if direction.lower().startswith("desc") else "ASC"
        cols.append(f"{_ident(name)} {d}")
    return (" ORDER BY " + ", ".join(cols)) if cols else ""


def _limit(params: dict | None) -> str:
    lim = (params or {}).get("limit")
    return f" LIMIT {int(lim)}" if lim is not None else ""


def _select_cols(params: dict | None) -> str:
    sel = (params or {}).get("select")
    if not sel or sel == "*":
        return "*"
    return ", ".join(_ident(c.strip()) for c in str(sel).split(",") if c.strip())


# ── Statement builders (pure; unit-tested without a DB) ───────────────────────


def build_rpc(fn: str, body: dict | None) -> str:
    """Call a Postgres function the way PostgREST's ``POST /rpc/<fn>`` did — the
    body maps the function's named args to values. ``SELECT * FROM fn(...)``
    covers both scalar functions (one row, one column named after the fn — what
    ``invites.consume`` reads) and set-returning ones (the result rows). Named-arg
    notation (``arg => value``) keeps callers order-independent."""
    args = body or {}
    for k in args:
        if not str(k).replace("_", "").isalnum():
            raise ValueError(f"unsafe SQL argument name: {k!r}")
    argstr = ", ".join(f"{k} => {_lit(v)}" for k, v in args.items())
    return f"SELECT * FROM {_ident(fn)}({argstr})"


def build_select(table: str, params: dict | None) -> str:
    return (
        f"SELECT {_select_cols(params)} FROM {_ident(table)}"
        f"{_where(params)}{_order(params)}{_limit(params)}"
    )


def build_upsert(
    table: str,
    row: dict,
    pk_cols: list[str],
    col_types: dict[str, str] | None = None,
    merge_jsonb: list[str] | None = None,
) -> str:
    """INSERT ... ON CONFLICT for ``row``.

    ``merge_jsonb`` names jsonb columns that must be MERGED into the stored
    value on conflict (``col = <table>.col || EXCLUDED.col``) rather than
    replaced. Keys the writer supplies win; keys it does not supply survive.

    This exists because a writer that rebuilds a shared jsonb column from its
    own fields silently deletes everything another writer put there. On
    ``agents.config`` that destroyed a member's Listing consent and their host39
    publication record on every re-registration — measured, and invisible until
    the upsert itself was repaired, because until then the write never landed at
    all. Doing it in the conflict clause keeps it a single atomic statement: the
    obvious alternative (SELECT the config, merge in Python, write it back) is a
    read-modify-write race between concurrent registrations.
    """
    ct = col_types or {}
    merge = set(merge_jsonb or ())
    cols = list(row.keys())
    collist = ", ".join(_ident(c) for c in cols)
    vals = ", ".join(_lit_for(row[c], ct.get(c)) for c in cols)
    stmt = f"INSERT INTO {_ident(table)} ({collist}) VALUES ({vals})"
    if pk_cols:
        conflict = ", ".join(_ident(c) for c in pk_cols)
        updatable = [c for c in cols if c not in pk_cols]
        if updatable:
            setlist = ", ".join(
                (
                    f"{_ident(c)} = {_ident(table)}.{_ident(c)} || EXCLUDED.{_ident(c)}"
                    if c in merge
                    else f"{_ident(c)} = EXCLUDED.{_ident(c)}"
                )
                for c in updatable
            )
            stmt += f" ON CONFLICT ({conflict}) DO UPDATE SET {setlist}"
        else:
            stmt += f" ON CONFLICT ({conflict}) DO NOTHING"
    return stmt + " RETURNING *"


def build_update(
    table: str, params: dict | None, body: dict, col_types: dict[str, str] | None = None
) -> str:
    ct = col_types or {}
    setlist = ", ".join(f"{_ident(c)} = {_lit_for(v, ct.get(c))}" for c, v in body.items())
    return f"UPDATE {_ident(table)} SET {setlist}{_where(params)} RETURNING *"


def build_delete(table: str, params: dict | None) -> str:
    return f"DELETE FROM {_ident(table)}{_where(params)} RETURNING *"


# ── Execution (asyncpg; exercised by the docker e2e, not the mocked unit tests) ─

_pool: Any = None
_pk_cache: dict[str, list[str]] = {}
_coltype_cache: dict[str, dict[str, str]] = {}


def database_url() -> str:
    return os.environ.get("DATABASE_URL", "").strip()


# a failed pool creation must NOT latch permanently — a transient blip
# (DB restart, network hiccup) would then brick the worker until a process restart.
# Instead we back off for a COOLDOWN and retry, so the worker self-heals once the DB
# returns. `_pool_unavailable_until` is a monotonic deadline; while now < it, we
# fail fast (return None) without hammering a down DB.
_pool_unavailable_until: float = 0.0
_POOL_RETRY_COOLDOWN_S = 5.0

# ── TLS to Postgres (AUDIT_HARSH C3) ────────────────────────────────────────
#
# `create_pool()` used to pass the raw DSN and NO `ssl` argument. For a
# `postgres://` URL with no `sslmode`, asyncpg then negotiates **no TLS at all**,
# so everything on that link — signing keys, API keys, tokens, receipts, member
# PII — crosses the wire in plaintext. Measured against `pgvector/pgvector:pg15`:
#
#     no ssl argument   -> connects, plaintext, silently
#     ssl="disable"     -> connects, plaintext, explicitly
#     ssl="prefer"      -> connects, but falls back to plaintext with no signal
#     ssl="require"     -> ConnectionError: "rejected SSL upgrade"
#
# So `prefer` is not a security control (it downgrades silently), and a bare
# `require` breaks every local run and CI — the compose image reports `ssl=off`
# and ships no certificate. The shape that is both safe and survivable is:
# **require by default, and exempt the local/dev path explicitly and visibly**.
_DB_SSL_ENV = "ORRERY_DB_SSL"

#: Hosts that are, by construction, a loopback or a compose-network sidecar —
#: never a network an attacker is on. `db` is this repo's compose service name.
_LOCAL_DB_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "db", "postgres", "pgvector"})

_ssl_decision_logged = False


def _resolve_db_ssl(url: str) -> str | None:
    """The asyncpg ``ssl`` argument for ``url``, or None to leave it to asyncpg.

    Precedence, most explicit first:
      1. ``ORRERY_DB_SSL`` — an operator override, used verbatim. This is the
         escape hatch for a deployment whose Postgres genuinely cannot do TLS.
      2. an ``sslmode`` already in the DSN — the operator has said what they
         want in the URL, so return None and let asyncpg honour it rather than
         overriding it from here.
      3. host-based default — loopback/compose ⇒ ``disable``, anything else
         (i.e. a real network hop) ⇒ ``require``.
    """
    explicit = os.environ.get(_DB_SSL_ENV, "").strip().lower()
    if explicit:
        return explicit
    if "sslmode=" in (url or "").lower():
        return None  # the DSN already decides; don't override it
    from urllib.parse import urlparse

    try:
        host = (urlparse(url).hostname or "").lower()
    except Exception:  # noqa: BLE001 - a malformed DSN fails later, with a better message
        host = ""
    return "disable" if host in _LOCAL_DB_HOSTS else "require"


#: Result of the boot-time TLS capability probe: True/False once probed, None
#: until then (or when the probe itself could not run). Surfaced on /health as
#: ``db.tls_available`` so the answer is visible without a shell.
_db_tls_available: bool | None = None
_tls_probe_done = False


def db_tls_available() -> bool | None:
    """Whether this Postgres accepted a TLS connection at boot. None = unprobed."""
    return _db_tls_available


async def _probe_tls_capability(url: str) -> None:
    """Open ONE ssl='require' connection, record the outcome, close it.

    Never raises and never influences the real pool. A failure here is a fact
    about the database, not a fault in this process.
    """
    global _db_tls_available, _tls_probe_done
    if _tls_probe_done:
        return
    _tls_probe_done = True
    try:
        # Imported inside the try: a suite that blocks asyncpg entirely must see
        # the probe decline, not raise.
        import asyncpg

        conn = await asyncpg.connect(url, ssl="require", timeout=5)
        await conn.close()
        _db_tls_available = True
    except Exception as exc:  # noqa: BLE001 — the probe's whole job is to not care
        _db_tls_available = False
        _db_log("db.tls_probe", available=False, detail=f"{type(exc).__name__}: {exc}"[:200])
        return
    _db_log("db.tls_probe", available=True)


async def _get_pool():
    """The asyncpg pool, or None if the database is currently unreachable.

    On a create failure we back off for ``_POOL_RETRY_COOLDOWN_S`` and retry on the
    next call after the cooldown — never a permanent latch. A bad/absent
    DATABASE_URL (e.g. unit tests) still fails fast so nothing hangs."""
    global _pool, _pool_unavailable_until
    if _pool is not None:
        return _pool
    if time.monotonic() < _pool_unavailable_until:
        return None  # in cooldown after a recent failure — don't hammer a down DB
    import asyncpg

    global _ssl_decision_logged
    url = database_url()
    ssl_mode = _resolve_db_ssl(url)
    # Say which way it went, once per process. An exemption nobody can see is
    # indistinguishable from the bug this replaces (C3).
    if not _ssl_decision_logged:
        _ssl_decision_logged = True
        _db_log(
            "db.tls_mode",
            ssl=ssl_mode if ssl_mode is not None else "from-dsn",
            source=(
                _DB_SSL_ENV
                if os.environ.get(_DB_SSL_ENV, "").strip()
                else ("dsn" if ssl_mode is None else "host-default")
            ),
        )

    # ── TLS capability probe (C3 residual) ───────────────────────────────────
    # Whether this Postgres accepts TLS on THIS hop cannot be determined from
    # outside Railway's private network — the host resolves only in-cluster. But
    # the server itself runs inside it, so it can just ask, once, at boot.
    #
    # ⚠️ REPORTS, NEVER REQUIRES — and it runs only AFTER the real pool exists
    # (below), so a deployment with no reachable database adds no network touch
    # here. test_no_real_db_connections pins that: _get_pool must return None
    # without reaching the network, and a diagnostic is not a licence to break it.
    kwargs: dict[str, Any] = {"min_size": 1, "max_size": 8, "timeout": 5, "command_timeout": 15}
    if ssl_mode is not None:
        kwargs["ssl"] = ssl_mode

    try:
        _pool = await asyncpg.create_pool(url, **kwargs)
        # The pool is up, so the database is reachable and asking whether it would
        # ALSO have accepted TLS is now a cheap, meaningful question.
        await _probe_tls_capability(url)
        _pool_unavailable_until = 0.0  # recovered — clear the backoff
        return _pool
    except Exception as e:  # noqa: BLE001 — logged + metric'd, retried after cooldown
        _pool_unavailable_until = time.monotonic() + _POOL_RETRY_COOLDOWN_S
        _record_db_failure("pool_create")
        detail = str(e)
        # A server that refuses the TLS upgrade produces an error that reads like
        # a generic connection failure. Name the knob in the log so this costs an
        # operator seconds instead of an outage — the one deployment shape this
        # change can regress is a Postgres that cannot do TLS at all.
        if "rejected ssl upgrade" in detail.lower() or "server does not support ssl" in detail.lower():
            _db_log(
                "db.tls_required_but_unsupported",
                error=detail[:200],
                remedy=f"this Postgres refuses TLS; set {_DB_SSL_ENV}=disable if that is expected",
            )
        # Authentication refused. Postgres answers 28P01 for a wrong password AND
        # for a role that does not exist — it does not distinguish them on the
        # wire, deliberately, so that a stranger cannot enumerate roles. The
        # remedy therefore names both causes rather than guessing one: the most
        # likely reason on an upgraded install is that the application role has
        # not been created yet, and the migration that creates it is not applied
        # by any runner.
        if getattr(e, "sqlstate", None) == "28P01":
            _db_log(
                "db.auth_failed",
                error=detail[:200],
                remedy=(
                    "Postgres refused authentication for the DATABASE_URL user. It reports the "
                    "same error for a role that does not exist and for a wrong password, so "
                    "check both: apply infra/migrations/0006_app_role.sql as a superuser if the "
                    "role has never been created, or confirm the password. To fall back, point "
                    "DATABASE_URL at the superuser and restart."
                ),
            )
        _db_log("db.pool_create_failed", error=detail[:200], retry_after_s=_POOL_RETRY_COOLDOWN_S)
        return None


async def _pk_for(table: str) -> list[str]:
    """Primary-key columns for ``table`` (cached) — the ON CONFLICT target."""
    if table not in _pk_cache:
        pool = await _get_pool()
        rows = await pool.fetch(
            "SELECT a.attname FROM pg_index i "
            "JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY(i.indkey) "
            "WHERE i.indrelid = $1::regclass AND i.indisprimary ORDER BY a.attnum",
            table,
        )
        _pk_cache[table] = [r["attname"] for r in rows]
    return _pk_cache[table]


async def _col_types(table: str) -> dict[str, str]:
    """``{column: canonical_pg_type}`` for ``table`` (cached) — so list/dict values
    render as the column's real type (text[] vs jsonb) instead of always jsonb."""
    if table not in _coltype_cache:
        pool = await _get_pool()
        rows = await pool.fetch(
            "SELECT a.attname, format_type(a.atttypid, a.atttypmod) AS t "
            "FROM pg_attribute a WHERE a.attrelid = $1::regclass "
            "AND a.attnum > 0 AND NOT a.attisdropped",
            table,
        )
        _coltype_cache[table] = {r["attname"]: r["t"] for r in rows}
    return _coltype_cache[table]


def _coerce(v: Any) -> Any:
    """Map an asyncpg-native value to the JSON shape PostgREST returned, so
    pg_store stays a true drop-in. asyncpg gives Python ``datetime``/``UUID``/
    ``Decimal`` objects where PostgREST returned ISO strings / strings / numbers —
    code that compared a timestamp column to an ISO string (e.g. the digest window
    filter) or JSON-serialized a UUID broke against the direct-Postgres backend."""
    if isinstance(v, (datetime.datetime, datetime.date, datetime.time)):
        return v.isoformat()
    if isinstance(v, uuid.UUID):
        return str(v)
    if isinstance(v, decimal.Decimal):
        return float(v)
    return v


def _rows(records) -> list[dict]:
    out = []
    for r in records:
        d = dict(r)
        for k, v in d.items():
            if isinstance(v, str):
                if v and v[0] in "{[":
                    try:
                        d[k] = json.loads(v)  # jsonb columns come back as text
                    except (ValueError, TypeError):
                        pass
            else:
                coerced = _coerce(v)
                if coerced is not v:
                    d[k] = coerced
        out.append(d)
    return out


async def db_reachable() -> bool:
    """True if a Postgres connection pool can be obtained. Distinguishes
    'database configured but unreachable' (the whole server already degrades
    under this) from 'reachable but an operation failed'. Used by the boot
    schema-ensure so an unreachable DB defers the ensure rather than crashing
    startup, while a reachable-but-failing DDL still raises."""
    return bool(database_url()) and (await _get_pool()) is not None


async def db_ping() -> bool:
    """Actively prove a Postgres round-trip (``SELECT 1``) — a LIVE readiness
    probe, distinct from ``db_reachable()`` which only checks that a pool can be
    obtained. Exercises the real query loop, so it catches a pool that is up but
    whose backend is failing. False when ``DATABASE_URL`` is set but the round-trip
    cannot complete; never raises (a readiness endpoint reports, it does not crash)."""
    if not database_url():
        return False
    try:
        pool = await _get_pool()
        if pool is None:
            return False
        return (await pool.fetchval("SELECT 1")) == 1
    except Exception:  # noqa: BLE001 — an unreachable/failing DB is "not ready", not an error
        return False


async def execute_ddl(sql: str) -> None:
    """Run a raw DDL script against Postgres (schema ensure at boot).

    Distinct from ``pg_request``, which swallows errors and returns None — a
    schema ensure that fails must RAISE so a boot-time misconfiguration (no
    CREATE privilege, unreachable DB) is loud, never a silently-missing table.
    Requires ``DATABASE_URL``; raises ``RuntimeError`` if the pool is
    unavailable (callers only invoke this when a database is configured).
    """
    if not database_url():
        raise RuntimeError("execute_ddl called without DATABASE_URL")
    pool = await _get_pool()
    if pool is None:
        raise RuntimeError("execute_ddl: database pool unavailable")
    async with pool.acquire() as conn:
        await conn.execute(sql)


async def pg_request(
    method: str,
    table: str,
    params: dict | None = None,
    body: dict | list | None = None,
    on_conflict: list[str] | None = None,
    merge_jsonb: list[str] | None = None,
) -> dict | list | None:
    """Drop-in replacement for ``pg_request`` over direct Postgres.

    ``on_conflict`` names the columns a POST should treat as the upsert key,
    overriding the table's PRIMARY KEY. Pass it when the row body identifies an
    existing record by a NATURAL key rather than by the surrogate primary key.

    Why this is explicit rather than inferred. Under PostgREST the conflict
    target was inferred from whichever unique constraint the payload actually
    collided with; the port to direct Postgres hardcoded the primary key, so a
    row that omits a surrogate ``id`` and re-supplies an existing natural key
    gets a fresh ``gen_random_uuid()``, never trips ``ON CONFLICT (id)``, and
    raises a unique violation instead — the write is DROPPED.

    Restoring the inference globally would have been the smaller diff and the
    wrong change: it silently converts "duplicate refused" into "existing row
    overwritten" for every table with a natural unique, and some of those rows
    are meant to be immutable. ``arp_receipts`` is unique on
    ``(receipt_id, issuer_did)`` — today a repeat POST is refused, and under
    blanket inference it would quietly overwrite a receipt that has already been
    issued and possibly co-signed. Making each call site name its key means
    overwriting is always a decision someone made, never a default they
    inherited.

    ``merge_jsonb`` names jsonb columns to MERGE rather than replace on
    conflict — see :func:`build_upsert`. Required whenever a writer rebuilds a
    jsonb column that other writers also contribute keys to.
    """
    if not database_url():
        return None
    try:
        pool = await _get_pool()
        if pool is None:
            return None
        m = method.upper()
        if m == "GET":
            return _rows(await pool.fetch(build_select(table, params)))
        if m == "POST" and table.startswith("rpc/"):
            # PostgREST RPC: POST rpc/<fn> → call the Postgres function.
            rpc_body = body if isinstance(body, dict) else {}
            return _rows(await pool.fetch(build_rpc(table[len("rpc/"):], rpc_body)))
        if m == "POST":
            rows = body if isinstance(body, list) else [body or {}]
            # An explicit conflict target replaces the primary key entirely —
            # a row keyed on a natural unique never carries the surrogate PK,
            # so falling back to it is what breaks the upsert.
            pk = list(on_conflict) if on_conflict else await _pk_for(table)
            ct = await _col_types(table)
            out: list[dict] = []
            async with pool.acquire() as conn:
                async with conn.transaction():
                    for row in rows:
                        out.extend(_rows(await conn.fetch(build_upsert(table, row, pk, ct, merge_jsonb))))
            return out
        if m in ("PATCH", "PUT"):
            ct = await _col_types(table)
            return _rows(await pool.fetch(build_update(table, params, body if isinstance(body, dict) else {}, ct)))
        if m == "DELETE":
            return _rows(await pool.fetch(build_delete(table, params)))
        raise ValueError(f"unsupported method {method!r}")
    except Exception as e:  # noqa: BLE001
        # a CONFIGURED-DB operation failed. This is DISTINCT from the
        # not-configured quiet None at the top: emit a structured error log + a
        # metric so the failure is observable/alertable, never a silent bare print.
        # None is still returned for backward compatibility with the ~45 callers;
        # callers that must not under-persist should use pg_execute_strict().
        _record_db_failure(f"{method.upper()}:{table}")
        _db_log("db.operation_failed", method=method.upper(), table=table, error=str(e)[:200])
        return None


async def pg_execute_strict(
    method: str, table: str, params: dict | None = None, body: dict | list | None = None
):
    """like ``pg_request`` but RAISES a typed ``DatabaseError`` on a configured
    failure instead of returning None. For callers where a swallowed failure would
    silently lose data (e.g. member persistence). Still returns None only when NO
    database is configured — there is genuinely nothing to persist to."""
    if not database_url():
        return None
    pool = await _get_pool()
    if pool is None:
        raise DatabaseError(f"{method} {table}: database pool unavailable")
    result = await pg_request(method, table, params, body)
    # pg_request returns None on a configured-DB failure (it logged + metric'd it).
    # A successful write with RETURNING * yields a list; distinguish failure here.
    if result is None:
        raise DatabaseError(f"{method} {table}: operation failed (see db.operation_failed log)")
    return result
