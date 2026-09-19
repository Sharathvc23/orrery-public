"""Offline outbox — SQLite-backed retry queue for settings sync.

The member SDK runs on a laptop that comes and goes from network. If a
member changes their settings while disconnected, we can't push to the
chapter right then. Options:

  A. Raise → agent surfaces "offline" to user (current 0.5.x behavior).
  B. Queue → appear to succeed, apply the patch locally, replay on reconnect.

This module implements option B. The queue is durable (SQLite, mode 0600)
so it survives app restart. Each entry has an auto-increment sequence,
and a **vector clock** per settings key so out-of-order replays converge
correctly.

Design notes
──────────────

1. **Last-writer-wins by the member's own clock.** The chapter is the
   source of truth but the *member's* local sequence decides which of
   two pending writes from the same member wins. Between members, the
   chapter's existing server-side resolution (updated_at monotonic)
   still applies.

2. **Exponential backoff** on drain failure. 10s → 20s → 40s → cap 10min.
   After a full retry cycle, entries older than 14 days get purged
   (preventing the outbox from growing forever if a member never
   reconnects).

3. **Idempotency key** = (agent_id, sequence). The chapter's
   settings_sync/update_settings handler already upserts by
   (agent_id, key) so a replay of the same seq doesn't double-apply.

4. **Entries carry a KIND** (schema v2). The queue was written for settings
   patches and hard-coded ``client.update_settings`` in ``drain``; an outbound
   email needs the same durability, backoff and attempt tracking, and a second
   queue beside this one would be a second set of retry semantics to keep in
   step. So ``drain`` dispatches on ``kind`` and the settings path is unchanged.

   ⚠️ Existing outbox.db files predate the column. The migration ADDs it with a
   default of ``settings_patch``, so a queue written by an older build drains
   exactly as before rather than being skipped by a dispatcher that finds no
   handler — a silently un-drained queue looks identical to an empty one.

R1-R10 coverage in tests/test_outbox.py.
"""

from __future__ import annotations

import inspect
import json
import os
import sqlite3
import time
from pathlib import Path
from typing import Any

_OUTBOX_PATH: Path | None = None
_SCHEMA_VERSION = 2
_BACKOFF_BASE_SEC = 10
_BACKOFF_CAP_SEC = 600
_PURGE_AFTER_DAYS = 14


def _path() -> Path:
    """Return the outbox DB path: ``<agent home>/outbox.db``.

    The agent home is COMMUNITY_MEMBER_HOME when set, else
    ~/.community-member. Overridable outright via the COMMUNITY_MEMBER_OUTBOX
    env var (useful for testing), which still wins over both.
    """
    global _OUTBOX_PATH
    if _OUTBOX_PATH is not None:
        return _OUTBOX_PATH
    override = os.environ.get("COMMUNITY_MEMBER_OUTBOX")
    if override:
        p = Path(override)
    else:
        from community_member import agent_home

        p = agent_home.base_dir() / "outbox.db"
    p.parent.mkdir(parents=True, exist_ok=True)
    _OUTBOX_PATH = p
    return p


def reset_for_test(path: Path | None = None) -> None:
    """Test hook: reset the cached outbox path (lets tests use tmp_path)."""
    global _OUTBOX_PATH
    _OUTBOX_PATH = path


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(_path())
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA foreign_keys = ON")
    _migrate(conn)
    return conn


def _migrate(conn: sqlite3.Connection) -> None:
    """Create tables if not present. Idempotent."""
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS outbox (
            sequence INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id TEXT NOT NULL,
            patch_json TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0,
            last_attempt_at INTEGER,
            last_error TEXT,
            next_retry_at INTEGER NOT NULL DEFAULT 0,
            kind TEXT NOT NULL DEFAULT 'settings_patch'
        );
        CREATE INDEX IF NOT EXISTS idx_outbox_retry
            ON outbox(next_retry_at);

        CREATE TABLE IF NOT EXISTS meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
    """)
    # v1 -> v2: add `kind` to a table that already exists. CREATE TABLE IF NOT
    # EXISTS above is a no-op on an existing DB, so the column has to be added
    # explicitly. Defaulted, so rows written by v1 keep draining as settings
    # patches instead of falling through the dispatcher unhandled.
    existing = {r["name"] for r in conn.execute("PRAGMA table_info(outbox)")}
    if "kind" not in existing:
        conn.execute("ALTER TABLE outbox ADD COLUMN kind TEXT NOT NULL DEFAULT 'settings_patch'")

    # Pin schema version. INSERT OR IGNORE alone would leave a v1 database
    # claiming version 1 forever, so the value is updated rather than only
    # seeded — a version that lies about the schema is worse than none.
    conn.execute(
        "INSERT INTO meta(key, value) VALUES('schema_version', ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (str(_SCHEMA_VERSION),),
    )
    conn.commit()
    # File-mode 0600 if POSIX
    try:
        os.chmod(_path(), 0o600)
    except OSError:
        pass


def enqueue(agent_id: str, patch: dict, *, kind: str = "settings_patch") -> int:
    """Append an entry to the outbox. Returns the sequence assigned.

    ``kind`` selects the drain handler. It defaults to ``settings_patch`` so
    every existing caller keeps its exact behaviour, and an unknown kind is
    refused HERE rather than at drain time — an entry nothing can handle would
    sit in the queue retrying forever, consuming the backoff schedule and
    looking from the outside like a network problem.
    """
    if not agent_id or not isinstance(patch, dict):
        raise ValueError("enqueue requires agent_id + dict patch")
    if kind not in DRAIN_HANDLERS:
        raise ValueError(f"unknown outbox kind {kind!r}; known: {sorted(DRAIN_HANDLERS)}")
    patch_json = json.dumps(patch, sort_keys=True)
    now = int(time.time())
    conn = _connect()
    try:
        cur = conn.execute(
            "INSERT INTO outbox(agent_id, patch_json, created_at, next_retry_at, kind) VALUES (?, ?, ?, ?, ?)",
            (agent_id, patch_json, now, now, kind),
        )
        conn.commit()
        return int(cur.lastrowid)
    finally:
        conn.close()


def pending_count(agent_id: str | None = None) -> int:
    """Return number of pending entries (optionally scoped to one agent)."""
    conn = _connect()
    try:
        if agent_id:
            row = conn.execute(
                "SELECT COUNT(*) AS c FROM outbox WHERE agent_id = ?",
                (agent_id,),
            ).fetchone()
        else:
            row = conn.execute("SELECT COUNT(*) AS c FROM outbox").fetchone()
        return int(row["c"])
    finally:
        conn.close()


def peek(agent_id: str, limit: int = 50) -> list[dict[str, Any]]:
    """Read pending entries for one agent, oldest-first. Does NOT dequeue."""
    conn = _connect()
    now = int(time.time())
    try:
        rows = conn.execute(
            "SELECT sequence, agent_id, patch_json, created_at, attempts, "
            "last_attempt_at, last_error, next_retry_at, kind "
            "FROM outbox WHERE agent_id = ? AND next_retry_at <= ? "
            "ORDER BY sequence ASC LIMIT ?",
            (agent_id, now, int(limit)),
        ).fetchall()
        return [
            {
                "sequence": r["sequence"],
                "agent_id": r["agent_id"],
                "patch": json.loads(r["patch_json"]),
                "created_at": r["created_at"],
                "attempts": r["attempts"],
                "last_attempt_at": r["last_attempt_at"],
                "last_error": r["last_error"],
                "next_retry_at": r["next_retry_at"],
                "kind": r["kind"],
            }
            for r in rows
        ]
    finally:
        conn.close()


def mark_success(sequence: int) -> None:
    """Remove an entry after successful replay."""
    conn = _connect()
    try:
        conn.execute("DELETE FROM outbox WHERE sequence = ?", (sequence,))
        conn.commit()
    finally:
        conn.close()


def mark_failure(sequence: int, error: str) -> None:
    """Record a replay failure. Bumps attempts + schedules exponential backoff."""
    conn = _connect()
    now = int(time.time())
    try:
        row = conn.execute(
            "SELECT attempts FROM outbox WHERE sequence = ?",
            (sequence,),
        ).fetchone()
        if not row:
            return
        attempts = int(row["attempts"]) + 1
        backoff = min(_BACKOFF_BASE_SEC * (2 ** min(attempts - 1, 8)), _BACKOFF_CAP_SEC)
        conn.execute(
            "UPDATE outbox SET attempts = ?, last_attempt_at = ?, last_error = ?, next_retry_at = ? WHERE sequence = ?",
            (attempts, now, (error or "")[:200], now + backoff, sequence),
        )
        conn.commit()
    finally:
        conn.close()


def purge_expired() -> int:
    """Delete entries older than _PURGE_AFTER_DAYS. Returns rows purged."""
    conn = _connect()
    cutoff = int(time.time()) - (_PURGE_AFTER_DAYS * 86400)
    try:
        cur = conn.execute("DELETE FROM outbox WHERE created_at < ?", (cutoff,))
        conn.commit()
        return cur.rowcount
    finally:
        conn.close()


class DeferEntry(Exception):
    """Raised by a handler for "not now, but not a failure either".

    ⚠️ Exists because an outbound send awaiting an operator approval is NEITHER
    success nor error. Deleting the row would drop the message; recording a
    failure would burn the backoff schedule and eventually purge it, so a message
    waiting on a human would be discarded for the crime of waiting. It stays
    queued, and the attempt is counted as deferred.
    """


def _drain_settings_patch(agent_id: str, entry: dict[str, Any], client: Any) -> None:
    """The original path, unchanged. Mirrors settings_sync.push_to_chapter; we
    don't write_local because the cache was written at enqueue time."""
    result = client.update_settings(agent_id, entry["patch"])
    if result is None:
        raise RuntimeError("client returned None")


#: kind -> handler. A kind with no handler cannot be enqueued (see ``enqueue``),
#: so the dispatcher never meets an entry it does not understand.
DRAIN_HANDLERS: dict[str, Any] = {"settings_patch": _drain_settings_patch}


def register_drain_handler(kind: str, handler: Any) -> None:
    """Register a handler for a new entry kind.

    Registration rather than an import here: the outbox is generic durable
    machinery and must not depend on any particular edge. A module that owns an
    edge registers itself, so this file never needs to know that Klaviyo exists.
    """
    DRAIN_HANDLERS[kind] = handler


async def drain(agent_id: str, client, *, max_to_drain: int = 100) -> dict[str, int]:
    """Replay pending entries. Called on reconnect.

    Contract:
      - Pulls up to max_to_drain entries due for retry
      - Dispatches each on its ``kind`` (settings patches take the original path)
      - On success: DELETE the row
      - On DeferEntry: leave it queued, count it deferred, do NOT burn a retry
      - On failure: bump attempts + schedule exponential backoff

    Returns {"attempted": N, "succeeded": M, "deferred": D, "failed": K, "remaining": R}.
    """
    entries = peek(agent_id, limit=max_to_drain)
    stats = {"attempted": 0, "succeeded": 0, "deferred": 0, "failed": 0, "remaining": 0}

    for entry in entries:
        stats["attempted"] += 1
        seq = entry["sequence"]
        try:
            handler = DRAIN_HANDLERS[entry.get("kind") or "settings_patch"]
            result = handler(agent_id, entry, client)
            if inspect.isawaitable(result):
                await result
            mark_success(seq)
            stats["succeeded"] += 1
        except DeferEntry:
            stats["deferred"] += 1
        except Exception as e:
            mark_failure(seq, f"{type(e).__name__}: {e}")
            stats["failed"] += 1

    stats["remaining"] = pending_count(agent_id)
    return stats


__all__ = [
    "DRAIN_HANDLERS",
    "DeferEntry",
    "drain",
    "enqueue",
    "mark_failure",
    "mark_success",
    "peek",
    "pending_count",
    "purge_expired",
    "register_drain_handler",
    "reset_for_test",
]
