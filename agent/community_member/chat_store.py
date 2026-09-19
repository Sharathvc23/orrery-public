"""Chat history — SQLite-backed durable store of conversation turns.

The agent's chat panel was previously stateless: every refresh threw
away the conversation. The chat endpoint stays stateless on the
wire (the client sends the full message array each turn, so the
server doesn't have to invent a session abstraction), but the
history needs to survive a browser refresh and an Electron restart.

Design

  - Sole source of truth lives in ``~/.community-member/chat_history.db``.
    SQLite with WAL so concurrent reads from the dashboard don't
    block writes from the chat stream.

  - Schema: ``(id, role, content_json, created_at)``. Content is
    stored as JSON because multimodal turns are content-block lists,
    not strings. Single-tenant — one row per turn, no thread/session
    column.

  - Write happens at *turn boundaries*: server records the user
    message at stream start and the assistant message at stream end.
    Tool calls aren't persisted as separate rows — they ride with
    the assistant message they belong to.

  - Reads are most-recent-first, capped at ``limit`` (default 200).
    The client can hydrate at mount and prepend the array to its
    in-memory state.

Privacy

  Same constraint as ``memory.json``: never leaves the host. No
  cross-device sync, no chapter upload. If the user wants to wipe,
  ``DELETE /api/local/chat/history`` truncates the table — no
  retention guarantees.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path

__all__ = [
    "_reset_for_tests",
    "append",
    "clear",
    "init",
    "list_recent",
]

_db_path: Path | None = None
_write_lock = threading.Lock()

_SCHEMA = """
CREATE TABLE IF NOT EXISTS chat_turns (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    role TEXT NOT NULL CHECK (role IN ('system', 'user', 'assistant', 'tool')),
    content_json TEXT NOT NULL,
    created_at REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_chat_turns_created_at
    ON chat_turns(created_at DESC);
"""


def init(db_path: str | Path) -> None:
    """Create the table if it doesn't exist. Idempotent."""
    global _db_path
    _db_path = Path(db_path)
    _db_path.parent.mkdir(parents=True, exist_ok=True)
    with _connect() as con:
        con.executescript(_SCHEMA)
        # WAL mode lets the dashboard read while the stream endpoint
        # is mid-write. Cheap and worth it.
        con.execute("PRAGMA journal_mode=WAL")


def _connect() -> sqlite3.Connection:
    if _db_path is None:
        raise RuntimeError("chat_store.init() must be called first")
    con = sqlite3.connect(str(_db_path), timeout=5.0)
    con.row_factory = sqlite3.Row
    return con


def append(role: str, content: str | list[dict]) -> int:
    """Persist one turn. Returns the row id.

    ``content`` may be a string (text-only turn) or a list of
    OpenAI-shape content blocks (multimodal). Both serialize as JSON.
    """
    if role not in ("system", "user", "assistant", "tool"):
        raise ValueError(f"invalid role: {role}")
    with _write_lock, _connect() as con:
        cur = con.execute(
            "INSERT INTO chat_turns (role, content_json, created_at) VALUES (?, ?, ?)",
            (role, json.dumps(content), time.time()),
        )
        con.commit()
        return cur.lastrowid or 0


def list_recent(limit: int = 200) -> list[dict]:
    """Return up to ``limit`` most-recent turns, oldest-first.

    The client wants chronological order to render the thread, but
    the index is keyed on ``created_at DESC`` so the recent slice is
    cheap to fetch. We reverse in Python.
    """
    limit = max(1, min(int(limit), 1000))
    with _connect() as con:
        rows = con.execute(
            "SELECT id, role, content_json, created_at FROM chat_turns ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    out: list[dict] = []
    for r in reversed(rows):
        try:
            content = json.loads(r["content_json"])
        except json.JSONDecodeError:
            content = r["content_json"]
        out.append(
            {
                "id": r["id"],
                "role": r["role"],
                "content": content,
                "created_at": r["created_at"],
            }
        )
    return out


def clear() -> int:
    """Wipe every turn. Returns the count deleted."""
    with _write_lock, _connect() as con:
        cur = con.execute("DELETE FROM chat_turns")
        con.commit()
        return cur.rowcount or 0


def _reset_for_tests() -> None:
    """Reset module state. Tests call init() with a tmp_path fresh."""
    global _db_path
    _db_path = None
