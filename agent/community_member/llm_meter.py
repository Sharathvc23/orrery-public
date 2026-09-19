"""Agent-side LLM meter — what a provider actually reported, on disk.

The org side records into ``server/agent_telemetry``; this is its counterpart
for the agent, persisted to sqlite under the agent home so a figure survives the
restart that an in-memory counter would lose.

⚠️ WHY A METER SHIPS BEFORE THE SAVING IT MEASURES. The largest planned
optimisation removes 287 of 288 daily calls per agent. A skip that is not
counted cannot be proven and a regression in it cannot be seen, so the counting
has to exist first.

⚠️ EVERY FIGURE HERE IS AN OBSERVATION, NEVER AN ESTIMATE. What this repo has
produced so far is a tokenizer approximation: inputs from tiktoken over the
assembled request (measured 3.4% low against a real model's own
``prompt_tokens``) and outputs that are a ``max_tokens`` CEILING rather than
anything a provider said. This store records only what came back in
``response.usage``. There is no parameter through which an estimate can enter —
mixing one in would make the total unauditable, and the total is the point.

⚠️ AN ABSENT USAGE REPORT IS NOT ZERO. ``record(usage=None)`` says "the call
happened, the provider reported nothing"; it adds no tokens and increments
``calls_without_usage``. Summing tokens across calls where some reported nothing
would produce a number that looks complete and is not.

PER-PRINCIPAL FROM DAY ONE. Rows are keyed by
``(side, callsite, principal, provider, model)``. Keying costs nothing now and
is the only thing that would let a per-member multiplier land visibly rather
than as unexplained growth.

RECORD-ONLY: no gate, no skip decision, no cap, no price table.
"""

from __future__ import annotations

import sqlite3
import threading
from pathlib import Path
from typing import Any

#: Override, not a location. ``None`` means "resolve from the agent home on
#: use", which is what honours ``COMMUNITY_MEMBER_HOME``; tests pin a temp file.
#: Binding a path at import is how a store ends up shared by every agent on a
#: machine regardless of its home.
METER_PATH: Path | None = None

_KEY_FIELDS = ("side", "callsite", "principal", "provider", "model")
_COUNTERS = ("calls", "input_tokens", "output_tokens", "cached_tokens", "calls_skipped", "calls_without_usage")

_lock = threading.Lock()

_SCHEMA = """
CREATE TABLE IF NOT EXISTS llm_meter (
    side                TEXT NOT NULL,
    callsite            TEXT NOT NULL,
    principal           TEXT NOT NULL,
    provider            TEXT NOT NULL,
    model               TEXT NOT NULL,
    calls               INTEGER NOT NULL DEFAULT 0,
    input_tokens        INTEGER NOT NULL DEFAULT 0,
    output_tokens       INTEGER NOT NULL DEFAULT 0,
    cached_tokens       INTEGER NOT NULL DEFAULT 0,
    calls_skipped       INTEGER NOT NULL DEFAULT 0,
    calls_without_usage INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (side, callsite, principal, provider, model)
);
CREATE TABLE IF NOT EXISTS llm_skip_reason (
    side      TEXT NOT NULL,
    callsite  TEXT NOT NULL,
    principal TEXT NOT NULL,
    provider  TEXT NOT NULL,
    model     TEXT NOT NULL,
    reason    TEXT NOT NULL,
    count     INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (side, callsite, principal, provider, model, reason)
);
"""


def default_path() -> Path:
    """``<agent home>/.nanda/llm_meter.sqlite3``."""
    from community_member import agent_home

    return agent_home.resolve("llm_meter.sqlite3")


def meter_path() -> Path:
    """The store's path, resolved on every call.

    Resolved rather than cached so a process that sets ``COMMUNITY_MEMBER_HOME``
    late — a test, a wizard, an embedding host — is not left writing to a
    directory chosen before it got the chance.
    """
    return Path(METER_PATH) if METER_PATH is not None else default_path()


def _connect() -> sqlite3.Connection:
    path = meter_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.executescript(_SCHEMA)
    return conn


def _norm(value: Any) -> str:
    """A key field as a stable string. Empty becomes ``unknown`` rather than an
    empty string, so a missing principal stays visible instead of blending into
    the next row."""
    text = str(value).strip() if value is not None else ""
    return text or "unknown"


def _key(side: str, callsite: str, principal: str, provider: str, model: str) -> tuple[str, ...]:
    return tuple(_norm(v) for v in (side, callsite, principal, provider, model))


def record(
    *,
    side: str = "agent",
    callsite: str,
    principal: str,
    provider: str,
    model: str,
    usage: dict[str, Any] | None,
) -> None:
    """Record one LLM call that WAS made.

    ``usage`` is the provider's own report normalised to
    ``{input_tokens, output_tokens, cached_tokens}``; ``None`` means it reported
    nothing and is counted as such, contributing no tokens.
    """
    key = _key(side, callsite, principal, provider, model)
    if usage is None:
        deltas = {"calls": 1, "calls_without_usage": 1}
    else:
        deltas = {"calls": 1}
        for column, source in (
            ("input_tokens", "input_tokens"),
            ("output_tokens", "output_tokens"),
            ("cached_tokens", "cached_tokens"),
        ):
            value = usage.get(source)
            if isinstance(value, (int, float)) and value >= 0:
                deltas[column] = int(value)
    _apply(key, deltas)


def record_skip(
    *,
    side: str = "agent",
    callsite: str,
    principal: str,
    provider: str,
    model: str,
    reason: str,
) -> None:
    """Record one LLM call that was NOT made, and why."""
    key = _key(side, callsite, principal, provider, model)
    _apply(key, {"calls_skipped": 1})
    with _lock, _connect() as conn:
        conn.execute(
            "INSERT INTO llm_skip_reason (side, callsite, principal, provider, model, reason, count) "
            "VALUES (?, ?, ?, ?, ?, ?, 1) "
            "ON CONFLICT (side, callsite, principal, provider, model, reason) "
            "DO UPDATE SET count = count + 1",
            (*key, _norm(reason)),
        )


def _apply(key: tuple[str, ...], deltas: dict[str, int]) -> None:
    """Add ``deltas`` to one row, creating it. Columns are from a fixed tuple,
    never from caller input, so the interpolation below cannot carry a value."""
    columns = [c for c in _COUNTERS if c in deltas]
    insert_cols = ", ".join(columns)
    insert_vals = ", ".join("?" for _ in columns)
    updates = ", ".join(f"{c} = {c} + excluded.{c}" for c in columns)
    with _lock, _connect() as conn:
        conn.execute(
            f"INSERT INTO llm_meter ({', '.join(_KEY_FIELDS)}, {insert_cols}) "
            f"VALUES (?, ?, ?, ?, ?, {insert_vals}) "
            f"ON CONFLICT ({', '.join(_KEY_FIELDS)}) DO UPDATE SET {updates}",
            (*key, *(deltas[c] for c in columns)),
        )


def spend() -> dict:
    """A snapshot of the meter: per-series rows plus totals."""
    with _lock, _connect() as conn:
        conn.row_factory = sqlite3.Row
        rows = [dict(r) for r in conn.execute(f"SELECT * FROM llm_meter ORDER BY {', '.join(_KEY_FIELDS)}")]
        reasons = [dict(r) for r in conn.execute("SELECT * FROM llm_skip_reason")]

    by_key: dict[tuple[str, ...], dict[str, int]] = {}
    for r in reasons:
        by_key.setdefault(tuple(r[f] for f in _KEY_FIELDS), {})[r["reason"]] = int(r["count"])
    for row in rows:
        row["skip_reason"] = by_key.get(tuple(row[f] for f in _KEY_FIELDS), {})

    totals: dict[str, Any] = {c: sum(int(r[c]) for r in rows) for c in _COUNTERS}
    merged: dict[str, int] = {}
    for buckets in by_key.values():
        for reason, count in buckets.items():
            merged[reason] = merged.get(reason, 0) + count
    totals["skip_reason"] = merged

    return {
        "record_only": True,
        "observed_usage_only": True,
        "path": str(meter_path()),
        "series": rows,
        "series_count": len(rows),
        "totals": totals,
    }


def reset() -> None:
    """Drop every recorded figure. For tests and for an operator who wants a
    clean measurement window; never called by the runtime."""
    with _lock, _connect() as conn:
        conn.execute("DELETE FROM llm_meter")
        conn.execute("DELETE FROM llm_skip_reason")
