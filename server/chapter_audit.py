"""
Chapter audit log — immutable append-only event ledger.

Every privileged action writes a row here. Rows form a hash chain so any
mutation is detectable: each event's sha256 includes the sha256 of the
previous event in the same chapter. Auditors (or a verify_chain() call)
can re-derive the chain and fail loud on tampering.

Rows are public-readable but service-writes-only, and there is no UPDATE
or DELETE RLS policy — Postgres itself refuses modifications.

For SIEM integration the export helper emits JSON Lines, which every
major SIEM (Splunk, Datadog, Sumo) consumes natively.

Public API
----------
init(pg_request)            — DI
record(chapter_id, action, ...)   — append a row (returns event hash)
list_events(chapter_id, filters)  — paginated read
verify_chain(chapter_id)          — recompute hash chain; raises on drift
export_jsonl(chapter_id, since)   — yield JSON lines for SIEM ingest

canonical_event(event)            — deterministic serialization (pure)
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any

_pg_request: Callable[..., Awaitable[Any]] | None = None

MAX_DETAIL_BYTES = 32 * 1024
VALID_OUTCOMES = frozenset({"ok", "fail", "denied"})
MAX_ACTION_LEN = 64


def init(pg_request_fn: Callable[..., Awaitable[Any]]) -> None:
    global _pg_request
    _pg_request = pg_request_fn


# ── Pure: canonical serialization + hash chain ──────────────────


def canonical_event(event: dict) -> str:
    """Deterministic JSON serialization for hashing.

    Keys are sorted, whitespace stripped, UTF-8 encoded. Two events with
    equal content produce the same sha256 regardless of dict insertion
    order — a bedrock requirement for chain integrity.
    """
    # Only the fields that define the event identity.
    minimal = {
        "chapter_id": event.get("chapter_id"),
        "actor_agent_id": event.get("actor_agent_id"),
        "action": event.get("action"),
        "target_type": event.get("target_type"),
        "target_id": event.get("target_id"),
        "outcome": event.get("outcome"),
        "detail": event.get("detail") or {},
        "occurred_at": event.get("occurred_at"),
        "prev_sha256": event.get("prev_sha256") or "",
    }
    return json.dumps(minimal, sort_keys=True, separators=(",", ":"))


def sha256_of(event: dict) -> str:
    return hashlib.sha256(canonical_event(event).encode("utf-8")).hexdigest()


# ── Validation ─────────────────────────────────────────────────


def _validate(action: str, outcome: str, detail: dict) -> tuple[bool, str]:
    if not action or not isinstance(action, str):
        return False, "action is required"
    if len(action) > MAX_ACTION_LEN:
        return False, f"action too long (max {MAX_ACTION_LEN})"
    if outcome not in VALID_OUTCOMES:
        return False, f"outcome must be one of {sorted(VALID_OUTCOMES)}"
    if detail is not None:
        if not isinstance(detail, dict):
            return False, "detail must be a dict"
        if len(json.dumps(detail).encode("utf-8")) > MAX_DETAIL_BYTES:
            return False, f"detail too large (max {MAX_DETAIL_BYTES} bytes)"
    return True, "ok"


# ── Append ─────────────────────────────────────────────────────


async def record(
    chapter_id: str,
    action: str,
    *,
    actor_agent_id: str | None = None,
    target_type: str | None = None,
    target_id: str | None = None,
    outcome: str = "ok",
    detail: dict | None = None,
) -> dict:
    """Append an event to the chapter's audit log. Returns the persisted row."""
    if _pg_request is None:
        raise RuntimeError("chapter_audit not initialized — call init()")

    ok, reason = _validate(action, outcome, detail or {})
    if not ok:
        raise ValueError(reason)

    # Fetch the most recent event for this server to chain.
    prev = await _pg_request(
        "GET",
        "chapter_audit_events",
        params={
            "chapter_id": f"eq.{chapter_id}",
            "order": "occurred_at.desc",
            "select": "event_sha256",
            "limit": "1",
        },
    )
    prev_hash = (prev[0]["event_sha256"] if prev else "") or ""

    event = {
        "chapter_id": chapter_id,
        "actor_agent_id": actor_agent_id,
        "action": action[:MAX_ACTION_LEN],
        "target_type": (target_type or "")[:64] or None,
        "target_id": (target_id or "")[:128] or None,
        "outcome": outcome,
        "detail": detail or {},
        "occurred_at": datetime.now(UTC).isoformat(),
        "prev_sha256": prev_hash or None,
    }
    event["event_sha256"] = sha256_of(event)

    inserted = await _pg_request("POST", "chapter_audit_events", body=event)
    return inserted[0] if isinstance(inserted, list) and inserted else event


# ── Read ───────────────────────────────────────────────────────


async def list_events(
    chapter_id: str,
    action: str | None = None,
    actor_agent_id: str | None = None,
    since: str | None = None,
    limit: int = 100,
) -> list[dict]:
    if _pg_request is None:
        raise RuntimeError("chapter_audit not initialized")
    params: dict[str, str] = {
        "chapter_id": f"eq.{chapter_id}",
        "order": "occurred_at.desc",
        "limit": str(min(max(int(limit), 1), 1000)),
    }
    if action:
        params["action"] = f"eq.{action[:MAX_ACTION_LEN]}"
    if actor_agent_id:
        params["actor_agent_id"] = f"eq.{actor_agent_id}"
    if since:
        params["occurred_at"] = f"gte.{since}"
    return await _pg_request("GET", "chapter_audit_events", params=params) or []


# ── Verify chain ───────────────────────────────────────────────


async def verify_chain(chapter_id: str) -> dict:
    """Re-derive the hash chain for chapter_id's audit log.

    Returns {ok, length, first_broken_at?, expected_sha, actual_sha}.
    """
    if _pg_request is None:
        raise RuntimeError("chapter_audit not initialized")

    rows = await _pg_request(
        "GET",
        "chapter_audit_events",
        params={
            "chapter_id": f"eq.{chapter_id}",
            "order": "occurred_at.asc",
            "limit": "5000",
        },
    )
    rows = rows or []
    prev = ""
    for i, r in enumerate(rows):
        event = {
            "chapter_id": r["chapter_id"],
            "actor_agent_id": r.get("actor_agent_id"),
            "action": r["action"],
            "target_type": r.get("target_type"),
            "target_id": r.get("target_id"),
            "outcome": r["outcome"],
            "detail": r.get("detail") or {},
            "occurred_at": r["occurred_at"],
            "prev_sha256": (r.get("prev_sha256") or prev) or None,
        }
        expected = sha256_of(event)
        if expected != r["event_sha256"]:
            return {
                "ok": False,
                "length": len(rows),
                "first_broken_at": r["occurred_at"],
                "broken_index": i,
                "expected_sha256": expected,
                "actual_sha256": r["event_sha256"],
            }
        if (r.get("prev_sha256") or "") != (prev or ""):
            return {
                "ok": False,
                "length": len(rows),
                "first_broken_at": r["occurred_at"],
                "broken_index": i,
                "reason": "prev_sha256 does not match chain",
                "expected_prev": prev,
                "actual_prev": r.get("prev_sha256"),
            }
        prev = r["event_sha256"]
    return {"ok": True, "length": len(rows)}


# ── Export ─────────────────────────────────────────────────────


async def chain_tip(chapter_id: str) -> dict:
    """Return the audit chain's current state for ``chapter_id``.

    Shape:
      {
        "tip_sha256":         <sha of most-recent event, or "" if chain empty>,
        "length":             <int row count for this chapter>,
        "first_occurred_at":  <ISO timestamp of earliest row, or None>,
        "last_occurred_at":   <ISO timestamp of most-recent row, or None>,
      }

    Used by A3.3 to build Signed Tree Head attestations — a chapter
    commits to its chain state at a point in time, signs the commitment,
    and publishes. Verifiers compare across snapshots to detect chain
    mutation (events removed, reordered, or back-dated).

    Capped at 10 000 rows. Above that, the chain has outgrown a
    single-snapshot attestation primitive; paginated snapshots are a
    follow-up if/when long-running chapters need them.
    """
    if _pg_request is None:
        raise RuntimeError("chapter_audit not initialized")
    rows = await _pg_request(
        "GET",
        "chapter_audit_events",
        params={
            "chapter_id": f"eq.{chapter_id}",
            "order": "occurred_at.asc",
            "limit": "10000",
            "select": "event_sha256,occurred_at",
        },
    )
    rows = rows or []
    if not rows:
        return {
            "tip_sha256": "",
            "length": 0,
            "first_occurred_at": None,
            "last_occurred_at": None,
        }
    return {
        "tip_sha256": rows[-1]["event_sha256"],
        "length": len(rows),
        "first_occurred_at": rows[0]["occurred_at"],
        "last_occurred_at": rows[-1]["occurred_at"],
    }


async def export_jsonl(chapter_id: str, since: str | None = None) -> list[str]:
    """Return events as JSON Lines strings ready for SIEM ingest.

    We return a list (not a generator) because FastAPI StreamingResponse
    ergonomics are awkward for our callers right now; volume-wise this
    is fine for <10k rows per request.
    """
    events = await list_events(chapter_id, since=since, limit=1000)
    return [json.dumps(e, sort_keys=True, default=str) for e in reversed(events)]
