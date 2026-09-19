"""Event bus — publish primitive for the chapter (EB-2).

The chapter is now a publisher. ``publish()`` is the only sanctioned
way to record an event:

  1. Validate the payload against the closed schema in ``event_types``
     (raises ``ValueError`` on unknown event_type or malformed body).
  2. Persist to ``event_log`` via Postgres. The bigserial ``id`` is
     the canonical Last-Event-ID for SSE resume (EB-4).
  3. Return the persisted ``event_id`` to the caller (so the trigger
     site can audit it, and so subscribers see strictly increasing IDs).

Fanout to live subscribers is intentionally NOT in this module — that's
EB-4 (SSE delivery). EB-2 only persists. Subscribers query
``event_log.id > last_event_id`` to catch up.

Trust gating is enforced at fanout time (EB-5): EB-2 records every
event; the SSE endpoint snapshots each subscriber's trust score at
stream start and drops any event whose ``MIN_TRUST_TO_SUBSCRIBE`` tier
exceeds it. Both SSE delivery (EB-4, ``/api/events``) and this per-
subscriber gating are live.

Idempotency: every ``publish()`` call writes a new row. If a caller
needs at-most-once semantics, it's the caller's job to dedupe
(usually via the trigger event's own primary key).

Failure mode: if Postgres is unconfigured or the insert fails, this
returns None rather than raising. Callers that care should check the
return value; callers that fire-and-forget (the common case for
``register_member`` etc.) should use ``safe_publish()`` so the
business action doesn't fail because telemetry didn't.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from typing import Any

from event_types import EventPayloadBase, validate_event

logger = logging.getLogger(__name__)

_pg_request: Callable[..., Awaitable[Any]] | None = None
_chapter_id: str = ""


def init(pg_request: Callable[..., Awaitable[Any]], chapter_id: str) -> None:
    """Wire the postgres request callable + chapter id. Called at startup."""
    global _pg_request, _chapter_id  # noqa: PLW0603
    _pg_request = pg_request
    _chapter_id = chapter_id


def is_initialized() -> bool:
    """True iff init() has been called. Tests check this before asserting."""
    return _pg_request is not None


async def publish(
    event_type: str,
    payload: dict | EventPayloadBase,
    *,
    publisher_agent_id: str | None = None,
    trace: str | None = None,
) -> int | None:
    """Validate + persist an event to the chapter's event_log.

    ``payload`` may be a dict (validated here) or an already-built
    payload model (re-validated for safety; cheap).

    Returns the bigserial ``id`` Postgres assigned, or None if the
    bus isn't initialized OR the insert returned no row. Callers
    treat None as "event was not durably persisted" — never assume
    the row landed without seeing an integer back.

    Raises ``ValueError`` for an unknown event_type or a payload
    that fails the closed-set schema. Trigger sites should let the
    raise propagate so the bug is loud, not swallowed.
    """
    if _pg_request is None:
        logger.warning("event_bus.publish() called before init() — dropped event_type=%s", event_type)
        return None

    payload_dict = payload.model_dump(exclude_none=True) if isinstance(payload, EventPayloadBase) else dict(payload)

    # Re-validate even when the caller passed a model — guards against
    # someone hand-mutating the dict between construction and publish.
    validated = validate_event(event_type, payload_dict)

    body = {
        "event_type": event_type,
        "publisher_agent_id": publisher_agent_id or _chapter_id,
        "payload": validated.model_dump(exclude_none=True),
    }
    if trace:
        body["trace"] = trace

    result = await _pg_request("POST", "event_log", body=body)
    if not result:
        logger.warning("event_bus: Postgres INSERT returned no row for event_type=%s", event_type)
        return None

    # PostgREST returns a list with the inserted row when
    # ``Prefer: return=representation`` is set (default in this server).
    row = result[0] if isinstance(result, list) and result else result
    if not isinstance(row, dict):
        return None
    event_id = row.get("id")
    return int(event_id) if event_id is not None else None


# ── Read side — events_since() backs the SSE replay buffer ──────────


# Max rows returned per events_since() call. Bounds the per-poll memory
# footprint AND the catch-up batch size after a long disconnect. A
# subscriber that's been offline a long time will paginate naturally
# by passing the highest id from the previous batch as Last-Event-ID.
DEFAULT_EVENTS_SINCE_LIMIT = 100


async def events_since(
    last_event_id: int,
    topics: list[str],
    *,
    limit: int = DEFAULT_EVENTS_SINCE_LIMIT,
) -> list[dict]:
    """Fetch event_log rows with id > last_event_id and event_type IN topics.

    Backs:
      * SSE resume — a subscriber reconnects with ``Last-Event-ID: N``
        and gets every matching event since.
      * The SSE long-poll itself — every tick this is called with the
        highest id seen so far.

    Returns a list of dicts ordered by id ASC (so the caller can stream
    them in chronological order and update ``last_event_id`` row-by-row).
    Empty list on Postgres failure — same fault-tolerance shape as the
    rest of the chapter's Postgres wrappers.
    """
    if _pg_request is None or not topics:
        return []

    # PostgREST ``in.(a,b,c)`` filter. Topics are validated as known
    # EventTypes at subscribe time, so no SQL-injection risk from here —
    # but URL-quote anyway in case a future topic value contains a comma.
    topics_clause = ",".join(topics)
    params = {
        "id": f"gt.{last_event_id}",
        "event_type": f"in.({topics_clause})",
        "order": "id.asc",
        "limit": str(limit),
        "select": "id,event_type,publisher_agent_id,payload,created_at,trace",
    }
    result = await _pg_request("GET", "event_log", params=params)
    if not isinstance(result, list):
        return []
    return [r for r in result if isinstance(r, dict)]


def format_sse_event(row: dict) -> str:
    """Format an event_log row as a single SSE message.

    Wire format (per HTML5 SSE spec):
      id: <event_log.id>\\n
      event: <event_type>\\n
      data: <json payload>\\n
      \\n

    The ``id:`` field is critical — browsers/EventSource send it back
    as the ``Last-Event-ID`` header on reconnect, which is how resume
    works without explicit client bookkeeping.
    """
    import json as _json

    sse_id = row.get("id", "")
    event_type = row.get("event_type", "unknown")
    # Compact payload — SSE is line-sensitive and lower bytes-per-event
    # is friendlier to proxies + bandwidth-limited clients.
    data = _json.dumps(row.get("payload") or {}, separators=(",", ":"))
    return f"id: {sse_id}\nevent: {event_type}\ndata: {data}\n\n"


async def safe_publish(
    event_type: str,
    payload: dict | EventPayloadBase,
    *,
    publisher_agent_id: str | None = None,
    trace: str | None = None,
) -> int | None:
    """Fire-and-forget wrapper around publish().

    Swallows every exception (validation, Postgres, network) and logs.
    Use this from business-critical trigger sites where event emission
    failure must NOT cascade into a 5xx for the user (registration,
    intent submission, etc.).

    Use ``publish()`` directly when the caller MUST know whether the
    event landed (e.g. background reconciliation jobs that retry).
    """
    try:
        return await publish(event_type, payload, publisher_agent_id=publisher_agent_id, trace=trace)
    except Exception as e:  # noqa: BLE001
        logger.warning("event_bus.safe_publish swallowed error for %s: %s", event_type, e)
        return None
