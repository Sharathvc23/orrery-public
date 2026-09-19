"""Trust-tier gating for event delivery (EB-5).

Filter events at DELIVERY time (not subscribe time) so a trust change
applies immediately to the next event, without revoking the subscription
or requiring a re-handshake.

The contract:
  * subscriber with trust_score < MIN_TRUST_TO_SUBSCRIBE[event_type]
    does NOT receive events of that type
  * the event is still recorded in event_log — gating is at the
    delivery boundary, not at publish. This preserves audit ("alice
    posted X at time T") while protecting subscribers from seeing
    things their trust tier shouldn't see.
  * a freshly-promoted subscriber sees the NEXT event of the new
    tier; we do NOT retroactively backfill events they missed while
    below threshold. Backfill would be a security regression — the
    point of the tier is "you weren't trusted with this at the time."

Trust score lookup happens via Postgres ``agents`` table. To avoid
hammering Postgres on every SSE tick we cache scores for
``DEFAULT_CACHE_TTL_S`` seconds — long enough to spare the DB,
short enough that a real trust event lands in subscribers' filters
within ~30s of the event landing.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Awaitable, Callable
from typing import Any

from event_types import MIN_TRUST_TO_SUBSCRIBE, EventType

logger = logging.getLogger(__name__)

DEFAULT_CACHE_TTL_S = 30.0

_pg_request: Callable[..., Awaitable[Any]] | None = None

# agent_id → (trust_score, expires_at_unix_seconds)
_score_cache: dict[str, tuple[float, float]] = {}


def init(pg_request: Callable[..., Awaitable[Any]]) -> None:
    """Wire the postgres request callable. Called at startup."""
    global _pg_request  # noqa: PLW0603
    _pg_request = pg_request


def _clear_cache_for_tests() -> None:
    """Used by test fixtures only — do not call from production code."""
    _score_cache.clear()


async def get_subscriber_trust_score(
    agent_id: str,
    *,
    cache_ttl_s: float = DEFAULT_CACHE_TTL_S,
) -> float:
    """Read agents.trust_score for ``agent_id``.

    Returns 0.0 when the agent doesn't exist, the column is null, or
    Postgres is unreachable. A missing score is the safest default —
    it means the agent gets only trust-0 events, which is what we'd
    want for an unknown caller anyway.

    Cached for ``cache_ttl_s`` seconds per agent_id to keep the per-tick
    SSE poll cheap. Cache is best-effort; a stale entry just means the
    subscriber sees up to ``cache_ttl_s`` worth of events at their old
    tier before promotion/demotion kicks in.
    """
    if _pg_request is None:
        return 0.0

    now = time.time()
    cached = _score_cache.get(agent_id)
    if cached is not None and cached[1] > now:
        return cached[0]

    try:
        rows = await _pg_request(
            "GET",
            "agents",
            params={
                "agent_id": f"eq.{agent_id}",
                "select": "trust_score",
                "limit": "1",
            },
        )
    except Exception as e:  # noqa: BLE001
        logger.warning("trust_gate: Postgres error reading score for %s: %s", agent_id, e)
        rows = None

    score = 0.0
    if isinstance(rows, list) and rows:
        raw = rows[0].get("trust_score") if isinstance(rows[0], dict) else None
        if raw is not None:
            try:
                score = float(raw)
            except (TypeError, ValueError):
                score = 0.0

    _score_cache[agent_id] = (score, now + cache_ttl_s)
    return score


def filter_events_for_trust(rows: list[dict], subscriber_trust_score: float) -> list[dict]:
    """Drop events whose MIN_TRUST_TO_SUBSCRIBE exceeds the subscriber score.

    Closed-set semantics — an event_type not in the table is treated
    as `requires_trust = +inf` (drop). This is the safe failure mode:
    a future event type whose tier hasn't been registered yet gets
    blocked rather than silently leaking.
    """
    out: list[dict] = []
    for row in rows:
        event_type_str = row.get("event_type", "")
        try:
            et = EventType(event_type_str)
        except ValueError:
            # Unknown event_type — drop. Should be impossible because
            # validate_event blocks unknown types at publish; defensive.
            continue
        threshold = MIN_TRUST_TO_SUBSCRIBE.get(et)
        if threshold is None:
            continue
        if subscriber_trust_score >= threshold:
            out.append(row)
    return out
