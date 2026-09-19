"""Subscription service — register/list/cancel chapter event subscriptions (EB-3).

Backed by the ``event_subscriptions`` table from EB-1. Sits behind
three endpoints in chapter_agent.py:

  POST   /api/subscriptions          create
  GET    /api/subscriptions          list caller's active subscriptions
  DELETE /api/subscriptions/{id}     cancel (soft-delete)

All three require Ed25519 auth — the auth middleware sets
``request.state.agent_id`` from the verified signature, and these
handlers use it as the canonical subscriber identity. The body never
gets to assert "I am alice" — only the signature does.

Trust gating per event-type lives in EB-5 at PUBLISH time, not here.
A low-trust subscriber can subscribe to intent.matched; they just
won't receive any events of that type until their trust score
crosses MIN_TRUST_TO_SUBSCRIBE[intent.matched]. We deliberately do
NOT reject the subscription request — trust changes happen on a
faster timescale than the 30-day subscription expiry, so silently
filtering at delivery time is the correct behaviour.

Cancellation is soft-delete (``active = false``) so audit can still
trace "subscriber X was watching topic Y between dates A and B"
even after they unsubscribed. Hard delete is the expiry sweep's
job (post-launch).
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from typing import Any

from event_types import EventType

logger = logging.getLogger(__name__)

# At least one topic per subscription — empty list is meaningless and
# the DB CHECK constraint also enforces this. We catch it earlier so
# the user gets a clean 400 instead of a Postgres error string.
MIN_TOPICS_PER_SUBSCRIPTION = 1

# Defense-in-depth on top of the migration's CHECK constraint.
WEBHOOK_REQUIRED_PREFIX = "https://"

_pg_request: Callable[..., Awaitable[Any]] | None = None
_chapter_id: str = ""


def init(pg_request: Callable[..., Awaitable[Any]], chapter_id: str) -> None:
    """Wire the postgres request callable + chapter id. Called at startup."""
    global _pg_request, _chapter_id  # noqa: PLW0603
    _pg_request = pg_request
    _chapter_id = chapter_id


def is_initialized() -> bool:
    return _pg_request is not None


# ── Validation ───────────────────────────────────────────────────────


def validate_topics(topics: list[str]) -> None:
    """Raise ValueError if any topic isn't a known EventType.

    Closed-set enforcement at subscribe time. Subscribing to a typo'd
    or future topic name silently delivers zero events, which is the
    worst kind of bug — the subscriber thinks they're listening but
    aren't. Fail loud at the boundary.
    """
    if not topics or len(topics) < MIN_TOPICS_PER_SUBSCRIPTION:
        raise ValueError("topics: at least one topic is required")

    known = {et.value for et in EventType}
    unknown = [t for t in topics if t not in known]
    if unknown:
        raise ValueError(f"unknown topics: {unknown}; valid topics: {sorted(known)}")


def validate_delivery(delivery: str, webhook_url: str | None) -> None:
    """Raise ValueError on bad delivery / webhook combination."""
    if delivery not in ("stream", "webhook"):
        raise ValueError(f"delivery must be 'stream' or 'webhook', got {delivery!r}")
    if delivery == "webhook":
        if not webhook_url:
            raise ValueError("delivery='webhook' requires webhook_url")
        if not webhook_url.startswith(WEBHOOK_REQUIRED_PREFIX):
            raise ValueError(f"webhook_url must start with {WEBHOOK_REQUIRED_PREFIX!r}")


# ── Service ──────────────────────────────────────────────────────────


async def create_subscription(
    *,
    subscriber_agent_id: str,
    subscriber_did_key: str,
    topics: list[str],
    filters: dict | None = None,
    delivery: str = "stream",
    webhook_url: str | None = None,
) -> dict | None:
    """Create a new subscription. Returns the persisted row.

    Raises ``ValueError`` for bad topics / delivery / webhook combos —
    the endpoint handler converts to 400.

    Returns None on Postgres failure (the endpoint surfaces 500). We
    don't raise on Postgres errors because the existing pg_request
    pattern returns None on failure; staying consistent with that.
    """
    if _pg_request is None:
        raise RuntimeError("subscriptions.init(...) must be called first")

    validate_topics(topics)
    validate_delivery(delivery, webhook_url)

    body = {
        "subscriber_agent_id": subscriber_agent_id,
        "subscriber_did_key": subscriber_did_key,
        "topics": topics,
        "filters": filters or {},
        "delivery": delivery,
    }
    if webhook_url:
        body["webhook_url"] = webhook_url

    result = await _pg_request("POST", "event_subscriptions", body=body)
    if not result:
        logger.warning("subscriptions: Postgres INSERT returned no row")
        return None
    row = result[0] if isinstance(result, list) and result else result
    return row if isinstance(row, dict) else None


async def list_active_subscriptions(subscriber_agent_id: str) -> list[dict]:
    """Return the caller's active subscriptions (most-recent first).

    Cross-tenant isolation is enforced here, NOT in the SELECT policy
    — RLS on event_subscriptions is closed and writes go through
    service_role, so this filter is the canonical "only your own subs"
    boundary.
    """
    if _pg_request is None:
        raise RuntimeError("subscriptions.init(...) must be called first")

    params = {
        "subscriber_agent_id": f"eq.{subscriber_agent_id}",
        "active": "eq.true",
        "order": "created_at.desc",
        "select": "*",
    }
    result = await _pg_request("GET", "event_subscriptions", params=params)
    if not result:
        return []
    return [r for r in result if isinstance(r, dict)] if isinstance(result, list) else []


async def get_subscription_for_owner(
    subscription_id: str,
    subscriber_agent_id: str,
) -> dict | None:
    """Fetch a single subscription, gated on ownership.

    Returns the row, or None if it doesn't exist OR belongs to someone
    else (same shape — no oracle leak). Used by the SSE stream endpoint
    (EB-4) to gate the long-lived connection: the caller must prove
    ownership before they can subscribe to the firehose.
    """
    if _pg_request is None:
        raise RuntimeError("subscriptions.init(...) must be called first")

    params = {
        "id": f"eq.{subscription_id}",
        "subscriber_agent_id": f"eq.{subscriber_agent_id}",
        "active": "eq.true",
        "select": "*",
        "limit": "1",
    }
    result = await _pg_request("GET", "event_subscriptions", params=params)
    if not result:
        return None
    rows = result if isinstance(result, list) else [result]
    return rows[0] if rows and isinstance(rows[0], dict) else None


async def cancel_subscription(
    *,
    subscription_id: str,
    subscriber_agent_id: str,
) -> bool:
    """Mark a subscription inactive. Only the owner can cancel.

    Returns True if a row was updated, False if the subscription
    doesn't exist OR belongs to someone else (we deliberately don't
    distinguish — same response shape avoids a per-id existence
    oracle for a hostile caller).
    """
    if _pg_request is None:
        raise RuntimeError("subscriptions.init(...) must be called first")

    params = {
        "id": f"eq.{subscription_id}",
        "subscriber_agent_id": f"eq.{subscriber_agent_id}",
        "active": "eq.true",
    }
    result = await _pg_request(
        "PATCH",
        "event_subscriptions",
        params=params,
        body={"active": False},
    )
    if not result:
        return False
    rows = result if isinstance(result, list) else [result]
    return len(rows) > 0
