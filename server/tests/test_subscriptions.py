"""Tests for the subscription service (EB-3).

Covers the create/list/cancel boundary that the chapter exposes
behind /api/subscriptions. The HTTP layer is thin — the business
logic (closed-set topic validation, webhook URL guard, cross-tenant
isolation, soft-delete semantics) lives in subscriptions.py.

  * topic validation: empty rejected, unknown rejected, every known
    EventType accepted
  * webhook validation: requires https://, requires URL, default
    delivery ok with no URL
  * create persists with the right body shape (subscriber identity
    locked from caller, never trusted from request body)
  * list filters by subscriber_agent_id + active=true (cross-tenant
    isolation enforced at the service, not the DB)
  * cancel only marks active=false for the OWNER's subscription;
    cross-tenant cancel attempts return False (no oracle leak)
  * not-initialised raises (subscriptions are too important to
    silently drop — different policy from event_bus.publish)
"""

from __future__ import annotations

from typing import Any

import pytest

import subscriptions
from event_types import EventType


@pytest.fixture(autouse=True)
def _reset_subs():
    subscriptions._pg_request = None
    subscriptions._chapter_id = ""
    yield
    subscriptions._pg_request = None
    subscriptions._chapter_id = ""


class FakePostgres:
    """Records calls; default return is a one-row list mimicking PostgREST."""

    def __init__(self, *, return_value: Any = "AUTO") -> None:
        self.calls: list[tuple[str, str, dict | None, dict | list | None]] = []
        self._next_id = 1
        self._return_value = return_value

    async def __call__(
        self,
        method: str,
        table: str,
        params: dict | None = None,
        body: dict | list | None = None,
    ) -> Any:
        self.calls.append((method, table, params, body))
        if self._return_value == "AUTO":
            if method == "POST":
                row = {**(body or {}), "id": f"sub-{self._next_id:04d}", "active": True}
                self._next_id += 1
                return [row]
            return [{"id": "sub-existing"}]
        return self._return_value


# ── validate_topics() ────────────────────────────────────────────────


def test_validate_topics_rejects_empty_list() -> None:
    with pytest.raises(ValueError, match="at least one"):
        subscriptions.validate_topics([])


def test_validate_topics_rejects_unknown_topic() -> None:
    with pytest.raises(ValueError, match="unknown topics"):
        subscriptions.validate_topics(["member.joined", "not.a.real.topic"])


def test_validate_topics_accepts_every_known_event_type() -> None:
    # Every EventType in the catalog must be subscribable. If a future
    # PR adds a member but forgets, this fails.
    for et in EventType:
        subscriptions.validate_topics([et.value])  # no raise


def test_validate_topics_accepts_a_mix() -> None:
    subscriptions.validate_topics(["member.joined", "intent.published"])


# ── validate_delivery() ──────────────────────────────────────────────


def test_validate_delivery_stream_default_no_url_required() -> None:
    subscriptions.validate_delivery("stream", None)  # no raise


def test_validate_delivery_webhook_requires_url() -> None:
    with pytest.raises(ValueError, match="requires webhook_url"):
        subscriptions.validate_delivery("webhook", None)


def test_validate_delivery_webhook_requires_https() -> None:
    with pytest.raises(ValueError, match="must start with"):
        subscriptions.validate_delivery("webhook", "http://insecure.example/hook")


def test_validate_delivery_rejects_unknown_mode() -> None:
    with pytest.raises(ValueError, match="must be 'stream' or 'webhook'"):
        subscriptions.validate_delivery("smoke-signals", None)


def test_validate_delivery_webhook_accepts_https() -> None:
    subscriptions.validate_delivery("webhook", "https://hooks.example/x")  # no raise


# ── create_subscription() — happy path + identity locking ────────────


@pytest.mark.asyncio
async def test_create_subscription_persists_correct_body() -> None:
    sb = FakePostgres()
    subscriptions.init(sb, "chapter-x")

    row = await subscriptions.create_subscription(
        subscriber_agent_id="alice",
        subscriber_did_key="did:key:zAlice",
        topics=["member.joined", "intent.published"],
    )

    assert row is not None
    assert row["id"].startswith("sub-")
    method, table, _, body = sb.calls[0]
    assert (method, table) == ("POST", "event_subscriptions")
    assert body == {
        "subscriber_agent_id": "alice",
        "subscriber_did_key": "did:key:zAlice",
        "topics": ["member.joined", "intent.published"],
        "filters": {},
        "delivery": "stream",
    }


@pytest.mark.asyncio
async def test_create_subscription_with_filters_and_webhook() -> None:
    sb = FakePostgres()
    subscriptions.init(sb, "chapter-x")

    await subscriptions.create_subscription(
        subscriber_agent_id="alice",
        subscriber_did_key="did:key:zAlice",
        topics=["intent.published"],
        filters={"min_trust": 25},
        delivery="webhook",
        webhook_url="https://hooks.example/alice",
    )

    body = sb.calls[0][3]
    assert body["filters"] == {"min_trust": 25}
    assert body["delivery"] == "webhook"
    assert body["webhook_url"] == "https://hooks.example/alice"


@pytest.mark.asyncio
async def test_create_subscription_propagates_validation_errors() -> None:
    sb = FakePostgres()
    subscriptions.init(sb, "chapter-x")

    with pytest.raises(ValueError, match="unknown topics"):
        await subscriptions.create_subscription(
            subscriber_agent_id="alice",
            subscriber_did_key="did:key:zAlice",
            topics=["totally.fake"],
        )

    assert sb.calls == []  # nothing persisted


@pytest.mark.asyncio
async def test_create_subscription_returns_none_on_supabase_failure() -> None:
    sb = FakePostgres(return_value=None)
    subscriptions.init(sb, "chapter-x")

    row = await subscriptions.create_subscription(
        subscriber_agent_id="alice",
        subscriber_did_key="did:key:zAlice",
        topics=["member.joined"],
    )
    assert row is None


@pytest.mark.asyncio
async def test_create_subscription_raises_when_uninitialised() -> None:
    with pytest.raises(RuntimeError, match="must be called first"):
        await subscriptions.create_subscription(
            subscriber_agent_id="alice",
            subscriber_did_key="did:key:zAlice",
            topics=["member.joined"],
        )


# ── list_active_subscriptions() — cross-tenant isolation ─────────────


@pytest.mark.asyncio
async def test_list_filters_by_subscriber_and_active() -> None:
    sb = FakePostgres(
        return_value=[
            {"id": "sub-1", "subscriber_agent_id": "alice", "topics": ["member.joined"], "active": True},
        ]
    )
    subscriptions.init(sb, "chapter-x")

    rows = await subscriptions.list_active_subscriptions("alice")

    assert len(rows) == 1
    assert rows[0]["id"] == "sub-1"
    method, table, params, _ = sb.calls[0]
    assert (method, table) == ("GET", "event_subscriptions")
    assert params["subscriber_agent_id"] == "eq.alice"
    assert params["active"] == "eq.true"


@pytest.mark.asyncio
async def test_list_returns_empty_when_no_subs() -> None:
    sb = FakePostgres(return_value=[])
    subscriptions.init(sb, "chapter-x")

    rows = await subscriptions.list_active_subscriptions("nobody")
    assert rows == []


@pytest.mark.asyncio
async def test_list_returns_empty_on_supabase_failure() -> None:
    sb = FakePostgres(return_value=None)
    subscriptions.init(sb, "chapter-x")

    rows = await subscriptions.list_active_subscriptions("alice")
    assert rows == []


# ── get_subscription_for_owner() — gated fetch for SSE (EB-4) ────────


@pytest.mark.asyncio
async def test_get_for_owner_returns_row_when_match() -> None:
    sb = FakePostgres(
        return_value=[
            {"id": "sub-1", "subscriber_agent_id": "alice", "topics": ["member.joined"], "active": True},
        ]
    )
    subscriptions.init(sb, "chapter-x")

    row = await subscriptions.get_subscription_for_owner("sub-1", "alice")
    assert row is not None
    assert row["id"] == "sub-1"
    method, table, params, _ = sb.calls[0]
    assert (method, table) == ("GET", "event_subscriptions")
    # Triple filter: id, subscriber, active — no oracle, no inactive replay.
    assert params["id"] == "eq.sub-1"
    assert params["subscriber_agent_id"] == "eq.alice"
    assert params["active"] == "eq.true"


@pytest.mark.asyncio
async def test_get_for_owner_returns_none_when_not_owner() -> None:
    """Cross-tenant fetch returns None — same shape as "doesn't exist"."""
    sb = FakePostgres(return_value=[])
    subscriptions.init(sb, "chapter-x")

    row = await subscriptions.get_subscription_for_owner("sub-bobs", "alice")
    assert row is None


@pytest.mark.asyncio
async def test_get_for_owner_returns_none_on_supabase_failure() -> None:
    sb = FakePostgres(return_value=None)
    subscriptions.init(sb, "chapter-x")
    row = await subscriptions.get_subscription_for_owner("sub-1", "alice")
    assert row is None


# ── cancel_subscription() — owner-only, soft-delete ──────────────────


@pytest.mark.asyncio
async def test_cancel_marks_inactive_for_owner() -> None:
    sb = FakePostgres(return_value=[{"id": "sub-1", "active": False}])
    subscriptions.init(sb, "chapter-x")

    ok = await subscriptions.cancel_subscription(
        subscription_id="sub-1",
        subscriber_agent_id="alice",
    )

    assert ok is True
    method, table, params, body = sb.calls[0]
    assert (method, table) == ("PATCH", "event_subscriptions")
    # Both filters present — service does the cross-tenant guard, not RLS.
    assert params["id"] == "eq.sub-1"
    assert params["subscriber_agent_id"] == "eq.alice"
    assert params["active"] == "eq.true"  # don't re-cancel an already-inactive row
    assert body == {"active": False}


@pytest.mark.asyncio
async def test_cancel_returns_false_when_not_owner_or_missing() -> None:
    """Cross-tenant attempt → empty result → False. No oracle leak."""
    sb = FakePostgres(return_value=[])
    subscriptions.init(sb, "chapter-x")

    ok = await subscriptions.cancel_subscription(
        subscription_id="sub-belonging-to-bob",
        subscriber_agent_id="alice",
    )
    assert ok is False


@pytest.mark.asyncio
async def test_cancel_returns_false_on_supabase_failure() -> None:
    sb = FakePostgres(return_value=None)
    subscriptions.init(sb, "chapter-x")

    ok = await subscriptions.cancel_subscription(
        subscription_id="sub-1",
        subscriber_agent_id="alice",
    )
    assert ok is False
