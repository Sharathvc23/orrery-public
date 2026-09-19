"""Endpoint-layer tests for /api/subscriptions (EB-3).

Calls the FastAPI handler coroutines directly with a minimal Request
stand-in. This bypasses the auth middleware (covered by its own
tests) so we can focus on the endpoint's own contract:

  * caller identity comes from request.state.agent_id, NOT the body
  * 400 on validation failure with a useful error string
  * 503 on Postgres failure (clean error, not a 5xx)
  * cancel returns 404 (not 403) for cross-tenant attempts so a
    hostile caller can't enumerate other agents' subscription IDs

The service-layer logic (closed-set topic check, webhook URL guard,
cross-tenant SQL filter) is covered in test_subscriptions.py.
"""

from __future__ import annotations

import os

os.environ.setdefault("AGENT_ID", "test-chapter")
os.environ.setdefault("AGENT_NAME", "Test Chapter")

import json  # noqa: E402
from typing import Any  # noqa: E402

import pytest  # noqa: E402

import chapter_agent  # noqa: E402
import subscriptions as subscriptions_svc  # noqa: E402


class FakeState:
    def __init__(self, agent_id: str = "") -> None:
        self.agent_id = agent_id


class FakeRequest:
    """Minimal Request stand-in. Only what the handlers touch."""

    def __init__(self, agent_id: str = "", header_agent_id: str = "") -> None:
        self.state = FakeState(agent_id)
        self.headers = {"X-Agent-ID": header_agent_id} if header_agent_id else {}


def _read_body(resp) -> dict:
    """Pull the JSON body out of a FastAPI response (handler may return
    a dict OR a JSONResponse depending on the path it took)."""
    if isinstance(resp, dict):
        return resp
    body = resp.body
    if isinstance(body, bytes):
        body = body.decode()
    return json.loads(body)


def _status(resp) -> int:
    return getattr(resp, "status_code", 200)


@pytest.fixture(autouse=True)
def _stub_subs_service(monkeypatch):
    state: dict[str, Any] = {"created": [], "listed": [], "cancelled": []}

    async def _create(**kwargs):
        state["created"].append(kwargs)
        if "totally.fake" in kwargs["topics"]:
            raise ValueError("unknown topics: ['totally.fake']")
        if kwargs["subscriber_agent_id"] == "force-503":
            return None
        return {"id": "sub-123", **kwargs, "active": True}

    async def _list(agent_id: str):
        state["listed"].append(agent_id)
        return [{"id": "sub-1", "subscriber_agent_id": agent_id, "topics": ["member.joined"]}]

    async def _cancel(*, subscription_id: str, subscriber_agent_id: str):
        state["cancelled"].append((subscription_id, subscriber_agent_id))
        return subscription_id == "sub-mine" and subscriber_agent_id == "alice"

    monkeypatch.setattr(subscriptions_svc, "create_subscription", _create)
    monkeypatch.setattr(subscriptions_svc, "list_active_subscriptions", _list)
    monkeypatch.setattr(subscriptions_svc, "cancel_subscription", _cancel)
    yield state


# ── Identity locking ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_create_uses_request_state_agent_id_not_body(_stub_subs_service):
    req = chapter_agent.SubscriptionRequest(topics=["member.joined"])
    request = FakeRequest(agent_id="alice")
    result = await chapter_agent.create_subscription_endpoint(req, request)

    assert _status(result) == 200
    body = _read_body(result)
    assert body["subscription"]["subscriber_agent_id"] == "alice"
    assert _stub_subs_service["created"][-1]["subscriber_agent_id"] == "alice"


@pytest.mark.asyncio
async def test_create_ignores_spoofed_x_agent_id_header_without_state(_stub_subs_service):
    """P0: a spoofed X-Agent-ID header with no verified state is NOT a
    caller — the old header fallback is gone, so this is rejected as unauth
    rather than silently acting as 'bob'."""
    req = chapter_agent.SubscriptionRequest(topics=["member.joined"])
    request = FakeRequest(agent_id="", header_agent_id="bob")
    result = await chapter_agent.create_subscription_endpoint(req, request)

    assert _status(result) == 401
    assert _stub_subs_service["created"] == []


@pytest.mark.asyncio
async def test_create_returns_401_with_no_caller():
    req = chapter_agent.SubscriptionRequest(topics=["member.joined"])
    request = FakeRequest()
    result = await chapter_agent.create_subscription_endpoint(req, request)
    assert _status(result) == 401


# ── Validation error mapping ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_unknown_topic_returns_400():
    req = chapter_agent.SubscriptionRequest(topics=["totally.fake"])
    request = FakeRequest(agent_id="alice")
    result = await chapter_agent.create_subscription_endpoint(req, request)

    assert _status(result) == 400
    assert "unknown topics" in _read_body(result)["error"]


@pytest.mark.asyncio
async def test_supabase_failure_returns_503():
    req = chapter_agent.SubscriptionRequest(topics=["member.joined"])
    request = FakeRequest(agent_id="force-503")
    result = await chapter_agent.create_subscription_endpoint(req, request)

    assert _status(result) == 503
    assert "unavailable" in _read_body(result)["error"]


# ── List ─────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_list_returns_caller_subscriptions_only(_stub_subs_service):
    request = FakeRequest(agent_id="alice")
    result = await chapter_agent.list_subscriptions_endpoint(request)

    body = _read_body(result)
    assert body["total"] == 1
    assert body["subscriptions"][0]["subscriber_agent_id"] == "alice"
    # Service called with the caller's id, not anything from a body
    assert _stub_subs_service["listed"] == ["alice"]


@pytest.mark.asyncio
async def test_list_unauth_returns_401():
    request = FakeRequest()
    result = await chapter_agent.list_subscriptions_endpoint(request)
    assert _status(result) == 401


# ── Cancel — owner-only, no oracle leak ──────────────────────────────


@pytest.mark.asyncio
async def test_cancel_owner_returns_200(_stub_subs_service):
    request = FakeRequest(agent_id="alice")
    result = await chapter_agent.cancel_subscription_endpoint("sub-mine", request)

    assert _status(result) == 200
    body = _read_body(result)
    assert body == {"subscription_id": "sub-mine", "cancelled": True}
    assert _stub_subs_service["cancelled"] == [("sub-mine", "alice")]


@pytest.mark.asyncio
async def test_cancel_cross_tenant_returns_404(_stub_subs_service):
    """A hostile caller cancelling someone else's sub gets 404, not
    403 — same shape as "doesn't exist", so the response can't be
    used to enumerate other agents' subscription IDs."""
    request = FakeRequest(agent_id="alice")
    result = await chapter_agent.cancel_subscription_endpoint("sub-not-mine", request)
    assert _status(result) == 404
    assert "not found" in _read_body(result)["error"].lower()


@pytest.mark.asyncio
async def test_cancel_unauth_returns_401():
    request = FakeRequest()
    result = await chapter_agent.cancel_subscription_endpoint("sub-mine", request)
    assert _status(result) == 401
