"""Tests for A2AClient subscription + stream methods (v0.7.0).

Mirrors the chapter's EB-3 + EB-4 endpoints from the client side:
  - create_subscription / list_subscriptions / cancel_subscription
  - stream_events SSE generator (frame parsing, keepalive skipping,
    Last-Event-ID resume header)

The HTTP transport is mocked via httpx.MockTransport so tests don't
need a live chapter. Signing is exercised via a stub auth helper that
records the headers added.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from community_member.a2a_client import A2AClient, MissingCredentialsError


def _client(transport: httpx.MockTransport, *, with_creds: bool = True) -> A2AClient:
    """Build an A2AClient whose httpx calls go through the mock transport.

    Patches the module-level httpx symbol so _post / _get / _delete /
    httpx.stream all hit the mock.
    """
    c = A2AClient(
        chapter_url="https://chapter.test",
        agent_id="alice" if with_creds else "",
        private_key="not-a-real-key" if with_creds else "",
    )
    return c


def _auth_stub(monkeypatch):
    """Replace _auth_headers with a deterministic stub so we don't need
    a real Ed25519 keypair. Records the body argument for assertions."""
    captured: dict[str, Any] = {"bodies": [], "calls": []}

    def _hdrs(self, body: str = "", method: str = "", url_path: str = "") -> dict:
        captured["bodies"].append(body)
        captured["calls"].append((method, url_path))
        # Reflect the real client: a mutating call binds method+path (v0.3).
        scheme = "ed25519+nonce" if method in ("POST", "PUT", "PATCH", "DELETE") else "ed25519"
        return {
            "X-Agent-ID": self.agent_id or "",
            "X-Agent-Signature": "stub-sig",
            "X-Agent-Timestamp": "0",
            "X-Agent-Sig-Scheme": scheme,
        }

    monkeypatch.setattr(A2AClient, "_auth_headers", _hdrs)
    return captured


# ── create_subscription ─────────────────────────────────────────────


def test_create_subscription_posts_with_topics(monkeypatch):
    _auth_stub(monkeypatch)
    requests: list[httpx.Request] = []

    def handler(req: httpx.Request) -> httpx.Response:
        requests.append(req)
        return httpx.Response(
            200,
            json={
                "subscription": {
                    "id": "sub-abc",
                    "topics": json.loads(req.content)["topics"],
                    "active": True,
                }
            },
        )

    transport = httpx.MockTransport(handler)
    monkeypatch.setattr(httpx, "post", lambda *a, **kw: httpx.Client(transport=transport).post(*a, **kw))

    client = _client(transport)
    out = client.create_subscription(["member.joined", "intent.published"])

    assert out["subscription"]["id"] == "sub-abc"
    assert out["subscription"]["topics"] == ["member.joined", "intent.published"]
    assert len(requests) == 1
    assert requests[0].url.path == "/api/subscriptions"
    assert requests[0].method == "POST"
    body = json.loads(requests[0].content)
    assert body == {"topics": ["member.joined", "intent.published"]}
    # Auth headers attached
    assert requests[0].headers.get("X-Agent-ID") == "alice"


def test_create_subscription_passes_filters_and_webhook(monkeypatch):
    _auth_stub(monkeypatch)
    requests: list[httpx.Request] = []

    def handler(req: httpx.Request) -> httpx.Response:
        requests.append(req)
        return httpx.Response(200, json={"subscription": {"id": "s"}})

    transport = httpx.MockTransport(handler)
    monkeypatch.setattr(httpx, "post", lambda *a, **kw: httpx.Client(transport=transport).post(*a, **kw))

    client = _client(transport)
    client.create_subscription(
        ["intent.matched"],
        filters={"min_trust": 25},
        delivery="webhook",
        webhook_url="https://hooks.example/x",
    )

    body = json.loads(requests[0].content)
    assert body["filters"] == {"min_trust": 25}
    assert body["delivery"] == "webhook"
    assert body["webhook_url"] == "https://hooks.example/x"


def test_create_subscription_omits_default_delivery(monkeypatch):
    """Don't bloat the request body with delivery=stream when it's the default."""
    _auth_stub(monkeypatch)
    captured_bodies: list[dict] = []

    def handler(req: httpx.Request) -> httpx.Response:
        captured_bodies.append(json.loads(req.content))
        return httpx.Response(200, json={"subscription": {"id": "s"}})

    transport = httpx.MockTransport(handler)
    monkeypatch.setattr(httpx, "post", lambda *a, **kw: httpx.Client(transport=transport).post(*a, **kw))

    client = _client(transport)
    client.create_subscription(["member.joined"])

    assert "delivery" not in captured_bodies[0]
    assert "webhook_url" not in captured_bodies[0]
    assert "filters" not in captured_bodies[0]


# ── list / cancel ────────────────────────────────────────────────────


def test_list_subscriptions_get(monkeypatch):
    _auth_stub(monkeypatch)
    requests: list[httpx.Request] = []

    def handler(req: httpx.Request) -> httpx.Response:
        requests.append(req)
        return httpx.Response(200, json={"subscriptions": [{"id": "s-1"}], "total": 1})

    transport = httpx.MockTransport(handler)
    monkeypatch.setattr(httpx, "get", lambda *a, **kw: httpx.Client(transport=transport).get(*a, **kw))

    client = _client(transport)
    out = client.list_subscriptions()

    assert out == {"subscriptions": [{"id": "s-1"}], "total": 1}
    assert requests[0].method == "GET"
    assert requests[0].url.path == "/api/subscriptions"


def test_cancel_subscription_delete(monkeypatch):
    _auth_stub(monkeypatch)
    requests: list[httpx.Request] = []

    def handler(req: httpx.Request) -> httpx.Response:
        requests.append(req)
        return httpx.Response(200, json={"subscription_id": "s-1", "cancelled": True})

    transport = httpx.MockTransport(handler)
    monkeypatch.setattr(httpx, "delete", lambda *a, **kw: httpx.Client(transport=transport).delete(*a, **kw))

    client = _client(transport)
    out = client.cancel_subscription("s-1")

    assert out["cancelled"] is True
    assert requests[0].method == "DELETE"
    assert requests[0].url.path == "/api/subscriptions/s-1"


# ── stream_events SSE parsing ────────────────────────────────────────


SSE_BODY = (
    "id: 1\n"
    "event: member.joined\n"
    'data: {"agent_id":"alice","origin":"sovereign"}\n'
    "\n"
    ": keepalive\n"
    "\n"
    "id: 2\n"
    "event: intent.published\n"
    'data: {"intent_id":"int-1","text":"hi"}\n'
    "\n"
    ": keepalive\n"
    "\n"
)


def test_stream_events_parses_sse_frames(monkeypatch):
    _auth_stub(monkeypatch)
    captured_request: dict[str, Any] = {}

    def handler(req: httpx.Request) -> httpx.Response:
        captured_request["req"] = req
        return httpx.Response(200, content=SSE_BODY.encode(), headers={"Content-Type": "text/event-stream"})

    transport = httpx.MockTransport(handler)
    monkeypatch.setattr(httpx, "stream", lambda *a, **kw: httpx.Client(transport=transport).stream(*a, **kw))

    client = _client(transport)
    events = list(client.stream_events("sub-1"))

    assert len(events) == 2
    assert events[0] == {
        "id": 1,
        "event": "member.joined",
        "data": {"agent_id": "alice", "origin": "sovereign"},
    }
    assert events[1] == {
        "id": 2,
        "event": "intent.published",
        "data": {"intent_id": "int-1", "text": "hi"},
    }
    # Auth header attached
    assert captured_request["req"].headers.get("X-Agent-ID") == "alice"


def test_stream_events_skips_keepalive_comments(monkeypatch):
    """Keepalive lines (": keepalive") must not surface as events."""
    _auth_stub(monkeypatch)
    body = ": keepalive\n\n: keepalive\n\nid: 5\nevent: x\ndata: {}\n\n"

    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=body.encode())

    transport = httpx.MockTransport(handler)
    monkeypatch.setattr(httpx, "stream", lambda *a, **kw: httpx.Client(transport=transport).stream(*a, **kw))

    client = _client(transport)
    events = list(client.stream_events("sub-1"))

    assert events == [{"id": 5, "event": "x", "data": {}}]


def test_stream_events_sends_last_event_id_header(monkeypatch):
    """Resume — when last_event_id is set, the request carries
    Last-Event-ID so the chapter replays from that id forward."""
    _auth_stub(monkeypatch)
    captured: dict[str, Any] = {}

    def handler(req: httpx.Request) -> httpx.Response:
        captured["last_event_id"] = req.headers.get("Last-Event-ID")
        return httpx.Response(200, content=b"")

    transport = httpx.MockTransport(handler)
    monkeypatch.setattr(httpx, "stream", lambda *a, **kw: httpx.Client(transport=transport).stream(*a, **kw))

    client = _client(transport)
    list(client.stream_events("sub-1", last_event_id=42))
    assert captured["last_event_id"] == "42"


def test_stream_events_omits_last_event_id_when_zero(monkeypatch):
    """Default last_event_id=0 → no header (start from "now")."""
    _auth_stub(monkeypatch)
    captured: dict[str, Any] = {}

    def handler(req: httpx.Request) -> httpx.Response:
        captured["last_event_id"] = req.headers.get("Last-Event-ID")
        return httpx.Response(200, content=b"")

    transport = httpx.MockTransport(handler)
    monkeypatch.setattr(httpx, "stream", lambda *a, **kw: httpx.Client(transport=transport).stream(*a, **kw))

    client = _client(transport)
    list(client.stream_events("sub-1"))
    assert captured["last_event_id"] is None


# ── Auth gating ──────────────────────────────────────────────────────


def test_create_subscription_raises_without_credentials():
    """Stream endpoint requires auth — no creds = MissingCredentialsError
    rather than silently sending unsigned (which would 401 from chapter)."""
    client = A2AClient(chapter_url="https://chapter.test")  # no agent_id, no key
    with pytest.raises(MissingCredentialsError):
        client.create_subscription(["member.joined"])


def test_stream_events_raises_without_credentials():
    client = A2AClient(chapter_url="https://chapter.test")
    with pytest.raises(MissingCredentialsError):
        # Trigger the generator — _auth_headers runs before the HTTP call
        next(client.stream_events("sub-1"))
