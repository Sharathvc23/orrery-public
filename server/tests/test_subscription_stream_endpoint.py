"""SSE endpoint integration tests (EB-4).

Covers the stream endpoint's contract:

  * 401 with no caller
  * 404 when subscription doesn't exist OR caller doesn't own it
    (same shape — no oracle leak)
  * Last-Event-ID parsing (junk → 0; valid → used as floor)
  * Replay phase emits the right SSE frames for the matched rows
  * Headers (Cache-Control, X-Accel-Buffering, Content-Type) set
    correctly so proxies + nginx don't buffer the stream

Long-poll loop testing is out of scope here — it's an infinite loop
gated on request.is_disconnected(). We exercise it indirectly by
forcing is_disconnected() to True on first poll.
"""

from __future__ import annotations

import os

os.environ.setdefault("AGENT_ID", "test-chapter")
os.environ.setdefault("AGENT_NAME", "Test Chapter")

import json  # noqa: E402

import pytest  # noqa: E402

import chapter_agent  # noqa: E402
import event_bus  # noqa: E402
import subscriptions as subscriptions_svc  # noqa: E402
import trust_gate  # noqa: E402


class FakeState:
    def __init__(self, agent_id: str = "") -> None:
        self.agent_id = agent_id


class FakeRequest:
    """Request stand-in with controllable is_disconnected behaviour."""

    def __init__(
        self,
        agent_id: str = "",
        headers: dict | None = None,
        disconnect_after_n: int = 0,
    ) -> None:
        self.state = FakeState(agent_id)
        self.headers = headers or {}
        self._disconnect_after_n = disconnect_after_n
        self._is_disconnected_calls = 0

    async def is_disconnected(self) -> bool:
        self._is_disconnected_calls += 1
        return self._is_disconnected_calls > self._disconnect_after_n


def _parse_status(resp) -> int:
    return getattr(resp, "status_code", 200)


def _body_dict(resp) -> dict:
    body = resp.body
    if isinstance(body, bytes):
        body = body.decode()
    return json.loads(body)


# ── Auth + ownership gating ──────────────────────────────────────────


@pytest.mark.asyncio
async def test_stream_returns_401_with_no_caller():
    req = FakeRequest()
    resp = await chapter_agent.stream_subscription_endpoint("sub-1", req)
    assert _parse_status(resp) == 401


@pytest.mark.asyncio
async def test_stream_returns_404_when_sub_missing(monkeypatch):
    async def _none(**kwargs):
        return None

    monkeypatch.setattr(subscriptions_svc, "get_subscription_for_owner", _none)

    req = FakeRequest(agent_id="alice")
    resp = await chapter_agent.stream_subscription_endpoint("sub-1", req)
    assert _parse_status(resp) == 404
    assert "not found" in _body_dict(resp)["error"].lower()


@pytest.mark.asyncio
async def test_stream_returns_404_when_cross_tenant(monkeypatch):
    """Same shape as missing — no oracle to enumerate other agents'
    subscription IDs."""
    captured: list = []

    async def _none(*, subscription_id, subscriber_agent_id):
        captured.append((subscription_id, subscriber_agent_id))
        return None  # cross-tenant fetch returns None

    monkeypatch.setattr(subscriptions_svc, "get_subscription_for_owner", _none)

    req = FakeRequest(agent_id="alice")
    resp = await chapter_agent.stream_subscription_endpoint("sub-bobs", req)
    assert _parse_status(resp) == 404
    # Confirm the service was called with the CALLER's identity, not
    # anything from the URL — same as for cancel.
    assert captured == [("sub-bobs", "alice")]


# ── Last-Event-ID parsing ────────────────────────────────────────────


def test_parse_last_event_id_handles_junk():
    assert chapter_agent._parse_last_event_id("garbage") == 0
    assert chapter_agent._parse_last_event_id("") == 0
    assert chapter_agent._parse_last_event_id("-5") == 0  # clamped to 0
    assert chapter_agent._parse_last_event_id("42") == 42


# ── Replay phase ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_stream_replays_events_since_last_event_id(monkeypatch):
    """If Last-Event-ID is set, the stream replays matching rows before
    going into long-poll."""
    sub = {
        "id": "sub-1",
        "subscriber_agent_id": "alice",
        "topics": ["member.joined"],
        "active": True,
    }
    replay_rows = [
        {"id": 11, "event_type": "member.joined", "payload": {"agent_id": "bob"}},
        {"id": 12, "event_type": "member.joined", "payload": {"agent_id": "carol"}},
    ]
    events_since_args: list = []

    async def _get_sub(**kwargs):
        return sub

    async def _events_since(last_id, topics, **kw):
        events_since_args.append((last_id, list(topics)))
        # First call = replay; second = first long-poll tick = empty
        return replay_rows if len(events_since_args) == 1 else []

    monkeypatch.setattr(subscriptions_svc, "get_subscription_for_owner", _get_sub)
    monkeypatch.setattr(event_bus, "events_since", _events_since)
    monkeypatch.setattr(chapter_agent, "_SSE_POLL_INTERVAL_S", 0.0)

    req = FakeRequest(
        agent_id="alice",
        headers={"Last-Event-ID": "10"},
        disconnect_after_n=1,
    )
    resp = await chapter_agent.stream_subscription_endpoint("sub-1", req)

    # Collect what the generator emits.
    frames: list[str] = []
    async for chunk in resp.body_iterator:
        frames.append(chunk if isinstance(chunk, str) else chunk.decode())

    # First call to events_since was the replay — last_id=10, the parsed header.
    assert events_since_args[0] == (10, ["member.joined"])
    # Both replay rows landed as SSE frames.
    combined = "".join(frames)
    assert "id: 11" in combined and "id: 12" in combined
    assert "event: member.joined" in combined
    assert '"agent_id":"bob"' in combined
    assert '"agent_id":"carol"' in combined
    # A keepalive comment also went out.
    assert ": keepalive" in combined


@pytest.mark.asyncio
async def test_stream_no_replay_when_no_last_event_id_header(monkeypatch):
    """No Last-Event-ID → first events_since call is from id=0."""
    sub = {"id": "s", "subscriber_agent_id": "alice", "topics": ["member.joined"]}
    captured: list = []

    async def _get_sub(**kwargs):
        return sub

    async def _events_since(last_id, topics, **kw):
        captured.append(last_id)
        return []

    monkeypatch.setattr(subscriptions_svc, "get_subscription_for_owner", _get_sub)
    monkeypatch.setattr(event_bus, "events_since", _events_since)
    monkeypatch.setattr(chapter_agent, "_SSE_POLL_INTERVAL_S", 0.0)

    req = FakeRequest(agent_id="alice", disconnect_after_n=0)
    resp = await chapter_agent.stream_subscription_endpoint("s", req)

    # Drain the generator (will exit immediately because disconnect_after_n=0)
    async for _ in resp.body_iterator:
        pass

    assert captured[0] == 0


# ── Response headers ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_stream_sets_sse_headers(monkeypatch):
    sub = {"id": "s", "subscriber_agent_id": "alice", "topics": ["member.joined"]}

    async def _get_sub(**kwargs):
        return sub

    async def _events_since(*args, **kwargs):
        return []

    monkeypatch.setattr(subscriptions_svc, "get_subscription_for_owner", _get_sub)
    monkeypatch.setattr(event_bus, "events_since", _events_since)

    req = FakeRequest(agent_id="alice", disconnect_after_n=0)
    resp = await chapter_agent.stream_subscription_endpoint("s", req)

    assert resp.media_type == "text/event-stream"
    assert resp.headers["cache-control"] == "no-cache, no-transform"
    assert resp.headers["x-accel-buffering"] == "no"


# ── Resilience: Postgres blip mid-stream doesn't crash ───────────────


# ── EB-5: trust-tier gating at delivery ──────────────────────────────


@pytest.mark.asyncio
async def test_stream_filters_events_above_subscriber_tier(monkeypatch):
    """An EB-3-subscribed alice with trust=0 must NOT receive
    intent.matched (tier 25) even though she subscribed to the
    topic. The event is recorded in event_log (publisher integrity)
    but never reaches her stream (subscriber security)."""
    sub = {
        "id": "sub-1",
        "subscriber_agent_id": "alice",
        "topics": ["member.joined", "intent.matched"],
    }

    async def _get_sub(**kwargs):
        return sub

    rows = [
        {"id": 1, "event_type": "member.joined", "payload": {"agent_id": "bob"}},
        {"id": 2, "event_type": "intent.matched", "payload": {"intent_id": "x"}},
    ]

    async def _events_since(last_id, topics, **kw):
        # First call (replay) returns both; second (poll) returns empty.
        return rows if last_id == 0 else []

    async def _zero_trust(agent_id, **kwargs):
        return 0.0  # alice is brand-new — only sees tier-0 events

    monkeypatch.setattr(subscriptions_svc, "get_subscription_for_owner", _get_sub)
    monkeypatch.setattr(event_bus, "events_since", _events_since)
    monkeypatch.setattr(trust_gate, "get_subscriber_trust_score", _zero_trust)
    monkeypatch.setattr(chapter_agent, "_SSE_POLL_INTERVAL_S", 0.0)

    req = FakeRequest(agent_id="alice", disconnect_after_n=1)
    resp = await chapter_agent.stream_subscription_endpoint("sub-1", req)

    frames = []
    async for chunk in resp.body_iterator:
        frames.append(chunk if isinstance(chunk, str) else chunk.decode())
    combined = "".join(frames)

    # member.joined (tier 0) — visible.
    assert "id: 1" in combined
    assert "event: member.joined" in combined
    # intent.matched (tier 25) — FILTERED OUT for trust=0 alice.
    assert "id: 2" not in combined
    assert "intent.matched" not in combined
    # Keepalive still went out — stream healthy.
    assert ": keepalive" in combined


@pytest.mark.asyncio
async def test_stream_allows_events_at_subscriber_tier(monkeypatch):
    """Verified member (trust=25) sees tier-0 + tier-25 events."""
    sub = {"id": "s", "subscriber_agent_id": "alice", "topics": ["member.joined", "intent.matched"]}
    rows = [
        {"id": 1, "event_type": "member.joined", "payload": {}},
        {"id": 2, "event_type": "intent.matched", "payload": {}},
    ]

    async def _get_sub(**kwargs):
        return sub

    async def _events_since(last_id, topics, **kw):
        return rows if last_id == 0 else []

    async def _verified(agent_id, **kwargs):
        return 25.0

    monkeypatch.setattr(subscriptions_svc, "get_subscription_for_owner", _get_sub)
    monkeypatch.setattr(event_bus, "events_since", _events_since)
    monkeypatch.setattr(trust_gate, "get_subscriber_trust_score", _verified)
    monkeypatch.setattr(chapter_agent, "_SSE_POLL_INTERVAL_S", 0.0)

    req = FakeRequest(agent_id="alice", disconnect_after_n=1)
    resp = await chapter_agent.stream_subscription_endpoint("s", req)

    frames = []
    async for chunk in resp.body_iterator:
        frames.append(chunk if isinstance(chunk, str) else chunk.decode())
    combined = "".join(frames)
    assert "id: 1" in combined
    assert "id: 2" in combined


@pytest.mark.asyncio
async def test_stream_survives_events_since_exception(monkeypatch):
    """A transient Postgres error during the long-poll must NOT crash
    the SSE connection — log + keepalive + retry next tick."""
    sub = {"id": "s", "subscriber_agent_id": "alice", "topics": ["member.joined"]}
    call_count = {"n": 0}

    async def _get_sub(**kwargs):
        return sub

    async def _events_since(*args, **kwargs):
        call_count["n"] += 1
        if call_count["n"] == 2:  # second call (first long-poll tick) blows up
            raise RuntimeError("supabase blip")
        return []

    monkeypatch.setattr(subscriptions_svc, "get_subscription_for_owner", _get_sub)
    monkeypatch.setattr(event_bus, "events_since", _events_since)
    monkeypatch.setattr(chapter_agent, "_SSE_POLL_INTERVAL_S", 0.0)

    req = FakeRequest(agent_id="alice", disconnect_after_n=1)
    resp = await chapter_agent.stream_subscription_endpoint("s", req)

    frames: list[str] = []
    async for chunk in resp.body_iterator:
        frames.append(chunk if isinstance(chunk, str) else chunk.decode())

    # Stream did NOT raise — generator yielded a keepalive after the blip.
    combined = "".join(frames)
    assert ": keepalive" in combined
