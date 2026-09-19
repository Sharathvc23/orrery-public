"""the per-IP rate limiter must key on the REAL client IP behind a proxy.

Keying on request.client.host puts every user behind an edge/reverse proxy into ONE
bucket (the proxy's IP): a single attacker 429s everyone and abusers aren't isolated.
The limiter now reads the real client from X-Forwarded-For per TRUSTED_PROXY_HOPS, and
uvicorn is launched with proxy_headers so request.client resolves the real peer.

Classification: HAPPY / EDGE / ADVERSARIAL.
"""

from __future__ import annotations

import os

os.environ.setdefault("AGENT_ID", "test-ratelimit-chapter")
os.environ.setdefault("AGENT_NAME", "Test RateLimit Chapter")

from fastapi.testclient import TestClient

import chapter_agent


class _Req:
    """Minimal Request stand-in for the resolver: .client.host + .headers.get."""

    def __init__(self, peer: str | None, xff: str | None = None):
        self.client = type("C", (), {"host": peer})() if peer else None
        self.headers = {"x-forwarded-for": xff} if xff is not None else {}


# ── resolver unit tests ─────────────────────────────────────────────────────────


def test_direct_connect_uses_socket_peer_and_ignores_xff(monkeypatch):
    """Default (0 trusted hops): trust nothing forwarded — key on the socket peer."""
    monkeypatch.setattr(chapter_agent, "TRUSTED_PROXY_HOPS", 0)
    assert chapter_agent.client_ip_for_rate_limit(_Req("1.2.3.4", xff="9.9.9.9")) == "1.2.3.4"


def test_one_trusted_hop_reads_real_client_from_xff(monkeypatch):
    """Behind one edge proxy: the real client is the XFF entry the proxy appended,
    NOT the proxy's socket IP."""
    monkeypatch.setattr(chapter_agent, "TRUSTED_PROXY_HOPS", 1)
    req = _Req("10.0.0.1", xff="203.0.113.5")  # peer=proxy, xff=real client
    assert chapter_agent.client_ip_for_rate_limit(req) == "203.0.113.5"


def test_distinct_xff_clients_resolve_to_distinct_keys(monkeypatch):
    """Two users behind the same proxy get DIFFERENT keys (the point of that change)."""
    monkeypatch.setattr(chapter_agent, "TRUSTED_PROXY_HOPS", 1)
    a = chapter_agent.client_ip_for_rate_limit(_Req("10.0.0.1", xff="203.0.113.5"))
    b = chapter_agent.client_ip_for_rate_limit(_Req("10.0.0.1", xff="203.0.113.6"))
    assert a != b and "10.0.0.1" not in (a, b)


def test_spoofed_left_prepended_xff_is_ignored(monkeypatch):
    """ADVERSARIAL: a client that prepends a fake XFF entry cannot choose its bucket —
    only the rightmost (trusted-proxy-written) hop is consulted."""
    monkeypatch.setattr(chapter_agent, "TRUSTED_PROXY_HOPS", 1)
    # client sent "1.1.1.1"; the trusted edge appended the real "203.0.113.5"
    req = _Req("10.0.0.1", xff="1.1.1.1, 203.0.113.5")
    assert chapter_agent.client_ip_for_rate_limit(req) == "203.0.113.5"


def test_short_chain_falls_back_to_peer(monkeypatch):
    """If XFF is shorter than the configured hops (misconfig / direct hit), fall back
    to the socket peer rather than trusting a spoofable value."""
    monkeypatch.setattr(chapter_agent, "TRUSTED_PROXY_HOPS", 2)
    assert chapter_agent.client_ip_for_rate_limit(_Req("10.0.0.1", xff="203.0.113.5")) == "10.0.0.1"


# ── integration: independent 429 buckets per XFF client ─────────────────────────


def test_one_attacker_does_not_429_everyone(monkeypatch):
    """End-to-end: exhaust the write limit from one XFF client → it 429s; a different
    XFF client (same proxy peer) is unaffected. The proxy IP is never the bucket key."""
    monkeypatch.setattr(chapter_agent, "TRUSTED_PROXY_HOPS", 1)
    chapter_agent._rate_limit_store.clear()
    client = TestClient(chapter_agent.app)

    attacker = {"X-Forwarded-For": "203.0.113.99"}
    victim = {"X-Forwarded-For": "198.51.100.7"}

    saw_429 = False
    for _ in range(chapter_agent.RATE_LIMIT_MAX + 5):
        r = client.post("/api/intents", headers=attacker, json={})
        if r.status_code == 429:
            saw_429 = True
            break
    assert saw_429, "the attacker's own bucket never rate-limited"

    # A different client behind the SAME proxy is not collateral-damaged.
    r = client.post("/api/intents", headers=victim, json={})
    assert r.status_code != 429, "a distinct client shared the attacker's bucket (proxy-IP keying)"

    chapter_agent._rate_limit_store.clear()
