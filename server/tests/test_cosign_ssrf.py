"""P1 — cosign-broker SSRF guard.

The broker's only "SSRF guard" was registered-members-only resolution, but a
member's A2A ``endpoint`` is self-asserted at registration (sanitize_text only
truncates). Since /api/members is TOFU-open, an attacker self-registers with
``endpoint: http://169.254.169.254/...`` (cloud metadata) or any internal host,
then drives the unauthenticated /api/cosign/broker to POST to it server-side.

The relay now validates the resolved endpoint and declines (fail-safe, §3)
without any outbound call when it resolves to a loopback / private / link-local
/ reserved address or a non-http(s) scheme.

Classification: ADVERSARIAL.
"""

from __future__ import annotations

import pytest

import cosign_broker

# ── _is_safe_relay_url ───────────────────────────────────────────────


def test_public_https_is_safe():
    # 93.184.216.34 = a routable public IP literal (no DNS lookup needed).
    assert cosign_broker._is_safe_relay_url("https://93.184.216.34/") is True


@pytest.mark.parametrize(
    "url",
    [
        "http://169.254.169.254/latest/meta-data/",  # cloud metadata (link-local)
        "http://127.0.0.1:8080/",  # loopback
        "http://[::1]/",  # loopback v6
        "http://10.0.0.5/",  # private
        "http://192.168.1.10/",  # private
        "http://172.16.5.5/",  # private
        "file:///etc/passwd",  # non-http scheme
        "gopher://127.0.0.1/",  # non-http scheme
        "http:///nohost",  # no host
    ],
)
def test_unsafe_targets_rejected(url):
    assert cosign_broker._is_safe_relay_url(url) is False


# ── relay_cosign honors the guard ────────────────────────────────────


@pytest.mark.asyncio
async def test_relay_declines_unsafe_endpoint_without_posting(monkeypatch):
    calls: list[str] = []

    async def fake_post(url, body, timeout):
        calls.append(url)
        return {"result": {"witness": {"witness_did": "x", "signature": "y"}}}

    monkeypatch.setattr(cosign_broker, "resolve_member_endpoint", lambda *a, **k: "http://169.254.169.254/")
    out = await cosign_broker.relay_cosign(
        {"action": {"counterparty_did": "did:key:zabc"}}, members={}, post=fake_post
    )
    assert out is None
    assert calls == [], "relayed to an internal target — SSRF"


@pytest.mark.asyncio
async def test_relay_allows_safe_public_endpoint(monkeypatch):
    calls: list[str] = []

    async def fake_post(url, body, timeout):
        calls.append(url)
        return {"result": {"witness": {"witness_did": "x", "signature": "y"}}}

    monkeypatch.setattr(cosign_broker, "resolve_member_endpoint", lambda *a, **k: "https://93.184.216.34/")
    out = await cosign_broker.relay_cosign(
        {"action": {"counterparty_did": "did:key:zabc"}}, members={}, post=fake_post
    )
    assert out == {"witness_did": "x", "signature": "y"}
    assert len(calls) == 1
