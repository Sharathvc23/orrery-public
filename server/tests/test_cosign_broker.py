"""Chapter-brokered co-sign relay — cosign-companion.md §4 (Option C).

Prosecution-grade coverage of ``cosign_broker`` + the ``POST /api/cosign/broker``
endpoint. The chapter brokers the co-sign handshake for a reduced-tier member: it
relays the issuer's unsigned receipt to the counterparty's A2A endpoint and
returns that counterparty's witness entry UNCHANGED. The load-bearing invariants:

  * the relayed entry actually CORROBORATES (byte-identical to inline, §4);
  * the chapter NEVER signs as the witness — it only carries bytes;
  * it fails SAFE to ``witness=None`` (decline) and never raises (§3);
  * an unresolvable counterparty declines WITHOUT any outbound call (SSRF guard).

Classification: HAPPY / EDGE / FAILURE / ADVERSARIAL.
"""

from __future__ import annotations

import base64
import hashlib
import importlib
import sys

import base58
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from sm_arp.vrp import cosign_receipt, is_corroborated

import cosign_broker

# ── helpers ────────────────────────────────────────────────────────────────


def _key(seed: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(seed.encode()).digest())


def _pubkey_b64(sk: Ed25519PrivateKey) -> str:
    raw = sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(raw).decode()


def _did(sk: Ed25519PrivateKey) -> str:
    raw = sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return "did:key:z" + base58.b58encode(b"\xed\x01" + raw).decode()


def _raw_seed(sk: Ed25519PrivateKey) -> bytes:
    return sk.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )


def _unsigned_receipt(issuer_sk: Ed25519PrivateKey, counterparty_sk: Ed25519PrivateKey, n: int = 1) -> dict:
    """An issuer's receipt BEFORE the witness entry and top-level signature — exactly
    what a reduced-tier issuer hands the broker to get co-signed."""
    return {
        "version": "arp/0.1",
        "receipt_id": f"{n:08d}-4444-4444-8444-444444444444",
        "issuer_did": _did(issuer_sk),
        "principal_did": _did(issuer_sk),
        "issued_at": f"2026-06-10T00:00:{n:02d}Z",
        "action": {
            "category": "purchase",
            "human_summary": f"brokered-{n}",
            "outcome": "completed",
            "counterparty_did": _did(counterparty_sk),
            "counterparty_label": "B",
        },
    }


def _members_with(counterparty_sk: Ed25519PrivateKey, *, endpoint: str = "https://93.184.216.34/a2a") -> dict:
    """A chapter member registry in which the counterparty B is a registered member
    with an Ed25519 key and an A2A endpoint."""
    return {
        "member-B": {
            "name": "B",
            "public_key": _pubkey_b64(counterparty_sk),
            "endpoint": endpoint,
            "origin": "sovereign",
        }
    }


def _cosigning_transport(counterparty_sk: Ed25519PrivateKey, *, calls: list | None = None):
    """A fake transport that simulates B co-signing over its A2A endpoint: it returns
    the JSON-RPC envelope B's ``nanda/cosignReceipt`` would, signed with B's real key."""

    async def post(url: str, body: dict, timeout: float):
        if calls is not None:
            calls.append((url, body))
        receipt = body["params"]["receipt"]
        entry = cosign_receipt(receipt, signing_key_bytes=_raw_seed(counterparty_sk))
        return {"jsonrpc": "2.0", "id": body.get("id"), "result": {"witness": entry}}

    return post


# ── HAPPY: the relayed entry corroborates, and it's B's signature ───────────


async def test_relay_returns_entry_that_corroborates() -> None:
    a, b = _key("issuer-A"), _key("counterparty-B")
    receipt = _unsigned_receipt(a, b)

    entry = await cosign_broker.relay_cosign(receipt, members=_members_with(b), post=_cosigning_transport(b))

    assert entry is not None
    # The issuer inserts the entry and the receipt is now corroborated — byte-for-byte
    # what an inline co-sign would have produced (§4 brokered-path equivalence).
    receipt["evidence"] = {"witness_signatures": [entry]}
    assert is_corroborated(receipt)


async def test_relay_witness_did_is_counterparty_never_chapter() -> None:
    a, b = _key("issuer-A"), _key("counterparty-B")
    entry = await cosign_broker.relay_cosign(
        _unsigned_receipt(a, b), members=_members_with(b), post=_cosigning_transport(b)
    )
    assert entry is not None
    assert entry["witness_did"] == _did(b)  # B's own did:key, not the chapter's


async def test_relay_posts_rpc_envelope_to_counterparty_endpoint() -> None:
    a, b = _key("issuer-A"), _key("counterparty-B")
    calls: list = []
    await cosign_broker.relay_cosign(
        _unsigned_receipt(a, b),
        members=_members_with(b, endpoint="https://93.184.216.34/a2a"),
        post=_cosigning_transport(b, calls=calls),
    )
    assert len(calls) == 1
    url, body = calls[0]
    assert url == "https://93.184.216.34/a2a/"  # endpoint root, single trailing slash
    assert body["method"] == "nanda/cosignReceipt"
    assert body["jsonrpc"] == "2.0"
    assert body["params"]["receipt"]["action"]["counterparty_did"] == _did(b)


# ── EDGE: decline without an outbound call (SSRF guard) ─────────────────────


async def test_unregistered_counterparty_declines_without_outbound_call() -> None:
    a, b = _key("issuer-A"), _key("counterparty-B")
    calls: list = []
    # B is NOT in the registry → must decline and never call out.
    entry = await cosign_broker.relay_cosign(
        _unsigned_receipt(a, b), members={}, post=_cosigning_transport(b, calls=calls)
    )
    assert entry is None
    assert calls == []  # no outbound request to an unknown URL


async def test_registered_member_without_endpoint_declines() -> None:
    a, b = _key("issuer-A"), _key("counterparty-B")
    calls: list = []
    entry = await cosign_broker.relay_cosign(
        _unsigned_receipt(a, b),
        members=_members_with(b, endpoint=""),
        post=_cosigning_transport(b, calls=calls),
    )
    assert entry is None
    assert calls == []


async def test_no_counterparty_did_declines() -> None:
    a = _key("issuer-A")
    receipt = _unsigned_receipt(a, _key("counterparty-B"))
    receipt["action"].pop("counterparty_did")
    calls: list = []
    entry = await cosign_broker.relay_cosign(receipt, members={}, post=_cosigning_transport(a, calls=calls))
    assert entry is None
    assert calls == []


# ── FAILURE: every non-corroborating reply is a safe decline, never a raise ─


async def test_transport_failure_declines() -> None:
    a, b = _key("issuer-A"), _key("counterparty-B")

    async def offline(url, body, timeout):
        return None  # _default_post returns None on any transport error

    entry = await cosign_broker.relay_cosign(_unsigned_receipt(a, b), members=_members_with(b), post=offline)
    assert entry is None


async def test_counterparty_declines_witness_null() -> None:
    a, b = _key("issuer-A"), _key("counterparty-B")

    async def declines(url, body, timeout):
        return {"jsonrpc": "2.0", "id": body.get("id"), "result": {"witness": None}}

    entry = await cosign_broker.relay_cosign(_unsigned_receipt(a, b), members=_members_with(b), post=declines)
    assert entry is None


async def test_rpc_error_envelope_declines() -> None:
    a, b = _key("issuer-A"), _key("counterparty-B")

    async def errors(url, body, timeout):
        return {"jsonrpc": "2.0", "id": body.get("id"), "error": {"code": -32601, "message": "nope"}}

    entry = await cosign_broker.relay_cosign(_unsigned_receipt(a, b), members=_members_with(b), post=errors)
    assert entry is None


# ── ADVERSARIAL: the chapter is a pure relay — it signs nothing, mints nothing ─


async def test_relay_passes_entry_through_unchanged() -> None:
    """The chapter returns EXACTLY what B sent — it does not substitute, re-derive,
    or re-sign. (A non-corroborating entry is the issuer's to reject, not the broker's.)"""
    a, b = _key("issuer-A"), _key("counterparty-B")
    forged = {"witness_did": "did:key:zSomeoneElse", "signature": "AAAA"}

    async def returns_forged(url, body, timeout):
        return {"jsonrpc": "2.0", "id": body.get("id"), "result": {"witness": forged}}

    entry = await cosign_broker.relay_cosign(_unsigned_receipt(a, b), members=_members_with(b), post=returns_forged)
    assert entry == forged  # relayed verbatim — the broker added no authority


async def test_relay_never_fabricates_on_silence() -> None:
    """When B says nothing usable, the chapter must NOT mint a witness of its own —
    a relay that fabricated corroboration would be exactly the trust drift VRP prevents."""
    a, b = _key("issuer-A"), _key("counterparty-B")

    async def garbage(url, body, timeout):
        return {"not": "an rpc response"}

    entry = await cosign_broker.relay_cosign(_unsigned_receipt(a, b), members=_members_with(b), post=garbage)
    assert entry is None


# ── resolve_member_endpoint unit ───────────────────────────────────────────


def test_resolve_matches_member_by_derived_did() -> None:
    b = _key("counterparty-B")
    assert cosign_broker.resolve_member_endpoint(_did(b), _members_with(b, endpoint="https://b/a2a")) == "https://b/a2a"


def test_resolve_skips_non_ed25519_keys() -> None:
    b = _key("counterparty-B")
    members = {"legacy": {"public_key": "hmac-shaped-not-44-chars", "endpoint": "https://x"}}
    assert cosign_broker.resolve_member_endpoint(_did(b), members) is None


def test_resolve_unknown_did_returns_none() -> None:
    b = _key("counterparty-B")
    assert cosign_broker.resolve_member_endpoint("did:key:zUnknown", _members_with(b)) is None


# ── endpoint (HTTP) tests ──────────────────────────────────────────────────


@pytest.fixture
def chapter_agent_module(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("AGENT_ID", "TEST-fixture-chapter")
    monkeypatch.setenv("AGENT_NAME", "Fixture")
    monkeypatch.setenv("XAI_API_KEY", "test-key")
    monkeypatch.delenv("CHAPTER_SLUG", raising=False)
    monkeypatch.delenv("CHAPTER_DISPLAY_NAME", raising=False)
    sys.modules.pop("chapter_agent", None)
    return importlib.import_module("chapter_agent")


@pytest.fixture
def client(chapter_agent_module) -> TestClient:
    return TestClient(chapter_agent_module.app)


def test_endpoint_relays_witness(chapter_agent_module, client, monkeypatch) -> None:
    a, b = _key("issuer-A"), _key("counterparty-B")
    chapter_agent_module.members.clear()
    chapter_agent_module.members.update(_members_with(b))
    monkeypatch.setattr(cosign_broker, "_default_post", _cosigning_transport(b))

    resp = client.post("/api/cosign/broker", json={"receipt": _unsigned_receipt(a, b)})
    assert resp.status_code == 200, resp.text
    entry = resp.json()["witness"]
    assert entry is not None and entry["witness_did"] == _did(b)


def test_endpoint_unknown_counterparty_returns_witness_null(chapter_agent_module, client) -> None:
    a, b = _key("issuer-A"), _key("counterparty-B")
    chapter_agent_module.members.clear()  # B not registered → decline, fail-safe
    resp = client.post("/api/cosign/broker", json={"receipt": _unsigned_receipt(a, b)})
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"witness": None}


def test_endpoint_missing_receipt_is_400(client) -> None:
    resp = client.post("/api/cosign/broker", json={"not_a_receipt": True})
    assert resp.status_code == 400


def test_endpoint_missing_counterparty_did_is_400(client) -> None:
    a = _key("issuer-A")
    receipt = _unsigned_receipt(a, _key("counterparty-B"))
    receipt["action"].pop("counterparty_did")
    resp = client.post("/api/cosign/broker", json={"receipt": receipt})
    assert resp.status_code == 400


def test_endpoint_invalid_json_is_400(client) -> None:
    resp = client.post("/api/cosign/broker", content=b"{not json", headers={"content-type": "application/json"})
    assert resp.status_code == 400


# ── F3: SSRF / DNS-rebinding — resolve once, pin the validated IP ────────────


def _fake_getaddrinfo(*ips):
    def _gai(host, port, *a, **k):
        return [(2, 1, 6, "", (ip, port)) for ip in ips]

    return _gai


def test_resolve_and_pin_rejects_private_target(monkeypatch):
    """A hostname resolving to a private/internal address fails closed."""
    monkeypatch.setattr(cosign_broker.socket, "getaddrinfo", _fake_getaddrinfo("10.0.0.5"))
    assert cosign_broker._resolve_and_pin("https://evil.example/") is None
    assert cosign_broker._is_safe_relay_url("https://evil.example/") is False


def test_resolve_and_pin_rejects_metadata_ip(monkeypatch):
    """Cloud metadata (169.254.169.254) is link-local → rejected."""
    monkeypatch.setattr(cosign_broker.socket, "getaddrinfo", _fake_getaddrinfo("169.254.169.254"))
    assert cosign_broker._resolve_and_pin("http://metadata.example/") is None


def test_resolve_and_pin_rejects_cgnat(monkeypatch):
    """Carrier-grade NAT (100.64.0.0/10) is internal routing space that
    ipaddress.is_private does NOT flag — reject it explicitly."""
    monkeypatch.setattr(cosign_broker.socket, "getaddrinfo", _fake_getaddrinfo("100.64.1.1"))
    assert cosign_broker._resolve_and_pin("https://cgnat.example/") is None
    assert cosign_broker._is_public_addr("100.64.1.1") is False
    assert cosign_broker._is_public_addr("100.128.0.1") is True  # just outside the /10


def test_resolve_and_pin_fails_closed_on_mixed_public_private(monkeypatch):
    """DNS-rebinding shape: a set with a public AND a private address must fail
    closed — an attacker can't smuggle an internal IP alongside a public one."""
    monkeypatch.setattr(cosign_broker.socket, "getaddrinfo", _fake_getaddrinfo("93.184.216.34", "127.0.0.1"))
    assert cosign_broker._resolve_and_pin("https://mix.example/") is None


def test_resolve_and_pin_returns_pinned_public_ip(monkeypatch):
    """A fully-public resolution returns the pinned IP the transport will
    connect to (no second resolution → no rebinding window)."""
    monkeypatch.setattr(cosign_broker.socket, "getaddrinfo", _fake_getaddrinfo("93.184.216.34"))
    result = cosign_broker._resolve_and_pin("https://good.example:8443/a2a/")
    assert result == ("https", "good.example", 8443, "93.184.216.34")


@pytest.mark.asyncio
async def test_default_post_declines_unsafe_target_without_connecting(monkeypatch):
    """The real transport declines (returns None) when the target is unsafe, and
    never opens a connection — proven by making a client construction blow up if
    it were ever reached."""
    monkeypatch.setattr(cosign_broker, "_resolve_and_pin", lambda url: None)

    def _boom(*a, **k):
        raise AssertionError("_default_post attempted an outbound connection to an unsafe target")

    import httpx

    monkeypatch.setattr(httpx, "AsyncClient", _boom)
    out = await cosign_broker._default_post("https://evil.example/", {"x": 1}, timeout=5.0)
    assert out is None


@pytest.mark.asyncio
async def test_default_post_connects_to_the_pinned_ip(monkeypatch):
    """The transport must actually route through the pinning backend: connect_tcp
    is called with the PINNED ip, not the hostname. Guards against an httpx
    internal rename silently reverting to the default re-resolving pool (a silent
    SSRF regression)."""
    import httpcore

    monkeypatch.setattr(cosign_broker, "_resolve_and_pin", lambda url: ("https", "good.example", 443, "93.184.216.34"))

    seen = {}
    real_connect = httpcore.AnyIOBackend.connect_tcp

    async def _spy(self, host, port, timeout=None, local_address=None, socket_options=None):
        seen["host"] = host
        raise httpcore.ConnectError("short-circuit after capturing the target")

    monkeypatch.setattr(httpcore.AnyIOBackend, "connect_tcp", _spy)
    try:
        out = await cosign_broker._default_post("https://good.example/", {"x": 1}, timeout=5.0)
    finally:
        monkeypatch.setattr(httpcore.AnyIOBackend, "connect_tcp", real_connect)
    assert out is None  # the connect was short-circuited → decline
    assert seen.get("host") == "93.184.216.34", "transport did not connect to the pinned IP (pinning not wired)"
