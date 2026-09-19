"""P1 — server-to-server signing for federation broadcasts (model B).

Sign a broadcast with the chapter's Ed25519 key; verify it against the peer's
published did.json public key (discovered from the allowlist endpoint). Cutover
is warn-then-enforce gated by FEDERATION_ENFORCE_SIGNED_BROADCASTS (default OFF).

Classification: HAPPY / ADVERSARIAL.
"""

from __future__ import annotations

import base64
import os

os.environ.setdefault("AGENT_ID", "test-chapter")
os.environ.setdefault("AGENT_NAME", "Test Chapter")

import pytest  # noqa: E402

import federation_signing as fs  # noqa: E402
import sovereign_identity  # noqa: E402


@pytest.fixture
def chapter_pubkey_b64() -> str:
    sovereign_identity.generate_ed25519_keypair("test-chapter")
    kp = sovereign_identity._ed25519_keypairs["test-chapter"]
    return base64.b64encode(kp["public_key"]).decode()


def _did_json(pubkey_b64: str) -> dict:
    return {
        "verificationMethod": [
            {"type": "Ed25519VerificationKey2020", "publicKeyBase64": pubkey_b64}
        ]
    }


@pytest.mark.asyncio
async def test_sign_verify_roundtrip(chapter_pubkey_b64):
    body = {"broadcast_id": "b1", "title": "hi", "origin_chapter_id": "test-chapter", "tags": ["x", "y"]}
    headers = fs.sign_outbound("test-chapter", body)
    assert fs.CHAPTER_SIG_HEADER in headers and fs.CHAPTER_DID_HEADER in headers

    async def fake_get(url):
        assert url.endswith("/.well-known/did.json")
        return _did_json(chapter_pubkey_b64)

    valid, reason = await fs.verify_inbound(body, headers, "https://peer.example/agent", http_get=fake_get)
    assert valid is True and reason == "ok"


@pytest.mark.asyncio
async def test_missing_signature_rejected():
    valid, reason = await fs.verify_inbound({"x": 1}, {}, "https://peer.example", http_get=None)
    assert valid is False and reason == "missing_signature"


@pytest.mark.asyncio
async def test_tampered_body_invalid(chapter_pubkey_b64):
    body = {"broadcast_id": "b1", "title": "hi"}
    headers = fs.sign_outbound("test-chapter", body)
    tampered = {"broadcast_id": "b1", "title": "EVIL — forged broadcast"}

    async def fake_get(url):
        return _did_json(chapter_pubkey_b64)

    valid, reason = await fs.verify_inbound(tampered, headers, "https://peer.example", http_get=fake_get)
    assert valid is False and reason == "invalid_signature"


@pytest.mark.asyncio
async def test_wrong_key_invalid(chapter_pubkey_b64):
    """A peer that publishes a DIFFERENT key than the one that signed → invalid."""
    body = {"broadcast_id": "b1", "title": "hi"}
    headers = fs.sign_outbound("test-chapter", body)
    other = base64.b64encode(sovereign_identity._ed25519_keypairs[
        "other-chapter" if sovereign_identity.generate_ed25519_keypair("other-chapter") else "other-chapter"
    ]["public_key"]).decode()

    async def fake_get(url):
        return _did_json(other)

    valid, reason = await fs.verify_inbound(body, headers, "https://peer.example", http_get=fake_get)
    assert valid is False and reason == "invalid_signature"


@pytest.mark.asyncio
async def test_peer_key_unavailable(chapter_pubkey_b64):
    body = {"x": 1}
    headers = fs.sign_outbound("test-chapter", body)

    async def fake_get(url):
        return None  # did.json unreachable / malformed

    valid, reason = await fs.verify_inbound(body, headers, "https://peer.example", http_get=fake_get)
    assert valid is False and reason == "peer_key_unavailable"


# ── That change: replay protection (signed timestamp + freshness window) ──────────


@pytest.mark.asyncio
async def test_fresh_signed_broadcast_accepted(chapter_pubkey_b64):
    """A broadcast verified within the freshness window is accepted."""
    body = {"broadcast_id": "b1", "title": "hi"}
    headers = fs.sign_outbound("test-chapter", body, now=1000, nonce="n1")

    async def fake_get(url):
        return _did_json(chapter_pubkey_b64)

    valid, reason = await fs.verify_inbound(
        body, headers, "https://peer.example", http_get=fake_get, now=1010, max_age_s=300
    )
    assert valid is True and reason == "ok"


@pytest.mark.asyncio
async def test_replay_after_restart_rejected_by_freshness(chapter_pubkey_b64):
    """A captured, validly-signed broadcast replayed after the freshness window
    (e.g. after a process restart cleared the in-memory dedup ring) is rejected
    because its SIGNED timestamp is now stale."""
    body = {"broadcast_id": "b1", "title": "hi"}
    headers = fs.sign_outbound("test-chapter", body, now=1000, nonce="n1")

    async def fake_get(url):
        return _did_json(chapter_pubkey_b64)

    # Replayed 301s later, window is 300s → stale. The dedup ring being empty
    # (simulated restart) doesn't matter: the check is stateless.
    valid, reason = await fs.verify_inbound(
        body, headers, "https://peer.example", http_get=fake_get, now=1301, max_age_s=300
    )
    assert valid is False and reason == "stale_timestamp"


@pytest.mark.asyncio
async def test_attacker_cannot_refresh_timestamp(chapter_pubkey_b64):
    """The timestamp is part of the SIGNED material, so an attacker can't make a
    stale captured broadcast fresh by editing the X-Chapter-Timestamp header —
    the signature no longer matches."""
    body = {"broadcast_id": "b1", "title": "hi"}
    headers = fs.sign_outbound("test-chapter", body, now=1000, nonce="n1")
    # Forge a fresh-looking timestamp without re-signing.
    forged = dict(headers)
    forged[fs.CHAPTER_TS_HEADER] = "1300"

    async def fake_get(url):
        return _did_json(chapter_pubkey_b64)

    valid, reason = await fs.verify_inbound(
        body, forged, "https://peer.example", http_get=fake_get, now=1305, max_age_s=300
    )
    assert valid is False and reason == "invalid_signature"


@pytest.mark.asyncio
async def test_nonint_timestamp_rejected(chapter_pubkey_b64):
    body = {"broadcast_id": "b1", "title": "hi"}
    headers = fs.sign_outbound("test-chapter", body, now=1000, nonce="n1")
    headers[fs.CHAPTER_TS_HEADER] = "not-a-number"

    async def fake_get(url):
        return _did_json(chapter_pubkey_b64)

    valid, reason = await fs.verify_inbound(
        body, headers, "https://peer.example", http_get=fake_get, now=1000, max_age_s=300
    )
    assert valid is False and reason == "invalid_timestamp"


@pytest.mark.asyncio
async def test_legacy_body_only_signature_still_verifies(chapter_pubkey_b64):
    """Backward compat (warn-then-enforce): a older peer signs the body only,
    with no timestamp/nonce headers. It must still verify (as 'ok_legacy') so an
    un-upgraded honest peer isn't punished with a scary 'invalid_signature' log;
    it simply lacks replay protection until it upgrades."""
    body = {"broadcast_id": "b1", "title": "hi"}
    sk_b64 = base64.b64encode(sovereign_identity._ed25519_keypairs["test-chapter"]["private_key"]).decode()
    legacy_sig = sovereign_identity.ed25519_sign(fs._canonical(body), sk_b64)
    legacy_headers = {fs.CHAPTER_SIG_HEADER: legacy_sig}

    async def fake_get(url):
        return _did_json(chapter_pubkey_b64)

    valid, reason = await fs.verify_inbound(body, legacy_headers, "https://peer.example", http_get=fake_get)
    assert valid is True and reason == "ok_legacy"


@pytest.mark.asyncio
async def test_legacy_rejected_under_enforcement(chapter_pubkey_b64):
    """That change re-fix: a legacy body-only signature has NO replay protection (no
    timestamp), so under enforcement it MUST be rejected — otherwise captured
    legacy bytes replay forever across restarts with no key needed."""
    body = {"broadcast_id": "b1", "title": "hi"}
    sk_b64 = base64.b64encode(sovereign_identity._ed25519_keypairs["test-chapter"]["private_key"]).decode()
    legacy_sig = sovereign_identity.ed25519_sign(fs._canonical(body), sk_b64)
    legacy_headers = {fs.CHAPTER_SIG_HEADER: legacy_sig}

    async def fake_get(url):
        return _did_json(chapter_pubkey_b64)

    valid, reason = await fs.verify_inbound(
        body, legacy_headers, "https://peer.example", http_get=fake_get, require_replay_protection=True
    )
    assert valid is False and reason == "missing_timestamp"


@pytest.mark.asyncio
async def test_stale_still_rejected_under_enforcement(chapter_pubkey_b64):
    """A timestamped-but-stale broadcast is rejected regardless of the
    require_replay_protection flag (freshness always applies when ts present)."""
    body = {"broadcast_id": "b1", "title": "hi"}
    headers = fs.sign_outbound("test-chapter", body, now=1000, nonce="n1")

    async def fake_get(url):
        return _did_json(chapter_pubkey_b64)

    valid, reason = await fs.verify_inbound(
        body, headers, "https://peer.example", http_get=fake_get, now=1301, max_age_s=300, require_replay_protection=True
    )
    assert valid is False and reason == "stale_timestamp"


def test_enforcement_default_on(monkeypatch):
    """C9: the default flipped to ON when the cutover completed (2026-07-20).

    This asserted ``is False`` for the warn-then-enforce window. Leaving it that
    way meant an unset variable ran with no enforcement while .env.example said
    ``true`` — the fail-open default the audit filed.
    """
    monkeypatch.delenv("FEDERATION_ENFORCE_SIGNED_BROADCASTS", raising=False)
    assert fs.enforcement_enabled() is True


@pytest.mark.parametrize("val", ["0", "false", "no", "off"])
def test_enforcement_off_only_when_explicitly_disabled(monkeypatch, val):
    """The operator's warn-only lever survives the default flip."""
    monkeypatch.setenv("FEDERATION_ENFORCE_SIGNED_BROADCASTS", val)
    assert fs.enforcement_enabled() is False


@pytest.mark.parametrize("val", ["1", "true", "yes", "on"])
def test_enforcement_on_when_flag_set(monkeypatch, val):
    monkeypatch.setenv("FEDERATION_ENFORCE_SIGNED_BROADCASTS", val)
    assert fs.enforcement_enabled() is True


# ── Pinned-DID verification (no did.json fetch) ──────────────────────────


async def _no_fetch(url):
    raise AssertionError(f"network fetch attempted with a pinned DID: {url}")


@pytest.mark.asyncio
async def test_pinned_did_verifies_offline(chapter_pubkey_b64):
    """HAPPY: with a pinned DID the key comes from the DID itself — the
    endpoint (and its did.json) is never contacted."""
    body = {"broadcast_id": "b1", "title": "hi"}
    headers = fs.sign_outbound("test-chapter", body)
    pinned = headers[fs.CHAPTER_DID_HEADER]  # the signer's real did:key

    valid, reason = await fs.verify_inbound(
        body, headers, "https://peer.example", http_get=_no_fetch, pinned_did=pinned
    )
    assert valid is True and reason == "ok_pinned"


@pytest.mark.asyncio
async def test_pin_defeats_registry_supplied_key(chapter_pubkey_b64):
    """ADVERSARIAL: the circular-trust attack. A cheating registry points a
    peer record at an attacker endpoint; the attacker signs with their own key
    and serves the matching did.json. Without a pin that verifies — WITH the
    victim's pinned DID it fails."""
    import base64 as b64

    sovereign_identity.generate_ed25519_keypair("attacker-chapter")
    body = {"broadcast_id": "b1", "title": "totally from your trusted peer"}
    attacker_headers = fs.sign_outbound("attacker-chapter", body)
    attacker_pub = b64.b64encode(sovereign_identity._ed25519_keypairs["attacker-chapter"]["public_key"]).decode()

    async def attacker_didjson(url):
        return _did_json(attacker_pub)

    # The hole this whole series closes: endpoint-anchored discovery trusts
    # whatever key the (attacker-controlled) endpoint publishes.
    valid, reason = await fs.verify_inbound(
        body, attacker_headers, "https://attacker.example", http_get=attacker_didjson
    )
    assert valid is True and reason == "ok"

    # The pin: the victim's real DID is the trust anchor — attacker key loses.
    victim_did = sovereign_identity.build_did_key_from_ed25519(chapter_pubkey_b64)
    valid, reason = await fs.verify_inbound(
        body, attacker_headers, "https://attacker.example", http_get=attacker_didjson, pinned_did=victim_did
    )
    assert valid is False and reason == "invalid_signature"


@pytest.mark.asyncio
async def test_undecodable_pin_fails_closed(chapter_pubkey_b64):
    """ADVERSARIAL: a pin that doesn't decode fails verification outright —
    NO fallback to the endpoint's did.json (falling back would let an attacker
    escape the pin by corrupting it)."""
    body = {"broadcast_id": "b1", "title": "hi"}
    headers = fs.sign_outbound("test-chapter", body)

    valid, reason = await fs.verify_inbound(
        body, headers, "https://peer.example", http_get=_no_fetch, pinned_did="did:web:not-a-key"
    )
    assert valid is False and reason == "pinned_did_invalid"


@pytest.mark.asyncio
async def test_legacy_body_only_signature_with_pin(chapter_pubkey_b64):
    """HAPPY: a older peer (body-only signature, no timestamp) still
    verifies against the pin under warn mode — ok_legacy_pinned."""
    import base64 as b64

    body = {"broadcast_id": "b1", "title": "hi"}
    kp = sovereign_identity._ed25519_keypairs["test-chapter"]
    sig = sovereign_identity.ed25519_sign(fs._canonical(body), b64.b64encode(kp["private_key"]).decode())
    pinned = sovereign_identity.build_did_key_from_ed25519(chapter_pubkey_b64)

    valid, reason = await fs.verify_inbound(
        body, {fs.CHAPTER_SIG_HEADER: sig}, "https://peer.example", http_get=_no_fetch, pinned_did=pinned
    )
    assert valid is True and reason == "ok_legacy_pinned"


# ── pinned_did_for: persistent pin > in-memory attested DID > None ───────


@pytest.mark.asyncio
async def test_pinned_did_for_prefers_persistent_pin(monkeypatch):
    import federation_policy

    async def _row(peer_id):
        return {"peer_chapter_id": peer_id, "pinned_did": "did:key:zPERSISTED"}

    monkeypatch.setattr(federation_policy, "get_peer_policy", _row)
    did, lookup_failed = await fs.pinned_did_for("acme", {"did": "did:key:zINMEMORY"})
    assert did == "did:key:zPERSISTED"
    assert lookup_failed is False


@pytest.mark.asyncio
async def test_pinned_did_for_falls_back_to_attested(monkeypatch):
    import federation_policy

    async def _no_row(peer_id):
        return None

    monkeypatch.setattr(federation_policy, "get_peer_policy", _no_row)
    did, lookup_failed = await fs.pinned_did_for("acme", {"did": "did:key:zINMEMORY"})
    assert did == "did:key:zINMEMORY"
    # A legitimately-absent pin is NOT a lookup failure — the fallback is safe.
    assert lookup_failed is False


@pytest.mark.asyncio
async def test_pinned_did_for_none_when_unpinned(monkeypatch):
    import federation_policy

    async def _no_row(peer_id):
        return None

    monkeypatch.setattr(federation_policy, "get_peer_policy", _no_row)
    did, lookup_failed = await fs.pinned_did_for("acme", {"endpoint": "https://acme.example.com"})
    assert did is None
    assert lookup_failed is False


@pytest.mark.asyncio
async def test_pinned_did_for_signals_failure_on_db_error(monkeypatch):
    """F5: a DB read error is NOT 'no pin'. It must set lookup_failed=True so the
    caller fails closed instead of silently downgrading a pinned peer to the
    endpoint's did.json (the circular-trust hole the pin exists to close)."""
    import federation_policy

    async def _boom(peer_id):
        raise RuntimeError("no database")

    monkeypatch.setattr(federation_policy, "get_peer_policy", _boom)
    did, lookup_failed = await fs.pinned_did_for("acme", {"endpoint": "https://acme.example.com"})
    assert lookup_failed is True, "DB read error was swallowed as 'no pin' (fail-open)"


# ── F5 caller-side: the inbox endpoint fails closed under enforcement ────


class _AsyncReq:
    """A stand-in inbound broadcast request from peer ``acme``."""

    def __init__(self, headers: dict, payload: dict) -> None:
        self.headers = headers
        self._payload = payload

    async def json(self):
        return self._payload


@pytest.mark.asyncio
async def test_inbox_rejects_broadcast_when_pin_lookup_fails_under_enforcement(monkeypatch):
    """A DB error resolving the peer's pin must NOT let the broadcast through
    under enforcement — the handler returns 503 (retryable) rather than verifying
    against the endpoint-supplied did.json."""
    from fastapi.responses import JSONResponse

    import chapter_agent
    import federation_signing

    monkeypatch.setattr(chapter_agent, "federation", {"acme": {"endpoint": "https://acme.example.com"}})
    monkeypatch.setattr(federation_signing, "enforcement_enabled", lambda: True)

    async def _pin_failed(sender, entry):
        return None, True  # (did, lookup_failed)

    monkeypatch.setattr(federation_signing, "pinned_did_for", _pin_failed)

    req = _AsyncReq(
        {"X-Chapter-Origin": "acme"},
        {"origin_chapter_id": "acme", "event": {}},
    )
    resp = await chapter_agent.broadcast_inbox_endpoint(req)
    assert isinstance(resp, JSONResponse)
    assert resp.status_code == 503


@pytest.mark.asyncio
async def test_inbox_pin_lookup_failure_is_tolerated_in_warn_mode(monkeypatch):
    """With enforcement OFF the gate is advisory: a pin-lookup failure is logged
    and the broadcast still processes (does NOT 503)."""
    import chapter_agent
    import federation_signing

    monkeypatch.setattr(chapter_agent, "federation", {"acme": {"endpoint": "https://acme.example.com"}})
    monkeypatch.setattr(federation_signing, "enforcement_enabled", lambda: False)

    async def _pin_failed(sender, entry):
        return None, True

    monkeypatch.setattr(federation_signing, "pinned_did_for", _pin_failed)

    async def _verify(*a, **k):
        return True, "ok"

    monkeypatch.setattr(federation_signing, "verify_inbound", _verify)

    import broadcast as broadcast_mod

    async def _receive(**kwargs):
        return {"ok": True, "broadcast_id": "b1", "event_id": "e1"}

    monkeypatch.setattr(broadcast_mod, "receive_broadcast", _receive)

    req = _AsyncReq(
        {"X-Chapter-Origin": "acme"},
        {"origin_chapter_id": "acme", "event": {}},
    )
    resp = await chapter_agent.broadcast_inbox_endpoint(req)
    # Processed, not 503.
    assert getattr(resp, "status_code", 200) != 503
