"""
Server-side auth verification tests — Phase 2.

SEC: DELETE protection, TOFU registration, per-agent rate limiting.
"""

import base64
import hashlib
import hmac
import time

import pytest

import auth_verify


@pytest.fixture(autouse=True)
def clean_state():
    auth_verify._agent_keys.clear()
    auth_verify._nonces.clear()
    # These tests exercise the SIGNING schemes. Standalone, the module lets
    # nobody TOFU-bootstrap (fail closed); the app installs a membership
    # predicate. Every id here is treated as registered so the TOFU tests
    # remain about the key exchange. The refusal itself is asserted below in
    # test_tofu_is_refused_for_an_id_nobody_vouched_for.
    auth_verify.set_tofu_eligibility(lambda _agent_id: True)
    yield
    auth_verify.set_tofu_eligibility(None)
    auth_verify._agent_keys.clear()
    auth_verify._nonces.clear()


def _sign(body: str, agent_id: str, private_key: bytes, timestamp: str = "") -> dict:
    """Helper to create signed headers."""
    ts = timestamp or str(int(time.time()))
    message = f"{body}:{agent_id}:{ts}"
    sig = hmac.new(private_key, message.encode(), hashlib.sha256).digest()
    pub = hashlib.sha256(private_key).digest()
    return {
        "X-Agent-ID": agent_id,
        "X-Agent-Signature": base64.b64encode(sig).decode(),
        "X-Agent-Timestamp": ts,
        "X-Agent-Public-Key": base64.b64encode(pub).decode(),
    }


# ═══════════════════════════════════════════════
# OPEN PATH CHECKS
# ═══════════════════════════════════════════════


def test_health_is_open():
    assert auth_verify.is_open_path("GET", "/health")


def test_surfaces_is_open():
    assert auth_verify.is_open_path("GET", "/api/surfaces/dashboard")


def test_federation_is_open():
    assert auth_verify.is_open_path("GET", "/api/federation")


def test_post_members_is_self_signed_open():
    """POST /api/members is classified as self-signed-open because the
    handler does TOFU internally + enforces origin-mismatch on re-register.
    Middleware gating was blocking first-time registration (discovered
    running OpenClaw skill flow live on 2026-04-22).
    """
    assert auth_verify.is_open_path("POST", "/api/members") is True


def test_post_digest_build_requires_a_credential():
    """POST /api/digest/build is NOT open (audit M11).

    This test used to assert the opposite, on the grounds that the handler
    "declares it public-tier" and the 5/min ceiling caps LLM burn. The
    ceiling bounds cost; the finding was about content. An unauthenticated
    build returned member-authored intent text and a seven-day joiner roster
    (measured in server/tests/test_digest_build_gate.py). The route now sits
    at the tier of the rows it reads: the global signature gate for a member,
    plus the operator bearer via is_admin_bearer_path.
    """
    assert auth_verify.is_open_path("POST", "/api/digest/build") is False
    assert auth_verify.requires_auth("POST", "/api/digest/build")
    assert auth_verify.is_admin_bearer_path("POST", "/api/digest/build") is True
    # Sibling paths must NOT inherit the bearer allowance — exact match only.
    assert auth_verify.is_admin_bearer_path("POST", "/api/digest") is False
    assert auth_verify.is_admin_bearer_path("POST", "/api/digest/build/something") is False
    assert auth_verify.is_admin_bearer_path("GET", "/api/digest/build") is False


def test_delete_requires_auth():
    assert auth_verify.requires_auth("DELETE", "/api/members/alice")


def test_post_intents_requires_auth():
    assert auth_verify.requires_auth("POST", "/api/intents")


# ═══════════════════════════════════════════════
# TOFU REGISTRATION
# ═══════════════════════════════════════════════


def test_hmac_first_contact_rejected_no_tofu():
    """SECURITY (C1): an HMAC first request is NOT accepted via header TOFU.

    An X-Agent-Public-Key header is not proof of possession of an HMAC secret,
    so a novel agent_id with the (default) hmac-sha256 scheme must be rejected —
    previously this fail-open returned ``tofu_accepted`` without checking the
    signature, verifying an arbitrary caller as an arbitrary identity.
    """
    private_key = b"secret-key-32-bytes-long-padding!"
    headers = _sign("{}", "alice", private_key)

    valid, agent_id, reason = auth_verify.verify_request("{}", headers)
    assert not valid
    assert agent_id == "alice"
    assert reason == "no_stored_key"
    assert not auth_verify.has_agent_key("alice")


def test_hmac_forged_signature_with_pubkey_header_rejected():
    """SECURITY (C1): garbage signature + a public-key header does not authenticate.

    The core exploit: X-Agent-ID: <anyone>, a bogus signature, and any
    X-Agent-Public-Key must NOT verify. No stored secret exists for this id, so
    there is no branch that can return valid.
    """
    headers = {
        "X-Agent-ID": "attacker-" + str(int(time.time())),
        "X-Agent-Signature": base64.b64encode(b"not-a-real-signature").decode(),
        "X-Agent-Timestamp": str(int(time.time())),
        "X-Agent-Public-Key": base64.b64encode(b"whatever-32-bytes-of-garbage!!!!").decode(),
    }
    valid, _agent_id, reason = auth_verify.verify_request("{}", headers)
    assert not valid
    assert reason in ("no_stored_key", "invalid_signature")


def test_tofu_stores_key():
    """HAPPY: TOFU stores the public key for future verification."""
    auth_verify.store_agent_key("bob", "pubkey123", "secret123")
    assert auth_verify.has_agent_key("bob")
    key = auth_verify.get_agent_key("bob")
    assert key["public_key"] == "pubkey123"


# ═══════════════════════════════════════════════
# SIGNATURE VERIFICATION
# ═══════════════════════════════════════════════


def test_valid_signature_accepted():
    """HAPPY: correctly signed request passes."""
    private_key = b"my-secret-key-32-bytes-padding!!"
    secret_b64 = base64.b64encode(private_key).decode()
    pub = hashlib.sha256(private_key).digest()
    pub_b64 = base64.b64encode(pub).decode()

    auth_verify.store_agent_key("alice", pub_b64, secret_b64)

    headers = _sign('{"data": "test"}', "alice", private_key)
    valid, agent_id, reason = auth_verify.verify_request('{"data": "test"}', headers)
    assert valid
    assert reason == "verified"


def test_forged_signature_rejected():
    """ADVERSARIAL: forged signature fails."""
    private_key = b"real-key-32-bytes-long-padding!!!"
    secret_b64 = base64.b64encode(private_key).decode()
    auth_verify.store_agent_key("alice", "pub", secret_b64)

    headers = {
        "X-Agent-ID": "alice",
        "X-Agent-Signature": base64.b64encode(b"fake-signature").decode(),
        "X-Agent-Timestamp": str(int(time.time())),
    }
    valid, agent_id, reason = auth_verify.verify_request("{}", headers)
    assert not valid
    assert reason == "invalid_signature"


def test_tampered_body_rejected():
    """ADVERSARIAL: modified body fails signature check."""
    private_key = b"my-secret-key-32-bytes-padding!!"
    secret_b64 = base64.b64encode(private_key).decode()
    auth_verify.store_agent_key("alice", "pub", secret_b64)

    headers = _sign('{"original": true}', "alice", private_key)
    valid, _, reason = auth_verify.verify_request('{"tampered": true}', headers)
    assert not valid


def test_expired_timestamp_rejected():
    """EDGE: old timestamp rejected."""
    private_key = b"my-secret-key-32-bytes-padding!!"
    secret_b64 = base64.b64encode(private_key).decode()
    auth_verify.store_agent_key("alice", "pub", secret_b64)

    old_ts = str(int(time.time()) - 600)
    headers = _sign("{}", "alice", private_key, timestamp=old_ts)
    valid, _, reason = auth_verify.verify_request("{}", headers)
    assert not valid
    assert reason == "expired_timestamp"


# ═══════════════════════════════════════════════
# MISSING HEADERS
# ═══════════════════════════════════════════════


def test_missing_agent_id():
    """FAILURE: no agent ID → rejected."""
    valid, _, reason = auth_verify.verify_request("{}", {"X-Agent-Signature": "x", "X-Agent-Timestamp": "1"})
    assert not valid
    assert reason == "missing_agent_id"


def test_missing_signature():
    """FAILURE: no signature → rejected."""
    valid, _, reason = auth_verify.verify_request("{}", {"X-Agent-ID": "alice", "X-Agent-Timestamp": "1"})
    assert not valid
    assert reason == "missing_signature"


def test_missing_timestamp():
    """FAILURE: no timestamp → rejected."""
    valid, _, reason = auth_verify.verify_request("{}", {"X-Agent-ID": "alice", "X-Agent-Signature": "x"})
    assert not valid
    assert reason == "missing_timestamp"


def test_empty_headers():
    """FAILURE: empty headers → rejected."""
    valid, _, reason = auth_verify.verify_request("{}", {})
    assert not valid


# ═══════════════════════════════════════════════
# NONCE CHALLENGE
# ═══════════════════════════════════════════════


def test_nonce_generation_and_verification():
    """HAPPY: generate nonce, verify it."""
    nonce = auth_verify.generate_nonce("alice")
    assert auth_verify.verify_nonce(nonce, "alice")


def test_nonce_single_use():
    """EDGE: nonce can only be used once."""
    nonce = auth_verify.generate_nonce("alice")
    auth_verify.verify_nonce(nonce, "alice")
    assert not auth_verify.verify_nonce(nonce, "alice")  # Second use fails


def test_nonce_wrong_agent():
    """ADVERSARIAL: nonce for different agent fails."""
    nonce = auth_verify.generate_nonce("alice")
    assert not auth_verify.verify_nonce(nonce, "bob")


# ═══════════════════════════════════════════════
# KEY LOADING
# ═══════════════════════════════════════════════


def test_load_keys_from_members():
    """HAPPY: keys loaded from members dict on startup."""
    members = {
        "alice": {"name": "Alice", "public_key": "pk1", "signing_secret": "sk1"},
        "bob": {"name": "Bob"},  # No key
    }
    auth_verify.load_keys_from_members(members)
    assert auth_verify.has_agent_key("alice")
    assert not auth_verify.has_agent_key("bob")


# ═══════════════════════════════════════════════
# ED25519 SIGNATURE PATH (NANDA Index spec)
# ═══════════════════════════════════════════════


def _ed25519_headers(body: str, agent_id: str, private_b64: str, timestamp: str = "") -> dict:
    """Helper: build Ed25519-scheme headers for a signed request."""
    import sovereign_identity

    ts = timestamp or str(int(time.time()))
    message = f"{body}:{agent_id}:{ts}"
    sig = sovereign_identity.ed25519_sign(message, private_b64)
    return {
        "X-Agent-ID": agent_id,
        "X-Agent-Signature": sig,
        "X-Agent-Timestamp": ts,
        "X-Agent-Sig-Scheme": "ed25519",
    }


def test_ed25519_tofu_via_did_key_accepted():
    """HAPPY: first Ed25519 request with X-Agent-DID-Key stored via TOFU."""
    import sovereign_identity

    kp = sovereign_identity.generate_ed25519_keypair("alice")
    did = sovereign_identity.build_did_key_from_ed25519(kp["public_key"])

    headers = _ed25519_headers("{}", "alice", kp["private_key"])
    headers["X-Agent-DID-Key"] = did

    valid, agent_id, reason = auth_verify.verify_request("{}", headers)
    assert valid
    assert agent_id == "alice"
    assert reason == "tofu_accepted"
    assert auth_verify.get_agent_key("alice")["ed25519_pubkey"] == kp["public_key"]


def test_tofu_is_refused_for_an_id_nobody_vouched_for():
    """ADVERSARIAL: a fresh keypair and a made-up id must NOT bootstrap a key.

    Standalone the module fails closed (no predicate installed); with a
    predicate, an id it does not vouch for is refused BEFORE the key is filed,
    so a refused caller leaves nothing in ``_agent_keys`` to verify against
    next time. Measured before this existed: such a caller was tofu_accepted
    and read the member directory.
    """
    import sovereign_identity

    kp = sovereign_identity.generate_ed25519_keypair("stranger")
    headers = _ed25519_headers("{}", "stranger", kp["private_key"])
    headers["X-Agent-DID-Key"] = sovereign_identity.build_did_key_from_ed25519(kp["public_key"])

    auth_verify.set_tofu_eligibility(None)
    valid, _, reason = auth_verify.verify_request("{}", headers)
    assert (valid, reason) == (False, "no_stored_key")
    assert auth_verify.get_agent_key("stranger") is None, "a refused TOFU must file no key"

    auth_verify.set_tofu_eligibility(lambda agent_id: agent_id == "someone-else")
    valid, _, reason = auth_verify.verify_request("{}", headers)
    assert (valid, reason) == (False, "no_stored_key")
    assert auth_verify.get_agent_key("stranger") is None


def test_tofu_is_accepted_on_the_a2a_interop_surfaces_without_membership():
    """The /a2a and /run family is invoked by callers who never joined: there
    the signature is accountability, not membership, and TOFU proceeds with no
    predicate at all."""
    import sovereign_identity

    auth_verify.set_tofu_eligibility(None)
    for path in ("/run", "/a2a", "/a2a/@someone", "/run?x=1"):
        auth_verify._agent_keys.clear()
        kp = sovereign_identity.generate_ed25519_keypair("visitor")
        headers = _ed25519_headers("{}", "visitor", kp["private_key"])
        headers["X-Agent-DID-Key"] = sovereign_identity.build_did_key_from_ed25519(kp["public_key"])
        valid, _, reason = auth_verify.verify_request("{}", headers, method="POST", url_path=path)
        assert (valid, reason) == (True, "tofu_accepted"), path
    auth_verify._agent_keys.clear()
    kp = sovereign_identity.generate_ed25519_keypair("visitor")
    headers = _ed25519_headers("{}", "visitor", kp["private_key"])
    headers["X-Agent-DID-Key"] = sovereign_identity.build_did_key_from_ed25519(kp["public_key"])
    valid, _, reason = auth_verify.verify_request("{}", headers, method="GET", url_path="/api/members")
    assert (valid, reason) == (False, "no_stored_key")


def test_ed25519_stored_key_accepted():
    """HAPPY: stored Ed25519 pubkey accepts valid signature on subsequent requests."""
    import sovereign_identity

    kp = sovereign_identity.generate_ed25519_keypair("alice")
    auth_verify.store_agent_key("alice", "", "", ed25519_pubkey=kp["public_key"])

    headers = _ed25519_headers('{"data":1}', "alice", kp["private_key"])
    valid, _, reason = auth_verify.verify_request('{"data":1}', headers)
    assert valid
    assert reason == "verified"


def test_ed25519_tampered_body_rejected():
    """ADVERSARIAL: body swap after signing fails Ed25519 verification."""
    import sovereign_identity

    kp = sovereign_identity.generate_ed25519_keypair("alice")
    auth_verify.store_agent_key("alice", "", "", ed25519_pubkey=kp["public_key"])

    headers = _ed25519_headers('{"original":true}', "alice", kp["private_key"])
    valid, _, reason = auth_verify.verify_request('{"tampered":true}', headers)
    assert not valid
    assert reason == "invalid_signature"


def test_ed25519_wrong_key_rejected():
    """ADVERSARIAL: valid Ed25519 signature from another keypair rejected."""
    import sovereign_identity

    attacker = sovereign_identity.generate_ed25519_keypair("attacker")
    victim = sovereign_identity.generate_ed25519_keypair("alice")
    auth_verify.store_agent_key("alice", "", "", ed25519_pubkey=victim["public_key"])

    headers = _ed25519_headers('{"hi":1}', "alice", attacker["private_key"])
    valid, _, reason = auth_verify.verify_request('{"hi":1}', headers)
    assert not valid
    assert reason == "invalid_signature"


def test_ed25519_expired_timestamp_rejected():
    """ADVERSARIAL: Ed25519 sig with stale timestamp rejected regardless of sig validity."""
    import sovereign_identity

    kp = sovereign_identity.generate_ed25519_keypair("alice")
    auth_verify.store_agent_key("alice", "", "", ed25519_pubkey=kp["public_key"])

    stale = str(int(time.time()) - 3600)  # 1h old
    headers = _ed25519_headers("{}", "alice", kp["private_key"], timestamp=stale)
    valid, _, reason = auth_verify.verify_request("{}", headers)
    assert not valid
    assert reason == "expired_timestamp"


def test_ed25519_future_timestamp_rejected():
    """C5 boundary: timestamp 301s in the future rejected (max_age=300)."""
    import sovereign_identity

    kp = sovereign_identity.generate_ed25519_keypair("alice")
    auth_verify.store_agent_key("alice", "", "", ed25519_pubkey=kp["public_key"])

    future = str(int(time.time()) + 301)
    headers = _ed25519_headers("{}", "alice", kp["private_key"], timestamp=future)
    valid, _, reason = auth_verify.verify_request("{}", headers)
    assert not valid
    assert reason == "expired_timestamp"


def test_ed25519_boundary_exactly_at_max_age_accepted():
    """C5 boundary: timestamp exactly at max_age (300s) accepted."""
    import sovereign_identity

    kp = sovereign_identity.generate_ed25519_keypair("alice")
    auth_verify.store_agent_key("alice", "", "", ed25519_pubkey=kp["public_key"])

    at_edge = str(int(time.time()) - 300)
    headers = _ed25519_headers("{}", "alice", kp["private_key"], timestamp=at_edge)
    valid, _, reason = auth_verify.verify_request("{}", headers)
    assert valid


def test_ed25519_boundary_just_over_max_age_rejected():
    """C5 boundary: timestamp 301s old rejected."""
    import sovereign_identity

    kp = sovereign_identity.generate_ed25519_keypair("alice")
    auth_verify.store_agent_key("alice", "", "", ed25519_pubkey=kp["public_key"])

    too_old = str(int(time.time()) - 301)
    headers = _ed25519_headers("{}", "alice", kp["private_key"], timestamp=too_old)
    valid, _, reason = auth_verify.verify_request("{}", headers)
    assert not valid
    assert reason == "expired_timestamp"


def test_ed25519_malformed_did_key_rejected():
    """ADVERSARIAL: malformed did:key in TOFU rejected, no key stored."""
    headers = {
        "X-Agent-ID": "mallory",
        "X-Agent-Signature": "c29tZXNpZw==",
        "X-Agent-Timestamp": str(int(time.time())),
        "X-Agent-Sig-Scheme": "ed25519",
        "X-Agent-DID-Key": "did:key:notvalidbase58!!!",
    }
    valid, _, reason = auth_verify.verify_request("{}", headers)
    assert not valid
    assert reason == "invalid_did_key"
    assert not auth_verify.has_agent_key("mallory")


def test_ed25519_missing_key_rejected():
    """ADVERSARIAL: Ed25519 scheme with no stored key and no DID header rejected."""
    headers = {
        "X-Agent-ID": "ghost",
        "X-Agent-Signature": "c29tZXNpZw==",
        "X-Agent-Timestamp": str(int(time.time())),
        "X-Agent-Sig-Scheme": "ed25519",
    }
    valid, _, reason = auth_verify.verify_request("{}", headers)
    assert not valid
    assert reason == "no_stored_key"


def test_ed25519_forged_signature_bytes_rejected():
    """ADVERSARIAL: random base64 bytes as signature rejected."""
    import sovereign_identity

    kp = sovereign_identity.generate_ed25519_keypair("alice")
    auth_verify.store_agent_key("alice", "", "", ed25519_pubkey=kp["public_key"])

    headers = {
        "X-Agent-ID": "alice",
        "X-Agent-Signature": base64.b64encode(b"forged" * 11).decode(),
        "X-Agent-Timestamp": str(int(time.time())),
        "X-Agent-Sig-Scheme": "ed25519",
    }
    valid, _, reason = auth_verify.verify_request("{}", headers)
    assert not valid
    assert reason == "invalid_signature"


def test_unknown_sig_scheme_rejected():
    """ADVERSARIAL: unknown X-Agent-Sig-Scheme rejected without trying any path."""
    headers = {
        "X-Agent-ID": "alice",
        "X-Agent-Signature": "c29tZQ==",
        "X-Agent-Timestamp": str(int(time.time())),
        "X-Agent-Sig-Scheme": "sha3-512-sneaky",
    }
    valid, _, reason = auth_verify.verify_request("{}", headers)
    assert not valid
    assert reason == "unknown_sig_scheme"


def test_load_keys_from_members_includes_ed25519_from_did_key():
    """HAPPY: load_keys_from_members extracts Ed25519 pubkey from AgentFacts did:key."""
    import sovereign_identity

    kp = sovereign_identity.generate_ed25519_keypair("alice")
    did = sovereign_identity.build_did_key_from_ed25519(kp["public_key"])

    members = {
        "alice": {
            "name": "Alice",
            "agent_facts": {"provider": {"did": did}},
        }
    }
    auth_verify.load_keys_from_members(members)
    stored = auth_verify.get_agent_key("alice")
    assert stored is not None
    assert stored["ed25519_pubkey"] == kp["public_key"]


def test_header_case_insensitive_ed25519():
    """EDGE: lowercase header names accepted for Ed25519 scheme."""
    import sovereign_identity

    kp = sovereign_identity.generate_ed25519_keypair("alice")
    did = sovereign_identity.build_did_key_from_ed25519(kp["public_key"])
    ts = str(int(time.time()))
    message = f"{{}}:alice:{ts}"
    sig = sovereign_identity.ed25519_sign(message, kp["private_key"])

    headers = {
        "x-agent-id": "alice",
        "x-agent-signature": sig,
        "x-agent-timestamp": ts,
        "x-agent-sig-scheme": "ed25519",
        "x-agent-did-key": did,
    }
    valid, _, reason = auth_verify.verify_request("{}", headers)
    assert valid


def test_hmac_still_works_when_ed25519_path_added():
    """EDGE: HMAC default path unaffected by Ed25519 additions."""
    private_key = b"hmac-default-key-32-bytes-padding"
    secret_b64 = base64.b64encode(private_key).decode()
    auth_verify.store_agent_key("alice", "pub", secret_b64)

    headers = _sign('{"ok":1}', "alice", private_key)
    valid, _, reason = auth_verify.verify_request('{"ok":1}', headers)
    assert valid
    assert reason == "verified"


# ═══════════════════════════════════════════════
# ED25519+NONCE PATH (the org protocol v0.3)
# spec/0.3/signing.md — canonical = method:url_path:body:agent_id:timestamp:nonce
# ═══════════════════════════════════════════════


def _ed25519_v03_headers(
    body: str,
    agent_id: str,
    private_b64: str,
    method: str = "POST",
    url_path: str = "/api/intents",
    timestamp: str = "",
    nonce: str = "",
) -> dict:
    """Build v0.3 (ed25519+nonce) signed headers."""
    import base64 as _b64
    import os as _os

    import sovereign_identity

    ts = timestamp or str(int(time.time()))
    n = nonce or _b64.b64encode(_os.urandom(32)).decode()
    canonical = f"{method.upper()}:{url_path}:{body}:{agent_id}:{ts}:{n}"
    sig = sovereign_identity.ed25519_sign(canonical, private_b64)
    return {
        "X-Agent-ID": agent_id,
        "X-Agent-Signature": sig,
        "X-Agent-Timestamp": ts,
        "X-Agent-Sig-Scheme": "ed25519+nonce",
        "X-Agent-Nonce": n,
    }


@pytest.fixture(autouse=True)
def clean_v03_replay_store():
    """Each test starts with an empty replay store so nonce reuse across
    tests does not poison the state. Runs alongside the existing
    `clean_state` fixture."""
    auth_verify._v03_replay_store.clear()
    yield
    auth_verify._v03_replay_store.clear()


def test_v03_HAPPY_valid_signed_request_accepted():
    import sovereign_identity

    kp = sovereign_identity.generate_ed25519_keypair("alice")
    auth_verify.store_agent_key("alice", "", "", ed25519_pubkey=kp["public_key"])
    headers = _ed25519_v03_headers('{"text":"hi"}', "alice", kp["private_key"])
    valid, agent_id, reason = auth_verify.verify_request(
        '{"text":"hi"}', headers, method="POST", url_path="/api/intents"
    )
    assert valid
    assert agent_id == "alice"
    assert reason == "verified"


def test_v03_ADVERSARIAL_replay_same_nonce_rejected():
    """spec/0.3 §replay-protection: a duplicate (agent_id, nonce) must reject."""
    import sovereign_identity

    kp = sovereign_identity.generate_ed25519_keypair("alice")
    auth_verify.store_agent_key("alice", "", "", ed25519_pubkey=kp["public_key"])
    headers = _ed25519_v03_headers("{}", "alice", kp["private_key"])
    valid1, _, reason1 = auth_verify.verify_request("{}", headers, method="POST", url_path="/api/intents")
    assert valid1, reason1
    valid2, _, reason2 = auth_verify.verify_request("{}", headers, method="POST", url_path="/api/intents")
    assert not valid2
    assert reason2 == "nonce_replay"


def test_v03_ADVERSARIAL_cross_endpoint_replay_rejected():
    """A captured signature replayed against a different url_path must
    reject because url_path is bound into the canonical (so the signature
    does not verify) AND because the (agent_id, nonce) pair has been seen.
    Either rejection mode is acceptable; we assert the request is denied.
    """
    import sovereign_identity

    kp = sovereign_identity.generate_ed25519_keypair("alice")
    auth_verify.store_agent_key("alice", "", "", ed25519_pubkey=kp["public_key"])
    headers = _ed25519_v03_headers("{}", "alice", kp["private_key"], method="POST", url_path="/api/intents")
    # First request to /api/intents — accepted.
    valid1, _, _ = auth_verify.verify_request("{}", headers, method="POST", url_path="/api/intents")
    assert valid1
    # Replay same headers (same nonce, same body, same method) against a
    # DIFFERENT url_path. Must reject.
    valid2, _, reason2 = auth_verify.verify_request("{}", headers, method="POST", url_path="/api/receipts")
    assert not valid2
    assert reason2 in ("invalid_signature", "nonce_replay")


def test_v03_ADVERSARIAL_method_swap_rejected():
    """A signature produced for POST cannot be replayed as DELETE (or any
    other method) because method is bound into the canonical."""
    import sovereign_identity

    kp = sovereign_identity.generate_ed25519_keypair("alice")
    auth_verify.store_agent_key("alice", "", "", ed25519_pubkey=kp["public_key"])
    headers = _ed25519_v03_headers("{}", "alice", kp["private_key"], method="POST", url_path="/api/intents")
    valid, _, reason = auth_verify.verify_request("{}", headers, method="DELETE", url_path="/api/intents")
    assert not valid
    assert reason == "invalid_signature"


def test_v03_FAILURE_missing_nonce_rejected():
    """ed25519+nonce scheme without X-Agent-Nonce header → missing_nonce."""
    import sovereign_identity

    kp = sovereign_identity.generate_ed25519_keypair("alice")
    auth_verify.store_agent_key("alice", "", "", ed25519_pubkey=kp["public_key"])
    headers = _ed25519_v03_headers("{}", "alice", kp["private_key"])
    headers.pop("X-Agent-Nonce")
    valid, _, reason = auth_verify.verify_request("{}", headers, method="POST", url_path="/api/intents")
    assert not valid
    assert reason == "missing_nonce"


def test_v03_HAPPY_different_agents_same_nonce_both_accepted():
    """Replay key is (agent_id, nonce), not nonce alone — two distinct
    agents using the same random nonce must both succeed."""
    import sovereign_identity

    a = sovereign_identity.generate_ed25519_keypair("alice")
    b = sovereign_identity.generate_ed25519_keypair("bob")
    auth_verify.store_agent_key("alice", "", "", ed25519_pubkey=a["public_key"])
    auth_verify.store_agent_key("bob", "", "", ed25519_pubkey=b["public_key"])
    shared_nonce = "shared-nonce-xyz="
    h1 = _ed25519_v03_headers("{}", "alice", a["private_key"], nonce=shared_nonce)
    h2 = _ed25519_v03_headers("{}", "bob", b["private_key"], nonce=shared_nonce)
    v1, _, _ = auth_verify.verify_request("{}", h1, method="POST", url_path="/api/intents")
    v2, _, _ = auth_verify.verify_request("{}", h2, method="POST", url_path="/api/intents")
    assert v1
    assert v2


def _v02_headers(body: str, agent_id: str, private_b64: str) -> dict:
    import sovereign_identity

    ts = str(int(time.time()))
    canonical = f"{body}:{agent_id}:{ts}"
    sig = sovereign_identity.ed25519_sign(canonical, private_b64)
    return {
        "X-Agent-ID": agent_id,
        "X-Agent-Signature": sig,
        "X-Agent-Timestamp": ts,
        "X-Agent-Sig-Scheme": "ed25519",
    }


def test_v03_HAPPY_v02_fallback_still_works_for_reads():
    """A v0.3-capable server MUST still accept a v0.2-shaped GET (negotiation).
    v0.2's canonical string omits method/path — fine for an idempotent read."""
    import sovereign_identity

    kp = sovereign_identity.generate_ed25519_keypair("alice")
    auth_verify.store_agent_key("alice", "", "", ed25519_pubkey=kp["public_key"])
    headers = _v02_headers("{}", "alice", kp["private_key"])
    valid, _, reason = auth_verify.verify_request("{}", headers, method="GET", url_path="/api/receipts")
    assert valid
    assert reason == "verified"


def test_C4_v02_rejected_on_mutation():
    """C4: a v0.2 (method/path-unbound) signature MUST be rejected on a mutating
    method — otherwise a captured signed GET replays as a DELETE. The rejection
    fires BEFORE crypto, so even a validly-signed v0.2 POST is refused."""
    import sovereign_identity

    kp = sovereign_identity.generate_ed25519_keypair("alice")
    auth_verify.store_agent_key("alice", "", "", ed25519_pubkey=kp["public_key"])
    headers = _v02_headers("{}", "alice", kp["private_key"])  # a genuinely valid v0.2 sig
    for method in ("POST", "PUT", "PATCH", "DELETE"):
        valid, _, reason = auth_verify.verify_request(
            "{}", headers, method=method, url_path="/api/intents", require_method_binding=True
        )
        assert not valid, f"{method} accepted a method-unbound v0.2 signature"
        assert reason == "method_binding_required", f"{method} rejected for the wrong reason: {reason}"


def test_C4_hmac_rejected_on_mutation():
    """The same binding requirement applies to the legacy hmac scheme."""
    headers = {
        "X-Agent-ID": "alice",
        "X-Agent-Signature": "irrelevant",
        "X-Agent-Timestamp": str(int(time.time())),
        "X-Agent-Sig-Scheme": "hmac-sha256",
    }
    valid, _, reason = auth_verify.verify_request(
        "{}", headers, method="DELETE", url_path="/api/members/bob", require_method_binding=True
    )
    assert not valid
    assert reason == "method_binding_required"


def test_C4_v03_still_accepted_on_mutation():
    """The method-bound scheme (v0.3) is the sanctioned way to authenticate a
    mutation and continues to verify + replay-protect it."""
    import sovereign_identity

    kp = sovereign_identity.generate_ed25519_keypair("alice")
    auth_verify.store_agent_key("alice", "", "", ed25519_pubkey=kp["public_key"])
    headers = _ed25519_v03_headers("{}", "alice", kp["private_key"], method="DELETE", url_path="/api/members/alice")
    valid, _, reason = auth_verify.verify_request(
        "{}", headers, method="DELETE", url_path="/api/members/alice", require_method_binding=True
    )
    assert valid
    assert reason == "verified"


def test_C4_enforce_method_binding_policy():
    """The path policy: mutations on the internal API require binding; reads and
    the A2A interop POSTs are exempt.

    The exempt set is spec/0.5/signing.md §"What mutating means" VERBATIM — the
    `/a2a` family plus `POST /run` and `POST /run/`. `/run` briefly left this
    list in the advertised-version correction, when v0.5 as first published named only `/a2a`; umbrella
    / PR corrected the spec (the omission was accidental — `/run` is the
    standard A2A invoke and the runtime v0.5 was drafted against has no such
    route), and the exemption came back. The spec calls the enumeration
    exhaustive, so this list must never grow locally: amend the spec instead."""
    assert auth_verify.enforce_method_binding("POST", "/api/intents") is True
    assert auth_verify.enforce_method_binding("DELETE", "/api/members/bob") is True
    assert auth_verify.enforce_method_binding("GET", "/api/receipts") is False
    for exempt in ("/a2a", "/a2a/", "/a2a/@alice", "/run", "/run/"):
        assert auth_verify.enforce_method_binding("POST", exempt) is False, f"{exempt} should be exempt"


# ── OPEN_POST_PATHS — handler-verified open POSTs (fix/broadcast-inbox-open-post) ──


def test_open_post_path_passes_is_open_path_for_post() -> None:
    """Entries in OPEN_POST_PATHS must be open for POST (handler does
    its own verification). Regression for the broadcast inbox 401 bug
    where adding to OPEN_PATHS only opened the path for GET."""
    from auth_verify import OPEN_POST_PATHS, is_open_path

    assert OPEN_POST_PATHS, "OPEN_POST_PATHS must have at least one entry"
    for path in OPEN_POST_PATHS:
        assert is_open_path("POST", path), f"{path} must be open for POST"
        # NOT open for GET — GETs of these endpoints should still
        # require auth (or hit a different rule). Document the
        # asymmetry explicitly so a future contributor doesn't move
        # an entry from OPEN_POST_PATHS to OPEN_PATHS thinking they're
        # equivalent.
        assert not is_open_path("GET", path), f"{path} should NOT be open for GET — that's OPEN_PATHS"


def test_broadcast_inbox_is_open_for_post() -> None:
    """Explicit anchor for the federation broadcast inbox endpoint —
    a regression here breaks cross-chapter broadcast."""
    from auth_verify import is_open_path

    assert is_open_path("POST", "/api/federation/broadcast/inbox")


# ═══════════════════════════════════════════════
# R6: LOG-BEFORE-DENY — no silent except in the deny paths.
# Each test proves the deny behavior is UNCHANGED and the reason is logged.
# ═══════════════════════════════════════════════


def test_ed25519_verifier_crash_denies_with_logged_reason(monkeypatch, capsys):
    """R6: if the Ed25519 verifier itself raises, the request is denied as
    invalid_signature (unchanged) and the exception is logged (new)."""
    import sovereign_identity

    kp = sovereign_identity.generate_ed25519_keypair("alice")
    auth_verify.store_agent_key("alice", "", "", ed25519_pubkey=kp["public_key"])

    def _boom(message, signature_b64, public_key_b64):
        raise RuntimeError("verifier exploded")

    monkeypatch.setattr(sovereign_identity, "ed25519_verify", _boom)

    ts = str(int(time.time()))
    sig = sovereign_identity.ed25519_sign(f"{{}}:alice:{ts}", kp["private_key"])
    headers = {
        "X-Agent-ID": "alice",
        "X-Agent-Signature": sig,
        "X-Agent-Timestamp": ts,
        "X-Agent-Sig-Scheme": "ed25519",
    }
    valid, agent_id, reason = auth_verify.verify_request("{}", headers)
    assert (valid, agent_id, reason) == (False, "alice", "invalid_signature")
    out = capsys.readouterr().out
    assert "[auth][deny]" in out
    assert "verifier exploded" in out


def test_did_header_parse_crash_logs_warning_but_still_verifies(monkeypatch, capsys):
    """R6: a crash while parsing X-Agent-DID-Key skips the key-mismatch check
    (unchanged) but now logs a warning; a valid signature still verifies."""
    import sovereign_identity

    kp = sovereign_identity.generate_ed25519_keypair("alice")
    auth_verify.store_agent_key("alice", "", "", ed25519_pubkey=kp["public_key"])

    def _boom(did_key):
        raise RuntimeError("extract exploded")

    monkeypatch.setattr(sovereign_identity, "extract_ed25519_pubkey_from_did_key", _boom)

    ts = str(int(time.time()))
    sig = sovereign_identity.ed25519_sign(f"{{}}:alice:{ts}", kp["private_key"])
    headers = {
        "X-Agent-ID": "alice",
        "X-Agent-Signature": sig,
        "X-Agent-Timestamp": ts,
        "X-Agent-Sig-Scheme": "ed25519",
        "X-Agent-DID-Key": "did:key:zWhatever",
    }
    valid, _, reason = auth_verify.verify_request("{}", headers)
    assert valid
    assert reason == "verified"
    out = capsys.readouterr().out
    assert "[auth][warn]" in out
    assert "key-mismatch check skipped" in out


def test_hmac_undecodable_stored_secret_denies_with_logged_reason(capsys):
    """R6: a stored signing_secret that can't be base64-decoded denies as
    invalid_signature (unchanged) and logs the reason (new)."""
    auth_verify.store_agent_key("alice", "pub", "%%%not-base64%%%")

    ts = str(int(time.time()))
    headers = {
        "X-Agent-ID": "alice",
        "X-Agent-Signature": base64.b64encode(b"whatever").decode(),
        "X-Agent-Timestamp": ts,
    }
    valid, agent_id, reason = auth_verify.verify_request("{}", headers)
    assert (valid, agent_id, reason) == (False, "alice", "invalid_signature")
    out = capsys.readouterr().out
    assert "[auth][deny]" in out
    assert "hmac verification failed to run" in out


def test_is_open_path_calls_is_admin_api_path_not_a_re_derived_copy():
    """is_open_path used to re-derive the /admin/api/ predicate inline
    (path.startswith("/admin/api/") or path == "/admin/api") instead of
    calling is_admin_api_path, which computes the exact same thing — so
    is_admin_api_path had exactly one grep hit in the whole codebase, its
    own definition, and the two copies could silently diverge if one were
    edited and not the other. Asserts the call site directly rather than
    only the boolean outcome, so a future edit that reintroduces a
    hand-rolled duplicate (even one that still returns the right answer
    today) fails this test instead of passing it by accident.
    """
    import inspect

    source = inspect.getsource(auth_verify.is_open_path)
    assert "is_admin_api_path(" in source
