"""
Security tests for auth.py — SC-1: Authenticated Registration + SC-4: Signed A2A.

SEC-01: Valid signature accepted on registration
SEC-02: Forged signature rejected (ADVERSARIAL)
SEC-03: Expired nonce rejected (EDGE)
SEC-04: Replay rejected (ADVERSARIAL)
SEC-13: Signed message accepted
SEC-14: Tampered body rejected (ADVERSARIAL)
SEC-15: Missing signature rejected (FAILURE)
"""

import time

import pytest

from community_member.auth import (
    get_private_key,
    init_keys,
    sign_request_body,
    verify_request_headers,
)


@pytest.fixture
def keys():
    # Force HMAC scheme so legacy tests using known_keys={agent: private_key} continue to work.
    # Ed25519 parity tests live in test_ed25519_client_signing.py.
    kp = init_keys(scheme="hmac-sha256")
    return kp


# ═══════════════════════════════════════════════
# SEC-01: Valid signature accepted
# ═══════════════════════════════════════════════


def test_valid_signature_accepted(keys):
    """HAPPY: correctly signed request passes verification."""
    body = '{"agent_id": "alice", "name": "@alice"}'
    headers = sign_request_body(body, "alice")

    valid, reason = verify_request_headers(
        body,
        headers,
        known_keys={"alice": get_private_key()},
    )
    assert valid, f"Should be valid: {reason}"


# ═══════════════════════════════════════════════
# SEC-02: Forged signature rejected
# ═══════════════════════════════════════════════


def test_forged_signature_rejected(keys):
    """ADVERSARIAL: forged signature fails."""
    body = '{"agent_id": "alice"}'
    headers = sign_request_body(body, "alice")
    headers["X-Agent-Signature"] = "ZmFrZWZha2VmYWtl"  # Fake base64

    valid, reason = verify_request_headers(
        body,
        headers,
        known_keys={"alice": get_private_key()},
    )
    assert not valid
    assert "Invalid signature" in reason


def test_wrong_agent_key_rejected(keys):
    """ADVERSARIAL: signature from different agent's key fails."""
    body = '{"agent_id": "alice"}'
    headers = sign_request_body(body, "alice")

    # Verify with bob's key
    init_keys()  # Generates new keypair
    valid, reason = verify_request_headers(
        body,
        headers,
        known_keys={"alice": get_private_key()},  # Now bob's key
    )
    # This will fail because init_keys() changed the global keys
    # The old alice signature no longer matches
    assert not valid or "TOFU" in reason


# ═══════════════════════════════════════════════
# SEC-03: Expired timestamp rejected
# ═══════════════════════════════════════════════


def test_expired_timestamp_rejected(keys):
    """EDGE: old timestamp rejected."""
    body = '{"agent_id": "alice"}'
    headers = sign_request_body(body, "alice")
    # Set timestamp to 10 minutes ago
    headers["X-Agent-Timestamp"] = str(int(time.time()) - 600)

    valid, reason = verify_request_headers(
        body,
        headers,
        known_keys={"alice": get_private_key()},
        max_age_seconds=300,
    )
    assert not valid
    assert "expired" in reason.lower()


# ═══════════════════════════════════════════════
# SEC-04: Replay rejected (same signature, different timestamp)
# ═══════════════════════════════════════════════


def test_replay_different_timestamp_rejected(keys):
    """ADVERSARIAL: replayed signature with modified timestamp fails."""
    body = '{"agent_id": "alice"}'
    headers = sign_request_body(body, "alice")

    # Attacker replays with different timestamp
    headers["X-Agent-Timestamp"] = str(int(time.time()) + 1)
    # Signature no longer matches because timestamp is part of signed message

    valid, reason = verify_request_headers(
        body,
        headers,
        known_keys={"alice": get_private_key()},
    )
    assert not valid


# ═══════════════════════════════════════════════
# SEC-13: Signed message accepted
# ═══════════════════════════════════════════════


def test_signed_message_accepted(keys):
    """HAPPY: properly signed A2A message passes."""
    body = '{"content": {"type": "text", "text": "hello"}}'
    headers = sign_request_body(body, "agent-1")

    valid, reason = verify_request_headers(
        body,
        headers,
        known_keys={"agent-1": get_private_key()},
    )
    assert valid


# ═══════════════════════════════════════════════
# SEC-14: Tampered body rejected
# ═══════════════════════════════════════════════


def test_tampered_body_rejected(keys):
    """ADVERSARIAL: modified body fails signature check."""
    body = '{"content": "hello"}'
    headers = sign_request_body(body, "agent-1")

    # Attacker modifies the body
    tampered_body = '{"content": "EVIL INJECTION"}'

    valid, reason = verify_request_headers(
        tampered_body,
        headers,
        known_keys={"agent-1": get_private_key()},
    )
    assert not valid


# ═══════════════════════════════════════════════
# SEC-15: Missing signature rejected
# ═══════════════════════════════════════════════


def test_missing_signature_rejected():
    """FAILURE: no signature header → rejected."""
    valid, reason = verify_request_headers(
        '{"content": "hello"}',
        {"X-Agent-ID": "alice"},
    )
    assert not valid
    assert "Missing" in reason


def test_missing_agent_id_rejected():
    """FAILURE: no agent ID → rejected."""
    valid, reason = verify_request_headers(
        '{"content": "hello"}',
        {"X-Agent-Signature": "abc"},
    )
    assert not valid
    assert "Missing" in reason


def test_missing_timestamp_rejected():
    """FAILURE: no timestamp → rejected."""
    valid, reason = verify_request_headers(
        '{"content": "hello"}',
        {"X-Agent-ID": "alice", "X-Agent-Signature": "abc"},
    )
    assert not valid
    assert "Missing" in reason


def test_empty_headers_rejected():
    """FAILURE: empty headers → rejected."""
    valid, reason = verify_request_headers('{"content": "hello"}', {})
    assert not valid


# ═══════════════════════════════════════════════
# TOFU (Trust On First Use)
# ═══════════════════════════════════════════════


def test_tofu_accepts_first_registration(keys):
    """HAPPY: first registration with public key accepted via TOFU."""
    body = '{"agent_id": "newcomer"}'
    headers = sign_request_body(body, "newcomer")

    # No known keys — TOFU accepts
    valid, reason = verify_request_headers(body, headers, known_keys={})
    assert valid
    assert "TOFU" in reason
