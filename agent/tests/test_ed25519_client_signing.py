"""
Tests for Ed25519 signing in community-member — NANDA Index spec.

Covers the outgoing sign path (sign_request_body with scheme=ed25519),
the server-side verify path (verify_request_headers with did:key), and
parity with the chapter agent's auth_verify ingress.

Classification: HAPPY / EDGE / FAILURE / ADVERSARIAL
"""

import base64
import time

import pytest

from community_member import auth
from community_member.crypto import (
    build_did_key,
    ed25519_available,
    ed25519_sign_message,
    generate_ed25519_keypair,
)

pytestmark = pytest.mark.skipif(not ed25519_available(), reason="pynacl/base58 not installed")


@pytest.fixture
def ed_keys():
    return auth.init_keys(scheme="ed25519")


# ── HAPPY ──────────────────────────────────────────────────


def test_init_keys_ed25519_returns_did_key(ed_keys):
    """HAPPY: init_keys(scheme='ed25519') produces a valid did:key."""
    assert ed_keys["scheme"] == "ed25519"
    assert ed_keys["did_key"].startswith("did:key:z")


def test_sign_request_body_ed25519_sets_scheme_header(ed_keys):
    """HAPPY: sign_request_body(scheme=ed25519) sets X-Agent-Sig-Scheme: ed25519."""
    headers = auth.sign_request_body('{"hello":1}', "alice")
    assert headers["X-Agent-Sig-Scheme"] == "ed25519"
    assert headers["X-Agent-DID-Key"].startswith("did:key:z")
    assert "X-Agent-Public-Key" not in headers  # Ed25519 path uses DID, not raw pubkey


def test_ed25519_roundtrip_via_did_key(ed_keys):
    """HAPPY: sign + verify via did:key roundtrip succeeds."""
    body = '{"intent":"find rust dev"}'
    headers = auth.sign_request_body(body, "alice")

    valid, reason = auth.verify_request_headers(body, headers, known_keys={})
    assert valid, reason
    assert "ed25519" in reason.lower()


def test_ed25519_roundtrip_with_stored_pubkey(ed_keys):
    """HAPPY: verification with known_keys[agent_id]=pubkey_b64 succeeds."""
    body = "{}"
    headers = auth.sign_request_body(body, "alice")
    # Drop the DID header to force pubkey-store path
    headers.pop("X-Agent-DID-Key", None)
    valid, reason = auth.verify_request_headers(body, headers, known_keys={"alice": auth.get_public_key()})
    assert valid, reason


# ── ADVERSARIAL ────────────────────────────────────────────


def test_ed25519_tampered_body_rejected(ed_keys):
    """ADVERSARIAL: swapping body after signing fails verification."""
    headers = auth.sign_request_body('{"a":1}', "alice")
    valid, reason = auth.verify_request_headers('{"a":2}', headers, known_keys={})
    assert not valid
    assert "invalid" in reason.lower()


def test_ed25519_wrong_pubkey_rejected(ed_keys):
    """ADVERSARIAL: signature from one keypair fails with another's pubkey."""
    body = "{}"
    headers = auth.sign_request_body(body, "alice")

    other = generate_ed25519_keypair()
    # Swap out the DID for another keypair's DID
    headers["X-Agent-DID-Key"] = build_did_key(other["public_key"])
    valid, reason = auth.verify_request_headers(body, headers, known_keys={})
    assert not valid
    assert "invalid" in reason.lower()


def test_ed25519_replay_rejected(ed_keys):
    """ADVERSARIAL: timestamp older than max_age rejected."""
    body = "{}"
    headers = auth.sign_request_body(body, "alice")
    # Manually forge an old timestamp and re-sign
    old_ts = str(int(time.time()) - 3600)
    message = f"{body}:alice:{old_ts}"
    headers["X-Agent-Timestamp"] = old_ts
    headers["X-Agent-Signature"] = ed25519_sign_message(message, auth.get_private_key())

    valid, reason = auth.verify_request_headers(body, headers, known_keys={})
    assert not valid
    assert "expired" in reason.lower()


def test_ed25519_bad_did_key_rejected(ed_keys):
    """ADVERSARIAL: malformed did:key header with no known_keys = failure."""
    body = "{}"
    headers = auth.sign_request_body(body, "alice")
    headers["X-Agent-DID-Key"] = "did:key:notvalid!!!"
    valid, reason = auth.verify_request_headers(body, headers, known_keys={})
    assert not valid


def test_ed25519_missing_scheme_infers_from_length(ed_keys):
    """EDGE: scheme header absent but signature length = 88 → inferred ed25519."""
    body = "{}"
    headers = auth.sign_request_body(body, "alice")
    assert len(headers["X-Agent-Signature"]) > 60
    del headers["X-Agent-Sig-Scheme"]
    valid, reason = auth.verify_request_headers(body, headers, known_keys={})
    assert valid, reason


def test_ed25519_did_key_multicodec_prefix(ed_keys):
    """C7: every did:key we produce decodes to 0xed 0x01 + 32-byte pubkey."""
    import base58

    did = ed_keys["did_key"]
    encoded = did[len("did:key:z") :]
    raw = base58.b58decode(encoded)
    assert raw[:2] == b"\xed\x01"
    assert len(raw) == 34


def test_ed25519_different_messages_different_sigs(ed_keys):
    """HAPPY: same key signing different messages produces different sigs."""
    a = auth.sign_request_body('{"a":1}', "alice")["X-Agent-Signature"]
    b = auth.sign_request_body('{"b":1}', "alice")["X-Agent-Signature"]
    assert a != b


def test_ed25519_sig_base64_decodes_to_64_bytes(ed_keys):
    """C5: Ed25519 signature is exactly 64 bytes per RFC 8032."""
    headers = auth.sign_request_body("{}", "alice")
    raw = base64.b64decode(headers["X-Agent-Signature"])
    assert len(raw) == 64


# ── C4: mutating requests bind the HTTP method + path (v0.3) ─────────


def test_C4_sign_request_body_binds_method_and_path(ed_keys):
    """When method + url_path are supplied, the client emits v0.3
    (ed25519+nonce) whose signature commits to METHOD:url_path — so a captured
    signature cannot be replayed against a different verb/path."""
    from community_member.auth import canonical_string_v03
    from community_member.crypto import ed25519_sign_message

    body = '{"x":1}'
    headers = auth.sign_request_body(body, "alice", method="POST", url_path="/api/intents")
    assert headers["X-Agent-Sig-Scheme"] == "ed25519+nonce"
    assert headers.get("X-Agent-Nonce")

    ts = headers["X-Agent-Timestamp"]
    nonce = headers["X-Agent-Nonce"]
    emitted = headers["X-Agent-Signature"]
    priv = auth._private_key

    # Re-signing the POST canonical with the same key reproduces the emitted
    # signature → the signature commits to method:url_path.
    post_sig = ed25519_sign_message(canonical_string_v03("POST", "/api/intents", body, "alice", ts, nonce), priv)
    assert emitted == post_sig, "emitted signature is not over the method-bound canonical"

    # Signing a DELETE canonical (same body/ts/nonce) yields a DIFFERENT
    # signature — so the captured POST signature cannot authenticate a DELETE.
    delete_sig = ed25519_sign_message(canonical_string_v03("DELETE", "/api/intents", body, "alice", ts, nonce), priv)
    assert delete_sig != emitted, "method is not part of what's signed — binding is ineffective"


def test_C4_a2a_client_delete_uses_method_bound_scheme(ed_keys):
    """A2AClient._delete/_post sign v0.3 so the hardened server accepts them and
    a captured GET can't be replayed as a DELETE."""
    from community_member.a2a_client import A2AClient

    client = A2AClient(
        chapter_url="https://chapter.test",
        agent_id="alice",
        private_key=auth._private_key,
    )
    headers = client._auth_headers("", "DELETE", "/api/subscriptions/s-1")
    assert headers["X-Agent-Sig-Scheme"] == "ed25519+nonce"
    assert headers.get("X-Agent-Nonce")
