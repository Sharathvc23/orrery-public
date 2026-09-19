"""
Tests for Ed25519 cryptographic identity — NANDA Index spec compliance.

Tests Ed25519 key generation, signing, verification, DID:key format,
and backward compatibility with existing HMAC system.
Classification: HAPPY / EDGE / FAILURE / ADVERSARIAL
"""

import base64

import pytest

import sovereign_identity


@pytest.fixture(autouse=True)
def setup():
    sovereign_identity._agent_id = "test-chapter"
    sovereign_identity._ed25519_keypairs.clear()


# ── HAPPY: Ed25519 key generation and signing ────────────────


def test_ed25519_keypair_generation():
    """HAPPY: Generates valid Ed25519 keypair with proper encoding."""
    kp = sovereign_identity.generate_ed25519_keypair("alice")

    assert "private_key" in kp
    assert "public_key" in kp
    # Both are valid base64
    priv = base64.b64decode(kp["private_key"])
    pub = base64.b64decode(kp["public_key"])
    assert len(priv) == 32  # Ed25519 private key
    assert len(pub) == 32  # Ed25519 public key


def test_ed25519_sign_verify_roundtrip():
    """HAPPY: Sign with private key, verify with public key succeeds."""
    kp = sovereign_identity.generate_ed25519_keypair("alice")
    message = "Hello, NANDA!"

    signature = sovereign_identity.ed25519_sign(message, kp["private_key"])
    assert signature  # Not empty

    valid = sovereign_identity.ed25519_verify(message, signature, kp["public_key"])
    assert valid is True


def test_ed25519_different_messages():
    """HAPPY: Different messages produce different signatures."""
    kp = sovereign_identity.generate_ed25519_keypair("alice")

    sig1 = sovereign_identity.ed25519_sign("message one", kp["private_key"])
    sig2 = sovereign_identity.ed25519_sign("message two", kp["private_key"])
    assert sig1 != sig2


def test_did_key_from_ed25519():
    """HAPPY: DID:key starts with z6Mk prefix (Ed25519 multicodec)."""
    kp = sovereign_identity.generate_ed25519_keypair("alice")
    did = sovereign_identity.build_did_key_from_ed25519(kp["public_key"])

    assert did.startswith("did:key:z")
    # Should be significantly longer than 32 chars
    assert len(did) > 40


# ── ADVERSARIAL: Forgery and tampering ──────────────────────


def test_ed25519_forged_signature_rejected():
    """ADVERSARIAL: Random signature bytes rejected."""
    kp = sovereign_identity.generate_ed25519_keypair("alice")
    fake_sig = base64.b64encode(b"forged" * 11).decode()  # 66 bytes

    valid = sovereign_identity.ed25519_verify("Hello", fake_sig, kp["public_key"])
    assert valid is False


def test_ed25519_tampered_message_rejected():
    """ADVERSARIAL: Changing message after signing fails verification."""
    kp = sovereign_identity.generate_ed25519_keypair("alice")
    sig = sovereign_identity.ed25519_sign("original message", kp["private_key"])

    valid = sovereign_identity.ed25519_verify("tampered message", sig, kp["public_key"])
    assert valid is False


def test_ed25519_wrong_key_rejected():
    """ADVERSARIAL: Signature from one key fails with another's public key."""
    kp1 = sovereign_identity.generate_ed25519_keypair("alice")
    kp2 = sovereign_identity.generate_ed25519_keypair("bob")

    sig = sovereign_identity.ed25519_sign("message", kp1["private_key"])
    valid = sovereign_identity.ed25519_verify("message", sig, kp2["public_key"])
    assert valid is False


def test_ed25519_empty_message():
    """ADVERSARIAL: Empty message can be signed and verified."""
    kp = sovereign_identity.generate_ed25519_keypair("alice")
    sig = sovereign_identity.ed25519_sign("", kp["private_key"])
    valid = sovereign_identity.ed25519_verify("", sig, kp["public_key"])
    assert valid is True


def test_ed25519_invalid_key_format():
    """ADVERSARIAL: Invalid base64 key doesn't crash, returns False."""
    valid = sovereign_identity.ed25519_verify("msg", "badsig==", "badkey==")
    assert valid is False


# ── did:key roundtrip (W3C spec compliance) ────────────────


def test_did_key_roundtrip():
    """HAPPY: build_did_key_from_ed25519 → extract_ed25519_pubkey_from_did_key roundtrips."""
    kp = sovereign_identity.generate_ed25519_keypair("alice")
    did = sovereign_identity.build_did_key_from_ed25519(kp["public_key"])
    assert did.startswith("did:key:z")

    recovered = sovereign_identity.extract_ed25519_pubkey_from_did_key(did)
    assert recovered == kp["public_key"]


def test_did_key_ed25519_multicodec_prefix():
    """C7: did:key's decoded bytes start with 0xed 0x01 Ed25519 multicodec prefix."""
    import base58 as b58

    kp = sovereign_identity.generate_ed25519_keypair("alice")
    did = sovereign_identity.build_did_key_from_ed25519(kp["public_key"])
    encoded = did[len("did:key:z") :]
    raw = b58.b58decode(encoded)

    assert raw[0] == 0xED
    assert raw[1] == 0x01
    assert len(raw) == 34  # 2-byte prefix + 32-byte Ed25519 pubkey


def test_extract_from_empty_did_key():
    """ADVERSARIAL: empty string returns None, doesn't crash."""
    assert sovereign_identity.extract_ed25519_pubkey_from_did_key("") is None


def test_extract_from_non_did_key_string():
    """ADVERSARIAL: bare string returns None."""
    assert sovereign_identity.extract_ed25519_pubkey_from_did_key("hello world") is None


def test_extract_from_did_web_returns_none():
    """ADVERSARIAL: did:web (different DID method) returns None."""
    assert sovereign_identity.extract_ed25519_pubkey_from_did_key("did:web:example.com") is None


def test_extract_from_truncated_did_key():
    """ADVERSARIAL: truncated did:key returns None without crashing."""
    kp = sovereign_identity.generate_ed25519_keypair("alice")
    did = sovereign_identity.build_did_key_from_ed25519(kp["public_key"])
    truncated = did[:-5]
    # Either recovers garbage that doesn't match, or returns None — both acceptable
    recovered = sovereign_identity.extract_ed25519_pubkey_from_did_key(truncated)
    assert recovered != kp["public_key"]


def test_build_did_key_rejects_wrong_size():
    """C5 boundary (R4): pubkey that's not 32 bytes RAISES — the old
    fallback returned a malformed did:key that could never round-trip."""
    import base64 as b64

    # 16 bytes (half the required size)
    short = b64.b64encode(b"\x00" * 16).decode()
    with pytest.raises(ValueError, match="32 bytes"):
        sovereign_identity.build_did_key_from_ed25519(short)


def test_did_key_deterministic():
    """HAPPY: same pubkey always produces same did:key."""
    import base64 as b64

    pubkey = b64.b64encode(b"\xab" * 32).decode()
    did1 = sovereign_identity.build_did_key_from_ed25519(pubkey)
    did2 = sovereign_identity.build_did_key_from_ed25519(pubkey)
    assert did1 == did2


# ── R4 + R6: no-silent-failure in identity paths ────────────────


def test_build_did_key_raises_on_undecodable_input():
    """FAILURE (R4): garbage input raises — the old code returned a
    malformed `did:key:{b64-prefix}` that extract could never round-trip."""
    with pytest.raises(Exception):
        # "!!!!" survives base64's lenient char-filtering as 0 bytes → ValueError;
        # other garbage raises binascii.Error directly. Either way: no return.
        sovereign_identity.build_did_key_from_ed25519("!!!!")


def test_build_did_key_never_returns_malformed_fallback():
    """ADVERSARIAL (R4): for a corpus of invalid inputs, the builder must
    raise every time — the malformed `did:key:` fallback is gone."""
    invalid_inputs = ["", "not-a-key", "%%%", "a" * 31, base64.b64encode(b"\x01" * 33).decode()]
    for bad in invalid_inputs:
        with pytest.raises(Exception):
            sovereign_identity.build_did_key_from_ed25519(bad)


def test_try_build_did_key_valid_key_matches_strict_builder():
    """HAPPY: the lenient variant equals the strict builder on valid input."""
    kp = sovereign_identity.generate_ed25519_keypair("alice")
    assert sovereign_identity.try_build_did_key_from_ed25519(
        kp["public_key"]
    ) == sovereign_identity.build_did_key_from_ed25519(kp["public_key"])


def test_try_build_did_key_returns_none_and_logs_on_junk(capsys):
    """EDGE (R4+R6): non-Ed25519 material → None, with the reason logged
    (never a malformed DID, never silent)."""
    assert sovereign_identity.try_build_did_key_from_ed25519("legacy-hmac-key") is None
    out = capsys.readouterr().out
    assert "not did:key material" in out


def test_ed25519_verify_logs_reason_on_malformed_material(capsys):
    """R6: undecodable key/signature still denies, but logs the reason."""
    assert sovereign_identity.ed25519_verify("msg", "badsig==", "badkey==") is False
    out = capsys.readouterr().out
    assert "[Identity][deny]" in out
    assert "malformed key/signature material" in out


def test_ed25519_verify_logs_reason_on_bad_signature(capsys):
    """R6: a signature that doesn't verify denies with a logged reason."""
    kp = sovereign_identity.generate_ed25519_keypair("alice")
    other = sovereign_identity.generate_ed25519_keypair("mallory")
    sig = sovereign_identity.ed25519_sign("msg", other["private_key"])
    assert sovereign_identity.ed25519_verify("msg", sig, kp["public_key"]) is False
    out = capsys.readouterr().out
    assert "[Identity][deny]" in out
    assert "does not verify" in out
