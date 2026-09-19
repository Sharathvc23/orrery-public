"""
Security tests for crypto.py — SC-2: Encrypted Key Storage.

SEC-05: Encrypt→decrypt roundtrip
SEC-06: Wrong passphrase fails cleanly (FAILURE)
SEC-07: Corrupted ciphertext detected (ADVERSARIAL)
SEC-08: Salt unique per encryption (EDGE)
"""

import base64
import time

import pytest

from community_member.crypto import (
    decrypt_value,
    derive_key,
    encrypt_value,
    generate_keypair,
    sign_challenge,
    sign_message,
    verify_challenge,
    verify_signature,
)

# ═══════════════════════════════════════════════
# SEC-05: Encrypt/decrypt roundtrip
# ═══════════════════════════════════════════════


def test_encrypt_decrypt_roundtrip():
    """HAPPY: encrypt then decrypt returns original value."""
    plaintext = "EXAMPLE-not-a-real-secret-value-for-roundtrip"
    passphrase = "my-strong-passphrase"
    encrypted = encrypt_value(plaintext, passphrase)
    decrypted = decrypt_value(encrypted, passphrase)
    assert decrypted == plaintext


def test_encrypt_decrypt_empty_string():
    """EDGE: empty plaintext raises."""
    with pytest.raises(ValueError, match="Nothing to encrypt"):
        encrypt_value("", "pass")


def test_encrypt_decrypt_long_value():
    """EDGE: long value encrypts and decrypts correctly."""
    plaintext = "A" * 10000
    encrypted = encrypt_value(plaintext, "pass")
    assert decrypt_value(encrypted, "pass") == plaintext


def test_encrypt_decrypt_unicode():
    """EDGE: unicode value roundtrips."""
    plaintext = "こんにちは世界 🌍 émojis"
    encrypted = encrypt_value(plaintext, "pass")
    assert decrypt_value(encrypted, "pass") == plaintext


# ═══════════════════════════════════════════════
# SEC-06: Wrong passphrase fails cleanly
# ═══════════════════════════════════════════════


def test_wrong_passphrase_raises():
    """FAILURE: wrong passphrase raises ValueError, not garbage."""
    encrypted = encrypt_value("secret", "correct-pass")
    with pytest.raises(ValueError, match="wrong passphrase or tampered"):
        decrypt_value(encrypted, "wrong-pass")


def test_similar_passphrase_fails():
    """ADVERSARIAL: off-by-one passphrase still fails."""
    encrypted = encrypt_value("secret", "passphrase1")
    with pytest.raises(ValueError):
        decrypt_value(encrypted, "passphrase2")


# ═══════════════════════════════════════════════
# SEC-07: Corrupted ciphertext detected
# ═══════════════════════════════════════════════


def test_tampered_ciphertext_detected():
    """ADVERSARIAL: modified ciphertext fails authentication."""
    encrypted = encrypt_value("secret", "pass")
    # Flip a byte in the ciphertext
    ct = base64.b64decode(encrypted["ciphertext"])
    tampered = bytes([ct[0] ^ 0xFF]) + ct[1:]
    encrypted["ciphertext"] = base64.b64encode(tampered).decode()
    with pytest.raises(ValueError, match="wrong passphrase or tampered"):
        decrypt_value(encrypted, "pass")


def test_tampered_tag_detected():
    """ADVERSARIAL: modified tag fails."""
    encrypted = encrypt_value("secret", "pass")
    encrypted["tag"] = base64.b64encode(b"fake" * 8).decode()
    with pytest.raises(ValueError):
        decrypt_value(encrypted, "pass")


def test_missing_fields_detected():
    """ADVERSARIAL: missing fields raise ValueError."""
    with pytest.raises(ValueError, match="Invalid encrypted data"):
        decrypt_value({"ciphertext": "abc"}, "pass")


def test_garbage_base64_detected():
    """ADVERSARIAL: non-base64 data raises."""
    with pytest.raises(ValueError):
        decrypt_value({"ciphertext": "not-base64!!!", "salt": "x", "nonce": "x", "tag": "x"}, "pass")


# ═══════════════════════════════════════════════
# SEC-08: Salt unique per encryption
# ═══════════════════════════════════════════════


def test_salt_unique():
    """EDGE: two encryptions of the same value produce different salts."""
    e1 = encrypt_value("same", "same-pass")
    e2 = encrypt_value("same", "same-pass")
    assert e1["salt"] != e2["salt"]


def test_nonce_unique():
    """EDGE: two encryptions produce different nonces."""
    e1 = encrypt_value("same", "same-pass")
    e2 = encrypt_value("same", "same-pass")
    assert e1["nonce"] != e2["nonce"]


def test_ciphertext_different():
    """EDGE: same plaintext + same passphrase → different ciphertext (due to random salt/nonce)."""
    e1 = encrypt_value("same", "same-pass")
    e2 = encrypt_value("same", "same-pass")
    assert e1["ciphertext"] != e2["ciphertext"]


# ═══════════════════════════════════════════════
# Key derivation
# ═══════════════════════════════════════════════


def test_derive_key_deterministic_with_salt():
    """HAPPY: same passphrase + same salt → same key."""
    key1, salt = derive_key("pass")
    key2, _ = derive_key("pass", salt)
    assert key1 == key2


def test_derive_key_different_passphrases():
    """EDGE: different passphrases → different keys."""
    key1, salt = derive_key("pass1")
    key2, _ = derive_key("pass2", salt)
    assert key1 != key2


def test_derive_key_empty_passphrase_rejected():
    """FAILURE: empty passphrase raises."""
    with pytest.raises(ValueError, match="empty"):
        derive_key("")


# ═══════════════════════════════════════════════
# Signing
# ═══════════════════════════════════════════════


def test_sign_verify_valid():
    """HAPPY: sign and verify with correct key."""
    kp = generate_keypair()
    sig = sign_message("hello", kp["private_key"])
    assert verify_signature("hello", sig, kp["public_key"], kp["private_key"])


def test_sign_verify_wrong_key():
    """ADVERSARIAL: verify with wrong key fails."""
    kp1 = generate_keypair()
    kp2 = generate_keypair()
    sig = sign_message("hello", kp1["private_key"])
    assert not verify_signature("hello", sig, kp2["public_key"], kp2["private_key"])


def test_sign_verify_tampered_message():
    """ADVERSARIAL: tampered message fails verification."""
    kp = generate_keypair()
    sig = sign_message("hello", kp["private_key"])
    assert not verify_signature("TAMPERED", sig, kp["public_key"], kp["private_key"])


def test_sign_verify_forged_signature():
    """ADVERSARIAL: forged signature fails."""
    kp = generate_keypair()
    assert not verify_signature("hello", "ZmFrZQ==", kp["public_key"], kp["private_key"])


def test_keypair_unique():
    """EDGE: every keypair is unique."""
    kp1 = generate_keypair()
    kp2 = generate_keypair()
    assert kp1["private_key"] != kp2["private_key"]
    assert kp1["public_key"] != kp2["public_key"]


# ═══════════════════════════════════════════════
# Challenge-response
# ═══════════════════════════════════════════════


def test_challenge_response_valid():
    """HAPPY: valid challenge-response passes."""
    kp = generate_keypair()
    signed = sign_challenge("nonce123", kp["private_key"], "agent-1")
    assert verify_challenge(signed, "nonce123", "agent-1", kp["private_key"])


def test_challenge_wrong_nonce():
    """ADVERSARIAL: wrong nonce fails."""
    kp = generate_keypair()
    signed = sign_challenge("nonce123", kp["private_key"], "agent-1")
    assert not verify_challenge(signed, "WRONG", "agent-1", kp["private_key"])


def test_challenge_wrong_agent():
    """ADVERSARIAL: wrong agent_id fails."""
    kp = generate_keypair()
    signed = sign_challenge("nonce123", kp["private_key"], "agent-1")
    assert not verify_challenge(signed, "nonce123", "IMPERSONATOR", kp["private_key"])


def test_challenge_expired():
    """EDGE: challenge with old timestamp rejected."""
    kp = generate_keypair()
    # Manually create a signed challenge with a 10-minute-old timestamp
    old_timestamp = str(int(time.time()) - 600)
    message = f"challenge:nonce123:agent-1:{old_timestamp}"
    sig = sign_message(message, kp["private_key"])
    signed = base64.b64encode(f"{sig}:{old_timestamp}".encode()).decode()
    # Should reject because 600 > 300 (max_age_seconds)
    assert not verify_challenge(signed, "nonce123", "agent-1", kp["private_key"], max_age_seconds=300)


# ═══════════════════════════════════════════════
# S2: construction is what the docs now say (HMAC etMAC), and the
#     PBKDF2 cost / wire format is pinned so a bump can't silently brick vaults
# ═══════════════════════════════════════════════


def test_S2_wire_format_and_kdf_params_are_pinned():
    """blobs are versioned and carry their KDF params. This pins the v2
    shape, the cipher/KDF identifiers, and BOTH iteration constants — the live
    default (may be bumped deliberately) and the FROZEN legacy constant
    (must never change: it is what legacy vaults were sealed with). Any
    change here must be a deliberate, migration-reviewed edit."""
    from community_member import crypto

    assert crypto.PBKDF2_ITERATIONS == 100_000
    assert crypto.LEGACY_PBKDF2_ITERATIONS == 100_000  # FROZEN — never change
    assert crypto.BLOB_VERSION == 2
    assert crypto.KDF_NAME == "pbkdf2-sha256"
    assert crypto.CIPHER_NAME == "hmac-sha256-etm-v1"
    blob = encrypt_value("secret", "pass")
    assert set(blob) == {"v", "kdf", "cipher", "ciphertext", "salt", "nonce", "tag"}
    assert blob["v"] == 2
    assert blob["kdf"] == {"name": "pbkdf2-sha256", "iterations": crypto.PBKDF2_ITERATIONS}
    assert blob["cipher"] == "hmac-sha256-etm-v1"


# A REAL legacy blob (version-less, sealed at the frozen 100k cost) —
# hardcoded so the legacy-read path is pinned against the actual historical
# artifact, not a reconstruction. It must decrypt forever.
GOLDEN_LEGACY_PASSPHRASE = "golden-legacy-pass"
GOLDEN_LEGACY_PLAINTEXT = "the-legacy-vault-secret"
GOLDEN_LEGACY_BLOB = {
    "ciphertext": "AigSyFlgQCBW5D70kI8rnRL+7Le0A3o=",
    "salt": "3FKt5I/gd2YrIy9zguVmyQJgH3Of9JsE0clf2F5gnQQ=",
    "nonce": "YaKGF8IPakOR/PmKG1JX5g==",
    "tag": "cyOXoU35O9GqQOPmuq1N4dxdP+JZcgx013kIfbJtDgM=",
}


def test_S2_golden_legacy_blob_decrypts_forever():
    """the hardcoded legacy blob opens via the frozen legacy path."""
    from community_member import crypto

    assert crypto.is_legacy_blob(GOLDEN_LEGACY_BLOB)
    assert decrypt_value(dict(GOLDEN_LEGACY_BLOB), GOLDEN_LEGACY_PASSPHRASE) == GOLDEN_LEGACY_PLAINTEXT


def test_S2_cost_bump_no_longer_bricks_vaults(monkeypatch):
    """That change's whole point: bump the LIVE cost and (a) old v2 blobs still
    decrypt with their recorded params, (b) legacy blobs still decrypt via the
    frozen constant, (c) new blobs record the new cost."""
    from community_member import crypto

    old_blob = encrypt_value("secret", "pass")
    monkeypatch.setattr(crypto, "PBKDF2_ITERATIONS", 200_000)
    assert decrypt_value(old_blob, "pass") == "secret"
    assert decrypt_value(dict(GOLDEN_LEGACY_BLOB), GOLDEN_LEGACY_PASSPHRASE) == GOLDEN_LEGACY_PLAINTEXT
    new_blob = crypto.encrypt_value("secret", "pass")
    assert new_blob["kdf"]["iterations"] == 200_000
    assert crypto.decrypt_value(new_blob, "pass") == "secret"


def test_S2_unknown_version_kdf_cipher_fail_loud():
    """forward-compat failures are explicit, never a silent downgrade."""
    blob = encrypt_value("secret", "pass")
    for mutate in (
        {"v": 3},
        {"cipher": "aes-256-gcm"},
        {"kdf": {"name": "argon2id", "iterations": 100_000}},
    ):
        bad = {**blob, **mutate}
        with pytest.raises(ValueError, match="Unsupported"):
            decrypt_value(bad, "pass")


def test_S2_tampered_or_absurd_iterations_rejected():
    """an out-of-range per-blob cost is malformed (rejected BEFORE any
    KDF work — the DoS guard); an in-range tampered cost fails the MAC."""
    blob = encrypt_value("secret", "pass")
    for bad_iters in (1, 49_999, 10_000_001, 10**12, "100000", None):
        bad = {**blob, "kdf": {"name": "pbkdf2-sha256", "iterations": bad_iters}}
        with pytest.raises(ValueError, match="out of range"):
            decrypt_value(bad, "pass")
    tampered = {**blob, "kdf": {"name": "pbkdf2-sha256", "iterations": 60_000}}
    with pytest.raises(ValueError, match="wrong passphrase or tampered"):
        decrypt_value(tampered, "pass")


def test_S2_is_not_aes_gcm_but_is_authenticated():
    """Backs the corrected docs: the tag is a real integrity check (a flipped
    tag is rejected) — i.e. this is genuine authenticated encryption, just not
    AES-GCM."""
    blob = encrypt_value("secret", "pass")
    tag = base64.b64decode(blob["tag"])
    blob["tag"] = base64.b64encode(bytes([tag[0] ^ 0xFF]) + tag[1:]).decode()
    with pytest.raises(ValueError, match="wrong passphrase or tampered"):
        decrypt_value(blob, "pass")
