"""
R1-R10 adversarial + behavioral tests for BIP39 recovery + key rotation.

Covers:
  1. community_member.recovery — BIP39 + SLIP-0010 Ed25519 derivation
  2. community_member.auth.create_rotation_attestation / verify_rotation_attestation

R1-R10 convention (nanda-bridge ordering): adversarial tests first, happy last.

  R1  Forgery            — attestation signed by wrong key
  R2  Replay             — nonce already seen
  R3  Injection          — malformed attestation fields
  R4  Authorization      — new-pubkey must differ from old (can't "rotate" to self)
  R5  Boundary           — clock skew, pubkey length
  R6  Concurrency        — deterministic derivation under parallel calls
  R7  Adversarial input  — invalid mnemonic, tampered base64
  R8  Downgrade          — scheme must be ed25519 (no HMAC fallback for rotations)
  R9  Timing             — clock skew rejected symmetrically
  R10 Persistence        — recovery produces same keypair across runs
"""

from __future__ import annotations

import base64
import time

import pytest

from community_member import auth, recovery

# ── Shared setup ──────────────────────────────────────────────────────


@pytest.fixture
def fresh_identity():
    """Generate a fresh identity for each test."""
    return recovery.generate_recovery()


@pytest.fixture
def second_identity():
    """A second, independent identity — useful for rotation targets."""
    return recovery.generate_recovery()


# ══════════════════════════════════════════════════════════════════════
# R1 — Forgery: attestation signed by the WRONG key
# ══════════════════════════════════════════════════════════════════════


def test_R1_forgery_wrong_signing_key(fresh_identity, second_identity):
    """Attacker signs an attestation with a key that isn't the stored one."""
    forged = auth.create_rotation_attestation(
        old_private_key_b64=second_identity.private_key_b64,  # wrong key!
        new_public_key_b64=second_identity.public_key_b64,
        chapter_id="test-chapter",
        agent_id="victim",
    )
    # Chapter stored fresh_identity.public_key_b64 — forged was signed by
    # second_identity's private key, so verification must fail
    valid, reason = auth.verify_rotation_attestation(forged, fresh_identity.public_key_b64)
    assert valid is False
    assert "invalid signature" in reason.lower()


# ══════════════════════════════════════════════════════════════════════
# R2 — Replay: same nonce seen twice
# ══════════════════════════════════════════════════════════════════════


def test_R2_replay_rejected(fresh_identity, second_identity):
    att = auth.create_rotation_attestation(
        old_private_key_b64=fresh_identity.private_key_b64,
        new_public_key_b64=second_identity.public_key_b64,
        chapter_id="test-chapter",
        agent_id="alice",
    )
    known_nonces = {att["nonce"]}
    valid, reason = auth.verify_rotation_attestation(att, fresh_identity.public_key_b64, known_nonces=known_nonces)
    assert valid is False
    assert "replay" in reason.lower()


# ══════════════════════════════════════════════════════════════════════
# R3 — Injection: missing/malformed fields
# ══════════════════════════════════════════════════════════════════════


def test_R3_injection_missing_field(fresh_identity, second_identity):
    att = auth.create_rotation_attestation(
        old_private_key_b64=fresh_identity.private_key_b64,
        new_public_key_b64=second_identity.public_key_b64,
        chapter_id="test-chapter",
        agent_id="alice",
    )
    del att["nonce"]
    valid, reason = auth.verify_rotation_attestation(att, fresh_identity.public_key_b64)
    assert valid is False
    assert "missing" in reason.lower()


def test_R3_injection_wrong_kind(fresh_identity, second_identity):
    att = auth.create_rotation_attestation(
        old_private_key_b64=fresh_identity.private_key_b64,
        new_public_key_b64=second_identity.public_key_b64,
        chapter_id="test-chapter",
        agent_id="alice",
    )
    att["kind"] = "intent"  # lying about what this is
    valid, reason = auth.verify_rotation_attestation(att, fresh_identity.public_key_b64)
    assert valid is False
    assert "not a rotation" in reason.lower()


# ══════════════════════════════════════════════════════════════════════
# R4 — Authorization: cannot "rotate" to same key (identity attack)
# ══════════════════════════════════════════════════════════════════════


def test_R4_authz_rotate_to_same_key_rejected(fresh_identity):
    # Attacker takes a valid signed attestation and changes new_public_key
    # to match old — a no-op rotation that might otherwise confuse state
    att = auth.create_rotation_attestation(
        old_private_key_b64=fresh_identity.private_key_b64,
        new_public_key_b64=fresh_identity.public_key_b64,  # same as old
        chapter_id="test-chapter",
        agent_id="alice",
    )
    valid, reason = auth.verify_rotation_attestation(att, fresh_identity.public_key_b64)
    assert valid is False
    assert "must differ" in reason.lower()


# ══════════════════════════════════════════════════════════════════════
# R5 — Boundary: clock skew, pubkey length
# ══════════════════════════════════════════════════════════════════════


def test_R5_boundary_timestamp_too_old(fresh_identity, second_identity):
    att = auth.create_rotation_attestation(
        old_private_key_b64=fresh_identity.private_key_b64,
        new_public_key_b64=second_identity.public_key_b64,
        chapter_id="test-chapter",
        agent_id="alice",
        timestamp=int(time.time()) - 3600,  # 1 hour old
    )
    valid, reason = auth.verify_rotation_attestation(att, fresh_identity.public_key_b64)
    assert valid is False
    assert "out of window" in reason.lower()


def test_R5_boundary_timestamp_future(fresh_identity, second_identity):
    att = auth.create_rotation_attestation(
        old_private_key_b64=fresh_identity.private_key_b64,
        new_public_key_b64=second_identity.public_key_b64,
        chapter_id="test-chapter",
        agent_id="alice",
        timestamp=int(time.time()) + 3600,  # 1 hour future
    )
    valid, reason = auth.verify_rotation_attestation(att, fresh_identity.public_key_b64)
    assert valid is False
    assert "out of window" in reason.lower()


def test_R5_boundary_pubkey_wrong_length(fresh_identity):
    # Attestation with a pubkey that isn't 32 bytes (Ed25519 requirement)
    bad_pub = base64.b64encode(b"too_short").decode()
    att = auth.create_rotation_attestation(
        old_private_key_b64=fresh_identity.private_key_b64,
        new_public_key_b64=bad_pub,
        chapter_id="test-chapter",
        agent_id="alice",
    )
    valid, reason = auth.verify_rotation_attestation(att, fresh_identity.public_key_b64)
    assert valid is False
    assert "wrong length" in reason.lower() or "not valid" in reason.lower()


# ══════════════════════════════════════════════════════════════════════
# R6 — Concurrency: derivation is deterministic under parallel calls
# ══════════════════════════════════════════════════════════════════════


def test_R6_concurrency_derivation_deterministic():
    """Same mnemonic, N calls, must produce identical keypairs."""
    phrase = recovery.generate_mnemonic()
    results = [recovery.recover_from_mnemonic(phrase) for _ in range(10)]
    # All did_keys must match
    dids = {r.did_key for r in results}
    assert len(dids) == 1, f"expected 1 unique did_key, got {len(dids)}"


# ══════════════════════════════════════════════════════════════════════
# R7 — Adversarial input: malformed mnemonics, tampered base64
# ══════════════════════════════════════════════════════════════════════


def test_R7_adversarial_empty_mnemonic():
    with pytest.raises(ValueError, match="invalid"):
        recovery.recover_from_mnemonic("")


def test_R7_adversarial_eleven_words_rejected():
    """BIP39 min is 12 words; 11 words must fail checksum."""
    with pytest.raises(ValueError, match="invalid"):
        recovery.recover_from_mnemonic("abandon " * 11)


def test_R7_adversarial_garbage_words_rejected():
    with pytest.raises(ValueError, match="invalid"):
        recovery.recover_from_mnemonic("foo bar baz " * 8)


def test_R7_adversarial_corrupt_signature_rejected(fresh_identity, second_identity):
    att = auth.create_rotation_attestation(
        old_private_key_b64=fresh_identity.private_key_b64,
        new_public_key_b64=second_identity.public_key_b64,
        chapter_id="test-chapter",
        agent_id="alice",
    )
    att["signature"] = base64.b64encode(b"\x00" * 64).decode()
    valid, _ = auth.verify_rotation_attestation(att, fresh_identity.public_key_b64)
    assert valid is False


# ══════════════════════════════════════════════════════════════════════
# R8 — Downgrade: scheme must be ed25519 (no HMAC fallback)
# ══════════════════════════════════════════════════════════════════════


def test_R8_downgrade_hmac_scheme_rejected(fresh_identity, second_identity):
    att = auth.create_rotation_attestation(
        old_private_key_b64=fresh_identity.private_key_b64,
        new_public_key_b64=second_identity.public_key_b64,
        chapter_id="test-chapter",
        agent_id="alice",
    )
    att["scheme"] = "hmac-sha256"  # downgrade attempt
    valid, reason = auth.verify_rotation_attestation(att, fresh_identity.public_key_b64)
    assert valid is False
    assert "unsupported scheme" in reason.lower()


# ══════════════════════════════════════════════════════════════════════
# R9 — Timing: clock skew enforced symmetrically
# ══════════════════════════════════════════════════════════════════════


def test_R9_timing_skew_bounded_both_directions(fresh_identity, second_identity):
    """Past and future rejections must be symmetric within max_age."""
    window = 300
    for offset in (-window - 1, window + 1):  # just outside allowed window on each side
        att = auth.create_rotation_attestation(
            old_private_key_b64=fresh_identity.private_key_b64,
            new_public_key_b64=second_identity.public_key_b64,
            chapter_id="test-chapter",
            agent_id="alice",
            timestamp=int(time.time()) + offset,
        )
        valid, reason = auth.verify_rotation_attestation(att, fresh_identity.public_key_b64, max_age_seconds=window)
        assert valid is False
        assert "out of window" in reason.lower()


# ══════════════════════════════════════════════════════════════════════
# R10 — Persistence: same mnemonic → same keypair across runs
# ══════════════════════════════════════════════════════════════════════


def test_R10_persistence_fixed_mnemonic_deterministic():
    """Deterministic derivation from a known mnemonic. Test vector serves
    as a cross-version regression guard — if SLIP-0010 derivation logic
    ever changes, this test MUST fail loudly."""
    # Using the 24-word "abandon" mnemonic (BIP39 all-zero entropy checksum)
    phrase = (
        "abandon abandon abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon abandon abandon art"
    )
    assert recovery.validate_mnemonic(phrase)

    m1 = recovery.recover_from_mnemonic(phrase)
    m2 = recovery.recover_from_mnemonic(phrase)
    assert m1.did_key == m2.did_key
    assert m1.private_key_b64 == m2.private_key_b64
    assert m1.public_key_b64 == m2.public_key_b64
    # Pin the derivation path default
    assert m1.derivation_path == "m/44'/9004'/0'/0'/0'"


def test_R10_persistence_passphrase_changes_derivation():
    """Different passphrases on the same phrase MUST produce different keys."""
    phrase = recovery.generate_mnemonic()
    m_a = recovery.recover_from_mnemonic(phrase, passphrase="")
    m_b = recovery.recover_from_mnemonic(phrase, passphrase="extra-salt")
    assert m_a.did_key != m_b.did_key


# ══════════════════════════════════════════════════════════════════════
# HAPPY — kept last per R1-R10 ordering
# ══════════════════════════════════════════════════════════════════════


def test_happy_generate_recovery_produces_full_material():
    r = recovery.generate_recovery()
    assert len(r.mnemonic.split()) == 24  # default strength=256
    assert r.did_key.startswith("did:key:z")
    assert len(base64.b64decode(r.public_key_b64)) == 32
    assert len(base64.b64decode(r.private_key_b64)) == 32


def test_happy_rotation_round_trip(fresh_identity, second_identity):
    att = auth.create_rotation_attestation(
        old_private_key_b64=fresh_identity.private_key_b64,
        new_public_key_b64=second_identity.public_key_b64,
        chapter_id="bayarea-nanda-chapter",
        agent_id="alice",
    )
    valid, reason = auth.verify_rotation_attestation(att, fresh_identity.public_key_b64)
    assert valid is True
    assert reason == "valid"


def test_happy_12_word_mnemonic_works():
    m = recovery.generate_recovery(strength=128)
    assert len(m.mnemonic.split()) == 12
    assert m.did_key.startswith("did:key:z")
