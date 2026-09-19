"""
R1-R10 tests for auth_verify.replace_agent_key — the rotation-safe
pubkey overwrite.

Discovered live 2026-04-22: store_agent_key uses OR-fallback, so calling
it after a rotation with only the new public_key kept the old
ed25519_pubkey in place. Signing with the new key then failed because
verify_request reads ed25519_pubkey for scheme=ed25519.

This test file pins the invariant that replace_agent_key wipes every
stored key slot.
"""

from __future__ import annotations

import auth_verify


def _reset():
    auth_verify._agent_keys.clear()


def test_R1_forgery_after_replace_old_key_cannot_verify():
    """After replace_agent_key, the OLD ed25519_pubkey is gone.
    verify_request reading against the new key can't match the old."""
    _reset()
    auth_verify.store_agent_key("alice", "old_pub", ed25519_pubkey="old_ed_pub")
    assert auth_verify._agent_keys["alice"]["ed25519_pubkey"] == "old_ed_pub"

    auth_verify.replace_agent_key("alice", "new_pub")
    assert auth_verify._agent_keys["alice"]["ed25519_pubkey"] == "new_pub"


def test_R4_authz_replace_wipes_all_slots():
    """HMAC signing_secret must also be invalidated — rotation means
    the whole identity changed, not just one scheme."""
    _reset()
    auth_verify.store_agent_key("alice", "old_pub", signing_secret="old_secret", ed25519_pubkey="old_ed")

    auth_verify.replace_agent_key("alice", "new_pub")
    assert auth_verify._agent_keys["alice"]["public_key"] == "new_pub"
    assert auth_verify._agent_keys["alice"]["ed25519_pubkey"] == "new_pub"
    assert auth_verify._agent_keys["alice"]["signing_secret"] == ""


def test_R5_boundary_replace_on_agent_with_no_stored_key():
    """replace_agent_key on an unknown agent creates the entry fresh."""
    _reset()
    auth_verify.replace_agent_key("newcomer", "pub")
    assert auth_verify._agent_keys["newcomer"] == {
        "public_key": "pub",
        "signing_secret": "",
        "ed25519_pubkey": "pub",
    }


def test_R10_persistence_store_agent_key_still_uses_or_fallback():
    """Regression guard: store_agent_key OR-fallback behavior is preserved.
    The bug was NOT with store_agent_key itself — it's semantically correct
    for TOFU/registration paths where partial updates are expected.
    Rotation needs replace_agent_key, not a store_agent_key change.
    """
    _reset()
    auth_verify.store_agent_key("alice", "pub_a", ed25519_pubkey="ed_a")
    # Partial update: only supply public_key; ed25519_pubkey must survive
    auth_verify.store_agent_key("alice", "pub_b")
    assert auth_verify._agent_keys["alice"]["public_key"] == "pub_b"
    assert auth_verify._agent_keys["alice"]["ed25519_pubkey"] == "ed_a"


def test_happy_replace_enables_new_key_verification():
    """End-to-end: after replace_agent_key with pubkey X, verify_request
    reading _agent_keys[agent_id]["ed25519_pubkey"] sees X (not the old
    value). This is the exact invariant that the rotation handler needs."""
    _reset()
    auth_verify.store_agent_key("alice", "OLD", ed25519_pubkey="OLD")
    auth_verify.replace_agent_key("alice", "NEW")

    # verify_request's Ed25519 path reads this exact field
    stored = auth_verify._agent_keys.get("alice", {})
    assert stored.get("ed25519_pubkey") == "NEW"
    assert stored.get("public_key") == "NEW"
