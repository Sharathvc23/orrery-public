"""Headless identity must NOT re-mint on redeploy (the core invariant).

On a redeploy the keystore restores the PRIVATE key, but config.json (which
carries the public key) may be absent on the pure-env path. If public_key stays
empty, ``Config.has_keypair()`` is False and ``ensure_keypair()`` mints a BRAND
NEW keypair → a new did:key → orphaned org/NEST/host39 registrations. The fix is
to derive public_key from the restored private key before ``ensure_keypair``.
"""

from __future__ import annotations

from community_member import crypto
from community_member.config import Config


def test_derive_public_matches_generation() -> None:
    kp = crypto.generate_ed25519_keypair()
    assert crypto.ed25519_public_from_private(kp["private_key"]) == kp["public_key"]


def test_restored_private_plus_derived_public_stops_remint() -> None:
    """Simulate the redeploy path: only the private key is restored (config.json
    absent). Deriving the public key first must make ensure_keypair a no-op."""
    kp = crypto.generate_ed25519_keypair()

    config = Config()
    config.agent_id = "TEST-headless"
    config.private_key = kp["private_key"]  # restored from keystore
    config.public_key = ""  # config.json absent on the pure-env path
    assert config.has_keypair() is False  # the re-mint trap

    # The fix: derive the public key before ensure_keypair.
    config.public_key = crypto.ed25519_public_from_private(config.private_key)
    assert config.has_keypair() is True

    config.ensure_keypair()  # must NOT re-mint now
    assert config.private_key == kp["private_key"]  # identity preserved
    assert config.public_key == kp["public_key"]


def test_without_derivation_ensure_keypair_would_remint() -> None:
    """Proves the bug exists absent the fix: empty public_key → ensure_keypair
    overwrites the restored private key with a fresh identity."""
    kp = crypto.generate_ed25519_keypair()
    config = Config()
    config.agent_id = "TEST-headless"
    config.private_key = kp["private_key"]
    config.public_key = ""  # no derivation
    config.ensure_keypair()
    assert config.private_key != kp["private_key"]  # re-minted — a DIFFERENT identity
