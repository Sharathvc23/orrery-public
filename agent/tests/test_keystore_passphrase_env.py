"""COMMUNITY_MEMBER_PASSPHRASE env fallback — headless / Railway identity.

BACKEND_PASSPHRASE normally prompts via getpass, which is impossible on a
no-tty service (Railway). With COMMUNITY_MEMBER_KEYSTORE=passphrase +
COMMUNITY_MEMBER_PASSPHRASE set, the keystore unlocks the persisted vault
NON-INTERACTIVELY, so the agent's Ed25519 identity (its did:key) is stable
across redeploys (given a persistent COMMUNITY_MEMBER_HOME volume) instead of
regenerating and orphaning its org/NEST/host39 registrations.

The interactive default is unchanged — these only exercise the env path.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from community_member import keystore

_GOOD_PASS = "railway-stable-passphrase"  # ≥ _MIN_PASSPHRASE (10)
_KEY_B64 = "Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZmdoaWprbG0="  # any stable b64


@pytest.fixture
def passphrase_keystore(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """passphrase backend + the env passphrase + a tmp keystore dir."""
    monkeypatch.setenv("COMMUNITY_MEMBER_KEYSTORE", "passphrase")
    monkeypatch.setenv("COMMUNITY_MEMBER_PASSPHRASE", _GOOD_PASS)
    keystore.reset_for_tests(dir_override=tmp_path)
    yield tmp_path
    keystore.reset_for_tests()


def _no_prompt(monkeypatch):
    """Make any getpass call an instant failure — proves we never prompted."""

    def _boom(*_a, **_k):
        raise AssertionError("getpass was called — env passphrase did not take effect")

    monkeypatch.setattr(keystore.getpass, "getpass", _boom)


def test_env_passphrase_unlocks_without_prompting(passphrase_keystore, monkeypatch):
    _no_prompt(monkeypatch)
    keystore.store_private_key("agent-x", _KEY_B64)
    assert keystore.load_private_key("agent-x") == _KEY_B64  # round-trips, no tty


def test_env_passphrase_stable_identity_across_restart(passphrase_keystore, monkeypatch):
    """The same env passphrase reopens the SAME persisted vault → SAME key
    (hence SAME did:key) after a simulated restart — the whole point."""
    _no_prompt(monkeypatch)
    keystore.store_private_key("agent-x", _KEY_B64)

    # Simulate a redeploy: drop the in-RAM cache + backend memo, KEEP the dir/vault.
    keystore.reset_for_tests(dir_override=passphrase_keystore)
    monkeypatch.setenv("COMMUNITY_MEMBER_KEYSTORE", "passphrase")
    monkeypatch.setenv("COMMUNITY_MEMBER_PASSPHRASE", _GOOD_PASS)

    assert keystore.load_private_key("agent-x") == _KEY_B64  # identical key survives


def test_wrong_env_passphrase_on_existing_vault_raises(passphrase_keystore, monkeypatch):
    """A bad env passphrase against an existing vault fails LOUD — it must not
    silently fall through to a prompt that would hang the service."""
    keystore.store_private_key("agent-x", _KEY_B64)

    keystore.reset_for_tests(dir_override=passphrase_keystore)
    monkeypatch.setenv("COMMUNITY_MEMBER_KEYSTORE", "passphrase")
    monkeypatch.setenv("COMMUNITY_MEMBER_PASSPHRASE", "the-wrong-passphrase")
    _no_prompt(monkeypatch)

    with pytest.raises(keystore.WrongPassphraseError):
        keystore.load_private_key("agent-x")


def test_short_env_passphrase_rejected(tmp_path, monkeypatch):
    """A too-short env passphrase on a fresh vault is rejected, not stored."""
    monkeypatch.setenv("COMMUNITY_MEMBER_KEYSTORE", "passphrase")
    monkeypatch.setenv("COMMUNITY_MEMBER_PASSPHRASE", "short")  # < 10
    keystore.reset_for_tests(dir_override=tmp_path)
    _no_prompt(monkeypatch)
    try:
        with pytest.raises(keystore.WrongPassphraseError):
            keystore.store_private_key("agent-x", _KEY_B64)
    finally:
        keystore.reset_for_tests()
