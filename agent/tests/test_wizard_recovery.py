"""P0 — signup mints the identity FROM a BIP39 recovery phrase.

Before this, `wizard.new_member_flow` generated a RANDOM Ed25519 keypair via
`config.ensure_keypair()` and never minted or displayed a phrase — yet the CLI
(cli.py) advertises "the BIP39 recovery phrase you saved at signup is the only
way to restore this identity". These tests pin the fix: the phrase shown at
signup deterministically restores the exact identity.

Classification: HAPPY / REGRESSION.
"""

from __future__ import annotations

from community_member import recovery
from community_member.config import Config
from community_member.wizard import _generate_identity_with_recovery, _show_recovery_phrase


def test_signup_identity_is_restorable_from_the_displayed_phrase():
    """THE claim: recovering from the phrase shown at signup reproduces the
    exact keypair the agent signs with — not a different key."""
    config = Config()
    phrase = _generate_identity_with_recovery(config)

    assert phrase is not None, "signup must mint a recovery phrase"
    assert len(phrase.split()) == 24, "256-bit strength → 24 words"
    assert config.private_key and config.public_key, "identity keys must be set from the phrase"

    restored = recovery.recover_from_mnemonic(phrase)
    assert restored.private_key_b64 == config.private_key
    assert restored.public_key_b64 == config.public_key


def test_two_signups_get_distinct_phrases_and_identities():
    """Each signup mints a fresh phrase → a distinct identity."""
    a, b = Config(), Config()
    pa = _generate_identity_with_recovery(a)
    pb = _generate_identity_with_recovery(b)
    assert pa != pb
    assert a.public_key != b.public_key


def test_show_recovery_phrase_renders_without_raising(monkeypatch):
    """The one-time display must render + acknowledge non-interactively (no hang)."""
    import community_member.wizard as wiz

    monkeypatch.setattr(wiz.Confirm, "ask", lambda *a, **k: True)
    _show_recovery_phrase(recovery.generate_mnemonic())
