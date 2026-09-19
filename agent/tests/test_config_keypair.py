"""
Tests for Phase 1: Keypair generation + persistence in Config.

Tests that:
1. Config generates keypair on demand
2. Keypair persists across save/load
3. Returning member without keypair gets one (migration)
4. A2AClient receives credentials from config
"""

from community_member.config import Config


def test_config_has_no_keypair_initially():
    """EDGE: new config has no keypair."""
    config = Config()
    assert not config.has_keypair()
    assert config.private_key == ""
    assert config.public_key == ""


def test_ensure_keypair_generates():
    """HAPPY: ensure_keypair generates a valid keypair."""
    config = Config()
    config.ensure_keypair()
    assert config.has_keypair()
    assert len(config.private_key) > 10
    assert len(config.public_key) > 10


def test_ensure_keypair_idempotent():
    """EDGE: calling ensure_keypair twice doesn't overwrite."""
    config = Config()
    config.ensure_keypair()
    pk1 = config.private_key
    config.ensure_keypair()
    assert config.private_key == pk1  # Same key


def test_keypair_persists(tmp_path, monkeypatch):
    """HAPPY: keypair survives save/load cycle."""
    import community_member.config as config_mod

    monkeypatch.setattr(config_mod, "CONFIG_DIR", tmp_path)

    config = Config()
    config.agent_id = "test"
    config.chapter_url = "https://test.com"
    config.api_key = "key"
    config.ensure_keypair()
    pk = config.private_key
    pub = config.public_key
    config.save()

    loaded = Config.load()
    assert loaded.private_key == pk
    assert loaded.public_key == pub
    assert loaded.has_keypair()


def test_keypair_not_in_agent_state(tmp_path, monkeypatch):
    """ADVERSARIAL: private key never appears in agent state export."""
    import community_member.config as config_mod

    monkeypatch.setattr(config_mod, "CONFIG_DIR", tmp_path)

    config = Config()
    config.ensure_keypair()
    config.save_agent_state({"agent_id": "test", "skills": ["python"]})

    state = config.load_agent_state()
    import json

    state_str = json.dumps(state)
    assert config.private_key not in state_str
    assert "private_key" not in state_str


# ── Multi-agent: COMMUNITY_MEMBER_HOME override ──────────────────


def test_COMMUNITY_MEMBER_HOME_env_var_overrides_default(tmp_path, monkeypatch):
    """Setting COMMUNITY_MEMBER_HOME before module import points
    CONFIG_DIR at the override directory. Lets users run multiple
    sovereign agents on one machine, each with isolated state."""
    custom = tmp_path / "agent-work"
    monkeypatch.setenv("COMMUNITY_MEMBER_HOME", str(custom))
    # Re-import so the env var is read fresh.
    import importlib

    from community_member import config as config_mod

    importlib.reload(config_mod)
    try:
        assert custom.resolve() == config_mod.CONFIG_DIR
    finally:
        # Reset to default for subsequent tests.
        monkeypatch.delenv("COMMUNITY_MEMBER_HOME", raising=False)
        importlib.reload(config_mod)


def test_default_config_dir_when_env_unset(monkeypatch):
    """Without the env var, CONFIG_DIR falls back to ~/.community-member."""
    monkeypatch.delenv("COMMUNITY_MEMBER_HOME", raising=False)
    import importlib
    from pathlib import Path

    from community_member import config as config_mod

    importlib.reload(config_mod)
    expected = Path.home() / ".community-member"
    assert expected == config_mod.CONFIG_DIR


def test_env_override_with_tilde_expands(tmp_path, monkeypatch):
    """A path containing ~ expands as expected (no literal '~' on disk)."""
    monkeypatch.setenv("COMMUNITY_MEMBER_HOME", "~/test-agent-home-xyz")
    import importlib
    from pathlib import Path

    from community_member import config as config_mod

    importlib.reload(config_mod)
    try:
        # Resolved path should NOT contain '~'.
        assert "~" not in str(config_mod.CONFIG_DIR)
        assert (Path.home() / "test-agent-home-xyz").resolve() == config_mod.CONFIG_DIR
    finally:
        monkeypatch.delenv("COMMUNITY_MEMBER_HOME", raising=False)
        importlib.reload(config_mod)


# ── Cryptographic correctness: ensure_keypair must produce a real
#    asymmetric keypair where pub is derivable from priv via Ed25519.
#    A pre-fix wizard generated HMAC-SHA256-style keys (pub = sha256(priv))
#    that were silently incompatible with Ed25519 signing — registration
#    succeeded via TOFU bootstrap but every subsequent signed request
#    failed verification because the chapter held a hash, not a verify key.


def test_ensure_keypair_produces_ed25519_pair_when_available():
    """ADVERSARIAL: pub must be the Ed25519 verify-key derived from priv.

    Specifically NOT sha256(priv) — that's the legacy HMAC scheme and
    will pass-but-be-broken for any subsequent signed request.
    """
    import base64

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from community_member.crypto import ed25519_available

    if not ed25519_available():
        import pytest

        pytest.skip("Ed25519 extra not installed — falls back to HMAC scheme")

    config = Config()
    config.ensure_keypair()

    priv = Ed25519PrivateKey.from_private_bytes(base64.b64decode(config.private_key))
    derived_pub = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    assert base64.b64encode(derived_pub).decode() == config.public_key, (
        "public_key on Config must be the Ed25519 verify-key derived from "
        "private_key. Anything else (e.g. sha256(priv)) is a wire-incompatible "
        "key that the chapter cannot verify against."
    )


# ── Multi-agent: keystore must also honor COMMUNITY_MEMBER_HOME ──────


def test_keystore_dir_honors_COMMUNITY_MEMBER_HOME(tmp_path, monkeypatch):
    """Keystore artefacts (keystore.enc, keystore.meta.json) follow the
    same env override config does. Without this, COMMUNITY_MEMBER_HOME
    only redirected config.json + agent.json, and the wizard's freshly-
    generated keypair landed in ~/.community-member/keystore.enc — which
    polluted the developer's real keystore on every test run.
    """
    custom = tmp_path / "agent-work"
    monkeypatch.setenv("COMMUNITY_MEMBER_HOME", str(custom))
    import importlib

    from community_member import keystore as keystore_mod

    importlib.reload(keystore_mod)
    try:
        assert custom.expanduser() == keystore_mod.KEYSTORE_DIR
    finally:
        monkeypatch.delenv("COMMUNITY_MEMBER_HOME", raising=False)
        importlib.reload(keystore_mod)


# ── is_configured: identity is enough; keyless is a complete setup ──


def _identified() -> Config:
    c = Config()
    c.agent_id = "alice"
    c.ensure_keypair()  # agent_id + public key = an identity
    return c


def test_is_configured_keyless_is_complete():
    """HAPPY: a standalone, keyless agent (identity, NO llm key) is a COMPLETE
    setup — the wizard must not report 'incomplete'. Matches the README's
    'keyless install is complete and working' posture."""
    c = _identified()
    c.api_key = ""
    c._api_key_encrypted = ""
    assert c.is_configured() is True


def test_is_configured_with_llm_key_still_complete():
    """HAPPY: adding an LLM key doesn't change completeness (regression)."""
    c = _identified()
    c.api_key = "sk-whatever"
    assert c.is_configured() is True


def test_is_configured_requires_an_identity():
    """FAILURE: no identity (missing agent_id or public key) is NOT configured,
    even with an llm key present."""
    no_id = Config()
    no_id.ensure_keypair()
    no_id.api_key = "sk-whatever"
    assert no_id.is_configured() is False  # no agent_id

    no_key = Config()
    no_key.agent_id = "bob"  # no keypair generated → no public_key
    no_key.api_key = "sk-whatever"
    assert no_key.is_configured() is False
