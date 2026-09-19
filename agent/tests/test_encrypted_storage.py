"""
Tests for Phase 3: Encrypted API key storage.

SEC: Encrypted key stored, plaintext cleared, wrong passphrase fails.
"""

import json

import pytest

from community_member.config import Config


def test_set_api_key_encrypts(tmp_path, monkeypatch):
    """HAPPY: set_api_key encrypts and clears plaintext."""
    import community_member.config as config_mod

    monkeypatch.setattr(config_mod, "CONFIG_DIR", tmp_path)

    config = Config()
    config.agent_id = "test"
    config.chapter_url = "https://test.com"
    config.set_api_key("xai-my-secret-key", "my-passphrase")
    config.save()

    # Read the raw file
    raw = json.loads((tmp_path / "config.json").read_text())
    assert raw["api_key"] == ""  # Plaintext cleared
    assert raw["api_key_encrypted"] is not None
    assert "ciphertext" in raw["api_key_encrypted"]
    assert "xai-my-secret-key" not in json.dumps(raw)  # Key not in file


def test_get_api_key_decrypts(tmp_path, monkeypatch):
    """HAPPY: get_api_key decrypts with correct passphrase."""
    import community_member.config as config_mod

    monkeypatch.setattr(config_mod, "CONFIG_DIR", tmp_path)

    config = Config()
    config.agent_id = "test"
    config.chapter_url = "https://test.com"
    config.set_api_key("xai-my-secret-key", "my-passphrase")
    config.save()

    loaded = Config.load()
    key = loaded.get_api_key("my-passphrase")
    assert key == "xai-my-secret-key"


def test_wrong_passphrase_fails(tmp_path, monkeypatch):
    """FAILURE: wrong passphrase raises ValueError."""
    import community_member.config as config_mod

    monkeypatch.setattr(config_mod, "CONFIG_DIR", tmp_path)

    config = Config()
    config.set_api_key("secret", "correct")
    config.save()

    loaded = Config.load()
    with pytest.raises(ValueError, match="wrong passphrase"):
        loaded.get_api_key("wrong")


def test_legacy_plaintext_still_loads(tmp_path, monkeypatch):
    """EDGE: old config with plaintext api_key still works."""
    import community_member.config as config_mod

    monkeypatch.setattr(config_mod, "CONFIG_DIR", tmp_path)

    # Write a legacy config with plaintext key
    (tmp_path / "config.json").write_text(
        json.dumps(
            {"agent_id": "test", "public_key": "pub", "api_key": "plaintext-key", "chapter_url": "https://test.com"}
        )
    )

    loaded = Config.load()
    assert loaded.api_key == "plaintext-key"
    assert loaded.get_api_key() == "plaintext-key"  # No passphrase needed
    assert loaded.is_configured()


def test_legacy_migrates_on_encrypt(tmp_path, monkeypatch):
    """HAPPY: legacy plaintext migrates to encrypted on set_api_key."""
    import community_member.config as config_mod

    monkeypatch.setattr(config_mod, "CONFIG_DIR", tmp_path)

    config = Config()
    config.agent_id = "test"
    config.chapter_url = "https://test.com"
    config.api_key = "plaintext-key"
    config.set_api_key("plaintext-key", "new-passphrase")
    config.save()

    raw = json.loads((tmp_path / "config.json").read_text())
    assert raw["api_key"] == ""
    assert raw["api_key_encrypted"] is not None


def test_encrypted_config_is_configured(tmp_path, monkeypatch):
    """HAPPY: encrypted key counts as configured."""
    import community_member.config as config_mod

    monkeypatch.setattr(config_mod, "CONFIG_DIR", tmp_path)

    config = Config()
    config.agent_id = "test"
    config.ensure_keypair()  # identity
    config.chapter_url = "https://test.com"
    config.set_api_key("key", "pass")
    assert config.is_configured()


def test_no_api_key_not_configured():
    """EDGE: no key at all = not configured."""
    config = Config()
    config.agent_id = "test"
    config.chapter_url = "https://test.com"
    assert not config.is_configured()
