"""serve.py BYOK — deployed agents read the LLM provider/key/model from env.

A headless agent has no config.json LLM section, so without an env overlay it's
stuck in no-LLM mode. _build_config overlays AGENT_PROVIDER / AGENT_API_KEY (or
ANTHROPIC_API_KEY) / AGENT_MODEL when set. The API key is held IN-MEMORY only —
the Railway env var is the secret store, so the plaintext key must NOT be written
to the volume's config.json (where it would outlive an env-var rotation).
"""

from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path

import pytest

import community_member.config as cfg
from community_member import keystore


@pytest.fixture
def headless_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Redirect config + keystore to a tmp 'volume'; device backend = no prompt."""
    monkeypatch.setattr(cfg, "CONFIG_DIR", tmp_path)
    monkeypatch.setenv("COMMUNITY_MEMBER_KEYSTORE", "device")
    keystore.reset_for_tests(dir_override=tmp_path)
    monkeypatch.setenv("AGENT_ID", "TEST-byok")
    for k in ("AGENT_PROVIDER", "AGENT_API_KEY", "ANTHROPIC_API_KEY", "AGENT_MODEL"):
        monkeypatch.delenv(k, raising=False)
    yield tmp_path
    keystore.reset_for_tests()


def _build():
    import serve

    importlib.reload(serve)  # pick up the patched cfg.CONFIG_DIR
    return serve._build_config()


def test_byok_env_overlays_provider_key_model(headless_home, monkeypatch):
    monkeypatch.setenv("AGENT_PROVIDER", "anthropic")
    monkeypatch.setenv("AGENT_API_KEY", "sk-ant-test-123")
    monkeypatch.setenv("AGENT_MODEL", "claude-opus-4-8")

    config = _build()
    assert config.provider == "anthropic"
    assert config.api_key == "sk-ant-test-123"
    assert config.model == "claude-opus-4-8"
    assert config.is_configured() is True  # LLM path now configured


def test_byok_accepts_anthropic_api_key_alias(headless_home, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-from-alias")
    config = _build()
    assert config.api_key == "sk-ant-from-alias"
    assert config.is_configured() is True


def test_byok_key_is_not_persisted_to_disk(headless_home, monkeypatch):
    """The plaintext key stays in-memory; config.json on the volume must not hold it."""
    monkeypatch.setenv("AGENT_API_KEY", "sk-ant-secret")
    config = _build()
    assert config.api_key == "sk-ant-secret"  # in memory
    on_disk = json.loads((headless_home / "config.json").read_text())
    assert on_disk.get("api_key", "") == ""  # NOT written to the volume


def test_byok_unset_leaves_config_unchanged(headless_home):
    """No env → no LLM key, defaults preserved. The agent still has its restored
    identity, so it is a COMPLETE keyless setup (the LLM key is optional).

    The model assertion used to read ``== "grok-3-mini"  # the Config default``,
    which encoded the defect rather than catching it: a keyless agent reported a
    specific vendor's model while holding no provider and no key, and the
    autonomous loop took that as licence to call xAI on every tick. With no
    provider there is no model to name.
    """
    config = _build()
    assert config.api_key == ""
    assert config.provider == ""
    assert config.model == ""  # no provider ⇒ no vendor's model
    assert config.is_configured() is True  # keyless: identity present, no key needed


@pytest.fixture(autouse=True)
def _clean_serve():
    yield
    sys.modules.pop("serve", None)
