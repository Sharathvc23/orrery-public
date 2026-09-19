"""Provider-agnostic LLM resolution (llm_config).

The chapter is no longer welded to xAI/Grok: provider/base_url/key/model resolve
from env, defaulting to Claude and auto-detecting from whichever provider key is
present. A missing key is non-fatal (boot must not crash).

Classification: HAPPY / EDGE / FAILURE.
"""

from __future__ import annotations

import os

os.environ.setdefault("AGENT_ID", "test-chapter")
os.environ.setdefault("XAI_API_KEY", "test-xai-key")

import pytest  # noqa: E402

import llm_config  # noqa: E402

_ENV_KEYS = (
    "LLM_PROVIDER",
    "LLM_API_KEY",
    "LLM_MODEL",
    "LLM_BASE_URL",
    "DEFAULT_LLM_MODEL",
    "ANTHROPIC_API_KEY",
    "XAI_API_KEY",
    "OPENAI_API_KEY",
    "GROQ_API_KEY",
)


@pytest.fixture
def clean_env(monkeypatch):
    """Strip every LLM-related env var so each test starts from nothing."""
    for k in _ENV_KEYS:
        monkeypatch.delenv(k, raising=False)
    return monkeypatch


def _r(monkeypatch, **env):
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    return llm_config._resolve()  # (provider, base_url, api_key, model)


# ── auto-detect (no explicit provider) ────────────────────────────────


def test_defaults_to_anthropic_when_no_keys(clean_env):  # HAPPY — "default Claude"
    provider, base_url, api_key, model = _r(clean_env)
    assert provider == "anthropic"
    assert "anthropic.com" in base_url
    assert model.startswith("claude")
    assert api_key == ""  # none set → empty (non-fatal)


def test_autodetects_xai_when_only_xai_key(clean_env):  # HAPPY — no surprise migration
    provider, _b, api_key, model = _r(clean_env, XAI_API_KEY="xk")
    assert provider == "xai"
    assert api_key == "xk"
    assert model == "grok-3-mini"


def test_prefers_anthropic_when_both_keys(clean_env):  # EDGE — preference order
    provider, _b, api_key, _m = _r(clean_env, XAI_API_KEY="xk", ANTHROPIC_API_KEY="ak")
    assert provider == "anthropic"
    assert api_key == "ak"


# ── explicit provider ─────────────────────────────────────────────────


def test_explicit_provider_wins_over_detection(clean_env):  # HAPPY
    provider, _b, api_key, _m = _r(clean_env, LLM_PROVIDER="openai", OPENAI_API_KEY="ok", ANTHROPIC_API_KEY="ak")
    assert provider == "openai"
    assert api_key == "ok"


def test_unknown_provider_falls_back_to_anthropic(clean_env):  # FAILURE — never crash on a typo'd provider
    provider, _b, _k, _m = _r(clean_env, LLM_PROVIDER="frobnicate")
    assert provider == "anthropic"


# ── overrides ──────────────────────────────────────────────────────────


def test_llm_api_key_overrides_provider_key(clean_env):  # EDGE
    _p, _b, api_key, _m = _r(clean_env, LLM_PROVIDER="anthropic", ANTHROPIC_API_KEY="ak", LLM_API_KEY="override")
    assert api_key == "override"


def test_llm_model_and_base_url_override(clean_env):  # EDGE
    _p, base_url, _k, model = _r(
        clean_env, LLM_PROVIDER="anthropic", LLM_MODEL="claude-opus-4-8", LLM_BASE_URL="https://proxy.local/v1"
    )
    assert model == "claude-opus-4-8"
    assert base_url == "https://proxy.local/v1"


def test_legacy_default_llm_model_still_honored(clean_env):  # EDGE — back-compat with existing deployments
    _p, _b, _k, model = _r(clean_env, LLM_PROVIDER="xai", DEFAULT_LLM_MODEL="grok-2")
    assert model == "grok-2"


# ── client construction ────────────────────────────────────────────────


def test_build_client_never_raises_without_key(clean_env):  # FAILURE — boot must survive a missing key
    # Module-level API_KEY was resolved at import; build_client must still return
    # a client object regardless (calls would fail later with a clear auth error).
    client = llm_config.build_client()
    assert client is not None
    assert hasattr(client, "chat")
