"""The resolver refuses where the old path silently reached OpenAI.

Measured on the agent's own table before this module existed, using the exact
resolution its server path performs (`(provider or "").lower()` then
`base_urls.get(provider, "https://api.openai.com/v1")`):

    provider='ollama'         -> http://localhost:11434/v1/
    provider=' ollama '       -> https://api.openai.com/v1/   <-- OpenAI
    provider=''               -> https://api.openai.com/v1/   <-- OpenAI
    provider='typo-provider'  -> https://api.openai.com/v1/   <-- OpenAI

and the key resolved for the intended provider travelled with it.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from community_member import llm_runtime

REPO = Path(__file__).resolve().parents[2]


# ── the defect, expressed as the cases that used to leak ──────────────────────


@pytest.mark.parametrize("raw", ["", "   ", None, "typo-provider", "openai-", "OpenAI Inc"])
def test_an_unusable_provider_refuses_rather_than_resolving_anywhere(raw):
    """No fallback. The old path answered every one of these with OpenAI's URL."""
    with pytest.raises(llm_runtime.LLMNotConfigured):
        llm_runtime.resolve(raw)


@pytest.mark.parametrize("raw", ["ollama", " ollama ", "Ollama", "  OLLAMA\t"])
def test_whitespace_and_case_reach_the_same_provider(raw):
    """One normalisation, so the two call sites cannot disagree again.

    ' ollama ' resolved to OpenAI on the path that lowercased without stripping,
    and to Ollama on the path that stripped. Both are this function now.
    """
    resolution = llm_runtime.resolve(raw)
    assert resolution.provider.name == "ollama"
    assert resolution.base_url == "http://localhost:11434/v1"


def test_no_input_can_produce_an_openai_base_url_except_openai():
    """The property, stated directly rather than case by case."""
    for name in llm_runtime.PROVIDERS:
        resolution = llm_runtime.resolve(name)
        if name == "openai":
            assert "api.openai.com" in resolution.base_url
        else:
            assert "api.openai.com" not in resolution.base_url, f"{name} resolves to an OpenAI endpoint"


def test_the_module_contains_no_defaulted_provider_lookup():
    """The defect was one default argument. Assert it cannot come back.

    `base_urls.get(provider, "https://api.openai.com/v1")` is the whole bug. A
    grep is a blunt instrument, but this one is precise: there is no legitimate
    reason for this module to hand `.get` a fallback for a provider lookup.
    """
    source = (REPO / "agent" / "community_member" / "llm_runtime.py").read_text()
    assert "PROVIDERS.get(name)" in source, "the lookup moved; re-check this guard"
    for line in source.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        assert "PROVIDERS.get(" not in stripped or stripped.endswith("PROVIDERS.get(name)"), (
            f"a defaulted provider lookup reintroduces the fallback: {stripped!r}"
        )


# ── keys belong to the provider they are sent to ─────────────────────────────


def test_a_remote_provider_with_no_key_refuses_rather_than_sending_a_placeholder(monkeypatch):
    """The old path sent api_key="local" to a remote endpoint when nothing was set."""
    monkeypatch.delenv("XAI_API_KEY", raising=False)
    resolution = llm_runtime.resolve("xai")
    with pytest.raises(llm_runtime.LLMNotConfigured, match="XAI_API_KEY"):
        llm_runtime.build_client(resolution)


def test_a_key_is_read_only_from_the_variable_belonging_to_the_provider(monkeypatch):
    """The old path fell through config.api_key or OPENAI_API_KEY or XAI_API_KEY,
    so whichever key happened to be set travelled to whichever endpoint resolved.
    """
    monkeypatch.setenv("OPENAI_API_KEY", "openai-key-value")
    monkeypatch.delenv("XAI_API_KEY", raising=False)

    resolution = llm_runtime.resolve("xai")
    with pytest.raises(llm_runtime.LLMNotConfigured, match="XAI_API_KEY"):
        llm_runtime.build_client(resolution)


def test_a_local_provider_needs_no_key_and_declares_no_key_variable():
    for name in sorted(llm_runtime.LOCAL_PROVIDERS):
        provider = llm_runtime.PROVIDERS[name]
        assert provider.key_env == "", f"{name} is local and names a key variable"
        assert llm_runtime.egress_allowed(llm_runtime.resolve(name)) is False


def test_egress_is_reported_for_every_remote_provider():
    for name, provider in llm_runtime.PROVIDERS.items():
        if provider.is_local:
            continue
        assert llm_runtime.egress_allowed(llm_runtime.resolve(name)) is True
        assert provider.key_env, f"{name} is remote and names no key variable"


# ── the registry itself ──────────────────────────────────────────────────────


def test_the_registry_is_the_union_of_both_trees():
    assert set(llm_runtime.PROVIDERS) == {
        "anthropic",
        "openai",
        "xai",
        "groq",
        "ollama",
        "llama_cpp",
        "mlx_lm",
    }


def test_every_provider_declares_every_tier():
    for name, provider in llm_runtime.PROVIDERS.items():
        assert set(provider.models) == set(llm_runtime.TIERS), f"{name} is missing a tier"
        for tier, model in provider.models.items():
            assert model.strip(), f"{name}/{tier} declares an empty model"


def test_capabilities_are_unknown_rather_than_guessed():
    """Left unpopulated on purpose — a separate probe measures them.

    A table that looked authoritative and was guessed is the failure this module
    exists to end, so the absence is asserted rather than left to drift into
    invented values.
    """
    for name, provider in llm_runtime.PROVIDERS.items():
        caps = provider.caps
        assert caps.forced_tool_choice is None, f"{name} has a guessed capability"
        assert caps.json_object_response_format is None, f"{name} has a guessed capability"
        assert caps.stream_options_include_usage is None, f"{name} has a guessed capability"
        assert caps.cache_control is None, f"{name} has a guessed capability"


# ── report-only ──────────────────────────────────────────────────────────────


def test_describe_resolution_never_raises_and_never_carries_a_key(monkeypatch):
    """It is logged next to the current path's answer, so it must be safe to log."""
    monkeypatch.setenv("XAI_API_KEY", "a-real-looking-secret-value")

    for raw in ("xai", "", "typo-provider", " ollama ", None):
        record = llm_runtime.describe_resolution(raw)
        assert isinstance(record, dict)
        assert "a-real-looking-secret-value" not in repr(record), (
            "describe_resolution put a key value in a record meant for a log"
        )

    resolved = llm_runtime.describe_resolution("xai")
    assert resolved["resolved"] is True
    assert resolved["key_env"] == "XAI_API_KEY"
    assert resolved["key_present"] is True

    refused = llm_runtime.describe_resolution("typo-provider")
    assert refused["resolved"] is False
    assert refused["would_have_fallen_back"] is True


def test_importing_the_module_changes_no_behaviour_and_needs_no_network():
    """Report-only: importing it must not reach anything.

    The module holds stdlib imports at the top and imports openai only inside
    build_client, so a call site can log a resolution without constructing a
    client or requiring the dependency at import time.
    """
    source = (REPO / "agent" / "community_member" / "llm_runtime.py").read_text()
    top = source.split("def build_client", 1)[0]
    assert "from openai import" not in top, "openai is imported at module scope"
    assert "import requests" not in source and "import httpx" not in source
    assert "community_member" not in source.replace("agent/community_member/", ""), (
        "the vendored module imports from community_member, which the server tree lacks"
    )


# ── the two copies are one file ──────────────────────────────────────────────


def test_llm_runtime_is_byte_identical_to_the_server_copy():
    """Same pin as retry_policy.py, for the same reason.

    A copy that drifts is two registries wearing one name, which is the condition
    this module was written to remove. Copy it whole; do not edit one side.
    """
    agent_copy = (REPO / "agent" / "community_member" / "llm_runtime.py").read_bytes()
    server_copy = (REPO / "server" / "llm_runtime.py").read_bytes()
    assert agent_copy == server_copy, (
        "server/llm_runtime.py has drifted from agent/community_member/llm_runtime.py — "
        "re-copy it whole rather than editing one side. "
        f"agent md5={hashlib.md5(agent_copy).hexdigest()} "
        f"server md5={hashlib.md5(server_copy).hexdigest()}"
    )
