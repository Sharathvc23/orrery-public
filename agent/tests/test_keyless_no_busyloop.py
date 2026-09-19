"""A keyless install must not address a third party it was never given.

Found by driving a keyless install end to end. `orrery-up` prints *"keyless install — complete and
working"*; the agent came out `provider=''`, `api_key` empty, `model='grok-3-mini'`,
and the autonomous loop then issued a rejected request to **xAI** every tick,
forever. Measured on a real throwaway org: 14 failures in ~60s at a 5s interval —
~17k failed calls/day/agent, ~69k across four agents. Had the key been
valid-but-metered, that loop would have spent real money on a permanent error.

Two independent guesses caused it, and both are now gone:

    base_url = base_urls.get(config.provider, "https://api.x.ai/v1")  # empty ⇒ xAI
    api_key  = config.api_key or "local"                              # empty ⇒ "local"

The rule itself was never missing — `llm_client.chat_or_error` already refused
cleanly with *"no LLM configured"*. The autonomous path simply did not ask. It
now asks the same function, so the two cannot drift apart again.

Classification: ADVERSARIAL (defect regression guard).
"""

from __future__ import annotations

import pytest

from community_member import llm_client
from community_member.config import Config


class TestTheOneDefinition:
    """`llm_is_configured` is the single gate both paths read."""

    @pytest.mark.parametrize("provider", ["ollama", "llama_cpp", "mlx_lm"])
    def test_local_providers_need_no_key(self, provider: str) -> None:
        """That is the entire point of a local provider."""
        assert llm_client.llm_is_configured(provider, "") is True

    @pytest.mark.parametrize("provider", ["xai", "openai", "anthropic", "groq"])
    def test_remote_providers_need_a_key(self, provider: str) -> None:
        assert llm_client.llm_is_configured(provider, "") is False
        assert llm_client.llm_is_configured(provider, "sk-something") is True

    @pytest.mark.parametrize(
        "provider,key",
        [("", ""), (None, None), ("   ", "   "), ("", "sk-orphaned-key"), ("xai", "   ")],
    )
    def test_the_keyless_shapes_are_all_unconfigured(self, provider, key) -> None:
        """Including the two that bit: no provider at all, and a key with no
        provider to spend it against."""
        assert llm_client.llm_is_configured(provider, key) is False


class TestNoVendorIsEverGuessed:
    def test_unknown_provider_has_no_base_url(self) -> None:
        """It used to resolve to xAI. Returning None is what makes the caller
        unable to accidentally address someone."""
        assert llm_client.base_url_for("") is None
        assert llm_client.base_url_for(None) is None
        assert llm_client.base_url_for("not-a-provider") is None

    def test_known_providers_still_resolve(self) -> None:
        assert llm_client.base_url_for("anthropic") == "https://api.anthropic.com/v1"
        assert llm_client.base_url_for("ollama") == "http://localhost:11434/v1"

    def test_config_has_no_vendor_model_by_default(self) -> None:
        """A fresh Config reported `grok-3-mini` with no provider and no key,
        which is how the broken state read as 'configured' to a human."""
        assert Config().model == ""

    def test_no_module_guesses_a_vendor_when_provider_is_empty(self) -> None:
        """Belt and braces: the two `or "grok-3-mini"` fallbacks are gone. A
        vendor string may only appear in a provider TABLE, keyed by provider."""
        import inspect

        from community_member import agent as agent_mod
        from community_member import config as config_mod
        from community_member import server as server_mod

        for mod in (agent_mod, config_mod):
            src = inspect.getsource(mod)
            assert 'or "grok-3-mini"' not in src, f"{mod.__name__} still guesses a vendor model"
            assert '"https://api.x.ai/v1")' not in src, f"{mod.__name__} still guesses a vendor URL"
        # server.py legitimately holds the provider CATALOGUE (keyed by
        # provider id), which is not a guess — only the bare fallback was.
        assert 'or "grok-3-mini"' not in inspect.getsource(server_mod)


class TestTheAgentRefusesRatherThanGuessing:
    def _agent(self, provider: str, api_key: str):
        from community_member.agent import LocalAgent

        cfg = Config()
        cfg.agent_id = "svc"
        cfg.provider = provider
        cfg.api_key = api_key
        return LocalAgent(cfg)

    def test_keyless_agent_builds_no_llm_client(self) -> None:
        a = self._agent("", "")
        assert a.llm_configured is False
        assert a.llm is None, "a keyless agent still built an LLM client"

    def test_configured_agent_still_builds_one(self) -> None:
        a = self._agent("anthropic", "sk-test")
        assert a.llm_configured is True
        assert a.llm is not None
        assert "anthropic" in str(a.llm.base_url)

    def test_local_provider_builds_one_without_a_key(self) -> None:
        a = self._agent("ollama", "")
        assert a.llm_configured is True
        assert a.llm is not None
        assert "11434" in str(a.llm.base_url)


@pytest.mark.asyncio
async def test_keyless_run_loop_never_calls_the_planner() -> None:
    """The behavioural assertion, and the one that would have caught the
    original defect: with no LLM configured, the loop must not reach think_v2
    even once. Everything here is local — no network is possible."""
    from community_member.agent import LocalAgent

    cfg = Config()
    cfg.agent_id = "svc"
    cfg.provider = ""
    cfg.api_key = ""
    agent = LocalAgent(cfg)

    calls = {"think": 0, "drain": 0}
    agent.think_v2 = lambda *a, **k: calls.__setitem__("think", calls["think"] + 1)  # type: ignore[method-assign]

    def _drain() -> None:
        calls["drain"] += 1
        if calls["drain"] >= 3:
            agent.running = False

    agent._drain_inbound = _drain  # type: ignore[method-assign]
    agent.running = True

    await agent.run(interval=0)

    assert calls["think"] == 0, "keyless agent invoked the planner"
    assert calls["drain"] >= 3, "keyless agent stopped doing deterministic work"
