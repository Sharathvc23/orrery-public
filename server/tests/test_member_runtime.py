"""Tests for member_runtime.py — runtime lifecycle, routing, edge cases."""

import asyncio

import pytest

import member_runtime


class FakePostgresRequest:
    def __init__(self):
        self.calls = []
        self.responses = {}

    async def __call__(self, method, table, params=None, body=None):
        self.calls.append((method, table, params, body))
        return self.responses.get(f"{method}:{table}")


class FakeConvStore:
    def __init__(self):
        self._data = {}

    async def load(self, key):
        return self._data.get(key, [])

    async def append(self, uuid, key, user_msg, assistant_msg):
        self._data.setdefault(key, [])
        self._data[key].append({"role": "user", "content": user_msg})
        self._data[key].append({"role": "assistant", "content": assistant_msg})


async def noop_log_activity(*args, **kwargs):
    pass


async def noop_log_thought(*args, **kwargs):
    pass


def noop_build_card(*args, **kwargs):
    return {}


@pytest.fixture
def runtime_env():
    fake_sb = FakePostgresRequest()
    fake_conv = FakeConvStore()
    member_runtime.init(
        pg_request=fake_sb,
        conv_store=fake_conv,
        log_activity=noop_log_activity,
        log_agent_thought=noop_log_thought,
        build_thought_card=noop_build_card,
        knowledge_cache={"chapter_intelligence": {}},
        agent_id="test-chapter",
        agent_name="Test Chapter",
    )
    member_runtime.runtimes.clear()
    return fake_sb


# --- Runtime Checks ---


def test_has_runtime_false_by_default(runtime_env):
    """No runtime exists initially."""
    assert member_runtime.has_runtime("nonexistent") is False


def test_has_runtime_true_after_creation(runtime_env):
    """Runtime detectable after manual creation."""
    rt = member_runtime.MemberAgentRuntime(
        "test-agent", {"name": "Test", "skills": ["python"]}, "xai", "fake-key", "https://api.x.ai/v1", "grok-3-mini"
    )
    member_runtime.runtimes["test-agent"] = rt
    assert member_runtime.has_runtime("test-agent") is True


def test_has_runtime_false_when_error(runtime_env):
    """Error status runtime reports as not active."""
    rt = member_runtime.MemberAgentRuntime(
        "err-agent", {"name": "Error"}, "xai", "fake-key", "https://api.x.ai/v1", "grok-3-mini"
    )
    rt.status = "error"
    member_runtime.runtimes["err-agent"] = rt
    assert member_runtime.has_runtime("err-agent") is False


# --- Member Respond ---


@pytest.mark.asyncio
async def test_member_respond_no_runtime(runtime_env):
    """Returns None when no runtime exists."""
    result = await member_runtime.member_respond("ghost", "hello", "conv-1")
    assert result is None


@pytest.mark.asyncio
async def test_member_respond_error_runtime(runtime_env):
    """Returns None when runtime is in error state."""
    rt = member_runtime.MemberAgentRuntime(
        "err", {"name": "Error"}, "xai", "fake-key", "https://api.x.ai/v1", "grok-3-mini"
    )
    rt.status = "error"
    member_runtime.runtimes["err"] = rt
    result = await member_runtime.member_respond("err", "hello", "conv-1")
    assert result is None


# --- Load Runtimes ---


@pytest.mark.asyncio
async def test_load_runtimes_no_keys(runtime_env):
    """No runtimes created when no API keys exist."""
    runtime_env.responses["GET:agent_api_keys"] = []
    await member_runtime.load_runtimes({"alice": {"name": "Alice"}})
    assert len(member_runtime.runtimes) == 0


@pytest.mark.asyncio
async def test_load_runtimes_no_agents(runtime_env):
    """No runtimes when no active agents found."""
    runtime_env.responses["GET:agent_api_keys"] = [
        {"profile_id": "p1", "provider": "xai", "api_key_encrypted": "key", "base_url": ""}
    ]
    runtime_env.responses["GET:agents"] = []
    await member_runtime.load_runtimes({"alice": {"name": "Alice"}})
    assert len(member_runtime.runtimes) == 0


@pytest.mark.asyncio
async def test_load_runtimes_skips_existing(runtime_env):
    """Doesn't recreate existing runtimes."""
    rt = member_runtime.MemberAgentRuntime(
        "existing", {"name": "Existing"}, "xai", "key", "https://api.x.ai/v1", "grok-3-mini"
    )
    member_runtime.runtimes["existing"] = rt

    runtime_env.responses["GET:agent_api_keys"] = [
        {"profile_id": "p1", "provider": "xai", "api_key_encrypted": "key2", "base_url": ""}
    ]
    runtime_env.responses["GET:agents"] = [
        {"agent_id": "existing", "profile_id": "p1", "llm_provider": "xai", "llm_model": "grok-3-mini"}
    ]
    await member_runtime.load_runtimes({"existing": {"name": "Existing"}})
    # Should still be the original runtime, not recreated
    assert member_runtime.runtimes["existing"] is rt


# --- System Prompt ---


def test_system_prompt_includes_skills(runtime_env):
    """System prompt includes member skills."""
    rt = member_runtime.MemberAgentRuntime(
        "alice",
        {"name": "Alice", "skills": ["python", "ml"], "description": "ML engineer"},
        "xai",
        "key",
        "https://api.x.ai/v1",
        "grok-3-mini",
    )
    prompt = rt._system_prompt()
    assert "python" in prompt
    assert "ml" in prompt
    assert "Alice" in prompt


def test_system_prompt_handles_empty_skills(runtime_env):
    """System prompt works with no skills."""
    rt = member_runtime.MemberAgentRuntime(
        "bob", {"name": "Bob", "skills": [], "description": ""}, "xai", "key", "https://api.x.ai/v1", "grok-3-mini"
    )
    prompt = rt._system_prompt()
    assert "general" in prompt  # Fallback


# --- Adversarial ---


def test_runtime_creation_with_empty_key(runtime_env, monkeypatch):
    """Runtime tolerates an empty per-member key — fails only on actual LLM call.

    Adversarial path: a member is registered without a configured
    provider key. Construction must succeed (status="active") so the
    chapter can keep running; the failure is deferred to the first
    real LLM call (which will return 401 from the upstream provider
    and is caught by the calling code).

    Pre-fix, the OpenAI v2 client raised ``OpenAIError`` on
    construction whenever api_key was empty/None *and*
    ``OPENAI_API_KEY`` was unset — there's no lazy-init path. The
    runtime now substitutes a placeholder string when the real key is
    missing, so the construction succeeds and the contract holds. We
    unset the env var here to prove the constructor doesn't depend
    on env at all.
    """
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    rt = member_runtime.MemberAgentRuntime(
        "no-key", {"name": "No Key"}, "xai", "", "https://api.x.ai/v1", "grok-3-mini"
    )
    assert rt.status == "active"


def test_runtime_stats_initial(runtime_env):
    """Initial runtime stats are zero."""
    rt = member_runtime.MemberAgentRuntime(
        "fresh", {"name": "Fresh"}, "xai", "key", "https://api.x.ai/v1", "grok-3-mini"
    )
    assert rt.thought_count == 0
    assert rt.conversation_count == 0
    assert rt.last_thought_at is None


@pytest.mark.asyncio
async def test_think_member_cycle_no_runtimes(runtime_env):
    """Think cycle with no runtimes doesn't crash."""
    await member_runtime.think_member_cycle({})


# --- Provider client construction (provider-agnostic OpenAI-compatible path) ---


def test_anthropic_provider_defaults_to_official_compat_endpoint(runtime_env):
    """With no base_url, the anthropic provider points at Anthropic's
    officially-supported OpenAI-compatibility endpoint — not a separate SDK."""
    rt = member_runtime.MemberAgentRuntime(
        "a", {"name": "A"}, "anthropic", "key", "", "claude-sonnet-4-6"
    )
    assert "api.anthropic.com" in str(rt.llm.base_url)


def test_anthropic_provider_honors_explicit_base_url(runtime_env):
    """A member may route anthropic through a proxy / self-host — the explicit
    base_url wins over the default compat endpoint."""
    rt = member_runtime.MemberAgentRuntime(
        "a", {"name": "A"}, "anthropic", "key", "https://proxy.internal/v1", "claude-sonnet-4-6"
    )
    assert "proxy.internal" in str(rt.llm.base_url)


def test_non_anthropic_provider_uses_its_base_url(runtime_env):
    """Every other provider reaches its own OpenAI-compatible endpoint via the
    passed base_url — one call-site, no per-provider branching."""
    rt = member_runtime.MemberAgentRuntime(
        "x", {"name": "X"}, "xai", "key", "https://api.x.ai/v1", "grok-3-mini"
    )
    assert "x.ai" in str(rt.llm.base_url)


# --- Logging (no print()) ---


@pytest.mark.asyncio
async def test_respond_llm_error_sets_error_status_and_fallback(runtime_env):
    """An upstream LLM failure is caught, not raised: the runtime goes to error
    and the caller gets a safe fallback. (That the error is *logged* rather than
    printed is enforced by test_module_has_no_print_calls.)"""
    rt = member_runtime.MemberAgentRuntime(
        "logtest", {"name": "L", "skills": ["x"]}, "xai", "key", "https://api.x.ai/v1", "grok-3-mini"
    )

    class _BoomLLM:
        class chat:
            class completions:
                @staticmethod
                def create(**_kw):
                    raise RuntimeError("upstream 500")

    rt.llm = _BoomLLM()
    reply = await rt.respond("hi", "conv-x")
    # respond() fires a background activity-log task; drain it so no pending
    # task survives into event-loop teardown.
    await asyncio.sleep(0)

    assert rt.status == "error"
    assert "trouble responding" in reply


def test_module_has_no_print_calls():
    """Production-grade: member_runtime must use logging, not print()."""
    import inspect

    src = inspect.getsource(member_runtime)
    # Strip strings/comments crudely is overkill; the module has no legitimate
    # 'print(' token once hardened.
    assert "print(" not in src, "member_runtime should log, not print()"
