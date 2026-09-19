"""A member on a local provider gets a runtime, with no key.

THE REGRESSION. ``build_member_runtimes`` had a literal ``if not api_key:
continue``, so it refused a runtime to every member whose provider was local —
even though the wizard's own express default is ollama. A local provider has no
key to hold, so the most common configuration the product offers was the one
that silently got nothing: no runtime, no error, no log line saying why.

Only a REMOTE provider without a key is skipped now, which is the case the check
was reaching for.
"""

from __future__ import annotations

import llm_runtime
import member_runtime


def test_a_member_on_a_local_provider_gets_a_runtime_without_a_key():
    """ollama is the wizard's express default. It has no key by design."""
    runtime = member_runtime.MemberAgentRuntime(
        "local-member",
        {"agent_id": "local-member", "skills": ["general"]},
        "ollama",
        "",  # no key, and none needed
        "",
        "llama3.2",
    )
    assert runtime.status == "active"
    assert runtime.llm is not None
    assert "11434" in str(runtime.llm.base_url), str(runtime.llm.base_url)


def test_every_local_provider_is_reachable_without_a_key():
    """Not just ollama: llama_cpp and mlx_lm are local too, and were refused."""
    for name in sorted(llm_runtime.LOCAL_PROVIDERS):
        runtime = member_runtime.MemberAgentRuntime(
            f"m-{name}", {"agent_id": f"m-{name}"}, name, "", "", "local-model"
        )
        assert runtime.llm is not None, f"{name} got no client"


def test_the_skip_rule_itself():
    """Driven through the predicate the loop calls, not around it.

    An earlier version of this test built a runtime directly and asserted it
    worked — which it did both before and after the fix, because the defect was
    in the LOOP's decision, not in the constructor. Restoring the old
    ``if not api_key`` did not redden it. This asserts the decision.
    """
    # a local provider with no key is reachable
    for name in sorted(llm_runtime.LOCAL_PROVIDERS):
        assert member_runtime._member_is_unreachable(name, "") is False, name
        assert member_runtime._member_is_unreachable(f"  {name.upper()}  ", "") is False, name

    # a remote provider with no key is not
    for name in ("xai", "openai", "anthropic", "groq"):
        assert member_runtime._member_is_unreachable(name, "") is True, name

    # a key makes any provider reachable, including one this build does not know
    assert member_runtime._member_is_unreachable("xai", "a-key") is False
    assert member_runtime._member_is_unreachable("some-future-provider", "a-key") is False


def test_the_loop_uses_that_predicate_and_nothing_else():
    """A predicate the loop does not call would leave the defect in place."""
    from pathlib import Path

    src = Path(member_runtime.__file__).read_text()
    assert "if _member_is_unreachable(provider, api_key):" in src
    assert "if not api_key:\n            continue" not in src, (
        "the bare key check is back, and it refuses every local provider"
    )


def test_the_client_carries_the_capped_retries_and_timeout():
    """The reason construction moved: every site ran the SDK defaults."""
    runtime = member_runtime.MemberAgentRuntime(
        "capped", {"agent_id": "capped"}, "ollama", "", "", "llama3.2"
    )
    assert runtime.llm.max_retries == llm_runtime.DEFAULT_MAX_RETRIES
    assert runtime.llm.timeout == llm_runtime.DEFAULT_TIMEOUT_S
