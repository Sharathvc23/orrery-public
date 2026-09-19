"""Tests for LocalAgent.think_v2 — the v2 wrapper on top of runtime.think_v2.

These tests exercise the AGENT-level glue: how the LocalAgent
builds a PlannerContext from its config + pending chapter intents
and hands it to `runtime.think_v2`.

The LLM and the A2A chapter client are both mocked so the tests
don't hit the network or require Chromium. What they pin:

  * User profile lands in TrustedContext
  * Pending chapter intents land in SemiTrustedContext with the
    chapter URL as source — NEVER in TrustedContext
  * Untrusted context is empty for the base think cycle (no web
    content yet)
  * think_v2 returns a ThinkOutcome (or None on LLM catastrophe)
  * Legacy `think()` still works — the v2 addition is purely additive
  * The consent ledger is auto-initialized on first think_v2 call
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from community_member.agent import LocalAgent
from community_member.config import Config
from community_member.consent import ledger
from community_member.runtime import ThinkOutcome


@pytest.fixture(autouse=True)
def _reset():
    ledger._reset_for_tests()
    yield
    ledger._reset_for_tests()


@pytest.fixture
def tmp_env(tmp_path: Path, monkeypatch):
    """Redirect CONFIG_DIR + keystore to a temp dir so tests don't
    clobber a developer's real agent state."""
    from community_member import config as config_mod
    from community_member import keystore

    monkeypatch.setattr(config_mod, "CONFIG_DIR", tmp_path)
    keystore.reset_for_tests(dir_override=tmp_path)
    return tmp_path


@pytest.fixture
def cfg(tmp_env) -> Config:
    c = Config()
    c.agent_id = "alice"
    c.name = "Alice"
    c.description = "Builder of things"
    c.skills = ["python", "rust"]
    c.interests = ["edge compute", "cryptography"]
    c.chapter_url = "https://chapter.example"
    c.provider = "xai"
    c.api_key = "key-for-test"
    c.model = "grok-3-mini"
    c.private_key = "dummy-priv"
    c.public_key = "dummy-pub"
    return c


def _mk_llm_response(proposals, summary="ok"):
    """Build a fake OpenAI response carrying a propose_actions tool call."""
    tool_call = SimpleNamespace(
        function=SimpleNamespace(
            name="propose_actions",
            arguments=json.dumps({"proposals": proposals, "summary": summary}),
        )
    )
    return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=None, tool_calls=[tool_call]))])


def _patch_agent_llm(agent, proposals):
    """Replace the agent's OpenAI client with a fake that returns `proposals`."""

    def create(**_kwargs):
        return _mk_llm_response(proposals)

    agent.llm = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=create)))


def _patch_chapter_client(agent, pending=()):
    """Make the A2A chapter client return `pending` intents."""
    agent.client = SimpleNamespace(
        get_intents_pending=lambda _agent_id: {"pending": list(pending)},
    )


# ── Basic: trusted proposal → pending_approval bucket ─────────────


def test_think_v2_trusted_proposal_lands_in_pending(cfg):
    agent = LocalAgent(cfg)
    _patch_chapter_client(agent)
    _patch_agent_llm(
        agent,
        [
            {
                "capability": "browser.navigate",
                "scope": "https://docs.example.com",
                "context": "research",
                "provenance": "trusted",
            }
        ],
    )
    outcome = agent.think_v2()
    assert isinstance(outcome, ThinkOutcome)
    assert len(outcome.pending_approval) == 1
    assert outcome.rejected == ()
    assert outcome.errored == ()


def test_think_v2_untrusted_proposal_lands_in_rejected(cfg):
    agent = LocalAgent(cfg)
    _patch_chapter_client(agent)
    _patch_agent_llm(
        agent,
        [
            {
                "capability": "browser.navigate",
                "scope": "https://evil.example",
                "context": "research",
                "provenance": "untrusted",
                "source_ref": "https://news.example/article",
            }
        ],
    )
    outcome = agent.think_v2()
    assert len(outcome.rejected) == 1
    assert outcome.pending_approval == ()


def test_think_v2_increments_thought_count(cfg):
    agent = LocalAgent(cfg)
    before = agent.thought_count
    _patch_chapter_client(agent)
    _patch_agent_llm(agent, [])
    agent.think_v2()
    assert agent.thought_count == before + 1


# ── Context construction: user profile → trusted only ───────────


def test_think_v2_puts_user_profile_in_trusted_not_untrusted(cfg):
    """The user's own skills/interests MUST NOT leak into the
    untrusted context bucket. This is a provenance-layering test:
    an LLM that sees "interests: cryptography" as trusted and also
    sees attacker text in untrusted must not be able to conflate
    them — the rendered prompt ships them as separate labeled
    blocks."""
    agent = LocalAgent(cfg)
    _patch_chapter_client(agent)

    captured_call = {}

    def capture(**kwargs):
        captured_call["messages"] = kwargs["messages"]
        return _mk_llm_response([])

    agent.llm = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=capture)))

    agent.think_v2()
    user_msg = next(m for m in captured_call["messages"] if m["role"] == "user")
    rendered = user_msg["content"]
    # User profile appears under TRUSTED.
    assert "TRUSTED CONTEXT" in rendered
    assert "skills: python, rust" in rendered
    # And NOT under any untrusted block. (There's no untrusted block
    # in this cycle at all.)
    assert "UNTRUSTED CONTENT" not in rendered


def test_think_v2_chapter_intents_land_in_semi_trusted(cfg):
    agent = LocalAgent(cfg)
    _patch_chapter_client(
        agent,
        pending=[
            {"intent_text": "Looking for a Rust expert for edge compute"},
            {"intent_text": "Want to co-author a paper on zk-SNARKs"},
        ],
    )

    captured = {}

    def capture(**kwargs):
        captured["messages"] = kwargs["messages"]
        return _mk_llm_response([])

    agent.llm = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=capture)))

    agent.think_v2()
    rendered = next(m for m in captured["messages"] if m["role"] == "user")["content"]
    assert "SEMI-TRUSTED CONTEXT" in rendered
    assert "chapter:https://chapter.example" in rendered
    assert "Rust expert" in rendered


def test_think_v2_handles_chapter_client_failure_gracefully(cfg):
    """If the chapter client raises on get_intents_pending, think_v2
    must still run — the intent fetch is best-effort, not required."""
    agent = LocalAgent(cfg)

    def boom(_agent_id):
        raise RuntimeError("chapter offline")

    agent.client = SimpleNamespace(get_intents_pending=boom)
    _patch_agent_llm(agent, [])
    outcome = agent.think_v2()
    assert outcome is not None  # still ran; pending intents just absent


# ── LLM error → the caller classifies it ─────────────────────────


def test_think_v2_propagates_an_llm_failure_to_its_caller(cfg):
    """⚠️ THIS ASSERTED THE DEFECT. It pinned ``outcome is None``, i.e. that
    think_v2 swallows every exception — which is precisely what made
    ``run()``'s retry_policy classifier unreachable. While it held, a sustained
    401 sent eight full 1,403-token requests through eight consecutive refusals
    and the retryable-backoff branch in ``run()`` was dead code.

    The ORIGINAL exception must arrive, not a wrapper: ``classify()`` reads the
    status and the type name to tell a 429 (wait, it clears) from a 401 (stop,
    it cannot), and a single wrapper type would collapse that distinction and
    halt the agent on a transient rate limit.
    """
    agent = LocalAgent(cfg)
    _patch_chapter_client(agent)

    def broken(**_kwargs):
        raise ConnectionError("network dead")

    agent.llm = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=broken)))
    with pytest.raises(ConnectionError):
        agent.think_v2()


def test_the_propagated_failure_is_the_one_retry_policy_classifies(cfg):
    """The point of propagating: the caller's verdict differs by exception, and
    it can only differ if the exception survives the trip."""
    from community_member import retry_policy

    class _RateLimited(Exception):
        status_code = 429

    class _Unauthorized(Exception):
        status_code = 401

    cases = (
        (_RateLimited, retry_policy.Decision.RETRYABLE),
        (_Unauthorized, retry_policy.Decision.TERMINAL),
    )
    for exc_type, expected in cases:
        agent = LocalAgent(cfg)
        _patch_chapter_client(agent)

        def broken(_e=exc_type, **_kwargs):
            raise _e("provider said so")

        agent.llm = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=broken)))
        with pytest.raises(exc_type) as caught:
            agent.think_v2()
        assert retry_policy.classify(caught.value) is expected


# ── Ledger auto-init ────────────────────────────────────────────


def test_think_v2_auto_initializes_consent_ledger(cfg, tmp_env):
    """First call to think_v2 must initialize the consent ledger so
    every proposed action gets audited. Running twice doesn't
    double-init (idempotent)."""
    agent = LocalAgent(cfg)
    _patch_chapter_client(agent)
    _patch_agent_llm(agent, [])

    # Ledger starts uninitialized (see autouse fixture).
    ledger._reset_for_tests()
    agent.think_v2()
    # Ledger is now initialized + DB exists.
    assert (tmp_env / "consent.db").exists()


def test_think_v2_writes_ledger_rows(cfg, tmp_env):
    agent = LocalAgent(cfg)
    _patch_chapter_client(agent)
    _patch_agent_llm(
        agent,
        [
            {
                "capability": "browser.navigate",
                "scope": "https://a.example",
                "context": "c",
                "provenance": "trusted",
            },
            {
                "capability": "browser.navigate",
                "scope": "https://b.example",
                "context": "c",
                "provenance": "untrusted",
                "source_ref": "https://b.example",
            },
        ],
    )
    agent.think_v2()
    # Exactly 2 rows (one prompt, one reject).
    prompts = ledger.list_events(action="consent.prompt")
    rejects = ledger.list_events(action="consent.reject")
    assert len(prompts) == 1
    assert len(rejects) == 1
    assert ledger.verify_chain()["ok"] is True


# ── Legacy think() untouched ────────────────────────────────────


def test_legacy_think_method_still_exists(cfg):
    agent = LocalAgent(cfg)
    # Just verify the attribute is callable; we don't run it because
    # it hits a real LLM. The point is that think_v2 is additive.
    assert callable(agent.think)
    assert callable(agent.think_v2)
    assert agent.think is not agent.think_v2


# ── Agent without agent_id → graceful ─────────────────────────


def test_think_v2_without_agent_id_still_runs(tmp_env):
    cfg = Config()
    cfg.provider = "xai"
    cfg.api_key = "k"
    cfg.chapter_url = "https://chapter.example"
    # agent_id intentionally missing
    agent = LocalAgent(cfg)
    _patch_chapter_client(agent)
    _patch_agent_llm(agent, [])

    # Init should degrade gracefully — keystore has nothing for ""
    with patch("community_member.agent.console"):
        outcome = agent.think_v2()
    # Returns an outcome (possibly None if ledger init fails, but
    # should not crash on return).
    assert outcome is None or isinstance(outcome, ThinkOutcome)
