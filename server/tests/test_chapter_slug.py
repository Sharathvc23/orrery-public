"""Tests for chapter slug derivation in `chapter_agent._derive_chapter_slug`.

The slug is the URL identifier the multi-chapter portal uses to route to
a chapter. CHAPTER_SLUG env var wins; the derivation is the fallback so
chapters that don't set the env still get a sensible slug from agent_id.

Classification: HAPPY / EDGE / ADVERSARIAL.
"""

from __future__ import annotations

import importlib
import sys

import pytest


@pytest.fixture
def chapter_agent_module(monkeypatch: pytest.MonkeyPatch):
    """Import chapter_agent with stubbed required env vars.

    chapter_agent reads several env vars at import time. We only care
    about the slug derivation, so we stub the bare minimum required
    for import success and skip the heavy startup hook.
    """
    monkeypatch.setenv("AGENT_ID", "TEST-fixture-chapter")
    monkeypatch.setenv("AGENT_NAME", "Fixture")
    monkeypatch.setenv("XAI_API_KEY", "test-key")
    monkeypatch.delenv("CHAPTER_SLUG", raising=False)
    monkeypatch.delenv("CHAPTER_DISPLAY_NAME", raising=False)
    sys.modules.pop("chapter_agent", None)
    mod = importlib.import_module("chapter_agent")
    return mod


# ── HAPPY: production agent_ids derive to clean slugs ──────────


@pytest.mark.parametrize(
    "agent_id, expected_slug",
    [
        ("TEST-boston-chapter", "boston"),
        ("TEST-london-chapter", "london"),
        ("TEST-bangalore-chapter", "bangalore"),
        ("TEST-tokyo-chapter", "tokyo"),
        ("bayarea-nanda-chapter", "bayarea"),
        ("bayarea-agent", "bayarea"),
    ],
)
def test_derive_strips_test_prefix_and_known_suffixes(chapter_agent_module, agent_id: str, expected_slug: str) -> None:
    assert chapter_agent_module._derive_chapter_slug(agent_id) == expected_slug


# ── EDGE: agent_ids with no recognised affixes pass through ─────


def test_derive_passes_through_unrecognised_pattern(chapter_agent_module) -> None:
    """A custom agent_id with no TEST- prefix or chapter/agent suffix
    is its own slug. Production-rollout chapters should set CHAPTER_SLUG
    explicitly; the derivation only catches the convention."""
    assert chapter_agent_module._derive_chapter_slug("custom-id-42") == "custom-id-42"


def test_derive_lowercases_mixed_case(chapter_agent_module) -> None:
    """Slugs must be URL-safe lowercase. Mixed-case agent_ids get folded."""
    assert chapter_agent_module._derive_chapter_slug("Bayarea-Chapter") == "bayarea"


# ── ADVERSARIAL: empty / weird agent_ids ────────────────────────


def test_derive_empty_agent_id_returns_self(chapter_agent_module) -> None:
    """Empty input is undefined behaviour upstream (AGENT_ID is required)
    but the derivation must not crash — return the input unchanged."""
    assert chapter_agent_module._derive_chapter_slug("") == ""


def test_derive_only_test_prefix_returns_self_no_strip(chapter_agent_module) -> None:
    """`TEST-` alone (no body) would strip to empty; fall back to original
    agent_id rather than silently emit an empty slug."""
    assert chapter_agent_module._derive_chapter_slug("TEST-") == "TEST-"


def test_derive_only_chapter_suffix_strips_to_empty_falls_back(chapter_agent_module) -> None:
    """`-chapter` alone strips to empty; fall back to original."""
    assert chapter_agent_module._derive_chapter_slug("-chapter") == "-chapter"


# ── HAPPY: env var override beats derivation ────────────────────


def test_chapter_slug_env_var_wins_over_derivation(monkeypatch: pytest.MonkeyPatch) -> None:
    """Once production sets CHAPTER_SLUG explicitly, the derivation must
    not run — operators control the URL identity, not the runtime."""
    monkeypatch.setenv("AGENT_ID", "TEST-boston-chapter")
    monkeypatch.setenv("AGENT_NAME", "Boston")
    monkeypatch.setenv("XAI_API_KEY", "test-key")
    monkeypatch.setenv("CHAPTER_SLUG", "beantown")
    monkeypatch.setenv("CHAPTER_DISPLAY_NAME", "Boston Beantown")
    sys.modules.pop("chapter_agent", None)
    mod = importlib.import_module("chapter_agent")
    assert mod.CHAPTER_SLUG == "beantown"
    assert mod.CHAPTER_DISPLAY_NAME == "Boston Beantown"


def test_chapter_slug_env_blank_falls_back_to_derivation(monkeypatch: pytest.MonkeyPatch) -> None:
    """Whitespace-only env var is treated as unset (not as a literal
    empty slug). The fallback derivation runs."""
    monkeypatch.setenv("AGENT_ID", "TEST-tokyo-chapter")
    monkeypatch.setenv("AGENT_NAME", "Tokyo")
    monkeypatch.setenv("XAI_API_KEY", "test-key")
    monkeypatch.setenv("CHAPTER_SLUG", "   ")
    sys.modules.pop("chapter_agent", None)
    mod = importlib.import_module("chapter_agent")
    assert mod.CHAPTER_SLUG == "tokyo"


def test_chapter_display_name_falls_back_to_agent_name(chapter_agent_module) -> None:
    """When CHAPTER_DISPLAY_NAME is unset, AGENT_NAME is the human label."""
    assert chapter_agent_module.CHAPTER_DISPLAY_NAME == chapter_agent_module.AGENT_NAME
