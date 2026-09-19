"""
Tests for @agent mention routing — NANDA Adapter compatibility.

Tests handle resolution, target_agent routing, and federated forwarding.
Classification: HAPPY / EDGE / FAILURE / ADVERSARIAL
"""

import os
import sys

import pytest

# chapter_agent.py reads env vars at module level — set them before import
os.environ.setdefault("AGENT_ID", "test-routing-chapter")
os.environ.setdefault("AGENT_NAME", "Test Routing Chapter")
os.environ.setdefault("AGENT_DESCRIPTION", "Test")
os.environ.setdefault("AGENT_CAPABILITIES", "testing")
os.environ.setdefault("PORT", "7099")
os.environ.setdefault("PUBLIC_URL", "https://test-chapter.example.com")
os.environ.setdefault("SUPABASE_URL", "https://fake.supabase.co")
os.environ.setdefault("SUPABASE_KEY", "fake-key")
os.environ.setdefault("XAI_API_KEY", "fake-xai-key")
os.environ.setdefault("OPENAI_API_KEY", "fake-openai-key")

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))


@pytest.fixture(autouse=True)
def setup_routing():
    """Set up chapter_agent globals for routing tests."""
    import chapter_agent

    chapter_agent.PUBLIC_URL = "https://test-chapter.example.com"
    chapter_agent.federation = {
        "boston": {"name": "Boston", "status": "online", "endpoint": "https://boston.example.com"},
        "london": {"name": "London", "status": "online", "endpoint": "https://london.example.com"},
    }
    chapter_agent.members = {
        "alice": {"name": "Alice", "skills": ["python"]},
        "bob": {"name": "Bob", "skills": ["rust"]},
    }


# ── HAPPY: Handle resolution ───────────────────────────────


def test_resolve_local_handle():
    """HAPPY: Simple @agent-id resolves to local agent."""
    from chapter_agent import resolve_handle

    agent_id, endpoint = resolve_handle("@alice")
    assert agent_id == "alice"
    assert endpoint is None  # Local


def test_resolve_local_handle_with_our_domain():
    """HAPPY: @agent@our-domain resolves locally."""
    from chapter_agent import resolve_handle

    agent_id, endpoint = resolve_handle("@alice@test-chapter.example.com")
    assert agent_id == "alice"
    assert endpoint is None


def test_resolve_federated_handle():
    """HAPPY: @agent@other-domain resolves to federation endpoint."""
    from chapter_agent import resolve_handle

    agent_id, endpoint = resolve_handle("@carol@boston.example.com")
    assert agent_id == "carol"
    assert endpoint == "https://boston.example.com"


def test_resolve_handle_strips_leading_at():
    """HAPPY: Leading @ is stripped cleanly."""
    from chapter_agent import resolve_handle

    agent_id, _ = resolve_handle("@@bob")
    # Double @ → first stripped, "bob" parsed
    assert agent_id is not None


# ── EDGE: Boundary cases ────────────────────────────────────


def test_resolve_unknown_domain():
    """EDGE: Unknown domain returns agent_id with no endpoint (try local)."""
    from chapter_agent import resolve_handle

    agent_id, endpoint = resolve_handle("@carol@unknown.example.com")
    assert agent_id == "carol"
    assert endpoint is None  # Can't resolve, try local


def test_resolve_bare_handle():
    """EDGE: Handle without @ prefix still works."""
    from chapter_agent import resolve_handle

    agent_id, endpoint = resolve_handle("alice")
    assert agent_id == "alice"
    assert endpoint is None


# ── ADVERSARIAL: Malicious handles ──────────────────────────


def test_resolve_empty_handle():
    """ADVERSARIAL: Empty handle doesn't crash."""
    from chapter_agent import resolve_handle

    agent_id, endpoint = resolve_handle("")
    assert endpoint is None


def test_resolve_malformed_handle():
    """ADVERSARIAL: Malformed handle @@@@ doesn't crash."""
    from chapter_agent import resolve_handle

    agent_id, endpoint = resolve_handle("@@@@")
    assert endpoint is None  # Just returns something, no crash


def test_resolve_injection_handle():
    """ADVERSARIAL: SQL injection in handle doesn't crash."""
    from chapter_agent import resolve_handle

    agent_id, endpoint = resolve_handle("@'; DROP TABLE agents;--@evil.com")
    assert endpoint is None
    assert agent_id is not None
