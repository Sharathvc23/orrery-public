"""
Tests for AgentFacts versioning — CRDT-lite version tracking.

Tests monotonic version counter, ETag support, and conditional GET.
Classification: HAPPY / EDGE / FAILURE / ADVERSARIAL
"""

import pytest

import sovereign_identity


@pytest.fixture(autouse=True)
def setup():
    sovereign_identity._agent_id = "test-chapter"
    sovereign_identity._ed25519_keypairs.clear()
    sovereign_identity._facts_versions.clear()


SAMPLE_MEMBER = {"name": "Alice", "skills": ["python"], "description": "Test"}
PUBLIC_URL = "https://test.example.com"


# ── HAPPY: Version tracking ─────────────────────────────────


def test_version_increments():
    """HAPPY: Successive builds produce incrementing version numbers."""
    f1 = sovereign_identity.build_nanda_facts("alice", SAMPLE_MEMBER, public_url=PUBLIC_URL)
    f2 = sovereign_identity.build_nanda_facts("alice", SAMPLE_MEMBER, public_url=PUBLIC_URL)
    f3 = sovereign_identity.build_nanda_facts("alice", SAMPLE_MEMBER, public_url=PUBLIC_URL)

    assert f1["facts_version"] == 1
    assert f2["facts_version"] == 2
    assert f3["facts_version"] == 3


def test_version_per_agent():
    """HAPPY: Different agents have independent version counters."""
    fa = sovereign_identity.build_nanda_facts("alice", SAMPLE_MEMBER, public_url=PUBLIC_URL)
    fb = sovereign_identity.build_nanda_facts("bob", SAMPLE_MEMBER, public_url=PUBLIC_URL)
    fa2 = sovereign_identity.build_nanda_facts("alice", SAMPLE_MEMBER, public_url=PUBLIC_URL)

    assert fa["facts_version"] == 1
    assert fb["facts_version"] == 1
    assert fa2["facts_version"] == 2


def test_updated_at_changes():
    """HAPPY: updated_at timestamp changes between builds."""
    import time

    f1 = sovereign_identity.build_nanda_facts("alice", SAMPLE_MEMBER, public_url=PUBLIC_URL)
    time.sleep(0.01)  # Ensure different timestamp
    f2 = sovereign_identity.build_nanda_facts("alice", SAMPLE_MEMBER, public_url=PUBLIC_URL)

    assert f1["updated_at"] != f2["updated_at"]


def test_facts_version_field_present():
    """HAPPY: facts_version is always present in output."""
    facts = sovereign_identity.build_nanda_facts("alice", SAMPLE_MEMBER, public_url=PUBLIC_URL)
    assert "facts_version" in facts
    assert isinstance(facts["facts_version"], int)


def test_get_facts_version_monotonic():
    """HAPPY: get_facts_version returns strictly increasing values."""
    v1 = sovereign_identity.get_facts_version("test")
    v2 = sovereign_identity.get_facts_version("test")
    v3 = sovereign_identity.get_facts_version("test")

    assert v1 < v2 < v3


# ── EDGE: Boundary cases ────────────────────────────────────


def test_version_starts_at_one():
    """EDGE: First version for a new agent is 1, not 0."""
    facts = sovereign_identity.build_nanda_facts("new-agent", SAMPLE_MEMBER, public_url=PUBLIC_URL)
    assert facts["facts_version"] == 1


def test_version_survives_multiple_agents():
    """EDGE: Many agents don't interfere with each other's counters."""
    for i in range(50):
        sovereign_identity.build_nanda_facts(f"agent-{i}", SAMPLE_MEMBER, public_url=PUBLIC_URL)

    # Each should be at version 1
    for i in range(50):
        assert sovereign_identity._facts_versions[f"agent-{i}"] == 1

    # Build one more for agent-0
    f = sovereign_identity.build_nanda_facts("agent-0", SAMPLE_MEMBER, public_url=PUBLIC_URL)
    assert f["facts_version"] == 2
    # Others untouched
    assert sovereign_identity._facts_versions["agent-1"] == 1
