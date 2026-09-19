"""Tests for federation_intelligence.py — knowledge exchange, skill matching, edge cases."""

import pytest

import federation_intelligence


class FakePostgresRequest:
    def __init__(self):
        self.calls = []

    async def __call__(self, method, table, params=None, body=None):
        self.calls.append((method, table, params, body))
        return None


@pytest.fixture
def fed_intel():
    fake_sb = FakePostgresRequest()
    federation_intelligence.init(
        pg_request=fake_sb,
        knowledge_cache={
            "chapter_intelligence": {
                "skill_graph": {"python": 3, "rust": 1, "orchestration": 2},
                "skill_gaps": ["Rust programming", "Leadership"],
                "trending_topics": ["AI ethics", "Climate tech"],
                "recommendations": ["Host Rust workshop"],
                "patterns": ["Insight-heavy activity"],
                "member_count": 25,
                "active_members": ["alice", "bob", "charlie"],
                "last_reflected": "2026-04-10T12:00:00Z",
            }
        },
        agent_id="test-chapter",
        agent_name="Test Chapter",
    )
    federation_intelligence.federation_knowledge.clear()
    return fake_sb


# --- Summary Generation ---


def test_get_our_summary(fed_intel):
    """Summary includes all expected fields."""
    summary = federation_intelligence.get_our_summary()
    assert summary["chapter_id"] == "test-chapter"
    assert summary["chapter_name"] == "Test Chapter"
    assert summary["member_count"] == 25
    assert summary["active_member_count"] == 3
    assert "python" in summary["skill_graph"]
    assert len(summary["top_skills"]) <= 10
    assert "Rust programming" in summary["skill_gaps"]


def test_get_our_summary_empty_cache():
    """Summary with no intelligence returns empty defaults."""
    federation_intelligence._knowledge_cache = {}
    summary = federation_intelligence.get_our_summary()
    assert summary["skill_graph"] == {}
    assert summary["member_count"] == 0


# --- Skill Matching ---


def test_find_skill_matches_with_peers(fed_intel):
    """Finds matches when peer has skills matching our gaps."""
    federation_intelligence.federation_knowledge["austin-chapter"] = {
        "chapter_name": "Austin Chapter",
        "skill_graph": {"rust": 5, "go": 3},
        "top_skills": ["rust", "go"],
        "skill_gaps": [],
        "member_count": 15,
    }
    matches = federation_intelligence.find_skill_matches()
    rust_matches = [m for m in matches if "Rust" in m["our_gap"]]
    assert len(rust_matches) >= 1
    assert rust_matches[0]["their_chapter_name"] == "Austin Chapter"


def test_find_skill_matches_no_peers(fed_intel):
    """No matches when no peers have knowledge."""
    matches = federation_intelligence.find_skill_matches()
    assert matches == []


def test_find_skill_matches_custom_gaps(fed_intel):
    """Can pass custom gaps instead of using chapter intelligence."""
    federation_intelligence.federation_knowledge["seattle-chapter"] = {
        "chapter_name": "Seattle",
        "skill_graph": {"kubernetes": 4},
        "top_skills": ["kubernetes"],
        "skill_gaps": [],
        "member_count": 10,
    }
    matches = federation_intelligence.find_skill_matches(our_gaps=["kubernetes"])
    assert len(matches) == 1
    assert matches[0]["their_chapter_name"] == "Seattle"


# --- Network Aggregation ---


def test_get_network_skill_map(fed_intel):
    """Network skill map aggregates across chapters."""
    federation_intelligence.federation_knowledge["peer-1"] = {
        "chapter_name": "Peer 1",
        "skill_graph": {"python": 2, "ml": 5},
    }
    skill_map = federation_intelligence.get_network_skill_map()
    # Python should appear in both chapters
    assert skill_map["python"]["total"] == 5  # 3 ours + 2 peer
    assert len(skill_map["python"]["chapters"]) == 2
    # ML only in peer
    assert skill_map["ml"]["total"] == 5


def test_get_network_skill_map_empty(fed_intel):
    """Network map with no peers returns only our skills."""
    skill_map = federation_intelligence.get_network_skill_map()
    assert "python" in skill_map
    assert skill_map["python"]["total"] == 3  # Only ours


def test_get_network_trends(fed_intel):
    """Trends aggregated and deduplicated across chapters."""
    federation_intelligence.federation_knowledge["peer-1"] = {
        "trending_topics": ["AI ethics", "Quantum computing"],
    }
    trends = federation_intelligence.get_network_trends()
    assert "AI ethics" in trends  # From our chapter
    assert "Quantum computing" in trends  # From peer
    # No duplicates
    assert trends.count("AI ethics") == 1


def test_get_network_trends_empty(fed_intel):
    """Trends with no peers returns only our topics."""
    trends = federation_intelligence.get_network_trends()
    assert trends == ["AI ethics", "Climate tech"]


# --- Edge Cases ---


def test_skill_match_case_insensitive(fed_intel):
    """Skill matching is case-insensitive."""
    federation_intelligence.federation_knowledge["case-test"] = {
        "chapter_name": "Case Test",
        "skill_graph": {"RUST": 3},
        "top_skills": ["RUST"],
        "skill_gaps": [],
        "member_count": 5,
    }
    matches = federation_intelligence.find_skill_matches()
    rust_matches = [m for m in matches if "Rust" in m["our_gap"]]
    assert len(rust_matches) >= 1


def test_federation_knowledge_overwrite(fed_intel):
    """New exchange overwrites old data for same chapter."""
    federation_intelligence.federation_knowledge["ch-1"] = {"member_count": 10}
    federation_intelligence.federation_knowledge["ch-1"] = {"member_count": 20}
    assert federation_intelligence.federation_knowledge["ch-1"]["member_count"] == 20


# --- Adversarial ---


def test_network_skill_map_handles_missing_fields(fed_intel):
    """Handles peers with missing or malformed skill_graph."""
    federation_intelligence.federation_knowledge["bad-peer"] = {
        "chapter_name": "Bad Peer",
        # Missing skill_graph entirely
    }
    skill_map = federation_intelligence.get_network_skill_map()
    assert "python" in skill_map  # Our skills still work


def test_find_matches_handles_empty_skill_graph(fed_intel):
    """Peer with empty skill_graph doesn't match anything."""
    federation_intelligence.federation_knowledge["empty-peer"] = {
        "chapter_name": "Empty",
        "skill_graph": {},
        "top_skills": [],
        "skill_gaps": [],
        "member_count": 0,
    }
    matches = federation_intelligence.find_skill_matches()
    empty_matches = [m for m in matches if m["their_chapter_name"] == "Empty"]
    assert len(empty_matches) == 0
