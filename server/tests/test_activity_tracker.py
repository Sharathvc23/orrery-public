"""Tests for activity_tracker.py — weighted evolution, reputation, edge cases."""

import pytest

import activity_tracker


class FakePostgresRequest:
    """Mock Postgres that records calls and returns configurable responses."""

    def __init__(self):
        self.calls: list[tuple] = []
        self.responses: dict[str, list | dict | None] = {}

    async def __call__(self, method, table, params=None, body=None):
        self.calls.append((method, table, params, body))
        return self.responses.get(f"{method}:{table}")


@pytest.fixture
def tracker():
    fake_sb = FakePostgresRequest()
    activity_tracker.init(pg_request=fake_sb, agent_id="test-chapter")
    activity_tracker._activity_scores.clear()
    return fake_sb


# --- Weighted Selection ---


def test_pick_weighted_member_empty():
    """Empty members dict returns None."""
    assert activity_tracker.pick_weighted_member({}) is None


def test_pick_weighted_member_single():
    """Single member always picked."""
    activity_tracker._activity_scores.clear()
    result = activity_tracker.pick_weighted_member({"alice": {}})
    assert result == "alice"


def test_pick_weighted_member_prefers_active():
    """Active member picked more often than inactive (statistical)."""
    activity_tracker._activity_scores.clear()
    activity_tracker._activity_scores["active-member"] = 100.0
    activity_tracker._activity_scores["inactive-member"] = 0.0

    members = {"active-member": {}, "inactive-member": {}}
    picks = [activity_tracker.pick_weighted_member(members) for _ in range(100)]
    active_count = picks.count("active-member")
    # Active member should be picked >80% of the time with score 100 vs baseline 1
    assert active_count > 80, f"Active picked only {active_count}/100 times"


def test_inactive_members_still_have_chance():
    """Even members with zero activity get baseline score of 1.0."""
    weighted = activity_tracker.get_weighted_members({"zero-score": {}})
    assert weighted[0][1] == 1.0  # Baseline


# --- Score Calculations ---


def test_score_for_known_types():
    """All known activity types have defined scores."""
    known_types = [
        "introduction_received",
        "conversation",
        "poll_vote",
        "event_rsvp",
        "event_proposed",
        "startup_collaboration",
        "member_thought",
        "introduction_given",
    ]
    for t in known_types:
        assert activity_tracker._score_for(t) > 0, f"Missing score for {t}"


def test_score_for_unknown_type():
    """Unknown activity type gets default score of 1.0."""
    assert activity_tracker._score_for("unknown_type_xyz") == 1.0


def test_reputation_field_mapping():
    """All activity types map to valid reputation fields."""
    expected = {
        "introduction_received": "introductions",
        "conversation": "contributions",
        "poll_vote": "votes",
        "event_rsvp": "events",
        "startup_collaboration": "sprints",
    }
    for activity, field in expected.items():
        assert activity_tracker._reputation_field(activity) == field


def test_reputation_field_unknown():
    """Unknown activity type returns None (no reputation field)."""
    assert activity_tracker._reputation_field("random_unknown") is None


# --- Track Function ---


@pytest.mark.asyncio
async def test_track_increments_score(tracker):
    """Tracking activity increments in-memory score."""
    activity_tracker._activity_scores.clear()
    await activity_tracker.track("alice", "conversation")
    assert activity_tracker.get_activity_score("alice") == 1.5


@pytest.mark.asyncio
async def test_track_multiple_activities(tracker):
    """Multiple activities accumulate."""
    activity_tracker._activity_scores.clear()
    await activity_tracker.track("bob", "conversation")  # 1.5
    await activity_tracker.track("bob", "introduction_received")  # 2.0
    await activity_tracker.track("bob", "poll_vote")  # 1.0
    assert activity_tracker.get_activity_score("bob") == pytest.approx(4.5)


@pytest.mark.asyncio
async def test_track_persists_to_db(tracker):
    """Activity is persisted to Postgres."""
    await activity_tracker.track("alice", "conversation", {"topic": "test"})
    # Give fire-and-forget task a moment
    import asyncio

    await asyncio.sleep(0.1)
    post_calls = [c for c in tracker.calls if c[0] == "POST" and c[1] == "agent_member_activity"]
    assert len(post_calls) >= 1


# --- Edge Cases ---


def test_get_activity_score_nonexistent():
    """Non-existent member has score 0."""
    activity_tracker._activity_scores.clear()
    assert activity_tracker.get_activity_score("ghost") == 0


def test_weighted_members_sorted():
    """Weighted members returned sorted by score descending."""
    activity_tracker._activity_scores.clear()
    activity_tracker._activity_scores["a"] = 5.0
    activity_tracker._activity_scores["b"] = 10.0
    activity_tracker._activity_scores["c"] = 1.0

    members = {"a": {}, "b": {}, "c": {}}
    weighted = activity_tracker.get_weighted_members(members)
    scores = [s for _, s in weighted]
    assert scores == sorted(scores, reverse=True)


# --- Adversarial ---


@pytest.mark.asyncio
async def test_track_empty_agent_id(tracker):
    """Empty agent_id doesn't crash."""
    await activity_tracker.track("", "conversation")
    assert activity_tracker.get_activity_score("") == 1.5


@pytest.mark.asyncio
async def test_track_very_long_data(tracker):
    """Very long activity data doesn't crash."""
    await activity_tracker.track("alice", "conversation", {"topic": "x" * 10000})


@pytest.mark.asyncio
async def test_track_special_characters(tracker):
    """Special characters in agent_id and data don't crash."""
    await activity_tracker.track("alice's-agent@test", "conversation", {"topic": "'); DROP TABLE agents;--"})


def test_pick_weighted_large_member_set():
    """Weighted selection works with many members."""
    activity_tracker._activity_scores.clear()
    members = {f"member-{i}": {} for i in range(1000)}
    result = activity_tracker.pick_weighted_member(members)
    assert result is not None
    assert result.startswith("member-")
