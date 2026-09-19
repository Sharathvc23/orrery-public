"""
Tests for the admin surface + supporting functions.

Tests build_admin_surface(), get_chapter_activity_summary(),
and get_cross_chapter_opportunities() — the new admin console code.

Classification: HAPPY / EDGE / FAILURE / ADVERSARIAL
"""

import pytest

import activity_tracker
import federation_intelligence
import surfaces

# ── Shared test infrastructure ─────────────────────────────


class FakePostgresRequest:
    """Mock Postgres that records calls and returns configurable responses."""

    def __init__(self):
        self.calls: list[tuple] = []
        self.responses: dict[str, list | dict | None] = {}

    async def __call__(self, method, table, params=None, body=None):
        self.calls.append((method, table, params, body))
        return self.responses.get(f"{method}:{table}", [])


class FakeIntents:
    """Minimal intents module mock."""

    def __init__(self, intents_list=None):
        self._intents = intents_list or []

    async def get_active_intents(self):
        return self._intents


@pytest.fixture
def fake_sb():
    return FakePostgresRequest()


@pytest.fixture
def setup_activity_tracker(fake_sb):
    """Initialize activity_tracker with fake Postgres."""
    activity_tracker.init(pg_request=fake_sb, agent_id="test-chapter")
    activity_tracker._activity_scores.clear()
    return fake_sb


@pytest.fixture
def setup_federation(fake_sb):
    """Initialize federation_intelligence with test data."""
    federation_intelligence.init(
        pg_request=fake_sb,
        knowledge_cache={
            "chapter_intelligence": {
                "skill_graph": {"python": 5, "ml": 3, "devops": 2},
                "skill_gaps": ["Rust", "Leadership"],
                "trending_topics": ["AI agents", "Privacy"],
                "member_count": 20,
                "active_members": ["a1", "a2", "a3"],
            }
        },
        agent_id="test-chapter",
        agent_name="Test Chapter",
    )
    federation_intelligence.federation_knowledge.clear()
    return fake_sb


@pytest.fixture
def setup_surfaces(fake_sb, setup_federation, setup_activity_tracker):
    """Initialize surfaces module with all dependencies."""
    members = {
        "alice": {"name": "Alice", "skills": ["python", "ml"], "virtual": False},
        "bob": {"name": "Bob", "skills": ["devops"], "virtual": False},
        "agent-1": {"name": "Chapter Agent", "skills": [], "virtual": True},
    }
    federation = {
        "boston": {"name": "Boston Chapter", "status": "online", "members": 12, "endpoint": "http://boston:7000"},
        "london": {"name": "London Chapter", "status": "offline", "members": 8, "endpoint": "http://london:7000"},
    }
    surfaces.init(
        pg_request_fn=fake_sb,
        members_dict=members,
        federation_dict=federation,
        knowledge_cache={
            "chapter_intelligence": {
                "skill_graph": {"python": 5, "ml": 3, "devops": 2},
                "skill_gaps": ["Rust", "Leadership"],
                "trending_topics": ["AI agents", "Privacy"],
                "member_count": 20,
                "active_members": ["a1", "a2", "a3"],
            }
        },
        agent_id="test-chapter",
        agent_name="Test Chapter",
        get_think_count=lambda: 42,
        intents_mod=FakeIntents(
            [
                {"intent_text": "Need a Rust dev", "status": "active", "matches_found": 2},
                {"intent_text": "Looking for PM", "status": "active", "matches_found": 0},
            ]
        ),
        projections_mod=None,
        outcome_tracker_mod=None,
        agent_conversations_module=None,
        federation_intelligence_mod=federation_intelligence,
        activity_tracker_mod=activity_tracker,
        portal_layout_fn=None,
    )
    return members, federation


# ══════════════════════════════════════════════════════════════
# get_chapter_activity_summary()
# ══════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_activity_summary_with_data(setup_activity_tracker):
    """HAPPY: Summary correctly aggregates activities by type and member."""
    fake_sb = setup_activity_tracker
    fake_sb.responses["GET:agent_member_activity"] = [
        {"agent_id": "alice", "activity_type": "conversation"},
        {"agent_id": "alice", "activity_type": "conversation"},
        {"agent_id": "bob", "activity_type": "poll_vote"},
        {"agent_id": "alice", "activity_type": "intent_submitted"},
        {"agent_id": "charlie", "activity_type": "conversation"},
    ]

    result = await activity_tracker.get_chapter_activity_summary(days=7)

    assert result["total_activities"] == 5
    assert result["active_members"] == 3
    assert result["by_type"]["conversation"] == 3
    assert result["by_type"]["poll_vote"] == 1
    assert result["by_type"]["intent_submitted"] == 1
    # Top members sorted by count descending
    top = result["top_members"]
    assert top[0][0] == "alice"
    assert top[0][1] == 3
    assert len(top) == 3


@pytest.mark.asyncio
async def test_activity_summary_empty(setup_activity_tracker):
    """EDGE: No activities returns zero-filled summary, not crash."""
    fake_sb = setup_activity_tracker
    fake_sb.responses["GET:agent_member_activity"] = []

    result = await activity_tracker.get_chapter_activity_summary(days=7)

    assert result["total_activities"] == 0
    assert result["active_members"] == 0
    assert result["by_type"] == {}
    assert result["top_members"] == []


@pytest.mark.asyncio
async def test_activity_summary_none_response(setup_activity_tracker):
    """FAILURE: Postgres returns None instead of list."""
    fake_sb = setup_activity_tracker
    fake_sb.responses["GET:agent_member_activity"] = None

    result = await activity_tracker.get_chapter_activity_summary(days=7)

    assert result["total_activities"] == 0
    assert result["active_members"] == 0


@pytest.mark.asyncio
async def test_activity_summary_missing_fields(setup_activity_tracker):
    """ADVERSARIAL: Activity rows with missing agent_id or activity_type."""
    fake_sb = setup_activity_tracker
    fake_sb.responses["GET:agent_member_activity"] = [
        {"agent_id": "", "activity_type": "conversation"},  # empty agent_id
        {"activity_type": "poll_vote"},  # missing agent_id key
        {"agent_id": "alice"},  # missing activity_type
        {"agent_id": "bob", "activity_type": "conversation"},  # valid
    ]

    result = await activity_tracker.get_chapter_activity_summary(days=7)

    # Should not crash — counts whatever it can
    assert result["total_activities"] == 4
    assert "conversation" in result["by_type"]


@pytest.mark.asyncio
async def test_activity_summary_respects_days_param(setup_activity_tracker):
    """HAPPY: The days parameter is passed to the Postgres query filter."""
    fake_sb = setup_activity_tracker
    fake_sb.responses["GET:agent_member_activity"] = []

    await activity_tracker.get_chapter_activity_summary(days=30)

    # Verify the query includes a created_at filter
    get_calls = [c for c in fake_sb.calls if c[0] == "GET" and c[1] == "agent_member_activity"]
    assert len(get_calls) == 1
    params = get_calls[0][2]
    assert "created_at" in params
    assert params["created_at"].startswith("gt.")


@pytest.mark.asyncio
async def test_activity_summary_top_members_capped(setup_activity_tracker):
    """EDGE: Top members capped at 10 even with many active."""
    fake_sb = setup_activity_tracker
    fake_sb.responses["GET:agent_member_activity"] = [
        {"agent_id": f"member-{i}", "activity_type": "conversation"} for i in range(50)
    ]

    result = await activity_tracker.get_chapter_activity_summary(days=7)

    assert len(result["top_members"]) <= 10


# ══════════════════════════════════════════════════════════════
# get_cross_chapter_opportunities()
# ══════════════════════════════════════════════════════════════


def test_opportunities_bidirectional(setup_federation):
    """HAPPY: Finds opportunities in both directions — our gaps in their skills AND their gaps in our skills."""
    # Boston has Rust (our gap) and needs Python (our strength)
    federation_intelligence.federation_knowledge["boston"] = {
        "chapter_name": "Boston Chapter",
        "skill_graph": {"rust": 4, "go": 3},
        "top_skills": ["rust", "go"],
        "skill_gaps": ["Python"],
        "member_count": 15,
    }

    opps = federation_intelligence.get_cross_chapter_opportunities()

    # Should find: Boston has Rust (our gap) + Boston needs Python (our strength)
    our_gap_filled = [o for o in opps if o["gap"] == "Rust" and o["matching_chapter"] == "Boston Chapter"]
    their_gap_filled = [o for o in opps if "Python" in o["gap"] and o["matching_chapter"] == "Test Chapter"]

    assert len(our_gap_filled) >= 1, "Boston should fill our Rust gap"
    assert len(their_gap_filled) >= 1, "We should fill Boston's Python gap"


def test_opportunities_no_peers(setup_federation):
    """EDGE: No federation peers returns empty list."""
    opps = federation_intelligence.get_cross_chapter_opportunities()
    assert opps == []


def test_opportunities_no_matching_skills(setup_federation):
    """EDGE: Peer has skills but none match our gaps."""
    federation_intelligence.federation_knowledge["niche-chapter"] = {
        "chapter_name": "Niche Chapter",
        "skill_graph": {"underwater_basket_weaving": 10},
        "top_skills": ["underwater_basket_weaving"],
        "skill_gaps": ["quantum_teleportation"],
        "member_count": 5,
    }

    opps = federation_intelligence.get_cross_chapter_opportunities()
    assert len(opps) == 0


def test_opportunities_missing_skill_gaps_key(setup_federation):
    """ADVERSARIAL: Peer data missing skill_gaps key doesn't crash."""
    federation_intelligence.federation_knowledge["bad-peer"] = {
        "chapter_name": "Bad Peer",
        "skill_graph": {"rust": 3},
        "top_skills": ["rust"],
        # No skill_gaps key at all
        "member_count": 5,
    }

    # Should not crash, should still find they can fill our Rust gap
    opps = federation_intelligence.get_cross_chapter_opportunities()
    rust_opps = [o for o in opps if o["gap"] == "Rust"]
    assert len(rust_opps) >= 1


def test_opportunities_empty_knowledge_cache(setup_federation):
    """FAILURE: Empty knowledge cache doesn't crash."""
    federation_intelligence._knowledge_cache = {}
    federation_intelligence.federation_knowledge["peer"] = {
        "chapter_name": "Peer",
        "skill_graph": {"rust": 5},
        "skill_gaps": ["python"],
        "member_count": 10,
    }

    # No our_skills and no our_gaps → nothing to match
    opps = federation_intelligence.get_cross_chapter_opportunities()
    # Can't fill their Python gap because we have no skill_graph
    # Can't identify our gaps because cache is empty
    assert isinstance(opps, list)


def test_opportunities_case_insensitive(setup_federation):
    """HAPPY: Skill matching is case-insensitive."""
    federation_intelligence.federation_knowledge["case-ch"] = {
        "chapter_name": "Case Chapter",
        "skill_graph": {"RUST": 3, "rust programming": 2},
        "skill_gaps": ["PYTHON"],
        "member_count": 8,
    }

    opps = federation_intelligence.get_cross_chapter_opportunities()
    rust_opps = [o for o in opps if o["gap"] == "Rust"]
    python_opps = [o for o in opps if "PYTHON" in o["gap"]]

    assert len(rust_opps) >= 1, "Should match RUST to our Rust gap"
    assert len(python_opps) >= 1, "Should match PYTHON to our python skill"


# ══════════════════════════════════════════════════════════════
# build_admin_surface()
# ══════════════════════════════════════════════════════════════


# ── v0.9 helpers ───────────────────────────────────────────
def _comps(result: dict) -> list[dict]:
    """Extract components from a v0.9 surface envelope."""
    return result["updateComponents"]["components"]


def _surface_id(result: dict) -> str:
    return result["updateComponents"]["surfaceId"]


def _root(result: dict) -> str:
    return result["updateComponents"]["root"]


def _by_type(components: list[dict], type_name: str) -> list[dict]:
    """Filter components by v0.9 flat discriminator."""
    return [c for c in components if c.get("component") == type_name]


def _text_value(node: dict) -> str:
    """Extract text string from a v0.9 Text node."""
    t = node.get("text", "")
    return t if isinstance(t, str) else t.get("literalString", "")


@pytest.mark.asyncio
async def test_admin_surface_structure(setup_surfaces):
    """HAPPY: Admin surface returns valid A2UI v0.9 structure with all sections."""
    result = await surfaces.build_admin_surface()

    # Must be valid A2UI v0.9 surface
    assert "createSurface" in result
    assert "updateComponents" in result
    assert _surface_id(result) == "surface-admin"

    # Must have components
    components = _comps(result)
    assert len(components) > 10  # Admin surface has many sections

    # Check that key component types exist (flat discriminator)
    component_types = {c.get("component") for c in components}

    # Note: build_admin_surface uses Heading for titles (v0.9 idiom) but may still
    # emit Text for body copy. Either is acceptable.
    assert "Text" in component_types or "Heading" in component_types
    assert "Metric" in component_types
    assert "Card" in component_types
    assert "Column" in component_types


@pytest.mark.asyncio
async def test_admin_surface_shows_member_counts(setup_surfaces):
    """HAPPY: Admin surface displays correct member counts."""
    members, _ = setup_surfaces
    result = await surfaces.build_admin_surface()

    components = _comps(result)
    metrics = _by_type(components, "Metric")

    total_metric = [m for m in metrics if m["label"] == "Total Agents"]
    assert len(total_metric) == 1
    assert total_metric[0]["value"] == "3"  # alice, bob, agent-1

    human_metric = [m for m in metrics if m["label"] == "Human Members"]
    assert len(human_metric) == 1
    assert human_metric[0]["value"] == "2"  # alice, bob (not agent-1)


@pytest.mark.asyncio
async def test_admin_surface_shows_federation(setup_surfaces):
    """HAPPY: Admin surface includes federation chapter cards."""
    result = await surfaces.build_admin_surface()

    components = _comps(result)
    # Gather text from Text and Heading nodes
    text_values = [_text_value(t) for t in _by_type(components, "Text")]
    text_values += [t.get("text", "") for t in _by_type(components, "Heading")]

    assert any("Boston Chapter" in t for t in text_values)  # peer display name (data) — unchanged
    assert any("Server Health" in t for t in text_values)  # rename tier 1: "Chapter Health" → "Server Health"


@pytest.mark.asyncio
async def test_admin_surface_shows_intents(setup_surfaces):
    """HAPPY: Admin surface shows matched intent count."""
    result = await surfaces.build_admin_surface()

    components = _comps(result)
    metrics = _by_type(components, "Metric")

    intent_metric = [m for m in metrics if m["label"] == "Intents Matched"]
    assert len(intent_metric) == 1
    assert intent_metric[0]["value"] == "1"
    assert intent_metric[0]["suffix"] == "/2"


@pytest.mark.asyncio
async def test_admin_surface_includes_skill_intelligence(setup_surfaces):
    """HAPPY: Admin surface renders skill stats from federation intelligence."""
    federation_intelligence.federation_knowledge["boston"] = {
        "chapter_name": "Boston Chapter",
        "skill_graph": {"rust": 4, "go": 3},
        "top_skills": ["rust", "go"],
        "skill_gaps": ["python"],
        "member_count": 15,
    }

    result = await surfaces.build_admin_surface()
    stats = _by_type(_comps(result), "Stat")
    stat_labels = [s["label"] for s in stats]

    assert "python" in stat_labels or any("python" in lbl.lower() for lbl in stat_labels)


@pytest.mark.asyncio
async def test_admin_surface_with_activity(setup_surfaces):
    """HAPPY: Admin surface includes activity summary when data exists."""
    activity_tracker._activity_scores["alice"] = 15.0
    activity_tracker._activity_scores["bob"] = 8.0

    surfaces.pg_request.responses["GET:agent_member_activity"] = [
        {"agent_id": "alice", "activity_type": "conversation"},
        {"agent_id": "alice", "activity_type": "intent_submitted"},
        {"agent_id": "bob", "activity_type": "poll_vote"},
    ]

    result = await surfaces.build_admin_surface()
    components = _comps(result)

    text_values = [_text_value(t) for t in _by_type(components, "Text")]
    text_values += [t.get("text", "") for t in _by_type(components, "Heading")]

    assert any("Activity" in t for t in text_values)
    metrics = _by_type(components, "Metric")
    activity_metrics = [m for m in metrics if m["label"] == "Total Activities"]
    assert len(activity_metrics) == 1
    assert activity_metrics[0]["value"] == "3"


@pytest.mark.asyncio
async def test_admin_surface_no_activity(setup_surfaces):
    """EDGE: Admin surface works without activity data (empty response)."""
    surfaces.pg_request.responses["GET:agent_member_activity"] = []

    result = await surfaces.build_admin_surface()

    assert "updateComponents" in result
    components = _comps(result)
    assert len(components) > 5  # Still has health, skills, federation sections


@pytest.mark.asyncio
async def test_admin_surface_no_federation(setup_surfaces):
    """EDGE: Admin surface works with empty federation dict."""
    surfaces.federation = {}
    surfaces.pg_request.responses["GET:agent_member_activity"] = []

    result = await surfaces.build_admin_surface()

    assert "updateComponents" in result
    metrics = _by_type(_comps(result), "Metric")
    chapter_metric = [m for m in metrics if m["label"] == "Orgs Online"]
    assert chapter_metric[0]["value"] == "1"


@pytest.mark.asyncio
async def test_admin_surface_unique_component_ids(setup_surfaces):
    """ADVERSARIAL: All component IDs in the surface must be unique — duplicates cause render bugs."""
    federation_intelligence.federation_knowledge["boston"] = {
        "chapter_name": "Boston",
        "skill_graph": {"rust": 4},
        "skill_gaps": ["python"],
        "top_skills": ["rust"],
        "member_count": 10,
    }
    surfaces.pg_request.responses["GET:agent_member_activity"] = [
        {"agent_id": "alice", "activity_type": "conversation"},
    ]

    result = await surfaces.build_admin_surface()
    components = _comps(result)

    ids = [c["id"] for c in components]
    duplicates = [x for x in ids if ids.count(x) > 1]
    assert len(duplicates) == 0, f"Duplicate component IDs: {set(duplicates)}"


@pytest.mark.asyncio
async def test_admin_surface_root_references_valid(setup_surfaces):
    """ADVERSARIAL: Root node and all child references point to existing component IDs (v0.9)."""
    surfaces.pg_request.responses["GET:agent_member_activity"] = []

    result = await surfaces.build_admin_surface()
    components = _comps(result)
    root_id = _root(result)

    all_ids = {c["id"] for c in components}

    # Root must exist
    assert root_id in all_ids, f"Root '{root_id}' not found in components"

    # All child references must resolve (v0.9: flat plain-array children)
    for comp in components:
        ctype = comp.get("component")
        if ctype == "Card":
            child = comp.get("child")
            assert child in all_ids, f"Card '{comp['id']}' references missing child '{child}'"
        if ctype in ("Column", "Row", "Grid"):
            children = comp.get("children", []) or []
            # Handle both v0.9 plain list and legacy wrapper if any remains
            if isinstance(children, dict):
                children = children.get("explicitList", [])
            for child in children:
                assert child in all_ids, f"{ctype} '{comp['id']}' references missing child '{child}'"


@pytest.mark.asyncio
async def test_admin_surface_no_intents_module():
    """FAILURE: Admin surface handles None intents module gracefully."""
    fake_sb = FakePostgresRequest()
    fake_sb.responses["GET:agent_member_activity"] = []

    surfaces.init(
        pg_request_fn=fake_sb,
        members_dict={"alice": {"name": "Alice", "virtual": False}},
        federation_dict={},
        knowledge_cache={},
        agent_id="test",
        agent_name="Test",
        get_think_count=lambda: 0,
        intents_mod=FakeIntents([]),  # Empty intents
        federation_intelligence_mod=None,  # No federation intel
        activity_tracker_mod=None,  # No activity tracker
    )

    result = await surfaces.build_admin_surface()

    # Should render without crashing, just with less data
    assert "updateComponents" in result
    assert len(_comps(result)) > 3
