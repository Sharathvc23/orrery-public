"""
Prosecution-grade tests for mesh.py — unified agent-facing mesh interface.

Covers: peer discovery, find_peer, send_to_peer (local + federation),
submit_intent, my_trust, oversized-message rejection, self-send
rejection, peer_grid shaping.

Classification: HAPPY / EDGE / FAILURE / ADVERSARIAL
"""

from __future__ import annotations

import pytest

import mesh

# ─── Fakes ───────────────────────────────────────────────


class _FakeIntents:
    def __init__(self):
        self.created: list[dict] = []

    async def create_intent(self, requester_agent_id, intent_text, intent_tags):
        iid = f"intent-{len(self.created) + 1}"
        self.created.append({"id": iid, "requester": requester_agent_id, "text": intent_text, "tags": intent_tags})
        return iid


class _FakeFI:
    """Stand-in for federation_intelligence."""

    def get_cross_chapter_opportunities(self):
        return [
            {"gap": "Rust", "matching_chapter": "Boston", "matches": [{"agent_id": "a"}]},
            {"gap": "Leadership", "matching_chapter": "Tokyo", "matches": []},
        ]


class _FakeGov:
    async def compute_trust_score(self, agent_id: str) -> float:
        return {"alice": 62.0, "bob": 10.0, "carol": 80.0}.get(agent_id, 0.0)


_MEMBERS = {
    "alice": {"name": "Alice", "skills": ["python", "ml"], "trust_score": 62.0, "virtual": False},
    "bob": {"name": "Bob", "skills": ["devops"], "trust_score": 10.0, "virtual": False},
    "chapter-agent": {"name": "Chapter Agent", "skills": [], "virtual": True},
}

_FEDERATION_WITH_CACHE = {
    "boston": {
        "name": "Boston",
        "status": "online",
        "members_cache": [
            {
                "agent_id": "charlie",
                "name": "Charlie",
                "skills": ["rust", "climate"],
                "trust_score": 55.0,
            },
            {
                "agent_id": "dana",
                "name": "Dana",
                "skills": ["design"],
                "trust_score": 30.0,
            },
        ],
    },
    "tokyo": {
        "name": "Tokyo",
        "status": "offline",
        "members_cache": [{"agent_id": "eve", "name": "Eve", "skills": ["robotics"], "trust_score": 80.0}],
    },
}


@pytest.fixture
def setup_mesh():
    intents = _FakeIntents()
    mesh.init(
        pg_request=None,
        members=dict(_MEMBERS),
        federation=dict(_FEDERATION_WITH_CACHE),
        agent_id="test-chapter",
        intents_module=intents,
        federation_intelligence_module=_FakeFI(),
        federation_discovery_module=None,
        auth_verify_module=None,
        governance_module=_FakeGov(),
    )
    return intents


# ═══════════════════════════════════════════════════════════════
# get_mesh_state
# ═══════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_get_mesh_state_counts_real_members(setup_mesh):
    state = await mesh.get_mesh_state()
    # alice + bob, not chapter-agent (virtual)
    assert state["members_here"] == 2
    assert state["peers_online"] == 1
    assert state["peers_offline"] == 1


@pytest.mark.asyncio
async def test_get_mesh_state_includes_opportunities(setup_mesh):
    state = await mesh.get_mesh_state()
    assert len(state["opportunities"]) == 2
    assert state["opportunities"][0]["gap"] == "Rust"


@pytest.mark.asyncio
async def test_get_mesh_state_self_trust_resolved(setup_mesh):
    state = await mesh.get_mesh_state(agent_id="alice")
    assert state["my_trust"]["tier"] == "trusted"
    assert state["my_trust"]["trust_score"] == 62.0


# ═══════════════════════════════════════════════════════════════
# list_peers
# ═══════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_list_peers_returns_locals_and_federated(setup_mesh):
    peers = await mesh.list_peers()
    ids = {p["agent_id"] for p in peers}
    # Locals
    assert "alice" in ids and "bob" in ids
    # Federated
    assert "charlie" in ids and "dana" in ids and "eve" in ids


@pytest.mark.asyncio
async def test_list_peers_excludes_virtual(setup_mesh):
    peers = await mesh.list_peers()
    assert not any(p["agent_id"] == "chapter-agent" for p in peers)


@pytest.mark.asyncio
async def test_list_peers_filters_by_skill(setup_mesh):
    peers = await mesh.list_peers(skills=["rust"])
    assert {p["agent_id"] for p in peers} == {"charlie"}


@pytest.mark.asyncio
async def test_list_peers_query_searches_name_and_id(setup_mesh):
    peers = await mesh.list_peers(query="alice")
    assert {p["agent_id"] for p in peers} == {"alice"}
    peers_by_name = await mesh.list_peers(query="charlie")
    assert {p["agent_id"] for p in peers_by_name} == {"charlie"}


@pytest.mark.asyncio
async def test_list_peers_respects_limit(setup_mesh):
    peers = await mesh.list_peers(limit=2)
    assert len(peers) == 2


@pytest.mark.asyncio
async def test_list_peers_scoped_to_chapter(setup_mesh):
    peers = await mesh.list_peers(chapter_id="tokyo")
    assert {p["agent_id"] for p in peers} == {"alice", "bob", "eve"} or {p["agent_id"] for p in peers} == {"eve"}
    # Accept either: some impls include locals always, ours does.
    tokyo_peers = [p for p in peers if p.get("chapter_id") == "tokyo"]
    assert {p["agent_id"] for p in tokyo_peers} == {"eve"}


# ═══════════════════════════════════════════════════════════════
# find_peer
# ═══════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_find_peer_local(setup_mesh):
    p = await mesh.find_peer("alice")
    assert p is not None
    assert p["local"] is True
    assert p["chapter_id"] == "test-chapter"


@pytest.mark.asyncio
async def test_find_peer_federated(setup_mesh):
    p = await mesh.find_peer("charlie")
    assert p is not None
    assert p["local"] is False
    assert p["chapter_id"] == "boston"


@pytest.mark.asyncio
async def test_find_peer_missing_returns_none(setup_mesh):
    assert await mesh.find_peer("ghost") is None


# ═══════════════════════════════════════════════════════════════
# send_to_peer
# ═══════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_send_to_local_peer(setup_mesh):
    r = await mesh.send_to_peer("alice", "bob", "hi")
    assert r["delivery"] == "local"
    assert r["ok"] is True


@pytest.mark.asyncio
async def test_send_to_federated_peer(setup_mesh):
    r = await mesh.send_to_peer("alice", "charlie", "collab on rust?")
    assert r["delivery"] == "federation"
    assert r["chapter_id"] == "boston"


@pytest.mark.asyncio
async def test_send_rejects_unknown_peer(setup_mesh):
    with pytest.raises(ValueError, match="not found in mesh"):
        await mesh.send_to_peer("alice", "ghost", "hi")


@pytest.mark.asyncio
async def test_send_rejects_self(setup_mesh):
    """EDGE: you can't send a message to yourself — protects against prompt-injection loops."""
    with pytest.raises(ValueError, match="cannot send a message to yourself"):
        await mesh.send_to_peer("alice", "alice", "hi")


@pytest.mark.asyncio
async def test_send_rejects_empty_text(setup_mesh):
    with pytest.raises(ValueError, match="text is required"):
        await mesh.send_to_peer("alice", "bob", "   ")


@pytest.mark.asyncio
async def test_send_rejects_oversized_text(setup_mesh):
    """ADVERSARIAL: 32 KiB payload rejected."""
    huge = "x" * (32 * 1024)
    with pytest.raises(ValueError, match="too large"):
        await mesh.send_to_peer("alice", "bob", huge)


@pytest.mark.asyncio
async def test_send_rejects_empty_sender(setup_mesh):
    with pytest.raises(ValueError, match="sender"):
        await mesh.send_to_peer("", "bob", "hi")


# ═══════════════════════════════════════════════════════════════
# submit_intent
# ═══════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_submit_intent_happy(setup_mesh):
    intents = setup_mesh
    result = await mesh.submit_intent("alice", "find a rust dev", tags=["rust", "climate"])
    assert result["intent_id"] == "intent-1"
    assert intents.created[0]["text"] == "find a rust dev"


@pytest.mark.asyncio
async def test_submit_intent_sanitizes_tags(setup_mesh):
    """ADVERSARIAL: inject SQL-ish characters into tags → stripped, not passed through."""
    intents = setup_mesh
    await mesh.submit_intent("alice", "text", tags=["'; DROP TABLE--", "rust<script>"])
    # Tags cleaned to safe charset.
    saved_tags = intents.created[0]["tags"]
    for t in saved_tags:
        assert all(c.isalnum() or c in "._-" for c in t), f"bad char in {t!r}"


@pytest.mark.asyncio
async def test_submit_intent_rejects_empty_text(setup_mesh):
    with pytest.raises(ValueError, match="intent text is required"):
        await mesh.submit_intent("alice", "")


@pytest.mark.asyncio
async def test_submit_intent_rejects_oversized(setup_mesh):
    with pytest.raises(ValueError, match="too long"):
        await mesh.submit_intent("alice", "x" * 3000)


# ═══════════════════════════════════════════════════════════════
# my_trust
# ═══════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_my_trust_tiers(setup_mesh):
    assert (await mesh.my_trust("alice"))["tier"] == "trusted"
    assert (await mesh.my_trust("bob"))["tier"] == "newcomer"
    assert (await mesh.my_trust("carol"))["tier"] == "power"


@pytest.mark.asyncio
async def test_my_trust_unknown_agent_newcomer(setup_mesh):
    result = await mesh.my_trust("ghost")
    assert result["trust_score"] == 0.0
    assert result["tier"] == "newcomer"


# ═══════════════════════════════════════════════════════════════
# peer_grid shape helper
# ═══════════════════════════════════════════════════════════════


def test_peer_grid_reshapes_for_membercard():
    grid = mesh.peer_grid(
        [
            {"agent_id": "a", "name": "A", "local": True, "trust_score": 40, "skills": ["x"]},
            {"agent_id": "b", "name": "B", "local": False, "chapter_id": "boston", "skills": []},
        ]
    )
    assert grid[0]["role"] == "here"
    assert grid[1]["role"] == "@boston"


def test_peer_grid_caps_skills_at_six():
    """EDGE: 8-skill member shows at most 6 in the card."""
    grid = mesh.peer_grid([{"agent_id": "a", "name": "A", "skills": [f"s{i}" for i in range(8)]}])
    assert len(grid[0]["skills"]) == 6
