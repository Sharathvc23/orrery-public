"""
Prosecution-grade tests for A2A Agent Card.

Thesis:
  1. The card validates against the A2A v0.2 shape.
  2. Every one of our 20 AGENT_TOOLS maps to a declared A2A skill — nothing
     silently dropped, nothing invokable that isn't advertised.
  3. NANDA identity survives as an x-nanda extension without breaking
     A2A-only clients (which must still parse the card cleanly).
  4. The card survives empty/missing config fields — no crash when a
     member hasn't finished onboarding.

Classification: HAPPY / EDGE / FAILURE / ADVERSARIAL
"""

from __future__ import annotations

import json

import pytest

from community_member.a2a_card import CATCHALL_SKILL_ID, TOOL_TO_SKILL, build_agent_card
from community_member.a2a_models import AgentCard
from community_member.agent import AGENT_TOOLS

# ═══════════════════════════════════════════════════════
# HAPPY — card shape
# ═══════════════════════════════════════════════════════


def test_card_validates_as_agent_card_model():
    card = build_agent_card(
        agent_id="alice",
        display_name="Alice",
        description="hi",
        version="0.5.0",
        base_url="http://localhost:7777",
        chapter_url="https://chapter.example",
        did="did:key:z6Mk",
        skills_declared=["rust"],
        tools=AGENT_TOOLS,
    )
    assert isinstance(card, AgentCard)
    dumped = card.model_dump(mode="json", by_alias=True, exclude_none=True)
    # By-alias gives us the wire field name `x-nanda`, not `x_nanda`.
    assert "x-nanda" in dumped
    assert "x_nanda" not in dumped


def test_card_round_trips_through_json():
    card = build_agent_card(
        agent_id="alice",
        display_name="Alice",
        description="hi",
        version="0.5.0",
        base_url="http://localhost:7777",
        chapter_url="https://chapter.example",
        did="did:key:z6Mk",
        tools=AGENT_TOOLS,
    )
    blob = json.dumps(card.model_dump(mode="json", by_alias=True, exclude_none=True))
    reparsed = AgentCard.model_validate(json.loads(blob))
    assert reparsed.name == "Alice"


def test_card_declares_streaming_capability():
    """Day 3 will deliver SSE; the card advertises it upfront so clients
    can branch on `capabilities.streaming` before the endpoint lands."""
    card = build_agent_card(
        agent_id="alice",
        display_name=None,
        description=None,
        version="0.5.0",
        base_url="http://localhost:7777",
        chapter_url=None,
        did=None,
        tools=AGENT_TOOLS,
    )
    assert card.capabilities.streaming is True


def test_card_authentication_scheme_is_ed25519_hmac():
    """Our A2A handshake will use Ed25519 signed requests — matches the
    scheme string our server's `auth_verify` middleware expects."""
    card = build_agent_card(
        agent_id="alice",
        display_name=None,
        description=None,
        version="0.5.0",
        base_url="http://localhost:7777",
        chapter_url=None,
        did="did:key:z6Mk",
        tools=AGENT_TOOLS,
    )
    assert card.authentication.schemes == ["ed25519", "did-auth"]
    assert card.authentication.credentials == "did:key:z6Mk"


# ═══════════════════════════════════════════════════════
# HAPPY — tool→skill mapping completeness
# ═══════════════════════════════════════════════════════


def test_every_agent_tool_has_a_skill_mapping():
    """No tool should silently fall into the catchall. Every one of our
    invokable tools must be findable via a declared A2A skill. If this
    fails when we add a new tool, the fix is to add it to TOOL_TO_SKILL."""
    tool_names = {t["function"]["name"] for t in AGENT_TOOLS}
    mapped = set(TOOL_TO_SKILL.keys())
    missing = tool_names - mapped
    assert not missing, f"Tools missing from TOOL_TO_SKILL: {sorted(missing)}"


def test_card_never_emits_catchall_for_current_tools():
    """Belt-and-braces: even if TOOL_TO_SKILL gets edited wrong, the card
    built from AGENT_TOOLS should not advertise the catchall skill today."""
    card = build_agent_card(
        agent_id="alice",
        display_name=None,
        description=None,
        version="0.5.0",
        base_url="http://localhost:7777",
        chapter_url=None,
        did=None,
        tools=AGENT_TOOLS,
    )
    skill_ids = {s.id for s in card.skills}
    assert CATCHALL_SKILL_ID not in skill_ids


def test_card_deduplicates_skills_from_multiple_tools():
    """search_chapter, search_federation, find_peer all map to skill.discovery.
    The card should declare that skill exactly once, not three times."""
    card = build_agent_card(
        agent_id="alice",
        display_name=None,
        description=None,
        version="0.5.0",
        base_url="http://localhost:7777",
        chapter_url=None,
        did=None,
        tools=AGENT_TOOLS,
    )
    ids = [s.id for s in card.skills]
    assert len(ids) == len(set(ids)), f"duplicate skill ids: {ids}"


def test_every_mapped_skill_id_is_stable_prefix():
    """A2A clients index skills by id. Our ids must be stable — `skill.*`
    namespace means we can evolve without colliding with third-party skills."""
    for _, (skill_id, _, _, _) in TOOL_TO_SKILL.items():
        assert skill_id.startswith("skill."), f"bad skill id: {skill_id}"


# ═══════════════════════════════════════════════════════
# HAPPY — NANDA extension
# ═══════════════════════════════════════════════════════


def test_x_nanda_present_when_did_supplied():
    card = build_agent_card(
        agent_id="alice",
        display_name=None,
        description=None,
        version="0.5.0",
        base_url="http://localhost:7777",
        chapter_url="https://chapter.example",
        did="did:key:z6MkABC",
        tools=AGENT_TOOLS,
    )
    dumped = card.model_dump(mode="json", by_alias=True, exclude_none=True)
    ext = dumped["x-nanda"]
    assert ext["did"] == "did:key:z6MkABC"
    assert ext["chapter_url"] == "https://chapter.example"
    assert ext["agentfacts_url"].endswith("/agentfacts.json")
    assert ext["spec"] == "nanda-index-v0.1"


def test_x_nanda_omitted_when_no_did_or_chapter():
    """EDGE: a member mid-onboarding with no DID and no chapter URL should
    still produce a valid A2A card — just without the NANDA extension."""
    card = build_agent_card(
        agent_id="alice",
        display_name=None,
        description=None,
        version="0.5.0",
        base_url="http://localhost:7777",
        chapter_url=None,
        did=None,
        tools=AGENT_TOOLS,
    )
    dumped = card.model_dump(mode="json", by_alias=True, exclude_none=True)
    assert "x-nanda" not in dumped


# ═══════════════════════════════════════════════════════
# EDGE — config edge cases
# ═══════════════════════════════════════════════════════


def test_card_with_empty_tools_list():
    """EDGE: an agent with no tools loaded yet. Card still builds, just
    with only the topical skill (if any) and no RPC-backed skills."""
    card = build_agent_card(
        agent_id="alice",
        display_name="Alice",
        description="hi",
        version="0.5.0",
        base_url="http://localhost:7777",
        chapter_url=None,
        did=None,
        skills_declared=["rust"],
        tools=[],
    )
    # Only the topical advertising skill survives
    assert [s.id for s in card.skills] == ["skill.topical"]


def test_card_with_nothing_at_all():
    """FAILURE mode: bare-minimum inputs. Must not crash."""
    card = build_agent_card(
        agent_id="alice",
        display_name=None,
        description=None,
        version="0.5.0",
        base_url="http://localhost:7777",
        chapter_url=None,
        did=None,
        tools=None,
    )
    assert card.name == "alice"
    assert card.skills == []


def test_topical_skills_capped_at_32():
    """ADVERSARIAL: user pastes 500 skills during onboarding. Card must
    not blow up in size — we cap the tag list."""
    card = build_agent_card(
        agent_id="alice",
        display_name=None,
        description=None,
        version="0.5.0",
        base_url="http://localhost:7777",
        chapter_url=None,
        did=None,
        skills_declared=[f"skill-{i}" for i in range(500)],
        tools=None,
    )
    topical = next(s for s in card.skills if s.id == "skill.topical")
    assert len(topical.tags or []) <= 32


def test_topical_skills_deduplicated_and_lowercased():
    """EDGE: user enters 'Rust', 'RUST', 'rust' — the card advertises it once."""
    card = build_agent_card(
        agent_id="alice",
        display_name=None,
        description=None,
        version="0.5.0",
        base_url="http://localhost:7777",
        chapter_url=None,
        did=None,
        skills_declared=["Rust", "RUST", "rust", "python"],
        tools=None,
    )
    topical = next(s for s in card.skills if s.id == "skill.topical")
    assert sorted(topical.tags or []) == ["python", "rust"]


# ═══════════════════════════════════════════════════════
# ADVERSARIAL — unknown tool shouldn't break the card
# ═══════════════════════════════════════════════════════


def test_unknown_tool_falls_to_catchall_not_crash():
    """ADVERSARIAL: an installed skill exposes a tool we don't know about.
    The card should include the catchall skill, not crash."""
    hostile = [
        {
            "type": "function",
            "function": {"name": "evil_unknown_tool", "description": "mystery"},
        }
    ]
    card = build_agent_card(
        agent_id="alice",
        display_name=None,
        description=None,
        version="0.5.0",
        base_url="http://localhost:7777",
        chapter_url=None,
        did=None,
        tools=hostile,
    )
    assert any(s.id == CATCHALL_SKILL_ID for s in card.skills)


def test_tool_without_name_is_skipped_silently():
    """ADVERSARIAL: a malformed tool entry (no `function.name`) must not
    crash the Agent Card builder."""
    bad = [
        {"type": "function", "function": {}},  # no name
        {"type": "function", "function": {"name": "search_chapter"}},
    ]
    card = build_agent_card(
        agent_id="alice",
        display_name=None,
        description=None,
        version="0.5.0",
        base_url="http://localhost:7777",
        chapter_url=None,
        did=None,
        tools=bad,
    )
    # The valid tool still contributed; the bad one was ignored.
    assert any(s.id == "skill.discovery" for s in card.skills)


# ═══════════════════════════════════════════════════════
# HAPPY — end-to-end HTTP
# ═══════════════════════════════════════════════════════


@pytest.fixture
def app_client():
    """Spin up the real FastAPI server with a minimal config and hit the
    well-known endpoint. This proves the route is wired, not just the builder."""
    from fastapi.testclient import TestClient

    from community_member.config import Config
    from community_member.server import create_app

    cfg = Config()
    cfg.agent_id = "alice"
    cfg.name = "Alice"
    cfg.description = "test"
    cfg.skills = ["rust", "fpga"]
    cfg.chapter_url = "https://chapter.example"
    cfg.api_key = "x" * 32
    # Real keypair so the DID path works
    from community_member.crypto import generate_keypair

    kp = generate_keypair()
    cfg.private_key = kp["private_key"]
    cfg.public_key = kp["public_key"]

    return TestClient(create_app(cfg))


def test_well_known_endpoint_returns_valid_a2a_card(app_client):
    resp = app_client.get("/.well-known/agent.json")
    assert resp.status_code == 200
    body = resp.json()
    # The wire field name must be the hyphenated alias.
    assert "x-nanda" in body
    # Validates back into our model (round-trip proof).
    reparsed = AgentCard.model_validate(body)
    assert reparsed.name == "Alice"
    assert reparsed.capabilities.streaming is True
    assert reparsed.authentication.schemes == ["ed25519", "did-auth"]


def test_well_known_endpoint_serves_did_key(app_client):
    """The DID should be derivable from the member's public key. Any
    client who fetches this card can immediately verify our signatures."""
    resp = app_client.get("/.well-known/agent.json")
    body = resp.json()
    did = body["x-nanda"]["did"]
    assert did.startswith("did:key:z")
