"""Tests for chapter/sm_bridge_adapter.py — sm-bridge parallel routers.

Classification: HAPPY / EDGE / FAILURE / ADVERSARIAL.

The adapter is downstream-only; we never modify sm-bridge. Tests focus on:
  1. Conversion correctness — chapter member dict → SmAgentFacts shape
  2. Exclusion discipline — TEST-* + is_demo members never leak into
     federation discovery
  3. Pagination semantics
  4. Mounting onto a FastAPI app (smoketest — full HTTP coverage is in
     test_sm_bridge_endpoints_e2e.py via TestClient)
"""

from __future__ import annotations

import os

os.environ.setdefault("AGENT_ID", "test-sm-bridge-chapter")
os.environ.setdefault("AGENT_NAME", "Test sm-bridge Chapter")

import importlib
import sys

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


@pytest.fixture
def adapter():
    """Reload the adapter module per test for a clean import state."""
    if "sm_bridge_adapter" in sys.modules:
        importlib.reload(sys.modules["sm_bridge_adapter"])
    import sm_bridge_adapter

    return sm_bridge_adapter


@pytest.fixture
def members():
    """Realistic mix: real members, demo, test fixture, startup synthetic."""
    return {
        # The index enumerates only members who OPTED IN to be listed —
        # the same consent record the Listing document reads. alice and bob
        # carry it; the tests below about pagination and exclusion are about
        # members who are eligible in the first place.
        "alice": {
            "agent_id": "alice",
            "name": "Alice",
            "description": "Real engineer in AI infra",
            "skills": ["python", "ml-infrastructure", "distributed-systems"],
            "is_demo": False,
            "listing": {"listed": True, "agent_url": "https://alice.example"},
        },
        "bob": {
            "agent_id": "bob",
            "name": "Bob",
            "description": "Product builder",
            "skills": ["product", "design"],
            "is_demo": False,
            "listing": {"listed": True, "agent_url": "https://bob.example"},
        },
        "TEST-fixture-alice": {
            "agent_id": "TEST-fixture-alice",
            "name": "Test Alice",
            "description": "Conformance fixture",
            "skills": [],
            "is_demo": False,
        },
        "demo-persona": {
            "agent_id": "demo-persona",
            "name": "Demo Persona",
            "description": "Synthetic demo",
            "skills": ["demo"],
            "is_demo": True,
        },
    }


# ══════════════════════════════════════════════════════════════════════
# HAPPY — converter shape
# ══════════════════════════════════════════════════════════════════════


def test_HAPPY_converter_to_sm_produces_well_formed_facts(adapter, members):
    """to_sm maps a chapter member to a SmAgentFacts with all required
    NANDA fields populated."""
    converter = adapter.make_chapter_converter(
        agent_id="test-chapter",
        agent_name="Test Chapter",
        public_url="https://test-chapter.example.com",
        members=members,
    )
    assert converter is not None

    facts = converter.to_sm(members["alice"])
    # SmAgentFacts is a Pydantic model
    assert "alice" in facts.id  # did:web:host:agents:alice
    assert facts.agent_name == "Alice"
    # Never the member row's free-text description: this document is served
    # to anyone, and that field is member-authored prose the Listing forbids.
    assert facts.description == "Alice"
    assert "Real engineer" not in facts.description
    assert facts.provider.name == "Test Chapter"
    assert facts.provider.url == "https://test-chapter.example.com"
    # Skills converted from list[str] to list[SmSkill]
    skill_ids = [s.id for s in facts.skills]
    assert "python" in skill_ids
    assert "ml-infrastructure" in skill_ids


def test_HAPPY_endpoints_carry_chapter_a2a_url(adapter, members):
    """SmAgentFacts.endpoints.static lists the chapter's /a2a URL for
    federation consumers to know where to send A2A messages."""
    converter = adapter.make_chapter_converter(
        agent_id="bayarea",
        agent_name="Bay Area Chapter",
        public_url="https://bayarea.example.com",
        members=members,
    )
    facts = converter.to_sm(members["alice"])
    assert "https://bayarea.example.com/a2a" in facts.endpoints.static


# ══════════════════════════════════════════════════════════════════════
# EDGE — exclusion discipline
# ══════════════════════════════════════════════════════════════════════


def test_EDGE_list_agents_excludes_test_fixtures(adapter, members):
    """TEST-* prefix members never appear in federation discovery."""
    converter = adapter.make_chapter_converter(
        agent_id="c",
        agent_name="C",
        public_url="https://c.example.com",
        members=members,
    )
    ids = [a["agent_id"] for a in converter.list_agents(limit=100, offset=0)]
    assert "TEST-fixture-alice" not in ids


def test_EDGE_list_agents_excludes_a_member_who_did_not_opt_in(adapter, members):
    """A registered member with no listing consent is not enumerated. This
    index used to iterate every member — measured on a deployed org: all
    twenty-three, names and descriptions, to an anonymous GET — which is the
    population GET /api/members is gated for and the catalog withholds."""
    members["silent"] = {
        "agent_id": "silent",
        "name": "Silent Member",
        "description": "Contact: silent@example.com",
        "skills": ["x"],
        "is_demo": False,
    }
    members["refused"] = {**members["silent"], "agent_id": "refused", "listing": {"listed": False}}
    converter = adapter.make_chapter_converter(
        agent_id="c",
        agent_name="C",
        public_url="https://c.example.com",
        members=members,
    )
    ids = [a["agent_id"] for a in converter.list_agents(limit=100, offset=0)]
    assert "silent" not in ids and "refused" not in ids
    assert {"alice", "bob"} <= set(ids), "members who opted in are still listed"


def test_EDGE_list_agents_excludes_demo_personas(adapter, members):
    """is_demo=True members never appear in federation discovery."""
    converter = adapter.make_chapter_converter(
        agent_id="c",
        agent_name="C",
        public_url="https://c.example.com",
        members=members,
    )
    ids = [a["agent_id"] for a in converter.list_agents(limit=100, offset=0)]
    assert "demo-persona" not in ids


def test_EDGE_get_agent_returns_none_for_demo(adapter, members):
    """A direct get_agent call for a demo persona returns None (not the
    member with is_demo=True). Same exclusion rule applies."""
    converter = adapter.make_chapter_converter(
        agent_id="c",
        agent_name="C",
        public_url="https://c.example.com",
        members=members,
    )
    assert converter.get_agent("demo-persona") is None


def test_EDGE_get_agent_returns_unknown_member_as_none(adapter, members):
    converter = adapter.make_chapter_converter(
        agent_id="c",
        agent_name="C",
        public_url="https://c.example.com",
        members=members,
    )
    assert converter.get_agent("not-a-real-member") is None


def test_get_agent_round_trips_the_index_advertised_id(adapter, members):
    """That change (org twin of that change): the index advertises id=did:web:{host}:agents:{mid}
    and agent_name=<name>, so resolve MUST accept those — not just the raw member
    id — or a NANDA/NEST consumer that reads the index id and resolves by it 404s."""
    converter = adapter.make_chapter_converter(
        agent_id="c",
        agent_name="C",
        public_url="https://c.example.com",
        members=members,
    )
    # The exact id the index advertises for alice.
    facts = converter.to_sm({"agent_id": "alice", **members["alice"]})
    advertised_did = facts.id
    assert advertised_did == "did:web:c.example.com:agents:alice"

    for key in (advertised_did, "Alice", "@alice", "alice"):
        resolved = converter.get_agent(key)
        assert resolved is not None, f"resolve by {key!r} 404'd (must round-trip the index)"
        assert resolved["agent_id"] == "alice"


def test_EDGE_is_public_false_for_test_and_demo(adapter, members):
    converter = adapter.make_chapter_converter(
        agent_id="c",
        agent_name="C",
        public_url="https://c.example.com",
        members=members,
    )
    assert converter.is_public(members["alice"]) is True
    assert converter.is_public(members["TEST-fixture-alice"]) is False
    assert converter.is_public(members["demo-persona"]) is False


# ══════════════════════════════════════════════════════════════════════
# Pagination
# ══════════════════════════════════════════════════════════════════════


def test_HAPPY_list_agents_paginates(adapter, members):
    """Adding more real members + verifying offset/limit slice cleanly."""
    extras = {
        f"member-{i}": {
            "agent_id": f"member-{i}",
            "name": f"Member {i}",
            "description": "synthetic",
            "skills": [],
            "is_demo": False,
            "listing": {"listed": True, "agent_url": f"https://member-{i}.example"},
        }
        for i in range(10)
    }
    all_members = {**members, **extras}
    converter = adapter.make_chapter_converter(
        agent_id="c",
        agent_name="C",
        public_url="https://c.example.com",
        members=all_members,
    )
    first_page = list(converter.list_agents(limit=5, offset=0))
    second_page = list(converter.list_agents(limit=5, offset=5))
    # 12 real members total (alice, bob, 10 extras)
    assert len(first_page) == 5
    assert len(second_page) == 5
    # No overlap
    first_ids = {a["agent_id"] for a in first_page}
    second_ids = {a["agent_id"] for a in second_page}
    assert first_ids.isdisjoint(second_ids)


# ══════════════════════════════════════════════════════════════════════
# Routes mounted — HTTP smoke
# ══════════════════════════════════════════════════════════════════════


def test_HAPPY_mount_sm_bridge_routers_serves_index(adapter, members):
    """End-to-end via TestClient: mount the routers on a fresh FastAPI
    app, hit /sm-bridge/nanda/index, expect a paginated response with
    the chapter's real members."""
    app = FastAPI()
    converter = adapter.mount_sm_bridge_routers(
        app,
        agent_id="bayarea",
        agent_name="Bay Area",
        public_url="https://bayarea.example.com",
        members=members,
    )
    assert converter is not None

    client = TestClient(app)
    # sm-bridge mounts the nanda router with prefix /sm-bridge (we pass
    # prefix kwarg). The default sub-routes are /index, /resolve,
    # /deltas, /tools.
    r = client.get("/sm-bridge/index")
    assert r.status_code == 200, r.text
    body = r.json()
    # SmAgentFactsIndexResponse has an items list
    assert "items" in body or "data" in body or isinstance(body, dict)


def test_HAPPY_mount_serves_wellknown(adapter, members):
    """sm-bridge's wellknown router serves /.well-known/nanda.json
    (NOT nanda-agent.json — different filename, no collision with the
    chapter's existing /.well-known/nanda-agent.json endpoint)."""
    app = FastAPI()
    adapter.mount_sm_bridge_routers(
        app,
        agent_id="bayarea",
        agent_name="Bay Area",
        public_url="https://bayarea.example.com",
        members=members,
    )
    client = TestClient(app)
    r = client.get("/.well-known/nanda.json")
    assert r.status_code == 200, r.text
