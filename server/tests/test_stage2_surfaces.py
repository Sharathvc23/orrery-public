"""Smoke tests for Stage-2 portal-migration surfaces.

Covers:
  - build_directory_surface (federation-wide agent directory)
  - build_search_surface    (cross-table search)

Each test wires the module via surfaces.init() with fake state, then
asserts the builder returns a well-formed v0.9 envelope without
throwing.
"""

from __future__ import annotations

from typing import Any

import pytest

import surfaces


class FakePostgres:
    def __init__(self, table_responses: dict[str, list[dict]] | None = None):
        self.calls: list[tuple] = []
        self._responses = table_responses or {}

    async def __call__(self, method: str, table: str, params: dict | None = None, body: Any = None):
        self.calls.append((method, table, params, body))
        return self._responses.get(table)


def _init_with_state(
    fake_sb: FakePostgres,
    members_dict: dict | None = None,
    federation_dict: dict | None = None,
) -> None:
    surfaces.init(
        pg_request_fn=fake_sb,
        members_dict=members_dict or {},
        federation_dict=federation_dict or {},
        knowledge_cache={"chapter_intelligence": {}},
        agent_id="test-chapter",
        agent_name="Test Chapter",
        get_think_count=lambda: 0,
    )


def _assert_v09_shape(result: dict, prefix: str) -> list[dict]:
    """Common shape assertions; returns the components list."""
    assert "createSurface" in result
    assert "updateComponents" in result
    assert result["version"] == "0.10"
    assert result["createSurface"]["surfaceId"].startswith(prefix)
    components = result["updateComponents"]["components"]
    assert isinstance(components, list)
    assert len(components) > 0, "expected at least one component"
    # Every node must have id + component fields.
    for c in components:
        assert "id" in c, f"node missing id: {c}"
        assert "component" in c, f"node missing component: {c}"
    return components


# ─── Directory ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_directory_with_local_members_renders_member_cards():
    fake_sb = FakePostgres()
    _init_with_state(
        fake_sb,
        members_dict={
            "alice": {"name": "Alice", "skills": ["rust"], "description": "ML infra"},
            "bob": {"name": "Bob", "skills": ["python"], "description": "Data sci"},
        },
    )
    result = await surfaces.build_directory_surface()
    components = _assert_v09_shape(result, "surface-directory")
    member_cards = [c for c in components if c.get("component") == "MemberCard"]
    assert len(member_cards) == 2
    assert any(c["name"] == "Alice" for c in member_cards)


@pytest.mark.asyncio
async def test_directory_with_federation_peers_renders_chapter_summary():
    """The federation cache stores chapter-level info only — name +
    endpoint + an integer ``members`` count — not a per-member list.
    The directory therefore shows local members as MemberCards but
    federation peers as Card summaries (chapter name + member count
    + online/offline badge). Enumerating peer members is a follow-
    up that requires live HTTP fan-out to peer /api/members."""
    fake_sb = FakePostgres()
    _init_with_state(
        fake_sb,
        members_dict={"alice": {"name": "Alice"}},
        federation_dict={
            "TEST-boston-chapter": {
                "name": "Boston Chapter",
                "endpoint": "https://test-boston-chapter.example",
                "members": 30,
                "status": "online",
            },
            "TEST-tokyo-chapter": {
                "name": "Tokyo Chapter",
                "members": 23,
                "status": "offline",
            },
        },
    )
    result = await surfaces.build_directory_surface()
    components = _assert_v09_shape(result, "surface-directory")
    # Local: still rendered as MemberCard.
    member_cards = [c for c in components if c.get("component") == "MemberCard"]
    assert len(member_cards) == 1
    assert member_cards[0]["name"] == "Alice"
    # Federated: rendered as labelled Cards. Look for the chapter
    # name + member-count badge text.
    text_nodes = [c for c in components if c.get("component") == "Text"]
    assert any(c.get("text") == "Boston Chapter" for c in text_nodes)
    assert any(c.get("text") == "Tokyo Chapter" for c in text_nodes)
    badges = [c for c in components if c.get("component") == "Badge"]
    assert any("30 members" in (c.get("text") or "") for c in badges)
    assert any("23 members" in (c.get("text") or "") for c in badges)
    # Caption shows total = 1 local + (30 + 23) federated = 54
    captions = [c for c in components if c.get("usageHint") == "caption"]
    assert any("54" in (c.get("text") or "") for c in captions)


@pytest.mark.asyncio
async def test_directory_tolerates_int_members_field_no_crash():
    """Adversarial: pre-fix the builder iterated ``info["members"]``
    expecting a list of dicts. Production federation stores it as
    an int. This test pins out the regression."""
    fake_sb = FakePostgres()
    _init_with_state(
        fake_sb,
        federation_dict={
            "peer-A": {"name": "Peer A", "members": 12, "status": "online"},
            "peer-B": {"name": "Peer B", "members": 0},
            # Garbage values shouldn't crash either.
            "peer-C": {"name": "Peer C", "members": None},
            "peer-D": "not even a dict",  # noqa: S101
        },
    )
    # Should not raise.
    result = await surfaces.build_directory_surface()
    _assert_v09_shape(result, "surface-directory")


@pytest.mark.asyncio
async def test_directory_when_empty_renders_callout():
    fake_sb = FakePostgres()
    _init_with_state(fake_sb)  # zero members, zero federation
    result = await surfaces.build_directory_surface()
    components = _assert_v09_shape(result, "surface-directory")
    assert any(c.get("component") == "Callout" for c in components)


# ─── Search ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_search_with_no_target_renders_prompt():
    fake_sb = FakePostgres()
    _init_with_state(fake_sb)
    result = await surfaces.build_search_surface(target=None)
    components = _assert_v09_shape(result, "surface-search")
    # Prompts for query — no Postgres calls made.
    assert fake_sb.calls == []
    assert any(c.get("component") == "Callout" for c in components)


@pytest.mark.asyncio
async def test_search_with_query_hits_profiles_and_events():
    fake_sb = FakePostgres(
        table_responses={
            "profiles": [
                {"id": "alice", "full_name": "Alice", "bio": "ML researcher", "skills": ["ml"]},
            ],
            "agent_events": [
                {"id": "ev1", "title": "ML meetup", "description": "Talk on transformers"},
            ],
        }
    )
    _init_with_state(fake_sb)
    result = await surfaces.build_search_surface(target="ml")
    components = _assert_v09_shape(result, "surface-search:ml")
    # Both Postgres calls happened.
    tables_queried = [c[1] for c in fake_sb.calls]
    assert "profiles" in tables_queried
    assert "agent_events" in tables_queried
    # MemberCard for Alice + Callout for the event.
    assert any(c.get("component") == "MemberCard" and c.get("name") == "Alice" for c in components)
    assert any(c.get("component") == "Callout" and "ML meetup" in str(c) for c in components)


@pytest.mark.asyncio
async def test_search_with_no_results_shows_zero_text():
    fake_sb = FakePostgres(table_responses={"profiles": [], "agent_events": []})
    _init_with_state(fake_sb)
    result = await surfaces.build_search_surface(target="nonexistent")
    components = _assert_v09_shape(result, "surface-search:nonexistent")
    headings = [c for c in components if c.get("component") == "Text" and c.get("usageHint") == "h3"]
    # We render a "Members (0)" and "Events (0)" header pair.
    assert any("0" in c.get("text", "") for c in headings)


# ─── SURFACE_BUILDERS registry ─────────────────────────────────


def test_new_builders_registered():
    assert "directory" in surfaces.SURFACE_BUILDERS
    assert "search" in surfaces.SURFACE_BUILDERS
    # Sanity: builders are coroutines.
    import inspect

    for key in ("directory", "search"):
        builder = surfaces.SURFACE_BUILDERS[key]
        assert inspect.iscoroutinefunction(builder), f"{key} should be async"
