"""Which table each avatar comes from, now that two of them carry the column.

Migration 0007 adds ``agents.avatar_url`` — the AGENT's picture — alongside the
``profiles.avatar_url`` that already existed for the PERSON. The two rows are
joined by ``agents.profile_id``, so from here on "the avatar" is ambiguous
unless something says which one a given reader gets.

The failure mode is a wrong face on a member card. Nobody files that bug: it
looks like someone changed their picture. So each reader is pinned here rather
than left to the next `select=*` or row merge to decide.

Every reader was established by reading, before the column was added:

  surfaces.build_profile_surface  — PROFILE, and empty when not public
  surfaces (member search)        — PROFILE, selected explicitly
  chapter_agent public agent card — the in-memory member registry, which is
                                    composed field-by-field from a select list
                                    that does not name the column
  a2ui_helpers.build_member_cards — whatever its caller's dict holds; its one
                                    production caller passes no avatar at all
"""

from __future__ import annotations

import pytest

import surfaces

AGENT = "avatar-probe"
PROFILE_ID = "11111111-1111-1111-1111-111111111111"
PROFILE_AVATAR = "https://example.test/PROFILE-face.png"
AGENT_AVATAR = "https://example.test/AGENT-face.png"


def _avatar_of(surface: dict) -> str:
    """The avatarUrl the rendered MemberCard actually carries."""
    components = surface.get("components") or surface.get("updateComponents", {}).get("components", [])
    for c in components:
        if c.get("component") == "MemberCard":
            return str(c.get("avatarUrl", ""))
    raise AssertionError("no MemberCard in this surface — the assertion below would be vacuous")


@pytest.fixture
def wired(monkeypatch):
    """A store where the agent row and the profile row carry DIFFERENT avatars,
    so a reader that takes the wrong one cannot pass by coincidence."""

    state = {"is_public": True}

    async def pg(method, table, params=None, body=None):
        if method != "GET":
            return []
        if table == "agents":
            return [
                {
                    "agent_id": AGENT,
                    "profile_id": PROFILE_ID,
                    "name": "Agent Name",
                    "description": "agent bio",
                    "skills": ["py"],
                    "profile_type": "member",
                    "trust_score": 10.0,
                    "avatar_url": AGENT_AVATAR,
                }
            ]
        if table == "profiles":
            return [
                {
                    "id": PROFILE_ID,
                    "full_name": "Person Name",
                    "bio": "person bio",
                    "avatar_url": PROFILE_AVATAR,
                    "title": "",
                    "company": "",
                    "location": "",
                    "skills": ["py"],
                    "is_public": state["is_public"],
                }
            ]
        return []

    surfaces.init(
        pg_request_fn=pg,
        members_dict={AGENT: {"name": "Agent Name", "description": "agent bio", "skills": ["py"]}},
        federation_dict={},
        knowledge_cache={},
        agent_id="TEST-avatar-chapter",
        agent_name="Avatar Chapter",
        get_think_count=lambda: 0,
    )
    return state


# ── the profile surface: the PERSON's avatar, and only when they published it ─


@pytest.mark.asyncio
async def test_the_profile_surface_shows_the_profile_avatar_not_the_agents(wired):
    """Both rows carry an avatar and they differ. This reader composes from
    ``account_row`` (the profiles row) and consults the agent row only through
    explicit ``.get()`` calls, so adding agents.avatar_url must not move it."""
    surface = await surfaces.build_profile_surface(AGENT)
    assert _avatar_of(surface) == PROFILE_AVATAR


@pytest.mark.asyncio
async def test_a_private_profile_does_not_fall_back_to_the_agent_avatar(wired):
    """⚠️ THE TRAP 0007 SETS. ``name`` and ``bio`` on this surface fall back to
    the agent row when the profile is not public, and ``avatar_url``
    deliberately does not — it goes empty. Now that agents carries an avatar,
    adding the "obviously missing" symmetric fallback would publish a picture
    for a member who set is_public=false, on a page that is reachable with no
    account at all."""
    wired["is_public"] = False
    surface = await surfaces.build_profile_surface(AGENT)
    got = _avatar_of(surface)
    assert got != AGENT_AVATAR, "a private profile published the agent's avatar"
    assert got == "", f"a private profile published an avatar at all: {got!r}"


# ── the member registry: unchanged by 0007 unless someone changes it twice ───


@pytest.mark.asyncio
async def test_the_member_registry_does_not_carry_an_avatar_column(monkeypatch):
    """``chapter_agent`` renders the public agent card from ``members[id]``,
    reading ``m.get("avatar_url")``. That dict is composed field-by-field from a
    select list, and neither names the column — so the card shows no avatar
    today and 0007 does not silently change it.

    Driven, not read: the store returns a row that DOES carry an agent avatar,
    and the registry still must not pick it up. Adding one is then a decision
    that has to be made in both the select and the dict, which is what makes it
    a decision rather than a side effect of the column existing.
    """
    import importlib
    import sys

    monkeypatch.setenv("AGENT_ID", "TEST-avatar-chapter")
    monkeypatch.setenv("XAI_API_KEY", "test-key")
    sys.modules.pop("chapter_agent", None)
    ca = importlib.import_module("chapter_agent")

    captured: dict = {}

    async def pg(method, table, params=None, body=None, *a, **k):
        if method == "GET" and table == "agents":
            captured["select"] = (params or {}).get("select", "")
            return [
                {
                    "agent_id": AGENT,
                    "name": "Agent Name",
                    "description": "agent bio",
                    "skills": ["py"],
                    "config": {"parent_chapter": ca.AGENT_ID},
                    "profile_type": "member",
                    "origin": "sovereign",
                    "agent_facts": {},
                    "avatar_url": AGENT_AVATAR,
                }
            ]
        return []

    monkeypatch.setattr(ca, "pg_request", pg)
    monkeypatch.setattr(ca, "_recorded_rotation_chains", lambda: _empty_chains())
    ca.members.clear()
    try:
        await ca.load_persisted_members()
        assert AGENT in ca.members, "no member was loaded — the assertion below would be vacuous"
        assert "avatar_url" not in ca.members[AGENT], (
            "the member registry now carries avatar_url. If that is deliberate, say which table's "
            "avatar the public agent card should show and pin it here."
        )
        assert "avatar_url" not in captured.get("select", ""), "load_persisted_members now selects avatar_url"
    finally:
        ca.members.clear()


async def _empty_chains():
    return {}


@pytest.mark.asyncio
async def test_the_member_search_renders_no_avatar_at_all(wired):
    """This reader SELECTS ``avatar_url`` from ``profiles`` and never passes it
    to the card — the same selected-and-never-read shape the file already calls
    out for ``is_public`` a few hundred lines down.

    Pinned as empty rather than wired up, and the reason is the difference
    between the two queries. ``build_profile_surface`` gates its profiles read
    on ``is_public`` before publishing anything from that row; this query has no
    such filter, so passing the value through would publish a private member's
    picture to a search that the profile page would refuse to show it on. That
    is a privacy decision, not an avatar decision.

    So the guard is: this card carries no avatar, and if someone wires one in
    they must consult ``is_public`` first — and change this test deliberately
    rather than discover the behaviour changed under them.
    """
    surface = await surfaces.build_search_surface("Person")
    components = surface.get("updateComponents", {}).get("components", [])
    cards = [c for c in components if c.get("component") == "MemberCard"]
    assert cards, "the search surface rendered no MemberCard — nothing was asserted"
    got = cards[0].get("avatarUrl", "")
    assert got != AGENT_AVATAR, "member search rendered the AGENT's avatar"
    assert got == "", (
        f"member search now renders an avatar ({got!r}). Its profiles query does not filter on "
        "is_public — gate it before publishing, then update this test."
    )


def test_build_member_cards_takes_the_avatar_from_its_caller():
    """``a2ui_helpers`` reads ``avatar_url`` off a plain dict, so it has no table
    of its own. Pinned as pass-through: it must not acquire a default or a
    lookup, which is how a helper starts deciding provenance for every caller."""
    import a2ui_helpers

    surface = a2ui_helpers.build_member_cards([{"name": "A", "id": "a", "avatar_url": AGENT_AVATAR}])
    assert surface and _avatar_of(surface) == AGENT_AVATAR
    bare = a2ui_helpers.build_member_cards([{"name": "A", "id": "a"}])
    assert bare and _avatar_of(bare) == "", "the helper invented an avatar its caller did not supply"
