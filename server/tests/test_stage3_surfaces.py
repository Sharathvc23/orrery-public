"""Smoke + behavior tests for Stage-3 profile surface (read-only).

Per the membership tier model (cloud OAuth / local SDK / OpenClaw),
profile *editing* is not chapter-driven — each tier has its own
write path. The chapter only owns the *read* view, which this
surface implements.

Covers:
  - Empty target → prompt callout
  - Real agent_id → MemberCard header + bio + trust link + recent
    contributions Timeline
  - Missing agent in registry → renders best-effort + warning
  - Missing trust score → "not yet computed" caption
  - Postgres outage → warning Callout, no crash
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


def _init(fake_sb) -> None:
    surfaces.init(
        pg_request_fn=fake_sb,
        members_dict={},
        federation_dict={},
        knowledge_cache={"chapter_intelligence": {}},
        agent_id="test-chapter",
        agent_name="Test Chapter",
        get_think_count=lambda: 0,
    )


def _shape(result: dict, prefix: str) -> list[dict]:
    assert "createSurface" in result
    assert "updateComponents" in result
    assert result["version"] == "0.10"
    assert result["createSurface"]["surfaceId"].startswith(prefix)
    return result["updateComponents"]["components"]


@pytest.mark.asyncio
async def test_profile_with_no_target_renders_prompt():
    fake_sb = FakePostgres()
    _init(fake_sb)
    result = await surfaces.build_profile_surface(target=None)
    components = _shape(result, "surface-profile")
    # No supabase calls when target missing.
    assert fake_sb.calls == []
    assert any(c.get("component") == "Callout" for c in components)


@pytest.mark.asyncio
async def test_profile_with_full_data_renders_member_card_and_trust_link():
    fake_sb = FakePostgres(
        table_responses={
            "agents": [
                {
                    "agent_id": "alice",
                    "profile_id": "uuid-alice",
                    "name": "Alice Example",
                    "description": "ML infrastructure",
                    "skills": ["ml-infra", "rust"],
                    "interests": ["climate"],
                    "profile_type": "leader",
                    "trust_score": 65,
                    "github_data": None,
                    "linkedin_url": None,
                },
            ],
            "profiles": [
                {
                    "id": "uuid-alice",
                    "full_name": "Alice Example",
                    "bio": "Builds local-first agent infra.",
                    "avatar_url": "",
                    "title": "Engineer",
                    "company": "Stellar Minds",
                    "location": "Berlin",
                    "is_public": True,
                },
            ],
            "agent_thoughts": [
                {
                    "thought": "Drafted intent for Rust mentors.",
                    "thought_type": "intent",
                    "created_at": "2026-05-08T12:00:00Z",
                },
            ],
        }
    )
    _init(fake_sb)
    result = await surfaces.build_profile_surface(target="alice")
    components = _shape(result, "surface-profile:alice")

    cards = [c for c in components if c.get("component") == "MemberCard"]
    assert len(cards) == 1
    card_node = cards[0]
    assert card_node["name"] == "Alice Example"
    assert card_node["agentId"] == "alice"
    assert card_node["role"] == "leader"
    assert "Engineer" in (card_node["subtitle"] or "")

    # Trust link points at /page/trust.
    links = [c for c in components if c.get("component") == "Link"]
    trust_link = next((lnk for lnk in links if "/page/trust" in (lnk.get("url") or "")), None)
    assert trust_link is not None
    assert "alice" in trust_link["url"]

    # Recent contributions Timeline.
    timelines = [c for c in components if c.get("component") == "Timeline"]
    assert len(timelines) == 1
    assert len(timelines[0]["entries"]) == 1

    # Edit link points at /profile/edit (NOT through chapter).
    edit_link = next((lnk for lnk in links if lnk.get("url") == "/profile/edit"), None)
    assert edit_link is not None


@pytest.mark.asyncio
async def test_profile_with_missing_agent_renders_warning():
    fake_sb = FakePostgres(table_responses={"agents": []})
    _init(fake_sb)
    result = await surfaces.build_profile_surface(target="ghost")
    components = _shape(result, "surface-profile:ghost")
    callouts = [c for c in components if c.get("component") == "Callout"]
    assert any(c.get("variant") == "warning" for c in callouts)


@pytest.mark.asyncio
async def test_profile_without_trust_score_shows_caption():
    fake_sb = FakePostgres(
        table_responses={
            "agents": [
                {
                    "agent_id": "newbie",
                    "profile_id": None,
                    "name": "Brand New",
                    "description": "Just joined.",
                    "skills": [],
                    "trust_score": None,
                    "profile_type": "newcomer",
                },
            ],
            "agent_thoughts": [],
        }
    )
    _init(fake_sb)
    result = await surfaces.build_profile_surface(target="newbie")
    components = _shape(result, "surface-profile:newbie")
    captions = [c for c in components if c.get("component") == "Text" and c.get("usageHint") == "caption"]
    assert any("not yet computed" in (c.get("text") or "") for c in captions)
    metrics = [c for c in components if c.get("component") == "Metric"]
    assert metrics == [], "expected no trust-score Metric when score is None"


@pytest.mark.asyncio
async def test_profile_supabase_failure_still_renders_surface():
    """Adversarial: Postgres outage / RLS denial / network blip
    must not 500 the profile surface. Best-effort rendering should
    fall through to a warning Callout."""

    class FailingPostgres:
        async def __call__(self, *args, **kwargs):
            raise RuntimeError("simulated supabase down")

    surfaces.init(
        pg_request_fn=FailingPostgres(),
        members_dict={},
        federation_dict={},
        knowledge_cache={"chapter_intelligence": {}},
        agent_id="test-chapter",
        agent_name="Test Chapter",
        get_think_count=lambda: 0,
    )

    result = await surfaces.build_profile_surface(target="alice")
    components = _shape(result, "surface-profile:alice")
    callouts = [c for c in components if c.get("component") == "Callout"]
    assert any(c.get("variant") == "warning" for c in callouts)


def test_profile_registered():
    assert "profile" in surfaces.SURFACE_BUILDERS
    import inspect

    assert inspect.iscoroutinefunction(surfaces.SURFACE_BUILDERS["profile"])
