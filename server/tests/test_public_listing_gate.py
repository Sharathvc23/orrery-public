"""Public-listing gate tests.

Pre-launch audit found the production bayarea chapter serving entries
like ``TEST-injection-DROPTABLEagents--`` and other hostile fixtures as
visible community members via ``GET /api/members``. The conformance
suite (R3 in ``conformance/server/test_register.py``) deliberately
registers these to verify the chapter sanitizes input — that's correct
behavior on the write path. The bug is that the read-side never
filtered them back out.

This module locks the gate: every public read surface (members
directory, thoughts feed, member-card lookup) MUST drop entries whose
``agent_id`` matches one of ``_PUBLIC_HIDDEN_PREFIXES``. The chapter is
free to keep referencing the agents internally — federation,
governance, conformance — but they never leak into a public list.
"""

from __future__ import annotations

import importlib
import sys

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def chapter_agent_module(monkeypatch: pytest.MonkeyPatch):
    """Same shape as ``test_chapter_slug``: stub the env that chapter_agent
    reads at import time, then re-import for a clean slate."""
    monkeypatch.setenv("AGENT_ID", "TEST-fixture-chapter")
    monkeypatch.setenv("AGENT_NAME", "Fixture")
    monkeypatch.setenv("XAI_API_KEY", "test-key")
    monkeypatch.delenv("CHAPTER_SLUG", raising=False)
    monkeypatch.delenv("CHAPTER_DISPLAY_NAME", raising=False)
    sys.modules.pop("chapter_agent", None)
    return importlib.import_module("chapter_agent")


@pytest.fixture
def client(chapter_agent_module) -> TestClient:
    chapter_agent_module.members.clear()
    return TestClient(chapter_agent_module.app)


def _seed_members(mod, extras: dict[str, dict] | None = None) -> None:
    """Populate the in-memory members dict with a realistic mix:
    one real user, one synthetic startup, three test fixtures."""
    mod.members.clear()
    mod.members.update(
        {
            "alice": {"name": "Alice", "description": "Real user", "skills": ["python"]},
            "STARTUP-abc-ceo": {
                "name": "ACME CEO",
                "description": "Synthetic startup agent",
                "skills": ["bizdev"],
            },
            "TEST-priya": {"name": "Priya", "description": "Seed", "skills": ["ai"]},
            "TEST-conformance-deadbeef": {
                "name": "Conformance probe",
                "description": "Test fixture",
                "skills": [],
            },
            "TEST-injection-DROPTABLEagents--": {
                "name": "Injection probe",
                "description": "Hostile",
                "skills": [],
            },
        }
    )
    if extras:
        mod.members.update(extras)


def _ids(members: list[dict]) -> set[str]:
    return {m["agent_id"] for m in members}


def _reader(mod, agent_id: str = "listing-reader") -> dict[str, str]:
    """A signed member who may read the directory. The enumeration closure auth-gated the listing;
    the hidden-prefix contract below is about what an AUTHORIZED reader sees,
    which is a strictly narrower question than who may read at all."""
    from ._admin_fixtures import make_signer, register_test_regular_member

    member = register_test_regular_member(mod, agent_id=agent_id, name="Listing Reader")
    return make_signer(agent_id, member["private_key"])


async def _noop_supabase(*_, **__):  # noqa: ARG001
    return []


# ---------------------------------------------------------------------------
# /api/members — directory listing
# ---------------------------------------------------------------------------


def test_list_members_hides_TEST_prefixed_entries(
    client: TestClient, chapter_agent_module, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Real users + synthetic startups stay visible; every TEST- entry is gone."""
    _seed_members(chapter_agent_module)
    monkeypatch.setattr(chapter_agent_module, "pg_request", _noop_supabase)

    headers = _reader(chapter_agent_module)(method="GET", url_path="/api/members")
    resp = client.get("/api/members", headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    visible = _ids(body["members"])

    assert "alice" in visible
    assert "STARTUP-abc-ceo" in visible
    for hidden in (
        "TEST-priya",
        "TEST-conformance-deadbeef",
        "TEST-injection-DROPTABLEagents--",
    ):
        assert hidden not in visible, f"{hidden} leaked into public listing"

    # `total` reflects what's actually returned, not the in-memory count.
    assert body["total"] == len(visible)


def test_list_members_with_skill_filter_still_gates(
    client: TestClient, chapter_agent_module, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A TEST-* member with a matching skill MUST still be hidden."""
    _seed_members(
        chapter_agent_module,
        extras={"TEST-python-bot": {"name": "x", "description": "x", "skills": ["python"]}},
    )
    monkeypatch.setattr(chapter_agent_module, "pg_request", _noop_supabase)

    headers = _reader(chapter_agent_module)(method="GET", url_path="/api/members?skill=python")
    resp = client.get("/api/members?skill=python", headers=headers)
    assert resp.status_code == 200, resp.text[:300]
    visible = _ids(resp.json()["members"])
    assert "alice" in visible
    assert "TEST-python-bot" not in visible


def test_helper_recognises_each_hidden_prefix(chapter_agent_module) -> None:
    """Lock the predicate so a future PR cannot add a prefix without a test."""
    f = chapter_agent_module._hidden_from_public_listing
    assert f("TEST-anything")
    assert f("TEST-injection-DROPTABLEagents--")
    assert f("TEST-conformance-deadbeef")
    assert not f("alice")
    assert not f("STARTUP-x")
    assert not f("test-lowercase-not-hidden")
    # Empty / weird inputs MUST NOT crash.
    assert not f("")


# ---------------------------------------------------------------------------
# /api/thoughts — feed contains chapter-level prose mentioning members
# ---------------------------------------------------------------------------


def test_thoughts_filters_when_author_is_TEST_prefixed(
    client: TestClient, chapter_agent_module, monkeypatch: pytest.MonkeyPatch
) -> None:
    rows = [
        {"id": "1", "member_agent_id": "alice", "thought_text": "real thought"},
        {"id": "2", "member_agent_id": "TEST-priya", "thought_text": "test thought"},
    ]

    async def fake_supa(*_, **__):  # noqa: ARG001
        return rows

    monkeypatch.setattr(chapter_agent_module, "pg_request", fake_supa)

    resp = client.get("/api/thoughts")
    body = resp.json()
    ids = {t["id"] for t in body["thoughts"]}
    assert "1" in ids
    assert "2" not in ids


def test_thoughts_filters_when_body_mentions_TEST_prefix(
    client: TestClient, chapter_agent_module, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The chapter's LLM weaves member names into conversation summaries.
    Even when ``member_agent_id`` is null (chapter-level thought), if the
    body text references a TEST-* agent, the thought MUST be filtered —
    that's how the production audit found prose like
    ``Discussion between @sharathvchandra_agent and @TEST-injection-...``.
    """
    rows = [
        {"id": "clean", "member_agent_id": None, "thought_text": "Alice and Bob met"},
        {
            "id": "leaked",
            "member_agent_id": None,
            "thought_text": "Discussion between @alice and @TEST-injection-DROPTABLEagents--",
        },
    ]

    async def fake_supa(*_, **__):  # noqa: ARG001
        return rows

    monkeypatch.setattr(chapter_agent_module, "pg_request", fake_supa)

    resp = client.get("/api/thoughts")
    ids = {t["id"] for t in resp.json()["thoughts"]}
    assert ids == {"clean"}


def test_thoughts_respects_limit_after_filtering(
    client: TestClient, chapter_agent_module, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The handler over-fetches so post-filter we still hit the requested
    limit. Verify the trim is applied AFTER filtering — caller asks for 3,
    they get up to 3 clean rows even when half the source is dirty."""
    rows = [{"id": str(i), "member_agent_id": "alice", "thought_text": "ok"} for i in range(20)] + [
        {"id": f"bad{i}", "member_agent_id": "TEST-x", "thought_text": "TEST-injection-x"} for i in range(20)
    ]

    async def fake_supa(*_, **__):  # noqa: ARG001
        return rows

    monkeypatch.setattr(chapter_agent_module, "pg_request", fake_supa)

    resp = client.get("/api/thoughts?limit=3")
    visible = resp.json()["thoughts"]
    assert len(visible) == 3
    for t in visible:
        assert "TEST-" not in (t.get("member_agent_id") or "")
        assert "TEST-" not in (t.get("thought_text") or "")


# ---------------------------------------------------------------------------
# /api/agents/{agent_id}/profile — single-member lookup
#
# Retargeted from /api/member/{agent_id}/profile, which was retired as a
# near-duplicate: same gate, ported into its surviving twin so the
# TEST-fixture-hiding property didn't disappear along with the route.
# ---------------------------------------------------------------------------


def test_profile_404s_for_TEST_prefixed_agent(client: TestClient, chapter_agent_module) -> None:
    """Even when the member exists in the in-memory dict, a public profile
    lookup MUST 404 so a journalist can't paste the URL into a browser and
    see the test fixture."""
    _seed_members(chapter_agent_module)

    resp = client.get("/api/agents/TEST-injection-DROPTABLEagents--/profile")
    assert resp.status_code == 404
    assert resp.json()["detail"]


def test_profile_404s_even_when_TEST_prefix_member_missing_from_dict(client: TestClient, chapter_agent_module) -> None:
    """The gate runs BEFORE the membership lookup — there must be no
    branch where a TEST-* lookup leaks information about whether the
    fixture is present in memory or not."""
    chapter_agent_module.members.clear()
    chapter_agent_module.members["alice"] = {
        "name": "Alice",
        "description": "x",
        "skills": [],
    }

    resp = client.get("/api/agents/TEST-fake/profile")
    assert resp.status_code == 404
    assert resp.json()["detail"]
