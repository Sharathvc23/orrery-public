"""Group 2 closure: GET /api/projections answered anonymously and leaked
each row's projection_id -- the member's real agent_id.

projections.py exists specifically so identity is revealed only after
bilateral consent (module docstring): "Each member's agent publishes a
projection: skills, interests, availability, chapter -- NO name, email,
company, or personal details." projections.get_projections() itself claims
"anonymized -- no agent_ids in output", but its own next line adds
``"projection_id": aid`` to every row -- a real agent_id, contradicting its
own docstring on consecutive lines.

Closed at the API boundary, not in projections.get_projections() itself:
that function's projection_id is a legitimate internal correlation key for
the intent-matching pipeline (excluding the requester's own projection from
its own search, scoring matches) and none of those internal consumers ever
render it to a caller. Only GET /api/projections' handler is fixed --
gated (any signed member, not self-scoped, same shape as GET /api/policy)
and its response filtered to drop projection_id.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from tests._admin_fixtures import (
    register_test_regular_member,
    reset_chapter_agent_module,
)

MEMBER = "group2-projections-member"


@pytest.fixture
def stack(monkeypatch):
    mod = reset_chapter_agent_module(monkeypatch)
    mod.members.clear()
    member = register_test_regular_member(mod, agent_id=MEMBER, name="Projections Member")

    import projections

    monkeypatch.setattr(
        projections,
        "_projections_cache",
        {
            "some-other-member": {
                "skills": ["ml"],
                "interests": [],
                "availability": "active",
                "chapter": "Test Chapter",
                "chapter_id": "test-chapter",
                "skill_count": 1,
            }
        },
    )
    return mod, member, TestClient(mod.app)


def test_projections_is_gated_at_the_source():
    import auth_verify

    assert "/api/projections" in auth_verify.REQUIRE_AUTH_GET_PATHS


def test_unauthenticated_is_refused(stack):
    _mod, _member, client = stack
    resp = client.get("/api/projections")
    assert resp.status_code in (401, 403), resp.text


def test_signed_member_is_allowed_but_projection_id_is_stripped(stack):
    """THE GUARD: a signed member can read the anonymized directory, but
    still cannot learn WHO each entry is."""
    _mod, member, client = stack
    headers = member["signer"](method="GET", url_path="/api/projections", body="")
    resp = client.get("/api/projections", headers=headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["projections"], "fixture projection should be returned"
    for proj in body["projections"]:
        assert "projection_id" not in proj
    assert "some-other-member" not in resp.text
