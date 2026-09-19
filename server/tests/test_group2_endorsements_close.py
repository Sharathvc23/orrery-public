"""Group 2 closure: GET /api/agents/{agent_id}/endorsements answered
anonymously despite each row naming a THIRD PARTY (endorser_agent_id,
endorser_did) plus free-text note_markdown -- a who-endorsed-whom social
graph, not the "this agent exists" disclosure its open sibling
GET /api/agents/{agent_id}/profile is designed to allow.

Closed via a startswith/endswith check in auth_verify.requires_auth (same
idiom as the existing /api/agents/{id}/export and
/api/federation/{peer}/members checks) rather than a REQUIRE_AUTH_GET_PATHS
prefix entry, because /api/agents/ is shared by several sibling routes
(profile, trust, aae-events, export) with different auth postures -- a
prefix would have over-gated all of them.

NOTE: GET /api/surfaces/endorsements (the A2UI twin) is a SEPARATE,
pre-existing, deliberately-open surface (auth_verify.PER_AGENT_SHAREABLE_
SURFACES, locked by test_read_surface_lockdown.py's
test_public_per_agent_surfaces_stay_open) and is intentionally NOT touched
here -- its "discloses its subject's agent_id and nothing more" rationale
does not hold for endorsements specifically (it also names the endorser
and any free text they wrote), which is flagged separately for a ruling
rather than decided by this fix.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from tests._admin_fixtures import (
    register_test_regular_member,
    reset_chapter_agent_module,
)

TARGET = "group2-endorsements-target"
READER = "group2-endorsements-reader"


@pytest.fixture
def stack(monkeypatch):
    mod = reset_chapter_agent_module(monkeypatch)
    mod.members.clear()
    register_test_regular_member(mod, agent_id=TARGET, name="Target")
    reader = register_test_regular_member(mod, agent_id=READER, name="Reader")
    return mod, reader, TestClient(mod.app)


def test_endorsements_get_requires_auth_at_the_source():
    import auth_verify

    assert auth_verify.requires_auth("GET", f"/api/agents/{TARGET}/endorsements") is True
    # Sibling routes under the same prefix must NOT be swept in.
    assert auth_verify.requires_auth("GET", f"/api/agents/{TARGET}/profile") is False


def test_unauthenticated_is_refused(stack):
    _mod, _reader, client = stack
    resp = client.get(f"/api/agents/{TARGET}/endorsements")
    assert resp.status_code in (401, 403), resp.text


def test_any_signed_member_is_allowed(stack, monkeypatch):
    """Not self-scoped: reading ANOTHER agent's received endorsements to
    evaluate them is the endorsement feature's whole purpose."""
    _mod, reader, client = stack

    import endorsements as endorsements_mod

    async def fake_list_endorsements_received(agent_id, *, include_revoked=False, limit=50):
        return []

    monkeypatch.setattr(endorsements_mod, "list_endorsements_received", fake_list_endorsements_received)

    path = f"/api/agents/{TARGET}/endorsements"
    headers = reader["signer"](method="GET", url_path=path, body="")
    resp = client.get(path, headers=headers)
    assert resp.status_code == 200, resp.text
