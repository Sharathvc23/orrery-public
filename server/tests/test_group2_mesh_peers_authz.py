"""Group 2 closure: GET /api/mesh/peers, and its A2UI twin
GET /api/surfaces/mesh, both answered the peer search anonymously.

mesh.list_peers returns agent_id/name/skills/trust_score for every LOCAL
member matching the query — the same member-enumeration shape as the closed
GET /api/members and GET /api/surfaces/directory, just reached through the
mesh search rather than the directory. GET /api/surfaces/mesh renders its
peer browser by calling the exact same mesh.list_peers underneath
(surfaces.build_mesh_surface), so it carries the same leak and is closed the
same way: both paths join auth_verify.REQUIRE_AUTH_GET_PATHS as literals, and
"mesh" joins MEMBER_BEARING_SURFACES.

Neither route is self-scoped — this is a cross-org search, not one agent's
own state — so, like GET /api/policy and GET /api/policy/{key}/history, the
fix is a bare auth requirement with no handler change: any signed member is
an authorized reader, same as the search itself has always allowed any
caller (signed or not) to filter by any agent.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from tests._admin_fixtures import (
    register_test_regular_member,
    reset_chapter_agent_module,
)

MEMBER = "group2-mesh-member"


@pytest.fixture
def stack(monkeypatch):
    mod = reset_chapter_agent_module(monkeypatch)
    mod.members.clear()
    member = register_test_regular_member(mod, agent_id=MEMBER, name="Mesh Member")
    return mod, member, TestClient(mod.app)


def test_mesh_peers_and_surfaces_mesh_are_gated_at_the_source():
    import auth_verify

    assert "/api/mesh/peers" in auth_verify.REQUIRE_AUTH_GET_PATHS
    assert "/api/surfaces/mesh" in auth_verify.REQUIRE_AUTH_GET_PATHS
    assert "mesh" in auth_verify.MEMBER_BEARING_SURFACES


@pytest.mark.parametrize("path", ["/api/mesh/peers", "/api/surfaces/mesh"])
def test_unauthenticated_is_refused(stack, path):
    _mod, _member, client = stack
    resp = client.get(path)
    assert resp.status_code in (401, 403), resp.text


@pytest.mark.parametrize("path", ["/api/mesh/peers", "/api/surfaces/mesh"])
def test_any_signed_member_is_allowed(stack, path):
    """Not self-scoped: unlike authority/channels/onboarding, this is a
    cross-org search — any signed member is a valid reader, same as GET
    /api/policy."""
    _mod, member, client = stack
    headers = member["signer"](method="GET", url_path=path, body="")
    resp = client.get(path, headers=headers)
    assert resp.status_code == 200, resp.text
