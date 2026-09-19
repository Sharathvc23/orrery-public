"""Admin-gate coverage: the last of the 15 routes the admin-gate coverage
enumeration found unguarded — the remaining four Tier 1 routes plus both
Tier 2 routes.

Continues test_admin_membership_authz.py (the four highest-blast-radius
mutations) and test_admin_grants_members_authz.py (five more /admin/api/*
routes). This batch is the two-part tail:

TIER 1 (no middleware backstop — GET /api/admin/llm/spend, GET /api/approvals,
GET /api/invites, GET /api/invites/; POST /api/admin/think/resume is
technically Tier 2-shaped by path but grouped here since it shares the
_authorize_admin idiom and zero prior coverage): removing the check means
immediate, full anonymous access.

TIER 2 (a middleware backstop exists — POST /api/dsar/delete): removing the
check downgrades admin-only to any-authenticated-member, not full anonymity.
This is the route the admin-gate coverage enumeration used to prove the
SECOND case cannot be skipped — its existing "unauthenticated caller denied"
test passes even with the handler's own _authorize_admin call fully
bypassed, because the middleware's blanket POST-requires-auth rule rejects
the fully-unauthenticated request before the handler ever runs. Only a
signed-but-non-admin caller exercises the in-handler check, which is exactly
the case this file adds for it.

Every route needs both cases:
  - an unauthenticated caller is refused, and
  - a caller who signed as a real, registered member outside the allowed
    role set is refused.

No route's authorization is changed here.
"""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from tests._admin_fixtures import (
    register_test_admin_member,
    register_test_regular_member,
    reset_chapter_agent_module,
)

ADMIN = "admin-gate-carol3"
MEMBER = "admin-gate-alice3"


@pytest.fixture
def stack(monkeypatch):
    mod = reset_chapter_agent_module(monkeypatch)
    mod.members.clear()

    import governance

    admin = register_test_admin_member(mod, agent_id=ADMIN, name="Carol")
    member = register_test_regular_member(mod, agent_id=MEMBER, name="Alice")

    async def role_of(agent_id: str) -> str:
        return (mod.members.get(agent_id) or {}).get("chapter_role", "member")

    monkeypatch.setattr(governance, "get_chapter_role", role_of)
    return mod, admin, member, TestClient(mod.app)


def _request(client, method: str, path: str, body: dict | None, headers: dict | None = None):
    headers = dict(headers or {})
    if body is not None:
        content = json.dumps(body, separators=(",", ":"))
        headers["Content-Type"] = "application/json"
        return client.request(method, path, content=content, headers=headers)
    return client.request(method, path, headers=headers)


def _body_str(body: dict | None) -> str:
    return json.dumps(body, separators=(",", ":")) if body is not None else ""


#: (method, path, body). Query-string params (dsar/delete) are baked into the
#: path itself, same as any other URL — a seventh route is a new row.
ROUTES: list[tuple[str, str, dict | None]] = [
    ("GET", "/api/admin/llm/spend", None),
    ("GET", "/api/approvals", None),
    ("GET", "/api/invites", None),
    ("GET", "/api/invites/", None),
    ("POST", "/api/admin/think/resume", None),
    ("POST", "/api/dsar/delete?subject_did=did:key:zTargetDoesNotExist&confirm=true", None),
]


@pytest.mark.parametrize("method,path,body", ROUTES)
def test_unauthenticated_is_refused(stack, method, path, body):
    """No credentials at all."""
    _mod, _admin, _member, client = stack
    resp = _request(client, method, path, body)
    assert resp.status_code in (401, 403), resp.text


@pytest.mark.parametrize("method,path,body", ROUTES)
def test_signed_non_admin_is_refused(stack, method, path, body):
    """THE GUARD. A real, verified signature from a registered member whose
    chapter_role is 'member' — outside every allowed set here (leader/admin,
    leader/advisor/mentor/admin, or admin-only). This is the case that cannot
    be skipped: for POST /api/dsar/delete specifically, the unauthenticated
    case above is satisfied by the middleware's own blanket POST-requires-auth
    rule without ever reaching this handler's _authorize_admin call — this
    test is the only one that actually exercises it."""
    _mod, _admin, member, client = stack
    headers = member["signer"](method=method, url_path=path, body=_body_str(body))
    resp = _request(client, method, path, body, headers=headers)
    assert resp.status_code == 403, resp.text
