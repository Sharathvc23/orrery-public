"""Admin-gate coverage: the four /admin/api/* routes that mutate authority or
membership — highest blast radius of the 15 routes found unguarded by the
admin-gate coverage enumeration.

/admin/api/* carries NO middleware gate for any method (auth_verify.is_open_path
returns True unconditionally for the whole prefix) — the in-handler
``_authorize_admin`` call is the ONLY protection. Driving the live chapter
confirmed the checks work TODAY (anonymous GET /admin/api/members and
GET /admin/api/grants both return 401): this is not an open door, it is a door
whose hinge nothing inspects. These tests are the inspection.

Each route needs BOTH cases, and the enumeration's own finding
(POST /api/dsar/delete) is why the second cannot be skipped: an
"unauthenticated caller is refused" test can be satisfied by a middleware rule
that never touches the handler. /admin/api/* has no such rule, so here the
unauthenticated case genuinely exercises ``_authorize_admin`` — but the
wrong-role case is the one that proves it checks WHO, not just WHETHER
signed, and no route is declared covered without both:
  - an unauthenticated caller is refused (401/403), and
  - a caller who signed as a real, registered member NOT in the admin role
    is refused (403).

No route's authorization is changed here. If any of these assertions had
failed, that would be a ruling, not a fix — and none did.
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

ADMIN = "admin-gate-carol"
MEMBER = "admin-gate-alice"
TARGET = "admin-gate-target-bob"


@pytest.fixture
def stack(monkeypatch):
    mod = reset_chapter_agent_module(monkeypatch)
    mod.members.clear()

    import governance

    admin = register_test_admin_member(mod, agent_id=ADMIN, name="Carol")
    member = register_test_regular_member(mod, agent_id=MEMBER, name="Alice")
    mod.members[TARGET] = {
        "agent_id": TARGET,
        "name": "Bob",
        "description": "target member",
        "skills": [],
        "chapter_role": "member",
        "virtual": False,
        "is_demo": True,
    }

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


#: (method, path template, body). Route 5 is a new row, not a new test.
#: Bodies are shaped to pass FastAPI's own request validation (a missing
#: required field 422s before the handler's _authorize_admin ever runs,
#: which would make the "unauthenticated" case a false pass for the wrong
#: reason) — every case below reaches the auth check, not request parsing.
ROUTES = [
    ("DELETE", "/admin/api/members/{target}", None),
    ("POST", "/admin/api/members/{target}/role", {"role": "leader"}),
    ("POST", "/admin/api/grants", {"kind": "budget", "scope": {}, "cap": 1, "expires_at": "2999-01-01T00:00:00Z"}),
    ("DELETE", "/admin/api/grants/{grant}", None),
]


def _resolve_path(path_tpl: str) -> str:
    return path_tpl.format(target=TARGET, grant="grant-does-not-exist")


@pytest.mark.parametrize("method,path_tpl,body", ROUTES)
def test_unauthenticated_is_refused(stack, method, path_tpl, body):
    """No credentials at all. /admin/api/* has no middleware gate, so a 401/403
    here can only come from the handler's own _authorize_admin call."""
    _mod, _admin, _member, client = stack
    resp = _request(client, method, _resolve_path(path_tpl), body)
    assert resp.status_code in (401, 403), resp.text


@pytest.mark.parametrize("method,path_tpl,body", ROUTES)
def test_signed_non_admin_is_refused(stack, method, path_tpl, body):
    """THE GUARD. A real, verified signature from a registered member whose
    chapter_role is 'member', not 'admin'. Proves the check inspects WHO
    signed, not merely THAT something did — the case the DSAR false positive
    showed cannot be skipped."""
    _mod, _admin, member, client = stack
    path = _resolve_path(path_tpl)
    headers = member["signer"](method=method, url_path=path, body=_body_str(body))
    resp = _request(client, method, path, body, headers=headers)
    assert resp.status_code == 403, resp.text
