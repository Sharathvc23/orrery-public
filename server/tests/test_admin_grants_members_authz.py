"""Admin-gate coverage: the remaining Tier 1 /admin/api/* routes.

Continues tests/test_admin_membership_authz.py, which covered the four
routes that mutate authority or membership. These five carry the same shape
(an ``_authorize_admin`` / ``_require_admin`` check with zero prior test
coverage, on a route under /admin/api/*, which has no middleware gate for
any method) but lower blast radius — reads and lower-impact writes rather
than membership/authority mutation.

Each route needs BOTH cases, same reason as before: an unauthenticated
caller is refused, AND a caller who signed as a real, registered member
outside the admin role is refused. The second is what distinguishes "checks
WHO" from "checks THAT something signed" — the admin-gate coverage
enumeration found a route (POST /api/dsar/delete) where the first case alone
was satisfied by a middleware rule that never touched the handler.

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

ADMIN = "admin-gate-carol2"
MEMBER = "admin-gate-alice2"
TARGET = "admin-gate-target-bob2"


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


#: (method, path template, body). A sixth route is a new row, not a new test.
ROUTES: list[tuple[str, str, dict | None]] = [
    ("GET", "/admin/api/grants", None),
    ("GET", "/admin/api/grants/{grant}/consumptions", None),
    ("GET", "/admin/api/members", None),
    ("POST", "/admin/api/host39/record-publication/{target}", {}),
    ("POST", "/admin/api/receipts/publish", {}),
]


def _resolve_path(path_tpl: str) -> str:
    return path_tpl.format(target=TARGET, grant="grant-does-not-exist")


@pytest.mark.parametrize("method,path_tpl,body", ROUTES)
def test_unauthenticated_is_refused(stack, method, path_tpl, body):
    """No credentials at all. /admin/api/* has no middleware gate, so a 401/403
    here can only come from the handler's own admin check."""
    _mod, _admin, _member, client = stack
    resp = _request(client, method, _resolve_path(path_tpl), body)
    assert resp.status_code in (401, 403), resp.text


@pytest.mark.parametrize("method,path_tpl,body", ROUTES)
def test_signed_non_admin_is_refused(stack, method, path_tpl, body):
    """THE GUARD. A real, verified signature from a registered member whose
    chapter_role is 'member', not 'admin'."""
    _mod, _admin, member, client = stack
    path = _resolve_path(path_tpl)
    headers = member["signer"](method=method, url_path=path, body=_body_str(body))
    resp = _request(client, method, path, body, headers=headers)
    assert resp.status_code == 403, resp.text
