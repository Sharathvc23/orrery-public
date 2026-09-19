"""Group 2 closures: the four routes that expose one agent's private state
(or org-wide policy history) keyed by an id/key the caller supplies, with no
stated public purpose and no consumer anywhere in the repo.

GET /api/authority/{agent_id}, GET /api/channels/{agent_id} and
GET /api/onboarding/{agent_id} each have a write-side sibling
(POST /api/authority/{agent_id}, POST /api/channels/connect,
POST /api/onboarding/advance) that has ALWAYS scoped the caller to their own
id or an admin — the read side never got the same treatment. Closed the same
way: /api/authority/, /api/channels/ and /api/onboarding/ join
auth_verify.REQUIRE_AUTH_GET_PREFIXES, and each handler is scoped via the
existing _require_agent_owner helper, same idiom as /api/settings/{agent_id}
and /api/conversations/{agent_id}.

GET /api/policy/{key}/history is a gate-SHAPE bug, not a missing entry:
GET /api/policy is already in REQUIRE_AUTH_GET_PATHS, matched EXACTLY, so
this child path escaped its parent's gate entirely. It carries the same
org-wide policy data (a hyperparameter's history rather than its current
value) as its parent, so the fix is the same auth requirement — any signed
member, not self-scoped — via a new /api/policy/ prefix entry. No handler
change: /api/policy itself has none either.

Each route needs both cases: an unauthenticated caller is refused, and (for
the three self-scoped routes) a caller signed as someone OTHER than the
target agent is refused; for policy/history, any signed member is admitted
(it isn't self-scoped — a signed non-owner of anything is still a valid
reader of org-wide policy, same as GET /api/policy itself).
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from tests._admin_fixtures import (
    register_test_regular_member,
    reset_chapter_agent_module,
)

OWNER = "group2-scoped-owner"
OTHER = "group2-scoped-other"


@pytest.fixture
def stack(monkeypatch):
    mod = reset_chapter_agent_module(monkeypatch)
    mod.members.clear()
    owner = register_test_regular_member(mod, agent_id=OWNER, name="Owner")
    other = register_test_regular_member(mod, agent_id=OTHER, name="Other")
    return mod, owner, other, TestClient(mod.app)


#: (method, path template). Formatted with .format(owner=OWNER).
SELF_SCOPED_ROUTES = [
    ("GET", "/api/authority/{owner}"),
    ("GET", "/api/channels/{owner}"),
    ("GET", "/api/onboarding/{owner}"),
]


@pytest.mark.parametrize("method,path_tpl", SELF_SCOPED_ROUTES)
def test_unauthenticated_is_refused(stack, method, path_tpl):
    _mod, _owner, _other, client = stack
    path = path_tpl.format(owner=OWNER)
    resp = client.request(method, path)
    assert resp.status_code in (401, 403), resp.text


@pytest.mark.parametrize("method,path_tpl", SELF_SCOPED_ROUTES)
def test_signed_as_someone_else_is_refused(stack, method, path_tpl):
    """THE GUARD. A real, verified signature from a DIFFERENT registered
    member than the one named in the path."""
    _mod, _owner, other, client = stack
    path = path_tpl.format(owner=OWNER)
    headers = other["signer"](method=method, url_path=path, body="")
    resp = client.request(method, path, headers=headers)
    assert resp.status_code == 403, resp.text


# ── /api/policy/{key}/history — org-wide, not self-scoped ──────────────


def test_policy_history_get_prefix_requires_auth():
    import auth_verify

    prefixes = auth_verify.REQUIRE_AUTH_GET_PREFIXES
    assert "/api/policy/" in prefixes
    assert any("/api/policy/llm_provider/history".startswith(p) for p in prefixes)


def test_policy_history_unauthenticated_is_refused(stack):
    _mod, _owner, _other, client = stack
    resp = client.get("/api/policy/some-key/history")
    assert resp.status_code in (401, 403), resp.text


def test_policy_history_any_signed_member_is_allowed(stack, monkeypatch):
    """Not self-scoped: unlike the three above, ANY signed member reads org
    policy history — same as GET /api/policy itself."""
    _mod, owner, _other, client = stack

    async def fake_history_for(key, limit=50):
        return []

    import policy as policy_mod

    monkeypatch.setattr(policy_mod, "history_for", fake_history_for)

    path = "/api/policy/some-key/history"
    headers = owner["signer"](method="GET", url_path=path, body="")
    resp = client.get(path, headers=headers)
    assert resp.status_code == 200, resp.text
