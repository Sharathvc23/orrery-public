"""Org-level role authorization: the generalized `_authorize_role` gate and
the member-deletion hole it closes.

`_authorize_admin` is now the `allowed_roles={"admin"}` specialization of a
reusable `_authorize_role(request, allowed_roles)` (its admin behavior is
locked by test_admin_didkey_path.py / test_admin_api_authz.py — unchanged).
This module exercises the *generalization*:

  AUTHZ   a multi-role gate ({"leader","admin"}) admits a leader, refuses a
          plain member (403), and admits the bearer operator (break-glass
          satisfies any administrative gate)
  HOLE    DELETE /api/members/{id} was authenticated but NOT authorized — any
          signed member could remove any other. It now delegates to the admin
          handler: a signed non-admin is refused (403) before any mutation; a
          bearer operator removes.

Mirrors the MagicMock + monkeypatch style of test_admin_didkey_path.py.
"""

from __future__ import annotations

import importlib
import json
import os
from unittest.mock import AsyncMock, MagicMock

os.environ.setdefault("AGENT_ID", "test-chapter")
os.environ.setdefault("AGENT_NAME", "Test Chapter")

import pytest


@pytest.fixture
def reset_admin(monkeypatch, tmp_path):
    monkeypatch.delenv("CHAPTER_ADMIN_TOKEN", raising=False)
    monkeypatch.setenv("CHAPTER_HOME", str(tmp_path))
    import admin as admin_mod

    importlib.reload(admin_mod)
    admin_mod.init()
    return admin_mod


def _mock_request(*, method="POST", path="/api/x", body=b"", headers=None, caller=""):
    req = MagicMock()
    req.method = method
    req.url.path = path
    req.headers = dict(headers or {})
    req.body = AsyncMock(return_value=body)
    # The middleware sets request.state.agent_id to the verified caller (a str)
    # or leaves it unset; default to "" here so _resolve_caller returns a real
    # value, not an auto-MagicMock (self-removal routes on it).
    req.state.agent_id = caller
    return req


def _stub_identity(monkeypatch, *, agent_id: str, role: str):
    """Make verify_request succeed for `agent_id` with chapter_role `role`."""
    import auth_verify
    import governance

    def fake_verify(body, headers, method="", url_path="", max_age=300):
        return True, agent_id, "ok"

    async def fake_role(aid):
        return role if aid == agent_id else "member"

    monkeypatch.setattr(auth_verify, "verify_request", fake_verify)
    monkeypatch.setattr(governance, "get_chapter_role", fake_role)


# ══════════════════════════════════════════════════════════════════════
# _authorize_role — the generalized gate
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_role_gate_admits_leader_for_leader_or_admin(reset_admin, monkeypatch):
    import chapter_agent

    _stub_identity(monkeypatch, agent_id="lena", role="leader")
    req = _mock_request(headers={"X-Agent-Signature": "ab", "X-Agent-ID": "lena"})
    ok, identity, denied = await chapter_agent._authorize_role(req, {"leader", "admin"})
    assert ok is True
    assert denied is None
    assert identity == {"path": "did_key", "agent_id": "lena", "chapter_role": "leader"}


@pytest.mark.asyncio
async def test_role_gate_refuses_member_for_leader_or_admin(reset_admin, monkeypatch):
    import chapter_agent

    _stub_identity(monkeypatch, agent_id="mona", role="member")
    req = _mock_request(headers={"X-Agent-Signature": "ab", "X-Agent-ID": "mona"})
    ok, _identity, denied = await chapter_agent._authorize_role(
        req, {"leader", "admin"}
    )
    assert ok is False
    assert denied.status_code == 403
    body = json.loads(denied.body.decode())
    # Message names the required roles and the caller's actual role.
    assert "leader" in body["error"] and "admin" in body["error"]
    assert "chapter_role='member'" in body["hint"]


@pytest.mark.asyncio
async def test_role_gate_admits_admin_for_leader_or_admin(reset_admin, monkeypatch):
    import chapter_agent

    _stub_identity(monkeypatch, agent_id="ada", role="admin")
    req = _mock_request(headers={"X-Agent-Signature": "ab", "X-Agent-ID": "ada"})
    ok, _identity, denied = await chapter_agent._authorize_role(
        req, {"leader", "admin"}
    )
    assert ok is True and denied is None


@pytest.mark.asyncio
async def test_role_gate_bearer_satisfies_any_admin_gate(reset_admin):
    """The operator bearer is break-glass: it must pass even a leader-only
    gate, so an operator can always recover."""
    import chapter_agent

    token = reset_admin.init()[0]
    req = _mock_request(headers={"X-Admin-Token": token})
    ok, identity, denied = await chapter_agent._authorize_role(req, {"leader"})
    assert ok is True
    assert identity == {"path": "bearer"}
    assert denied is None


@pytest.mark.asyncio
async def test_role_gate_no_credentials_is_401(reset_admin):
    import chapter_agent

    req = _mock_request(headers={})
    ok, _identity, denied = await chapter_agent._authorize_role(
        req, {"leader", "admin"}
    )
    assert ok is False
    assert denied.status_code == 401


@pytest.mark.asyncio
async def test_require_role_returns_denial_or_none(reset_admin, monkeypatch):
    import chapter_agent

    _stub_identity(monkeypatch, agent_id="mona", role="member")
    sig = {"X-Agent-Signature": "ab", "X-Agent-ID": "mona"}
    denied = await chapter_agent._require_role(_mock_request(headers=sig), {"admin"})
    assert denied is not None and denied.status_code == 403

    _stub_identity(monkeypatch, agent_id="ada", role="admin")
    sig = {"X-Agent-Signature": "ab", "X-Agent-ID": "ada"}
    assert (
        await chapter_agent._require_role(_mock_request(headers=sig), {"admin"}) is None
    )


# ══════════════════════════════════════════════════════════════════════
# DELETE /api/members/{id} — the closed authorization hole
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_member_delete_refuses_signed_non_admin_without_mutating(
    reset_admin, monkeypatch
):
    import chapter_agent

    _stub_identity(monkeypatch, agent_id="mallory", role="member")
    chapter_agent.members["victim"] = {"name": "Victim", "chapter_role": "member"}

    async def _exploded(*a, **k):
        raise AssertionError("pg_request reached despite a non-admin caller")

    monkeypatch.setattr(chapter_agent, "pg_request", _exploded)

    req = _mock_request(
        method="DELETE",
        path="/api/members/victim",
        headers={"X-Agent-Signature": "ab", "X-Agent-ID": "mallory"},
    )
    resp = await chapter_agent.remove_member("victim", req)
    assert getattr(resp, "status_code", None) == 403
    # The mutation must NOT have happened.
    assert "victim" in chapter_agent.members
    chapter_agent.members.pop("victim", None)


@pytest.mark.asyncio
async def test_member_delete_bearer_operator_removes(reset_admin, monkeypatch):
    import chapter_agent

    chapter_agent.members["leaver"] = {"name": "Leaver", "chapter_role": "member"}

    # admin_remove_member reads role rows + issues a DELETE; an empty corpus
    # makes the last-admin guard a no-op (role defaults to 'member').
    monkeypatch.setattr(chapter_agent, "pg_request", AsyncMock(return_value=[]))

    token = reset_admin.init()[0]
    req = _mock_request(
        method="DELETE",
        path="/api/members/leaver",
        headers={"X-Admin-Token": token},
    )
    resp = await chapter_agent.remove_member("leaver", req)
    assert getattr(resp, "status_code", None) not in (401, 403)
    assert "leaver" not in chapter_agent.members
