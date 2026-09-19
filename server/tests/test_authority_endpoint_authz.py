"""POST /api/authority/{id} must bind to the AUTH-VERIFIED caller, not body `updated_by`.

Regression: the handler derived the actor from the request body's ``updated_by``
field (default ``"self"``), so any SIGNED member could edit ANY agent's authority
scope by POSTing /api/authority/<victim> with updated_by="self" — the actor became
the path id, the self-branch skipped the admin check, and the victim's scope was
mutated. The fix binds the actor to ``request.state.agent_id`` (set by the auth
middleware only on a valid Ed25519 signature). These tests pin that.
"""

from __future__ import annotations

import sys
from unittest.mock import MagicMock

import pytest

# Imported so sys.modules has these for the live-module patches below (which the
# handler resolves via its own in-function imports); patching sys.modules[...]
# rather than these names keeps the patch correct even if a fixture reloads them.
import authority  # noqa: F401
import chapter_agent
import governance  # noqa: F401


def _request(caller: str) -> MagicMock:
    """A request whose middleware-verified identity is ``caller`` ("" = unauthenticated)."""
    req = MagicMock()
    req.state.agent_id = caller
    return req


def _body(agent_id: str = "victim", updated_by: str = "self") -> chapter_agent.AuthorityUpdate:
    return chapter_agent.AuthorityUpdate(
        agent_id=agent_id, action_kind="rsvp.create", allowed=True, updated_by=updated_by
    )


@pytest.mark.asyncio
async def test_member_cannot_edit_others_scope_via_self_claim(monkeypatch):
    """Signed member 'mallory' hitting /api/authority/victim with updated_by='self'
    is refused (403) and mutates nothing — the verified caller ≠ the path id."""
    set_calls: list[dict] = []

    async def _set_scope(**kw):
        set_calls.append(kw)
        return {"ok": True}

    async def _role(_aid):
        return "member"

    monkeypatch.setattr(sys.modules["authority"], "set_scope", _set_scope)
    monkeypatch.setattr(sys.modules["governance"], "get_chapter_role", _role)

    with pytest.raises(chapter_agent.HTTPException) as exc:
        await chapter_agent.update_authority("victim", _body(updated_by="self"), _request("mallory"))
    assert exc.value.status_code == 403
    assert set_calls == []  # the body-claim bypass no longer mutates


@pytest.mark.asyncio
async def test_unauthenticated_request_is_rejected(monkeypatch):
    """No verified caller (no/invalid signature) → 401, no mutation."""

    async def _set_scope(**_kw):
        raise AssertionError("set_scope must not run for an unauthenticated caller")

    monkeypatch.setattr(sys.modules["authority"], "set_scope", _set_scope)

    with pytest.raises(chapter_agent.HTTPException) as exc:
        await chapter_agent.update_authority("victim", _body(), _request(""))
    assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_member_can_edit_own_scope(monkeypatch):
    """A member editing their OWN scope (verified caller == path id) succeeds, and
    the persisted ``updated_by`` is the verified caller — not the body claim."""
    set_calls: list[dict] = []

    async def _set_scope(**kw):
        set_calls.append(kw)
        return {"ok": True}

    monkeypatch.setattr(sys.modules["authority"], "set_scope", _set_scope)

    out = await chapter_agent.update_authority("alice", _body(agent_id="alice"), _request("alice"))
    assert out == {"ok": True}
    assert set_calls and set_calls[0]["updated_by"] == "alice"


@pytest.mark.asyncio
async def test_admin_can_edit_anyone(monkeypatch):
    """An admin may override another agent's scope; updated_by records the admin."""
    set_calls: list[dict] = []

    async def _set_scope(**kw):
        set_calls.append(kw)
        return {"ok": True}

    async def _role(_aid):
        return "admin"

    monkeypatch.setattr(sys.modules["authority"], "set_scope", _set_scope)
    monkeypatch.setattr(sys.modules["governance"], "get_chapter_role", _role)

    out = await chapter_agent.update_authority("victim", _body(), _request("bigboss"))
    assert out == {"ok": True}
    assert set_calls and set_calls[0]["updated_by"] == "bigboss"
