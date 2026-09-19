"""Governance/federation mutations must bind to the AUTH-VERIFIED caller, not a
body-claimed ``actor_agent_id``.

Regression for the systemic vuln class: override/pin/unpin_policy and block/
unblock_peer derived the actor from ``req.actor_agent_id``, so any SIGNED member
could perform an admin/leader action by naming a privileged id in the body. The
fix binds the actor to ``request.state.agent_id`` (``_resolve_caller``). These
tests pin two representatives (policy override + federation block).
"""

from __future__ import annotations

import sys
from unittest.mock import MagicMock

import pytest

import chapter_agent
import governance  # noqa: F401  (imported so sys.modules has it for the live patch)
import policy  # noqa: F401


def _request(caller: str) -> MagicMock:
    req = MagicMock()
    req.state.agent_id = caller
    return req


@pytest.mark.asyncio
async def test_override_policy_rejects_body_claimed_admin(monkeypatch):
    """A signed member naming an admin in the body is NOT admin — 403, no override."""

    async def _role(_aid):
        return "member"  # the VERIFIED caller's real role

    called = []

    async def _override(*a, **k):
        called.append(a)
        return {"ok": True}

    monkeypatch.setattr(sys.modules["governance"], "get_chapter_role", _role)
    monkeypatch.setattr(sys.modules["policy"], "override", _override)

    body = chapter_agent.PolicyOverride(actor_agent_id="admin-alice", new_value=5, reason="x")
    with pytest.raises(chapter_agent.HTTPException) as exc:
        await chapter_agent.override_policy("trust_threshold", body, _request("mallory"))
    assert exc.value.status_code == 403
    assert called == []  # the override never ran


@pytest.mark.asyncio
async def test_override_policy_unauthenticated(monkeypatch):
    async def _override(*a, **k):
        raise AssertionError("override must not run unauthenticated")

    monkeypatch.setattr(sys.modules["policy"], "override", _override)
    body = chapter_agent.PolicyOverride(actor_agent_id="admin-alice", new_value=5)
    with pytest.raises(chapter_agent.HTTPException) as exc:
        await chapter_agent.override_policy("k", body, _request(""))
    assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_block_peer_rejects_body_claimed_leader(monkeypatch):
    """A signed member naming a leader in the body cannot block a peer — 403."""

    async def _can_approve(_aid):
        return False  # the VERIFIED caller cannot approve

    monkeypatch.setattr(sys.modules["governance"], "can_approve", _can_approve)
    body = chapter_agent.PeerBlock(actor_agent_id="leader-bob", reason="x")
    with pytest.raises(chapter_agent.HTTPException) as exc:
        await chapter_agent.block_peer("some-peer", body, _request("mallory"))
    assert exc.value.status_code == 403


@pytest.mark.asyncio
async def test_block_peer_unauthenticated(monkeypatch):
    body = chapter_agent.PeerBlock(actor_agent_id="leader-bob")
    with pytest.raises(chapter_agent.HTTPException) as exc:
        await chapter_agent.block_peer("some-peer", body, _request(""))
    assert exc.value.status_code == 401
