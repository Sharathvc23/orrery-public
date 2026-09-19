"""That change piece 2 — member self-removal ("leave org") via the member's own signature.

The security-critical property: the self-removal path fires ONLY when the
VERIFIED caller (request.state.agent_id, set by the middleware on a valid
Ed25519 signature) equals the target — a signed member can remove ITSELF but
never a victim. Anything else falls through to admin authorization.
"""

from __future__ import annotations

import json
import os

os.environ.setdefault("AGENT_ID", "test-org")
os.environ.setdefault("AGENT_NAME", "Test Org")

import pytest  # noqa: E402

import chapter_agent  # noqa: E402


def _status(resp):
    return resp.status_code


def _body(resp):
    return json.loads(bytes(resp.body))


def _req(agent_id: str):
    class _State:
        pass

    st = _State()
    st.agent_id = agent_id

    class _Req:
        state = st
        query_params: dict = {}

    return _Req()


@pytest.mark.asyncio
async def test_self_path_only_when_caller_equals_target(monkeypatch):
    """Routing is the security boundary: self-removal only when caller==target;
    otherwise admin authorization, including the unsigned (no-caller) case."""
    calls: dict = {}

    async def fake_admin(agent_id, request):
        calls["admin"] = agent_id
        return chapter_agent.JSONResponse(content={"removed": agent_id})

    async def fake_self(safe_id, request):
        calls["self"] = safe_id
        return chapter_agent.JSONResponse(content={"removed": safe_id, "self": True})

    monkeypatch.setattr(chapter_agent, "admin_remove_member", fake_admin)
    monkeypatch.setattr(chapter_agent, "_self_remove_member", fake_self)

    # caller == target → self path
    await chapter_agent.remove_member("alice", _req("alice"))
    assert calls == {"self": "alice"}

    # caller != target (a signed member targeting a victim) → admin path (will deny)
    calls.clear()
    await chapter_agent.remove_member("bob", _req("alice"))
    assert calls == {"admin": "bob"}

    # no verified caller (unsigned) → admin path
    calls.clear()
    await chapter_agent.remove_member("bob", _req(""))
    assert calls == {"admin": "bob"}


@pytest.mark.asyncio
async def test_self_removal_removes_the_member(monkeypatch):
    chapter_agent.members["leaver"] = {"agent_id": "leaver", "name": "Leaver"}

    async def fake_sb(method, table, params=None, body=None, **k):
        if method == "GET" and table == "agents":
            return [{"chapter_role": "member"}]
        return []

    monkeypatch.setattr(chapter_agent, "pg_request", fake_sb)

    resp = await chapter_agent.remove_member("leaver", _req("leaver"))
    assert _status(resp) == 200
    assert _body(resp) == {"removed": "leaver", "self": True}
    assert "leaver" not in chapter_agent.members


@pytest.mark.asyncio
async def test_self_removal_emits_member_left(monkeypatch):
    """A departure fires member.left (self_revoke) — the event existed but was
    never published before, so subscribers never saw leaves."""
    import asyncio

    import event_bus

    chapter_agent.members["leaver2"] = {"agent_id": "leaver2"}
    published = []

    async def capture(event_type, payload):
        published.append((event_type, payload))

    async def fake_sb(method, table, params=None, body=None, **k):
        return [{"chapter_role": "member"}] if (method == "GET" and table == "agents") else []

    monkeypatch.setattr(chapter_agent, "pg_request", fake_sb)
    monkeypatch.setattr(event_bus, "safe_publish", capture)

    await chapter_agent.remove_member("leaver2", _req("leaver2"))
    await asyncio.sleep(0)  # let the fire-and-forget task run

    assert ("member.left", {"agent_id": "leaver2", "reason": "self_revoke"}) in published


@pytest.mark.asyncio
async def test_last_admin_self_removal_refused(monkeypatch):
    chapter_agent.members["soleadmin"] = {"agent_id": "soleadmin"}

    async def fake_sb(method, table, params=None, body=None, **k):
        if method == "GET" and table == "agents":
            # role lookup → admin; admin-list lookup → just this one
            if (params or {}).get("agent_id", "").endswith("soleadmin"):
                return [{"chapter_role": "admin"}]
            return [{"agent_id": "soleadmin"}]
        return []

    monkeypatch.setattr(chapter_agent, "pg_request", fake_sb)

    resp = await chapter_agent.remove_member("soleadmin", _req("soleadmin"))
    assert _status(resp) == 409
    assert "no admin" in _body(resp)["error"]
    assert "soleadmin" in chapter_agent.members  # not removed
