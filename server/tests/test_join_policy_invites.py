"""That change piece 1 — configurable join policy (open | invite | approval).

Three provable layers:
  * open (default) — registration is an instant active member, exactly as today
    (the non-breaking guard).
  * invite — a NEW join needs a valid token; consumption is atomic at the SQL
    layer (org_invites.consume_org_invite) — the live exploit-replay fires the
    same token twice and asserts one success.
  * approval — a NEW join creates NO member/key; it stashes the claimed identity
    in a member_admission approval and materializes only on leader-approve (a
    pending member with a recorded key could otherwise sign before approval).
"""

from __future__ import annotations

import asyncio
import os

os.environ.setdefault("AGENT_ID", "test-org")
os.environ.setdefault("AGENT_NAME", "Test Org")

import pytest  # noqa: E402

import chapter_agent  # noqa: E402
import event_bus  # noqa: E402


@pytest.fixture(autouse=True)
def _iso(monkeypatch):
    monkeypatch.setattr(chapter_agent, "members", {})
    monkeypatch.setattr(chapter_agent, "PUBLIC_URL", "")

    async def _noop(*a, **k):
        return None

    monkeypatch.setattr(chapter_agent, "_persist_member_to_db", _noop)
    monkeypatch.setattr(event_bus, "safe_publish", _noop)
    monkeypatch.setattr(chapter_agent, "_load_org_config", lambda: {})  # default: no join_policy → open
    yield


def _reg(agent_id="alice", name="Alice", **kw):
    return chapter_agent.MemberRegistration(agent_id=agent_id, name=name, **kw)


def _status(resp):
    return getattr(resp, "status_code", 200)


@pytest.mark.asyncio
async def test_open_policy_is_default_instant_member():
    """Non-breaking guard: unset/open join_policy → instant active member."""
    r = await chapter_agent.register_member(_reg())
    assert r.get("registered") is True
    assert "alice" in chapter_agent.members


@pytest.mark.asyncio
async def test_open_policy_re_registration_still_idempotent(monkeypatch):
    """Re-registration / profile update is never gated, under any policy."""
    monkeypatch.setattr(chapter_agent, "_load_org_config", lambda: {"join_policy": "invite"})
    chapter_agent.members["alice"] = {"name": "Alice", "origin": "sovereign", "public_key": ""}
    # No invite token, but 'alice' already exists → treated as update, not a new join.
    r = await chapter_agent.register_member(_reg())
    assert r.get("registered") is True


@pytest.mark.asyncio
async def test_invite_policy_requires_valid_token(monkeypatch):
    monkeypatch.setattr(chapter_agent, "_load_org_config", lambda: {"join_policy": "invite"})

    async def fake_consume(token, *, agent_id):
        return token == "GOOD"

    monkeypatch.setattr(chapter_agent.invites_mod, "consume", fake_consume)

    # missing/invalid token → 403, no member created
    r = await chapter_agent.register_member(_reg(agent_id="bob"))
    assert _status(r) == 403
    assert "bob" not in chapter_agent.members

    # valid token → registered
    r = await chapter_agent.register_member(_reg(agent_id="carol", invite_token="GOOD"))
    assert r.get("registered") is True
    assert "carol" in chapter_agent.members


@pytest.mark.asyncio
async def test_approval_policy_creates_no_member_until_approved(monkeypatch):
    """A pending join must NOT create a member/key — it could otherwise sign
    before any leader approves (no active-status gate in auth).

    Drives the REAL governance.propose (mock the supabase store, never the unit
    under test). Regression guard: the call site once omitted the required
    positional ``proposer_agent_id`` → TypeError → HTTP 500 on every approval
    join. A propose mock shaped to the broken call hid it; this asserts the row
    that actually reaches the store, so a signature drift fails loudly."""
    monkeypatch.setattr(chapter_agent, "_load_org_config", lambda: {"join_policy": "approval"})
    import governance

    posted: list[dict] = []

    async def fake_sb(method, table, *, params=None, body=None, **k):
        if method == "POST" and table == "pending_approvals":
            posted.append(body)
            return [{"id": "ap-1", **body}]
        return []

    # Mock the I/O seam, not propose itself, so the real signature is exercised.
    monkeypatch.setattr(governance, "_pg_request", fake_sb)
    monkeypatch.setattr(governance, "_agent_id", "test-org")

    r = await chapter_agent.register_member(_reg(agent_id="dave", public_key="Zm9v"))
    assert r.get("status") == "pending_approval"
    assert r.get("approval_id") == "ap-1"
    assert "dave" not in chapter_agent.members  # NO member created

    assert len(posted) == 1  # the real propose ran and wrote exactly one row
    row = posted[0]
    assert row["kind"] == "member_admission"
    assert row["proposer_agent_id"] == "dave"  # the agent proposes its own admission
    assert row["payload"]["agent_id"] == "dave"
    assert row["payload"]["public_key"] == "Zm9v"  # claimed key stashed for materialization


@pytest.mark.asyncio
async def test_approval_materializes_member_on_leader_approve(monkeypatch):
    """approve of a member_admission → the member is created (gate bypassed)."""
    monkeypatch.setattr(chapter_agent, "_load_org_config", lambda: {"join_policy": "approval"})
    import governance

    async def fake_approve(approval_id, approver, *, pre_authorized=False):
        # The handler passes the VERIFIED caller + pre_authorized=True (it has
        # already role-checked), never the body-claimed approver.
        assert pre_authorized is True
        return {
            "id": approval_id,
            "kind": "member_admission",
            "payload": {"agent_id": "erin", "name": "Erin", "public_key": "", "origin": "sovereign", "skills": ["go"]},
        }

    monkeypatch.setattr(governance, "approve", fake_approve)

    async def _authz(request, *, allowed_roles):
        return True, {"path": "did_key", "agent_id": "leader-1", "chapter_role": "leader"}, None

    monkeypatch.setattr(chapter_agent, "_authorize_role", _authz)

    class _Req:
        headers: dict = {}

    Decision = chapter_agent.ApprovalDecision
    await chapter_agent.approve_approval("ap-2", Decision(), _Req())
    await asyncio.sleep(0)
    assert "erin" in chapter_agent.members  # materialized


@pytest.mark.asyncio
async def test_set_join_policy_validates_and_persists(monkeypatch):
    """Admin can change the policy; invalid values are rejected; get reflects it."""
    saved = {}
    monkeypatch.setattr(chapter_agent, "_load_org_config", lambda: dict(saved))
    monkeypatch.setattr(chapter_agent, "_save_org_config", lambda c: saved.update(c))

    async def _authz(request, *, allowed_roles):
        return True, {"path": "did_key", "agent_id": "ada", "chapter_role": "admin"}, None

    monkeypatch.setattr(chapter_agent, "_authorize_role", _authz)

    class _Req:
        headers: dict = {}

    bad = await chapter_agent.set_join_policy(chapter_agent.JoinPolicyRequest(policy="nonsense"), _Req())
    assert _status(bad) == 400
    ok = await chapter_agent.set_join_policy(chapter_agent.JoinPolicyRequest(policy="invite"), _Req())
    assert ok == {"join_policy": "invite"}
    assert (await chapter_agent.get_join_policy()) == {"join_policy": "invite"}
