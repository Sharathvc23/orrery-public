"""That change — invites module: generate / consume (atomic RPC) / list / revoke."""

from __future__ import annotations

import pytest

import invites


@pytest.fixture
def fake_sb():
    calls = []

    async def _sb(method, table, *, params=None, body=None, **k):
        calls.append((method, table, params, body))
        if table == "rpc/consume_org_invite":
            # Echo a configurable result set on the fixture.
            return _sb.consume_result
        if method == "POST":
            return [{"ok": True}]
        if method == "PATCH":
            return [{"token": (params or {}).get("token")}]
        if method == "GET":
            return [{"token": "t1", "uses": 0, "max_uses": 1}]
        return []

    _sb.consume_result = [True]
    invites.init(_sb)
    return _sb, calls


@pytest.mark.asyncio
async def test_generate_returns_unguessable_token_and_ttl(fake_sb):
    inv = await invites.generate("leader-1", max_uses=1, ttl_days=7)
    assert inv and inv["max_uses"] == 1
    assert len(inv["token"]) >= 40  # secrets.token_urlsafe(32)
    assert "expires_at" in inv


@pytest.mark.asyncio
async def test_consume_calls_atomic_rpc_and_returns_its_verdict(fake_sb):
    sb, calls = fake_sb
    sb.consume_result = [True]
    assert await invites.consume("tok", agent_id="alice") is True
    sb.consume_result = [False]
    assert await invites.consume("tok", agent_id="alice") is False
    # empty token never hits the store
    assert await invites.consume("", agent_id="alice") is False
    assert any(t == "rpc/consume_org_invite" for _, t, _, _ in calls)


@pytest.mark.asyncio
async def test_consume_handles_scalar_and_wrapped_rpc_shapes(fake_sb):
    sb, _ = fake_sb
    for shape, expected in ([True], True), (True, True), ([{"consume_org_invite": True}], True), ([False], False):
        sb.consume_result = shape
        assert await invites.consume("tok", agent_id="a") is expected


@pytest.mark.asyncio
async def test_revoke(fake_sb):
    assert await invites.revoke("t1") is True
