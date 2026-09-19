"""Auth-scoping for the /api/settings/* routes (W11 hardening).

A member's settings bag (llm/voice/channels/trust/privacy) is private. The
middleware requires a valid signature on these routes (GET via the
``/api/settings/`` prefix, POSTs via the default mutation rule) and the handler
binds the target id to the verified caller — so a signed member can only
read/patch/reset their OWN settings, never another agent's by passing a
different id (the IDOR the raw handlers allowed).

Classification: HAPPY / ADVERSARIAL.
"""

import asyncio
from unittest.mock import MagicMock

import pytest

import auth_verify
import chapter_agent
import settings as settings_mod
from chapter_agent import SettingsUpdateRequest


def _req(caller: str, *, headers: dict | None = None):
    req = MagicMock()
    req.state.agent_id = caller
    req.headers = headers or {}
    return req


class _FakePg:
    async def __call__(self, method, table, params=None, body=None):
        # get_settings/update_settings query returns rows; empty → DEFAULTS.
        return []


@pytest.fixture(autouse=True)
def _init_settings():
    prev = settings_mod._pg_request
    settings_mod.init(_FakePg())
    yield
    settings_mod._pg_request = prev


# ── the GET is auth-gated at the middleware layer ──


def test_settings_get_prefix_requires_auth():
    prefixes = auth_verify.REQUIRE_AUTH_GET_PREFIXES
    assert "/api/settings/" in prefixes
    assert any("/api/settings/alice".startswith(p) for p in prefixes)


# ── ADVERSARIAL: a signed caller cannot touch another agent's settings ──


def test_settings_get_rejects_cross_agent():
    with pytest.raises(chapter_agent.HTTPException) as e:
        asyncio.run(chapter_agent.settings_get("alice", _req("bob")))
    assert e.value.status_code == 403


def test_settings_update_rejects_cross_agent():
    body = SettingsUpdateRequest(agent_id="alice", patch={"privacy": {"x": 1}})
    with pytest.raises(chapter_agent.HTTPException) as e:
        asyncio.run(chapter_agent.settings_update(body, _req("bob")))
    assert e.value.status_code == 403


def test_settings_reset_rejects_cross_agent():
    with pytest.raises(chapter_agent.HTTPException) as e:
        asyncio.run(chapter_agent.settings_reset("alice", _req("bob")))
    assert e.value.status_code == 403


def test_settings_update_rejects_unauthenticated():
    """No verified caller (empty request.state.agent_id) → 403, even though the
    body claims to be alice."""
    body = SettingsUpdateRequest(agent_id="alice", patch={"privacy": {"x": 1}})
    with pytest.raises(chapter_agent.HTTPException) as e:
        asyncio.run(chapter_agent.settings_update(body, _req("")))
    assert e.value.status_code == 403


# ── HAPPY: the agent (or an admin) reaches its own settings ──


def test_settings_get_allows_self():
    out = asyncio.run(chapter_agent.settings_get("alice", _req("alice")))
    assert out["agent_id"] == "alice"
    assert "settings" in out


def test_settings_update_allows_self():
    body = SettingsUpdateRequest(agent_id="alice", patch={"privacy": {"share": False}})
    out = asyncio.run(chapter_agent.settings_update(body, _req("alice")))
    assert out["agent_id"] == "alice"


def test_settings_get_allows_admin(monkeypatch):
    monkeypatch.setattr(auth_verify, "check_admin_token_header", lambda h: True)
    out = asyncio.run(chapter_agent.settings_get("alice", _req("bob")))
    assert out["agent_id"] == "alice"
