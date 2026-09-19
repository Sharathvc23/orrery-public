"""Tests for the did:key + chapter_role='admin' admin auth path.

These complement chapter/tests/test_admin.py (which covers the bearer-
token break-glass path) by exercising the *primary* admin auth path:
a sovereign member with chapter_role='admin' signing requests with
their Ed25519 key.

Coverage:

  HAPPY: signed-by-admin → authorized as did_key path
  AUTHZ: signed-by-non-admin → 403 with informative error
  AUTHZ: signed-by-admin but bad signature → 401 with verify reason
  FALLBACK: no signature, valid bearer → authorized as bearer path
  PRIORITY: signature present + bearer present → signature path wins
  ADVERSARIAL: missing both → 401 with both-paths hint
"""

from __future__ import annotations

import importlib
import os
from unittest.mock import AsyncMock, MagicMock

os.environ.setdefault("AGENT_ID", "test-chapter")
os.environ.setdefault("AGENT_NAME", "Test Chapter")

import pytest


@pytest.fixture
def reset_admin(monkeypatch, tmp_path):
    """Fresh admin module state per test."""
    monkeypatch.delenv("CHAPTER_ADMIN_TOKEN", raising=False)
    monkeypatch.setenv("CHAPTER_HOME", str(tmp_path))
    import admin as admin_mod

    importlib.reload(admin_mod)
    admin_mod.init()
    return admin_mod


def _mock_request(*, method="GET", path="/admin/api/status", body=b"", headers=None):
    """Build a minimal mock that quacks like a FastAPI Request enough for
    _authorize_admin. The helper only touches .headers (dict), .method
    (str), .url.path (str), .body() (coroutine returning bytes)."""
    req = MagicMock()
    req.method = method
    req.url.path = path
    req.headers = dict(headers or {})
    req.body = AsyncMock(return_value=body)
    return req


# ══════════════════════════════════════════════════════════════════════
# Path 1 — did:key signed-by-admin (primary)
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_didkey_admin_authorized(reset_admin, monkeypatch):
    """Member with chapter_role='admin' + valid signature → did_key path."""
    import auth_verify
    import chapter_agent
    import governance

    # Stub auth_verify.verify_request to "succeed for agent_id=alice"
    def fake_verify(body, headers, method="", url_path="", max_age=300):
        return True, "alice", "ok"

    # Stub governance.get_chapter_role to return 'admin' for alice
    async def fake_role(agent_id):
        return "admin" if agent_id == "alice" else "member"

    monkeypatch.setattr(auth_verify, "verify_request", fake_verify)
    monkeypatch.setattr(governance, "get_chapter_role", fake_role)

    request = _mock_request(headers={"X-Agent-Signature": "deadbeef", "X-Agent-ID": "alice"})
    ok, identity, denied = await chapter_agent._authorize_admin(request)
    assert ok is True
    assert denied is None
    assert identity == {"path": "did_key", "agent_id": "alice", "chapter_role": "admin"}


@pytest.mark.asyncio
async def test_didkey_signed_but_not_admin_returns_403(reset_admin, monkeypatch):
    """Member signed validly but lacks admin role → 403, NOT 401, with
    a remediation hint so they know how to fix it."""
    import auth_verify
    import chapter_agent
    import governance

    def fake_verify(body, headers, method="", url_path="", max_age=300):
        return True, "bob", "ok"

    async def fake_role(agent_id):
        return "leader"  # not admin

    monkeypatch.setattr(auth_verify, "verify_request", fake_verify)
    monkeypatch.setattr(governance, "get_chapter_role", fake_role)

    request = _mock_request(headers={"X-Agent-Signature": "deadbeef", "X-Agent-ID": "bob"})
    ok, identity, denied = await chapter_agent._authorize_admin(request)
    assert ok is False
    assert identity == {}
    assert denied is not None
    assert denied.status_code == 403
    import json as _json

    body = _json.loads(denied.body.decode())
    assert "admin role required" in body["error"]
    assert "leader" in body["hint"]
    assert "remediation" in body


@pytest.mark.asyncio
async def test_didkey_bad_signature_returns_401_with_reason(reset_admin, monkeypatch):
    """Signature present but verify_request fails → 401 surfaces the reason."""
    import auth_verify
    import chapter_agent

    def fake_verify(body, headers, method="", url_path="", max_age=300):
        return False, "alice", "timestamp_skew_too_large"

    monkeypatch.setattr(auth_verify, "verify_request", fake_verify)

    request = _mock_request(headers={"X-Agent-Signature": "garbage", "X-Agent-ID": "alice"})
    ok, identity, denied = await chapter_agent._authorize_admin(request)
    assert ok is False
    assert denied is not None
    assert denied.status_code == 401
    import json as _json

    body = _json.loads(denied.body.decode())
    assert "X-Agent-Signature verification failed" in body["error"]
    assert body["reason"] == "timestamp_skew_too_large"


# ══════════════════════════════════════════════════════════════════════
# Path 2 — bearer token (fallback)
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_bearer_only_no_signature_authorized(reset_admin):
    """No X-Agent-Signature header, valid X-Admin-Token → bearer path."""
    import chapter_agent

    token = reset_admin.init()[0]
    request = _mock_request(headers={"X-Admin-Token": token})
    ok, identity, denied = await chapter_agent._authorize_admin(request)
    assert ok is True
    assert denied is None
    assert identity == {"path": "bearer"}


@pytest.mark.asyncio
async def test_bearer_only_wrong_token_rejected(reset_admin):
    """Wrong bearer, no signature → 401 with both-paths hint."""
    import chapter_agent

    request = _mock_request(headers={"X-Admin-Token": "wrong-token"})
    ok, _identity, denied = await chapter_agent._authorize_admin(request)
    assert ok is False
    assert denied is not None
    assert denied.status_code == 401
    import json as _json

    body = _json.loads(denied.body.decode())
    assert "X-Agent-Signature" in body["hint"]
    assert "X-Admin-Token" in body["hint"]


# ══════════════════════════════════════════════════════════════════════
# Path priority — signature wins when both present
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_signature_takes_precedence_over_bearer(reset_admin, monkeypatch):
    """If both X-Agent-Signature and X-Admin-Token are present, the
    signature path is tried first. If it succeeds, identity reflects
    the signing agent (did_key path), not bearer — important for audit."""
    import auth_verify
    import chapter_agent
    import governance

    def fake_verify(body, headers, method="", url_path="", max_age=300):
        return True, "alice", "ok"

    async def fake_role(agent_id):
        return "admin"

    monkeypatch.setattr(auth_verify, "verify_request", fake_verify)
    monkeypatch.setattr(governance, "get_chapter_role", fake_role)

    token = reset_admin.init()[0]
    request = _mock_request(
        headers={
            "X-Agent-Signature": "deadbeef",
            "X-Agent-ID": "alice",
            "X-Admin-Token": token,
        }
    )
    ok, identity, denied = await chapter_agent._authorize_admin(request)
    assert ok is True
    assert denied is None
    # Identity reflects the signing agent, NOT bearer — audit trail
    # tells us WHO took this admin action.
    assert identity["path"] == "did_key"
    assert identity["agent_id"] == "alice"


# ══════════════════════════════════════════════════════════════════════
# Adversarial — neither path supplied
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_no_auth_returns_401_with_both_path_hint(reset_admin):
    """No signature, no bearer → 401 explaining BOTH paths so operators
    pick the right one for their situation."""
    import chapter_agent

    request = _mock_request(headers={})
    ok, _identity, denied = await chapter_agent._authorize_admin(request)
    assert ok is False
    assert denied is not None
    assert denied.status_code == 401
    import json as _json

    body = _json.loads(denied.body.decode())
    hint = body["hint"]
    # Must mention both paths so the operator knows their options
    assert "X-Agent-Signature" in hint
    assert "X-Admin-Token" in hint
    assert "chapter_role=admin" in hint
