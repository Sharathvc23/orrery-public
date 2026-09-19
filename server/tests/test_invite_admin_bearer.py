"""the invite POST endpoints must accept the X-Admin-Token bearer.

The global mutating-request gate (requires_auth + verify_request) only accepted
an Ed25519 X-Agent-Signature, so a valid X-Admin-Token bearer was 401'd BEFORE
create_invite/revoke_invite's own (bearer-aware) _authorize_role could run —
even though GET /api/invites (not globally gated) accepted the same token. The
fix lets a VALID admin bearer through the gate for these two POSTs only; the
handler still authorizes, and unauthenticated requests still 401.
"""

from __future__ import annotations

import importlib
import sys

import pytest
from fastapi.testclient import TestClient

_TOKEN = "a" * 64


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("AGENT_ID", "TEST-invite-org")
    monkeypatch.setenv("AGENT_NAME", "Test Invite Org")
    monkeypatch.setenv("XAI_API_KEY", "x")
    sys.modules.pop("chapter_agent", None)
    mod = importlib.import_module("chapter_agent")
    mod._rate_limit_store.clear()

    # Accept exactly _TOKEN as the admin bearer — monkeypatch the verifier (no
    # module reload, so nothing leaks into other tests). check_admin_token_header
    # imports `admin` lazily and calls verify_admin_token, so this is the seam.
    import admin as admin_mod

    monkeypatch.setattr(admin_mod, "verify_admin_token", lambda t: t == _TOKEN)

    async def fake_generate(created_by, *, max_uses=1, ttl_days=7):
        return {"token": "INV-TOKEN", "expires_at": "2026-07-01T00:00:00Z", "max_uses": max_uses}

    async def fake_revoke(token):
        return True

    monkeypatch.setattr(mod.invites_mod, "generate", fake_generate)
    monkeypatch.setattr(mod.invites_mod, "revoke", fake_revoke)
    return TestClient(mod.app)


# ── the bug: bearer must pass the global gate on the invite POSTs ─────


def test_generate_with_valid_bearer_200(client):
    r = client.post("/api/invites", json={}, headers={"X-Admin-Token": _TOKEN})
    assert r.status_code == 200, r.text
    assert r.json()["token"] == "INV-TOKEN"


def test_revoke_with_valid_bearer_200(client):
    r = client.post("/api/invites/INV-TOKEN/revoke", headers={"X-Admin-Token": _TOKEN})
    assert r.status_code == 200, r.text
    assert r.json()["revoked"] is True


# ── unauthenticated / bad bearer still 401 (no regression) ───────────


def test_generate_no_auth_still_401(client):
    assert client.post("/api/invites", json={}).status_code == 401


def test_generate_bad_bearer_still_401(client):
    assert client.post("/api/invites", json={}, headers={"X-Admin-Token": "b" * 64}).status_code == 401


def test_revoke_no_auth_still_401(client):
    assert client.post("/api/invites/INV-TOKEN/revoke").status_code == 401


# ── classification unit: only the invite POSTs are bearer-eligible ───


def test_is_admin_bearer_path_scope():
    import auth_verify

    assert auth_verify.is_admin_bearer_path("POST", "/api/invites") is True
    assert auth_verify.is_admin_bearer_path("POST", "/api/invites/") is True
    assert auth_verify.is_admin_bearer_path("POST", "/api/invites/abc123/revoke") is True
    # governance-sensitive admin POSTs whose handlers accept a bearer
    assert auth_verify.is_admin_bearer_path("POST", "/api/org/join-policy") is True
    assert auth_verify.is_admin_bearer_path("POST", "/api/approvals/ap-1/approve") is True
    assert auth_verify.is_admin_bearer_path("POST", "/api/approvals/ap-1/reject") is True
    # not other methods / paths
    assert auth_verify.is_admin_bearer_path("GET", "/api/invites") is False
    assert auth_verify.is_admin_bearer_path("GET", "/api/org/join-policy") is False
    assert auth_verify.is_admin_bearer_path("POST", "/api/members") is False
    assert auth_verify.is_admin_bearer_path("POST", "/api/approvals/ap-1/materialize") is False
    assert auth_verify.is_admin_bearer_path("POST", "/api/invites/abc/consume") is False
