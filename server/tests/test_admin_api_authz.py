"""AUTHZ: the /api/admin/* Tier-1 endpoints require admin authorization.

These endpoints (trust/decay-sweep, trust/drift) sit on the `/api/admin/*`
prefix rather than the handler-authenticated `/admin/api/*` prefix, so they
previously ran for ANY signed member — a privilege-escalation hole (a member
could sweep the trust graph). Each now calls `_authorize_admin`. This module
prosecutes that gate at the handler level:

  ADVERSARIAL  no credentials            → 401, and NO side effects (supabase untouched)
  AUTHZ        signed but non-admin member → 403 (the exact escalation vector)
  HAPPY        admin                      → passes the gate (not 401/403)

Mirrors the _authorize_admin stubbing style of test_admin_didkey_path.py.
"""

from __future__ import annotations

import importlib
import os
import sys
from unittest.mock import AsyncMock, MagicMock

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ.setdefault("AGENT_ID", "test-chapter")
os.environ.setdefault("AGENT_NAME", "Test Chapter")
os.environ.setdefault("XAI_API_KEY", "test-key")

import chapter_agent  # noqa: E402


@pytest.fixture
def reset_admin(monkeypatch):
    """Fresh admin module state + a known bearer token for the happy path."""
    monkeypatch.setenv("CHAPTER_ADMIN_TOKEN", "f" * 64)
    import admin as admin_mod

    importlib.reload(admin_mod)
    admin_mod.init()
    return admin_mod


def _mock_request(*, method="POST", path="/api/admin/x", headers=None):
    req = MagicMock()
    req.method = method
    req.url.path = path
    req.headers = dict(headers or {})
    req.body = AsyncMock(return_value=b"")
    return req


# Each endpoint as a (label, callable(request)) — different arities, one shape.
ENDPOINTS = [
    ("trust_decay_sweep", lambda req: chapter_agent.trust_decay_sweep(req)),
    ("trust_drift_report", lambda req: chapter_agent.trust_drift_report(req)),
]


@pytest.mark.asyncio
@pytest.mark.parametrize("label,call", ENDPOINTS, ids=[e[0] for e in ENDPOINTS])
async def test_ADVERSARIAL_no_credentials_rejected_before_any_work(label, call, reset_admin, monkeypatch):
    """No creds → 401 JSONResponse, and the gate blocks BEFORE touching Postgres."""

    async def _exploded(*a, **k):
        raise AssertionError(f"{label}: pg_request reached despite missing admin auth")

    monkeypatch.setattr(chapter_agent, "pg_request", _exploded)

    resp = await call(_mock_request())
    assert getattr(resp, "status_code", None) == 401


@pytest.mark.asyncio
@pytest.mark.parametrize("label,call", ENDPOINTS, ids=[e[0] for e in ENDPOINTS])
async def test_AUTHZ_signed_but_non_admin_rejected(label, call, reset_admin, monkeypatch):
    """A validly-signed NON-admin member is rejected (403) — the escalation vector."""
    import auth_verify
    import governance

    def fake_verify(body, headers, method="", url_path="", max_age=300):
        return True, "mallory", "ok"

    async def fake_role(agent_id):
        return "member"  # signed, valid, but NOT admin

    async def _exploded(*a, **k):
        raise AssertionError(f"{label}: pg_request reached for a non-admin member")

    monkeypatch.setattr(auth_verify, "verify_request", fake_verify)
    monkeypatch.setattr(governance, "get_chapter_role", fake_role)
    monkeypatch.setattr(chapter_agent, "pg_request", _exploded)

    resp = await call(_mock_request(headers={"X-Agent-Signature": "ab", "X-Agent-ID": "mallory"}))
    assert getattr(resp, "status_code", None) == 403


@pytest.mark.asyncio
@pytest.mark.parametrize("label,call", ENDPOINTS, ids=[e[0] for e in ENDPOINTS])
async def test_HAPPY_admin_bearer_passes_the_gate(label, call, reset_admin, monkeypatch):
    """With a valid admin bearer token the gate passes — the handler runs (not 401/403)."""
    import trust_events

    async def fake_supabase(*a, **k):
        return []  # empty corpus → handlers return benign dicts, not a denial

    async def fake_drift():
        return []

    monkeypatch.setattr(chapter_agent, "pg_request", fake_supabase)
    monkeypatch.setattr(trust_events, "detect_score_drift", fake_drift)

    resp = await call(_mock_request(headers={"X-Admin-Token": "f" * 64}))
    # Passed the gate iff it is not one of the denial responses.
    assert getattr(resp, "status_code", None) not in (401, 403)
