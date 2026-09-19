"""Tests for the graceful admin gate on admin-aware surfaces (milestone 1b).

Classification: ADVERSARIAL / EDGE / HAPPY.

The gate is *additive*: admin-aware surfaces (approvals, authority) serve the
redacted safe-projection floor to everyone, and embed full operator
detail ONLY when the request carries a valid X-Admin-Token. This file proves:

  - the floor holds for no-token / wrong-token (LEAK-CANARY strings absent), and
  - full detail appears ONLY with a valid token, and
  - an authed full-detail render is never cached + served to a later anon caller.

Reuses the LEAK-CANARY fixture convention from the redaction tests:
if a canary appears in the no-token response, the floor has regressed; if it's
absent from the with-token response, the gate over-redacted.
"""

from __future__ import annotations

import os

os.environ.setdefault("AGENT_ID", "test-gate-chapter")
os.environ.setdefault("AGENT_NAME", "Test Gate Chapter")
os.environ.setdefault("XAI_API_KEY", "test-xai-key")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

import chapter_agent  # noqa: E402


@pytest.fixture
def client():
    return TestClient(chapter_agent.app)


@pytest.fixture
def admin_token(monkeypatch):
    monkeypatch.setenv("CHAPTER_ADMIN_TOKEN", "test-token-abc123")
    import admin as admin_mod

    admin_mod._admin_token = "test-token-abc123"  # noqa: S105 — test stub
    return "test-token-abc123"


@pytest.fixture
def stub_governance(monkeypatch):
    """Approvals data with LEAK-CANARY identifiers in the sensitive fields."""
    import governance

    async def fake_get_dashboard():
        return {
            "pending_count": 1,
            "expiring_soon_count": 0,
            "approved_last_24h": 0,
            "rejected_last_24h": 0,
        }

    async def fake_list_pending(*, kind=None, limit=50):
        return [
            {
                "id": "appr-uuid-001",
                "kind": "introduction",
                "confidence": 0.9,
                "created_at": "2026-05-23T08:00:00Z",
                "payload": {
                    "member_a": {"name": "LEAK-CANARY-MEMBER-A"},
                    "member_b": {"name": "LEAK-CANARY-MEMBER-B"},
                    "reason": "LEAK-CANARY-INTRO-REASON",
                },
            }
        ]

    monkeypatch.setattr(governance, "get_dashboard", fake_get_dashboard)
    monkeypatch.setattr(governance, "list_pending", fake_list_pending)


@pytest.fixture
def stub_authority(monkeypatch):
    """Authority scope with LEAK-CANARY action kinds + constraints."""
    import authority as authority_mod

    async def fake_list_scope_for(agent_id):
        return [
            {
                "action_kind": "LEAK-CANARY-ACTION-POST",
                "allowed": True,
                "constraints": {"LEAK-CANARY-CONSTRAINT": "v"},
            },
            {"action_kind": "LEAK-CANARY-ACTION-EVENT", "allowed": False, "constraints": {}},
        ]

    monkeypatch.setattr(authority_mod, "list_scope_for", fake_list_scope_for)


def _body(d):
    import json

    return json.dumps(d, default=str)


# ══════════════════════════════════════════════════════════════════════
# ADVERSARIAL — the floor must hold without a valid token
# ══════════════════════════════════════════════════════════════════════


def test_ADVERSARIAL_approvals_no_token_keeps_floor(client, stub_governance):
    """No token → safe-projection. None of the canary identities leak."""
    resp = client.get("/api/surfaces/approvals")
    assert resp.status_code == 200
    blob = _body(resp.json())
    for canary in (
        "LEAK-CANARY-MEMBER-A",
        "LEAK-CANARY-MEMBER-B",
        "LEAK-CANARY-INTRO-REASON",
    ):
        assert canary not in blob


def test_ADVERSARIAL_approvals_wrong_token_keeps_floor(client, admin_token, stub_governance):
    """A present-but-wrong token must NOT unlock full detail."""
    resp = client.get("/api/surfaces/approvals", headers={"X-Admin-Token": "wrong-token"})
    blob = _body(resp.json())
    assert "LEAK-CANARY-MEMBER-A" not in blob


def test_ADVERSARIAL_authority_no_token_keeps_floor(client, stub_authority):
    """No token → counts only; per-action ACL stays redacted."""
    resp = client.get("/api/surfaces/authority?target=did:key:zVictim")
    blob = _body(resp.json())
    assert "LEAK-CANARY-ACTION-POST" not in blob
    assert "LEAK-CANARY-CONSTRAINT" not in blob


def test_ADVERSARIAL_authority_wrong_token_keeps_floor(client, admin_token, stub_authority):
    resp = client.get(
        "/api/surfaces/authority?target=did:key:zVictim",
        headers={"X-Admin-Token": "nope"},
    )
    blob = _body(resp.json())
    assert "LEAK-CANARY-ACTION-POST" not in blob


# ══════════════════════════════════════════════════════════════════════
# EDGE — cache isolation
# ══════════════════════════════════════════════════════════════════════


def test_EDGE_authed_render_does_not_poison_anon_call(client, admin_token, stub_governance):
    """An admin (full-detail) fetch must not cache a full-detail surface that a
    later anonymous caller then receives. approvals + authority are in
    _UNCACHED_SURFACES specifically to guarantee this."""
    # Admin call first — full detail.
    authed = client.get("/api/surfaces/approvals", headers={"X-Admin-Token": admin_token})
    assert "LEAK-CANARY-MEMBER-A" in _body(authed.json())
    # Immediately follow with an anonymous call — must be the floor again.
    anon = client.get("/api/surfaces/approvals")
    assert "LEAK-CANARY-MEMBER-A" not in _body(anon.json())


# ══════════════════════════════════════════════════════════════════════
# HAPPY — valid token unlocks full detail
# ══════════════════════════════════════════════════════════════════════


def test_HAPPY_approvals_valid_token_shows_full_detail(client, admin_token, stub_governance):
    """Valid token → member names + reason re-embedded."""
    resp = client.get("/api/surfaces/approvals", headers={"X-Admin-Token": admin_token})
    assert resp.status_code == 200
    blob = _body(resp.json())
    assert "LEAK-CANARY-MEMBER-A" in blob
    assert "LEAK-CANARY-MEMBER-B" in blob
    assert "LEAK-CANARY-INTRO-REASON" in blob


def test_HAPPY_authority_valid_token_shows_per_action_detail(client, admin_token, stub_authority):
    """Valid token → per-action_kind cards + constraint values appear."""
    resp = client.get(
        "/api/surfaces/authority?target=did:key:zSelf",
        headers={"X-Admin-Token": admin_token},
    )
    blob = _body(resp.json())
    assert "LEAK-CANARY-ACTION-POST" in blob
    assert "LEAK-CANARY-ACTION-EVENT" in blob
    assert "LEAK-CANARY-CONSTRAINT" in blob


def test_HAPPY_floor_still_functional_no_token(client, stub_governance):
    """The no-token approvals surface still renders its aggregate stats +
    action scaffolding (the floor is a working page, not an error)."""
    resp = client.get("/api/surfaces/approvals")
    assert resp.status_code == 200
    blob = _body(resp.json())
    assert "Approval Queue" in blob
    assert "appr-uuid-001" in blob  # item id still threaded to buttons
