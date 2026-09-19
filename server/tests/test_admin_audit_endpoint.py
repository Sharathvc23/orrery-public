"""Tests for /admin/api/audit + /admin/api/audit/verify (A2).

Classification: HAPPY / EDGE / FAILURE / AUTHZ.

Surfaces the chapter_audit_events ledger to operators without requiring
direct Postgres access. Before this endpoint, operators had to query
Postgres by hand to inspect their own audit trail.
"""

from __future__ import annotations

import os

os.environ.setdefault("AGENT_ID", "test-audit-chapter")
os.environ.setdefault("AGENT_NAME", "Test Audit Chapter")
os.environ.setdefault("XAI_API_KEY", "test-xai-key")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

import chapter_agent  # noqa: E402


@pytest.fixture
def client():
    return TestClient(chapter_agent.app)


@pytest.fixture
def admin_token(monkeypatch):
    """Set a known admin token + reset the cached value."""
    monkeypatch.setenv("CHAPTER_ADMIN_TOKEN", "test-token-abc123")
    import admin as admin_mod

    admin_mod._admin_token = "test-token-abc123"  # noqa: S105 — test stub, not a real secret
    return "test-token-abc123"


@pytest.fixture
def stub_audit_events(monkeypatch):
    """Replace chapter_audit.list_events + verify_chain with controllable stubs."""
    events_data = [
        {
            "id": "audit-1",
            "occurred_at": "2026-05-23T08:00:00Z",
            "action": "admin.role.change",
            "actor_agent_id": "sharath",
            "target_type": "agent",
            "target_id": "ethan-kim-42",
            "outcome": "ok",
            "detail": {
                "role_before": "member",
                "role_after": "leader",
                "compliance_credential": {
                    "type": ["VerifiableCredential", "ComplianceCredential"],
                    "credentialSubject": {"rule_id": "nist-800-171:3.1.5"},
                },
            },
            "prev_hash": "sha256:abc",
            "hash": "sha256:def",
        },
        {
            "id": "audit-2",
            "occurred_at": "2026-05-23T09:00:00Z",
            "action": "admin.dsar.delete",
            "actor_agent_id": "sharath",
            "target_type": "data_subject",
            "target_id": "did:key:zSubject",
            "outcome": "ok",
            "detail": {"total_deleted": 5},
            "prev_hash": "sha256:def",
            "hash": "sha256:ghi",
        },
    ]

    import chapter_audit

    async def fake_list_events(*, chapter_id, action=None, actor_agent_id=None, since=None, limit=100):
        out = list(events_data)
        if action:
            out = [e for e in out if action in e["action"]]
        if actor_agent_id:
            out = [e for e in out if e["actor_agent_id"] == actor_agent_id]
        if since:
            out = [e for e in out if e["occurred_at"] >= since]
        return out[:limit]

    async def fake_verify_chain(*, chapter_id):
        return {"valid": True, "events_checked": len(events_data), "broken_at": None}

    monkeypatch.setattr(chapter_audit, "list_events", fake_list_events)
    monkeypatch.setattr(chapter_audit, "verify_chain", fake_verify_chain)
    return events_data


# ══════════════════════════════════════════════════════════════════════
# /admin/api/audit — HAPPY
# ══════════════════════════════════════════════════════════════════════


def test_HAPPY_admin_audit_returns_events(client, admin_token, stub_audit_events):
    resp = client.get("/admin/api/audit", headers={"X-Admin-Token": admin_token})
    assert resp.status_code == 200
    body = resp.json()
    assert body["total_returned"] == 2
    assert body["limit"] == 100
    assert len(body["events"]) == 2
    # First event has the compliance credential from PR
    assert body["events"][0]["detail"]["compliance_credential"]["credentialSubject"]["rule_id"] == "nist-800-171:3.1.5"


def test_HAPPY_admin_audit_filter_by_action(client, admin_token, stub_audit_events):
    resp = client.get(
        "/admin/api/audit?action=admin.dsar",
        headers={"X-Admin-Token": admin_token},
    )
    body = resp.json()
    assert body["total_returned"] == 1
    assert body["events"][0]["action"] == "admin.dsar.delete"
    assert body["filters"]["action"] == "admin.dsar"


def test_HAPPY_admin_audit_filter_by_actor(client, admin_token, stub_audit_events):
    resp = client.get(
        "/admin/api/audit?actor_agent_id=sharath",
        headers={"X-Admin-Token": admin_token},
    )
    body = resp.json()
    assert body["total_returned"] == 2  # both events from sharath


def test_HAPPY_admin_audit_filter_by_since(client, admin_token, stub_audit_events):
    resp = client.get(
        "/admin/api/audit?since=2026-05-23T08:30:00Z",
        headers={"X-Admin-Token": admin_token},
    )
    body = resp.json()
    assert body["total_returned"] == 1
    assert body["events"][0]["occurred_at"] == "2026-05-23T09:00:00Z"


def test_HAPPY_limit_clamps_to_1000(client, admin_token, stub_audit_events):
    """Request limit=99999 → capped at 1000."""
    resp = client.get("/admin/api/audit?limit=99999", headers={"X-Admin-Token": admin_token})
    body = resp.json()
    assert body["limit"] == 1000


def test_EDGE_limit_minimum_clamps_to_1(client, admin_token, stub_audit_events):
    """limit=0 → 1 (no-zero-rows)."""
    resp = client.get("/admin/api/audit?limit=0", headers={"X-Admin-Token": admin_token})
    body = resp.json()
    assert body["limit"] == 1


# ══════════════════════════════════════════════════════════════════════
# /admin/api/audit/verify — HAPPY + FAILURE
# ══════════════════════════════════════════════════════════════════════


def test_HAPPY_admin_audit_verify_returns_chain_status(client, admin_token, stub_audit_events):
    resp = client.get("/admin/api/audit/verify", headers={"X-Admin-Token": admin_token})
    assert resp.status_code == 200
    body = resp.json()
    assert body["valid"] is True
    assert body["events_checked"] == 2
    assert body["broken_at"] is None


def test_FAILURE_chain_verify_supabase_error_returns_503(client, admin_token, monkeypatch):
    """If verify_chain raises, return 503 with error detail (not 500)."""
    import chapter_audit

    async def boom(**_kwargs):
        raise RuntimeError("supabase timeout")

    monkeypatch.setattr(chapter_audit, "verify_chain", boom)

    resp = client.get("/admin/api/audit/verify", headers={"X-Admin-Token": admin_token})
    assert resp.status_code == 503
    body = resp.json()
    assert "supabase timeout" in body["detail"]


def test_FAILURE_audit_list_supabase_error_returns_503(client, admin_token, monkeypatch):
    import chapter_audit

    async def boom(**_kwargs):
        raise RuntimeError("network unreachable")

    monkeypatch.setattr(chapter_audit, "list_events", boom)

    resp = client.get("/admin/api/audit", headers={"X-Admin-Token": admin_token})
    assert resp.status_code == 503
    assert "network unreachable" in resp.json()["detail"]


# ══════════════════════════════════════════════════════════════════════
# AUTHZ — admin gating
# ══════════════════════════════════════════════════════════════════════


def test_AUTHZ_admin_audit_requires_admin(client, stub_audit_events):
    resp = client.get("/admin/api/audit")
    assert resp.status_code == 401


def test_AUTHZ_admin_audit_verify_requires_admin(client, stub_audit_events):
    resp = client.get("/admin/api/audit/verify")
    assert resp.status_code == 401


def test_AUTHZ_admin_audit_rejects_wrong_token(client, admin_token, stub_audit_events):
    resp = client.get(
        "/admin/api/audit",
        headers={"X-Admin-Token": "wrong-token"},
    )
    assert resp.status_code == 401
