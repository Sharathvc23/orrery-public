"""Tests for E1 (audit log) + E2 (last-admin protection) + E3 (key revocation).

Classification: HAPPY / EDGE / AUTHZ / ADVERSARIAL

The three features bundle together because they share state (admin
endpoints) and infrastructure (the audit log writes to the same
chapter_audit primitive that other admin actions already use).
"""

from __future__ import annotations

import os
import sys

os.environ.setdefault("AGENT_ID", "test-hardening-chapter")
os.environ.setdefault("AGENT_NAME", "Test Hardening Chapter")

import pytest
from fastapi.testclient import TestClient

from tests._admin_fixtures import (
    register_test_admin_member,
    register_test_regular_member,
    reset_chapter_agent_module,
)


@pytest.fixture
def chapter_with_admin(monkeypatch):
    """Spin up a chapter with a known bearer token + alice (admin) and
    bob (member). Stubs pg_request + audit + governance role
    lookup so the endpoint logic can run in tests."""
    token = "c" * 64
    chapter_agent_mod = reset_chapter_agent_module(monkeypatch, chapter_admin_token=token)
    sys.modules.pop("admin", None)
    import admin as admin_mod

    admin_mod.init()
    assert admin_mod.verify_admin_token(token)

    chapter_agent_mod.members.clear()
    alice = register_test_admin_member(chapter_agent_mod)
    bob = register_test_regular_member(chapter_agent_mod)

    # Role map: alice=admin (only one), bob=member
    role_map = {alice["agent_id"]: "admin", bob["agent_id"]: "member"}
    # Audit log capture
    captured_audit: list[dict] = []

    async def fake_supabase(method, table, params=None, body=None):
        t = table.split("?")[0]
        if t == "agents" and method == "GET":
            # Filter on agent_id
            if (params or {}).get("agent_id", "").startswith("eq."):
                wanted = params["agent_id"][3:]
                if wanted in role_map:
                    return [{"chapter_role": role_map[wanted], "agent_id": wanted}]
                return []
            # Filter on chapter_role
            if (params or {}).get("chapter_role") == "eq.admin":
                return [{"agent_id": aid} for aid, r in role_map.items() if r == "admin"]
            return []
        if t == "agents" and method == "PATCH":
            # Check both URL (?agent_id=eq.X) and params dict
            target = ""
            spec = table.split("?", 1)[1] if "?" in table else ""
            for kv in spec.split("&"):
                if kv.startswith("agent_id=eq."):
                    target = kv[len("agent_id=eq.") :]
            if not target and (params or {}).get("agent_id", "").startswith("eq."):
                target = params["agent_id"][3:]
            if target:
                if isinstance(body, dict) and "chapter_role" in body:
                    role_map[target] = body["chapter_role"]
                return [{"agent_id": target, **(body or {})}]
            return []
        if t == "agents" and method == "DELETE":
            target = ""
            spec = table.split("?", 1)[1] if "?" in table else ""
            for kv in spec.split("&"):
                if kv.startswith("agent_id=eq."):
                    target = kv[len("agent_id=eq.") :]
            if not target and (params or {}).get("agent_id", "").startswith("eq."):
                target = params["agent_id"][3:]
            if target:
                role_map.pop(target, None)
            return []
        if t == "chapter_audit_events":
            if method == "GET":
                return []  # No prior events
            if method == "POST":
                captured_audit.append(dict(body or {}))
                return [body]
        return None

    monkeypatch.setattr(chapter_agent_mod, "pg_request", fake_supabase)
    import governance

    monkeypatch.setattr(governance, "_pg_request", fake_supabase)
    import chapter_audit

    chapter_audit.init(fake_supabase)

    client = TestClient(chapter_agent_mod.app)
    return {
        "mod": chapter_agent_mod,
        "token": token,
        "client": client,
        "alice": alice,
        "bob": bob,
        "role_map": role_map,
        "audit": captured_audit,
    }


# ══════════════════════════════════════════════════════════════════════
# E2 — Last-admin protection
# ══════════════════════════════════════════════════════════════════════


def test_E2_signed_demote_last_admin_returns_409(chapter_with_admin):
    """Alice is the only admin. Demoting her via signed path → 409."""
    c = chapter_with_admin
    headers = c["alice"]["signer"](
        method="POST",
        url_path=f"/admin/api/members/{c['alice']['agent_id']}/role",
        body='{"role":"leader"}',
    )
    headers["Content-Type"] = "application/json"
    r = c["client"].post(
        f"/admin/api/members/{c['alice']['agent_id']}/role",
        headers=headers,
        content='{"role":"leader"}',
    )
    assert r.status_code == 409, r.text
    body = r.json()
    assert "would leave no admin" in body["error"]
    assert "force=true" in body["hint"].lower()
    # Role unchanged
    assert c["role_map"][c["alice"]["agent_id"]] == "admin"


def test_E2_bearer_force_overrides_last_admin_protection(chapter_with_admin):
    """Bearer + ?force=true can demote the last admin (break-glass)."""
    c = chapter_with_admin
    r = c["client"].post(
        f"/admin/api/members/{c['alice']['agent_id']}/role?force=true",
        headers={"X-Admin-Token": c["token"], "Content-Type": "application/json"},
        json={"role": "leader"},
    )
    assert r.status_code == 200, r.text
    assert c["role_map"][c["alice"]["agent_id"]] == "leader"


def test_E2_bearer_without_force_still_refuses(chapter_with_admin):
    """Bearer without ?force=true gets the same 409 — force is opt-in."""
    c = chapter_with_admin
    r = c["client"].post(
        f"/admin/api/members/{c['alice']['agent_id']}/role",
        headers={"X-Admin-Token": c["token"], "Content-Type": "application/json"},
        json={"role": "leader"},
    )
    assert r.status_code == 409
    assert c["role_map"][c["alice"]["agent_id"]] == "admin"


def test_E2_promoting_non_admin_to_admin_not_blocked(chapter_with_admin):
    """Last-admin check only triggers on DEMOTION away from admin —
    promoting bob to admin is fine."""
    c = chapter_with_admin
    r = c["client"].post(
        f"/admin/api/members/{c['bob']['agent_id']}/role",
        headers={"X-Admin-Token": c["token"], "Content-Type": "application/json"},
        json={"role": "admin"},
    )
    assert r.status_code == 200
    assert c["role_map"][c["bob"]["agent_id"]] == "admin"


def test_E2_demote_when_multiple_admins_is_fine(chapter_with_admin):
    """With 2 admins, demoting one is fine (one still remains)."""
    c = chapter_with_admin
    # Promote bob first → 2 admins
    c["role_map"][c["bob"]["agent_id"]] = "admin"
    # Demote alice → bob is still admin → should succeed
    r = c["client"].post(
        f"/admin/api/members/{c['alice']['agent_id']}/role",
        headers={"X-Admin-Token": c["token"], "Content-Type": "application/json"},
        json={"role": "leader"},
    )
    assert r.status_code == 200
    assert c["role_map"][c["alice"]["agent_id"]] == "leader"


def test_E2_remove_last_admin_via_signed_returns_409(chapter_with_admin):
    """DELETE /admin/api/members/alice via signed path → 409 (alice is only admin)."""
    c = chapter_with_admin
    headers = c["alice"]["signer"](
        method="DELETE",
        url_path=f"/admin/api/members/{c['alice']['agent_id']}",
        body="",
    )
    r = c["client"].delete(
        f"/admin/api/members/{c['alice']['agent_id']}",
        headers=headers,
    )
    assert r.status_code == 409
    assert "would leave no admin" in r.json()["error"]


# ══════════════════════════════════════════════════════════════════════
# E1 — Audit log
# ══════════════════════════════════════════════════════════════════════


def test_E1_role_change_writes_audit_entry(chapter_with_admin):
    """Every successful role change appends a chapter_audit row."""
    c = chapter_with_admin
    r = c["client"].post(
        f"/admin/api/members/{c['bob']['agent_id']}/role",
        headers={"X-Admin-Token": c["token"], "Content-Type": "application/json"},
        json={"role": "leader"},
    )
    assert r.status_code == 200
    # Audit log should now have a "admin.role.change" entry
    role_changes = [a for a in c["audit"] if a.get("action") == "admin.role.change"]
    assert len(role_changes) == 1
    e = role_changes[0]
    assert e["target_id"] == c["bob"]["agent_id"]
    assert e["detail"]["role_before"] == "member"
    assert e["detail"]["role_after"] == "leader"
    assert e["detail"]["auth_path"] == "bearer"


def test_E1_member_remove_writes_audit_entry(chapter_with_admin):
    """DELETE writes admin.member.remove audit."""
    c = chapter_with_admin
    r = c["client"].delete(
        f"/admin/api/members/{c['bob']['agent_id']}",
        headers={"X-Admin-Token": c["token"]},
    )
    assert r.status_code == 200
    removes = [a for a in c["audit"] if a.get("action") == "admin.member.remove"]
    assert len(removes) == 1
    assert removes[0]["target_id"] == c["bob"]["agent_id"]


def test_E1_audit_records_signed_identity(chapter_with_admin):
    """Signed admin's audit entry carries their agent_id, not 'bearer'."""
    c = chapter_with_admin
    # Promote bob to admin first (using bearer)
    c["client"].post(
        f"/admin/api/members/{c['bob']['agent_id']}/role",
        headers={"X-Admin-Token": c["token"], "Content-Type": "application/json"},
        json={"role": "admin"},
    )
    c["audit"].clear()
    # Now alice (signed) demotes bob
    headers = c["alice"]["signer"](
        method="POST",
        url_path=f"/admin/api/members/{c['bob']['agent_id']}/role",
        body='{"role":"leader"}',
    )
    headers["Content-Type"] = "application/json"
    r = c["client"].post(
        f"/admin/api/members/{c['bob']['agent_id']}/role",
        headers=headers,
        content='{"role":"leader"}',
    )
    assert r.status_code == 200, r.text
    last = [a for a in c["audit"] if a.get("action") == "admin.role.change"][-1]
    assert last["actor_agent_id"] == c["alice"]["agent_id"]
    assert last["detail"]["auth_path"] == "did_key"


# ══════════════════════════════════════════════════════════════════════
# E3 — Key revocation
# ══════════════════════════════════════════════════════════════════════


def test_E3_revoke_clears_in_memory_auth_key(chapter_with_admin):
    """POST /admin/api/keys/revoke/{id} removes the agent from
    auth_verify._agent_keys."""
    import auth_verify

    c = chapter_with_admin
    # Pre-state: bob is in _agent_keys
    assert c["bob"]["agent_id"] in auth_verify._agent_keys

    r = c["client"].post(
        f"/admin/api/keys/revoke/{c['bob']['agent_id']}",
        headers={"X-Admin-Token": c["token"]},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["revoked"] is True
    assert body["agent_id"] == c["bob"]["agent_id"]

    # Post-state: bob is GONE from _agent_keys
    assert c["bob"]["agent_id"] not in auth_verify._agent_keys


def test_E3_revoke_writes_audit_entry(chapter_with_admin):
    """E1 wires E3 into audit log."""
    c = chapter_with_admin
    c["client"].post(
        f"/admin/api/keys/revoke/{c['bob']['agent_id']}",
        headers={"X-Admin-Token": c["token"]},
    )
    revokes = [a for a in c["audit"] if a.get("action") == "admin.key.revoke"]
    assert len(revokes) == 1
    assert revokes[0]["target_id"] == c["bob"]["agent_id"]


def test_E3_revoke_invalid_agent_id_returns_400(chapter_with_admin):
    """sanitize_agent_id rejects path-traversal in the URL path."""
    c = chapter_with_admin
    r = c["client"].post(
        "/admin/api/keys/revoke/../etc/passwd",
        headers={"X-Admin-Token": c["token"]},
    )
    # Either 400 (rejected by sanitize) or 404 (route doesn't match path) —
    # both safe; 500 would be a problem.
    assert r.status_code in (400, 404)


def test_E3_revoke_requires_admin_auth(chapter_with_admin):
    """No auth → 401, not 200."""
    c = chapter_with_admin
    r = c["client"].post(f"/admin/api/keys/revoke/{c['bob']['agent_id']}")
    assert r.status_code == 401
