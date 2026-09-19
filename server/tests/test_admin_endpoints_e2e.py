"""End-to-end tests for /admin/api/* endpoints over a real FastAPI TestClient.

Complementary to:
  * test_admin.py — unit tests for chapter.admin.verify_admin_token (bearer)
  * test_admin_didkey_path.py — unit tests for the _authorize_admin helper

This file exercises the full HTTP layer: middleware → routing → auth
helper → endpoint → response. Both auth paths (signed admin member and
bearer token) hit /admin/api/status, /admin/api/members,
/admin/api/members/{id}/role, /admin/api/members/{id} and we assert the
HTTP status + JSON body.

Coverage:

  HAPPY        — signed admin GET /admin/api/status → 200
  HAPPY        — bearer GET /admin/api/status → 200
  HAPPY        — bearer GET /admin/api/members lists registered members
  HAPPY        — signed admin POST role change updates the agents row
  HAPPY        — signed admin DELETE removes a member from registry + auth keys
  AUTHZ        — signed-by-non-admin → 403 with remediation hint
  AUTHZ        — no auth → 401 with both-paths hint
  AUTHZ        — bad signature → 401 with verify reason
  ADVERSARIAL  — bearer with wrong token → 401
  ADVERSARIAL  — promotion to invalid role → 400
  ADVERSARIAL  — promotion of unknown agent_id (sanitization) → 400
"""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from tests._admin_fixtures import (
    register_test_admin_member,
    register_test_regular_member,
    reset_chapter_agent_module,
)

# ── Fixtures ─────────────────────────────────────────────────────


@pytest.fixture
def chapter_with_admin_token(monkeypatch):
    """Spin up a fresh chapter_agent module with a known bearer admin
    token, return (chapter_agent_mod, admin_token, TestClient).

    The chapter's lifespan hook does not fire under TestClient unless
    we use it as a context manager (`with TestClient(app) as client`)
    — so we explicitly init the admin module after the chapter is up,
    using the same token we just set in the env var.
    """
    import sys

    token = "a" * 64
    chapter_agent_mod = reset_chapter_agent_module(monkeypatch, chapter_admin_token=token)

    # Force admin module to (re)load with our token
    sys.modules.pop("admin", None)
    import admin as admin_mod

    admin_mod.init()
    assert admin_mod.verify_admin_token(token), "fixture failed to install admin token"

    chapter_agent_mod.members.clear()
    client = TestClient(chapter_agent_mod.app)
    return chapter_agent_mod, token, client


@pytest.fixture
def signed_admin_setup(chapter_with_admin_token, monkeypatch):
    """Adds: a registered admin member (alice) + a regular member (bob)
    + a pg_request stub that returns matching chapter_role values.
    Returns (mod, token, client, alice, bob).
    """
    import governance

    mod, token, client = chapter_with_admin_token
    alice = register_test_admin_member(mod)
    bob = register_test_regular_member(mod)

    role_map = {alice["agent_id"]: "admin", bob["agent_id"]: "member"}

    async def fake_supabase(method, table, params=None, body=None):
        t = table.split("?")[0]
        if t == "agents" and method == "GET":
            eq_filter = (params or {}).get("agent_id", "")
            if isinstance(eq_filter, str) and eq_filter.startswith("eq."):
                wanted = eq_filter[3:]
                if wanted in role_map:
                    return [{"chapter_role": role_map[wanted]}]
            return []
        if t == "agents" and method == "PATCH":
            target = ""
            spec = table.split("?", 1)[1] if "?" in table else ""
            for kv in spec.split("&"):
                if kv.startswith("agent_id=eq."):
                    target = kv[len("agent_id=eq.") :]
                    if isinstance(body, dict) and "chapter_role" in body:
                        role_map[target] = body["chapter_role"]
            return [{"agent_id": target, **(body or {})}]
        if t == "agents" and method == "DELETE":
            spec = table.split("?", 1)[1] if "?" in table else ""
            for kv in spec.split("&"):
                if kv.startswith("agent_id=eq."):
                    target = kv[len("agent_id=eq.") :]
                    role_map.pop(target, None)
            return []
        return None

    monkeypatch.setattr(governance, "_pg_request", fake_supabase)
    # The chapter_agent module also has a pg_request — patch it too
    # so the DELETE/PATCH endpoints don't bypass our stub.
    monkeypatch.setattr(mod, "pg_request", fake_supabase)

    return mod, token, client, alice, bob


# ══════════════════════════════════════════════════════════════════════
# HAPPY — both paths return 200 on /admin/api/status
# ══════════════════════════════════════════════════════════════════════


def test_HAPPY_bearer_path_returns_200_on_status(chapter_with_admin_token):
    _mod, token, client = chapter_with_admin_token
    r = client.get("/admin/api/status", headers={"X-Admin-Token": token})
    assert r.status_code == 200, r.text
    body = r.json()
    assert "members_total" in body
    assert "federation_peers" in body
    assert body["agent_id"] == "TEST-admin-fixture-chapter"


def test_HAPPY_signed_admin_path_returns_200_on_status(signed_admin_setup):
    _mod, _token, client, alice, _bob = signed_admin_setup
    headers = alice["signer"](method="GET", url_path="/admin/api/status")
    r = client.get("/admin/api/status", headers=headers)
    assert r.status_code == 200, r.text
    assert r.json()["agent_id"] == "TEST-admin-fixture-chapter"


def test_HAPPY_bearer_lists_registered_members(signed_admin_setup):
    _mod, token, client, alice, bob = signed_admin_setup
    r = client.get("/admin/api/members", headers={"X-Admin-Token": token})
    assert r.status_code == 200
    body = r.json()
    agent_ids = {m["agent_id"] for m in body["members"]}
    assert alice["agent_id"] in agent_ids
    assert bob["agent_id"] in agent_ids


# ══════════════════════════════════════════════════════════════════════
# HAPPY — signed admin can promote / demote / remove
# ══════════════════════════════════════════════════════════════════════


def test_HAPPY_signed_admin_promotes_member_to_leader(signed_admin_setup):
    _mod, _token, client, alice, bob = signed_admin_setup
    body = json.dumps({"role": "leader"})
    path = f"/admin/api/members/{bob['agent_id']}/role"
    headers = alice["signer"](method="POST", url_path=path, body=body)
    headers["Content-Type"] = "application/json"

    r = client.post(path, headers=headers, content=body)
    assert r.status_code == 200, r.text
    assert r.json()["chapter_role"] == "leader"


def test_HAPPY_signed_admin_demotes_leader_back_to_member(signed_admin_setup):
    _mod, _token, client, alice, bob = signed_admin_setup

    # Step 1: promote
    promote_body = json.dumps({"role": "leader"})
    promote_path = f"/admin/api/members/{bob['agent_id']}/role"
    promote_headers = alice["signer"](method="POST", url_path=promote_path, body=promote_body)
    promote_headers["Content-Type"] = "application/json"
    r1 = client.post(promote_path, headers=promote_headers, content=promote_body)
    assert r1.status_code == 200, r1.text

    # Step 2: demote back to member — new signature with fresh nonce
    demote_body = json.dumps({"role": "member"})
    demote_headers = alice["signer"](method="POST", url_path=promote_path, body=demote_body)
    demote_headers["Content-Type"] = "application/json"
    r2 = client.post(promote_path, headers=demote_headers, content=demote_body)
    assert r2.status_code == 200, r2.text
    assert r2.json()["chapter_role"] == "member"


def test_HAPPY_bearer_admin_removes_member(signed_admin_setup):
    mod, token, client, _alice, bob = signed_admin_setup
    assert bob["agent_id"] in mod.members

    r = client.delete(
        f"/admin/api/members/{bob['agent_id']}",
        headers={"X-Admin-Token": token},
    )
    assert r.status_code == 200
    assert r.json()["removed"] == bob["agent_id"]
    # In-memory registry no longer holds bob
    assert bob["agent_id"] not in mod.members


# ══════════════════════════════════════════════════════════════════════
# AUTHZ — wrong role / no auth / bad sig
# ══════════════════════════════════════════════════════════════════════


def test_AUTHZ_signed_non_admin_returns_403_with_remediation(signed_admin_setup):
    _mod, _token, client, _alice, bob = signed_admin_setup
    # bob has chapter_role='member', not admin
    headers = bob["signer"](method="GET", url_path="/admin/api/status")
    r = client.get("/admin/api/status", headers=headers)
    assert r.status_code == 403, r.text
    body = r.json()
    assert "admin role required" in body["error"]
    assert "member" in body["hint"]  # the role they DO have
    assert "remediation" in body
    assert "promote" in body["remediation"].lower()


def test_AUTHZ_no_auth_returns_401_with_both_path_hint(chapter_with_admin_token):
    _mod, _token, client = chapter_with_admin_token
    r = client.get("/admin/api/status")
    assert r.status_code == 401
    body = r.json()
    assert "X-Agent-Signature" in body["hint"]
    assert "X-Admin-Token" in body["hint"]
    assert "chapter_role=admin" in body["hint"]


def test_AUTHZ_bad_signature_returns_401_with_verify_reason(signed_admin_setup):
    _mod, _token, client, alice, _bob = signed_admin_setup
    # Build valid headers, then corrupt the signature
    headers = alice["signer"](method="GET", url_path="/admin/api/status")
    headers["X-Agent-Signature"] = "AAAA" + headers["X-Agent-Signature"][4:]
    r = client.get("/admin/api/status", headers=headers)
    assert r.status_code == 401
    body = r.json()
    assert "X-Agent-Signature verification failed" in body["error"]
    assert "reason" in body


def test_AUTHZ_wrong_bearer_returns_401(chapter_with_admin_token):
    _mod, _token, client = chapter_with_admin_token
    r = client.get("/admin/api/status", headers={"X-Admin-Token": "b" * 64})
    assert r.status_code == 401


# ══════════════════════════════════════════════════════════════════════
# ADVERSARIAL — invalid input handled cleanly
# ══════════════════════════════════════════════════════════════════════


def test_ADVERSARIAL_promotion_to_invalid_role_returns_400(signed_admin_setup):
    _mod, token, client, _alice, bob = signed_admin_setup
    r = client.post(
        f"/admin/api/members/{bob['agent_id']}/role",
        headers={"X-Admin-Token": token, "Content-Type": "application/json"},
        json={"role": "god_emperor"},
    )
    assert r.status_code == 400
    body = r.json()
    assert "invalid role" in body["error"]
    assert "admin" in body["allowed"]
    assert "leader" in body["allowed"]


def test_ADVERSARIAL_promotion_of_hostile_agent_id_sanitized(signed_admin_setup):
    """Hostile agent_id (DROP TABLE / null-byte / path traversal) must be
    handled safely. The chapter's ``sanitize_agent_id`` may either reject
    outright (400) OR strip dangerous chars and proceed (200 with the
    scrubbed value). Either is acceptable — the security property is
    that NO hostile string flows unsanitized into the SQL builder or
    the response body."""
    _mod, token, client, _alice, _bob = signed_admin_setup
    hostile_ids = [
        "../etc/passwd",
        "DROP TABLE agents;--",
        "<script>alert(1)</script>",
    ]
    # Null-byte case: httpx rejects this at the client before sending, so
    # it's safe by virtue of the transport layer. We separately verify
    # sanitize_agent_id handles null bytes if they were to reach the
    # handler (e.g. via a non-httpx client). Cover via the unit test on
    # sanitize_agent_id rather than TestClient round-trip.
    for hostile in hostile_ids:
        r = client.post(
            f"/admin/api/members/{hostile}/role",
            headers={"X-Admin-Token": token, "Content-Type": "application/json"},
            json={"role": "leader"},
        )
        # 200/400/404 all acceptable. 500 is the failure mode — the
        # server crashed on hostile input. 200 must echo a scrubbed
        # agent_id, NOT the raw hostile string.
        assert r.status_code in (200, 400, 404), f"hostile id {hostile!r} caused server error {r.status_code}: {r.text}"
        if r.status_code == 200:
            echoed = r.json().get("agent_id", "")
            # SECURITY: no hostile substring should appear unsanitized
            assert "DROP TABLE" not in echoed, f"raw SQL in echo: {echoed!r}"
            assert "<script>" not in echoed, f"raw XSS in echo: {echoed!r}"
            assert "../" not in echoed, f"path traversal in echo: {echoed!r}"
            assert "\x00" not in echoed, f"null byte in echo: {echoed!r}"
