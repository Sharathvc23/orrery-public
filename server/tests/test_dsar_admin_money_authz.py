"""P1 — auth-layer tests for the DSAR (GDPR) routes.

The audit flagged that of ~170 routes only ~20 were HTTP-tested, and the
compliance routes — DSAR export/delete/inventory — had NO auth test. The
handlers ARE _authorize_admin-gated; this locks that contract so a future
refactor can't silently open them:

  * unauthenticated / unprivileged → 401/403 (never 200 with data or a delete);
  * a valid admin credential → allowed;
  * the public discovery surface (/.well-known/did.json, /.well-known/registries)
    stays open (200) — locking the other direction.

Classification: ADVERSARIAL (unauth GDPR-delete / data-dump) + contract lock.
"""

from __future__ import annotations

import importlib
import sys

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def chapter_agent_module(monkeypatch):
    monkeypatch.setenv("AGENT_ID", "TEST-dsar-chapter")
    monkeypatch.setenv("AGENT_NAME", "DSAR Fixture")
    monkeypatch.setenv("XAI_API_KEY", "test-key")
    monkeypatch.setenv("PUBLIC_URL", "http://localhost:7000")
    monkeypatch.delenv("CHAPTER_ADMIN_TOKEN", raising=False)
    for mod in ("admin", "auth_verify", "governance", "chapter_agent"):
        sys.modules.pop(mod, None)
    return importlib.import_module("chapter_agent")


@pytest.fixture
def client(chapter_agent_module) -> TestClient:
    chapter_agent_module._rate_limit_store.clear()
    return TestClient(chapter_agent_module.app)


_DENIED = (401, 403)


# ── DSAR (GDPR) — must be admin-gated ────────────────────────────────


def test_dsar_export_unauth_denied(client):
    resp = client.get("/api/dsar/export", params={"subject_did": "did:key:zVictim"})
    assert resp.status_code in _DENIED, f"DSAR export reachable unauth ({resp.status_code})"


def test_dsar_delete_unauth_denied(client):
    # The irreversible GDPR delete MUST never run unauthenticated.
    resp = client.post("/api/dsar/delete", params={"subject_did": "did:key:zVictim", "confirm": "true"})
    assert resp.status_code in _DENIED, f"DSAR delete reachable unauth ({resp.status_code})"


def test_dsar_inventory_unauth_denied(client):
    resp = client.get("/api/dsar/inventory")
    assert resp.status_code in _DENIED


def test_dsar_export_spoofed_header_denied(client):
    # A bare X-Agent-ID (no signature, not admin) must not authorize.
    resp = client.get(
        "/api/dsar/export",
        params={"subject_did": "did:key:zVictim"},
        headers={"X-Agent-ID": "mallory"},
    )
    assert resp.status_code in _DENIED


# ── public discovery surface — must STAY open ────────────────────────


def test_did_json_is_public(client):
    """This assertion predates the public-discovery rule and has always passed — which is itself the
    evidence that Orrery never gated this path. The public-discovery rule keeps it green and adds the
    key setup the handler no longer does for itself: did.json now READS the
    signing key rather than minting one on an anonymous request."""
    import sys

    import sovereign_identity

    # Via sys.modules, like routes/identity.py's `ca` proxy — a module-level
    # chapter_agent reference can be stale once another test re-imports it.
    live = sys.modules["chapter_agent"]
    sovereign_identity.generate_ed25519_keypair(live.AGENT_ID)
    try:
        resp = client.get("/.well-known/did.json")
    finally:
        sovereign_identity._ed25519_keypairs.pop(live.AGENT_ID, None)

    assert resp.status_code == 200, "did.json discovery doc must stay public"


def test_well_known_registries_is_public(client):
    resp = client.get("/.well-known/registries")
    assert resp.status_code == 200


# ── happy path — a valid admin token IS allowed (gate not broken-closed) ──


def test_dsar_inventory_allows_admin_token(monkeypatch):
    """A valid X-Admin-Token reaches the inventory (no DB needed) — proves the
    gate admits a real admin, not just that it rejects everyone."""
    token = "f" * 64
    monkeypatch.setenv("AGENT_ID", "TEST-dsar-admin-chapter")
    monkeypatch.setenv("AGENT_NAME", "DSAR Admin Fixture")
    monkeypatch.setenv("XAI_API_KEY", "test-key")
    monkeypatch.setenv("PUBLIC_URL", "http://localhost:7000")
    monkeypatch.setenv("CHAPTER_ADMIN_TOKEN", token)
    for mod in ("admin", "auth_verify", "governance", "chapter_agent"):
        sys.modules.pop(mod, None)
    mod = importlib.import_module("chapter_agent")
    with TestClient(mod.app) as client:  # context manager runs lifespan (admin.init)
        resp = client.get("/api/dsar/inventory", headers={"X-Admin-Token": token})
    assert resp.status_code == 200, resp.text
    assert "inventory" in resp.json()
