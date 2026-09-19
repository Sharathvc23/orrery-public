"""Reusable fixtures + helpers for admin auth tests.

This is NOT a conftest.py — fixtures are imported explicitly into the
test files that need them, so existing test modules are unaffected.

Two HTTP auth paths exist on /admin/api/* and BOTH need testable
fixtures so we can prosecute the contract across all of them:

  Path 1 — X-Agent-Signature from chapter_role='admin' member
           (the primary, did:key path)

  Path 2 — X-Admin-Token bearer
           (the fallback / bootstrap / break-glass path)

The verification script at chapter/scripts/verify_admin.py uses the
same primitives to verify a running chapter (local or production) end-
to-end over real HTTP.
"""

from __future__ import annotations

import base64
import importlib
import os
import sys
import time
from collections.abc import Callable


def build_v03_signed_headers(
    *,
    body: str,
    agent_id: str,
    private_key_b64: str,
    method: str = "GET",
    url_path: str = "/admin/api/status",
    timestamp: str = "",
    nonce: str = "",
) -> dict[str, str]:
    """Build v0.3 (ed25519+nonce) signed headers for a request.

    Canonical string is ``METHOD:url_path:body:agent_id:timestamp:nonce``
    — same scheme verified by ``auth_verify.verify_request`` when called
    with ``scheme='ed25519+nonce'``. Replay-protected by (agent_id, nonce)
    uniqueness within the chapter's replay-store TTL.
    """
    import sovereign_identity

    ts = timestamp or str(int(time.time()))
    n = nonce or base64.b64encode(os.urandom(32)).decode()
    canonical = f"{method.upper()}:{url_path}:{body}:{agent_id}:{ts}:{n}"
    sig = sovereign_identity.ed25519_sign(canonical, private_key_b64)
    return {
        "X-Agent-ID": agent_id,
        "X-Agent-Signature": sig,
        "X-Agent-Timestamp": ts,
        "X-Agent-Nonce": n,
        "X-Agent-Sig-Scheme": "ed25519+nonce",
    }


def make_signer(agent_id: str, private_key_b64: str) -> Callable[..., dict[str, str]]:
    """Return a request-signing callable bound to a specific (agent_id, key).

    Usage::

        sign = make_signer("alice", alice_priv_key_b64)
        headers = sign(method="POST", url_path="/admin/api/members/bob/role", body='{"role":"leader"}')
    """

    def _sign(
        *,
        method: str = "GET",
        url_path: str = "/admin/api/status",
        body: str = "",
    ) -> dict[str, str]:
        return build_v03_signed_headers(
            body=body,
            agent_id=agent_id,
            private_key_b64=private_key_b64,
            method=method,
            url_path=url_path,
        )

    return _sign


def reset_chapter_agent_module(
    monkeypatch,
    *,
    agent_id: str = "TEST-admin-fixture-chapter",
    agent_name: str = "Admin Fixture Chapter",
    chapter_admin_token: str | None = None,
) -> object:
    """Re-import chapter_agent + admin + auth_verify with a clean module
    state and stubbed env. Returns the chapter_agent module.

    NOTE: The admin module init runs at chapter startup (in lifespan), not
    at module import — so this function does NOT generate or write a
    token to disk by itself. Use the bearer_token_fixture below if you
    need a known bearer token.
    """
    monkeypatch.setenv("AGENT_ID", agent_id)
    monkeypatch.setenv("AGENT_NAME", agent_name)
    monkeypatch.setenv("XAI_API_KEY", "test-key")
    monkeypatch.setenv("PUBLIC_URL", "http://localhost:7000")
    if chapter_admin_token:
        monkeypatch.setenv("CHAPTER_ADMIN_TOKEN", chapter_admin_token)
    else:
        monkeypatch.delenv("CHAPTER_ADMIN_TOKEN", raising=False)
    # Per-test CHAPTER_HOME so the on-disk token file is isolated
    import tempfile

    monkeypatch.setenv("CHAPTER_HOME", tempfile.mkdtemp(prefix="chapter-admin-test-"))

    # Reload every module that caches state on import
    for mod in ("admin", "auth_verify", "governance", "chapter_agent"):
        sys.modules.pop(mod, None)

    chapter_agent_mod = importlib.import_module("chapter_agent")
    return chapter_agent_mod


def initialize_admin_token(monkeypatch) -> tuple[str, object]:
    """Initialize the admin module with a known token and return
    ``(token, admin_module)``. Useful when a test wants to know the
    bearer token without going through the chapter startup banner."""
    monkeypatch.setenv("CHAPTER_ADMIN_TOKEN", "f" * 64)
    sys.modules.pop("admin", None)
    import admin as admin_mod

    admin_mod.init()
    return "f" * 64, admin_mod


def register_test_admin_member(
    chapter_agent_mod,
    *,
    agent_id: str = "test-admin-alice",
    name: str = "Test Admin Alice",
) -> dict:
    """Register a test member with a fresh Ed25519 keypair, store their
    pubkey in auth_verify, and set chapter_role='admin'. Returns a dict
    with ``agent_id``, ``private_key`` (b64), ``public_key`` (b64), and
    a ``signer`` callable.

    Bypasses HTTP — manipulates in-memory state directly. For HTTP-level
    registration use the bearer path via the TestClient.
    """
    import auth_verify
    import sovereign_identity

    kp = sovereign_identity.generate_ed25519_keypair(agent_id)
    auth_verify.store_agent_key(agent_id, "", "", ed25519_pubkey=kp["public_key"])

    chapter_agent_mod.members[agent_id] = {
        "agent_id": agent_id,
        "name": name,
        "description": f"Fixture admin member for tests ({agent_id})",
        "skills": ["fixture"],
        "chapter_role": "admin",
        "virtual": False,
        "is_demo": True,
    }
    return {
        "agent_id": agent_id,
        "private_key": kp["private_key"],
        "public_key": kp["public_key"],
        "signer": make_signer(agent_id, kp["private_key"]),
        "chapter_role": "admin",
    }


def register_test_regular_member(
    chapter_agent_mod,
    *,
    agent_id: str = "test-member-bob",
    name: str = "Test Member Bob",
    chapter_role: str = "member",
) -> dict:
    """Same as register_test_admin_member but with chapter_role='member'
    (or any non-admin role). Used to verify the 403 path."""
    import auth_verify
    import sovereign_identity

    kp = sovereign_identity.generate_ed25519_keypair(agent_id)
    auth_verify.store_agent_key(agent_id, "", "", ed25519_pubkey=kp["public_key"])

    chapter_agent_mod.members[agent_id] = {
        "agent_id": agent_id,
        "name": name,
        "description": f"Fixture {chapter_role} for tests ({agent_id})",
        "skills": ["fixture"],
        "chapter_role": chapter_role,
        "virtual": False,
        "is_demo": True,
    }
    return {
        "agent_id": agent_id,
        "private_key": kp["private_key"],
        "public_key": kp["public_key"],
        "signer": make_signer(agent_id, kp["private_key"]),
        "chapter_role": chapter_role,
    }


def make_supabase_role_stub(
    role_by_agent_id: dict[str, str],
):
    """Build a pg_request stub that returns chapter_role from a
    dict keyed by agent_id. Use to override governance.get_chapter_role's
    real supabase lookup in tests.

    Usage::

        roles = {"test-admin-alice": "admin", "test-member-bob": "member"}
        monkeypatch.setattr(governance, "_pg_request", make_supabase_role_stub(roles))
    """

    async def _stub(method, table, params=None, body=None):
        t = table.split("?")[0]
        if t == "agents" and method == "GET":
            eq_filter = (params or {}).get("agent_id", "")
            if isinstance(eq_filter, str) and eq_filter.startswith("eq."):
                wanted = eq_filter[3:]
                if wanted in role_by_agent_id:
                    return [{"chapter_role": role_by_agent_id[wanted]}]
            return []
        return None

    return _stub


__all__ = [
    "build_v03_signed_headers",
    "make_signer",
    "reset_chapter_agent_module",
    "initialize_admin_token",
    "register_test_admin_member",
    "register_test_regular_member",
    "make_supabase_role_stub",
]
