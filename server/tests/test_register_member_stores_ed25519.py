"""Regression test for the 2026-05-10 'silent registration drift' bug.

Pre-fix: chapter_agent.register_member called
``auth_verify.store_agent_key(agent_id, public_key)`` which writes to
the legacy HMAC ``public_key`` slot ONLY. Subsequent Ed25519 / Ed25519+
nonce signed requests look up ``ed25519_pubkey`` from the same dict,
find nothing (or worse, a stale entry from an earlier TOFU bootstrap),
and reject with ``key_mismatch`` or ``invalid_signature``.

Post-fix: when reg.public_key looks like an Ed25519 pubkey (44 chars
base64 with '=' pad), we call ``replace_agent_key`` so BOTH slots are
overwritten cleanly.

This test asserts the fix end-to-end: after register_member, the
auth-verify pubkey lookup must return the registered key. Without the
fix, the assertion fails because ed25519_pubkey is empty.
"""

from __future__ import annotations

import base64
import os

os.environ.setdefault("AGENT_ID", "test-chapter")
os.environ.setdefault("AGENT_NAME", "Test Chapter")

import pytest  # noqa: E402

import auth_verify  # noqa: E402
import chapter_agent  # noqa: E402


@pytest.fixture(autouse=True)
def _isolate(monkeypatch):
    monkeypatch.setattr(chapter_agent, "members", {})
    monkeypatch.setattr(chapter_agent, "PUBLIC_URL", "")
    auth_verify._agent_keys.clear()
    yield
    auth_verify._agent_keys.clear()


def _ed25519_pubkey_b64() -> str:
    """44-char base64-padded Ed25519 key (any 32 bytes will do)."""
    return base64.b64encode(b"\x01" * 32).decode()  # ends in '='


@pytest.mark.asyncio
async def test_register_populates_ed25519_slot_so_signed_calls_can_verify():
    pubkey = _ed25519_pubkey_b64()

    await chapter_agent.register_member(
        chapter_agent.MemberRegistration(
            agent_id="alice",
            name="Alice",
            public_key=pubkey,
        )
    )

    stored = auth_verify._agent_keys.get("alice", {})
    assert stored.get("ed25519_pubkey") == pubkey, (
        "register_member must populate ed25519_pubkey so signed requests "
        "from this agent can be verified by the Ed25519 path in verify_request. "
        f"Got slot contents: {stored!r}"
    )


@pytest.mark.asyncio
async def test_plain_reregistration_cannot_change_key():
    """P0: a key CHANGE is a rotation and must be self-signed by the old
    key via POST /api/members/rotate. Plain re-registration with a new key is
    rejected (403) and leaves the stored key untouched — otherwise an
    unauthenticated POST (the /api/members path is open) was account takeover.

    (Genuine rotation overwrite-vs-merge behaviour is covered by
    test_member_rotation.py + test_auth_verify_replace_key.py.)"""
    old = base64.b64encode(b"\x01" * 32).decode()
    new = base64.b64encode(b"\x02" * 32).decode()

    # First registration — TOFU stores `old`.
    await chapter_agent.register_member(
        chapter_agent.MemberRegistration(agent_id="alice", name="Alice", public_key=old)
    )
    assert auth_verify._agent_keys["alice"]["ed25519_pubkey"] == old

    # Re-registration with a DIFFERENT key and no rotation proof — rejected.
    resp = await chapter_agent.register_member(
        chapter_agent.MemberRegistration(agent_id="alice", name="Alice", public_key=new)
    )
    assert getattr(resp, "status_code", 200) == 403
    assert auth_verify._agent_keys["alice"]["ed25519_pubkey"] == old


@pytest.mark.asyncio
async def test_non_ed25519_pubkey_falls_back_to_legacy_slot():
    """An HMAC-style key (short / non-Ed25519-shaped) still uses the
    legacy store_agent_key path — backward-compat for older clients."""
    hmac_key = "shortkey"  # not 44 chars + '=' pad

    await chapter_agent.register_member(
        chapter_agent.MemberRegistration(
            agent_id="legacy-bob",
            name="Bob",
            public_key=hmac_key,
        )
    )

    stored = auth_verify._agent_keys.get("legacy-bob", {})
    assert stored.get("public_key") == hmac_key
    # ed25519 slot NOT populated for a non-Ed25519-shaped key.
    assert not stored.get("ed25519_pubkey")
