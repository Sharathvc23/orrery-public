"""
R1-R10 tests pinning the invariant: POST /api/members must not require
X-Agent-Signature for first-time registration.

This bug was discovered running the OpenClaw skill flow end-to-end
against live bayarea on 2026-04-22. Fix: add /api/members to
SELF_SIGNED_POST_PATHS (the handler does TOFU internally + enforces
origin-mismatch on re-registration, so the middleware gate was
redundant and blocked new users).
"""

from __future__ import annotations

import auth_verify


def test_R4_authz_post_members_is_self_signed():
    """POST /api/members must be classified as self-signed so the
    middleware doesn't block first-time registrations."""
    assert auth_verify.is_open_path("POST", "/api/members") is True


def test_R4_authz_post_members_trailing_slash_also_open():
    assert auth_verify.is_open_path("POST", "/api/members/") is True


def test_R7_adversarial_rotate_is_self_signed():
    """POST /api/members/rotate body carries a full attestation signed
    by the OLD key. Middleware gate would break it."""
    assert auth_verify.is_open_path("POST", "/api/members/rotate") is True
    assert auth_verify.is_open_path("POST", "/api/members/rotate/") is True


def test_R5_boundary_skills_publish_requires_a_signed_member():
    """Publication into the org's registry is no longer open: it takes a
    registered member's request signature. The package signature proves what
    the skill IS; it says nothing about who may list it here."""
    assert auth_verify.is_open_path("POST", "/api/skills/publish") is False
    assert auth_verify.requires_auth("POST", "/api/skills/publish")
    assert auth_verify.requires_auth("POST", "/api/skills/publish/package")


def test_R10_persistence_self_signed_set_has_expected_entries():
    assert auth_verify.SELF_SIGNED_POST_PATHS == {
        # First-run org setup (/api/org/config) is no longer self-signed: it
        # takes the boot-printed admin bearer (is_admin_bearer_path).
        # /api/skills/publish and /publish/package are no longer self-signed:
        # publication takes a registered member's request signature; the
        # package signature is still verified fail-closed in the handler.
        "/api/members",
        "/api/members/",
        "/api/members/rotate",
        "/api/members/rotate/",
        # ARP v0.1: receipt body carries Ed25519 signature; chapter.arp.emit
        # verifies it inside the handler.
        "/api/receipts",
        "/api/receipts/",
    }


def test_happy_post_intents_still_requires_auth():
    """Sanity: we didn't open up too much. Intents still require auth."""
    assert auth_verify.is_open_path("POST", "/api/intents") is False
    assert auth_verify.requires_auth("POST", "/api/intents") is True


def test_happy_post_feedback_still_requires_auth():
    assert auth_verify.is_open_path("POST", "/api/feedback") is False


def test_happy_delete_member_still_requires_auth():
    assert auth_verify.requires_auth("DELETE", "/api/members/alice") is True
