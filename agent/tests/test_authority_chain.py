"""Tests for the ARP authority chain (spec §4.5 + §4.6).

Classification: HAPPY / EDGE / FAILURE / ADVERSARIAL.

The authority chain is a two-receipt pattern:
  1. Principal emits ``authority_granted`` receipt with scope + expiry.
  2. Subsequent action receipts reference the grant via
     ``action.granted_by_receipt_id``.

These tests exercise the SDK helpers ``emit_authority_grant`` and
``emit_authority_revocation`` plus the build_receipt flow accepting
``action.granted_by_receipt_id``.
"""

from __future__ import annotations

import uuid
from pathlib import Path

import pytest

from community_member import arp


@pytest.fixture
def sk_bytes():
    """Generate a fresh Ed25519 keypair for the principal."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    sk = Ed25519PrivateKey.generate()
    return sk.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


@pytest.fixture
def agency_log(tmp_path):
    """Fresh AgencyLog per test in a tmp dir."""
    return arp.AgencyLog(home=tmp_path)


# ══════════════════════════════════════════════════════════════════════
# HAPPY — emit grant + chain action to it
# ══════════════════════════════════════════════════════════════════════


def test_HAPPY_emit_authority_grant_produces_receipt(sk_bytes, agency_log):
    grant = arp.emit_authority_grant(
        sk_bytes=sk_bytes,
        granted_to_did="did:key:zAgent123",
        granted_scope=["intent_submitted", "message_sent"],
        grant_expires_at="2027-01-01T00:00:00Z",
        agency_log=agency_log,
        push=False,
    )
    assert grant["action"]["category"] == "authority_granted"
    assert grant["action"]["outcome"] == "completed"
    assert grant["action"]["machine_payload"]["granted_scope"] == ["intent_submitted", "message_sent"]
    assert grant["action"]["machine_payload"]["granted_to_did"] == "did:key:zAgent123"
    assert grant["action"]["machine_payload"]["grant_expires_at"] == "2027-01-01T00:00:00Z"
    # Signed
    assert grant.get("signature")
    # Issuer == principal (only principals grant authority for themselves)
    assert grant["issuer_did"] == grant["principal_did"]


def test_HAPPY_action_receipt_chains_to_grant(sk_bytes, agency_log):
    """An action receipt with action.granted_by_receipt_id pointing to
    a prior grant should pass through build_receipt cleanly."""
    grant = arp.emit_authority_grant(
        sk_bytes=sk_bytes,
        granted_to_did=arp.did_from_private_key(sk_bytes),
        granted_scope=["intent_submitted"],
        grant_expires_at="2027-01-01T00:00:00Z",
        agency_log=agency_log,
        push=False,
    )
    grant_id = grant["receipt_id"]

    # Now emit an action receipt referencing the grant
    issuer_did = arp.did_from_private_key(sk_bytes)
    action_receipt = arp.emit(
        action={
            "category": "intent_submitted",
            "human_summary": "I submitted an intent for a co-founder match.",
            "outcome": "completed",
            "granted_by_receipt_id": grant_id,
        },
        sk_bytes=sk_bytes,
        principal_did=issuer_did,
        agency_log=agency_log,
        push=False,
    )
    assert action_receipt["action"]["granted_by_receipt_id"] == grant_id


def test_HAPPY_emit_authority_revocation_produces_receipt(sk_bytes, agency_log):
    """Revoking a grant produces an authority_revoked receipt pointing
    to the original."""
    grant = arp.emit_authority_grant(
        sk_bytes=sk_bytes,
        granted_to_did="did:key:zAgent123",
        granted_scope=["*"],
        grant_expires_at="2027-01-01T00:00:00Z",
        agency_log=agency_log,
        push=False,
    )
    revocation = arp.emit_authority_revocation(
        sk_bytes=sk_bytes,
        revokes_receipt_id=grant["receipt_id"],
        reason="agent compromised",
        agency_log=agency_log,
        push=False,
    )
    assert revocation["action"]["category"] == "authority_revoked"
    assert revocation["action"]["machine_payload"]["revokes_receipt_id"] == grant["receipt_id"]
    assert "compromised" in revocation["action"]["human_summary"]


def test_HAPPY_grant_with_wildcard_scope(sk_bytes, agency_log):
    """granted_scope=['*'] means any category."""
    grant = arp.emit_authority_grant(
        sk_bytes=sk_bytes,
        granted_to_did="did:key:zAgent",
        granted_scope=["*"],
        grant_expires_at="2027-01-01T00:00:00Z",
        agency_log=agency_log,
        push=False,
    )
    assert grant["action"]["machine_payload"]["granted_scope"] == ["*"]


# ══════════════════════════════════════════════════════════════════════
# EDGE
# ══════════════════════════════════════════════════════════════════════


def test_EDGE_long_summary_truncated_to_280_chars(sk_bytes, agency_log):
    """Custom human_summary > 280 chars gets truncated cleanly."""
    long = "A" * 500
    grant = arp.emit_authority_grant(
        sk_bytes=sk_bytes,
        granted_to_did="did:key:zX",
        granted_scope=["intent_submitted"],
        grant_expires_at="2027-01-01T00:00:00Z",
        human_summary=long,
        agency_log=agency_log,
        push=False,
    )
    assert len(grant["action"]["human_summary"]) <= 280
    assert grant["action"]["human_summary"].endswith("...")


def test_EDGE_default_summary_generated_when_omitted(sk_bytes, agency_log):
    grant = arp.emit_authority_grant(
        sk_bytes=sk_bytes,
        granted_to_did="did:key:zAgent12345",
        granted_scope=["intent_submitted"],
        grant_expires_at="2027-01-01T00:00:00Z",
        agency_log=agency_log,
        push=False,
    )
    summary = grant["action"]["human_summary"]
    assert "Granted" in summary
    assert "intent_submitted" in summary


def test_EDGE_revocation_with_no_reason(sk_bytes, agency_log):
    revocation = arp.emit_authority_revocation(
        sk_bytes=sk_bytes,
        revokes_receipt_id=str(uuid.uuid4()),
        agency_log=agency_log,
        push=False,
    )
    assert "Revoked grant" in revocation["action"]["human_summary"]


# ══════════════════════════════════════════════════════════════════════
# Schema conformance — grant + revocation receipts pass JSON Schema
# ══════════════════════════════════════════════════════════════════════


def _validate_with_schema(receipt: dict) -> None:
    """Validate a receipt against the canonical ARP action schema.

    Uses the chapter's vendored _arp_verify module if available — it
    has the same schemas as conformance/arp/."""
    import sys

    chapter_path = str(Path(__file__).resolve().parent.parent.parent / "chapter")
    if chapter_path not in sys.path:
        sys.path.insert(0, chapter_path)
    try:
        import _arp_verify

        result = _arp_verify.verify_receipt(receipt)
        # We're not checking the signature here (different key namespace);
        # just that the schema validation step passed.
        assert result.stage != "schema", f"schema validation failed: {result.reason}"
    except (ImportError, ModuleNotFoundError):
        pytest.skip("chapter/_arp_verify not on path; schema check skipped")


def test_HAPPY_grant_receipt_validates_against_schema(sk_bytes, agency_log):
    grant = arp.emit_authority_grant(
        sk_bytes=sk_bytes,
        granted_to_did="did:key:z6MkmCJAZansQ3p1Qx5KJ9Z5VBs6N3wxc5fpfaY8Y1bdRsZc",
        granted_scope=["intent_submitted", "message_sent"],
        grant_expires_at="2027-01-01T00:00:00Z",
        agency_log=agency_log,
        push=False,
    )
    _validate_with_schema(grant)


def test_HAPPY_revocation_receipt_validates_against_schema(sk_bytes, agency_log):
    revocation = arp.emit_authority_revocation(
        sk_bytes=sk_bytes,
        revokes_receipt_id="01234567-89ab-4def-8123-456789abcdef",
        agency_log=agency_log,
        push=False,
    )
    _validate_with_schema(revocation)
