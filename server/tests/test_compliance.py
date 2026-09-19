"""Tests for chapter/compliance.py — sm-locp ComplianceCredential wiring.

Classification: HAPPY / EDGE / FAILURE.

Coverage:
  - HAPPY: init() with real key produces working VCGenerator
  - HAPPY: emit_compliance_attestation returns a signed W3C VC dict
           with the expected shape
  - EDGE: missing required fields (subject_did, rule_id, status) return {}
  - EDGE: not-initialized returns {} (no-op, never crashes)
  - FAILURE: init with bad key falls back to disabled state
"""

from __future__ import annotations

import base64
import os

os.environ.setdefault("AGENT_ID", "test-compliance-chapter")
os.environ.setdefault("AGENT_NAME", "Test Compliance Chapter")

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


@pytest.fixture
def fresh_compliance():
    """Reset module state before + after each test."""
    import compliance

    compliance.reset()
    yield compliance
    compliance.reset()


@pytest.fixture
def chapter_keypair():
    """Generate an Ed25519 keypair + register it in sovereign_identity
    under the test chapter id. compliance.init() resolves issuer DID
    from this."""
    import sovereign_identity

    sk = Ed25519PrivateKey.generate()
    sk_bytes = sk.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pk_bytes = sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    chapter_id = "test-compliance-chapter"
    sovereign_identity._ed25519_keypairs[chapter_id] = {
        "private_key": sk_bytes,
        "public_key": pk_bytes,
    }
    yield {
        "chapter_id": chapter_id,
        "private_key_b64": base64.b64encode(sk_bytes).decode(),
        "public_key_b64": base64.b64encode(pk_bytes).decode(),
    }
    sovereign_identity._ed25519_keypairs.pop(chapter_id, None)


# ══════════════════════════════════════════════════════════════════════
# HAPPY
# ══════════════════════════════════════════════════════════════════════


def test_HAPPY_init_with_real_key_produces_working_generator(fresh_compliance, chapter_keypair):
    """init() with a valid Ed25519 key resolves to is_initialized=True."""
    fresh_compliance.init(
        chapter_id=chapter_keypair["chapter_id"],
        private_key_b64=chapter_keypair["private_key_b64"],
    )
    assert fresh_compliance.is_initialized() is True


def test_HAPPY_emit_returns_w3c_vc_shape(fresh_compliance, chapter_keypair):
    """A successful emit produces a dict matching W3C VC v1 shape."""
    fresh_compliance.init(
        chapter_id=chapter_keypair["chapter_id"],
        private_key_b64=chapter_keypair["private_key_b64"],
    )
    vc = fresh_compliance.emit_compliance_attestation(
        subject_did="did:key:zMember123",
        rule_id="CCPA-1798.105-deletion-not-required",
        status="compliant",
        confidence=0.95,
        evaluation_state={"opt_out_received": False, "data_retention_days": 30},
        agency="CA-AG",
        cfr_reference="CA Civ Code §1798.105",
    )
    # W3C VC v1 top-level keys
    assert "@context" in vc
    assert "type" in vc
    assert "VerifiableCredential" in vc["type"]
    assert "credentialSubject" in vc
    assert vc["credentialSubject"]["id"] == "did:key:zMember123"
    assert vc["credentialSubject"]["rule_id"] == "CCPA-1798.105-deletion-not-required"
    assert vc["credentialSubject"]["status"] == "compliant"
    assert vc["credentialSubject"]["confidence"] == 0.95
    # Signed
    assert "proof" in vc
    assert vc["proof"].get("proofValue")


def test_HAPPY_confidence_clamped_to_unit_interval(fresh_compliance, chapter_keypair):
    """Out-of-range confidence (>1 or <0) is clamped to [0,1]."""
    fresh_compliance.init(
        chapter_id=chapter_keypair["chapter_id"],
        private_key_b64=chapter_keypair["private_key_b64"],
    )
    vc_over = fresh_compliance.emit_compliance_attestation(
        subject_did="did:key:zX",
        rule_id="R1",
        status="compliant",
        confidence=5.0,  # over 1.0
    )
    vc_under = fresh_compliance.emit_compliance_attestation(
        subject_did="did:key:zX",
        rule_id="R1",
        status="compliant",
        confidence=-0.5,  # under 0.0
    )
    assert vc_over["credentialSubject"]["confidence"] == 1.0
    assert vc_under["credentialSubject"]["confidence"] == 0.0


# ══════════════════════════════════════════════════════════════════════
# EDGE
# ══════════════════════════════════════════════════════════════════════


def test_EDGE_not_initialized_returns_empty_dict(fresh_compliance):
    """Calling emit before init returns {} — no crash, no junk VC."""
    vc = fresh_compliance.emit_compliance_attestation(
        subject_did="did:key:zX",
        rule_id="R1",
        status="compliant",
        confidence=1.0,
    )
    assert vc == {}
    assert fresh_compliance.is_initialized() is False


def test_EDGE_missing_required_field_returns_empty(fresh_compliance, chapter_keypair):
    """Empty subject_did, rule_id, or status → no VC minted."""
    fresh_compliance.init(
        chapter_id=chapter_keypair["chapter_id"],
        private_key_b64=chapter_keypair["private_key_b64"],
    )
    assert (
        fresh_compliance.emit_compliance_attestation(
            subject_did="",
            rule_id="R1",
            status="compliant",
            confidence=1.0,
        )
        == {}
    )
    assert (
        fresh_compliance.emit_compliance_attestation(
            subject_did="did:key:zX",
            rule_id="",
            status="compliant",
            confidence=1.0,
        )
        == {}
    )
    assert (
        fresh_compliance.emit_compliance_attestation(
            subject_did="did:key:zX",
            rule_id="R1",
            status="",
            confidence=1.0,
        )
        == {}
    )


def test_EDGE_evaluation_state_defaults_to_empty(fresh_compliance, chapter_keypair):
    """Omitting evaluation_state produces an empty-dict default — not None."""
    fresh_compliance.init(
        chapter_id=chapter_keypair["chapter_id"],
        private_key_b64=chapter_keypair["private_key_b64"],
    )
    vc = fresh_compliance.emit_compliance_attestation(
        subject_did="did:key:zX",
        rule_id="R1",
        status="compliant",
        confidence=1.0,
    )
    assert vc["credentialSubject"]["evaluation_state"] == {}


# ══════════════════════════════════════════════════════════════════════
# FAILURE — graceful degradation
# ══════════════════════════════════════════════════════════════════════


def test_FAILURE_init_with_malformed_key_falls_back_to_disabled(fresh_compliance):
    """An invalid private_key_b64 doesn't crash init — the module just
    stays disabled and subsequent emits no-op."""
    fresh_compliance.init(
        chapter_id="any-chapter",
        private_key_b64="not-valid-base64!!!",
    )
    assert fresh_compliance.is_initialized() is False
    # Subsequent emit no-ops cleanly
    vc = fresh_compliance.emit_compliance_attestation(
        subject_did="did:key:zX",
        rule_id="R1",
        status="compliant",
        confidence=1.0,
    )
    assert vc == {}
