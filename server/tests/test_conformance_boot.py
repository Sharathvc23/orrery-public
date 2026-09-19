"""Org-host boot-time conformance badge: honest counts (passed vs
explicitly-skipped client-side checks), self-attested label, offline
verification, and never clobbering an operator badge.

Classification: HAPPY / EDGE / ADVERSARIAL.
"""

import json

import pytest
from sm_conformance.badge import verify_envelope

import conformance_boot
import sovereign_identity

ORG_ID = "boot-badge-test-org"


@pytest.fixture
def org_key():
    sovereign_identity._ed25519_keypairs.pop(ORG_ID, None)
    sovereign_identity.generate_ed25519_keypair(ORG_ID)
    yield
    sovereign_identity._ed25519_keypairs.pop(ORG_ID, None)


def test_vectors_corpus_resolves():
    """HAPPY: the canonical corpus resolves from the repo checkout (and from
    /app/vectors in the image — same relative path)."""
    corpus = conformance_boot.vectors_dir()
    assert corpus is not None
    assert (corpus / "did-key-derivations.json").exists()


def test_self_checks_all_pass():
    """HAPPY: the org's primitives conform — 3/3 applicable checks."""
    corpus = conformance_boot.vectors_dir()
    assert conformance_boot.run_self_checks(corpus) == (3, 0, [])


def test_self_checks_count_real_failures(monkeypatch):
    """ADVERSARIAL: a drifted signer is COUNTED, not hidden."""
    monkeypatch.setattr(sovereign_identity, "ed25519_sign", lambda m, k: "not-a-signature")
    corpus = conformance_boot.vectors_dir()
    passed, failed, names = conformance_boot.run_self_checks(corpus)
    assert (passed, failed) == (2, 1)
    assert names == ["test_sign_roundtrip_v02"]


def test_boot_badge_generated_and_offline_verifiable(org_key, tmp_path):
    """HAPPY: fresh boot → badge written, verifies offline, honest split of
    passed vs skipped client-side checks, self-attested label."""
    path = tmp_path / "conformance.json"
    assert conformance_boot.ensure_boot_badge(ORG_ID, path) == path
    payload = verify_envelope(json.loads(path.read_text()))  # raises on tamper
    assert payload["passed"] == 3 and payload["failed"] == 0
    assert payload["skipped"] == 2
    assert set(payload["skipped_vectors"]) == set(conformance_boot.SKIPPED_CHECKS)
    ext = payload.get("extensions") or {}
    assert ext.get("org.orrery.attestation") == "self-attested"
    assert ext.get("org.orrery.witness") == "none"


def test_boot_badge_never_clobbers_valid_existing(org_key, tmp_path):
    """EDGE: an existing verifying badge (operator-generated) is kept
    byte-for-byte across a second boot."""
    path = tmp_path / "conformance.json"
    conformance_boot.ensure_boot_badge(ORG_ID, path)
    original = path.read_bytes()
    assert conformance_boot.ensure_boot_badge(ORG_ID, path) is None
    assert path.read_bytes() == original


def test_boot_badge_regenerates_over_invalid_existing(org_key, tmp_path):
    """EDGE: a tampered badge on disk is replaced with a valid one."""
    path = tmp_path / "conformance.json"
    conformance_boot.ensure_boot_badge(ORG_ID, path)
    tampered = json.loads(path.read_text())
    tampered["payload_b64"] = "dGFtcGVyZWQ="
    path.write_text(json.dumps(tampered))
    assert conformance_boot.ensure_boot_badge(ORG_ID, path) == path
    verify_envelope(json.loads(path.read_text()))


def test_no_org_keypair_means_no_badge(tmp_path, capsys):
    """EDGE: without the org keypair nothing is written and the reason is
    logged loudly — never an unsigned or fabricated badge."""
    sovereign_identity._ed25519_keypairs.pop(ORG_ID, None)
    path = tmp_path / "conformance.json"
    assert conformance_boot.ensure_boot_badge(ORG_ID, path) is None
    assert not path.exists()
    assert "[conformance][ERROR]" in capsys.readouterr().out
