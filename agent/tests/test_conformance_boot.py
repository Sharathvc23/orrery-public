"""Boot-time conformance badge: honest counts, self-attested label,
offline verification, and never clobbering an operator badge.

Also the drift-guard locking the embedded vector corpus to the canonical
``vectors/signing/`` at the repo root.

Classification: HAPPY / EDGE / ADVERSARIAL.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from community_member import conformance_boot
from community_member.config import Config
from community_member.conformance_badge import badge_path, load_badge, verify_badge
from community_member.crypto import generate_ed25519_keypair

REPO_VECTORS = Path(__file__).resolve().parents[2] / "vectors" / "signing"


@pytest.fixture
def agent_config(tmp_path, monkeypatch) -> Config:
    monkeypatch.setenv("COMMUNITY_MEMBER_HOME", str(tmp_path))
    kp = generate_ed25519_keypair()
    cfg = Config()
    cfg.agent_id = "boot-badge-test"
    cfg.private_key = kp["private_key"]
    cfg.public_key = kp["public_key"]
    return cfg


# ── drift guard ─────────────────────────────────────────────


@pytest.mark.skipif(not REPO_VECTORS.exists(), reason="canonical corpus only present in the repo checkout")
def test_embedded_vectors_lockstep_with_canonical():
    """ADVERSARIAL: the embedded corpus must be byte-identical to
    vectors/signing/ — a drifted mirror would sign a suite_digest for a corpus
    the canonical suite never blessed."""
    embedded = conformance_boot.vectors_dir()
    canonical_files = sorted(p.name for p in REPO_VECTORS.glob("*.json"))
    embedded_files = sorted(p.name for p in embedded.glob("*.json"))
    assert embedded_files == canonical_files
    for name in canonical_files:
        assert (embedded / name).read_bytes() == (REPO_VECTORS / name).read_bytes(), name


def test_suite_digest_matches_canonical_corpus():
    """HAPPY: the digest the boot badge pins equals the canonical corpus digest."""
    if not REPO_VECTORS.exists():
        pytest.skip("canonical corpus only present in the repo checkout")
    from sm_conformance.badge import compute_suite_digest

    assert compute_suite_digest(conformance_boot.vectors_dir()) == compute_suite_digest(REPO_VECTORS)


# ── self-checks ─────────────────────────────────────────────


def test_self_checks_all_pass():
    """HAPPY: this runtime conforms — 5/5, no failures."""
    passed, failed, names = conformance_boot.run_self_checks()
    assert (passed, failed, names) == (5, 0, [])


def test_self_checks_report_real_failures(monkeypatch):
    """ADVERSARIAL: a drifted runtime is COUNTED, not hidden — break the
    canonical builder and the counts must say so."""
    from community_member import auth

    monkeypatch.setattr(auth, "canonical_string_v02", lambda b, a, t: "WRONG")
    passed, failed, names = conformance_boot.run_self_checks()
    assert failed == 2  # canonical_v02 + the sign roundtrip that builds on it
    assert "test_canonical_string_v02" in names
    assert "test_sign_roundtrip_v02" in names
    assert passed == 3


# ── boot badge lifecycle ────────────────────────────────────


def test_boot_badge_generated_signed_and_offline_verifiable(agent_config):
    """HAPPY: fresh home → badge written, verifies offline, honest counts,
    self-attested label present."""
    path = conformance_boot.ensure_boot_badge(agent_config)
    assert path is not None and path == badge_path()
    badge = load_badge()
    payload = verify_badge(badge)  # raises on bad signature/schema
    assert payload["passed"] == 5 and payload["failed"] == 0
    ext = payload.get("extensions") or {}
    assert ext.get("org.orrery.attestation") == "self-attested"
    assert ext.get("org.orrery.witness") == "none"


def test_boot_badge_never_clobbers_valid_existing(agent_config):
    """EDGE: an existing verifying badge (e.g. operator-generated) is kept
    byte-for-byte; a second boot writes nothing."""
    conformance_boot.ensure_boot_badge(agent_config)
    original = badge_path().read_bytes()
    assert conformance_boot.ensure_boot_badge(agent_config) is None
    assert badge_path().read_bytes() == original


def test_boot_badge_regenerates_over_invalid_existing(agent_config):
    """EDGE: a tampered/corrupt badge on disk is replaced with a valid one."""
    conformance_boot.ensure_boot_badge(agent_config)
    tampered = json.loads(badge_path().read_text())
    tampered["payload_b64"] = "dGFtcGVyZWQ="  # breaks the signature
    badge_path().write_text(json.dumps(tampered))
    path = conformance_boot.ensure_boot_badge(agent_config)
    assert path is not None
    verify_badge(load_badge())


def test_no_signing_key_means_no_badge(agent_config, capsys):
    """EDGE: without a signable identity nothing is written (route 404s) and
    the reason is logged loudly — never an unsigned or fabricated badge."""
    agent_config.private_key = ""
    assert conformance_boot.ensure_boot_badge(agent_config) is None
    assert not badge_path().exists()
    assert "[conformance][ERROR]" in capsys.readouterr().out
