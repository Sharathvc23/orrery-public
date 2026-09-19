"""verdict parity — server attestation verifier vs the index gate's.

The lean index deploys standalone (its Docker context is index/ only), so it
carries its own verifier (`index/attestation_gate.py`) instead of importing
`registry_attestation`. Two verifiers for one artifact is a drift hazard; this
suite is the guard: for every attestation class — valid, tampered, expired,
not-yet-valid, inverted-window, malformed, unsupported DID — both verifiers
must return the SAME (valid, reason) verdict.

Runs in the server job (it has both modules' dependency stacks).
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

import registry_attestation
import sovereign_identity

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "index"))
import attestation_gate  # noqa: E402  (needs the index/ path above)

SIGNER = "parity-org"
NOW = 1_751_500_000.0


@pytest.fixture(autouse=True)
def signer_keypair():
    sovereign_identity.generate_ed25519_keypair(SIGNER)
    yield
    sovereign_identity._ed25519_keypairs.pop(SIGNER, None)


def _build(**kw):
    kw.setdefault("now", NOW)
    return registry_attestation.build(SIGNER, "https://org.example.com", SIGNER, **kw)


def _both(att, *, now):
    return (
        registry_attestation.verify(att, now=now),
        attestation_gate.verify_attestation(att, now=now),
    )


def _assert_parity(att, *, now, expect):
    server_verdict, index_verdict = _both(att, now=now)
    assert server_verdict == index_verdict == expect


def test_valid_attestation_parity():
    _assert_parity(_build(), now=NOW + 60, expect=(True, "ok"))


def test_tampered_record_parity():
    att = _build()
    att["record"]["endpoint"] = "https://attacker.example.com"
    _assert_parity(att, now=NOW + 60, expect=(False, "invalid_signature"))


def test_expired_parity():
    att = _build(ttl_s=60.0)
    _assert_parity(att, now=NOW + 3600, expect=(False, "expired"))


def test_not_yet_valid_parity():
    """F6: both verifiers reject a future-dated attestation past clock skew."""
    att = _build()
    _assert_parity(att, now=NOW - 3600, expect=(False, "not_yet_valid"))
    # ...and both ACCEPT within the skew window.
    server_verdict, index_verdict = _both(att, now=NOW - 200)
    assert server_verdict == index_verdict == (True, "ok")


def test_inverted_window_parity():
    """F6: issued_at > expires_at is malformed in both."""
    att = _build()
    att["record"]["issued_at"] = att["record"]["expires_at"] + 100
    _assert_parity(att, now=NOW + 60, expect=(False, "malformed"))


def test_malformed_parity():
    for bad in ("junk", {}, {"record": {}, "sig": "x"}, {"record": {"v": 1}, "sig": ""}, None, 42):
        server_verdict, index_verdict = _both(bad, now=NOW)
        assert server_verdict == index_verdict == (False, "malformed"), f"diverged on {bad!r}"


def test_unsupported_did_parity():
    att = _build()
    att["record"]["did"] = "did:web:example.com"
    _assert_parity(att, now=NOW + 60, expect=(False, "unsupported_did"))
