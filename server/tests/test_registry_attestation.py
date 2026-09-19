"""
Tests for registry_attestation — self-certifying registry records.

The security property under test: a registry (or anyone with write access to
its database) cannot alter a signed record without the signature breaking,
and cannot keep replaying an old one past its freshness window. Verification
is fully offline — the did:key inside the record IS the public key.

Classification: HAPPY / EDGE / FAILURE / ADVERSARIAL
"""

import pytest

import registry_attestation
import sovereign_identity

SIGNER = "test-org"
NOW = 1_751_500_000.0


@pytest.fixture(autouse=True)
def signer_keypair():
    sovereign_identity.generate_ed25519_keypair(SIGNER)
    yield
    sovereign_identity._ed25519_keypairs.pop(SIGNER, None)


def _build(subject=SIGNER, endpoint="https://org.example.com", **kw):
    kw.setdefault("now", NOW)
    return registry_attestation.build(subject, endpoint, SIGNER, **kw)


# ── HAPPY ────────────────────────────────────────────────────


def test_build_verify_roundtrip():
    """HAPPY: a freshly built attestation verifies."""
    att = _build()
    ok, reason = registry_attestation.verify(att, now=NOW + 60)
    assert (ok, reason) == (True, "ok")


def test_record_shape():
    """HAPPY: record carries version, subject, signer DID, endpoint, freshness window."""
    att = _build(subject="alice", endpoint="https://org.example.com/")
    rec = att["record"]
    assert rec["v"] == registry_attestation.ATTESTATION_VERSION
    assert rec["agent_id"] == "alice"
    assert rec["did"].startswith("did:key:z")
    assert rec["endpoint"] == "https://org.example.com"  # trailing slash normalized
    assert rec["expires_at"] == rec["issued_at"] + int(registry_attestation.DEFAULT_ATTESTATION_TTL_S)


def test_did_is_offline_verifiable():
    """HAPPY: the DID inside the record decodes to the key that verifies the sig —
    no endpoint fetch, no registry trust."""
    att = _build()
    pubkey = sovereign_identity.extract_ed25519_pubkey_from_did_key(att["record"]["did"])
    assert pubkey is not None
    assert sovereign_identity.ed25519_verify(registry_attestation._canonical(att["record"]), att["sig"], pubkey)


def test_verify_ignores_json_key_order():
    """HAPPY: JCS canonicalization — a registry that re-serializes the record
    with different key order does not break verification."""
    att = _build()
    reordered = {k: att["record"][k] for k in sorted(att["record"], reverse=True)}
    ok, reason = registry_attestation.verify({"record": reordered, "sig": att["sig"]}, now=NOW + 60)
    assert (ok, reason) == (True, "ok")


# ── EDGE ─────────────────────────────────────────────────────


def test_build_without_keypair_returns_none():
    """EDGE: no signer keypair yet (first boot) — best-effort None, no raise."""
    assert registry_attestation.build("x", "https://e.com", "no-such-signer", now=NOW) is None


def test_ttl_env_override(monkeypatch):
    """EDGE: REGISTRY_ATTESTATION_TTL_S overrides the default window."""
    monkeypatch.setenv("REGISTRY_ATTESTATION_TTL_S", "600")
    att = _build()
    assert att["record"]["expires_at"] == att["record"]["issued_at"] + 600


def test_ttl_env_garbage_falls_back(monkeypatch):
    """EDGE: unparseable TTL env falls back to the default, doesn't raise."""
    monkeypatch.setenv("REGISTRY_ATTESTATION_TTL_S", "not-a-number")
    att = _build()
    assert att["record"]["expires_at"] == att["record"]["issued_at"] + int(
        registry_attestation.DEFAULT_ATTESTATION_TTL_S
    )


# ── FAILURE ──────────────────────────────────────────────────


@pytest.mark.parametrize(
    "attestation",
    [
        None,
        "not-a-dict",
        {},
        {"record": {}, "sig": "x"},
        {"record": "not-a-dict", "sig": "x"},
        {"record": {"v": 1}, "sig": ""},
    ],
)
def test_verify_malformed(attestation):
    """FAILURE: junk shapes are 'malformed', never an exception."""
    ok, reason = registry_attestation.verify(attestation, now=NOW)
    assert (ok, reason) == (False, "malformed")


def test_verify_non_int_timestamps_malformed():
    """FAILURE: string timestamps are rejected as malformed (no coercion)."""
    att = _build()
    att["record"]["expires_at"] = str(att["record"]["expires_at"])
    ok, reason = registry_attestation.verify(att, now=NOW)
    assert (ok, reason) == (False, "malformed")


def test_verify_unsupported_did():
    """FAILURE: a non-did:key (or non-Ed25519) DID is unverifiable offline."""
    att = _build()
    att["record"]["did"] = "did:web:example.com"
    ok, reason = registry_attestation.verify(att, now=NOW)
    assert (ok, reason) == (False, "unsupported_did")


def test_verify_expired():
    """FAILURE: past expires_at the attestation is dead — replay of a captured
    old record ages out."""
    att = _build(ttl_s=300)
    ok, reason = registry_attestation.verify(att, now=NOW + 301)
    assert (ok, reason) == (False, "expired")


# ── ADVERSARIAL ──────────────────────────────────────────────


def test_tampered_endpoint_breaks_signature():
    """ADVERSARIAL: the cheating-registry attack — swap the endpoint to an
    attacker server. The signature must break."""
    att = _build()
    att["record"]["endpoint"] = "https://attacker.example.com"
    ok, reason = registry_attestation.verify(att, now=NOW + 60)
    assert (ok, reason) == (False, "invalid_signature")


def test_tampered_expiry_breaks_signature():
    """ADVERSARIAL: a registry can't extend a stale record's life — expires_at
    is inside the signed material."""
    att = _build(ttl_s=300)
    att["record"]["expires_at"] += 999_999
    ok, reason = registry_attestation.verify(att, now=NOW + 60)
    assert (ok, reason) == (False, "invalid_signature")


def test_swapped_did_breaks_signature():
    """ADVERSARIAL: a registry can't re-bind the record to its own key — the
    DID is inside the signed material, so key-substitution kills the sig."""
    other = sovereign_identity.generate_ed25519_keypair("attacker-org")
    att = _build()
    att["record"]["did"] = sovereign_identity.build_did_key_from_ed25519(other["public_key"])
    try:
        ok, reason = registry_attestation.verify(att, now=NOW + 60)
    finally:
        sovereign_identity._ed25519_keypairs.pop("attacker-org", None)
    assert (ok, reason) == (False, "invalid_signature")


def test_resigned_by_different_key_changes_did():
    """ADVERSARIAL: an attacker who re-signs a tampered record with their own
    key necessarily changes the DID — the record self-identifies its signer,
    which is what DID pinning (verifier side) will catch."""
    att = _build()
    original_did = att["record"]["did"]

    other = sovereign_identity.generate_ed25519_keypair("attacker-org")
    try:
        forged_record = dict(att["record"])
        forged_record["endpoint"] = "https://attacker.example.com"
        forged_record["did"] = sovereign_identity.build_did_key_from_ed25519(other["public_key"])
        forged_sig = sovereign_identity.ed25519_sign(
            registry_attestation._canonical(forged_record), other["private_key"]
        )
        forged = {"record": forged_record, "sig": forged_sig}

        # Internally valid — but it cannot claim the original identity.
        ok, reason = registry_attestation.verify(forged, now=NOW + 60)
        assert (ok, reason) == (True, "ok")
        assert forged_record["did"] != original_did
    finally:
        sovereign_identity._ed25519_keypairs.pop("attacker-org", None)
