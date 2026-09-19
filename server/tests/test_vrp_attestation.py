"""VRP 0.2 — chapter issues an AgentFacts Attestation that verifies end-to-end.

Drives the real chapter keypair through ``vrp.attest_facts_record`` and confirms that
``sm_arp.vrp.verify_attestation`` accepts it, that substitution/tamper is caught,
and that an un-keyed chapter degrades to an un-attested (not forged) record.
"""

from __future__ import annotations

import copy

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sm_arp.vrp import verify_attestation


@pytest.fixture
def keyed_chapter():
    import arp as arp_mod
    import sovereign_identity

    sk = Ed25519PrivateKey.from_private_bytes(b"vrp-attest-chapter-seed-32-byte!")
    pk_b = sk.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    sovereign_identity._ed25519_keypairs["test-chapter"] = {
        "private_key": sk.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        ),
        "public_key": pk_b,
    }
    arp_mod.init(pg_request=None, chapter_id="test-chapter", offline=True)
    chapter_did = arp_mod._chapter_keypair_bytes()[1]
    try:
        yield chapter_did
    finally:
        sovereign_identity._ed25519_keypairs.pop("test-chapter", None)


def _facts_with_facet() -> dict:
    return {
        "id": "did:web:chapter.example/alice",
        "agent_name": "Alice",
        "capabilities": {"skills": ["python"]},
        "verifiable_receipts": {
            "ledger_uri": "https://chapter.example/ledgers/alice.json",
            "behavioral_merkle_root": "sha256:" + "cd" * 32,
            "reputation_score": 10.0,
            "validity_rate": 1.0,
            "receipt_count": 2,
            "scoring_method": "nanda-rep/0.1",
            "as_of": "2026-06-08T00:00:00Z",
        },
    }


def test_chapter_attestation_round_trips(keyed_chapter):
    """HAPPY: the chapter signs, the vendored verifier accepts, attested_by == chapter."""
    import vrp as vrp_mod

    facts = _facts_with_facet()
    vrp_mod.attest_facts_record(facts, as_of="2026-06-08T00:00:00Z", version=3)

    assert facts["attestation"]["attested_by"] == keyed_chapter
    assert facts["attestation"]["version"] == 3
    v = verify_attestation(facts)
    assert v.ok and v.stage == "accepted", v


def test_chapter_attestation_catches_ledger_substitution(keyed_chapter):
    """ADVERSARIAL: repoint the facet after the chapter signed → rejected."""
    import vrp as vrp_mod

    facts = _facts_with_facet()
    vrp_mod.attest_facts_record(facts, as_of="2026-06-08T00:00:00Z")
    facts["verifiable_receipts"]["ledger_uri"] = "https://evil.example/inflated.json"
    assert not verify_attestation(facts).ok


def test_chapter_attestation_catches_identity_swap(keyed_chapter):
    """ADVERSARIAL: move a chapter-signed attestation onto another agent's card → rejected."""
    import vrp as vrp_mod

    facts = _facts_with_facet()
    vrp_mod.attest_facts_record(facts, as_of="2026-06-08T00:00:00Z")
    victim = copy.deepcopy(facts)
    victim["id"] = "did:web:chapter.example/mallory"
    assert not verify_attestation(victim).ok


def test_min_version_floor(keyed_chapter):
    import vrp as vrp_mod

    facts = _facts_with_facet()
    vrp_mod.attest_facts_record(facts, as_of="2026-06-08T00:00:00Z", version=2)
    assert verify_attestation(facts, min_version=2).ok
    assert not verify_attestation(facts, min_version=5).ok


def test_real_card_attests_across_json_serialization_boundary(keyed_chapter):
    """INTEGRATION: the discriminating test — a card from the REAL build_nanda_facts,
    with a facet attached as the endpoint does, attests AND survives the exact
    json.dumps -> json.loads boundary the endpoint serves over, then verifies.

    Catches (a) any non-JCS-serializable field in the real card (would make
    attest_facts_record raise → un-attested federation-wide, silently) and (b) any
    JCS divergence across the JSON round-trip (would make every facts_digest fail in
    production). In-memory-dict tests cannot surface either.
    """
    import json

    import sovereign_identity
    import vrp as vrp_mod

    member = {
        "name": "Alice Chen",
        "description": "Full-stack engineer in distributed systems",
        "skills": ["python", "rust", "kubernetes", "distributed-systems"],
    }
    facts = sovereign_identity.build_nanda_facts(
        "alice",
        member,
        public_key="abc123",
        public_url="https://test-chapter.example.com",
        evaluations={"performanceScore": 4.2, "totalInteractions": 150, "avgResponseTimeMs": 85.5},
        telemetry={"latency_p50_ms": 45.0, "latency_p99_ms": 200.0, "error_rate_pct": 0.5},
    )
    # The endpoint attaches the facet, then attests LAST.
    facts["verifiable_receipts"] = {
        "ledger_uri": "https://test-chapter.example.com/api/receipts/ledger/did:key:zAlice",
        "behavioral_merkle_root": "sha256:" + "ab" * 32,
        "reputation_score": 15.0,
        "validity_rate": 1.0,
        "receipt_count": 3,
        "scoring_method": "nanda-rep/0.1",
        "as_of": "2026-06-08T00:00:00Z",
    }
    vrp_mod.attest_facts_record(facts, version=int(facts.get("facts_version", 1)))
    assert "attestation" in facts, "real card failed to attest — a non-serializable field?"

    # The exact boundary the endpoint serves over (JSONResponse → wire → resolver).
    served = json.loads(json.dumps(facts))
    v = verify_attestation(served)
    assert v.ok and v.stage == "accepted", v

    # And substitution is still caught after the round-trip.
    served["verifiable_receipts"]["behavioral_merkle_root"] = "sha256:" + "00" * 32
    assert not verify_attestation(served).ok


def test_unkeyed_chapter_degrades_to_unattested():
    """FAILURE-safe: no chapter keypair → record returned un-attested, never forged."""
    import arp as arp_mod
    import sovereign_identity
    import vrp as vrp_mod

    sovereign_identity._ed25519_keypairs.pop("test-chapter", None)
    arp_mod.init(pg_request=None, chapter_id="test-chapter", offline=True)

    facts = _facts_with_facet()
    out = vrp_mod.attest_facts_record(facts)
    assert "attestation" not in out
    # A facet with no attestation is unverifiable standing (rejected), not zero.
    assert verify_attestation(out).stage == "attestation_missing"
