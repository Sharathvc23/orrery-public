"""VRP 0.2 — member-as-resolver verifies a presented AgentFacts trust binding.

The member receives another agent's AgentFacts record and must decide whether its
advertised standing is genuinely that agent's, over an un-substituted ledger, before
trusting it. ``verify_presented_facts`` is that binding check.
"""

from __future__ import annotations

import base64
import copy

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sm_arp.vrp import build_attestation, did_key_from_pubkey

from community_member.ledger import verify_presented_facts

_AUTHORITY_SEED = bytes(range(7, 39))
_AS_OF = "2026-06-08T00:00:00Z"


def _authority_did() -> str:
    pub = Ed25519PrivateKey.from_private_bytes(_AUTHORITY_SEED).public_key().public_bytes_raw()
    return did_key_from_pubkey(pub)


def _presented_facts() -> dict:
    record = {
        "id": "did:web:other-chapter.example/bob",
        "agent_name": "Bob",
        "capabilities": {"skills": ["negotiation"]},
        "verifiable_receipts": {
            "ledger_uri": "https://other-chapter.example/ledgers/bob.json",
            "behavioral_merkle_root": "sha256:" + "ef" * 32,
            "reputation_score": 20.0,
            "validity_rate": 1.0,
            "receipt_count": 4,
            "scoring_method": "nanda-rep/0.1",
            "as_of": _AS_OF,
        },
    }
    record["attestation"] = build_attestation(
        facts_record=record, signing_key_bytes=_AUTHORITY_SEED, as_of=_AS_OF, version=1
    )
    return record


def test_resolver_accepts_well_formed_binding():
    """HAPPY: a correctly-signed presented record passes the binding check."""
    v = verify_presented_facts(_presented_facts())
    assert v.ok and v.stage == "accepted", v
    assert _presented_facts()["attestation"]["attested_by"] == _authority_did()


def test_resolver_rejects_ledger_substitution():
    """ADVERSARIAL: a presenter repoints its ledger_uri to inflate → rejected."""
    record = _presented_facts()
    record["verifiable_receipts"]["ledger_uri"] = "https://attacker.example/fat-ledger.json"
    assert not verify_presented_facts(record).ok


def test_resolver_rejects_borrowed_standing():
    """ADVERSARIAL: attach a real binding to a different agent's card → rejected."""
    genuine = _presented_facts()
    impostor = copy.deepcopy(genuine)
    impostor["id"] = "did:web:attacker.example/eve"
    assert not verify_presented_facts(impostor).ok


def test_resolver_rejects_unsigned_standing():
    """FAILURE: a facet with no attestation is unverifiable, not trusted."""
    record = _presented_facts()
    del record["attestation"]
    assert verify_presented_facts(record).stage == "attestation_missing"


def test_resolver_rejects_tampered_signature():
    record = _presented_facts()
    sig = bytearray(base64.b64decode(record["attestation"]["signature"]))
    sig[-1] ^= 0x01
    record["attestation"]["signature"] = base64.b64encode(bytes(sig)).decode()
    assert verify_presented_facts(record).stage == "attestation_invalid"


def test_resolver_version_floor():
    record = _presented_facts()
    assert verify_presented_facts(record, min_version=1).ok
    assert not verify_presented_facts(record, min_version=2).ok


@pytest.mark.parametrize("missing", ["agent_name", "capabilities"])
def test_resolver_rejects_metadata_tamper(missing):
    """ADVERSARIAL: strip/alter any covered metadata field after signing → rejected."""
    record = _presented_facts()
    record.pop(missing, None)
    assert not verify_presented_facts(record).ok
