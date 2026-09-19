"""Tests for community_member.aae_export.

Mirrors chapter/tests/test_aae_export.py shape — same conversion
contract, same wire format, same prosecution-grade test discipline.

Classification: HAPPY / EDGE / FAILURE / ADVERSARIAL.
"""

from __future__ import annotations

import pytest

from community_member import aae_export


@pytest.fixture
def minimal_receipt() -> dict:
    return {
        "receipt_id": "01HKQXR3P0FX9JT3J6ZW5W3PXP",
        "issuer_did": "did:key:zMember123",
        "principal_did": "did:key:zMember123",
        "issued_at": "2026-05-22T05:00:00Z",
        "action": {
            "category": "intent_submitted",
            "human_summary": "I submitted an intent looking for a co-founder.",
            "outcome": "completed",
        },
        "signature": "AAAA-base64-sig",
    }


@pytest.fixture
def rich_receipt() -> dict:
    return {
        "receipt_id": "01HKR0002",
        "issuer_did": "did:key:zMember123",
        "principal_did": "did:key:zMember123",
        "issued_at": "2026-05-22T06:00:00Z",
        "action": {
            "category": "skill_installed",
            "human_summary": "Installed skill 'climate-policy-summarizer'.",
            "outcome": "completed",
            "counterparty_did": "did:key:zSkillAuthor",
            "counterparty_label": "climate-skills-author",
            "amount": {"value": 5, "currency": "USD"},
            "machine_payload": {"skill_id": "climate-policy-summarizer", "version": "0.3"},
        },
        "jurisdiction": {"iso_3166": ["US-CA"]},
        "accessibility": {"alt_summaries": {"es": "Instalé la habilidad..."}},
        "previous_receipt_hash": "sha256:abcdef",
        "signature": "BBBB-base64-sig",
    }


# HAPPY ───────────────────────────────────────────────────────────


def test_HAPPY_minimal_receipt_maps_correctly(minimal_receipt):
    ev = aae_export.arp_receipt_to_aae_event(minimal_receipt, tenant="alice")
    assert ev["v"] == 1
    assert ev["id"] == minimal_receipt["receipt_id"]
    assert ev["tenant"] == "alice"
    assert ev["type"] == "action"
    assert ev["lifecycle"] == "committed"
    assert ev["topic"] == "sdk.action.intent_submitted"
    assert ev["classification"] == "internal"  # SDK default
    assert ev["actor"]["did"] == minimal_receipt["issuer_did"]
    assert ev["payload"]["subject"]["did"] == minimal_receipt["principal_did"]
    assert ev["payload"]["kind"] == "intent_submitted"
    assert ev["payload"]["human_summary"].startswith("I submitted")


def test_HAPPY_public_flag_classifies_as_public(minimal_receipt):
    ev = aae_export.arp_receipt_to_aae_event(minimal_receipt, tenant="alice", public=True)
    assert ev["classification"] == "public"


def test_HAPPY_rich_receipt_preserves_all_arp_fields(rich_receipt):
    ev = aae_export.arp_receipt_to_aae_event(rich_receipt, tenant="alice")
    p = ev["payload"]
    assert p["counterparty_did"] == rich_receipt["action"]["counterparty_did"]
    assert p["counterparty_label"] == "climate-skills-author"
    assert p["amount"] == {"value": 5, "currency": "USD"}
    assert p["machine_payload"]["skill_id"] == "climate-policy-summarizer"
    assert p["jurisdiction"]["iso_3166"] == ["US-CA"]
    assert p["accessibility"]["alt_summaries"]["es"]
    assert p["previous_receipt_hash"] == "sha256:abcdef"


def test_HAPPY_proof_uses_w3c_di_proof_shape(rich_receipt):
    ev = aae_export.arp_receipt_to_aae_event(rich_receipt, tenant="alice")
    proof = ev["payload"]["proof"]
    assert proof["type"] == "DataIntegrityProof"
    assert proof["cryptosuite"] == "eddsa-jcs-2022"
    assert proof["proofValue"] == rich_receipt["signature"]
    assert proof["verificationMethod"] == rich_receipt["issuer_did"]


def test_HAPPY_topic_differentiates_sdk_from_chapter():
    """SDK receipts use sdk.action.* topic; chapter receipts use
    chapter.action.* (verified in chapter/tests/test_aae_export.py).
    Distinguishing tenant lets downstream consumers filter."""
    minimal = {
        "receipt_id": "x",
        "issuer_did": "did:key:zX",
        "principal_did": "did:key:zX",
        "issued_at": "2026-01-01T00:00:00Z",
        "action": {"category": "foo", "human_summary": "h", "outcome": "completed"},
    }
    ev = aae_export.arp_receipt_to_aae_event(minimal, tenant="alice")
    assert ev["topic"].startswith("sdk.action.")


# EDGE ────────────────────────────────────────────────────────────


def test_EDGE_omits_absent_optional_payload_fields(minimal_receipt):
    ev = aae_export.arp_receipt_to_aae_event(minimal_receipt, tenant="alice")
    p = ev["payload"]
    assert "counterparty_did" not in p
    assert "amount" not in p
    assert "machine_payload" not in p
    assert "jurisdiction" not in p
    assert "accessibility" not in p
    assert "previous_receipt_hash" not in p


def test_EDGE_no_signature_omits_proof_block(minimal_receipt):
    minimal_receipt.pop("signature", None)
    ev = aae_export.arp_receipt_to_aae_event(minimal_receipt, tenant="alice")
    assert "proof" not in ev["payload"]


def test_EDGE_empty_category_falls_back(minimal_receipt):
    minimal_receipt["action"]["category"] = ""
    ev = aae_export.arp_receipt_to_aae_event(minimal_receipt, tenant="alice")
    assert ev["topic"] == "sdk.action"


# FAILURE ────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "broken",
    [
        {},
        {"receipt_id": "x"},
        {  # missing action
            "receipt_id": "x",
            "issuer_did": "did:key:zX",
            "principal_did": "did:key:zX",
            "issued_at": "2026-01-01T00:00:00Z",
        },
    ],
)
def test_FAILURE_malformed_receipt_returns_empty(broken):
    assert aae_export.arp_receipt_to_aae_event(broken, tenant="alice") == {}


def test_FAILURE_non_dict_returns_empty():
    assert aae_export.arp_receipt_to_aae_event("string", tenant="alice") == {}
    assert aae_export.arp_receipt_to_aae_event(None, tenant="alice") == {}
    assert aae_export.arp_receipt_to_aae_event([], tenant="alice") == {}


# Bulk + adversarial ─────────────────────────────────────────────


def test_HAPPY_bulk_preserves_order(minimal_receipt, rich_receipt):
    out = aae_export.arp_receipts_to_aae_events([minimal_receipt, rich_receipt], tenant="alice")
    assert len(out) == 2
    assert out[0]["id"] == minimal_receipt["receipt_id"]
    assert out[1]["id"] == rich_receipt["receipt_id"]


def test_EDGE_bulk_skips_malformed(minimal_receipt):
    out = aae_export.arp_receipts_to_aae_events([minimal_receipt, {}, minimal_receipt], tenant="alice")
    assert len(out) == 2


def test_ADVERSARIAL_hostile_content_passes_through():
    """Hostile content in receipt fields flows through unchanged —
    output-side escaping is the renderer's responsibility, not this
    conversion's."""
    hostile = {
        "receipt_id": "x",
        "issuer_did": "did:key:zX",
        "principal_did": "did:key:zX",
        "issued_at": "2026-01-01T00:00:00Z",
        "action": {
            "category": "decision",
            "human_summary": "<script>alert(1)</script>",
            "outcome": "completed",
            "counterparty_label": "'; DROP TABLE foo;--",
        },
    }
    ev = aae_export.arp_receipt_to_aae_event(hostile, tenant="alice")
    assert ev["v"] == 1
    assert ev["payload"]["human_summary"] == "<script>alert(1)</script>"
    assert ev["payload"]["counterparty_label"] == "'; DROP TABLE foo;--"
