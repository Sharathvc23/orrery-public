"""Tests for ARP receipt → AAE AttestationEvent conversion.

Classification: HAPPY / EDGE / FAILURE / ADVERSARIAL

The conversion is a pure-function adapter (no side effects, no I/O)
so tests exercise the field-by-field mapping discipline directly. The
contract the chapter exposes is the AAE wire shape consumed by
sm-attest-viewer; verifying that contract here prevents drift between
the chapter's emit and the renderer's expectations.
"""

from __future__ import annotations

import os

os.environ.setdefault("AGENT_ID", "test-chapter")
os.environ.setdefault("AGENT_NAME", "Test Chapter")

import pytest

from aae_export import arp_receipt_to_aae_event, arp_receipts_to_aae_events

# ── Fixtures ─────────────────────────────────────────────────────


@pytest.fixture
def minimal_receipt() -> dict:
    return {
        "receipt_id": "01HKQXR3P0FX9JT3J6ZW5W3PXP",
        "issuer_did": "did:key:z6MkmCJAZansQ3p1Qx5KJ9Z5VBs6N3wxc5fpfaY8Y1bdRsZc",
        "principal_did": "did:key:z6MksJa4HRGdv3XEYsT3xH3vJDqfWcLqf8e8nFp8Vz9WnXk1",
        "issued_at": "2026-05-22T01:00:00Z",
        "action": {
            "category": "commitment_entered",
            "human_summary": "Chapter matched your intent with bob.",
            "outcome": "completed",
        },
        "signature": "AAAA-base64-placeholder-AAAA",
    }


@pytest.fixture
def rich_receipt() -> dict:
    return {
        "receipt_id": "01HKR0001",
        "issuer_did": "did:key:z6MkmCJAZansQ3p1Qx5KJ9Z5VBs6N3wxc5fpfaY8Y1bdRsZc",
        "principal_did": "did:key:z6MksJa4HRGdv3XEYsT3xH3vJDqfWcLqf8e8nFp8Vz9WnXk1",
        "issued_at": "2026-05-22T02:00:00Z",
        "action": {
            "category": "decision_made",
            "human_summary": "You approved bob's introduction request.",
            "outcome": "completed",
            "counterparty_did": "did:key:z6MkqL3W7xK5Vq8MnFp9Z9bN4XxRyL8YmKxQyZ5N8tQRgWdN",
            "counterparty_label": "bob",
            "amount": {"value": 25, "currency": "USD"},
            "machine_payload": {"approval_id": "ap-123", "kind": "introduction"},
        },
        "jurisdiction": {
            "iso_3166": ["US-CA"],
            "applicable_regimes": ["CA-CCPA"],
        },
        "accessibility": {
            "alt_summaries": {"es": "Aprobaste la solicitud de introducción de bob."},
        },
        "previous_receipt_hash": "sha256:abcdef0123456789",
        "signature": "BBBB-base64-placeholder-BBBB",
    }


# ══════════════════════════════════════════════════════════════════════
# HAPPY — basic conversion
# ══════════════════════════════════════════════════════════════════════


def test_HAPPY_minimal_receipt_maps_to_well_formed_aae(minimal_receipt):
    ev = arp_receipt_to_aae_event(minimal_receipt, tenant="bayarea-chapter")
    # AAE-standard top-level shape
    assert ev["v"] == 1
    assert ev["id"] == minimal_receipt["receipt_id"]
    assert ev["ts"] == minimal_receipt["issued_at"]
    assert ev["tenant"] == "bayarea-chapter"
    assert ev["type"] == "action"
    assert ev["lifecycle"] == "committed"
    assert ev["topic"] == "chapter.action.commitment_entered"
    assert ev["classification"] == "internal"  # default
    # Actor + subject (AAE-standard)
    assert ev["actor"]["did"] == minimal_receipt["issuer_did"]
    assert ev["actor"]["namespace"] == "did"
    assert ev["payload"]["subject"]["did"] == minimal_receipt["principal_did"]
    assert ev["payload"]["kind"] == "commitment_entered"
    assert ev["payload"]["human_summary"] == "Chapter matched your intent with bob."
    assert ev["payload"]["outcome"] == "completed"


def test_HAPPY_public_flag_classifies_as_public(minimal_receipt):
    ev = arp_receipt_to_aae_event(minimal_receipt, tenant="bayarea", public=True)
    assert ev["classification"] == "public"


def test_HAPPY_rich_receipt_preserves_all_arp_convention_fields(rich_receipt):
    """All ARP-specific fields ride in payload per the chapter's
    documented payload convention."""
    ev = arp_receipt_to_aae_event(rich_receipt, tenant="bayarea")
    p = ev["payload"]
    assert p["kind"] == "decision_made"
    assert p["counterparty_did"] == rich_receipt["action"]["counterparty_did"]
    assert p["counterparty_label"] == "bob"
    assert p["amount"] == {"value": 25, "currency": "USD"}
    assert p["machine_payload"]["approval_id"] == "ap-123"
    assert p["jurisdiction"]["iso_3166"] == ["US-CA"]
    assert p["accessibility"]["alt_summaries"]["es"]
    assert p["previous_receipt_hash"] == "sha256:abcdef0123456789"


def test_HAPPY_proof_block_uses_di_proof_w3c_shape(rich_receipt):
    """The signature maps into AAE's payload.proof block using the
    W3C DataIntegrityProof shape that sm-attest-viewer recognizes."""
    ev = arp_receipt_to_aae_event(rich_receipt, tenant="bayarea")
    proof = ev["payload"]["proof"]
    assert proof["type"] == "DataIntegrityProof"
    assert proof["cryptosuite"] == "eddsa-jcs-2022"
    assert proof["proofValue"] == rich_receipt["signature"]
    assert proof["verificationMethod"] == rich_receipt["issuer_did"]
    assert proof["created"] == rich_receipt["issued_at"]


# ══════════════════════════════════════════════════════════════════════
# EDGE — missing optional fields
# ══════════════════════════════════════════════════════════════════════


def test_EDGE_minimal_receipt_omits_absent_optional_payload_fields(minimal_receipt):
    """Optional ARP fields are NOT serialized as empty/null — they're
    omitted so the payload stays small and consumers don't have to
    null-check every field."""
    ev = arp_receipt_to_aae_event(minimal_receipt, tenant="bayarea")
    p = ev["payload"]
    assert "counterparty_did" not in p
    assert "counterparty_label" not in p
    assert "amount" not in p
    assert "machine_payload" not in p
    assert "jurisdiction" not in p
    assert "accessibility" not in p
    assert "previous_receipt_hash" not in p


def test_EDGE_no_signature_omits_proof_block(minimal_receipt):
    """An unsigned receipt (legitimate during issuance flow) produces
    an AAE event with no payload.proof rather than a proof block with
    null fields."""
    minimal_receipt.pop("signature", None)
    ev = arp_receipt_to_aae_event(minimal_receipt, tenant="bayarea")
    assert "proof" not in ev["payload"]


def test_EDGE_empty_category_falls_back_to_chapter_action_topic(minimal_receipt):
    minimal_receipt["action"]["category"] = ""
    ev = arp_receipt_to_aae_event(minimal_receipt, tenant="bayarea")
    assert ev["topic"] == "chapter.action"


# ══════════════════════════════════════════════════════════════════════
# FAILURE — malformed input returns empty dict (no crash)
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.parametrize(
    "broken_receipt",
    [
        {},  # totally empty
        {"receipt_id": "only-id"},  # missing rest
        {  # missing action
            "receipt_id": "x",
            "issuer_did": "did:key:z",
            "principal_did": "did:key:z",
            "issued_at": "2026-01-01T00:00:00Z",
        },
    ],
)
def test_FAILURE_malformed_receipt_returns_empty(broken_receipt):
    """A malformed receipt should be SKIPPED at the conversion boundary,
    not crash the export endpoint. Caller decides what to do with an
    empty result (usually: log + skip)."""
    ev = arp_receipt_to_aae_event(broken_receipt, tenant="bayarea")
    assert ev == {}


def test_FAILURE_non_dict_action_returns_empty(minimal_receipt):
    minimal_receipt["action"] = "not-a-dict"
    ev = arp_receipt_to_aae_event(minimal_receipt, tenant="bayarea")
    assert ev == {}


def test_FAILURE_non_dict_input_returns_empty():
    assert arp_receipt_to_aae_event("string", tenant="bayarea") == {}
    assert arp_receipt_to_aae_event(None, tenant="bayarea") == {}
    assert arp_receipt_to_aae_event([], tenant="bayarea") == {}


# ══════════════════════════════════════════════════════════════════════
# Bulk conversion
# ══════════════════════════════════════════════════════════════════════


def test_HAPPY_bulk_conversion_preserves_order(minimal_receipt, rich_receipt):
    out = arp_receipts_to_aae_events([minimal_receipt, rich_receipt], tenant="bayarea")
    assert len(out) == 2
    assert out[0]["id"] == minimal_receipt["receipt_id"]
    assert out[1]["id"] == rich_receipt["receipt_id"]


def test_EDGE_bulk_conversion_skips_malformed(minimal_receipt):
    out = arp_receipts_to_aae_events([minimal_receipt, {}, minimal_receipt], tenant="bayarea")
    # The two valid receipts pass; the empty dict is skipped
    assert len(out) == 2


def test_EDGE_bulk_conversion_handles_empty_list():
    assert arp_receipts_to_aae_events([], tenant="bayarea") == []
    assert arp_receipts_to_aae_events(None, tenant="bayarea") == []  # type: ignore


# ══════════════════════════════════════════════════════════════════════
# ADVERSARIAL — hostile field values don't break the shape
# ══════════════════════════════════════════════════════════════════════


def test_ADVERSARIAL_hostile_strings_in_payload_pass_through_unmodified():
    """The conversion is a pure remapping. Hostile content (XSS, SQL,
    null bytes) flows through unchanged — the chapter's existing
    sanitization happens at write-time on the receipt, not here.
    The contract: AAE shape is well-formed regardless of payload content."""
    hostile = {
        "receipt_id": "x",
        "issuer_did": "did:key:z",
        "principal_did": "did:key:z",
        "issued_at": "2026-01-01T00:00:00Z",
        "action": {
            "category": "decision_made",
            "human_summary": "<script>alert(1)</script>",
            "outcome": "completed",
            "counterparty_label": "'; DROP TABLE agents;--",
        },
    }
    ev = arp_receipt_to_aae_event(hostile, tenant="bayarea")
    # Shape is correct — content flows through; renderer is responsible
    # for output-side escaping.
    assert ev["v"] == 1
    assert ev["payload"]["human_summary"] == "<script>alert(1)</script>"
    assert ev["payload"]["counterparty_label"] == "'; DROP TABLE agents;--"
