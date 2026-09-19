"""ARP v0.1 conformance vector generator.

One-shot tool. Run from repo root to regenerate every vector in
``vectors/arp/0.1/``. Vectors are deterministic: keypairs are seeded
from fixed bytes so re-running this script produces byte-identical
vector files (modulo file ordering on disk).

The vectors exercise:
  - Every core action category
  - Optional sub-objects (evidence, jurisdiction, accessibility)
  - Hash-chain semantics (genesis + linked)
  - Reversal flow
  - Forward-compatibility (extensions, unknown category in tolerant mode)
  - Negative cases (tampered signature, broken chain, oversized summary,
    invalid version, invalid DID)

Each output file is a JSON document with this shape::

    {
      "id":               "<vector-id>",
      "description":      "<one-line>",
      "spec_ref":         "<section refs>",
      "expected_outcome": "verify_pass" | "schema_fail" | "signature_fail"
                          | "hash_chain_fail" | "version_unsupported"
                          | "tolerant_pass_strict_fail",
      "verifier_mode":    "strict" | "tolerant",
      "private_keys":     { issuer, principal }   # Ed25519 seed bytes b64,
                                                  # included so verifiers can
                                                  # reproduce or build variants
      "receipt":          { ... }                  # the receipt under test
    }

Usage::

    python conformance/arp/_vector_gen.py

Outputs to ``vectors/arp/0.1/``.
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path

import jcs
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

# Reproducible seeds — both 32 bytes
ISSUER_SEED = b"arp-vector-issuer-seed-32bytes!!"
PRINCIPAL_SEED = b"arp-vector-principal-seed-32by!!"
WITNESS_SEED = b"arp-vector-witness-seed-32bytes!"
COUNTERPARTY_SEED = b"arp-vector-counterparty-seed32b!"

assert len(ISSUER_SEED) == 32
assert len(PRINCIPAL_SEED) == 32
assert len(WITNESS_SEED) == 32
assert len(COUNTERPARTY_SEED) == 32


# ── crypto helpers ─────────────────────────────────────────────────


def keypair(seed: bytes) -> tuple[Ed25519PrivateKey, bytes]:
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    pk_bytes = sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return sk, pk_bytes


def did_key_from_pubkey(pk_bytes: bytes) -> str:
    """W3C did:key — multibase z-base58btc over multicodec 0xed01 ‖ pubkey32."""
    import base58

    prefixed = b"\xed\x01" + pk_bytes
    return "did:key:z" + base58.b58encode(prefixed).decode("ascii")


def sign_receipt(sk: Ed25519PrivateKey, receipt: dict) -> dict:
    """JCS-canonicalize the receipt sans-signature, Ed25519-sign, attach b64 sig."""
    body = {k: v for k, v in receipt.items() if k != "signature"}
    canonical = jcs.canonicalize(body)
    sig_bytes = sk.sign(canonical)
    assert len(sig_bytes) == 64
    receipt["signature"] = base64.b64encode(sig_bytes).decode("ascii")
    return receipt


def receipt_hash_chain_link(receipt: dict) -> str:
    """sha256: hash of the full canonical receipt (including signature) — input to
    the next receipt's previous_receipt_hash."""
    canonical = jcs.canonicalize(receipt)
    digest = hashlib.sha256(canonical).hexdigest()
    return f"sha256:{digest}"


# ── identities ─────────────────────────────────────────────────────

ISSUER_SK, ISSUER_PK = keypair(ISSUER_SEED)
PRINCIPAL_SK, PRINCIPAL_PK = keypair(PRINCIPAL_SEED)
WITNESS_SK, WITNESS_PK = keypair(WITNESS_SEED)
COUNTERPARTY_SK, COUNTERPARTY_PK = keypair(COUNTERPARTY_SEED)

ISSUER_DID = did_key_from_pubkey(ISSUER_PK)
PRINCIPAL_DID = did_key_from_pubkey(PRINCIPAL_PK)
COUNTERPARTY_DID = did_key_from_pubkey(COUNTERPARTY_PK)
WITNESS_DID = did_key_from_pubkey(WITNESS_PK)


def keys_b64() -> dict:
    return {
        "issuer": base64.b64encode(ISSUER_SEED).decode("ascii"),
        "principal": base64.b64encode(PRINCIPAL_SEED).decode("ascii"),
    }


# ── vector builders ────────────────────────────────────────────────

OUTPUT_DIR = Path(__file__).resolve().parent.parent.parent / "vectors" / "arp" / "0.1"


def emit(
    name: str,
    description: str,
    spec_ref: str,
    expected_outcome: str,
    receipt: dict,
    verifier_mode: str = "strict",
) -> None:
    path = OUTPUT_DIR / f"{name}.json"
    body = {
        "id": name,
        "description": description,
        "spec_ref": spec_ref,
        "expected_outcome": expected_outcome,
        "verifier_mode": verifier_mode,
        "private_keys": keys_b64(),
        "receipt": receipt,
    }
    path.write_text(json.dumps(body, indent=2, ensure_ascii=False) + "\n")
    print(f"  wrote {path.relative_to(OUTPUT_DIR.parent.parent.parent)}")


def base_receipt(
    *,
    receipt_id: str,
    issued_at: str,
    category: str,
    human_summary: str,
    outcome: str = "completed",
    **extras: object,
) -> dict:
    r: dict = {
        "version": "arp/0.1",
        "receipt_id": receipt_id,
        "issuer_did": ISSUER_DID,
        "principal_did": PRINCIPAL_DID,
        "issued_at": issued_at,
        "action": {
            "category": category,
            "human_summary": human_summary,
            "outcome": outcome,
        },
    }
    r.update(extras)
    return r


# ── individual vectors ─────────────────────────────────────────────


def vector_01_basic_purchase() -> None:
    r = base_receipt(
        receipt_id="11111111-1111-4111-8111-111111111111",
        issued_at="2026-05-21T14:23:01Z",
        category="purchase",
        human_summary="Bought 2 tickets to The Substance at AMC Boston Common 19, $34.50.",
    )
    r["action"]["counterparty_did"] = COUNTERPARTY_DID
    r["action"]["counterparty_label"] = "AMC Boston Common 19"
    r["action"]["amount"] = {"currency": "USD", "cents": -3450}
    sign_receipt(ISSUER_SK, r)
    emit(
        "01-basic-purchase",
        "Simple purchase, required fields plus counterparty + amount. Strict pass.",
        "spec.md §3, §4.3",
        "verify_pass",
        r,
    )


def vector_02_purchase_full() -> None:
    """Purchase with every optional sub-object populated."""
    r = base_receipt(
        receipt_id="22222222-2222-4222-8222-222222222222",
        issued_at="2026-05-21T14:30:00Z",
        category="purchase",
        human_summary="Booked a haircut at Supercuts Brookline for May 28 at 3pm, $35.",
    )
    r["action"].update(
        {
            "counterparty_did": COUNTERPARTY_DID,
            "counterparty_label": "Supercuts Brookline",
            "amount": {"currency": "USD", "cents": -3500},
            "machine_payload": {
                "booking_ref": "SC-998877",
                "scheduled_for": "2026-05-28T15:00:00-04:00",
            },
        }
    )
    r["authority_chain"] = [f"dat:{PRINCIPAL_DID}:personal-services-budget-q2"]
    r["evidence"] = {
        "external_refs": ["SC-998877"],
        "prompt_lineage_hash": "sha256:" + "a" * 64,
    }
    r["jurisdiction"] = {
        "principal_residence": "US-MA",
        "action_locus": "US-MA",
        "applicable_regimes": ["ccpa"],
    }
    r["accessibility"] = {
        "summary_language": "en-US",
        "complexity_level": "simple",
        "requires_review": False,
    }
    sign_receipt(ISSUER_SK, r)
    emit(
        "02-purchase-full",
        "Purchase with every optional sub-object populated. Strict pass.",
        "spec.md §3, §4, §5, §7, §8, §9",
        "verify_pass",
        r,
    )


def vector_03_message_sent() -> None:
    r = base_receipt(
        receipt_id="33333333-3333-4333-8333-333333333333",
        issued_at="2026-05-21T15:00:00Z",
        category="message_sent",
        human_summary="Sent a reply to Maria Hopper confirming the Friday meeting at 4pm.",
    )
    r["action"]["counterparty_did"] = COUNTERPARTY_DID
    r["action"]["counterparty_label"] = "Maria Hopper"
    sign_receipt(ISSUER_SK, r)
    emit(
        "03-message-sent",
        "message_sent category, no amount, with counterparty.",
        "spec.md §4.3",
        "verify_pass",
        r,
    )


def vector_04_data_shared_gdpr() -> None:
    r = base_receipt(
        receipt_id="44444444-4444-4444-8444-444444444444",
        issued_at="2026-05-21T15:15:00Z",
        category="data_shared",
        human_summary=(
            "Shared your address and dietary preferences with The Bakery Co for catering."
        ),
    )
    r["action"]["counterparty_label"] = "The Bakery Co"
    r["action"]["machine_payload"] = {
        "fields_shared": ["postal_address", "dietary_preferences"],
        "purpose": "catering_order_fulfillment",
    }
    r["jurisdiction"] = {
        "principal_residence": "DE-BY",
        "action_locus": "DE-BY",
        "data_residency": ["DE", "IE"],
        "applicable_regimes": ["gdpr"],
        "consent_evidence_hash": "sha256:" + "b" * 64,
    }
    r["accessibility"] = {
        "summary_language": "en-US",
        "alt_summaries": [
            {
                "lang": "de-DE",
                "summary": (
                    "Ihre Adresse und Ernährungspräferenzen wurden für das "
                    "Catering an The Bakery Co weitergegeben."
                ),
            }
        ],
        "complexity_level": "moderate",
        "requires_review": True,
    }
    sign_receipt(ISSUER_SK, r)
    emit(
        "04-data-shared-gdpr",
        "data_shared with GDPR applicable_regimes, data_residency, multilingual.",
        "spec.md §4.3, §8, §9",
        "verify_pass",
        r,
    )


def vector_05_attestation_issued() -> None:
    r = base_receipt(
        receipt_id="55555555-5555-4555-8555-555555555555",
        issued_at="2026-05-21T15:30:00Z",
        category="attestation_issued",
        human_summary=(
            "Issued an attestation that Tess Devereux is an active member of the Boston chapter."
        ),
    )
    r["action"]["counterparty_did"] = COUNTERPARTY_DID
    r["action"]["counterparty_label"] = "Tess Devereux"
    r["action"]["machine_payload"] = {
        "attestation_type": "chapter_membership",
        "attested_chapter": "boston-chapter",
        "validity_window_days": 365,
    }
    sign_receipt(ISSUER_SK, r)
    emit(
        "05-attestation-issued",
        "attestation_issued category — trust-graph operation.",
        "spec.md §4.3",
        "verify_pass",
        r,
    )


def vector_06_vote_cast() -> None:
    r = base_receipt(
        receipt_id="66666666-6666-4666-8666-666666666666",
        issued_at="2026-05-21T15:45:00Z",
        category="vote_cast",
        human_summary=(
            "Voted YES on the proposal to extend the federation peering window to 12 minutes."
        ),
    )
    r["action"]["machine_payload"] = {
        "proposal_id": "PROP-2026-014",
        "choice": "yes",
        "tally_chapter": "bayarea-nanda-chapter",
    }
    r["jurisdiction"] = {
        "principal_residence": "US-CA",
        "action_locus": "US-CA",
    }
    sign_receipt(ISSUER_SK, r)
    emit(
        "06-vote-cast",
        "vote_cast in a chapter governance poll.",
        "spec.md §4.3",
        "verify_pass",
        r,
    )


def vector_07_decision_made() -> None:
    r = base_receipt(
        receipt_id="77777777-7777-4777-8777-777777777777",
        issued_at="2026-05-21T16:00:00Z",
        category="decision_made",
        human_summary=(
            "Declined the Boston conference invitation in favor of the family commitment."
        ),
    )
    r["action"]["machine_payload"] = {
        "options": ["accept_boston_conf", "decline_boston_conf"],
        "choice": "decline_boston_conf",
        "rationale": "calendar_conflict",
    }
    sign_receipt(ISSUER_SK, r)
    emit(
        "07-decision-made",
        "decision_made with explicit choice + rationale in machine_payload.",
        "spec.md §4.3",
        "verify_pass",
        r,
    )


def vector_08_record_filed() -> None:
    r = base_receipt(
        receipt_id="88888888-8888-4888-8888-888888888888",
        issued_at="2026-05-21T16:15:00Z",
        category="record_filed",
        human_summary="Filed Form W-9 with Acme Robotics for the consulting engagement.",
    )
    r["action"]["counterparty_label"] = "Acme Robotics, Inc."
    r["action"]["machine_payload"] = {
        "form_id": "IRS-W9",
        "tax_year": 2026,
    }
    r["jurisdiction"] = {
        "principal_residence": "US-MA",
        "action_locus": "US",
        "applicable_regimes": ["irs"],
    }
    r["accessibility"] = {
        "summary_language": "en-US",
        "complexity_level": "complex",
        "requires_review": True,
    }
    sign_receipt(ISSUER_SK, r)
    emit(
        "08-record-filed",
        "record_filed (tax form) with jurisdiction and requires_review.",
        "spec.md §4.3, §8, §9",
        "verify_pass",
        r,
    )


def vector_09_appointment_booked() -> None:
    r = base_receipt(
        receipt_id="99999999-9999-4999-8999-999999999999",
        issued_at="2026-05-21T16:30:00Z",
        category="appointment_booked",
        human_summary="Booked a dental cleaning at Brookline Dental for June 4 at 10am.",
    )
    r["action"]["counterparty_label"] = "Brookline Dental"
    r["action"]["machine_payload"] = {
        "scheduled_for": "2026-06-04T10:00:00-04:00",
        "duration_minutes": 60,
    }
    sign_receipt(ISSUER_SK, r)
    emit(
        "09-appointment-booked",
        "appointment_booked with scheduled_for in machine_payload.",
        "spec.md §4.3",
        "verify_pass",
        r,
    )


def vector_10_reversal() -> None:
    """A purchase reversal that references vector 01."""
    r = base_receipt(
        receipt_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        issued_at="2026-05-21T17:00:00Z",
        category="purchase",
        human_summary="Refunded the AMC Boston Common 19 ticket purchase ($34.50).",
        outcome="reversed",
    )
    r["action"]["counterparty_did"] = COUNTERPARTY_DID
    r["action"]["counterparty_label"] = "AMC Boston Common 19"
    r["action"]["amount"] = {"currency": "USD", "cents": 3450}
    r["action"]["reversal_of_receipt_id"] = "11111111-1111-4111-8111-111111111111"
    sign_receipt(ISSUER_SK, r)
    emit(
        "10-reversal",
        "Reversal receipt — outcome=reversed, points to vector 01 via reversal_of_receipt_id.",
        "spec.md §4.2",
        "verify_pass",
        r,
    )


def vector_11_chain_genesis() -> dict:
    """First receipt in a hash chain — no previous_receipt_hash."""
    r = base_receipt(
        receipt_id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb1",
        issued_at="2026-05-21T17:30:00Z",
        category="message_sent",
        human_summary="Sent reminder to your team about the Friday review.",
    )
    sign_receipt(ISSUER_SK, r)
    emit(
        "11-chain-genesis",
        "First receipt in a hash chain — previous_receipt_hash absent.",
        "spec.md §6.4",
        "verify_pass",
        r,
    )
    return r


def vector_12_chain_linked(prior: dict) -> None:
    """Second receipt in a hash chain — previous_receipt_hash points to prior."""
    chain_link = receipt_hash_chain_link(prior)
    r = base_receipt(
        receipt_id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb2",
        issued_at="2026-05-21T17:31:00Z",
        category="message_sent",
        human_summary="Sent follow-up to your team about Friday agenda items.",
    )
    r["previous_receipt_hash"] = chain_link
    sign_receipt(ISSUER_SK, r)
    emit(
        "12-chain-linked",
        "Linked receipt — previous_receipt_hash matches vector 11's canonical hash.",
        "spec.md §6.4",
        "verify_pass",
        r,
    )


def vector_13_multilang_summary() -> None:
    r = base_receipt(
        receipt_id="cccccccc-cccc-4ccc-8ccc-cccccccccccc",
        issued_at="2026-05-21T18:00:00Z",
        category="message_sent",
        human_summary="Replied to Akira Tanaka thanking them for the robotics demo invitation.",
    )
    r["accessibility"] = {
        "summary_language": "en-US",
        "alt_summaries": [
            {
                "lang": "ja-JP",
                "summary": "田中明さんにロボティクスデモへのご招待のお礼を返信しました。",
            },
            {
                "lang": "es-MX",
                "summary": (
                    "Respondiste a Akira Tanaka agradeciéndole la invitación "
                    "a la demostración de robótica."
                ),
            },
        ],
        "complexity_level": "simple",
    }
    sign_receipt(ISSUER_SK, r)
    emit(
        "13-multilang-summary",
        "Accessibility with alt_summaries in two non-English locales.",
        "spec.md §9.2",
        "verify_pass",
        r,
    )


def vector_14_requires_review() -> None:
    r = base_receipt(
        receipt_id="dddddddd-dddd-4ddd-8ddd-dddddddddddd",
        issued_at="2026-05-21T18:15:00Z",
        category="purchase",
        human_summary="Purchased a $1,250 plane ticket: Boston → Tokyo, June 12 outbound.",
    )
    r["action"]["amount"] = {"currency": "USD", "cents": -125000}
    r["action"]["counterparty_label"] = "JAL Airlines"
    r["action"]["counterparty_did"] = COUNTERPARTY_DID
    r["accessibility"] = {
        "summary_language": "en-US",
        "complexity_level": "complex",
        "requires_review": True,
        "screen_reader_hints": {"priority": "notable"},
    }
    sign_receipt(ISSUER_SK, r)
    emit(
        "14-requires-review",
        "High-value purchase flagged requires_review=true with screen-reader priority.",
        "spec.md §9",
        "verify_pass",
        r,
    )


def vector_15_with_tool_invocations() -> None:
    r = base_receipt(
        receipt_id="eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
        issued_at="2026-05-21T18:30:00Z",
        category="purchase",
        human_summary="Bought 1 dozen organic eggs from FreshGrocer for $7.99.",
    )
    r["action"]["amount"] = {"currency": "USD", "cents": -799}
    r["action"]["counterparty_label"] = "FreshGrocer"
    r["evidence"] = {
        "tool_invocations": [
            {
                "tool_did": COUNTERPARTY_DID,
                "mcp_server_uri": "https://mcp.freshgrocer.example/v1",
                "request_hash": "sha256:" + "c" * 64,
                "response_hash": "sha256:" + "d" * 64,
                "timestamp": "2026-05-21T18:29:55Z",
            }
        ]
    }
    sign_receipt(ISSUER_SK, r)
    emit(
        "15-with-tool-invocations",
        "Purchase with MCP tool_invocations recorded in evidence.",
        "spec.md §5",
        "verify_pass",
        r,
    )


def vector_16_invalid_signature() -> None:
    """Tamper the body after signing — signature verification MUST fail."""
    r = base_receipt(
        receipt_id="ffffffff-ffff-4fff-8fff-ffffffffffff",
        issued_at="2026-05-21T19:00:00Z",
        category="purchase",
        human_summary="Bought a coffee at Pavement Coffeehouse for $4.25.",
    )
    r["action"]["amount"] = {"currency": "USD", "cents": -425}
    sign_receipt(ISSUER_SK, r)
    # Now tamper: change the amount AFTER signing
    r["action"]["amount"]["cents"] = -42500
    emit(
        "16-invalid-signature",
        "Body tampered after signing (amount changed from -$4.25 to -$425).",
        "spec.md §6.3 step 5",
        "signature_fail",
        r,
    )


def vector_17_wrong_version() -> None:
    r = base_receipt(
        receipt_id="01010101-0101-4101-8101-010101010101",
        issued_at="2026-05-21T19:15:00Z",
        category="message_sent",
        human_summary="Sent a message.",
    )
    r["version"] = "arp/0.0"  # invalid for v0.1
    sign_receipt(ISSUER_SK, r)
    emit(
        "17-wrong-version",
        "version='arp/0.0' is not accepted by v0.1 verifiers — schema fails.",
        "spec.md §3.1, §12.3",
        "schema_fail",
        r,
    )


def vector_18_oversized_summary() -> None:
    r = base_receipt(
        receipt_id="02020202-0202-4202-8202-020202020202",
        issued_at="2026-05-21T19:30:00Z",
        category="message_sent",
        human_summary="x" * 281,  # 281 > 280 maxLength
    )
    sign_receipt(ISSUER_SK, r)
    emit(
        "18-oversized-summary",
        "human_summary exceeds 280-character limit — schema fails.",
        "spec.md §4.1",
        "schema_fail",
        r,
    )


def vector_19_broken_hash_chain() -> None:
    """previous_receipt_hash declared but doesn't match vector-11."""
    r = base_receipt(
        receipt_id="03030303-0303-4303-8303-030303030303",
        issued_at="2026-05-21T19:45:00Z",
        category="message_sent",
        human_summary="A message that claims to be in vector 11's chain but isn't.",
    )
    # Use a hash that does NOT correspond to any prior real receipt
    r["previous_receipt_hash"] = "sha256:" + "0" * 64
    sign_receipt(ISSUER_SK, r)
    emit(
        "19-broken-hash-chain",
        "previous_receipt_hash present but doesn't match any real prior receipt.",
        "spec.md §6.4, §11.3",
        "hash_chain_fail",
        r,
        verifier_mode="strict",
    )


def vector_20_invalid_did() -> None:
    r = base_receipt(
        receipt_id="04040404-0404-4404-8404-040404040404",
        issued_at="2026-05-21T20:00:00Z",
        category="message_sent",
        human_summary="A message with a malformed issuer_did.",
    )
    sign_receipt(ISSUER_SK, r)
    # Corrupt the DID AFTER signing (so this would fail twice — DID format + sig
    # against a valid pubkey that doesn't match the corrupt DID). The schema
    # check catches it before signature.
    r["issuer_did"] = "did:web:not-a-key:invalid"
    emit(
        "20-invalid-did",
        "issuer_did is not a valid did:key — schema fails before signature check.",
        "spec.md §3.3",
        "schema_fail",
        r,
    )


def vector_21_unknown_extension_tolerant() -> None:
    r = base_receipt(
        receipt_id="05050505-0505-4505-8505-050505050505",
        issued_at="2026-05-21T20:15:00Z",
        category="message_sent",
        human_summary="A message with a namespace-prefixed extension key.",
    )
    r["extensions"] = {
        "arp.example.org.experiment-arm": "treatment-b",
        "acme.example.workflow-id": "WF-12345",
    }
    sign_receipt(ISSUER_SK, r)
    emit(
        "21-unknown-extension",
        "Namespace-prefixed extensions present. Tolerant + strict verifiers both pass.",
        "spec.md §12.1",
        "verify_pass",
        r,
    )


def vector_22_unknown_category_tolerant() -> None:
    """Use category='other' with action_type_label — both modes pass."""
    r = base_receipt(
        receipt_id="06060606-0606-4606-8606-060606060606",
        issued_at="2026-05-21T20:30:00Z",
        category="other",
        human_summary="Performed a custom workflow step: archive-quarterly-snapshot.",
    )
    r["action"]["machine_payload"] = {
        "action_type_label": "archive_quarterly_snapshot",
        "snapshot_id": "Q2-2026",
    }
    sign_receipt(ISSUER_SK, r)
    emit(
        "22-unknown-category-tolerant",
        "category='other' with machine_payload.action_type_label — required for 'other'.",
        "spec.md §4.3, §12.2",
        "verify_pass",
        r,
    )


def main() -> int:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    print(f"Generating ARP v0.1 conformance vectors in {OUTPUT_DIR}\n")
    print(f"Issuer DID:    {ISSUER_DID}")
    print(f"Principal DID: {PRINCIPAL_DID}\n")

    vector_01_basic_purchase()
    vector_02_purchase_full()
    vector_03_message_sent()
    vector_04_data_shared_gdpr()
    vector_05_attestation_issued()
    vector_06_vote_cast()
    vector_07_decision_made()
    vector_08_record_filed()
    vector_09_appointment_booked()
    vector_10_reversal()
    chain_genesis = vector_11_chain_genesis()
    vector_12_chain_linked(chain_genesis)
    vector_13_multilang_summary()
    vector_14_requires_review()
    vector_15_with_tool_invocations()
    vector_16_invalid_signature()
    vector_17_wrong_version()
    vector_18_oversized_summary()
    vector_19_broken_hash_chain()
    vector_20_invalid_did()
    vector_21_unknown_extension_tolerant()
    vector_22_unknown_category_tolerant()

    print("\nDone. 22 vectors generated.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
