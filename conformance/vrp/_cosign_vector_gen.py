"""Co-sign handshake conformance vector generator.

One-shot tool. Run from repo root to regenerate
``vectors/arp/0.2/cosign-handshake.json``. Deterministic: every keypair is
seeded from fixed bytes, so re-running produces a byte-identical file.

The vectors exercise the live co-sign handshake specified in
``spec/arp/0.2/cosign-companion.md`` and corroboration per VRP 0.3 §A:

  - happy-inline-cosign       — §1 inline co-sign → ARP-valid AND corroborated
  - decline-uncorroborated    — §3 no witness → ARP-valid, NOT corroborated, not an error
  - forged-witness-wrong-signer — §1/§4 witness_did claims B but a different key signed
  - witness-by-third-party    — §2 a non-counterparty co-signer does not corroborate
  - brokered-equivalence      — §4 brokered entry is byte-identical to the inline entry

Every receipt is finalized in the normative order (witness inserted BEFORE the
issuer signs), so each vector is a fully-formed ARP receipt: ``conformance/arp``
can verify the issuer signature and ``conformance/vrp`` can check corroboration.

Usage::

    python conformance/vrp/_cosign_vector_gen.py

Outputs to ``vectors/arp/0.2/cosign-handshake.json``.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

import jcs
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from conformance.vrp import (
    cosign_receipt,
    did_key_from_pubkey,
)

# Deterministic actors. A = issuer/actor, B = counterparty, C = unrelated third party,
# CHAPTER = brokering chapter (relay only, must never appear as witness_did).
_SEED = {"A": 1, "B": 2, "C": 3, "CHAPTER": 9}


def _sk(name: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes([_SEED[name]]) * 32)


def _did(name: str) -> str:
    return did_key_from_pubkey(_sk(name).public_key().public_bytes_raw())


def _seed_b64(name: str) -> str:
    return base64.b64encode(bytes([_SEED[name]]) * 32).decode("ascii")


# Deterministic UUID-v4 receipt ids (the ARP schema requires UUID-v4 shape). Keyed by the
# short case tag so re-running the generator is byte-stable.
_RID = {
    "c1": "c0510001-0000-4000-8000-000000000001",
    "c2": "c0510002-0000-4000-8000-000000000002",
    "c3": "c0510003-0000-4000-8000-000000000003",
    "c4": "c0510004-0000-4000-8000-000000000004",
    "c5": "c0510005-0000-4000-8000-000000000005",
}


def _base_receipt(rid: str) -> dict[str, Any]:
    """An unsigned, un-witnessed receipt by A naming B as counterparty."""
    return {
        "version": "arp/0.2",
        "receipt_id": _RID[rid],
        "issuer_did": _did("A"),
        "principal_did": _did("A"),
        "issued_at": "2026-06-08T00:00:00Z",
        "action": {
            # data_shared: a corroboration-meaningful, two-party action that is NOT
            # authority-gated (so the vector exercises the witness exchange, not DAT).
            "category": "data_shared",
            "human_summary": "Shared a record with the counterparty, who corroborates.",
            "outcome": "completed",
            "counterparty_did": _did("B"),
        },
        "evidence": {},
    }


def _finalize(receipt: dict[str, Any]) -> dict[str, Any]:
    """Issuer A signs JCS(receipt sans top-level signature) — covering any
    witness_signatures already present (the normative §1 step-4 order)."""
    if not receipt.get("evidence"):
        receipt.pop("evidence", None)  # empty evidence == no evidence (stable bytes)
    body = {k: v for k, v in receipt.items() if k != "signature"}
    sig = _sk("A").sign(jcs.canonicalize(body))
    receipt["signature"] = base64.b64encode(sig).decode("ascii")
    return receipt


def _with_witness(rid: str, entry: dict[str, Any] | None) -> dict[str, Any]:
    r = _base_receipt(rid)
    if entry is not None:
        r["evidence"]["witness_signatures"] = [entry]
    return _finalize(r)


def _cases() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    # §1 happy path: B co-signs the corroboration payload of the un-witnessed receipt,
    # the entry is inserted, then A finalizes.
    b_entry = cosign_receipt(_base_receipt("c1"), signing_key_bytes=bytes([_SEED["B"]]) * 32)
    happy = _with_witness("c1", b_entry)

    # §3 decline: no witness at all; still finalized and ARP-valid.
    decline = _with_witness("c2", None)

    # §4 brokered equivalence: the chapter relays the SAME corroboration payload to B; B
    # signs with B's own key. Deterministic Ed25519 => byte-identical to the inline entry.
    brokered_entry = cosign_receipt(_base_receipt("c5"), signing_key_bytes=bytes([_SEED["B"]]) * 32)
    brokered = _with_witness("c5", brokered_entry)

    cases = [
        {
            "id": "happy-inline-cosign",
            "description": "§1: B co-signs the corroboration payload → ARP-valid AND corroborated.",
            "spec_ref": "cosign-companion.md §1; vrp/0.3 §A",
            "input": {
                "receipt": happy,
                "counterparty_seed": _seed_b64("B"),
                "issuer_seed": _seed_b64("A"),
            },
            "expected": {"arp_valid": True, "corroborated": True},
        },
        {
            "id": "decline-uncorroborated",
            "description": "§3: counterparty declined → ARP-valid, NOT corroborated, NOT an error.",
            "spec_ref": "cosign-companion.md §3; vrp/0.3 §C",
            "input": {"receipt": decline, "issuer_seed": _seed_b64("A")},
            "expected": {"arp_valid": True, "corroborated": False, "is_error": False},
        },
        {
            "id": "brokered-equivalence",
            "description": (
                "§4: the brokered witness entry is byte-identical to the inline entry and "
                "its witness_did is B, never the chapter (broker relays, never signs)."
            ),
            "spec_ref": "cosign-companion.md §4",
            "input": {
                "receipt": brokered,
                "counterparty_seed": _seed_b64("B"),
                "chapter_did": _did("CHAPTER"),
                "expected_witness_entry": brokered_entry,
            },
            "expected": {
                "arp_valid": True,
                "corroborated": True,
                "witness_did": _did("B"),
                "inline_entry_equals_brokered": True,
            },
        },
    ]

    # §1/§4 forgery: witness_did claims B, but a DIFFERENT key (C) produced the signature.
    forged_entry = cosign_receipt(
        _base_receipt("c3"), signing_key_bytes=bytes([_SEED["C"]]) * 32, witness_did=_did("B")
    )
    forged = _with_witness("c3", forged_entry)

    # §2: a real co-signer who is NOT the counterparty (C signs as itself) — not corroboration.
    third_entry = cosign_receipt(_base_receipt("c4"), signing_key_bytes=bytes([_SEED["C"]]) * 32)
    third = _with_witness("c4", third_entry)

    adversarial = [
        {
            "id": "forged-witness-wrong-signer",
            "description": "§1/§4: witness_did claims B but a different key signed.",
            "spec_ref": "cosign-companion.md §1, §4; vrp/0.3 §A",
            "input": {"receipt": forged},
            "expected": {"arp_valid": True, "corroborated": False},
        },
        {
            "id": "witness-by-third-party",
            "description": "§2: a co-signer who is not the counterparty does NOT corroborate.",
            "spec_ref": "cosign-companion.md §2; vrp/0.3 §A",
            "input": {"receipt": third},
            "expected": {"arp_valid": True, "corroborated": False},
        },
    ]
    return cases, adversarial


def main() -> None:
    cases, adversarial = _cases()
    doc = {
        "spec_version": "arp/0.2 + vrp/0.3",
        "spec_ref": "spec/arp/0.2/cosign-companion.md; spec/vrp/0.3/spec.md §A",
        "description": (
            "Counterparty co-sign handshake: how a receipt's counterparty produces the "
            "evidence.witness_signatures entry that VRP 0.3 §A corroboration requires. No "
            "ARP envelope or canonical-signing change — corroboration rides the existing field."
        ),
        "corroboration_payload": (
            'JCS(receipt with top-level "signature" and "evidence.witness_signatures" removed)'
        ),
        "actors": {
            "A_issuer_did": _did("A"),
            "B_counterparty_did": _did("B"),
            "C_third_party_did": _did("C"),
            "chapter_did": _did("CHAPTER"),
        },
        "cases": cases,
        "adversarial_cases": adversarial,
    }
    out = Path(__file__).resolve().parents[2] / "vectors" / "arp" / "0.2" / "cosign-handshake.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {out} — {len(cases)} cases, {len(adversarial)} adversarial")


if __name__ == "__main__":
    main()
