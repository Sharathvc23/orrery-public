"""SDK-side ARP receipt → AAE AttestationEvent conversion.

Mirrors ``chapter/aae_export.py`` for the sovereign SDK. The SDK
stores ARP receipts locally in the AgencyLog (per the sovereignty
principle — the principal owns the log). For downstream consumers
that want the AAE wire shape (e.g. a future SDK-side React frontend
rendering via ``@sharathvc/sm-attest-viewer``), this module converts
the receipt rows to AAE-shaped JSON.

Architecture per ``docs/integrations/STELLARMINDS.md``:

  - sm-attest-viewer is UPSTREAM. We never modify it.
  - The SDK is downstream. It produces AAE-shaped JSON whose
    ``payload`` carries the ARP-convention fields per the chapter's
    documented payload shape (counterparty, jurisdiction,
    accessibility, etc.).
  - This module is the SDK's equivalent of ``chapter/aae_export.py``
    — same conversion rules, same wire shape. The chapter and SDK
    produce identical AAE shapes for the same canonical receipt;
    downstream consumers don't have to differentiate.

The conversion is a pure function — no I/O, no side effects. Caller
loads receipts from the AgencyLog (or anywhere) and passes them in;
this module returns the AAE-shaped dict(s).

Public API:

  arp_receipt_to_aae_event(receipt, *, tenant, public=False) -> dict
  arp_receipts_to_aae_events(receipts, *, tenant, public=False) -> list[dict]
"""

from __future__ import annotations

from typing import Any


def _actor_from_did(did: str, *, display_name: str | None = None) -> dict[str, str]:
    """Build an AAEActor from a did:key. The actor.value carries the
    did's identifier portion so downstream renderers can show a short
    handle without re-parsing the full did string."""
    if not did:
        return {"namespace": "did", "value": "", "did": "", "display_name": display_name or ""}
    identifier = did.split(":")[-1] if ":" in did else did
    actor: dict[str, str] = {
        "namespace": "did",
        "value": identifier,
        "did": did,
    }
    if display_name:
        actor["display_name"] = display_name
    return actor


def arp_receipt_to_aae_event(
    receipt: dict[str, Any],
    *,
    tenant: str,
    public: bool = False,
) -> dict[str, Any]:
    """Convert a single ARP receipt (SDK storage shape) into an AAE
    AttestationEvent (wire shape consumed by sm-attest-viewer).

    Args:
        receipt: The canonical ARP receipt dict — same shape as
                 chapter-side receipts. Required fields:
                 receipt_id, issuer_did, principal_did, issued_at,
                 action (with category + human_summary + outcome).
        tenant: Logical tenant label. Typically the agent_id of the
                SDK (so SDK-emitted receipts show "tenant: alice" vs
                chapter-emitted receipts "tenant: bayarea-chapter").
        public: If True, classification becomes 'public'. Default
                'internal' — SDK receipts are local-by-default; the
                principal opts in to public visibility per-receipt.

    Returns:
        AAE-shaped dict matching AttestationEvent.
        Returns {} if the receipt is missing required fields.
    """
    if not isinstance(receipt, dict):
        return {}
    required = ("receipt_id", "issuer_did", "principal_did", "issued_at", "action")
    if not all(receipt.get(k) for k in required):
        return {}

    action = receipt.get("action") or {}
    if not isinstance(action, dict):
        return {}

    category = action.get("category", "")
    classification = "public" if public else "internal"

    actor = _actor_from_did(receipt["issuer_did"], display_name=tenant)
    subject = _actor_from_did(
        receipt["principal_did"],
        display_name=action.get("counterparty_label") or None,
    )

    payload: dict[str, Any] = {
        "subject": subject,
        "kind": category,
        "human_summary": action.get("human_summary", ""),
        "outcome": action.get("outcome", "completed"),
    }
    if cp_did := action.get("counterparty_did"):
        payload["counterparty_did"] = cp_did
    if cp_label := action.get("counterparty_label"):
        payload["counterparty_label"] = cp_label
    if amount := action.get("amount"):
        payload["amount"] = amount
    if mp := action.get("machine_payload"):
        payload["machine_payload"] = mp
    if jurisdiction := receipt.get("jurisdiction"):
        payload["jurisdiction"] = jurisdiction
    if accessibility := receipt.get("accessibility"):
        payload["accessibility"] = accessibility
    if prev_hash := receipt.get("previous_receipt_hash"):
        payload["previous_receipt_hash"] = prev_hash

    if sig := receipt.get("signature"):
        payload["proof"] = {
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-jcs-2022",
            "created": receipt.get("issued_at", ""),
            "verificationMethod": receipt["issuer_did"],
            "proofValue": sig,
        }

    # Topic distinguishes SDK-emitted from server-emitted at a glance.
    topic = f"sdk.action.{category}" if category else "sdk.action"

    return {
        "v": 1,
        "id": receipt["receipt_id"],
        "ts": receipt["issued_at"],
        "tenant": tenant,
        "actor": actor,
        "topic": topic,
        "type": "action",
        "classification": classification,
        "payload": payload,
        "lifecycle": "committed",
    }


def arp_receipts_to_aae_events(
    receipts: list[dict[str, Any]],
    *,
    tenant: str,
    public: bool = False,
) -> list[dict[str, Any]]:
    """Bulk conversion. Skips malformed receipts (returns empty dict).
    Result order matches input order."""
    out: list[dict[str, Any]] = []
    for r in receipts or []:
        ev = arp_receipt_to_aae_event(r, tenant=tenant, public=public)
        if ev:
            out.append(ev)
    return out


def aae_envelope_to_attestation_event(
    envelope: dict[str, Any],
    *,
    tenant: str,
    public: bool = False,
) -> dict[str, Any]:
    """Convert a signed sm-aae envelope (a consent-gate authorization verdict)
    into an AttestationEvent — the ``type:"decision"`` / ``lifecycle:"signed"``
    half of the viewer stream, alongside receipts' ``type:"action"``.

    Verification-gated via ``sm_aae.verify_envelope``: a tampered or malformed
    envelope converts to ``{}``, mirroring the receipt path's skip behavior.
    The full signed envelope rides in ``payload.envelope`` so any consumer can
    re-verify offline; the event ``id`` is ``sm_aae.envelope_hash`` — the same
    value a successor's ``prev_hash`` points at.
    """
    from sm_aae import envelope_hash, verify_envelope

    if not verify_envelope(envelope):
        return {}

    action = envelope["action"]
    actor = _actor_from_did(envelope["agent_id"], display_name=tenant)
    payload: dict[str, Any] = {
        "subject": actor,
        "kind": action["verb"],
        "resource": action["resource"],
        "params": action["params"],
        "outcome": envelope["outcome"],
        "policy_id": envelope["policy_id"],
        "human_summary": f"{envelope['outcome']}: {action['verb']} on {action['resource']}",
        "envelope": envelope,
    }
    if envelope["prev_hash"]:
        payload["prev_envelope_hash"] = envelope["prev_hash"]

    return {
        "v": 1,
        "id": envelope_hash(envelope),
        "ts": envelope["issued_at"],
        "tenant": tenant,
        "actor": actor,
        "topic": f"sdk.decision.{action['verb']}",
        "type": "decision",
        "classification": "public" if public else "internal",
        "payload": payload,
        # Lifecycle is 'signed' — an envelope is a pre-action verdict, signed
        # at issue time; 'committed' belongs to receipts (post-action).
        "lifecycle": "signed",
    }


__all__ = [
    "aae_envelope_to_attestation_event",
    "arp_receipt_to_aae_event",
    "arp_receipts_to_aae_events",
]
