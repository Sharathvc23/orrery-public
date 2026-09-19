"""ARP receipt → AAE AttestationEvent shape conversion.

The chapter stores ARP receipts in their canonical shape (see
``spec/arp/0.1/spec.md``). For external consumption by the
``@sharathvc/sm-attest-viewer`` React renderer, the chapter exposes
receipts in the AAE wire envelope shape that the renderer expects.

Architecture rule per ``docs/integrations/STELLARMINDS.md``:

  - ``sm-attest-viewer`` is an UPSTREAM library. The chapter is
    downstream. We do NOT modify the upstream library to know about
    ARP; instead, we produce AAE-shaped JSON whose ``payload`` field
    carries the ARP-specific fields per our documented convention.

  - ARP receipts retain ALL their structured slots (counterparty,
    jurisdiction, accessibility, amount, hash chain) — they ride
    along in the AAE envelope's free-form ``payload``. Downstream
    consumers that don't know about ARP ignore the extras.

Reference wire shape (from sm-attest-viewer/src/types.ts):

    type AttestationEvent = {
      v: 1,
      id: string,
      ts: string,
      tenant: string,
      actor: { namespace, value, did, display_name? },
      topic: string,
      type: "action" | "decision" | "belief" | "checkpoint",
      classification: string,
      payload: AttestationPayload,
      lifecycle?: "proposed" | "signed" | "committed" | "anchored" | "reconciled",
    }
"""

from __future__ import annotations

from typing import Any


def _actor_from_did(did: str, *, display_name: str | None = None) -> dict[str, str]:
    """Build an AAEActor from a did:key. The actor.value carries the
    did's identifier portion so downstream renderers can show a short
    handle without re-parsing the full did string every time."""
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


def _classification_for_chapter_action() -> str:
    """Chapter actions are by default 'internal' visibility — the
    receipt is signed and chain-linked, but not advertised externally
    unless the principal has opted into a public Chronicle. The
    Chronicle endpoint can override this with 'public' when the
    principal's chapter_role / config has opted in.

    See chapter/chronicle.py for the public-toggle logic.
    """
    return "internal"


def arp_receipt_to_aae_event(
    receipt: dict[str, Any],
    *,
    tenant: str,
    public: bool = False,
) -> dict[str, Any]:
    """Convert a single ARP receipt (storage shape) into an AAE
    AttestationEvent (wire shape consumed by sm-attest-viewer).

    Args:
        receipt: The canonical ARP receipt dict (with at least
                 ``receipt_id``, ``issuer_did``, ``principal_did``,
                 ``issued_at``, ``action``, ``signature``).
        tenant: The chapter id (becomes the AAE event's tenant slug).
        public: If True, classification becomes 'public' (Chronicle
                opted in). Else 'internal'.

    Returns:
        AAE-shaped dict matching the AttestationEvent type that
        sm-attest-viewer renders. Returns an empty dict if the
        receipt is missing required fields — caller decides whether
        to skip or surface as an error.
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
    classification = "public" if public else _classification_for_chapter_action()

    # Standard AAE actor + subject blocks.
    actor = _actor_from_did(receipt["issuer_did"], display_name=tenant)
    subject = _actor_from_did(
        receipt["principal_did"],
        display_name=action.get("counterparty_label") or None,
    )

    # Payload carries the AAE-standard fields PLUS the server's
    # documented ARP convention fields. Downstream renderers that
    # only know AAE-standard fields ignore the ARP extras.
    payload: dict[str, Any] = {
        "subject": subject,
        "kind": category,
        # ── ARP-convention fields (server-specific, optional) ──
        "human_summary": action.get("human_summary", ""),
        "outcome": action.get("outcome", "completed"),
    }
    # Only include optional fields when present — keeps the payload
    # small and avoids confusing renderers with empty objects.
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

    # ARP signature is a base64 Ed25519 sig over JCS(receipt - signature).
    # Map it into AAE's proof block using the W3C DataIntegrityProof
    # shape with the eddsa-jcs-2022 cryptosuite (the spec ARP follows).
    if sig := receipt.get("signature"):
        payload["proof"] = {
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-jcs-2022",
            "created": receipt.get("issued_at", ""),
            "verificationMethod": receipt["issuer_did"],
            "proofValue": sig,
        }

    return {
        "v": 1,
        "id": receipt["receipt_id"],
        "ts": receipt["issued_at"],
        "tenant": tenant,
        "actor": actor,
        # Topic carries the server's action namespace so multi-tenant
        # consumers can filter to specific server activity.
        "topic": f"chapter.action.{category}" if category else "chapter.action",
        "type": "action",
        "classification": classification,
        "payload": payload,
        # Lifecycle is 'signed' — server receipts are signed at
        # emission. 'committed' would be after persistence; the server
        # persists then signs, so the receipt is committed-and-signed
        # by the time it's exported.
        "lifecycle": "committed",
    }


def arp_receipts_to_aae_events(
    receipts: list[dict[str, Any]],
    *,
    tenant: str,
    public: bool = False,
) -> list[dict[str, Any]]:
    """Bulk conversion. Skips any receipt that fails ``arp_receipt_to_aae_event``
    validation (returns empty dict). Result is ordered as input."""
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
    """Convert a signed sm-aae envelope (a pre-action authorization verdict)
    into an AttestationEvent — the ``type:"decision"`` / ``lifecycle:"signed"``
    half of the viewer stream, alongside receipts' ``type:"action"``.

    Mirrors ``agent/community_member/aae_export.py`` exactly except for the
    topic namespace (``chapter.decision.*``). Today the agent's consent gate
    is the envelope producer; the server-side governance/admission permits
    adopt this same seam post-1.0 (see docs/integrations/STELLARMINDS.md).

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
        "topic": f"chapter.decision.{action['verb']}",
        "type": "decision",
        "classification": "public" if public else _classification_for_chapter_action(),
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
