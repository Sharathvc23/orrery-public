"""Consent decisions as sm-decision-inspector envelopes.

``sm-decision-inspector`` is the React human-in-the-loop workbench for
``type:"decision"`` AAE envelopes: the proposed action, the signer roster, the
quorum chip, and approve/deny gesture controls. It is substrate-neutral — it
renders whatever ``DecisionEnvelope[]`` the consumer feeds it and routes
gestures back through the consumer's own callbacks.

This module is that feed, built from the agent's signed consent chain
(``consent/aae_emit.py``). The division of authority is strict:

- **The inspector renders and gestures.** ``onApprove``/``onDeny`` from the
  component are wired by the dashboard to the EXISTING
  ``POST /api/local/consent/approve`` / ``/deny`` endpoints — which run
  ``gate.approve`` / ``gate.deny``. The inspector grows no authorization
  surface of its own; a gesture is a request into the same gate everything
  else goes through.
- **Orrery decides.** Every fed envelope is verify-gated (a tampered stored
  envelope drops out), and the proof set the roster/quorum derive from is the
  envelope's own Ed25519 signature.

Mapping notes (inspector ``DecisionPayload``): our gate outcomes become the
operator-verb taxonomy (``authorized → operator_authorize``, ``denied →
operator_deny``, ``conditional → operator_prompt``); an UNRESOLVED prompt is
``lifecycle:"proposed"`` (the inspector's actionable state) and carries
``prompt_event_sha256`` for the gesture round-trip; ``trace_id`` is the
consent-ledger sha of the prompt, shared by the prompt envelope and whatever
resolves it — the inspector's causal-chain identifier. M-of-N quorum is out of
scope: the served policy is 1-of-1, satisfied by the agent's signature.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

# Mirror of gate.APPROVAL_TTL: a prompt older than this is no longer
# actionable (the pending queue drops it), so it is not "proposed" anymore.
PROMPT_TTL = timedelta(minutes=5)

_OPERATOR_VERB = {
    "authorized": "operator_authorize",
    "denied": "operator_deny",
    "conditional": "operator_prompt",
}

QUORUM_POLICY = {"required": 1}


def _intent_proof(envelope: dict[str, Any]) -> dict[str, Any]:
    """The sm-aae signature as the inspector's ``IntentProof`` shape. The
    inspector treats proofs as opaque and keys the roster on
    ``verificationMethod`` — the agent's did:key."""
    return {
        "type": "sm-aae/v1",
        "created": envelope["issued_at"],
        "verificationMethod": envelope["agent_id"],
        "proofPurpose": "assertionMethod",
        "proofValue": envelope["sig"],
    }


def export_decision_envelopes(
    *,
    tenant: str,
    now: datetime | None = None,
    public: bool = False,
) -> list[dict[str, Any]]:
    """The consent chain as inspector-ready ``DecisionEnvelope`` dicts,
    genesis-first. Verify-gated via the existing decision-event conversion."""
    from .aae_export import aae_envelope_to_attestation_event
    from .consent import aae_emit

    current = now or datetime.now(timezone.utc)
    envelopes = aae_emit.list_envelopes()

    # A conditional (prompt) envelope is resolved once ANY later envelope
    # points back at its consent-ledger row via prompt_event_sha256.
    resolved: set[str] = set()
    for env in envelopes:
        sha = env["action"]["params"].get("prompt_event_sha256")
        if sha:
            resolved.add(str(sha))

    out: list[dict[str, Any]] = []
    for env in envelopes:
        event = aae_envelope_to_attestation_event(env, tenant=tenant, public=public)
        if not event:
            continue  # tampered/malformed stored envelope: never fed to an operator
        params = env["action"]["params"]
        outcome = str(env["outcome"])
        payload = event["payload"]
        payload["kind"] = _OPERATOR_VERB.get(outcome, outcome)
        payload["recorded_at"] = env["issued_at"]
        payload["annotation"] = str(params.get("decision_reason") or "")
        payload["proofs"] = [_intent_proof(env)]

        own_sha = str(params.get("consent_event_sha256") or "")
        prompt_sha = str(params.get("prompt_event_sha256") or "")
        if outcome == "conditional":
            event["trace_id"] = own_sha
            pending = own_sha not in resolved and _within_ttl(env["issued_at"], current)
            event["lifecycle"] = "proposed" if pending else "signed"
            if pending:
                # The gesture handle: POST /api/local/consent/{approve,deny}
                # with this sha routes through gate.approve / gate.deny.
                payload["prompt_event_sha256"] = own_sha
        else:
            event["trace_id"] = prompt_sha or own_sha
        out.append(event)
    return out


def _within_ttl(issued_at: str, now: datetime) -> bool:
    try:
        stamp = datetime.fromisoformat(issued_at.replace("Z", "+00:00"))
    except ValueError:
        return False
    return now - stamp <= PROMPT_TTL


__all__ = ["PROMPT_TTL", "QUORUM_POLICY", "export_decision_envelopes"]
