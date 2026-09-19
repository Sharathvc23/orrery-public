"""Endorsements — explicit signed vouches between members.

A member with `trust_score >= MIN_ENDORSER_TRUST` can sign an endorsement
of another member. The endorsement is one row in `endorsements`, plus
one `trust_event(endorsement_received, +0.5)` for the endorsee.

Anti-farming property: each (endorser, endorsee) pair is worth at most
+0.5 of endorsement-derived trust, regardless of how many times the
endorser writes the row. To reach +2 of endorsement-derived trust, an
endorsee needs four DIFFERENT endorsers. Collusion costs grow with
the number of accomplices.

Plan: PR-B of the trust-events series.

Canonical signing string:

  ENDORSE:{chapter_id}:{endorser_did}:{endorsee_agent_id}:{created_unix}

R1-R10 coverage in tests/test_endorsements.py.
"""

from __future__ import annotations

import base64
import time
from collections.abc import Awaitable, Callable
from decimal import Decimal
from typing import Any

import trust_events

_pg_request: Callable[..., Awaitable[Any]] | None = None
_chapter_id: str = ""

MIN_ENDORSER_TRUST = trust_events.MIN_ENDORSER_TRUST  # Decimal("20.0")


def init(pg_request, chapter_id: str) -> None:
    global _pg_request, _chapter_id
    _pg_request = pg_request
    _chapter_id = chapter_id


def _canonical_string(
    chapter_id: str,
    endorser_did: str,
    endorsee_agent_id: str,
    created_unix: int,
) -> str:
    return f"ENDORSE:{chapter_id}:{endorser_did}:{endorsee_agent_id}:{created_unix}"


def create_endorsement_signature(
    *,
    private_key_b64: str,
    chapter_id: str,
    endorser_did: str,
    endorsee_agent_id: str,
    created_unix: int | None = None,
) -> tuple[str, int]:
    """Sign a canonical endorsement string with an Ed25519 private key.

    Returns (base64_signature, created_unix_used). The caller stores
    created_unix alongside the signature so verification can reconstruct
    the same canonical string.
    """
    try:
        from nacl.signing import SigningKey
    except ImportError as e:
        raise RuntimeError("pynacl required for endorsement signing") from e

    ts = int(created_unix if created_unix is not None else time.time())
    canonical = _canonical_string(chapter_id, endorser_did, endorsee_agent_id, ts)
    signing_key = SigningKey(base64.b64decode(private_key_b64))
    sig = signing_key.sign(canonical.encode()).signature
    return base64.b64encode(sig).decode(), ts


def verify_endorsement_signature(
    *,
    endorser_pubkey_b64: str,
    chapter_id: str,
    endorser_did: str,
    endorsee_agent_id: str,
    created_unix: int,
    signature_b64: str,
) -> bool:
    """Verify a signature using the endorser's Ed25519 public key.

    Returns False on any verification error (bad pubkey, bad sig, bad
    base64). Never raises into the caller — the caller treats False
    as auth failure.
    """
    try:
        from nacl.exceptions import BadSignatureError
        from nacl.signing import VerifyKey
    except ImportError:
        return False
    try:
        canonical = _canonical_string(chapter_id, endorser_did, endorsee_agent_id, created_unix)
        VerifyKey(base64.b64decode(endorser_pubkey_b64)).verify(
            canonical.encode(),
            base64.b64decode(signature_b64),
        )
        return True
    except (BadSignatureError, ValueError, TypeError):
        return False


# ── Service ──────────────────────────────────────────────────────────


async def _get_endorser_trust_score(endorser_agent_id: str) -> Decimal:
    """Read agents.trust_score; default 0 if missing."""
    if _pg_request is None:
        raise RuntimeError("endorsements.init(...) must be called first")
    rows = (
        await _pg_request(
            "GET",
            "agents",
            params={
                "agent_id": f"eq.{endorser_agent_id}",
                "select": "trust_score",
                "limit": 1,
            },
        )
        or []
    )
    if not rows:
        return Decimal("0")
    return Decimal(str(rows[0].get("trust_score") or 0))


async def record_endorsement(
    *,
    endorser_agent_id: str,
    endorser_did: str,
    endorsee_agent_id: str,
    endorser_pubkey_b64: str,
    signature_b64: str,
    created_unix: int,
    note_markdown: str | None = None,
) -> dict:
    """Record (or refresh) an endorsement. Returns a result dict.

    Result shape:
      {error: str}                         on validation/auth failure
      {ok: True, refreshed: bool, ...}     on success

    refreshed=True when the endorsement is replacing an existing row
    (the trust_event was already minted; no second +0.5 is awarded).
    """
    if _pg_request is None:
        raise RuntimeError("endorsements.init(...) must be called first")

    if endorser_agent_id == endorsee_agent_id:
        return {"error": "self-endorsement rejected"}
    if not endorser_pubkey_b64 or not signature_b64:
        return {"error": "missing signature material"}

    if not verify_endorsement_signature(
        endorser_pubkey_b64=endorser_pubkey_b64,
        chapter_id=_chapter_id,
        endorser_did=endorser_did,
        endorsee_agent_id=endorsee_agent_id,
        created_unix=created_unix,
        signature_b64=signature_b64,
    ):
        return {"error": "invalid_signature"}

    endorser_trust = await _get_endorser_trust_score(endorser_agent_id)
    if endorser_trust < MIN_ENDORSER_TRUST:
        return {"error": f"endorser_trust_below_floor: {endorser_trust} < {MIN_ENDORSER_TRUST}"}

    # UPSERT — second write replaces row but does NOT mint a second
    # trust_event (UNIQUE source_event_id keeps that idempotent).
    existing = (
        await _pg_request(
            "GET",
            "endorsements",
            params={
                "endorser_agent_id": f"eq.{endorser_agent_id}",
                "endorsee_agent_id": f"eq.{endorsee_agent_id}",
                "select": "id,revoked_at",
                "limit": 1,
            },
        )
        or []
    )

    body = {
        "chapter_id": _chapter_id,
        "endorser_agent_id": endorser_agent_id,
        "endorser_did": endorser_did,
        "endorsee_agent_id": endorsee_agent_id,
        "endorser_pubkey_b64": endorser_pubkey_b64,
        "signature_b64": signature_b64,
        "note_markdown": note_markdown,
        "created_unix": created_unix,
        # Re-endorsing UN-revokes the row.
        "revoked_at": None,
        "revocation_reason": None,
    }

    refreshed = bool(existing)
    if refreshed:
        existing_id = existing[0]["id"]
        await _pg_request(
            "PATCH",
            "endorsements", params={"id": f"eq.{existing_id}"},
            body=body,
        )
        row_id = existing_id
    else:
        result = await _pg_request("POST", "endorsements", body=body)
        row_id = (result[0] if isinstance(result, list) and result else result or {}).get("id")

    # Mint trust event. UNIQUE constraint guarantees this is a no-op
    # on refresh — the source_event_id is the (endorser, endorsee) pair.
    source_event_id = f"endorsement:{endorser_agent_id}:{endorsee_agent_id}"
    minted = await trust_events.record(
        agent_id=endorsee_agent_id,
        event_type="endorsement_received",
        source_event_id=source_event_id,
        source_agent_id=endorser_agent_id,
        reason=f"endorsed by {endorser_agent_id}",
    )

    # ARP — emit signed receipts for BOTH sides of the endorsement.
    # The endorser sees attestation_issued; the endorsee sees
    # attestation_received. Fire-and-forget — telemetry must not wedge
    # the endorsement flow. Refresh re-mints receipts (which is fine —
    # arp.emit's uniqueness gate is on receipt_id, not on subject).
    try:
        import arp as arp_mod

        endorser_principal_did = arp_mod.did_key_for_member(endorser_agent_id)
        endorsee_principal_did = arp_mod.did_key_for_member(endorsee_agent_id)
        if endorser_principal_did:
            await arp_mod.emit_chapter_action(
                principal_did=endorser_principal_did,
                category="attestation_issued",
                human_summary=f"You endorsed {endorsee_agent_id}.",
                counterparty_did=endorsee_principal_did or None,
                counterparty_label=endorsee_agent_id,
                machine_payload={
                    "action_type_label": "endorsement",
                    "endorsement_id": str(row_id),
                    "refreshed": refreshed,
                },
            )
        if endorsee_principal_did:
            await arp_mod.emit_chapter_action(
                principal_did=endorsee_principal_did,
                category="attestation_received",
                human_summary=f"{endorser_agent_id} endorsed you.",
                counterparty_did=endorser_principal_did or None,
                counterparty_label=endorser_agent_id,
                machine_payload={
                    "action_type_label": "endorsement",
                    "endorsement_id": str(row_id),
                    "refreshed": refreshed,
                },
            )
    except Exception as e:  # noqa: BLE001
        print(f"[endorsements] ARP receipt emission failed: {e}")

    return {
        "ok": True,
        "refreshed": refreshed,
        "endorsement_id": row_id,
        "trust_event_minted": minted is not None,
    }


async def revoke_endorsement(
    *,
    endorser_agent_id: str,
    endorsee_agent_id: str,
    revocation_reason: str = "",
) -> dict:
    """Revoke an endorsement. Soft-delete via revoked_at; emits a
    `revocation_received` trust_event so the endorsee's score drops.
    """
    if _pg_request is None:
        raise RuntimeError("endorsements.init(...) must be called first")
    if endorser_agent_id == endorsee_agent_id:
        return {"error": "self-revoke rejected"}

    existing = (
        await _pg_request(
            "GET",
            "endorsements",
            params={
                "endorser_agent_id": f"eq.{endorser_agent_id}",
                "endorsee_agent_id": f"eq.{endorsee_agent_id}",
                "select": "id,revoked_at",
                "limit": 1,
            },
        )
        or []
    )
    if not existing:
        return {"error": "not_found"}
    if existing[0].get("revoked_at"):
        return {"error": "already_revoked"}

    from datetime import UTC, datetime

    await _pg_request(
        "PATCH",
        "endorsements", params={"id": f"eq.{existing[0]['id']}"},
        body={
            "revoked_at": datetime.now(UTC).isoformat(),
            "revocation_reason": revocation_reason[:512],
        },
    )

    # Compensating trust event. The original endorsement_received row
    # remains in trust_events for audit; we add a revocation_received
    # row so the running score reflects the loss.
    revoked = await trust_events.record(
        agent_id=endorsee_agent_id,
        event_type="revocation_received",
        source_event_id=f"endorsement_revoke:{endorser_agent_id}:{endorsee_agent_id}",
        source_agent_id=endorser_agent_id,
        reason=f"endorsement revoked by {endorser_agent_id}: {revocation_reason[:120]}",
    )

    return {"ok": True, "trust_event_minted": revoked is not None}


async def list_endorsements_received(
    endorsee_agent_id: str,
    *,
    include_revoked: bool = False,
    limit: int = 50,
) -> list[dict]:
    if _pg_request is None:
        raise RuntimeError("endorsements.init(...) must be called first")
    params: dict[str, Any] = {
        "endorsee_agent_id": f"eq.{endorsee_agent_id}",
        "select": "id,endorser_agent_id,endorser_did,note_markdown,created_at,revoked_at,revocation_reason",
        "order": "created_at.desc",
        "limit": limit,
    }
    if not include_revoked:
        params["revoked_at"] = "is.null"
    rows = await _pg_request("GET", "endorsements", params=params)
    return rows or []
