"""Self-certifying registry records — signed endpoint attestations.

A registry (NEST / NANDA Index) stores whatever a registrant posts, and a
discovery consumer has no way to tell whether the ``endpoint`` in a record is
what the agent published or what the registry (or anyone with write access to
its database) substituted. Federation broadcast signing doesn't help here:
``federation_signing.verify_inbound`` fetches the peer key from
``{endpoint}/.well-known/did.json``, so a registry that lies about the endpoint
also controls the key the signature is checked against — the signature chain is
anchored to the very field the registry can forge.

This module breaks that circle by making the record self-certifying. The
publishing org signs ``{agent_id, did, endpoint, issued_at, expires_at}`` with
its Ed25519 key and ships the signature alongside the record. Because a
``did:key`` *is* the public key, a consumer verifies the record entirely
offline — no fetch to the (possibly attacker-controlled) endpoint, no trust in
the registry. The registry degrades to an untrusted courier: it can refuse to
serve a record, but it can't alter one without the signature breaking.

**Trust model.** The signer is the org server (the registry publisher), keyed
by the org's durable Ed25519 keypair (``sovereign_identity.ensure_chapter_keypair``).
For the org's own record the attestation is self-certifying (subject == signer);
for member records the org is the hosting authority — members are served at the
org's endpoint, so the org key attests them.

**Freshness.** ``expires_at`` bounds replay: a captured old attestation ages
out after ``REGISTRY_ATTESTATION_TTL_S`` (default 24h). The periodic
re-registration heartbeat re-signs with a fresh window, so a live org's record
keeps rolling while a dead or rotated one goes stale.

**Emission is best-effort.** ``build`` returns None when the signer has no
keypair yet (first boot registers before ``ensure_chapter_keypair`` runs; the
heartbeat re-publish carries the attestation ~30s later). Verification-side
enforcement is the consumer's cutover decision, mirroring the
warn-then-enforce pattern of ``federation_signing``.
"""

from __future__ import annotations

import base64
import os
import time
from typing import Any

import jcs

import sovereign_identity

ATTESTATION_VERSION = 1
DEFAULT_ATTESTATION_TTL_S = 24 * 3600.0

# F6: tolerance for issuer/verifier clock disagreement on the not-before check.
# Mirrored in index/attestation_gate.py — verdict-parity-tested.
NOT_BEFORE_SKEW_S = 300

_REQUIRED_RECORD_FIELDS = ("v", "agent_id", "did", "endpoint", "issued_at", "expires_at")


def _ttl_s() -> float:
    """Attestation validity window in seconds (REGISTRY_ATTESTATION_TTL_S, default 24h)."""
    raw = os.environ.get("REGISTRY_ATTESTATION_TTL_S", "").strip()
    if not raw:
        return DEFAULT_ATTESTATION_TTL_S
    try:
        return float(raw)
    except ValueError:
        return DEFAULT_ATTESTATION_TTL_S


def _canonical(record: dict[str, Any]) -> str:
    """JCS (RFC 8785) canonical JSON — signer and verifier compute byte-identical
    material regardless of key order or serializer (same discipline as
    ``federation_signing``)."""
    return jcs.canonicalize(record).decode("utf-8")


def build(
    subject_id: str,
    endpoint: str,
    signer_id: str,
    *,
    now: float | None = None,
    ttl_s: float | None = None,
) -> dict[str, Any] | None:
    """A signed endpoint attestation ``{"record": {...}, "sig": b64}`` — or None
    if the signer has no Ed25519 keypair yet (emission is best-effort).

    The DID inside the record is derived from the signing key itself, so the
    verifier needs nothing beyond the attestation. ``now``/``ttl_s`` are
    injectable for deterministic tests.
    """
    kp = sovereign_identity._ed25519_keypairs.get(signer_id)
    if not kp:
        return None
    pk_b64 = base64.b64encode(kp["public_key"]).decode()
    sk_b64 = base64.b64encode(kp["private_key"]).decode()
    ts = int(now if now is not None else time.time())
    record: dict[str, Any] = {
        "v": ATTESTATION_VERSION,
        "agent_id": subject_id,
        "did": sovereign_identity.build_did_key_from_ed25519(pk_b64),
        "endpoint": endpoint.rstrip("/"),
        "issued_at": ts,
        "expires_at": ts + int(ttl_s if ttl_s is not None else _ttl_s()),
    }
    sig = sovereign_identity.ed25519_sign(_canonical(record), sk_b64)
    return {"record": record, "sig": sig}


def verify(attestation: Any, *, now: float | None = None) -> tuple[bool, str]:
    """Verify an attestation's internal validity: signature over the canonical
    record against the key its own DID encodes, then freshness.

    Returns ``(valid, reason)``. Reasons: ``ok``, ``malformed``,
    ``unsupported_did``, ``invalid_signature``, ``expired``, ``not_yet_valid``.
    Never raises.

    Deliberately does NOT check who the subject is or whether the endpoint
    matches anything — binding the attestation to a discovery result
    (agent_id match, preferring the attested endpoint over the registry's
    unsigned copy) is the consumer's job.
    """
    if not isinstance(attestation, dict):
        return False, "malformed"
    record = attestation.get("record")
    sig = attestation.get("sig")
    if not isinstance(record, dict) or not isinstance(sig, str) or not sig:
        return False, "malformed"
    for field in _REQUIRED_RECORD_FIELDS:
        if field not in record:
            return False, "malformed"
    if not isinstance(record["issued_at"], int) or not isinstance(record["expires_at"], int):
        return False, "malformed"
    # F6 sanity: an inverted validity window is not a real attestation.
    if record["issued_at"] > record["expires_at"]:
        return False, "malformed"

    pubkey = sovereign_identity.extract_ed25519_pubkey_from_did_key(str(record["did"]))
    if not pubkey:
        return False, "unsupported_did"
    if not sovereign_identity.ed25519_verify(_canonical(record), sig, pubkey):
        return False, "invalid_signature"

    current = now if now is not None else time.time()
    if current > record["expires_at"]:
        return False, "expired"
    # F6 sanity: reject an attestation from the future (beyond clock skew) — a
    # pre-dated blob minted for later replay should not be bankable.
    if current < record["issued_at"] - NOT_BEFORE_SKEW_S:
        return False, "not_yet_valid"
    return True, "ok"
