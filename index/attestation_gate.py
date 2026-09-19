"""Per-org attestation gate for the lean index write surface (F2 stage 2).

The write surface stays open by default (NEST parity; self-certifying records +
consumer-side pinning are the primary defense) — but a record whose identity has
been established gets server-side takeover protection: the first write carrying
a VALID Ed25519 endpoint attestation TOFU-pins the record's DID, and every later
write to that id must present a valid attestation by the pinned DID. An
unsigned overwrite, a re-registration under a different key, or a forged
attestation is rejected at the write surface (403) instead of relying solely on
consumers to notice.

The attestation shape and verification semantics mirror
``server/registry_attestation`` exactly — ``{"record": {v, agent_id, did,
endpoint, issued_at, expires_at}, "sig": b64}``, Ed25519 over the RFC 8785
(JCS) canonical record, the DID being the key. A verdict-parity test
(``server/tests/test_index_gate_parity.py``) keeps the two verifiers agreeing;
this module additionally enforces the F6 sanity checks (``issued_at ≤
expires_at``, not-before with clock skew), which the server verifier gained in
the same change.

Dependency budget (recorded in docs/HARDENING.md): ``cryptography`` + ``jcs`` +
``base58`` — the repo-standard stack — rather than hand-vendored crypto.
"""

from __future__ import annotations

import base64
import time
from typing import Any

import base58
import jcs
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

_REQUIRED_RECORD_FIELDS = ("v", "agent_id", "did", "endpoint", "issued_at", "expires_at")
_DID_PREFIX = b"\xed\x01"

# Tolerance for issuer/verifier clock disagreement on the not-before check.
NOT_BEFORE_SKEW_S = 300


def _pubkey_from_did(did: str) -> Ed25519PublicKey | None:
    """Ed25519 public key encoded in a ``did:key:z…`` — None if it isn't one."""
    if not did.startswith("did:key:z"):
        return None
    try:
        raw = base58.b58decode(did[len("did:key:z") :])
    except ValueError:
        return None
    if len(raw) != 34 or not raw.startswith(_DID_PREFIX):
        return None
    try:
        return Ed25519PublicKey.from_public_bytes(raw[len(_DID_PREFIX) :])
    except ValueError:
        return None


def verify_attestation(attestation: Any, *, now: float | None = None) -> tuple[bool, str]:
    """Verify an attestation's internal validity — signature over the canonical
    record against the key its own DID encodes, then freshness and window
    sanity. Returns ``(valid, reason)``; reasons: ``ok``, ``malformed``,
    ``unsupported_did``, ``invalid_signature``, ``expired``, ``not_yet_valid``.
    Never raises on hostile input.

    Like the server verifier, this deliberately does NOT check who the subject
    is — binding the attestation to the write (path id, body endpoint, pinned
    DID) is :func:`evaluate_write`'s job.
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

    pubkey = _pubkey_from_did(str(record["did"]))
    if pubkey is None:
        return False, "unsupported_did"
    try:
        pubkey.verify(base64.b64decode(sig), jcs.canonicalize(record))
    except (InvalidSignature, ValueError, TypeError):
        return False, "invalid_signature"

    current = now if now is not None else time.time()
    if current > record["expires_at"]:
        return False, "expired"
    # F6 sanity: reject an attestation from the future (beyond clock skew) —
    # a pre-dated blob a squatter mints for later replay should not be bankable.
    if current < record["issued_at"] - NOT_BEFORE_SKEW_S:
        return False, "not_yet_valid"
    return True, "ok"


def evaluate_write(
    agent_id: str,
    body: dict[str, Any],
    pinned_did: str | None,
    *,
    now: float | None = None,
) -> tuple[bool, str, str | None]:
    """The gate decision for one write.

    Returns ``(allowed, reason, pin_did)`` — ``pin_did`` is non-None when the
    caller should TOFU-pin that DID for this id (first valid attested write).

    Rules:
      * body carries an attestation → it must be valid, its subject must be the
        path id, and (when the body claims an endpoint) the unsigned endpoint
        must match the attested one — else rejected.
      * id has a pinned DID → a valid attestation by exactly that DID is
        REQUIRED (an unsigned write or another key's attestation is rejected).
      * no pin, no attestation → allowed (the open-write default; nothing to
        authenticate against).
    """
    attestation = body.get("attestation")

    if attestation is None:
        if pinned_did is not None:
            return False, "attestation_required", None
        return True, "open", None

    valid, reason = verify_attestation(attestation, now=now)
    if not valid:
        return False, f"invalid_attestation:{reason}", None
    record = attestation["record"]
    if str(record["agent_id"]) != agent_id:
        return False, "subject_mismatch", None
    body_endpoint = body.get("endpoint")
    if isinstance(body_endpoint, str) and body_endpoint.strip():
        if body_endpoint.rstrip("/") != str(record["endpoint"]).rstrip("/"):
            return False, "endpoint_mismatch", None

    did = str(record["did"])
    if pinned_did is not None:
        if did != pinned_did:
            return False, "did_mismatch", None
        return True, "pinned_ok", None
    return True, "tofu_pin", did


__all__ = ["NOT_BEFORE_SKEW_S", "evaluate_write", "verify_attestation"]
