"""Sovereign member key rotation verification + persistence.

Server-side counterpart to community_member.auth.create_rotation_attestation.

Flow:
    1. Client signs attestation with OLD private key (see community-member)
    2. Client POSTs to /api/members/rotate with the attestation JSON
    3. This module verifies: signature, clock skew, nonce uniqueness,
       pubkey length, "new differs from old"
    4. If valid: updates auth_verify's stored pubkey for the agent AND
       inserts an audit row into member_key_rotations

R1-R10 coverage lives in tests/test_member_rotation.py.
"""

from __future__ import annotations

import base64
import time
from collections.abc import Awaitable, Callable
from typing import Any

_pg_request: Callable[..., Awaitable[Any]] | None = None
_chapter_id: str = ""


def init(pg_request, chapter_id: str) -> None:
    """DI — chapter_agent.py calls this on startup."""
    global _pg_request, _chapter_id
    _pg_request = pg_request
    _chapter_id = chapter_id


async def _nonce_seen(nonce: str) -> bool:
    """Check if the nonce has been used against this chapter already."""
    if _pg_request is None:
        return False
    try:
        rows = await _pg_request(
            "GET",
            "member_key_rotations",
            params={
                "chapter_id": f"eq.{_chapter_id}",
                "nonce": f"eq.{nonce}",
                "select": "id",
                "limit": "1",
            },
        )
    except Exception:
        # Fail-closed on infra error — better to reject a legitimate rotation
        # than accidentally accept a replay
        return True
    return bool(rows)


def _verify_attestation(
    attestation: dict,
    old_public_key_b64: str,
    max_age_seconds: int = 300,
    *,
    chapter_id: str | None = None,
) -> tuple[bool, str]:
    """Pure-function verification. No DB, no network.

    Mirrors community_member.auth.verify_rotation_attestation exactly so
    the contract stays symmetric — any change here must land in both.

    ``chapter_id`` overrides the module-level id for callers that run BEFORE
    ``init`` — the boot-time chain replay does, since ``load_persisted_members``
    runs ~140 lines ahead of it. Passing it explicitly keeps the cross-server
    reuse check ON for those callers; leaving it None preserves the live
    endpoint's behaviour exactly.
    """
    try:
        from nacl.exceptions import BadSignatureError
        from nacl.signing import VerifyKey
    except ImportError:
        return False, "pynacl not installed on chapter"

    required = {
        "chapter_id",
        "agent_id",
        "new_public_key_b64",
        "timestamp",
        "nonce",
        "signature",
    }
    missing = required - set(attestation.keys())
    if missing:
        return False, f"missing fields: {sorted(missing)}"

    if attestation.get("kind") != "rotation":
        return False, "not a rotation attestation"
    if attestation.get("scheme") != "ed25519":
        return False, f"unsupported scheme: {attestation.get('scheme')}"

    # Server id must match this server (prevent cross-server attestation reuse)
    expected_chapter = _chapter_id if chapter_id is None else chapter_id
    if expected_chapter and attestation["chapter_id"] != expected_chapter:
        return False, f"chapter_id mismatch (attestation is for {attestation['chapter_id']})"

    try:
        ts = int(attestation["timestamp"])
    except (TypeError, ValueError):
        return False, "invalid timestamp"
    now = int(time.time())
    if abs(now - ts) > max_age_seconds:
        return False, f"timestamp out of window ({abs(now - ts)}s, max {max_age_seconds}s)"

    if attestation["new_public_key_b64"] == old_public_key_b64:
        return False, "new public key must differ from old"

    try:
        new_raw = base64.b64decode(attestation["new_public_key_b64"])
        if len(new_raw) != 32:
            return False, f"new pubkey wrong length: {len(new_raw)} (Ed25519 needs 32)"
    except Exception:
        return False, "new pubkey not valid base64"

    try:
        old_pub = base64.b64decode(old_public_key_b64)
        verify_key = VerifyKey(old_pub)
        canonical = (
            f"ROTATE:{attestation['chapter_id']}:{attestation['agent_id']}:"
            f"{attestation['new_public_key_b64']}:{ts}:{attestation['nonce']}"
        )
        sig = base64.b64decode(attestation["signature"])
        verify_key.verify(canonical.encode(), sig)
    except BadSignatureError:
        return False, "invalid signature (old key did not sign this attestation)"
    except Exception as e:
        return False, f"verification error: {type(e).__name__}"

    return True, "valid"


#: Disables the replay window for `verify_recorded_link` — and ONLY for it.
#:
#: The 300s window on the live endpoint stops a captured attestation from being
#: replayed. A row in `member_key_rotations` is not a replay: it is the record
#: this server wrote *after* accepting one, and it is months old by the time a
#: boot re-reads it. Applying the window there would reject every row and leave
#: the rotation unrecoverable, which is the failure it is meant to prevent.
#: Replay is instead excluded by construction — nothing here accepts input from
#: the wire, and the nonce that guarded the original acceptance is the primary
#: key of the row being read.
_NO_REPLAY_WINDOW = 1 << 62


def verify_recorded_link(attestation: dict, old_public_key_b64: str, *, chapter_id: str) -> bool:
    """Re-verify one recorded rotation at boot: did ``old_public_key`` sign it?

    Called by the loader when it walks a member's chain forward. It exists so
    that reading the audit table gives a key exactly as trustworthy as the one
    the endpoint accepted — the signature is checked again here rather than the
    row being trusted because it is in the database.

    That distinction is the whole point: without it, anything that can INSERT a
    row into ``member_key_rotations`` could move any member's auth key on the
    next restart, which would turn a database write into an account takeover.
    With it, a forged row is refused at boot for the same reason the endpoint
    would have refused it — no signature from the key it claims to supersede.
    """
    ok, _reason = _verify_attestation(
        attestation,
        old_public_key_b64,
        max_age_seconds=_NO_REPLAY_WINDOW,
        chapter_id=chapter_id,
    )
    return ok


async def accept_rotation(
    attestation: dict,
    stored_public_key_b64: str,
    *,
    max_age_seconds: int = 300,
) -> dict:
    """Full-pipeline: verify + check replay + persist audit row.

    Returns:
        {"ok": True, "new_public_key_b64": str} on success.
        {"error": <reason>} on failure.

    Caller is responsible for updating auth_verify's in-memory key after
    this returns success (we don't touch auth_verify here to keep this
    module pure + testable).
    """
    # 1. Shape + signature + clock
    valid, reason = _verify_attestation(attestation, stored_public_key_b64, max_age_seconds=max_age_seconds)
    if not valid:
        return {"error": reason}

    # 2. Nonce replay check (hits DB)
    nonce = attestation["nonce"]
    if await _nonce_seen(nonce):
        return {"error": "nonce replay"}

    # 3. Persist audit row. Fail-closed on DB error — don't update the
    # in-memory key if we can't also record the rotation.
    if _pg_request is None:
        return {"error": "postgres not initialized"}
    try:
        await _pg_request(
            "POST",
            "member_key_rotations",
            body={
                "chapter_id": attestation["chapter_id"],
                "agent_id": attestation["agent_id"],
                "old_public_key": stored_public_key_b64,
                "new_public_key": attestation["new_public_key_b64"],
                "new_did_key": attestation.get("new_did_key", ""),
                "attestation": attestation,
                "nonce": nonce,
                "client_timestamp": int(attestation["timestamp"]),
            },
        )
    except Exception as e:
        return {"error": f"audit write failed: {type(e).__name__}"}

    return {"ok": True, "new_public_key_b64": attestation["new_public_key_b64"]}


__all__ = ["accept_rotation", "init", "verify_recorded_link"]
