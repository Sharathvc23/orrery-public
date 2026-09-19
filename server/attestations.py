"""Skill attestations — Ed25519-signed vouches by trusted-tier members.

A "live" attestation on a skill makes that skill eligible to mint revenue
events on use. Revenue split includes a share for every live attestation
on the exact (skill_id, skill_version) that was used.

Rules (locked during planning, 2026-04-22):
  • Only members at `trusted` or `leader` tier can attest.
  • Self-attestation is rejected (author_did != attestor_did).
  • Attestations are bound to content_sha256 — they do NOT carry over
    when the author publishes a new version.
  • Revocation is soft (revoked_at set); the row stays for audit.

Canonical signing string:
  ATTEST:{chapter_id}:{skill_id}:{skill_version}:{content_sha256}:{attestor_did}:{created_unix}

R1-R10 coverage in tests/test_attestations.py.
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


def _canonical_string(
    chapter_id: str,
    skill_id: str,
    skill_version: str,
    content_sha256: str,
    attestor_did: str,
    created_unix: int,
) -> str:
    return f"ATTEST:{chapter_id}:{skill_id}:{skill_version}:{content_sha256}:{attestor_did}:{created_unix}"


def create_attestation_signature(
    *,
    private_key_b64: str,
    chapter_id: str,
    skill_id: str,
    skill_version: str,
    content_sha256: str,
    attestor_did: str,
    created_unix: int | None = None,
) -> tuple[str, int]:
    """Sign a canonical attestation string with an Ed25519 private key.

    Returns (base64_signature, created_unix_used). The caller stores
    created_unix alongside the signature so verification can reconstruct
    the same canonical string.
    """
    try:
        from nacl.signing import SigningKey
    except ImportError as e:
        raise RuntimeError("pynacl required for attestation signing") from e

    ts = int(created_unix if created_unix is not None else time.time())
    canonical = _canonical_string(chapter_id, skill_id, skill_version, content_sha256, attestor_did, ts)
    signing_key = SigningKey(base64.b64decode(private_key_b64))
    sig = signing_key.sign(canonical.encode()).signature
    return base64.b64encode(sig).decode(), ts


def verify_attestation_signature(
    *,
    attestor_public_key_b64: str,
    chapter_id: str,
    skill_id: str,
    skill_version: str,
    content_sha256: str,
    attestor_did: str,
    created_unix: int,
    attestation_sig_b64: str,
) -> tuple[bool, str]:
    """Verify an Ed25519 attestation signature. Returns (ok, reason)."""
    try:
        from nacl.exceptions import BadSignatureError
        from nacl.signing import VerifyKey
    except ImportError:
        return False, "pynacl not installed"

    try:
        pub = base64.b64decode(attestor_public_key_b64)
        if len(pub) != 32:
            return False, f"attestor pubkey wrong length: {len(pub)}"
        verify_key = VerifyKey(pub)
        canonical = _canonical_string(chapter_id, skill_id, skill_version, content_sha256, attestor_did, created_unix)
        sig = base64.b64decode(attestation_sig_b64)
        verify_key.verify(canonical.encode(), sig)
    except BadSignatureError:
        return False, "invalid attestation signature"
    except Exception as e:
        return False, f"verify error: {type(e).__name__}"

    return True, "valid"


async def record_attestation(
    *,
    skill_id: str,
    skill_version: str,
    content_sha256: str,
    attestor_did: str,
    attestor_agent_id: str,
    attestor_public_key_b64: str,
    trust_tier_at_attest: str,
    attestation_sig_b64: str,
    created_unix: int,
    note_markdown: str = "",
    author_did: str = "",
) -> dict:
    """Verify the attestation signature + write a row.

    Returns {"ok": True, "id": uuid} on success or {"error": reason} on failure.
    Caller (chapter_agent endpoint) is responsible for:
      - loading the skill's author_did + content_sha256 (we verify they match)
      - verifying the member's trust tier is trusted/leader
    """
    if _pg_request is None:
        return {"error": "attestations module not initialized"}

    if trust_tier_at_attest not in ("trusted", "leader"):
        return {"error": f"trust_tier_at_attest must be trusted or leader, got {trust_tier_at_attest!r}"}

    # Self-attestation rejected — author cannot sign their own skill
    if author_did and author_did == attestor_did:
        return {"error": "self-attestation rejected: author cannot attest own skill"}

    # Verify the Ed25519 signature against the declared canonical inputs
    ok, reason = verify_attestation_signature(
        attestor_public_key_b64=attestor_public_key_b64,
        chapter_id=_chapter_id,
        skill_id=skill_id,
        skill_version=skill_version,
        content_sha256=content_sha256,
        attestor_did=attestor_did,
        created_unix=created_unix,
        attestation_sig_b64=attestation_sig_b64,
    )
    if not ok:
        return {"error": reason}

    # Insert. UNIQUE constraint handles replay (same advisor, same version).
    try:
        await _pg_request(
            "POST",
            "chapter_skill_attestations",
            body={
                "chapter_id": _chapter_id,
                "skill_id": skill_id,
                "skill_version": skill_version,
                "content_sha256": content_sha256,
                "attestor_did": attestor_did,
                "attestor_agent_id": attestor_agent_id,
                "trust_tier_at_attest": trust_tier_at_attest,
                "attestation_sig": attestation_sig_b64,
                "created_unix": created_unix,
                "note_markdown": note_markdown[:4000],
            },
        )
    except Exception as e:
        return {"error": f"insert failed: {type(e).__name__}"}

    return {"ok": True, "chapter_id": _chapter_id, "skill_id": skill_id, "skill_version": skill_version}


async def revoke_attestation(
    *,
    skill_id: str,
    skill_version: str,
    attestor_did: str,
    revocation_reason: str = "",
) -> dict:
    """Soft-delete an attestation. Future use events will not include this
    advisor in the split.
    """
    if _pg_request is None:
        return {"error": "attestations module not initialized"}

    from datetime import UTC, datetime

    try:
        rows = await _pg_request(
            "PATCH",
            "chapter_skill_attestations",
            params={
                "chapter_id": f"eq.{_chapter_id}",
                "skill_id": f"eq.{skill_id}",
                "skill_version": f"eq.{skill_version}",
                "attestor_did": f"eq.{attestor_did}",
            },
            body={
                "revoked_at": datetime.now(UTC).isoformat(),
                "revocation_reason": revocation_reason[:200] if revocation_reason else None,
            },
        )
    except Exception as e:
        return {"error": f"patch failed: {type(e).__name__}"}

    if not rows:
        return {"error": "attestation not found"}
    return {"ok": True}


async def list_live_attestations(skill_id: str, skill_version: str) -> list[dict]:
    """Return all non-revoked attestations for a (skill_id, skill_version) pair.

    Used by skill_revenue to compute the advisor-share split.
    """
    if _pg_request is None:
        return []

    try:
        rows = await _pg_request(
            "GET",
            "chapter_skill_attestations",
            params={
                "chapter_id": f"eq.{_chapter_id}",
                "skill_id": f"eq.{skill_id}",
                "skill_version": f"eq.{skill_version}",
                "revoked_at": "is.null",
                "select": "id,attestor_did,attestor_agent_id,trust_tier_at_attest,created_at",
            },
        )
    except Exception:
        return []
    return rows or []


async def count_live_attestations(skill_id: str, skill_version: str) -> int:
    """Cheap helper for surfaces + pricing."""
    rows = await list_live_attestations(skill_id, skill_version)
    return len(rows)


__all__ = [
    "count_live_attestations",
    "create_attestation_signature",
    "init",
    "list_live_attestations",
    "record_attestation",
    "revoke_attestation",
    "verify_attestation_signature",
]
