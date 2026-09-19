"""
Authentication — challenge-response registration + signed requests.

Flow:
1. Client requests challenge: GET /api/auth/challenge?agent_id=X
2. Server returns nonce (60s TTL)
3. Client signs nonce with private key
4. Client sends POST /api/members with X-Agent-Signature header
5. Server verifies signature

For ongoing requests, every A2A call includes:
- X-Agent-ID header
- X-Agent-Signature header (HMAC of request body)
- X-Agent-Timestamp header (replay protection)
"""

import base64
import hashlib
import hmac
import time

from .crypto import (
    build_did_key,
    ed25519_available,
    ed25519_sign_message,
    generate_ed25519_keypair,
    generate_keypair,
    sign_message,
)

# Stored locally
_private_key: str = ""
_public_key: str = ""
_sig_scheme: str = "hmac-sha256"  # or "ed25519"
_did_key: str = ""


def init_keys(private_key_b64: str = "", public_key_b64: str = "", scheme: str = ""):
    """Load or generate signing keys.

    scheme: "ed25519" (NANDA Index spec) or "hmac-sha256" (legacy).
    If empty, prefers Ed25519 when available, falls back to HMAC.
    """
    global _private_key, _public_key, _sig_scheme, _did_key

    chosen_scheme = (scheme or ("ed25519" if ed25519_available() else "hmac-sha256")).lower()

    if private_key_b64 and public_key_b64:
        _private_key = private_key_b64
        _public_key = public_key_b64
    elif chosen_scheme == "ed25519":
        kp = generate_ed25519_keypair()
        _private_key = kp["private_key"]
        _public_key = kp["public_key"]
    else:
        kp = generate_keypair()
        _private_key = kp["private_key"]
        _public_key = kp["public_key"]

    _sig_scheme = chosen_scheme
    _did_key = ""
    if chosen_scheme == "ed25519":
        try:
            _did_key = build_did_key(_public_key)
        except Exception:
            _did_key = ""

    return {
        "private_key": _private_key,
        "public_key": _public_key,
        "scheme": _sig_scheme,
        "did_key": _did_key,
    }


def get_public_key() -> str:
    return _public_key


def get_private_key() -> str:
    return _private_key


# --- Canonical string + header composition (single source of truth) ----------
#
# These pure functions are the ONLY place the v0.2 / v0.3 canonical string and
# header set are defined. `sign_request_body` below calls them, and the
# conformance adapter (conformance/client/adapters/member_sdk.py) calls the
# SAME functions — so the suite verifies exactly what production signs, not a
# reimplementation. The canonical format is on the spec's "never changes
# silently" list (spec/0.3/signing.md); changing it here changes it for both.


def canonical_string_v02(body: str, agent_id: str, timestamp: str) -> str:
    """v0.2 canonical: ``body:agent_id:timestamp`` (spec/0.2/signing.md)."""
    return f"{body}:{agent_id}:{timestamp}"


def canonical_string_v03(method: str, url_path: str, body: str, agent_id: str, timestamp: str, nonce: str) -> str:
    """v0.3 canonical: ``METHOD:url_path:body:agent_id:timestamp:nonce`` (spec/0.3/signing.md)."""
    return f"{method.upper()}:{url_path}:{body}:{agent_id}:{timestamp}:{nonce}"


def compose_signed_headers_v02(agent_id: str, did_key: str, timestamp: str, signature_b64: str) -> dict:
    """v0.2 ``ed25519`` header set. ``X-Agent-DID-Key`` is included when known."""
    headers = {
        "X-Agent-ID": agent_id,
        "X-Agent-Signature": signature_b64,
        "X-Agent-Timestamp": timestamp,
        "X-Agent-Sig-Scheme": "ed25519",
    }
    if did_key:
        headers["X-Agent-DID-Key"] = did_key
    return headers


def compose_signed_headers_v03(agent_id: str, did_key: str, timestamp: str, nonce: str, signature_b64: str) -> dict:
    """v0.3 ``ed25519+nonce`` header set. ``X-Agent-DID-Key`` is included when known."""
    headers = {
        "X-Agent-ID": agent_id,
        "X-Agent-Signature": signature_b64,
        "X-Agent-Timestamp": timestamp,
        "X-Agent-Nonce": nonce,
        "X-Agent-Sig-Scheme": "ed25519+nonce",
    }
    if did_key:
        headers["X-Agent-DID-Key"] = did_key
    return headers


def sign_request_body(
    body: str,
    agent_id: str,
    method: str = "",
    url_path: str = "",
) -> dict:
    """Sign a request body for A2A authentication.

    Default behavior (the org protocol v0.3):
    Uses `ed25519+nonce` scheme when both `method` and `url_path` are
    provided. Canonical string is
    `method:url_path:body:agent_id:timestamp:nonce` per spec/0.3/signing.md.
    Adds `X-Agent-Nonce` (32 random bytes, base64) for server-side
    uniqueness enforcement.

    Backward-compatible call sites (older code that only passes
    body + agent_id) default to v0.2 — they emit `ed25519` scheme with
    canonical string `body:agent_id:timestamp` and no nonce. v0.3 chapters
    MUST accept v0.2 per the negotiation contract; v0.2 chapters reject
    v0.3 because they don't recognize the new scheme value.

    Falls back to HMAC-SHA256 if Ed25519 is unavailable in the runtime.

    Returns headers to include on the request.
    """
    import base64 as _b64
    import os as _os

    timestamp = str(int(time.time()))

    if _sig_scheme == "ed25519":
        # v0.3 path: caller provided method + url_path → bind them + nonce.
        if method and url_path:
            nonce = _b64.b64encode(_os.urandom(32)).decode()
            message = canonical_string_v03(method, url_path, body, agent_id, timestamp, nonce)
            signature = ed25519_sign_message(message, _private_key)
            return compose_signed_headers_v03(agent_id, _did_key, timestamp, nonce, signature)

        # v0.2 fallback path: legacy callers without method/url_path.
        message = canonical_string_v02(body, agent_id, timestamp)
        signature = ed25519_sign_message(message, _private_key)
        return compose_signed_headers_v02(agent_id, _did_key, timestamp, signature)

    # HMAC-SHA256 (legacy v0.1)
    message = f"{body}:{agent_id}:{timestamp}"
    signature = sign_message(message, _private_key)
    return {
        "X-Agent-ID": agent_id,
        "X-Agent-Signature": signature,
        "X-Agent-Timestamp": timestamp,
        "X-Agent-Sig-Scheme": "hmac-sha256",
        "X-Agent-Public-Key": _public_key,
    }


def verify_request_headers(
    body: str, headers: dict, known_keys: dict | None = None, max_age_seconds: int = 300
) -> tuple[bool, str]:
    """Verify request authentication headers.

    Args:
        body: the raw request body
        headers: dict with X-Agent-ID, X-Agent-Signature, X-Agent-Timestamp, X-Agent-Public-Key
        known_keys: dict of agent_id → private_key_b64 (for server-side verification)
        max_age_seconds: maximum age of timestamp

    Returns:
        (valid, reason) — True if valid, False with reason string
    """
    agent_id = headers.get("X-Agent-ID", headers.get("x-agent-id", ""))
    signature = headers.get("X-Agent-Signature", headers.get("x-agent-signature", ""))
    timestamp_str = headers.get("X-Agent-Timestamp", headers.get("x-agent-timestamp", ""))
    public_key = headers.get("X-Agent-Public-Key", headers.get("x-agent-public-key", ""))

    if not agent_id:
        return False, "Missing X-Agent-ID header"
    if not signature:
        return False, "Missing X-Agent-Signature header"
    if not timestamp_str:
        return False, "Missing X-Agent-Timestamp header"

    # Check timestamp freshness
    try:
        timestamp = int(timestamp_str)
    except ValueError:
        return False, "Invalid timestamp format"

    now = int(time.time())
    if abs(now - timestamp) > max_age_seconds:
        return False, f"Timestamp expired ({abs(now - timestamp)}s old, max {max_age_seconds}s)"

    # Verify signature
    message = f"{body}:{agent_id}:{timestamp_str}"
    scheme = headers.get("X-Agent-Sig-Scheme", headers.get("x-agent-sig-scheme", "")).lower()
    did_key = headers.get("X-Agent-DID-Key", headers.get("x-agent-did-key", ""))

    # Default scheme inference: if no scheme header, choose based on signature length
    if not scheme:
        # HMAC-SHA256 produces 32 bytes → 44 base64 chars; Ed25519 produces 64 → 88
        scheme = "ed25519" if len(signature) > 60 else "hmac-sha256"

    # Ed25519 path
    if scheme == "ed25519":
        try:
            from nacl.exceptions import BadSignatureError
            from nacl.signing import VerifyKey
        except ImportError:
            return False, "Ed25519 verification not available (install pynacl)"

        # Pubkey source: known_keys[agent_id] (base64 pubkey) or parsed from did:key
        pubkey_b64 = ""
        if known_keys and agent_id in known_keys:
            pubkey_b64 = known_keys[agent_id]
        elif did_key and did_key.startswith("did:key:z"):
            try:
                import base58

                encoded = did_key[len("did:key:z") :]
                raw = base58.b58decode(encoded)
                if len(raw) == 34 and raw[:2] == b"\xed\x01":
                    pubkey_b64 = base64.b64encode(raw[2:]).decode()
            except Exception:
                pass

        if not pubkey_b64:
            return False, "No Ed25519 pubkey to verify against"

        try:
            verify_key = VerifyKey(base64.b64decode(pubkey_b64))
            verify_key.verify(message.encode(), base64.b64decode(signature))
            return True, "Valid (ed25519)"
        except BadSignatureError:
            return False, "Invalid Ed25519 signature"
        except Exception as e:
            return False, f"Ed25519 verification error: {e}"

    # HMAC-SHA256 path (legacy)
    if known_keys and agent_id in known_keys:
        private_key = known_keys[agent_id]
        try:
            private_key_bytes = base64.b64decode(private_key)
            expected = hmac.new(private_key_bytes, message.encode(), hashlib.sha256).digest()
            provided = base64.b64decode(signature)
            if hmac.compare_digest(expected, provided):
                return True, "Valid"
        except Exception:
            pass
        return False, "Invalid signature"

    # For TOFU (first-time registration), we can't verify yet —
    # we accept the public key and store it
    if public_key:
        return True, "TOFU: public key accepted (first registration)"

    return False, "No known key and no public key provided"


# ────────────────────────────────────────────────────────────────────
# Key rotation — signed attestation so a sovereign member can swap
# their pubkey on a server without re-proving identity from scratch.
# ────────────────────────────────────────────────────────────────────


def create_rotation_attestation(
    old_private_key_b64: str,
    new_public_key_b64: str,
    chapter_id: str,
    agent_id: str,
    timestamp: int | None = None,
    nonce: str | None = None,
) -> dict:
    """Produce a rotation attestation signed by the OLD private key.

    Contract (what chapter-runtime's verify_rotation_attestation expects):

      canonical = f"ROTATE:{chapter_id}:{agent_id}:{new_public_key_b64}:{timestamp}:{nonce}"
      signature = Ed25519_sign(canonical, old_private_key)

    The OLD key must sign because possession of the OLD private key is the
    only thing the chapter trusts at time t=now. If the user has lost the
    old key, they cannot produce this attestation — and they must re-enroll
    from scratch (losing their chapter trust tier + history).

    Clock skew: the chapter-side verify enforces +/- 5 minute window. The
    nonce (32 hex) ensures uniqueness even within the window (R2 replay).

    Returns:
        {
          "kind": "rotation",
          "chapter_id": str,
          "agent_id": str,
          "old_did_key": str,       # derived from old pubkey (if available)
          "new_public_key_b64": str,
          "new_did_key": str,       # derived from new pubkey
          "timestamp": int,
          "nonce": str,
          "signature": str,         # base64, Ed25519 of canonical string
          "scheme": "ed25519",
        }
    """
    import os

    from .crypto import build_did_key, ed25519_sign_message

    if not old_private_key_b64:
        raise ValueError("old_private_key_b64 required")
    if not new_public_key_b64:
        raise ValueError("new_public_key_b64 required")
    if not chapter_id:
        raise ValueError("chapter_id required")
    if not agent_id:
        raise ValueError("agent_id required")

    ts = int(timestamp if timestamp is not None else time.time())
    n = nonce or os.urandom(16).hex()

    # Derive DIDs for debug / audit, non-security
    new_did = ""
    try:
        new_did = build_did_key(new_public_key_b64)
    except Exception:
        pass

    canonical = f"ROTATE:{chapter_id}:{agent_id}:{new_public_key_b64}:{ts}:{n}"
    signature = ed25519_sign_message(canonical, old_private_key_b64)

    return {
        "kind": "rotation",
        "chapter_id": chapter_id,
        "agent_id": agent_id,
        "new_public_key_b64": new_public_key_b64,
        "new_did_key": new_did,
        "timestamp": ts,
        "nonce": n,
        "signature": signature,
        "scheme": "ed25519",
    }


def verify_rotation_attestation(
    attestation: dict,
    old_public_key_b64: str,
    max_age_seconds: int = 300,
    known_nonces: set[str] | None = None,
) -> tuple[bool, str]:
    """Verify a rotation attestation against the agent's CURRENT stored pubkey.

    Args:
        attestation: dict produced by create_rotation_attestation
        old_public_key_b64: what the chapter has stored for this agent_id TODAY
        max_age_seconds: +/- clock-skew tolerance
        known_nonces: set of already-seen nonces for replay protection

    Returns (valid, reason).

    Chapter side calls this before accepting a key rotation. If the
    attestation verifies, the chapter updates its stored pubkey to
    attestation["new_public_key_b64"].
    """
    try:
        from nacl.exceptions import BadSignatureError
        from nacl.signing import VerifyKey
    except ImportError:
        return False, "pynacl not installed"

    required = {"chapter_id", "agent_id", "new_public_key_b64", "timestamp", "nonce", "signature"}
    missing = required - set(attestation.keys())
    if missing:
        return False, f"missing fields: {sorted(missing)}"

    if attestation.get("kind") != "rotation":
        return False, "not a rotation attestation"
    if attestation.get("scheme") != "ed25519":
        return False, f"unsupported scheme: {attestation.get('scheme')}"

    # Clock skew window
    try:
        ts = int(attestation["timestamp"])
    except (TypeError, ValueError):
        return False, "invalid timestamp"
    now = int(time.time())
    if abs(now - ts) > max_age_seconds:
        return False, f"timestamp out of window ({abs(now - ts)}s, max {max_age_seconds}s)"

    # Replay check
    nonce = attestation["nonce"]
    if known_nonces is not None and nonce in known_nonces:
        return False, "nonce replay"

    # Signature verification — old pubkey must have signed the canonical
    try:
        old_pub = base64.b64decode(old_public_key_b64)
        verify_key = VerifyKey(old_pub)
        canonical = (
            f"ROTATE:{attestation['chapter_id']}:{attestation['agent_id']}:"
            f"{attestation['new_public_key_b64']}:{ts}:{nonce}"
        )
        sig = base64.b64decode(attestation["signature"])
        verify_key.verify(canonical.encode(), sig)
    except BadSignatureError:
        return False, "invalid signature (old key did not sign this attestation)"
    except Exception as e:
        return False, f"verification error: {type(e).__name__}"

    # Sanity: new pubkey must be different from old
    if attestation["new_public_key_b64"] == old_public_key_b64:
        return False, "new public key must differ from old"

    # Sanity: new pubkey must decode to 32 bytes (Ed25519)
    try:
        new_raw = base64.b64decode(attestation["new_public_key_b64"])
        if len(new_raw) != 32:
            return False, f"new pubkey wrong length: {len(new_raw)} (Ed25519 needs 32)"
    except Exception:
        return False, "new pubkey not valid base64"

    return True, "valid"
