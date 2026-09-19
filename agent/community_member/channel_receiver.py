"""
Channel receiver — inbound webhook server for the member agent.

The chapter side routes inbound messages from external platforms
(Slack / email / Discord / generic webhooks) to the member's
registered connection. This module listens on localhost and turns
those inbound webhooks into session messages the agent's turn loop
consumes.

Security posture — nothing optional:

- **Slack:** v0 signing scheme. The request is rejected unless
  HMAC-SHA256 of `v0:<timestamp>:<raw-body>` (signed with the
  workspace's signing secret) equals the `X-Slack-Signature` header.
  Replay window: 5 minutes. Older timestamps refused.
- **Generic:** HMAC-SHA256 of the raw body signed with a per-
  connection secret; 5-minute window required in `X-Nanda-Timestamp`.
- **Email:** accepts signed forwarding from providers (Mailgun / Postmark / SES)
  via the generic HMAC scheme configured per connection.
- **Discord:** Ed25519 webhook verification (signature over ``timestamp+body``
  per Discord's spec). Refuses with 401 until an application public key is
  configured — resolved per-connection from the channel secret store, with the
  ``DISCORD_PUBLIC_KEY`` env var as a fallback.

Every verified inbound event is:

1. Appended to ~/.community-member/inbox.jsonl (append-only audit log, mode 0600)
2. Enqueued into an asyncio.Queue the agent's turn loop drains

The audit log line is a canonical JSON serialization of the
verified envelope; the agent reads from the queue, not from the file.
Tamper-evidence: the log is hash-chained via sha256(prev || this).

Public API
----------
build_app(inbox_path, secret_resolver, max_clock_skew) → fastapi.FastAPI
    Returns a FastAPI app you mount on :7778 alongside the agent.
verify_slack_signature(body, ts, signature, secret, clock_skew_sec)
    Pure Slack v0 verification — returns (ok, reason). Never raises.
verify_generic_hmac(body, ts, signature, secret, clock_skew_sec)
    Pure generic HMAC verification — same contract.
append_audit(path, event, prev_sha)
    Append-only, hash-chained. Returns the new sha.
read_audit(path) → list[dict]
    Parse inbox.jsonl into event dicts.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request

_log = logging.getLogger(__name__)

from community_member.config import CONFIG_DIR

INBOX_PATH = CONFIG_DIR / "inbox.jsonl"
MAX_PAYLOAD_BYTES = 256 * 1024
DEFAULT_CLOCK_SKEW_SEC = 300  # 5 minutes, matches Slack spec


# ═══════════════════════════════════════════════════════════════
# Pure verification — no I/O, no FastAPI
# ═══════════════════════════════════════════════════════════════


def _constant_time_equals(a: str, b: str) -> bool:
    """Timing-safe string compare. Prevents side-channel leakage of the
    correct signature via response-time analysis."""
    return hmac.compare_digest(a, b)


def verify_slack_signature(
    body: bytes,
    timestamp: str,
    signature: str,
    signing_secret: str,
    *,
    now: float | None = None,
    clock_skew_sec: int = DEFAULT_CLOCK_SKEW_SEC,
) -> tuple[bool, str]:
    """Slack v0 scheme. Returns (ok, reason); never raises.

    Spec: https://api.slack.com/authentication/verifying-requests-from-slack
    """
    if not signing_secret:
        return False, "no signing secret configured for this workspace"
    if not signature or not signature.startswith("v0="):
        return False, "missing or malformed X-Slack-Signature"
    if not timestamp or not timestamp.isdigit():
        return False, "missing or non-numeric X-Slack-Request-Timestamp"

    current = now if now is not None else time.time()
    try:
        ts_int = int(timestamp)
    except ValueError:
        return False, "timestamp not an integer"

    if abs(current - ts_int) > clock_skew_sec:
        return False, f"timestamp outside {clock_skew_sec}s replay window"

    sig_base = f"v0:{timestamp}:".encode() + body
    expected = "v0=" + hmac.new(signing_secret.encode(), sig_base, hashlib.sha256).hexdigest()

    if not _constant_time_equals(expected, signature):
        return False, "signature mismatch"

    return True, "ok"


def verify_discord_signature(
    body: bytes,
    timestamp: str,
    signature_hex: str,
    public_key_hex: str,
    *,
    now: float | None = None,
    clock_skew_sec: int = DEFAULT_CLOCK_SKEW_SEC,
) -> tuple[bool, str]:
    """Discord interaction Ed25519 verification.

    Per https://discord.com/developers/docs/interactions/receiving-and-responding:
        signature = Ed25519_sign(timestamp || body, bot_private_key)

    Headers:
        X-Signature-Ed25519 (hex)
        X-Signature-Timestamp (unix seconds, as string)

    Returns (ok, reason); never raises.
    """
    if not public_key_hex:
        return False, "no DISCORD_PUBLIC_KEY configured"
    if not signature_hex:
        return False, "missing X-Signature-Ed25519"
    if not timestamp or not timestamp.isdigit():
        return False, "missing or non-numeric X-Signature-Timestamp"

    current = now if now is not None else time.time()
    try:
        ts_int = int(timestamp)
    except ValueError:
        return False, "timestamp not an integer"

    if abs(current - ts_int) > clock_skew_sec:
        return False, f"timestamp outside {clock_skew_sec}s replay window"

    try:
        from nacl.exceptions import BadSignatureError
        from nacl.signing import VerifyKey
    except ImportError:
        return False, "pynacl not installed"

    try:
        verify_key = VerifyKey(bytes.fromhex(public_key_hex))
        sig = bytes.fromhex(signature_hex)
    except (ValueError, TypeError):
        return False, "invalid hex encoding"

    message = timestamp.encode() + body
    try:
        verify_key.verify(message, sig)
    except BadSignatureError:
        return False, "signature mismatch"
    except Exception as e:
        return False, f"verification error: {type(e).__name__}"

    return True, "ok"


def verify_generic_hmac(
    body: bytes,
    timestamp: str,
    signature: str,
    secret: str,
    *,
    now: float | None = None,
    clock_skew_sec: int = DEFAULT_CLOCK_SKEW_SEC,
) -> tuple[bool, str]:
    """Generic HMAC-SHA256 scheme for email / webhook connections.

    Expected: X-Nanda-Signature = hex(hmac_sha256(secret, f"{ts}.{body}"))
    """
    if not secret:
        return False, "no secret configured"
    if not signature or len(signature) != 64 or not all(c in "0123456789abcdef" for c in signature.lower()):
        return False, "signature must be 64-char hex"
    if not timestamp or not timestamp.isdigit():
        return False, "missing or non-numeric X-Nanda-Timestamp"

    current = now if now is not None else time.time()
    try:
        ts_int = int(timestamp)
    except ValueError:
        return False, "timestamp not an integer"

    if abs(current - ts_int) > clock_skew_sec:
        return False, f"timestamp outside {clock_skew_sec}s replay window"

    sig_base = f"{timestamp}.".encode() + body
    expected = hmac.new(secret.encode(), sig_base, hashlib.sha256).hexdigest()

    if not _constant_time_equals(expected, signature.lower()):
        return False, "signature mismatch"

    return True, "ok"


# ═══════════════════════════════════════════════════════════════
# Audit log — append-only, hash-chained
# ═══════════════════════════════════════════════════════════════


def _canonical_event(event: dict) -> str:
    """Deterministic serialization for hashing. Sorted keys, no whitespace."""
    return json.dumps(event, sort_keys=True, separators=(",", ":"))


def _sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def append_audit(
    path: Path,
    event: dict,
    prev_sha: str = "",
) -> str:
    """Append event as JSONL. Each row includes `prev_sha256` + its own
    `event_sha256` so tampering breaks the chain. Returns the new event sha.
    """
    path.parent.mkdir(exist_ok=True, parents=True, mode=0o700)

    payload = {
        "kind": event.get("kind", ""),
        "remote_id": event.get("remote_id", ""),
        "sender": event.get("sender", "unknown"),
        "body": event.get("body", {}),
        "received_at": event.get("received_at") or datetime.now(UTC).isoformat(),
        "session_scope": event.get("session_scope", ""),
        "prev_sha256": prev_sha or None,
    }
    payload["event_sha256"] = _sha256_hex(_canonical_event(payload))

    # Append + flush. Open in append+text mode with utf-8 encoding.
    with path.open("a", encoding="utf-8") as f:
        f.write(_canonical_event(payload) + "\n")
        f.flush()
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return payload["event_sha256"]


def read_audit(path: Path) -> list[dict]:
    """Parse the JSONL audit log into a list of event dicts."""
    if not path.exists():
        return []
    out: list[dict] = []
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                _log.warning("skipped unparseable audit line")
    except (OSError, UnicodeDecodeError):
        return []
    return out


def verify_audit_chain(path: Path) -> tuple[bool, int]:
    """Re-derive the hash chain over the audit log. Returns (ok, broken_index).

    broken_index is -1 on success, or the 0-based index of the first
    row whose recomputed sha doesn't match its stored event_sha256.
    """
    events = read_audit(path)
    prev = ""
    for i, r in enumerate(events):
        payload = {k: r.get(k) for k in ("kind", "remote_id", "sender", "body", "received_at", "session_scope")}
        payload["prev_sha256"] = r.get("prev_sha256") or None
        expected = _sha256_hex(_canonical_event(payload))
        if expected != r.get("event_sha256"):
            return False, i
        if (r.get("prev_sha256") or "") != (prev or ""):
            return False, i
        prev = r["event_sha256"]
    return True, -1


# ═══════════════════════════════════════════════════════════════
# In-memory inbox queue — agent turn loop consumes from here
# ═══════════════════════════════════════════════════════════════


@dataclass
class InboxItem:
    kind: str
    remote_id: str
    sender: str
    body: dict
    session_scope: str
    event_sha256: str


class Inbox:
    """Thread-/coroutine-safe FIFO of verified inbound events."""

    def __init__(self, maxsize: int = 1000) -> None:
        self._q: asyncio.Queue[InboxItem] = asyncio.Queue(maxsize=maxsize)
        self._last_sha: str = ""
        self._lock = asyncio.Lock()

    async def put(self, item: InboxItem) -> None:
        await self._q.put(item)

    def put_nowait(self, item: InboxItem) -> None:
        self._q.put_nowait(item)

    async def get(self) -> InboxItem:
        return await self._q.get()

    def drain_nowait(self) -> list[InboxItem]:
        out: list[InboxItem] = []
        while not self._q.empty():
            try:
                out.append(self._q.get_nowait())
            except asyncio.QueueEmpty:
                break
        return out

    @property
    def size(self) -> int:
        return self._q.qsize()

    async def set_last_sha(self, sha: str) -> None:
        async with self._lock:
            self._last_sha = sha

    def last_sha(self) -> str:
        return self._last_sha


# ═══════════════════════════════════════════════════════════════
# FastAPI app — listens on :7778
# ═══════════════════════════════════════════════════════════════


# SecretResolver signature: (kind, remote_id) → secret str ("" if unknown)
SecretResolver = Callable[[str, str], str]


def build_app(
    *,
    inbox: Inbox | None = None,
    inbox_path: Path | None = None,
    secret_resolver: SecretResolver | None = None,
    clock_skew_sec: int = DEFAULT_CLOCK_SKEW_SEC,
    now_fn: Callable[[], float] | None = None,
) -> Any:
    """Build the FastAPI application.

    Every dependency is injectable so tests can exercise the full verify
    → audit → enqueue pipeline without a real Slack workspace.
    """
    inbox = inbox or Inbox()
    audit_path = inbox_path or INBOX_PATH
    resolver = secret_resolver or (lambda _kind, _remote: "")
    _now = now_fn or time.time

    app = FastAPI(title="nanda-channel-receiver", redirect_slashes=False)

    @app.get("/health")
    async def health() -> dict:
        return {"ok": True, "inbox_size": inbox.size, "audit_entries": len(read_audit(audit_path))}

    @app.post("/channels/slack/webhook")
    async def slack_webhook(request: Request):
        body = await request.body()
        if len(body) > MAX_PAYLOAD_BYTES:
            raise HTTPException(status_code=413, detail="payload too large")

        headers = {k.lower(): v for k, v in request.headers.items()}
        ts = headers.get("x-slack-request-timestamp", "")
        sig = headers.get("x-slack-signature", "")

        # Slack sends events with a `team_id` field — that's the workspace id.
        try:
            payload = json.loads(body) if body else {}
        except json.JSONDecodeError:
            raise HTTPException(status_code=400, detail="invalid JSON body") from None

        # URL verification handshake: must respond with the challenge.
        if payload.get("type") == "url_verification":
            # Even the handshake must be signed.
            secret = resolver("slack", payload.get("team_id", ""))
            ok, reason = verify_slack_signature(body, ts, sig, secret, now=_now(), clock_skew_sec=clock_skew_sec)
            if not ok:
                raise HTTPException(status_code=401, detail=f"signature check failed: {reason}")
            return {"challenge": payload.get("challenge", "")}

        team_id = payload.get("team_id", "")
        if not team_id:
            raise HTTPException(status_code=400, detail="missing team_id in Slack event")
        secret = resolver("slack", team_id)
        ok, reason = verify_slack_signature(body, ts, sig, secret, now=_now(), clock_skew_sec=clock_skew_sec)
        if not ok:
            raise HTTPException(status_code=401, detail=f"signature check failed: {reason}")

        event = payload.get("event", {}) or {}
        user = event.get("user") or payload.get("user_id", "") or "unknown"
        scope = f"agent:channel:slack:dm:{user}"
        item = await _ingest(inbox, audit_path, "slack", team_id, user, event, scope)
        return {"ok": True, "event_sha256": item.event_sha256, "queued": True}

    @app.post("/channels/generic/webhook")
    async def generic_webhook(request: Request):
        body = await request.body()
        if len(body) > MAX_PAYLOAD_BYTES:
            raise HTTPException(status_code=413, detail="payload too large")

        headers = {k.lower(): v for k, v in request.headers.items()}
        ts = headers.get("x-nanda-timestamp", "")
        sig = headers.get("x-nanda-signature", "")
        remote_id = headers.get("x-nanda-remote-id", "")
        if not remote_id:
            raise HTTPException(status_code=400, detail="missing X-Nanda-Remote-Id")

        try:
            payload = json.loads(body) if body else {}
        except json.JSONDecodeError:
            raise HTTPException(status_code=400, detail="invalid JSON body") from None

        secret = resolver("generic", remote_id)
        ok, reason = verify_generic_hmac(body, ts, sig, secret, now=_now(), clock_skew_sec=clock_skew_sec)
        if not ok:
            raise HTTPException(status_code=401, detail=f"signature check failed: {reason}")

        sender = payload.get("sender") or payload.get("from") or "unknown"
        scope = f"agent:channel:generic:dm:{sender}"
        item = await _ingest(inbox, audit_path, "generic", remote_id, sender, payload, scope)
        return {"ok": True, "event_sha256": item.event_sha256, "queued": True}

    @app.post("/channels/email/webhook")
    async def email_webhook(request: Request):
        # Email providers (Mailgun / Postmark / SES) forward over the same
        # generic HMAC scheme — the provider is configured with a secret
        # that matches what the member set in their channel connection.
        body = await request.body()
        if len(body) > MAX_PAYLOAD_BYTES:
            raise HTTPException(status_code=413, detail="payload too large")
        headers = {k.lower(): v for k, v in request.headers.items()}
        ts = headers.get("x-nanda-timestamp", "")
        sig = headers.get("x-nanda-signature", "")
        remote_id = headers.get("x-nanda-remote-id", "")
        if not remote_id:
            raise HTTPException(status_code=400, detail="missing X-Nanda-Remote-Id")
        try:
            payload = json.loads(body) if body else {}
        except json.JSONDecodeError:
            raise HTTPException(status_code=400, detail="invalid JSON body") from None

        secret = resolver("email", remote_id)
        ok, reason = verify_generic_hmac(body, ts, sig, secret, now=_now(), clock_skew_sec=clock_skew_sec)
        if not ok:
            raise HTTPException(status_code=401, detail=f"signature check failed: {reason}")

        sender = payload.get("from") or payload.get("sender") or "unknown"
        scope = f"agent:channel:email:dm:{sender}"
        item = await _ingest(inbox, audit_path, "email", remote_id, sender, payload, scope)
        return {"ok": True, "event_sha256": item.event_sha256, "queued": True}

    @app.post("/channels/discord/webhook")
    async def discord_webhook(request: Request):
        """Verify Discord Ed25519 interaction signature per their spec.

        Discord sends two headers: X-Signature-Ed25519 + X-Signature-Timestamp.
        The signature is over (timestamp + body) using Discord's documented
        algorithm, verified against the application's public key (set via
        DISCORD_PUBLIC_KEY on the channel config).
        """
        import os as _os

        sig = request.headers.get("X-Signature-Ed25519", "")
        ts = request.headers.get("X-Signature-Timestamp", "")
        body = await request.body()

        # Per-connection app public key from the resolver (Discord can't parse
        # remote_id before verifying, so a kind-only lookup), env as fallback.
        pub_key_hex = resolver("discord", "") or _os.environ.get("DISCORD_PUBLIC_KEY", "")
        ok, reason = verify_discord_signature(body, ts, sig, pub_key_hex)
        if not ok:
            raise HTTPException(status_code=401, detail=f"signature check failed: {reason}")

        # Parse payload
        try:
            payload = json.loads(body.decode())
        except json.JSONDecodeError:
            raise HTTPException(status_code=400, detail="invalid JSON body")  # noqa: B904

        # Discord interaction type 1 = PING (verification handshake)
        if payload.get("type") == 1:
            return {"type": 1}  # PONG

        remote_id = payload.get("id") or payload.get("interaction_id") or ""
        sender_id = (payload.get("member") or {}).get("user", {}).get("id", "")
        sender = f"discord:{sender_id}" if sender_id else "discord:unknown"
        scope = f"agent:channel:discord:dm:{sender}"
        item = await _ingest(inbox, audit_path, "discord", remote_id, sender, payload, scope)
        return {"ok": True, "event_sha256": item.event_sha256, "queued": True}

    return app


async def _ingest(
    inbox: Inbox,
    audit_path: Path,
    kind: str,
    remote_id: str,
    sender: str,
    body: dict,
    session_scope: str,
) -> InboxItem:
    """Append to audit log, enqueue for the agent loop, return the item."""
    received_at = datetime.now(UTC).isoformat()
    event = {
        "kind": kind,
        "remote_id": remote_id,
        "sender": sender,
        "body": body,
        "session_scope": session_scope,
        "received_at": received_at,
    }
    prev = inbox.last_sha()
    sha = append_audit(audit_path, event, prev)
    await inbox.set_last_sha(sha)

    item = InboxItem(
        kind=kind,
        remote_id=remote_id,
        sender=sender,
        body=body,
        session_scope=session_scope,
        event_sha256=sha,
    )
    await inbox.put(item)
    return item
