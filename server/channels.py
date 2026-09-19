"""
Channels — bridge between a member's agent and external messaging
platforms (Slack, email, Discord).

This module handles connection persistence, webhook dispatch, and
message routing. Actual wire-level integration with each platform
(Slack bot API, IMAP/SMTP, Discord gateway) is stubbed — the stubs
return structured "not_implemented" responses so the A2UI surface
and routing layer can exercise the full path today, with real wire
integration landing in W7.

Secrets (OAuth tokens, app passwords) do NOT live here. They land in
agent_private_memory via an injected `store_secret` callback. This
module stores only the fact that a connection exists + its public
config.

Public API
----------
connect(agent_id, kind, remote_id, ...)   — upsert a connection
list_connections(agent_id, kind)          — list per agent
get_connection(connection_id)             — detail
disconnect(connection_id, agent_id)       — remove (owner-only)
test(connection_id)                       — ping remote platform (stub-aware)
deliver_inbound(kind, remote_id, payload) — route inbound to an agent
send_outbound(connection_id, message)     — push a message (stub-aware)

Validation
----------
validate_connect(kind, remote_id, config) — pre-insert
SUPPORTED_KINDS                           — {slack, email, discord, webhook}
"""

from __future__ import annotations

import re
from collections.abc import Callable

# ── Config + DI ───────────────────────────────────────────

_pg_request: Callable | None = None

SUPPORTED_KINDS = frozenset({"slack", "email", "discord", "webhook"})
MAX_DISPLAY_NAME = 120
MAX_CONFIG_BYTES = 16 * 1024

# Basic validators per kind.
_RE_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_RE_SLACK_WORKSPACE = re.compile(r"^T[A-Z0-9]{5,24}$")  # Slack team ids start with T
_RE_DISCORD_GUILD = re.compile(r"^\d{10,25}$")


def init(pg_request_fn: Callable) -> None:
    global _pg_request
    _pg_request = pg_request_fn


# ── Validation ───────────────────────────────────────────


def validate_connect(kind: str, remote_id: str, config: dict | None = None) -> tuple[bool, str]:
    if kind not in SUPPORTED_KINDS:
        return False, f"unsupported kind {kind!r} — allowed: {sorted(SUPPORTED_KINDS)}"
    if not isinstance(remote_id, str) or not remote_id.strip():
        return False, "remote_id is required"
    if len(remote_id) > 256:
        return False, "remote_id too long (max 256)"

    if kind == "email" and not _RE_EMAIL.match(remote_id):
        return False, f"remote_id {remote_id!r} is not a valid email address"
    if kind == "slack" and not _RE_SLACK_WORKSPACE.match(remote_id):
        return False, f"remote_id {remote_id!r} is not a valid Slack workspace id (T...)"
    if kind == "discord" and not _RE_DISCORD_GUILD.match(remote_id):
        return False, f"remote_id {remote_id!r} is not a valid Discord guild id"

    if config is not None:
        if not isinstance(config, dict):
            return False, "config must be a dict"
        import json as _json

        if len(_json.dumps(config).encode("utf-8")) > MAX_CONFIG_BYTES:
            return False, f"config too large (max {MAX_CONFIG_BYTES} bytes)"

    return True, "ok"


# ── Core ops ─────────────────────────────────────────────


async def connect(
    agent_id: str,
    kind: str,
    remote_id: str,
    display_name: str = "",
    config: dict | None = None,
) -> dict:
    """Upsert a channel connection for an agent."""
    if _pg_request is None:
        raise RuntimeError("channels not initialized — call init() first")

    ok, reason = validate_connect(kind, remote_id, config)
    if not ok:
        raise ValueError(reason)

    existing = await _pg_request(
        "GET",
        "chapter_channel_connections",
        params={
            "agent_id": f"eq.{agent_id}",
            "kind": f"eq.{kind}",
            "remote_id": f"eq.{remote_id}",
            "select": "id",
            "limit": "1",
        },
    )

    row = {
        "agent_id": agent_id,
        "kind": kind,
        "remote_id": remote_id,
        "display_name": (display_name or remote_id)[:MAX_DISPLAY_NAME],
        "config": config or {},
        "status": "active",
        "last_error": None,
    }

    if existing:
        await _pg_request(
            "PATCH",
            "chapter_channel_connections",
            params={"id": f"eq.{existing[0]['id']}"},
            body=row,
        )
        return {**row, "id": existing[0]["id"]}

    inserted = await _pg_request("POST", "chapter_channel_connections", body=row)
    return inserted[0] if isinstance(inserted, list) and inserted else row


async def list_connections(agent_id: str, kind: str | None = None) -> list[dict]:
    if _pg_request is None:
        raise RuntimeError("channels not initialized")
    params: dict[str, str] = {"agent_id": f"eq.{agent_id}", "order": "kind.asc,created_at.desc"}
    if kind:
        params["kind"] = f"eq.{kind}"
    return await _pg_request("GET", "chapter_channel_connections", params=params) or []


async def get_connection(connection_id: str) -> dict | None:
    if _pg_request is None:
        raise RuntimeError("channels not initialized")
    rows = await _pg_request(
        "GET",
        "chapter_channel_connections",
        params={"id": f"eq.{connection_id}", "limit": "1"},
    )
    return rows[0] if rows else None


async def disconnect(connection_id: str, agent_id: str) -> dict:
    """Remove a connection. Enforces ownership — only the owning agent may delete."""
    if _pg_request is None:
        raise RuntimeError("channels not initialized")

    conn = await get_connection(connection_id)
    if not conn:
        raise ValueError(f"connection {connection_id!r} not found")
    if conn["agent_id"] != agent_id:
        raise ValueError("only the owning agent may disconnect this channel")

    await _pg_request(
        "DELETE",
        "chapter_channel_connections",
        params={"id": f"eq.{connection_id}"},
    )
    return {"id": connection_id, "status": "disconnected"}


# ── Stubbed wire-level dispatch (W7 wires real Slack / IMAP / SMTP) ──


async def test(connection_id: str) -> dict:
    """Ping the remote platform. Stubbed for now — W7 wires real checks."""
    conn = await get_connection(connection_id)
    if not conn:
        raise ValueError(f"connection {connection_id!r} not found")

    kind = conn["kind"]
    # Record the attempt regardless of whether the stub succeeds.
    from datetime import UTC, datetime

    now_iso = datetime.now(UTC).isoformat()
    if _pg_request is not None:
        await _pg_request(
            "PATCH",
            "chapter_channel_connections",
            params={"id": f"eq.{connection_id}"},
            body={
                "last_test_at": now_iso,
                # NOT a real connectivity check yet (W7 wires Slack/IMAP/SMTP), so
                # we must not claim success — last_test_ok stays NULL ("untested")
                # rather than True, which the admin UI rendered as a false "✓ ok".
                "last_test_ok": None,
                "last_error": "stub: wire-level test not yet implemented (W7)",
            },
        )

    return {
        "connection_id": connection_id,
        "kind": kind,
        "ok": None,
        "stub": True,
        "note": f"Wire-level {kind} test arrives in W7. Connection metadata verified, connectivity NOT checked.",
    }


async def deliver_inbound(
    kind: str,
    remote_id: str,
    payload: dict,
    verify_signature: Callable[[dict], bool] | None = None,
) -> dict:
    """Route an inbound message from a platform webhook to the owning agent.

    The caller (the FastAPI webhook route) is responsible for verifying
    platform-specific signatures (Slack's v0 scheme, email DKIM, etc.)
    BEFORE calling us. If `verify_signature` is passed, we double-check
    here as a defense-in-depth guard.

    Returns {agent_id, session_scope, delivered: bool}.
    """
    if _pg_request is None:
        raise RuntimeError("channels not initialized")

    if kind not in SUPPORTED_KINDS:
        raise ValueError(f"unsupported kind {kind!r}")

    if verify_signature is not None and not verify_signature(payload):
        raise ValueError("payload signature verification failed")

    import json as _json

    if len(_json.dumps(payload).encode("utf-8")) > 256 * 1024:
        raise ValueError("payload too large (max 256 KiB)")

    rows = await _pg_request(
        "GET",
        "chapter_channel_connections",
        params={
            "kind": f"eq.{kind}",
            "remote_id": f"eq.{remote_id}",
            "status": "eq.active",
            "limit": "1",
        },
    )
    if not rows:
        return {"delivered": False, "reason": "no active connection"}

    conn = rows[0]
    agent_id = conn["agent_id"]

    # Session scope mirrors OpenClaw's pattern — sandbox inbound messages
    # from external platforms so the agent treats them as untrusted.
    sender = payload.get("sender") or payload.get("user") or "unknown"
    session_scope = f"agent:{agent_id}:{kind}:dm:{sender}"

    return {
        "delivered": True,
        "agent_id": agent_id,
        "connection_id": conn["id"],
        "session_scope": session_scope,
        "kind": kind,
    }


async def send_outbound(connection_id: str, message: dict) -> dict:
    """Push a message to a platform. Stubbed for W7."""
    conn = await get_connection(connection_id)
    if not conn:
        raise ValueError(f"connection {connection_id!r} not found")
    if conn["status"] != "active":
        raise ValueError(f"connection is {conn['status']}, cannot send")
    if not isinstance(message, dict) or not message.get("text"):
        raise ValueError("message must have a 'text' field")

    # Not implemented yet (W7 wires the real Slack / SMTP / Discord send). We
    # must NOT claim success for a no-op — ok=False so a caller never treats a
    # stubbed send as delivered (mirrors test()'s honest ok=None).
    return {
        "connection_id": connection_id,
        "kind": conn["kind"],
        "ok": False,
        "stub": True,
        "note": f"Wire-level {conn['kind']} send is not implemented yet (arrives in W7) — message NOT delivered.",
    }
