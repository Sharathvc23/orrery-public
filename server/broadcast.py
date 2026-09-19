"""Chapter broadcast — one message, many recipients.

The chapter publishes a ``chapter.broadcast`` event locally (durable on
``event_log``) and pushes the same payload to every federated peer's
``/api/federation/broadcast/inbox``. Peers re-publish into their own
``event_log`` with ``origin_chapter_id`` preserved so subscribers
upstream of the bus (workspaces, dashboards, future SSE streams)
see the same broadcast wherever they are subscribed.

## Loop prevention

The receive handler **never forwards**. It is a leaf: peer → my
event_log. ``origin_chapter_id`` carries the original publisher so
audit + UI can label the source, but it is **not** used as a routing
hint. If chapter A broadcasts and we re-broadcast to chapter B's
inbox, chapter B would also see chapter A as origin and would have
to forward again — that's the loop. By forbidding forwarding, the
maximum hop count is 1.

## Dedup

Broadcasts are keyed by ``broadcast_id`` (UUID set by the publisher).
The receive handler checks the last 1000 received broadcast_ids
in-memory and rejects duplicates with 409. Persistence of dedup
state across restarts is intentionally not provided — a duplicate
delivered after restart is at most one extra event in event_log,
which the renderer dedupes on broadcast_id again.

## Auth — prototype tier

* ``send_broadcast`` is called from the ``POST /api/broadcast``
  handler in ``chapter_agent.py``, which already resolved the
  authenticated caller via ``_resolve_caller``. We do not re-verify
  here — we trust the chapter middleware.

* ``receive_broadcast`` is called from
  ``POST /api/federation/broadcast/inbox``. For the prototype the
  caller is trusted-by-whitelist: we verify ``origin_chapter_id``
  appears in the local federation registry. Production hardening
  (full Ed25519 chapter-to-chapter signing on the inbound side) is
  a clear follow-up PR but is not blocking for the demo.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from collections import deque
from collections.abc import Awaitable, Callable
from typing import Any

import httpx

import event_bus
from event_types import ChapterBroadcastPayload, EventType

logger = logging.getLogger(__name__)

# Module-level state, injected at server startup.
_pg_request: Callable[..., Awaitable[Any]] | None = None
_chapter_id: str = ""
# Read-only view of the server's known peers (id -> info dict).
# The server's federation_discovery owns the lifecycle; we just read.
_federation: dict[str, dict] | None = None
# Callable that signs an outbound HTTP request body for federation calls.
# Provided by chapter_agent.py at init time; same signer used by mesh.send_to_peer.
_sign_outbound: Callable[[str, str, dict], dict] | None = None

# Bounded LIFO dedup buffer of recently-seen broadcast_ids on the receive
# side. 1000 entries covers ~weeks at realistic prototype broadcast rates
# while staying tiny in memory. NOT shared across restarts — the persistent
# `federation_inbound_seen` table (below) is the restart-surviving guard; this
# ring is just the fast path.
DEDUP_WINDOW = 1000
_recent_broadcast_ids: deque[str] = deque(maxlen=DEDUP_WINDOW)

# Persistent, restart-surviving dedup for inbound federated broadcasts.
# A captured signed broadcast replayed AFTER a process restart (which clears the
# in-memory ring) within the signature freshness window would otherwise
# re-ingest. We record every accepted (origin_chapter_id, broadcast_id) here and
# check it before publishing. Fails OPEN to the in-memory ring if the store is
# unavailable (logged) — federation must not break on a misconfigured stack.
_SEEN_TABLE = "federation_inbound_seen"


async def dedup_store_healthy() -> tuple[bool, str]:
    """Probe the persistent restart-replay dedup store.

    Returns ``(healthy, detail)``. The ``federation_inbound_seen`` table is the
    guard that survives a restart; it's baked into ``infra/init.sql`` but
    there is no boot-time DDL / migration runner, so a database provisioned
    before it was added is missing it — and ``_seen_persisted`` then silently
    fails open, degrading restart-replay protection to the freshness window
    alone. This probe makes that condition observable instead of silent.
    """
    if _pg_request is None:
        return False, "no_pg_request"
    try:
        await _pg_request("GET", _SEEN_TABLE, params={"select": "id", "limit": "1"})
        return True, "ok"
    except Exception as e:  # noqa: BLE001 — the probe reports, never crashes boot
        return False, f"{type(e).__name__}: {str(e)[:120]}"


async def _seen_persisted(origin_chapter_id: str, broadcast_id: str) -> bool:
    """True if this (origin, broadcast_id) was already ingested — a durable,
    restart-surviving check. Fails open (False) + logs if the store is down."""
    if _pg_request is None:
        return False
    try:
        rows = await _pg_request(
            "GET",
            _SEEN_TABLE,
            params={
                "origin_chapter_id": f"eq.{origin_chapter_id}",
                "broadcast_id": f"eq.{broadcast_id}",
                "select": "id",
                "limit": "1",
            },
        )
        return bool(rows)
    except Exception as e:  # noqa: BLE001 — degrade to the in-memory ring, never crash ingest
        logger.warning(
            "federation dedup: persistent check failed for broadcast_id=%s (%r) — "
            "falling back to in-memory ring only",
            broadcast_id,
            e,
        )
        return False


async def _record_seen(origin_chapter_id: str, broadcast_id: str) -> None:
    """Record an accepted broadcast in the persistent dedup store. Best-effort;
    the UNIQUE(origin_chapter_id, broadcast_id) constraint also absorbs a race."""
    if _pg_request is None:
        return
    try:
        await _pg_request(
            "POST",
            _SEEN_TABLE,
            body={"origin_chapter_id": origin_chapter_id, "broadcast_id": broadcast_id},
        )
    except Exception as e:  # noqa: BLE001 — a failed record must not fail the ingest we already did
        logger.warning("federation dedup: persistent record failed for broadcast_id=%s (%r)", broadcast_id, e)

# Hard caps on outbound fanout. Each peer post is best-effort and bounded
# by a per-peer timeout; the total fanout cannot exceed the peer count.
PEER_PUSH_TIMEOUT_SECONDS = 8.0
PEER_PUSH_MAX_CONCURRENCY = 16


def init(
    pg_request: Callable[..., Awaitable[Any]],
    chapter_id: str,
    federation: dict[str, dict],
    sign_outbound: Callable[[str, str, dict], dict] | None = None,
) -> None:
    """Wire dependencies. Called once at chapter boot from chapter_agent.py."""
    global _pg_request, _chapter_id, _federation, _sign_outbound
    _pg_request = pg_request
    _chapter_id = chapter_id
    _federation = federation
    _sign_outbound = sign_outbound


def is_initialized() -> bool:
    return _pg_request is not None and bool(_chapter_id) and _federation is not None


# Trust floor for direct-broadcast authority. Members below this still
# have a path — POST /api/broadcast/propose — that routes through the
# leader approval queue. Pinned here (not in policy) because changing
# the floor without a code review is exactly the kind of thing we want
# to prevent.
DIRECT_BROADCAST_TRUST_FLOOR = 75.0
DIRECT_BROADCAST_ROLES = {"leader", "admin"}


async def caller_can_broadcast_directly(caller_agent_id: str) -> tuple[bool, str]:
    """Return (allowed, reason).

    Direct-broadcast authority comes from one of:
      * The chapter agent itself (always allowed — it's broadcasting on
        its own behalf via the autonomous think-cycle).
      * Chapter leaders / admins (chapter_role in DIRECT_BROADCAST_ROLES).
      * High-trust members (trust_score >= DIRECT_BROADCAST_TRUST_FLOOR).

    Anyone below those bars hits the propose path instead.

    Reason strings are stable identifiers for metrics + tests:
      "chapter_agent" | "leader_role" | "trust_floor" | "below_floor"
      | "unknown_agent"
    """
    if _pg_request is None:
        return False, "uninitialized"
    if caller_agent_id == _chapter_id:
        return True, "chapter_agent"
    rows = await _pg_request(
        "GET",
        "agents",
        params={
            "agent_id": f"eq.{caller_agent_id}",
            "select": "agent_id,trust_score,chapter_role",
            "limit": "1",
        },
    )
    if not rows:
        return False, "unknown_agent"
    row = rows[0]
    role = (row.get("chapter_role") or "").lower()
    trust = float(row.get("trust_score") or 0)
    if role in DIRECT_BROADCAST_ROLES:
        return True, "leader_role"
    if trust >= DIRECT_BROADCAST_TRUST_FLOOR:
        return True, "trust_floor"
    return False, "below_floor"


# ── Send side ──────────────────────────────────────────────────────


async def send_broadcast(
    *,
    sender_agent_id: str,
    title: str,
    body: str,
    tags: list[str] | None = None,
    audience: str = "all",
) -> dict[str, Any]:
    """Publish a broadcast locally + (optionally) push to federation.

    Returns:
        {
          "broadcast_id": str,
          "event_id": int | None,           # local event_log id
          "audience": str,                   # echo
          "federation": {                    # only present when audience != "local"
            "attempted": int,
            "succeeded": int,
            "failed": list[{peer_id, reason}]
          },
        }

    Loud failures (TypeError, ValueError) propagate. Best-effort failures
    (a peer is down, the local event_bus is unconfigured) are reported
    in the result dict — never silently swallowed.
    """
    if not is_initialized():
        raise RuntimeError("broadcast module not initialized; chapter not fully booted")

    if audience not in {"local", "federation", "all"}:
        raise ValueError(f"audience must be local|federation|all, got {audience!r}")

    broadcast_id = str(uuid.uuid4())

    payload = ChapterBroadcastPayload(
        broadcast_id=broadcast_id,
        origin_chapter_id=_chapter_id,
        sender_agent_id=sender_agent_id,
        title=title,
        body=body,
        tags=list(tags or []),
        audience=audience,
    )

    # Persist locally — this is the audit anchor. If this fails we do
    # NOT push to federation; we don't want phantom broadcasts that
    # only exist on peers.
    event_id = await event_bus.publish(EventType.CHAPTER_BROADCAST, payload)
    if event_id is None:
        return {
            "broadcast_id": broadcast_id,
            "event_id": None,
            "audience": audience,
            "error": "local_publish_failed",
        }

    # ARP — receipt for the broadcast sender. The principal is the
    # sender; the audience is intentionally NOT enumerated (fan-out
    # makes per-recipient attribution noisy in v1 — sender-only is the
    # clean cut). Future: emit per-recipient message_received receipts
    # at the inbox handler if subscribers desire that level of
    # accountability. Fire-and-forget by design.
    try:
        import asyncio as _asyncio

        import arp as arp_mod

        principal_did = arp_mod.did_key_for_member(sender_agent_id)
        if principal_did:
            _asyncio.create_task(
                arp_mod.emit_chapter_action(
                    principal_did=principal_did,
                    category="message_sent",
                    human_summary=f"You broadcast '{title[:60]}' to the {audience} audience.",
                    machine_payload={
                        "action_type_label": "chapter_broadcast",
                        "broadcast_id": broadcast_id,
                        "audience": audience,
                        "title": title[:200],
                        "tags": list(tags or [])[:10],
                    },
                )
            )
    except Exception:  # noqa: BLE001
        pass

    # Locally-only broadcasts stop here. Still audit so the log is
    # complete; total_peers=0 reflects no fanout was attempted.
    if audience == "local":
        await _audit_send(
            broadcast_id=broadcast_id,
            sender_agent_id=sender_agent_id,
            audience="local",
            title=title,
            fanout={"attempted": 0, "succeeded": 0, "failed": []},
        )
        return {
            "broadcast_id": broadcast_id,
            "event_id": event_id,
            "audience": "local",
        }

    fan = await _fanout_to_peers(payload)
    await _audit_send(
        broadcast_id=broadcast_id,
        sender_agent_id=sender_agent_id,
        audience=audience,
        title=title,
        fanout=fan,
    )
    return {
        "broadcast_id": broadcast_id,
        "event_id": event_id,
        "audience": audience,
        "federation": fan,
    }


async def _audit_send(
    *,
    broadcast_id: str,
    sender_agent_id: str,
    audience: str,
    title: str,
    fanout: dict[str, Any],
) -> None:
    """Best-effort row insert to ``broadcast_log`` after a send completes.

    Failure here is NOT fatal — the broadcast already landed on
    event_log (the canonical audit). This is the delivery-side
    audit for dashboards / podcast composer / leader review. If
    Postgres is down we log + continue rather than re-raising into
    the caller.
    """
    if _pg_request is None:
        return
    row = {
        "broadcast_id": broadcast_id,
        "chapter_id": _chapter_id,
        "sender_agent_id": sender_agent_id,
        "audience": audience,
        "title": title[:200],
        "total_peers": int(fanout.get("attempted", 0)),
        "succeeded": int(fanout.get("succeeded", 0)),
        "failed": int(len(fanout.get("failed", []))),
        "peer_results": fanout.get("failed", []),
    }
    try:
        await _pg_request("POST", "broadcast_log", body=row)
    except Exception as e:  # noqa: BLE001 — best-effort audit
        logger.warning("broadcast_log insert failed for broadcast_id=%s: %r", broadcast_id, e)


async def _fanout_to_peers(payload: ChapterBroadcastPayload) -> dict[str, Any]:
    """Push the broadcast to every known peer's inbox. Best-effort,
    bounded concurrency, per-peer timeout. Returns a summary."""
    if _federation is None:
        return {"attempted": 0, "succeeded": 0, "failed": []}

    peer_targets: list[tuple[str, str]] = []
    for peer_id, info in _federation.items():
        endpoint = info.get("endpoint") or info.get("url") or info.get("a2a_endpoint")
        if not endpoint or peer_id == _chapter_id:
            continue
        peer_targets.append((peer_id, endpoint.rstrip("/")))

    semaphore = asyncio.Semaphore(PEER_PUSH_MAX_CONCURRENCY)
    failed: list[dict[str, str]] = []
    succeeded = 0

    async def _push(peer_id: str, endpoint: str) -> None:
        nonlocal succeeded
        async with semaphore:
            try:
                ok, reason = await _push_to_peer(peer_id, endpoint, payload)
            except Exception as e:  # noqa: BLE001 — bounded; logged + reported
                ok, reason = False, f"exception:{type(e).__name__}:{e}"
            if ok:
                succeeded += 1
            else:
                failed.append({"peer_id": peer_id, "reason": reason})

    await asyncio.gather(*(_push(p, e) for p, e in peer_targets))
    return {"attempted": len(peer_targets), "succeeded": succeeded, "failed": failed}


async def _push_to_peer(
    peer_id: str,
    endpoint: str,
    payload: ChapterBroadcastPayload,
) -> tuple[bool, str]:
    """One HTTP POST to a peer's inbox. Returns (ok, reason)."""
    url = f"{endpoint}/api/federation/broadcast/inbox"
    body = payload.model_dump(exclude_none=True)
    # Convert HttpUrl-like to plain strings; Pydantic may serialize as
    # HttpUrl objects when using nested models. Not an issue here since
    # ChapterBroadcastPayload uses only str, list[str], and Literal.
    # Always include X-Server-Origin so the receiver can verify the
    # claimed origin matches a known peer in their federation registry
    # — the prototype's trust signal in lieu of full signing.
    headers = {
        "Content-Type": "application/json",
        "X-Chapter-Origin": _chapter_id,
    }
    if _sign_outbound is not None:
        # Real server-to-server Ed25519 signing: ``_sign_outbound``
        # populates the X-Chapter-DID / -Signature / -Timestamp / -Nonce
        # headers. The receiver verifies against the sender's published
        # did.json and (under enforcement) rejects forged or stale broadcasts.
        try:
            signed_headers = _sign_outbound("POST", "/api/federation/broadcast/inbox", body)
        except Exception as exc:  # OutboundUnsigned — injected callable, so caught by shape
            # H4: an unsigned broadcast is worthless to us (the receiver's
            # enforcement is what would have given it weight) and invisible from
            # here, so refuse to send rather than emit and hope.
            print(f"[broadcast][ERROR] not broadcasting to {peer_id}: {exc}")
            return False, "unsigned_refused"
        headers.update(signed_headers)

    try:
        async with httpx.AsyncClient(timeout=PEER_PUSH_TIMEOUT_SECONDS) as client:
            resp = await client.post(url, json=body, headers=headers)
    except httpx.TimeoutException:
        return False, "timeout"
    except httpx.HTTPError as e:
        return False, f"http_error:{type(e).__name__}"

    if resp.status_code in (200, 201, 202):
        return True, "ok"
    # 409 means peer dedup matched — count as success for our purposes.
    if resp.status_code == 409:
        return True, "duplicate_at_peer"
    return False, f"status:{resp.status_code}"


# ── Receive side ───────────────────────────────────────────────────


async def receive_broadcast(
    *,
    payload_dict: dict[str, Any],
    sender_chapter_id: str,
) -> dict[str, Any]:
    """Accept a broadcast pushed from a peer chapter.

    Validates the payload, dedupes against the recent in-memory ring,
    confirms ``origin_chapter_id`` matches the signing chapter, and
    re-publishes to local ``event_log``. Does NOT forward.

    Returns a dict with ``ok`` (bool) plus diagnostic fields. Status
    code mapping is the caller's job:
      * dedup hit -> 409
      * cross-tenant spoof -> 403
      * validation error -> 400
      * server error -> 500
    """
    if not is_initialized():
        return {"ok": False, "reason": "uninitialized"}

    # Validate the incoming payload BEFORE any side-effect.
    try:
        payload = ChapterBroadcastPayload.model_validate(payload_dict)
    except Exception as e:  # noqa: BLE001 — Pydantic validation error type
        return {"ok": False, "reason": "invalid_payload", "detail": str(e)[:200]}

    # Self-broadcast loopback: refuse anything that says it originated
    # at us but arrived via federation. This is a strict denial because
    # legitimate origin=self broadcasts never traverse the network.
    if payload.origin_chapter_id == _chapter_id:
        return {"ok": False, "reason": "self_origin_via_federation"}

    # Cross-tenant spoof check: the signing server MUST equal the
    # claimed origin server. Receivers do not accept "I'm forwarding
    # for server X" — that would let any peer fabricate broadcasts
    # under another server's name.
    if payload.origin_chapter_id != sender_chapter_id:
        return {
            "ok": False,
            "reason": "origin_sender_mismatch",
            "detail": f"origin={payload.origin_chapter_id} sender={sender_chapter_id}",
        }

    # Dedup. Cheap in-memory check first…
    if payload.broadcast_id in _recent_broadcast_ids:
        return {"ok": False, "reason": "duplicate", "broadcast_id": payload.broadcast_id}

    # …then the persistent check, which survives a restart (the ring does not).
    # This is what stops a captured signed broadcast from re-ingesting after a
    # restart within the signature's freshness window.
    if await _seen_persisted(payload.origin_chapter_id, payload.broadcast_id):
        _recent_broadcast_ids.append(payload.broadcast_id)  # repopulate the fast path
        return {"ok": False, "reason": "duplicate", "broadcast_id": payload.broadcast_id}

    # Persist locally. Preserves origin_chapter_id so the renderer can
    # show "from @boston" alongside our own broadcasts.
    event_id = await event_bus.publish(EventType.CHAPTER_BROADCAST, payload)
    if event_id is None:
        return {"ok": False, "reason": "local_publish_failed"}

    _recent_broadcast_ids.append(payload.broadcast_id)
    await _record_seen(payload.origin_chapter_id, payload.broadcast_id)
    return {
        "ok": True,
        "broadcast_id": payload.broadcast_id,
        "event_id": event_id,
        "origin_chapter_id": payload.origin_chapter_id,
    }


def _reset_dedup_for_tests() -> None:
    """Test-only hook to clear the in-memory dedup ring."""
    _recent_broadcast_ids.clear()


# ── Read side — audit log queries ──────────────────────────────────


async def list_recent_broadcasts(limit: int = 50) -> list[dict[str, Any]]:
    """Return this chapter's recent broadcasts from ``broadcast_log``.

    Ordered newest-first. Used by ``GET /api/broadcast/log`` for leader
    audit dashboards. The caller is responsible for auth — we trust
    that an authenticated caller is allowed to see their chapter's
    send audit (every member can see what the chapter broadcast).
    """
    if _pg_request is None:
        return []
    limit = max(1, min(int(limit), 200))
    rows = await _pg_request(
        "GET",
        "broadcast_log",
        params={
            "chapter_id": f"eq.{_chapter_id}",
            "order": "sent_at.desc",
            "limit": str(limit),
        },
    )
    return rows or []


async def hours_since_last_broadcast() -> float | None:
    """Return hours since this chapter's last broadcast, or None if never.

    Used by ``think_chapter_broadcast`` to honour the
    ``chapter_broadcast.min_interval_hours`` policy and avoid
    flooding peers with backlog after the cycle gets enabled.
    """
    if _pg_request is None:
        return None
    rows = await _pg_request(
        "GET",
        "broadcast_log",
        params={
            "chapter_id": f"eq.{_chapter_id}",
            "order": "sent_at.desc",
            "limit": "1",
            "select": "sent_at",
        },
    )
    if not rows:
        return None
    sent_at_str = rows[0].get("sent_at")
    if not sent_at_str:
        return None
    from datetime import UTC, datetime

    try:
        sent_at = datetime.fromisoformat(sent_at_str.replace("Z", "+00:00"))
    except ValueError:
        return None
    delta = datetime.now(UTC) - sent_at
    return delta.total_seconds() / 3600.0
