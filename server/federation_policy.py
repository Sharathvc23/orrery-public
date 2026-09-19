"""
Federation policy — per-peer state, exponential backoff, self-healing.

PR-2c of the governance rework. Makes the federation a self-healing
topology: failures tracked per peer, backoff doubles per consecutive
failure (capped), quarantined peers auto-probed for recovery, leaders
can explicitly block peers they don't want in their federation.

State machine:
  unknown     — first time we see this peer_id
  online      — reachable, exchanges running
  degraded    — recent failures but still trying
  quarantined — consecutive_failures >= 3; probed every 30 min
  blocked     — leader explicitly set; probes do NOT run; manual unblock only

Transitions are persisted to federation_policy + logged to
federation_policy_history for leader digest + audit.
"""

from __future__ import annotations

import os
import time
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx

_pg_request = None
_agent_id = ""

BASELINE_BACKOFF_SECONDS = 360  # 6-min default exchange cadence
MAX_BACKOFF_SECONDS = 3600  # 1h cap
QUARANTINE_THRESHOLD = 3  # consecutive failures
PROBE_COOLDOWN = timedelta(minutes=30)


def init(pg_request, agent_id: str) -> None:
    global _pg_request, _agent_id
    _pg_request = pg_request
    _agent_id = agent_id


# ═══════════════════════════════════════════════════════════════
# Pure helpers — testable without Postgres
# ═══════════════════════════════════════════════════════════════


def next_backoff(current: int, baseline: int = BASELINE_BACKOFF_SECONDS, cap: int = MAX_BACKOFF_SECONDS) -> int:
    """Double the backoff, capped at max."""
    doubled = max(baseline, current) * 2
    return min(cap, doubled)


def reset_backoff(baseline: int = BASELINE_BACKOFF_SECONDS) -> int:
    return baseline


def should_exchange_now(
    state: str,
    last_success_at: datetime | None,
    last_failure_at: datetime | None,
    backoff_seconds: int,
    blocked: bool,
    now: datetime | None = None,
) -> bool:
    """Decision: is it time to attempt an exchange with this peer?

    - blocked → never
    - online with no failure → yes (caller rate-limits)
    - degraded/quarantined → only if last attempt older than backoff_seconds
    - unknown → yes (probe it)
    """
    if blocked:
        return False
    if state == "unknown" or state == "online":
        return True
    now = now or datetime.now(UTC)
    last_attempt = max(
        last_success_at or datetime.min.replace(tzinfo=UTC), last_failure_at or datetime.min.replace(tzinfo=UTC)
    )
    if last_attempt == datetime.min.replace(tzinfo=UTC):
        return True
    elapsed = (now - last_attempt).total_seconds()
    return elapsed >= backoff_seconds


def state_after_success(current_state: str) -> str:
    """On success, every non-blocked state → online."""
    if current_state == "blocked":
        return "blocked"
    return "online"


def state_after_failure(current_state: str, consecutive_failures: int) -> str:
    """On failure, escalate: online → degraded → quarantined."""
    if current_state == "blocked":
        return "blocked"
    if consecutive_failures >= QUARANTINE_THRESHOLD:
        return "quarantined"
    return "degraded"


# ═══════════════════════════════════════════════════════════════
# Postgres-backed record operations
# ═══════════════════════════════════════════════════════════════


async def get_peer_policy(peer_chapter_id: str) -> dict | None:
    if _pg_request is None:
        return None
    try:
        rows = await _pg_request(
            "GET",
            "federation_policy",
            params={
                "chapter_id": f"eq.{_agent_id}",
                "peer_chapter_id": f"eq.{peer_chapter_id}",
                "select": "*",
            },
        )
        return rows[0] if rows else None
    except Exception:
        return None


async def list_policies() -> list[dict]:
    if _pg_request is None:
        return []
    try:
        return (
            await _pg_request(
                "GET",
                "federation_policy",
                params={"chapter_id": f"eq.{_agent_id}", "order": "peer_chapter_id.asc"},
            )
            or []
        )
    except Exception:
        return []


async def upsert_peer(peer_chapter_id: str, peer_endpoint: str | None = None) -> dict | None:
    """Create the policy row for a peer if it doesn't exist; update endpoint if different."""
    if _pg_request is None:
        return None
    existing = await get_peer_policy(peer_chapter_id)
    if existing:
        if peer_endpoint and existing.get("peer_endpoint") != peer_endpoint:
            try:
                rows = await _pg_request(
                    "PATCH",
                    "federation_policy", params={"chapter_id": f"eq.{_agent_id}", "peer_chapter_id": f"eq.{peer_chapter_id}"},
                    body={"peer_endpoint": peer_endpoint, "updated_at": datetime.now(UTC).isoformat()},
                )
                return rows[0] if isinstance(rows, list) and rows else existing
            except Exception:
                pass
        return existing
    try:
        rows = await _pg_request(
            "POST",
            "federation_policy",
            body={
                "chapter_id": _agent_id,
                "peer_chapter_id": peer_chapter_id,
                "peer_endpoint": peer_endpoint,
                "state": "unknown",
                "consecutive_failures": 0,
                "backoff_seconds": BASELINE_BACKOFF_SECONDS,
                "max_backoff_seconds": MAX_BACKOFF_SECONDS,
            },
        )
        await _log_history(peer_chapter_id, "seed", None, "unknown", "initial record", _agent_id)
        return rows[0] if isinstance(rows, list) and rows else None
    except Exception:
        return None


async def record_success(peer_chapter_id: str, peer_endpoint: str | None = None) -> None:
    if _pg_request is None:
        return
    policy = await upsert_peer(peer_chapter_id, peer_endpoint)
    if not policy:
        return
    old_state = policy.get("state", "unknown")
    new_state = state_after_success(old_state)
    try:
        await _pg_request(
            "PATCH",
            "federation_policy", params={"chapter_id": f"eq.{_agent_id}", "peer_chapter_id": f"eq.{peer_chapter_id}"},
            body={
                "state": new_state,
                "consecutive_failures": 0,
                "backoff_seconds": reset_backoff(),
                "last_success_at": datetime.now(UTC).isoformat(),
                "last_error": None,
                "updated_at": datetime.now(UTC).isoformat(),
            },
        )
        if old_state != new_state:
            await _log_history(
                peer_chapter_id,
                "recover" if old_state in ("degraded", "quarantined") else "success",
                old_state,
                new_state,
                None,
                _agent_id,
            )
    except Exception as e:
        print(f"[FedPolicy] record_success({peer_chapter_id}) failed: {e}")


async def record_failure(peer_chapter_id: str, error: str = "", peer_endpoint: str | None = None) -> None:
    if _pg_request is None:
        return
    policy = await upsert_peer(peer_chapter_id, peer_endpoint)
    if not policy:
        return
    if policy.get("state") == "blocked":
        return  # failures on blocked peers are ignored
    old_state = policy.get("state", "unknown")
    fails = (policy.get("consecutive_failures") or 0) + 1
    new_state = state_after_failure(old_state, fails)
    new_backoff = next_backoff(policy.get("backoff_seconds") or BASELINE_BACKOFF_SECONDS)
    try:
        await _pg_request(
            "PATCH",
            "federation_policy", params={"chapter_id": f"eq.{_agent_id}", "peer_chapter_id": f"eq.{peer_chapter_id}"},
            body={
                "state": new_state,
                "consecutive_failures": fails,
                "backoff_seconds": new_backoff,
                "last_failure_at": datetime.now(UTC).isoformat(),
                "last_error": error[:500] if error else None,
                "updated_at": datetime.now(UTC).isoformat(),
            },
        )
        if old_state != new_state:
            event = "quarantine" if new_state == "quarantined" else "failure"
            await _log_history(peer_chapter_id, event, old_state, new_state, error[:200], _agent_id)
    except Exception as e:
        print(f"[FedPolicy] record_failure({peer_chapter_id}) failed: {e}")


async def should_exchange_with(peer_chapter_id: str) -> bool:
    policy = await get_peer_policy(peer_chapter_id)
    if not policy:
        return True  # unknown peer — allow the first probe
    return should_exchange_now(
        state=policy.get("state", "unknown"),
        last_success_at=_parse_ts(policy.get("last_success_at")),
        last_failure_at=_parse_ts(policy.get("last_failure_at")),
        backoff_seconds=policy.get("backoff_seconds") or BASELINE_BACKOFF_SECONDS,
        blocked=(policy.get("state") == "blocked"),
    )


# ═══════════════════════════════════════════════════════════════
# Leader controls — block / unblock
# ═══════════════════════════════════════════════════════════════


async def block_peer(peer_chapter_id: str, actor_agent_id: str, reason: str = "") -> dict:
    """Leader: drop a peer from the federation permanently (until unblocked)."""
    if _pg_request is None:
        return {"error": "no_database"}
    policy = await upsert_peer(peer_chapter_id)
    if not policy:
        return {"error": "upsert_failed"}
    old_state = policy.get("state", "unknown")
    try:
        rows = await _pg_request(
            "PATCH",
            "federation_policy", params={"chapter_id": f"eq.{_agent_id}", "peer_chapter_id": f"eq.{peer_chapter_id}"},
            body={
                "state": "blocked",
                "blocked_by": actor_agent_id,
                "blocked_reason": reason[:500],
                "blocked_at": datetime.now(UTC).isoformat(),
                "updated_at": datetime.now(UTC).isoformat(),
            },
        )
        await _log_history(peer_chapter_id, "block", old_state, "blocked", reason[:200], actor_agent_id)
        return {"ok": True, "policy": rows[0] if isinstance(rows, list) and rows else None}
    except Exception as e:
        return {"error": "patch_failed", "detail": str(e)[:200]}


async def unblock_peer(peer_chapter_id: str, actor_agent_id: str) -> dict:
    if _pg_request is None:
        return {"error": "no_database"}
    policy = await get_peer_policy(peer_chapter_id)
    if not policy:
        return {"error": "not_found"}
    if policy.get("state") != "blocked":
        return {"error": "not_blocked", "current_state": policy.get("state")}
    try:
        rows = await _pg_request(
            "PATCH",
            "federation_policy", params={"chapter_id": f"eq.{_agent_id}", "peer_chapter_id": f"eq.{peer_chapter_id}"},
            body={
                "state": "unknown",
                "blocked_by": None,
                "blocked_reason": None,
                "blocked_at": None,
                "consecutive_failures": 0,
                "backoff_seconds": reset_backoff(),
                "updated_at": datetime.now(UTC).isoformat(),
            },
        )
        await _log_history(peer_chapter_id, "unblock", "blocked", "unknown", None, actor_agent_id)
        return {"ok": True, "policy": rows[0] if isinstance(rows, list) and rows else None}
    except Exception as e:
        return {"error": "patch_failed", "detail": str(e)[:200]}


# ═══════════════════════════════════════════════════════════════
# DID pinning — trust-on-first-use for attested peer identities
# ═══════════════════════════════════════════════════════════════


async def forget_peer(peer_chapter_id: str, actor_agent_id: str, reason: str = "") -> dict:
    """Leader: FORGET a peer — delete its policy row entirely.

    block_peer keeps a deliberate, reversible tombstone; forget removes a
    dead/legacy peer from every surface it haunts (/health federation_state,
    the Prometheus federation gauges, exchange scheduling). History keeps the
    audit trail — the row is gone, the record of forgetting is not.
    """
    if _pg_request is None:
        return {"error": "no_database"}
    policy = await get_peer_policy(peer_chapter_id)
    if not policy:
        return {"error": "not_found"}
    old_state = policy.get("state", "unknown")
    try:
        await _pg_request(
            "DELETE",
            "federation_policy",
            params={"chapter_id": f"eq.{_agent_id}", "peer_chapter_id": f"eq.{peer_chapter_id}"},
        )
    except Exception as e:
        return {"error": f"delete_failed:{type(e).__name__}"}
    await _log_history(peer_chapter_id, "forget", old_state, "forgotten", reason or "leader forget", actor_agent_id)
    return {"ok": True, "peer_chapter_id": peer_chapter_id, "forgotten": True, "previous_state": old_state}


async def prune_stale_peers(
    anchored_endpoints: list[str], live_peer_ids: set[str], max_stale_s: int
) -> list[str]:
    """Heartbeat auto-prune: forget policy rows for peers that are
    simultaneously (a) NOT operator-anchored (KNOWN_CHAPTER_ENDPOINTS — the
    trust anchor is never auto-forgotten), (b) NOT currently in the live
    federation, (c) NOT deliberately blocked (a leader tombstone is kept),
    and (d) stale past ``max_stale_s`` since the last success (falling back
    to updated_at/created_at for never-succeeded rows). Returns the pruned
    peer ids. ``max_stale_s <= 0`` disables pruning entirely.
    """
    if _pg_request is None or max_stale_s <= 0:
        return []
    now = datetime.now(UTC)
    anchored = {e.rstrip("/") for e in anchored_endpoints if e}
    pruned: list[str] = []
    for p in await list_policies():
        pid = str(p.get("peer_chapter_id") or "")
        if not pid or pid in live_peer_ids:
            continue
        if p.get("state") == "blocked":
            continue
        if str(p.get("peer_endpoint") or "").rstrip("/") in anchored:
            continue
        ts = _parse_ts(p.get("last_success_at")) or _parse_ts(p.get("updated_at")) or _parse_ts(p.get("created_at"))
        if ts is None:
            continue  # undatable row — leave it for the leader's explicit forget
        stale_s = (now - ts).total_seconds()
        if stale_s < max_stale_s:
            continue
        result = await forget_peer(
            pid, _agent_id, reason=f"auto-prune: stale {int(stale_s)}s, not anchored, not live"
        )
        if result.get("ok"):
            pruned.append(pid)
    if pruned:
        print(f"  Federation: auto-pruned stale peer(s): {', '.join(pruned)}")
    return pruned


# ── H9: peer key rotation without a mesh outage ──────────────────────────────
# A peer that legitimately rotates its signing key is isolated until an operator
# runs clear_did_pin: every verification against the kept pin fails. The fix is
# NOT to relax the pin — an automated "accept the new key" path is a takeover
# primitive. It is to accept exactly one thing: a rotation the peer proves with
# the key we ALREADY trust.
#
# ⚠️ Signed-by-the-OLD-key is the entire security of this. An attestation signed
# by the incoming key proves only that the attacker holds the key they are
# installing, which is what they would have either way. Every refusal in
# test_h9_rotation_attestation.py exists because the corresponding acceptance
# would be a silent hijack, and those tests were written before this code.
ROTATION_TYPE = "chapter.key.rotation"
ROTATION_MAX_AGE_S = int(os.environ.get("FEDERATION_ROTATION_MAX_AGE_S", "3600"))


def rotation_signing_material(att: dict) -> bytes:
    """Canonical bytes a rotation attestation is signed over.

    Binds peer, old key, new key and time. A field outside this material is a
    field an attacker can edit without breaking the signature, so the test suite
    asserts each one changes the output.
    """
    import jcs

    return jcs.canonicalize(
        {
            "type": ROTATION_TYPE,
            "peer_chapter_id": att.get("peer_chapter_id", ""),
            "old_did": att.get("old_did", ""),
            "new_did": att.get("new_did", ""),
            "issued_at": att.get("issued_at", 0),
        }
    )


def verify_rotation_attestation(
    att: dict, *, peer_id: str, pinned_did: str | None, now: float | None = None
) -> tuple[bool, str]:
    """Whether ``att`` authorises replacing ``pinned_did`` with ``att['new_did']``.

    Returns ``(ok, reason)``. Every rejection names its reason: a refusal nobody
    can diagnose gets cleared by an operator reaching for clear_did_pin, which
    is the very step this exists to remove.
    """
    import base64

    if not pinned_did:
        # No existing pin means no OLD key, so continuity cannot be proven. That
        # is first-sighting TOFU, a different path — never rotation.
        return False, "no_pin"
    if att.get("type") != ROTATION_TYPE:
        return False, "wrong_type"
    if att.get("peer_chapter_id") != peer_id:
        return False, "peer_mismatch"
    if att.get("old_did") != pinned_did:
        return False, "old_did_not_pinned"
    new_did = att.get("new_did") or ""
    if not new_did.startswith("did:key:") or new_did == pinned_did:
        return False, "new_did_invalid"

    issued_at = att.get("issued_at")
    if not isinstance(issued_at, int):
        return False, "issued_at_invalid"
    age = (now if now is not None else time.time()) - issued_at
    if age > ROTATION_MAX_AGE_S:
        return False, "stale"
    if age < -ROTATION_MAX_AGE_S:
        return False, "future_dated"

    sig_b64 = att.get("signature") or ""
    if not sig_b64:
        return False, "no_signature"
    # Verified against the OLD (pinned) key — never against new_did, which is
    # what makes this continuity rather than self-assertion.
    # did:key is self-certifying: the identifier IS the public key, so the
    # verifying key is derived from the pin itself rather than transported.
    try:
        import base58

        raw = base58.b58decode(pinned_did.removeprefix("did:key:")[1:])
        if not raw.startswith(b"\xed\x01"):
            return False, "pinned_did_undecodable"
        pub_bytes = raw[2:]
    except Exception:  # noqa: BLE001
        return False, "pinned_did_undecodable"
    try:
        import nacl.exceptions
        import nacl.signing

        nacl.signing.VerifyKey(pub_bytes).verify(
            rotation_signing_material(att), base64.b64decode(sig_b64)
        )
    except Exception:  # noqa: BLE001 — any failure is a refusal
        return False, "signature_not_by_pinned_key"
    return True, "ok"


# ── §8.5.2: the chain, and pulling a peer's ────────────────────────────────
# The single-attestation verifier above proves ONE link. A receiver that has
# been offline across two rotations holds a pin two links back, and no single
# attestation can prove continuity to it — accepting one anyway would be
# accepting a key nothing proved. So the peer publishes an ordered chain and the
# receiver walks it forward from its own pin.
ROTATION_WELL_KNOWN = "/.well-known/nanda-chapter-rotation.json"


def walk_rotation_chain(
    rotations: list[dict],
    *,
    peer_id: str,
    pinned_did: str,
    now: float | None = None,
) -> tuple[bool, str, str]:
    """Walk a §8.5.2 chain forward from ``pinned_did``. Returns (ok, reason, did).

    ATOMIC. On any broken link the whole walk is refused and the ORIGINAL pin is
    returned, never a partially-advanced one: §8.5.3 says a receiver that cannot
    establish every condition keeps the existing pin, and stopping on a valid
    prefix would leave the pin on a key no complete chain authorised.
    """
    if not isinstance(rotations, list) or not rotations:
        return False, "empty_chain", pinned_did
    current = pinned_did
    for att in rotations:
        if not isinstance(att, dict):
            return False, "malformed_entry", pinned_did
        ok, reason = verify_rotation_attestation(
            att, peer_id=peer_id, pinned_did=current, now=now
        )
        if not ok:
            # A link that does not continue from what we have accepted so far is
            # a chain break (§8.5.4 R9), reported as such rather than as a
            # generic pin mismatch — an operator reading "old_did_not_pinned"
            # here would reach for clear_did_pin, which is the manual step this
            # exists to remove.
            return False, ("chain_break" if reason == "old_did_not_pinned" else reason), pinned_did
        current = str(att["new_did"])
    return True, "ok", current


async def fetch_peer_rotation_chain(peer_endpoint: str, *, timeout: float = 5.0) -> list[dict] | None:
    """GET the peer's published chain. ``None`` on any failure — never raises.

    §8.5.2: an endpoint that is absent, unreachable or malformed is not an error
    to route around. The caller keeps its pin, which is exactly today's
    fail-closed behaviour rather than a new failure mode.
    """
    if not peer_endpoint:
        return None
    import httpx

    url = peer_endpoint.rstrip("/") + ROTATION_WELL_KNOWN
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
            resp = await client.get(url)
        if resp.status_code != 200:
            return None
        body = resp.json()
    except Exception as e:  # noqa: BLE001 — unreachable/malformed is a keep-the-pin, not a crash
        print(f"[FedPolicy] rotation chain fetch failed for {url}: {type(e).__name__}: {e}")
        return None
    rotations = body.get("rotations") if isinstance(body, dict) else None
    return rotations if isinstance(rotations, list) else None


async def try_accept_peer_rotation(
    peer_chapter_id: str,
    *,
    attested_did: str,
    pinned_did: str,
    peer_endpoint: str | None,
) -> tuple[bool, str]:
    """§8.5: on a pin mismatch, pull the peer's chain and accept ONLY a valid one.

    Returns ``(accepted, reason)``. Every outcome is logged to policy history —
    a key change that leaves no trace is indistinguishable from one that never
    happened (§8.5.3), and a refusal nobody can read gets "fixed" by an operator
    clearing the pin by hand, which is the hazard §8.5 removes.
    """
    if not peer_endpoint:
        return False, "no_endpoint_to_pull_from"
    rotations = await fetch_peer_rotation_chain(peer_endpoint)
    if rotations is None:
        return False, "no_chain_published"
    ok, reason, final_did = walk_rotation_chain(
        rotations, peer_id=peer_chapter_id, pinned_did=pinned_did
    )
    if not ok:
        return False, reason
    if final_did != attested_did:
        # The chain is internally valid but lands somewhere other than the key
        # actually presented. Accepting would pin a third key neither party is
        # using.
        return False, "chain_does_not_reach_attested_did"
    return True, "ok"


async def published_rotation_chain() -> list[dict]:
    """This org's own rotation chain, oldest-first, for §8.5.2 publication.

    Read from the persistent policy store so it survives a restart: a chain that
    lived only in memory would silently shorten on every deploy, and a peer two
    rotations behind would then be unable to prove continuity through the gap —
    the exact failure the chain exists to prevent.

    Empty until a rotation is performed. No rotation is performed here.
    """
    if _pg_request is None:
        return []
    try:
        rows = await _pg_request(
            "GET",
            "chapter_key_rotations",
            params={"chapter_id": f"eq.{_agent_id}", "order": "issued_at.asc"},
        )
    except Exception as e:  # noqa: BLE001 — a missing table must not 500 the well-known
        print(f"[FedPolicy] published_rotation_chain unavailable: {type(e).__name__}: {e}")
        return []
    if not isinstance(rows, list):
        return []
    out: list[dict] = []
    for r in rows:
        att = r.get("attestation") if isinstance(r, dict) else None
        if isinstance(att, dict):
            out.append(att)
    return out


async def check_and_pin_did(peer_chapter_id: str, did: str, peer_endpoint: str | None = None) -> tuple[str, str | None]:
    """TOFU pin of a peer's attested did:key against the persistent policy row.

    Returns ``(status, pinned_did)``:
      ``("pinned", did)``   — first attested sighting; pinned now
      ``("match", did)``    — attested DID equals the existing pin
      ``("rotated", did)``  — attested DID differs AND the peer proved the
                              change with a §8.5 chain from our pin; pin updated
      ``("mismatch", old)`` — attested DID differs and no valid chain proved it;
                              THE PIN IS KEPT
      ``("no_database", None)`` — no Postgres / pin not persistable

    The pin is never overwritten on an UNPROVEN mismatch: a registry record
    alone can never rotate a peer's identity, or a cheating registry could
    rotate a peer out from under every org that discovered it there. The only
    thing that moves a pin is spec/0.6 §8.5 — a chain the peer signs with the
    key we already trust. ``clear_did_pin`` remains for the case where no such
    proof exists (a genuinely lost key).
    """
    if _pg_request is None or not did:
        return "no_database", None
    policy = await upsert_peer(peer_chapter_id, peer_endpoint)
    if not policy:
        return "no_database", None
    existing = policy.get("pinned_did") or None
    if existing:
        if existing == did:
            return "match", existing
        state = policy.get("state", "unknown")
        # §8.5: a mismatch is either an attack or a legitimate rotation, and
        # until now this code could not tell them apart — it kept the pin and
        # the peer stayed isolated until a human ran clear_did_pin. Now we ask
        # the one question that distinguishes them: can the peer prove the
        # change with the key we ALREADY trust?
        #
        # This never relaxes the pin. It accepts exactly one thing — a valid
        # chain from our pin to the DID actually presented. Everything else,
        # including no published chain at all, falls through to the original
        # keep-the-pin behaviour below.
        accepted, why = await try_accept_peer_rotation(
            peer_chapter_id,
            attested_did=did,
            pinned_did=existing,
            peer_endpoint=peer_endpoint or policy.get("endpoint"),
        )
        if accepted:
            try:
                now = datetime.now(UTC).isoformat()
                await _pg_request(
                    "PATCH",
                    "federation_policy",
                    params={"chapter_id": f"eq.{_agent_id}", "peer_chapter_id": f"eq.{peer_chapter_id}"},
                    body={"pinned_did": did, "pinned_at": now, "updated_at": now},
                )
            except Exception as e:  # noqa: BLE001 — a failed write must not pretend to have rotated
                print(f"[FedPolicy] rotation accepted but pin write failed for {peer_chapter_id}: {e}")
                await _log_history(
                    peer_chapter_id, "did_rotation_write_failed", state, state,
                    f"verified chain to {did[:120]} but pin not persisted: {e}", _agent_id,
                )
                return "mismatch", existing
            await _log_history(
                peer_chapter_id,
                "did_rotation_accepted",
                state,
                state,
                f"§8.5 chain verified from {existing[:60]} to {did[:60]}",
                _agent_id,
            )
            return "rotated", did
        await _log_history(
            peer_chapter_id,
            "did_mismatch",
            state,
            state,
            f"attested {did[:120]} != pinned {existing[:120]}; rotation refused: {why}",
            _agent_id,
        )
        return "mismatch", existing
    try:
        now = datetime.now(UTC).isoformat()
        await _pg_request(
            "PATCH",
            "federation_policy", params={"chapter_id": f"eq.{_agent_id}", "peer_chapter_id": f"eq.{peer_chapter_id}"},
            body={"pinned_did": did, "pinned_at": now, "updated_at": now},
        )
        state = policy.get("state", "unknown")
        await _log_history(peer_chapter_id, "did_pin", state, state, did[:200], _agent_id)
        return "pinned", did
    except Exception as e:
        # A pre-migration schema (no pinned_did column) lands here — pinning
        # degrades to per-cycle TOFU rather than wedging discovery.
        print(f"[FedPolicy] check_and_pin_did({peer_chapter_id}) failed: {e}")
        return "no_database", None


async def clear_did_pin(peer_chapter_id: str, actor_agent_id: str) -> dict:
    """Leader: clear a peer's pinned DID to accept a legitimate key rotation.
    The peer's next attested sighting re-pins (TOFU again)."""
    if _pg_request is None:
        return {"error": "no_database"}
    policy = await get_peer_policy(peer_chapter_id)
    if not policy:
        return {"error": "not_found"}
    old_pin = policy.get("pinned_did") or None
    if not old_pin:
        return {"error": "not_pinned"}
    try:
        rows = await _pg_request(
            "PATCH",
            "federation_policy", params={"chapter_id": f"eq.{_agent_id}", "peer_chapter_id": f"eq.{peer_chapter_id}"},
            body={"pinned_did": None, "pinned_at": None, "updated_at": datetime.now(UTC).isoformat()},
        )
        state = policy.get("state", "unknown")
        await _log_history(peer_chapter_id, "did_unpin", state, state, f"cleared {old_pin[:120]}", actor_agent_id)
        return {"ok": True, "policy": rows[0] if isinstance(rows, list) and rows else None}
    except Exception as e:
        return {"error": "patch_failed", "detail": str(e)[:200]}


# ═══════════════════════════════════════════════════════════════
# Auto-recovery probe — runs from think_approvals_sweep
# ═══════════════════════════════════════════════════════════════


async def probe_quarantined() -> dict:
    """Probe quarantined peers that haven't been probed in the last 30 min.

    Success moves them back to 'online' and resets backoff. Failure just
    records another failure (backoff continues to extend).
    Returns {recovered: [...], still_down: [...]}.
    """
    if _pg_request is None:
        return {"recovered": [], "still_down": []}

    try:
        due = await _pg_request(
            "GET",
            "federation_probe_due",
            params={"chapter_id": f"eq.{_agent_id}", "limit": "50"},
        )
    except Exception:
        return {"recovered": [], "still_down": []}

    recovered: list[str] = []
    still_down: list[str] = []

    for policy in due or []:
        peer_id = policy.get("peer_chapter_id")
        endpoint = policy.get("peer_endpoint")
        if not peer_id or not endpoint:
            continue
        # Record probe attempt
        try:
            await _pg_request(
                "PATCH",
                "federation_policy", params={"chapter_id": f"eq.{_agent_id}", "peer_chapter_id": f"eq.{peer_id}"},
                body={"last_probe_at": datetime.now(UTC).isoformat()},
            )
        except Exception:
            pass
        # Actual HTTP probe
        ok = await _http_probe(endpoint)
        if ok:
            await record_success(peer_id, endpoint)
            recovered.append(peer_id)
        else:
            await record_failure(peer_id, "probe_failed", endpoint)
            still_down.append(peer_id)

    return {"recovered": recovered, "still_down": still_down}


async def _http_probe(endpoint: str) -> bool:
    """Cheap GET /health probe. 2xx = up."""
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{endpoint.rstrip('/')}/health", timeout=8.0)
            return resp.status_code < 300
    except Exception:
        return False


# ═══════════════════════════════════════════════════════════════
# Utility
# ═══════════════════════════════════════════════════════════════


def _parse_ts(v: Any) -> datetime | None:
    if not v:
        return None
    try:
        if isinstance(v, datetime):
            return v
        return datetime.fromisoformat(str(v).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


async def _log_history(
    peer_chapter_id: str,
    event: str,
    old_state: str | None,
    new_state: str | None,
    detail: str | None,
    actor: str | None,
) -> None:
    if _pg_request is None:
        return
    try:
        await _pg_request(
            "POST",
            "federation_policy_history",
            body={
                "chapter_id": _agent_id,
                "peer_chapter_id": peer_chapter_id,
                "event": event,
                "old_state": old_state,
                "new_state": new_state,
                "detail": (detail or "")[:500],
                "actor": actor,
            },
        )
    except Exception:
        pass


async def history_for(peer_chapter_id: str, limit: int = 50) -> list[dict]:
    if _pg_request is None:
        return []
    try:
        return (
            await _pg_request(
                "GET",
                "federation_policy_history",
                params={
                    "chapter_id": f"eq.{_agent_id}",
                    "peer_chapter_id": f"eq.{peer_chapter_id}",
                    "order": "created_at.desc",
                    "limit": str(min(limit, 500)),
                },
            )
            or []
        )
    except Exception:
        return []
