"""
Agent authority scope — the explicit delegation contract.

PR-3 of the governance rework. Every sovereign agent tool call flows
through `check_authority()` first. A member's human has already
consented to each action_kind via the authority_scope table; the check
here enforces rate limits + structural constraints.

Actions are categorised by default posture:
  auto-allowed: submit_intent (3/wk), submit_call (2/day),
                respond_to_{call,intent}, update_projection,
                save_private_note, start_conversation (5/day),
                rsvp_event (virtual+in-person)
  opt-in:       accept_meeting, cross_chapter_message,
                publish_public_note

When a check fails, returns a structured decision the calling tool
can surface back to the LLM so it explains to the member why the
action didn't happen.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

_pg_request = None
_agent_id = ""


class UsageLookupError(RuntimeError):
    """Raised when the per-(agent, action, window) usage count cannot be read.

    That change: the count MUST NOT silently fall back to 0 on a DB error — with a rate
    cap in force, ``used=0`` reads as "under the cap" and the rate-limited action is
    allowed (quota bypass, fail-open on resources). The caller (``check_authority``)
    turns this into a fail-CLOSED deny.
    """

# Tool-name → action_kind. Sovereign runtime + community-member share this map.
TOOL_ACTION_MAP: dict[str, str] = {
    "submit_intent": "submit_intent",
    "respond_to_intent": "respond_to_intent",
    "submit_call": "submit_call",
    "respond_to_call": "respond_to_call",
    "update_projection": "update_projection",
    "save_private_note": "save_private_note",
    "save_note": "save_private_note",  # community-member uses save_note locally
    "start_conversation": "start_conversation",
    "rsvp_event": "rsvp_event",
    "accept_meeting": "accept_meeting",
}


VALID_ACTIONS = {
    "submit_intent",
    "respond_to_intent",
    "submit_call",
    "respond_to_call",
    "update_projection",
    "rsvp_event",
    "accept_meeting",
    "start_conversation",
    "cross_chapter_message",
    "publish_public_note",
    "save_private_note",
}


def init(pg_request, agent_id: str) -> None:
    global _pg_request, _agent_id
    _pg_request = pg_request
    _agent_id = agent_id


# ═══════════════════════════════════════════════════════════════
# Read scope + usage
# ═══════════════════════════════════════════════════════════════


async def get_scope(agent_id: str, action_kind: str) -> dict | None:
    if _pg_request is None:
        return None
    try:
        rows = await _pg_request(
            "GET",
            "agent_authority_scope",
            params={
                "agent_id": f"eq.{agent_id}",
                "action_kind": f"eq.{action_kind}",
                "select": "*",
            },
        )
        return rows[0] if rows else None
    except Exception:
        return None


async def list_scope_for(agent_id: str) -> list[dict]:
    if _pg_request is None:
        return []
    try:
        return (
            await _pg_request(
                "GET",
                "agent_authority_scope",
                params={"agent_id": f"eq.{agent_id}", "order": "action_kind.asc"},
            )
            or []
        )
    except Exception:
        return []


async def _usage_count(agent_id: str, action_kind: str, window_kind: str) -> int:
    """Current usage count for this (agent, action, window) bucket.

    That change: fails CLOSED. A DB error (or an absent DB when a rate cap is being
    enforced, or an unparseable stored count) raises ``UsageLookupError`` rather
    than returning 0 — an unknown count must never be treated as "no usage yet",
    which would let the rate-limited action through. A SUCCESSFUL query with no row
    still legitimately returns 0 (the window genuinely has no usage).
    """
    if _pg_request is None:
        raise UsageLookupError("no database configured for usage lookup")
    window_start = _window_start(window_kind)
    try:
        rows = await _pg_request(
            "GET",
            "agent_authority_usage",
            params={
                "agent_id": f"eq.{agent_id}",
                "action_kind": f"eq.{action_kind}",
                "window_kind": f"eq.{window_kind}",
                "window_start": f"eq.{window_start.isoformat()}",
                "select": "count",
            },
        )
    except Exception as e:  # noqa: BLE001 — any read failure fails closed, never 0
        raise UsageLookupError(f"usage lookup failed for {action_kind}/{window_kind}: {e}") from e
    if not rows:
        return 0
    try:
        return int(rows[0].get("count") or 0)
    except (TypeError, ValueError) as e:
        raise UsageLookupError(f"unparseable usage count for {action_kind}/{window_kind}: {e}") from e


def _window_start(window_kind: str, now: datetime | None = None) -> datetime:
    now = now or datetime.now(UTC)
    if window_kind == "day":
        return now.replace(hour=0, minute=0, second=0, microsecond=0)
    if window_kind == "week":
        # ISO week: Monday 00:00 UTC
        days_since_monday = now.weekday()
        monday = now - timedelta(days=days_since_monday)
        return monday.replace(hour=0, minute=0, second=0, microsecond=0)
    return now


# ═══════════════════════════════════════════════════════════════
# Pure constraint evaluator (testable without Postgres)
# ═══════════════════════════════════════════════════════════════


def check_constraints(
    action_kind: str,
    constraints: dict,
    context: dict | None = None,
    current_usage: dict[str, int] | None = None,
) -> tuple[bool, str]:
    """Evaluate constraints against the current attempt context.

    Returns (allowed, reason_if_denied).

    context keys (action-specific):
      rsvp_event:       {"type": "virtual"|"in_person"}
      accept_meeting:   {"duration_min": int, "hour": int, "tz": str}
      submit_call:      {}
      (others):         {}

    current_usage: {"per_day": n, "per_week": n}
    """
    context = context or {}
    current_usage = current_usage or {}

    # Rate limits
    if "max_per_day" in constraints:
        cap = int(constraints["max_per_day"])
        used = int(current_usage.get("per_day", 0))
        if used >= cap:
            return (False, f"rate_limit: {used}/{cap} per day")

    if "max_per_week" in constraints:
        cap = int(constraints["max_per_week"])
        used = int(current_usage.get("per_week", 0))
        if used >= cap:
            return (False, f"rate_limit: {used}/{cap} per week")

    # Structural constraints per action
    if action_kind == "rsvp_event":
        allowed_types = constraints.get("types")
        proposed_type = context.get("type")
        if allowed_types and proposed_type and proposed_type not in allowed_types:
            return (False, f"attendance_type {proposed_type!r} not in {allowed_types}")

    if action_kind == "accept_meeting":
        max_min = constraints.get("duration_max_min")
        dur = context.get("duration_min")
        if max_min and dur and int(dur) > int(max_min):
            return (False, f"duration {dur}m exceeds max {max_min}m")
        hours = constraints.get("hours")  # "HH:MM-HH:MM" in TZ
        hour = context.get("hour")
        if hours and hour is not None:
            try:
                start, end = hours.split("-")
                start_h = int(start.split(":")[0])
                end_h = int(end.split(":")[0])
                if not (start_h <= int(hour) < end_h):
                    return (False, f"hour {hour} outside {hours}")
            except (ValueError, AttributeError):
                pass

    return (True, "ok")


# ═══════════════════════════════════════════════════════════════
# Main gate — call this before every sovereign tool invocation
# ═══════════════════════════════════════════════════════════════


async def check_authority(
    agent_id: str,
    action_kind: str,
    context: dict | None = None,
) -> dict:
    """The gate. Returns a structured decision.

    {"allowed": bool, "reason": str, "action_kind": str,
     "quota": {"per_day": (used, cap)? "per_week": (used, cap)?}}

    A tool dispatcher pattern:
      decision = await authority.check_authority(self.agent_id, "submit_call")
      if not decision["allowed"]:
          return json.dumps({"error": "not_authorized", **decision})
      # ...then perform the action and call record_usage...
    """
    if action_kind not in VALID_ACTIONS:
        return {"allowed": False, "reason": "unknown_action", "action_kind": action_kind}

    scope = await get_scope(agent_id, action_kind)
    if scope is None:
        # Never-seen action or member — default is strict (deny) for safety
        return {
            "allowed": False,
            "reason": "no_scope_configured",
            "action_kind": action_kind,
        }

    if not scope.get("allowed"):
        return {
            "allowed": False,
            "reason": "action_not_allowed",
            "action_kind": action_kind,
            "opt_in_required": True,
        }

    constraints = scope.get("constraints") or {}
    # Look up current usage if we have a rate constraint. That change: if the usage count
    # can't be read, fail CLOSED — never let the action through on an unknown count
    # (that is the quota-bypass this guards against). The primary get_scope gate
    # above already fails closed on a DB error; this closes the quota half.
    current_usage: dict[str, int] = {}
    try:
        if "max_per_day" in constraints:
            current_usage["per_day"] = await _usage_count(agent_id, action_kind, "day")
        if "max_per_week" in constraints:
            current_usage["per_week"] = await _usage_count(agent_id, action_kind, "week")
    except UsageLookupError as e:
        return {
            "allowed": False,
            "reason": "quota_check_failed",
            "action_kind": action_kind,
            "constraints": constraints,
            "detail": str(e)[:200],
        }

    allowed, reason = check_constraints(action_kind, constraints, context, current_usage)

    quota: dict[str, Any] = {}
    if "max_per_day" in constraints:
        quota["per_day"] = {
            "used": current_usage.get("per_day", 0),
            "cap": int(constraints["max_per_day"]),
        }
    if "max_per_week" in constraints:
        quota["per_week"] = {
            "used": current_usage.get("per_week", 0),
            "cap": int(constraints["max_per_week"]),
        }

    return {
        "allowed": allowed,
        "reason": reason,
        "action_kind": action_kind,
        "constraints": constraints,
        "quota": quota,
    }


async def record_usage(agent_id: str, action_kind: str) -> None:
    """Increment the appropriate usage counters after a successful action.

    No-op if the action has no rate constraint configured.
    """
    if _pg_request is None:
        return
    scope = await get_scope(agent_id, action_kind)
    if not scope:
        return
    constraints = scope.get("constraints") or {}

    for window_kind in ("day", "week"):
        constraint_key = f"max_per_{window_kind}"
        if constraint_key not in constraints:
            continue
        window_start = _window_start(window_kind).isoformat()
        # Try to increment; if row doesn't exist, insert
        try:
            existing = await _pg_request(
                "GET",
                "agent_authority_usage",
                params={
                    "agent_id": f"eq.{agent_id}",
                    "action_kind": f"eq.{action_kind}",
                    "window_kind": f"eq.{window_kind}",
                    "window_start": f"eq.{window_start}",
                    "select": "id,count",
                },
            )
            if existing:
                new_count = int(existing[0].get("count") or 0) + 1
                await _pg_request(
                    "PATCH",
                    "agent_authority_usage", params={"id": f"eq.{existing[0]['id']}"},
                    body={"count": new_count},
                )
            else:
                await _pg_request(
                    "POST",
                    "agent_authority_usage",
                    body={
                        "agent_id": agent_id,
                        "action_kind": action_kind,
                        "window_kind": window_kind,
                        "window_start": window_start,
                        "count": 1,
                    },
                )
        except Exception as e:
            print(f"[Authority] record_usage({agent_id},{action_kind},{window_kind}) failed: {e}")


# ═══════════════════════════════════════════════════════════════
# Member-facing updates (own scope) + admin overrides
# ═══════════════════════════════════════════════════════════════


async def set_scope(
    agent_id: str,
    action_kind: str,
    allowed: bool,
    constraints: dict | None = None,
    updated_by: str = "self",
) -> dict:
    if action_kind not in VALID_ACTIONS:
        return {"error": "unknown_action"}
    if _pg_request is None:
        return {"error": "no_database"}

    existing = await get_scope(agent_id, action_kind)
    body = {
        "agent_id": agent_id,
        "action_kind": action_kind,
        "allowed": bool(allowed),
        "constraints": constraints or {},
        "updated_at": datetime.now(UTC).isoformat(),
        "updated_by": updated_by,
    }
    try:
        if existing:
            rows = await _pg_request(
                "PATCH",
                "agent_authority_scope", params={"agent_id": f"eq.{agent_id}", "action_kind": f"eq.{action_kind}"},
                body=body,
            )
            return {"ok": True, "scope": rows[0] if isinstance(rows, list) and rows else None}
        rows = await _pg_request("POST", "agent_authority_scope", body=body)
        return {"ok": True, "scope": rows[0] if isinstance(rows, list) and rows else None}
    except Exception as e:
        return {"error": "patch_failed", "detail": str(e)[:200]}
