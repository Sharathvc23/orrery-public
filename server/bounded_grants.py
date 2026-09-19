"""Bounded operational grants — one operator decision, bounded on every axis.

THE PROBLEM THIS SOLVES, MEASURED. Single-use exact-key grants are correct and
are NOT weakened here: a grant is keyed to one `action_key` including a content
digest and is consumed on execution, which is what stops "approve once, send
forever". But it was the only option. Driving the identical send three times
filed three separate approvals, so 50 sends meant 50 approvals and 50 retries of
one send meant 50 more. The two reachable states were "approve every single
action" and "no gate", and a team of five routes around that.

This adds exactly ONE middle option — *"approve up to 200 sends to this segment
until Friday"* — not a third mode and not a relaxation.

**EVERY BOUND IS MANDATORY.** A bounded grant with an optional cap is an
unbounded grant with extra steps, so there is no default that means unlimited,
no absent expiry meaning forever, and a missing bound is REFUSED rather than
filled in generously. ``issue()`` raises on any omission.

═══ RETRY SEMANTICS — STATED, NOT EMERGENT ═══

An agent that crashes after sending but before recording retries the identical
action. Two possible rules, and the choice has to be deliberate:

  (a) every attempt charges a unit — a crash loop silently drains the operator's
      budget, and one email can cost twenty.
  (b) the cap counts DISTINCT ACTIONS, not attempts — a retry of the same
      `action_key` is idempotent and free.

**THIS IMPLEMENTS (b).** The `action_key` includes a content digest, so "the
same action_key" means genuinely the same action: same recipient, same subject,
same body. Charging an operator twice for one email is wrong, and (a) turns a
crash loop into budget exhaustion — the failure would land on the operator, not
on the buggy agent.

The consequence, stated rather than buried: **deliberately sending a
byte-identical message twice is charged once.** If two identical sends must both
be charged, vary the content or use a single-use exact-key grant, which still
exists for exactly that. This is a real trade and it is chosen with open eyes.

Idempotency is enforced by a partial UNIQUE INDEX on (grant_id, action_key)
WHERE charged, not by a read-then-write in Python, so two racing retries cannot
both charge.

═══ ATOMICITY ═══

Consumption runs in one Postgres function. A cap enforced by SELECT-then-UPDATE
is not a cap: four agents acting at once each read `consumed` before any writes.
The conditional `UPDATE ... WHERE consumed < cap` is a single statement, so the
check and the increment cannot be separated.

═══ AUDIT ═══

Every attempt is recorded — including uncharged retries, because an uncharged
retry storm is precisely what an operator would want to see. A bound whose
spending cannot be watched is not much of a bound.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

_pg_request = None
_agent_id = ""

# A scope is a literal action_key or a PREFIX ending in a single trailing
# '*'. The wildcard may only be the last character: an infix wildcard
# (`mailto:*@example.com`) reads as if it filters and would need LIKE
# semantics the matcher does not implement, so it is refused rather than
# silently meaning something else.
# Deliberately not a regex or a glob: an operator approving a bound should be
# able to read the scope and know what it covers, and a regex is a language in
# which "match everything" is easy to write by accident.
_SCOPE_RE = re.compile(r"^[^*]+\*?$")


class GrantRefused(ValueError):
    """An issue() call that would have produced an unbounded grant."""


@dataclass(frozen=True)
class Consumption:
    """The result of spending against a bounded grant."""

    authorized: bool
    reason: str
    grant_id: str | None = None
    charged: bool = False
    remaining: int | None = None


def init(pg_request, agent_id: str) -> None:
    global _pg_request, _agent_id
    _pg_request = pg_request
    _agent_id = agent_id


def validate_scope(scope: str) -> str:
    """A scope that matches everything is not a scope.

    Rejects the empty string and a bare ``*``. A prefix must have at least one
    literal character, so ``mailto:*`` is fine and ``*`` is not.
    """
    if not isinstance(scope, str) or not scope.strip():
        raise GrantRefused("scope is required — a grant with no scope is unbounded")
    scope = scope.strip()
    if scope == "*":
        raise GrantRefused("scope '*' matches every action — that is not a bound")
    if not _SCOPE_RE.match(scope):
        raise GrantRefused(f"scope {scope!r} is invalid — use a literal action_key or a prefix ending in a single '*'")
    return scope


def matches(scope: str, action_key: str) -> bool:
    """Python mirror of the SQL matching rule, for tests and for callers that
    want to preview coverage before issuing. The database remains the authority
    at consumption time."""
    if scope.endswith("*"):
        return action_key.startswith(scope[:-1])
    return scope == action_key


async def issue(
    *,
    kind: str,
    # Deliberately typed loosely: this function's job is to REFUSE a missing or
    # malformed bound, so it has to be callable with one. Narrow annotations
    # would push the check to the caller, and a caller that skipped it would
    # produce exactly the unbounded grant this module exists to prevent.
    scope: object,
    cap: object,
    expires_at: object,
    created_by: str,
    now: datetime | None = None,
) -> dict:
    """Issue a bounded grant. RAISES ``GrantRefused`` unless every bound is
    present and meaningful.

    There is deliberately no default for ``cap`` or ``expires_at``. Defaulting
    either would mean an operator could produce an unbounded grant by omission,
    which is the failure this whole module is shaped to prevent.
    """
    import governance

    if kind not in governance.OPERATIONAL_KINDS:
        raise GrantRefused(f"{kind!r} is not an operational approval kind")

    scope = validate_scope(scope)  # type: ignore[arg-type]  # validated here, by design

    if isinstance(cap, bool) or not isinstance(cap, int):
        raise GrantRefused("cap is required and must be an integer — an absent cap is unlimited")
    if cap <= 0:
        raise GrantRefused(f"cap must be positive, got {cap}")

    if not isinstance(expires_at, datetime):
        raise GrantRefused("expires_at is required — a grant with no expiry never lapses")
    if expires_at.tzinfo is None:
        raise GrantRefused("expires_at must be timezone-aware, or 'until Friday' means Friday somewhere")
    current = now or datetime.now(UTC)
    if expires_at <= current:
        raise GrantRefused(f"expires_at {expires_at.isoformat()} is not in the future")

    if not created_by:
        raise GrantRefused("created_by is required — an unattributed grant cannot be reviewed")

    if _pg_request is None:
        raise GrantRefused("governance store unavailable")

    grant_id = f"grant_{uuid.uuid4().hex[:16]}"
    row = {
        "grant_id": grant_id,
        "chapter_id": _agent_id,
        "kind": kind,
        "scope": scope,
        "cap": cap,
        "consumed": 0,
        "expires_at": expires_at.isoformat(),
        "created_by": created_by,
    }
    result = await _pg_request("POST", "operational_grants", body=row)
    if result is None:
        # pg_request swallows a configured-database failure into None.
        raise GrantRefused("the grant was not persisted — nothing was issued")
    print(
        f"[grants] issued {grant_id} kind={kind} scope={scope!r} cap={cap} "
        f"expires={expires_at.isoformat()} by={created_by}"
    )
    return row


async def consume(*, kind: str, action_key: str, actor_agent_id: str, now: datetime | None = None) -> Consumption:
    """Spend one unit against a matching live grant, atomically.

    Returns ``authorized=False`` rather than raising when no grant covers the
    action — the caller falls back to requesting a single-use approval, which is
    the existing path and stays unchanged.
    """
    if _pg_request is None:
        return Consumption(False, "governance store unavailable")

    current = (now or datetime.now(UTC)).isoformat()
    try:
        rows = await _pg_request(
            "POST",
            "rpc/consume_operational_grant",
            body={
                "_chapter_id": _agent_id,
                "_kind": kind,
                "_action_key": action_key,
                "_actor": actor_agent_id,
                "_now": current,
            },
        )
    except Exception as exc:
        # Fail CLOSED: an error consulting the grant store must not authorize.
        print(f"[grants] consume failed for {action_key!r}: {exc}")
        return Consumption(False, f"grant lookup failed: {exc}")

    if not rows:
        return Consumption(False, "no_matching_grant")
    payload = rows[0] if isinstance(rows, list) else rows
    if isinstance(payload, dict) and len(payload) == 1:
        # SELECT * FROM fn(...) yields one column named after the function.
        payload = next(iter(payload.values()))
    if isinstance(payload, str):
        import json

        payload = json.loads(payload)
    if not isinstance(payload, dict):
        return Consumption(False, "unreadable grant response")

    if not payload.get("authorized"):
        return Consumption(False, str(payload.get("reason") or "refused"))

    charged = bool(payload.get("charged"))
    remaining = payload.get("remaining")
    print(
        f"[grants] {'CHARGED' if charged else 'retry (free)'} {kind} {action_key!r} "
        f"via {payload.get('grant_id')} — {remaining} remaining"
    )
    return Consumption(
        True,
        str(payload.get("reason") or "authorized"),
        grant_id=str(payload.get("grant_id")),
        charged=charged,
        remaining=int(remaining) if remaining is not None else None,
    )


async def revoke(grant_id: str, *, now: datetime | None = None) -> bool:
    """Revoke before either bound is reached.

    The third thing that makes a bound safe: an operator who changes their mind
    must not have to wait for a cap to fill or a clock to run out. Revocation is
    checked inside the same conditional UPDATE that consumes, so a revoke racing
    a consumption cannot be stepped over.
    """
    if _pg_request is None:
        return False
    stamp = (now or datetime.now(UTC)).isoformat()
    result = await _pg_request(
        "PATCH",
        "operational_grants",
        params={"grant_id": f"eq.{grant_id}", "revoked_at": "is.null"},
        body={"revoked_at": stamp},
    )
    if result is None:
        print(f"[grants] revoke({grant_id}) did NOT persist — the grant is still live")
        return False
    print(f"[grants] revoked {grant_id}")
    return True


async def list_live(*, now: datetime | None = None) -> list[dict]:
    """Live grants for this org — what an operator is currently exposed to."""
    if _pg_request is None:
        return []
    stamp = (now or datetime.now(UTC)).isoformat().replace("+00:00", "Z")
    try:
        rows = await _pg_request(
            "GET",
            "operational_grants",
            params={
                "chapter_id": f"eq.{_agent_id}",
                "revoked_at": "is.null",
                "expires_at": f"gt.{stamp}",
                "order": "expires_at.asc",
            },
        )
        return rows or []
    except Exception as exc:
        print(f"[grants] list_live failed: {exc}")
        return []


async def consumptions(grant_id: str, *, limit: int = 200) -> list[dict]:
    """The per-consumption audit trail: which action, when, charged or not, and
    how many remained. Uncharged retries appear too — a retry storm that costs
    nothing is still something an operator should be able to see."""
    if _pg_request is None:
        return []
    try:
        rows = await _pg_request(
            "GET",
            "operational_grant_consumptions",
            params={"grant_id": f"eq.{grant_id}", "order": "consumed_at.desc", "limit": str(limit)},
        )
        return rows or []
    except Exception as exc:
        print(f"[grants] consumptions({grant_id}) failed: {exc}")
        return []
