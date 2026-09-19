"""
Chapter governance — approval queue + role nominations + trust score.

Implements the human-gated boundary for cross-chapter actions per the
governance design:

  - Leaders approve cross-chapter matches, event proposals, admissions
  - Advisors observe + can broadcast calls for info (read-only on approvals)
  - Members submit intents, RSVP, respond to calls
  - Admins (portal-marked) set roles; nomination ledger tracks evidence
    for a future auto-promote rule based on trust_score

State is persisted in the `pending_approvals` and
`chapter_role_nominations` Postgres tables. Nothing here touches the
NANDA protocol surface — this is chapter-internal governance.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from typing import Any

# Injected by chapter_agent.py at lifespan startup
_pg_request: Callable[..., Awaitable] | None = None


def _pg() -> Callable[..., Awaitable]:
    """The injected pg_request, or a LOUD failure if init() never ran — the
    old unguarded calls crashed with a bare 'NoneType' object is not callable
    (R2 whole-app sweep)."""
    if _pg_request is None:
        raise RuntimeError("governance.init() was never called — no pg_request injected")
    return _pg_request


_agent_id = ""  # chapter agent id (e.g. "acme-chapter")

APPROVAL_KINDS = {
    "introduction",
    "cross_chapter_intent",
    "cross_chapter_message",
    "event_proposal",
    "member_admission",
    "role_promotion",
    "call_cross_post",
    # Broadcast governance (PR5): verified members below the
    # direct-broadcast trust floor route through approval. Payload
    # carries {title, body, tags, audience}; on approve the
    # think_approvals_sweep executor calls broadcast.send_broadcast
    # with the server agent as sender.
    "broadcast",
}

# ═══════════════════════════════════════════════════════════════
# Operational approval kinds — the verbs a SERVICE org performs
# ═══════════════════════════════════════════════════════════════
#
# Every kind above is SOCIAL: it gates one member's exposure to another
# (introductions, admissions, cross-chapter messages). A service org run by
# one operator performs none of them, which is why an unattended-agent spike measured
# `pending_approvals` sitting at 0 for an entire run of four unattended
# service agents — the queue was not quiet, it had no vocabulary for what
# those agents actually do.
#
# The consequence is the part that matters: a verb with no approval kind is
# not "unapproved", it is UNGATEABLE. There is no way to express the gate, so
# every service verb ships open by construction — the same shape that produced
# the advisor-earnings hole, where the surface existed before the gate did.
#
# These three are deliberately coarse and verb-shaped rather than
# integration-shaped. `send_external` covers any outbound message to a
# non-member (email, SMS, webhook); a kind per vendor would mean a new
# governance change for every integration, and integrations that ship before
# their kind does are exactly what this is preventing.
OPERATIONAL_KINDS = {
    # Anything leaving the org toward a non-member recipient.
    "send_external",
    # Any durable write to a store the operator is accountable for.
    "record_write",
    # Any outbound read from a third party (rate/cost/data-egress bearing).
    "external_fetch",
}

APPROVAL_KINDS |= OPERATIONAL_KINDS

# `service` — an unattended agent with NO social surface. It is deliberately
# not in LEADER_ROLES, APPROVER_ROLES or ATTEST_ELIGIBLE_ROLES: an unattended
# process must not approve its own operational requests, and must not vouch
# for anyone. It exists so a service org can assign a role that is neither
# `member` (which grants a social surface it will never use, and which the
# spike showed all four service agents silently landed in) nor an approver.
SERVICE_ROLES = {"service"}

LEADER_ROLES = {"leader", "admin"}
APPROVER_ROLES = {"leader", "admin"}  # admin is assignable by portal; leader is nominated
VISIBILITY_ROLES = {"leader", "advisor", "mentor", "admin"}  # can see the FULL approval queue

# A service agent may see the queue, but only the operational part of it.
# Granting `service` full visibility would hand an unattended process the
# social queue — pending introductions name both members and the reason they
# were matched, which is precisely the identity exposure `consent_gate`
# exists to hold back. Visibility is therefore scoped by KIND, not just by
# role: see `visible_kinds_for_role`.
OPERATIONAL_VISIBILITY_ROLES = VISIBILITY_ROLES | SERVICE_ROLES


def visible_kinds_for_role(chapter_role: str) -> set[str] | None:
    """Which approval kinds this role may read.

    Returns None for "all kinds" (the human governance roles) and an explicit
    set for roles whose view is scoped. An empty set means the role sees
    nothing, which is the default for anything unrecognised — a new role must
    be granted visibility deliberately rather than inherit it.
    """
    if chapter_role in VISIBILITY_ROLES:
        return None
    if chapter_role in SERVICE_ROLES:
        return set(OPERATIONAL_KINDS)
    return set()


DEFAULT_APPROVAL_TTL = timedelta(hours=72)
DEFAULT_NOMINATION_TTL = timedelta(days=30)


def _utc_now_z() -> str:
    """ISO-8601 UTC timestamp safe for use inside a URL querystring.

    ``datetime.now(UTC).isoformat()`` produces ``...+00:00`` whose
    ``+`` is decoded as a literal space when interpolated into a
    PostgREST query like ``expires_at=lt.<ts>`` — PostgREST then
    rejects with ``invalid input syntax for type timestamp with
    time zone``. The ``Z`` suffix is wire-equivalent for UTC but
    contains no traversal-hostile characters. Used by sweep
    queries that want to compare with a current-time threshold.
    """
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def init(pg_request, agent_id: str):
    global _pg_request, _agent_id
    _pg_request = pg_request
    _agent_id = agent_id


# ═══════════════════════════════════════════════════════════════
# Role lookup (used by every gate check)
# ═══════════════════════════════════════════════════════════════


async def get_chapter_role(agent_id: str) -> str:
    """Return chapter_role for an agent; defaults to 'member' if unknown."""
    if not _pg_request or not agent_id:
        return "member"
    try:
        rows = await _pg_request(
            "GET",
            "agents",
            params={"agent_id": f"eq.{agent_id}", "select": "chapter_role"},
        )
        if rows:
            return rows[0].get("chapter_role", "member") or "member"
    except Exception:
        pass
    return "member"


async def is_leader(agent_id: str) -> bool:
    return (await get_chapter_role(agent_id)) in LEADER_ROLES


async def can_approve(agent_id: str) -> bool:
    return (await get_chapter_role(agent_id)) in APPROVER_ROLES


async def can_see_queue(agent_id: str) -> bool:
    """Whether this agent may see ANY part of the approval queue.

    True for a service agent, whose view is then narrowed to the operational
    kinds by ``visible_kinds_for_role``. Callers that render or return queue
    rows MUST apply that narrowing — this predicate answers "any access at
    all", not "unrestricted access".
    """
    return (await get_chapter_role(agent_id)) in OPERATIONAL_VISIBILITY_ROLES


# Role → attestation-tier label mapping.
#   Server roles `advisor` and `mentor` → 'trusted' tier (can attest)
#   Server roles `leader` and `admin`   → 'leader' tier (can attest)
#   Plain `member` (and unknown)         → rejected
ATTEST_ELIGIBLE_ROLES = {"advisor", "mentor", "leader", "admin"}


def role_to_attest_tier(chapter_role: str) -> str | None:
    """Map a chapter role to the attestation tier label.

    Returns 'leader' for leader/admin, 'trusted' for advisor/mentor,
    None for members (ineligible to attest).
    """
    if chapter_role in LEADER_ROLES:
        return "leader"
    if chapter_role in ("advisor", "mentor"):
        return "trusted"
    return None


async def require_trusted_tier(agent_id: str) -> tuple[bool, str, str | None]:
    """Gate attestation endpoints.

    Returns (eligible, reason, tier_label).
      eligible — True iff the agent's chapter_role is in ATTEST_ELIGIBLE_ROLES.
      reason   — human-readable rejection reason when not eligible.
      tier_label — 'trusted' or 'leader' (for writing into chapter_skill_attestations.trust_tier_at_attest).
    """
    if not agent_id:
        return False, "missing agent_id", None
    role = await get_chapter_role(agent_id)
    tier = role_to_attest_tier(role)
    if tier is None:
        return False, f"role '{role}' cannot attest — need advisor/mentor/leader/admin", None
    return True, "ok", tier


# ═══════════════════════════════════════════════════════════════
# Pending approvals — write (proposer side)
# ═══════════════════════════════════════════════════════════════


async def propose(
    kind: str,
    proposer_agent_id: str,
    payload: dict[str, Any],
    target_agent_id: str | None = None,
    peer_chapter_id: str | None = None,
    confidence: float = 0.5,
    ttl: timedelta | None = None,
) -> dict | None:
    """Write a new proposal to the approval queue.

    Returns the created row. RAISES ``ProposalFailed`` if the proposal was not
    queued — it never reports failure by returning None.

    WHY THIS RAISES. It used to return None on every failure path, and
    that turned a loud error into a permanent silent deadlock: PR1 added three
    operational kinds to the Python set but not to the ``pending_approvals``
    CHECK constraint, so Postgres rejected the INSERT, ``pg_request`` swallowed
    the violation and returned None, this function returned None, and the
    caller reported ``status: pending_approval`` with ``approval_id: null``.

    The verb was correctly refused, never queued, therefore never approvable,
    therefore never able to succeed — and every layer looked like it was
    working. Fixing only the constraint would leave the mechanism intact for
    the next kind someone adds, which is why this half matters more.
    """
    if kind not in APPROVAL_KINDS:
        raise ProposalFailed(kind, f"not a registered approval kind (known: {sorted(APPROVAL_KINDS)})")
    if _pg_request is None:
        raise ProposalFailed(kind, "governance store unavailable — governance.init() never ran")

    expires_at = datetime.now(UTC) + (ttl or DEFAULT_APPROVAL_TTL)

    body = {
        "kind": kind,
        "proposer_agent_id": proposer_agent_id,
        "target_agent_id": target_agent_id,
        "chapter_id": _agent_id,
        "peer_chapter_id": peer_chapter_id,
        "payload": payload,
        "confidence": max(0.0, min(1.0, confidence)),
        "expires_at": expires_at.isoformat(),
    }

    try:
        resp = await _pg_request("POST", "pending_approvals", body=body)
    except Exception as e:
        raise ProposalFailed(kind, f"{type(e).__name__}: {e}") from e

    # ``pg_request`` SWALLOWS a configured-database failure and returns None
    # rather than raising (it logs and counts a metric; its 45 callers depend on
    # the quiet return). So the absence of an exception is NOT evidence the row
    # exists — None here is precisely the constraint-violation case, and
    # treating it as success is what produced the deadlock.
    if resp is None:
        raise ProposalFailed(
            kind,
            "the INSERT did not land. If this kind was added recently, check that the "
            "pending_approvals_kind_check constraint lists it — a kind present in "
            "APPROVAL_KINDS but absent from the constraint is rejected by Postgres",
        )
    if isinstance(resp, list):
        if not resp:
            raise ProposalFailed(kind, "the INSERT returned no row")
        return resp[0]
    return resp


async def propose_introduction(
    proposer_agent_id: str,
    pair: tuple[str, str],
    reason: str,
    similarity: float,
) -> dict | None:
    """Convenience wrapper: introductions go through approval, never send directly."""
    a, b = pair
    return await propose(
        kind="introduction",
        proposer_agent_id=proposer_agent_id,
        target_agent_id=a,  # primary target
        payload={
            "pair": [a, b],
            "reason": reason,
            "similarity": similarity,
        },
        confidence=float(similarity),
    )


async def recent_introduction_exists(member_a: str, member_b: str, window: timedelta = timedelta(days=30)) -> bool:
    """Cool-down: return True if a pair has a pending or executed intro in the last N days."""
    if _pg_request is None:
        return False

    since = (datetime.now(UTC) - window).isoformat()
    try:
        # Check either (a,b) or (b,a) ordering by matching against the payload
        rows = await _pg_request(
            "GET",
            "pending_approvals",
            params={
                "chapter_id": f"eq.{_agent_id}",
                "kind": "eq.introduction",
                "status": "in.(pending,approved,executed)",
                "created_at": f"gte.{since}",
                "select": "payload",
            },
        )
        if not rows:
            return False
        pair_set = {member_a, member_b}
        for row in rows:
            pl = row.get("payload") or {}
            existing = set(pl.get("pair") or [])
            if existing == pair_set:
                return True
    except Exception:
        pass
    return False


# ═══════════════════════════════════════════════════════════════
# Pending approvals — decide (leader side)
# ═══════════════════════════════════════════════════════════════


#: Recorded as the approver when a decision arrives over the break-glass admin
#: token. That path authenticates a SECRET, not a person, so there is no
#: identity to record — and recording the org's own id instead would say the org
#: approved something no one at the org is named for.
#:
#: A colon cannot survive ``sanitize_agent_id`` (it strips everything outside
#: ``a-zA-Z0-9-_@.``), so no member id can ever equal this value. An auditor
#: reading ``approved_by`` can therefore always tell the two apart.
BREAK_GLASS_APPROVER = "break-glass:unattributed"


def is_break_glass(approver_agent_id: str) -> bool:
    """True when this decision was made over the break-glass token."""
    return approver_agent_id == BREAK_GLASS_APPROVER


async def approve(approval_id: str, approver_agent_id: str, *, pre_authorized: bool = False) -> dict | None:
    """Leader approves a pending item. Returns updated row or None.

    ``pre_authorized`` — set by the HTTP layer when the caller has ALREADY been
    authenticated + role-checked (a verified signed leader, or the break-glass
    bearer). It skips the by-name ``can_approve`` re-check, which would wrongly
    reject the bearer (no agent_id / no member row). Internal callers leave it
    False so the name-based role gate still applies.
    """
    if not pre_authorized and not await can_approve(approver_agent_id):
        return {"error": "not_authorized"}

    body = {
        "status": "approved",
        "approved_by": approver_agent_id,
        "approved_at": datetime.now(UTC).isoformat(),
    }
    try:
        rows = await _pg()(
            "PATCH",
            "pending_approvals",
            # The TTL is enforced HERE, at the decision, not only by the
            # sweeper. The sweeper runs on the think cycle, so between an
            # item's expires_at and the next sweep it still reads `pending`,
            # and a filter on status alone approved it — the endpoint's own
            # docstring said "expired items stay expired" while this let them
            # through. An expired item matches nothing, exactly as a decided
            # one does, and the caller sees the same "not pending" outcome.
            params={"id": f"eq.{approval_id}", "status": "eq.pending", "expires_at": f"gt.{_utc_now_z()}"},
            body=body,
        )
        updated = rows[0] if isinstance(rows, list) and rows else rows
        if isinstance(updated, dict):
            _emit_approval_receipt(updated, approver_agent_id, outcome="approved")
        return updated
    except Exception as e:
        print(f"[Governance] approve({approval_id}) failed: {e}")
        return None


async def reject(
    approval_id: str, approver_agent_id: str, reason: str = "", *, pre_authorized: bool = False
) -> dict | None:
    if not pre_authorized and not await can_approve(approver_agent_id):
        return {"error": "not_authorized"}
    # Same expiry filter as approve: an item past its TTL is `expired`, and
    # recording it as `rejected` would attribute to a person an outcome the
    # clock decided.
    body = {
        "status": "rejected",
        "approved_by": approver_agent_id,
        "approved_at": datetime.now(UTC).isoformat(),
        "rejection_reason": reason[:500],
    }
    try:
        rows = await _pg()(
            "PATCH",
            "pending_approvals",
            params={"id": f"eq.{approval_id}", "status": "eq.pending", "expires_at": f"gt.{_utc_now_z()}"},
            body=body,
        )
        updated = rows[0] if isinstance(rows, list) and rows else rows
        if isinstance(updated, dict):
            _emit_approval_receipt(updated, approver_agent_id, outcome="rejected", reason=reason)
        return updated
    except Exception as e:
        print(f"[Governance] reject({approval_id}) failed: {e}")
        return None


def _emit_approval_receipt(row: dict, approver_agent_id: str, *, outcome: str, reason: str = "") -> None:
    """Fire-and-forget ARP receipt emission for an approval decision.

    The principal is the original proposer (the agent whose action was
    just approved or rejected). The counterparty is the approving
    leader. Category is decision_made because the chapter just made a
    governance decision on the proposer's behalf.

    Telemetry-style: any exception here is swallowed so business logic
    in approve/reject is never wedged by receipt emission.
    """
    try:
        import asyncio as _asyncio

        import arp as arp_mod

        proposer = row.get("proposer_agent_id") or ""
        if not proposer:
            return
        principal_did = arp_mod.did_key_for_member(proposer)
        if not principal_did:
            return
        break_glass = is_break_glass(approver_agent_id)
        # No DID lookup for the break-glass path: there is no member behind it,
        # and asking would either miss or return the org's own DID.
        approver_did = (
            None if break_glass else (arp_mod.did_key_for_member(approver_agent_id) if approver_agent_id else None)
        )
        approver_label = "the break-glass token" if break_glass else approver_agent_id
        kind = row.get("kind") or "unknown"
        summary = (
            f"Your {kind} proposal was {outcome} by {approver_label}."
            if outcome == "approved"
            else f"Your {kind} proposal was {outcome} by {approver_label}{f' — {reason[:60]}' if reason else ''}."
        )
        _asyncio.create_task(
            arp_mod.emit_chapter_action(
                principal_did=principal_did,
                category="decision_made",
                human_summary=summary[:280],
                counterparty_did=approver_did,
                counterparty_label=approver_label or None,
                outcome=("completed" if outcome == "approved" else "reversed"),
                machine_payload={
                    "approval_id": row.get("id"),
                    "kind": kind,
                    "outcome": outcome,
                    "rejection_reason": reason[:200] if reason else None,
                },
            )
        )
    except Exception:  # noqa: BLE001 — receipt emission must never raise
        pass


async def mark_executed(approval_id: str) -> None:
    """Called by think_approvals_sweep after an approved item's action has been run."""
    if _pg_request is None:
        return
    try:
        await _pg_request(
            "PATCH",
            "pending_approvals",
            params={"id": f"eq.{approval_id}"},
            body={"status": "executed", "executed_at": datetime.now(UTC).isoformat()},
        )
    except Exception as e:
        print(f"[Governance] mark_executed({approval_id}) failed: {e}")


# ═══════════════════════════════════════════════════════════════
# The operational gate — what a service verb calls BEFORE acting
# ═══════════════════════════════════════════════════════════════


class ProposalFailed(RuntimeError):
    """A proposal could not be queued.

    Distinct from ``OperationalApprovalRequired``, and the distinction is the
    whole point of the approval-parity fix: "queued, waiting for an operator" and "never queued,
    nobody will ever see it" are opposite outcomes that both used to surface as
    ``status: pending_approval``. A caller that catches only
    ``OperationalApprovalRequired`` will NOT catch this — deliberately, so an
    unqueued proposal cannot be reported as pending.
    """

    def __init__(self, kind: str, reason: str):
        self.kind = kind
        self.reason = reason
        super().__init__(f"could not queue approval {kind!r}: {reason}")


class OperationalApprovalRequired(Exception):
    """Raised when an operational verb has no approved grant to consume.

    Carries the approval row (when one was queued) so the caller can surface
    "waiting on approval <id>" rather than a bare refusal.
    """

    def __init__(self, kind: str, reason: str, approval: dict | None = None):
        self.kind = kind
        self.reason = reason
        self.approval = approval
        super().__init__(f"{kind} refused: {reason}")


async def consume_operational_approval(
    kind: str,
    *,
    actor_agent_id: str,
    action_key: str,
    payload: dict[str, Any] | None = None,
    ttl: timedelta | None = None,
) -> dict:
    """Gate an operational verb. Raises ``OperationalApprovalRequired`` unless
    an approved grant exists, and CONSUMES that grant on success.

    Call this immediately before performing the side effect, not at planning
    time — the value is that the effect cannot happen without a grant, and a
    check further from the effect is a check something can be added past.

    ``action_key`` identifies the specific action within the kind (a recipient,
    a record id, an endpoint). It is matched exactly, so an approval to email
    one address does not authorize emailing another. A kind alone would be a
    standing grant to perform the verb against ANY target, which is close to
    not gating it.

    Grants are SINGLE-USE: the row is marked executed as it is consumed. An
    approval that stayed valid would turn one operator decision into unlimited
    sends, and "approve once, send forever" is the failure this gate exists to
    prevent. An operator who wants a standing grant should be made to say so
    explicitly rather than get one by default.

    FAIL-CLOSED THROUGHOUT. An unknown kind, an uninitialised store, or a
    database error all refuse. A gate that opens when its backing store is
    unreachable is worse than no gate, because it is trusted — and it is
    inducible by anyone who can make the store fail.
    """
    if kind not in OPERATIONAL_KINDS:
        raise OperationalApprovalRequired(kind, f"'{kind}' is not an operational approval kind")
    if not actor_agent_id or not action_key:
        raise OperationalApprovalRequired(kind, "actor_agent_id and action_key are required")
    if _pg_request is None:
        raise OperationalApprovalRequired(kind, "governance store unavailable")

    try:
        rows = await _pg_request(
            "GET",
            "pending_approvals",
            params={
                "chapter_id": f"eq.{_agent_id}",
                "kind": f"eq.{kind}",
                "status": "eq.approved",
                "order": "approved_at.asc",
                "limit": "50",
            },
        )
    except Exception as e:
        raise OperationalApprovalRequired(kind, f"approval lookup failed: {e}") from e

    for row in rows or []:
        grant = row.get("payload") or {}
        # The action_key must have been part of what the operator approved.
        # Matching on the stored payload rather than on anything the caller
        # supplies now is what stops a verb widening its own grant.
        if grant.get("action_key") == action_key:
            await mark_executed(row["id"])
            print(f"[Governance] {kind} authorized for {action_key!r} via approval {row['id']}")
            return row

    # No exact-key grant. Try a BOUNDED grant before asking the operator again
    # — this is the middle option: "up to N actions matching this scope until
    # this time", one decision instead of one per action. Checked AFTER the
    # exact-key path so single-use grants keep their existing meaning exactly;
    # this can only authorize something that was going to be refused.
    import bounded_grants

    spend = await bounded_grants.consume(kind=kind, action_key=action_key, actor_agent_id=actor_agent_id)
    if spend.authorized:
        return {
            "grant_id": spend.grant_id,
            "bounded": True,
            "charged": spend.charged,
            "remaining": spend.remaining,
            "kind": kind,
            "action_key": action_key,
        }

    # An unattended agent retries. Queueing a fresh proposal per attempt would
    # bury the operator in duplicates of one decision and make the queue
    # useless exactly when it matters, so an identical pending request is
    # reused rather than re-filed.
    try:
        pending = await _pg_request(
            "GET",
            "pending_approvals",
            params={
                "chapter_id": f"eq.{_agent_id}",
                "kind": f"eq.{kind}",
                "status": "eq.pending",
                "limit": "100",
            },
        )
    except Exception:
        pending = []
    for row in pending or []:
        if (row.get("payload") or {}).get("action_key") == action_key:
            raise OperationalApprovalRequired(kind, f"awaiting approval for {action_key!r}", approval=row)

    queued = await propose(
        kind=kind,
        proposer_agent_id=actor_agent_id,
        payload={"action_key": action_key, **(payload or {})},
        confidence=0.0,
        ttl=ttl,
    )
    raise OperationalApprovalRequired(kind, f"no approved grant for {action_key!r}", approval=queued)


async def sweep_expired() -> int:
    """Mark pending items past their expires_at as 'expired'. Returns count."""
    if _pg_request is None:
        return 0
    # `+` in `+00:00` URL-decodes as space when interpolated into a
    # querystring; PostgREST then rejects with HTTP 400. Use the
    # `Z` suffix instead — wire-equivalent for UTC and traversal-safe.
    now = _utc_now_z()
    try:
        rows = await _pg_request(
            "PATCH",
            "pending_approvals",
            params={"status": "eq.pending", "expires_at": f"lt.{now}"},
            body={"status": "expired"},
        )
        # Also expire stale nominations
        await _pg_request(
            "PATCH",
            "chapter_role_nominations",
            params={"status": "eq.pending", "expires_at": f"lt.{now}"},
            body={"status": "expired"},
        )
        return len(rows) if isinstance(rows, list) else 0
    except Exception as e:
        print(f"[Governance] sweep_expired failed: {e}")
        return 0


async def list_pending(kind: str | None = None, limit: int = 100) -> list[dict]:
    if _pg_request is None:
        return []
    params = {
        "chapter_id": f"eq.{_agent_id}",
        "status": "eq.pending",
        "order": "confidence.desc,created_at.desc",
        "limit": str(limit),
    }
    if kind:
        params["kind"] = f"eq.{kind}"
    try:
        rows = await _pg_request("GET", "pending_approvals", params=params)
        return rows or []
    except Exception:
        return []


async def get_dashboard() -> dict:
    """Aggregate counts for the leader A2UI surface."""
    if _pg_request is None:
        return {}
    try:
        rows = await _pg_request(
            "GET",
            "leader_dashboard",
            params={"chapter_id": f"eq.{_agent_id}", "limit": "1"},
        )
        if rows:
            return rows[0]
    except Exception:
        pass
    return {
        "pending_count": 0,
        "expiring_soon_count": 0,
        "approved_last_24h": 0,
        "rejected_last_24h": 0,
        "pending_by_kind": {},
    }


# ═══════════════════════════════════════════════════════════════
# Role nominations
# ═══════════════════════════════════════════════════════════════


async def nominate(
    nominator_agent_id: str,
    nominee_agent_id: str,
    target_role: str,
    reason: str = "",
) -> dict | None:
    """Any chapter member can nominate another member for advisor or leader.

    Nominations are a ledger. Admins review; leaders endorse. When
    trust_score_autopromote is flipped on, sufficient endorsements +
    tenure + reputation flip the role without admin action.
    """
    if target_role not in ("advisor", "leader"):
        return {"error": "invalid_target_role"}
    if _pg_request is None:
        return None

    body = {
        "nominator_agent_id": nominator_agent_id,
        "nominee_agent_id": nominee_agent_id,
        "chapter_id": _agent_id,
        "target_role": target_role,
        "reason": reason[:1000],
        "expires_at": (datetime.now(UTC) + DEFAULT_NOMINATION_TTL).isoformat(),
    }
    try:
        rows = await _pg_request("POST", "chapter_role_nominations", body=body)
        return rows[0] if isinstance(rows, list) and rows else rows
    except Exception as e:
        print(f"[Governance] nominate failed: {e}")
        return None


async def endorse(nomination_id: str, endorser_agent_id: str, signal: str = "up", note: str = "") -> dict | None:
    """Existing leader adds endorsement to a nomination.

    signal: 'up' | 'down'. Stored in endorsements jsonb array. When the
    ledger reaches a configurable threshold and target role criteria
    pass, resolve() can promote.
    """
    if signal not in ("up", "down"):
        return {"error": "invalid_signal"}
    if not await is_leader(endorser_agent_id):
        return {"error": "not_authorized"}

    # Read current endorsements, append, write back. Not atomic — acceptable
    # because endorsements are advisory; the authoritative action is resolve().
    try:
        rows = await _pg()(
            "GET",
            "chapter_role_nominations",
            params={"id": f"eq.{nomination_id}", "select": "endorsements"},
        )
        if not rows:
            return {"error": "not_found"}
        existing = rows[0].get("endorsements") or []
        # Dedupe: one endorsement per (endorser, nomination)
        existing = [e for e in existing if e.get("endorser") != endorser_agent_id]
        existing.append(
            {
                "endorser": endorser_agent_id,
                "signal": signal,
                "note": note[:500],
                "at": datetime.now(UTC).isoformat(),
            }
        )
        updated = await _pg()(
            "PATCH",
            "chapter_role_nominations",
            params={"id": f"eq.{nomination_id}"},
            body={"endorsements": existing},
        )
        return updated[0] if isinstance(updated, list) and updated else updated
    except Exception as e:
        print(f"[Governance] endorse failed: {e}")
        return None


async def resolve_nomination(
    nomination_id: str,
    resolver_agent_id: str,
    decision: str,
    note: str = "",
) -> dict | None:
    """Admin/leader resolves a nomination — approves or rejects promotion.

    decision: 'approved' | 'rejected'. On 'approved', agents.chapter_role
    is updated to the target_role.
    """
    if decision not in ("approved", "rejected"):
        return {"error": "invalid_decision"}
    resolver_role = await get_chapter_role(resolver_agent_id)
    if resolver_role not in ("admin", "leader"):
        return {"error": "not_authorized"}

    try:
        rows = await _pg()(
            "GET",
            "chapter_role_nominations",
            params={"id": f"eq.{nomination_id}", "select": "*"},
        )
        if not rows:
            return {"error": "not_found"}
        nom = rows[0]
        if nom["status"] != "pending":
            return {"error": "already_resolved", "current_status": nom["status"]}

        # Only admins can promote to leader. Leaders can only resolve advisor nominations.
        if nom["target_role"] == "leader" and resolver_role != "admin":
            return {"error": "only_admin_can_promote_to_leader"}

        # Update the nomination row
        body = {
            "status": decision,
            "resolved_by": resolver_agent_id,
            "resolved_at": datetime.now(UTC).isoformat(),
            "resolution_note": note[:500],
        }
        await _pg()(
            "PATCH",
            "chapter_role_nominations",
            params={"id": f"eq.{nomination_id}"},
            body=body,
        )

        # If approved, promote the agent
        if decision == "approved":
            await _pg()(
                "PATCH",
                "agents",
                params={"agent_id": f"eq.{nom['nominee_agent_id']}"},
                body={"chapter_role": nom["target_role"]},
            )
        return {**nom, **body}
    except Exception as e:
        print(f"[Governance] resolve_nomination failed: {e}")
        return None


async def list_nominations(status: str = "pending", limit: int = 50) -> list[dict]:
    if _pg_request is None:
        return []
    try:
        rows = await _pg_request(
            "GET",
            "chapter_role_nominations",
            params={
                "chapter_id": f"eq.{_agent_id}",
                "status": f"eq.{status}",
                "order": "created_at.desc",
                "limit": str(limit),
            },
        )
        return rows or []
    except Exception:
        return []


# ═══════════════════════════════════════════════════════════════
# Trust score (reserved — feature flag off by default)
# ═══════════════════════════════════════════════════════════════


def compute_trust_score(reputation: dict, endorsements: list, tenure_days: int) -> float:
    """Simple weighted score 0-100. Tune weights later once we have data.

    - Reputation contributes up to 60 (activity-weighted)
    - Endorsements contribute up to 30 (leader up-votes)
    - Tenure contributes up to 10 (saturates at 365d)
    """
    rep_raw = (
        (reputation.get("introductions", 0) or 0) * 2
        + (reputation.get("sprints", 0) or 0) * 3
        + (reputation.get("votes", 0) or 0) * 1
        + (reputation.get("events", 0) or 0) * 1
        + (reputation.get("contributions", 0) or 0) * 2
    )
    rep_score = min(60.0, rep_raw)

    up = sum(1 for e in endorsements if e.get("signal") == "up")
    down = sum(1 for e in endorsements if e.get("signal") == "down")
    endorse_score = max(0.0, min(30.0, (up - 0.5 * down) * 5))

    tenure_score = min(10.0, (tenure_days / 365) * 10)

    return round(rep_score + endorse_score + tenure_score, 2)
