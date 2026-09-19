"""Synthesize a self-approval for a graduated action.

This is the bridge that makes W3 functional. When an agent wants to
take a graduated action, it calls `auto_approve_if_graduated(...)`
FIRST, before the normal propose/approve dance. If the bucket is
graduated, we write a `consent.auto_approved` row (a synthetic
self-approval with the same 5-minute TTL as user approvals) and
return the event_sha256 the executor needs.

If not graduated, we return None and the agent falls through to
its usual propose/ConsentRequired/await-user flow.

Why this shape
--------------

  * Executors don't change. Their contract is still \"run only with
    a valid recent approval.\" We produce that approval synthetically
    when the graduation FSM says so.
  * The audit ledger records an auto-executed action as exactly
    what it is: a consent.auto_approved row followed by the usual
    execution-outcome row. A user inspecting the audit can tell
    auto-executed from user-approved actions at a glance.
  * No auto-execute can happen without a graduation_store, a
    habit_model, a device_did, and a context_fingerprint all
    present. Leaving ANY of these unset keeps the agent in
    always-prompt mode — useful during W3 shadow-only dogfood.

Security reminders
------------------

  * The auto-approval row is signed by the agent's own key (same
    as any ledger row). Tampering is detected by the hash chain.
  * The TTL is the same 5 minutes as user approvals — a graduated
    bucket doesn't mean \"run whenever you want,\" it means
    \"running this again right now gets pre-approved.\" An attacker
    who somehow produces a graduation can only use it for 5 min.
  * revoke flows (panic, duress) clear graduations atomically, so
    the next auto_approve_if_graduated returns None.
"""

from __future__ import annotations

from community_member.consent import gate, ledger
from community_member.consent.gate import ActionRequest
from community_member.graduation.state import (
    GRADUATION_MIN_APPROVALS,
    GRADUATION_MIN_POSTERIOR,
    GraduationStore,
)
from community_member.habits.model import HabitModel

__all__ = ["auto_approve_if_graduated"]


def auto_approve_if_graduated(
    req: ActionRequest,
    *,
    context_sha256: str,
    chapter_id: str,
    habit_model: HabitModel,
    graduation_store: GraduationStore,
    actor_agent_id: str | None = None,
) -> str | None:
    """Return an event_sha256 usable as an approval, or None.

    If the (capability, scope, context_sha256) bucket has crossed
    the graduation bar AND the GraduationStore hasn't been revoked,
    write a consent.auto_approved row (synthetic self-approval) and
    return its event_sha256. The caller can immediately invoke the
    executor's execute method with that hash.

    Returns None if:
      * The bucket is below the approval threshold
      * The posterior mean is at or below 0.85
      * The bucket is revoked (sticky)
      * context_sha256 is falsy (safety guard for callers that
        haven't computed a fingerprint yet)
    """
    if not context_sha256:
        return None

    stats = habit_model.stats(req.capability, req.scope, context_sha256)

    # Consult the FSM which reads stored state + applies threshold check.
    status = graduation_store.status(
        capability=req.capability,
        scope=req.scope,
        context_sha256=context_sha256,
        approvals=stats.approvals,
        posterior_mean=stats.posterior_mean,
    )
    if status.state != "graduated":
        return None

    # Persist the "first time we saw this bucket as graduated" timestamp
    # so the tray UI can show "graduated on ...". Idempotent.
    graduation_store.record_graduation(
        capability=req.capability,
        scope=req.scope,
        context_sha256=context_sha256,
    )

    # Write the synthetic self-approval. Uses gate.approve under the
    # hood so the executor's existing find_valid_approval path works
    # without modification. We record a prompt_event_sha256 placeholder
    # of "graduated" so the approval's detail makes clear it was
    # auto-synthesized, not a user click.
    auto_approval_hash = gate.approve(
        req,
        chapter_id=chapter_id,
        prompt_event_sha256="graduated",
        actor_agent_id=actor_agent_id,
    )

    # Additional audit marker so inspection tools can filter on
    # action='consent.auto_approved' easily (gate.approve uses
    # action='consent.approved', same as user approvals).
    ledger.record(
        chapter_id=chapter_id,
        action="consent.auto_approved",
        actor_agent_id=actor_agent_id,
        target_type="capability",
        target_id=req.capability,
        outcome="ok",
        detail={
            "approval_event_sha256": auto_approval_hash,
            "capability": req.capability,
            "scope": req.scope,
            "context_sha256": context_sha256,
            "approvals_count": stats.approvals,
            "posterior_mean": round(stats.posterior_mean, 4),
            "thresholds": {
                "min_approvals": GRADUATION_MIN_APPROVALS,
                "min_posterior": GRADUATION_MIN_POSTERIOR,
            },
        },
    )
    return auto_approval_hash
