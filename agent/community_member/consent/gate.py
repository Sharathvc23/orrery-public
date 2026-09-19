"""Consent gate — decides whether a proposed action needs a user prompt.

Every action the agent wants to take flows through `evaluate()` before any
executor sees it. The gate's decision is one of:

  "reject"   — the action's authorization trail is untrusted-only
               (e.g., a webpage told the agent to send an email). No
               consent prompt is raised; the action is blocked and
               logged. This is the primary defense against indirect
               prompt injection.
  "prompt"   — a human decision is required. Executor raises
               ConsentRequired; the desktop tray UI is responsible for
               routing the prompt to the user and recording an
               approval/denial back via `record_decision()`.
  "approved" — reachable when the request's (capability, scope,
               context) triple has been graduated by prior approvals
               (W4, shipped). `evaluate()` itself never returns
               "approved" — it only rejects or prompts; the executor
               synthesizes an "approved" decision via
               graduation.auto_approve_if_graduated / a valid stored
               user approval, both of which are minted only after
               evaluate() has already cleared the request. `skill.invoke`
               is exempt from auto-approval (executor `_NO_AUTO_APPROVE`).

`evaluate()` is pure: it reads a frozen `ActionRequest` and returns a
frozen `ConsentDecision`. No globals, no I/O. `record_decision()` is the
I/O layer — it appends the decision to the hash-chained local ledger.

What the ledger's chain does and does not do: the chain establishes ORDER
and completeness across rows, and `ledger.verify_chain()` is what checks it.
It is not consulted when an approval is honoured. What `find_valid_approval`
checks instead, per candidate row, is `ledger.verify_row` — that the row's
own hash re-derives from its fields and that its Ed25519 signature verifies.
Those two are what make a row's contents and origin trustworthy enough to act
on, and both are O(1). On a ledger with no signing key configured there is no
authenticity to check, so only integrity is; write access to the file is then
still enough to forge an approval.

Design rule: the executor must NEVER consult the LLM's `rationale` field
to pick an action. Rationale is logged for human review but has zero
decision-making weight. This is the "action-intent boundary" from the
v2 threat model — an LLM that's been prompt-injected can produce a
dangerous `action` with a benign `rationale`; we defend by making the
rationale advisory-only.
"""

from __future__ import annotations

import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Literal

from community_member.consent import aae_emit, ledger
from community_member.skill_runtime import ConsentRequired  # re-export as-is

__all__ = [
    "ActionRequest",
    "ConsentDecision",
    "ConsentRequired",
    "Provenance",
    "approve",
    "check_and_record",
    "claim_approval",
    "clear_denial",
    "evaluate",
    "find_recent_denial",
    "find_valid_approval",
    "is_consumed",
    "mark_consumed",
    "record_decision",
    "release_execution",
]

# How long an approval stays valid after the user clicks Approve.
# Intentionally short: the user approves "run this specific action right
# now," not "run anything like this for the next hour."
APPROVAL_TTL = timedelta(minutes=5)

# How long a denial SUPPRESSES the same action from being re-proposed to the
# user. When the user clicks Deny, the planner can still re-propose the action
# on later cycles (it doesn't remember it asked) — without this window it would
# re-prompt every cycle. Longer than APPROVAL_TTL because "no" should stick for
# a while, but not forever (the situation may genuinely change later).
DENIAL_COOLDOWN = timedelta(hours=1)

Provenance = Literal["trusted", "semi_trusted", "untrusted"]
_VALID_PROVENANCE: frozenset[Provenance] = frozenset({"trusted", "semi_trusted", "untrusted"})

DecisionState = Literal["reject", "prompt", "approved"]


@dataclass(frozen=True)
class ActionRequest:
    """Structured proposal the planner produces for the executor.

    Attributes:
        capability: Dotted capability string, e.g. "browser.navigate",
            "fs.read", "shell.exec".
        scope: Capability-specific scope — an origin for browser, a
            glob for files, a binary name for shell. Free-form but
            must be non-empty.
        context: Fingerprint used by the habit engine to group similar
            requests. Opaque to the gate; passed through to the ledger.
        provenance: Where the authorization to take this action came
            from — trusted (user said so directly), semi_trusted
            (chapter peer or installed skill said so), or untrusted
            (web content, email body, skill output containing text).
        source_ref: Identifier of the provenance source. For
            "untrusted" provenance this is REQUIRED and must be
            displayed to the user in any consent prompt.
        rationale: Free-form LLM explanation. Logged only. Never
            routed on. See module docstring.
    """

    capability: str
    scope: str
    context: str
    provenance: Provenance
    source_ref: str | None = None
    rationale: str = ""
    # `extra` lets callers attach arbitrary audit-only fields (request
    # id, LLM model used, etc.) without widening the stable schema.
    extra: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class ConsentDecision:
    """Gate verdict. Never mutate after construction."""

    state: DecisionState
    reason: str
    event_sha256: str | None = None


def _validate(req: ActionRequest) -> str | None:
    """Return an error string if the request is malformed, else None."""
    if not req.capability or not isinstance(req.capability, str):
        return "capability is required"
    if "." not in req.capability:
        return "capability must be dotted (e.g. 'browser.navigate')"
    if not req.scope or not isinstance(req.scope, str):
        return "scope is required"
    if not req.context or not isinstance(req.context, str):
        return "context is required"
    if req.provenance not in _VALID_PROVENANCE:
        return f"provenance must be one of {sorted(_VALID_PROVENANCE)}"
    if req.provenance == "untrusted" and not req.source_ref:
        return "untrusted provenance requires source_ref"
    return None


def evaluate(req: ActionRequest) -> ConsentDecision:
    """Decide how to route `req`. Pure — no I/O, no globals.

    The rules implemented here encode the v2 threat model's provenance
    policy (see plans/…/yes-the-whole-point-humble-hopcroft.md §"The
    prompt-injection problem"). Downstream callers MUST persist the
    returned decision via `record_decision()` before executing.
    """
    err = _validate(req)
    if err is not None:
        return ConsentDecision(state="reject", reason=f"invalid_request: {err}")

    # S3: an action whose only authorization trail is untrusted content
    # must never reach a consent prompt. This is the single most
    # important rule in the gate — it's the load-bearing defense
    # against indirect prompt injection.
    if req.provenance == "untrusted":
        return ConsentDecision(
            state="reject",
            reason="untrusted_provenance",
        )

    # W1: trusted + semi-trusted both go to the prompt layer. In W4+
    # this branch will check the graduation store first.
    return ConsentDecision(
        state="prompt",
        reason="user_confirmation_required",
    )


# ── I/O: record the decision to the hash-chained ledger ────────────


def record_decision(
    req: ActionRequest,
    decision: ConsentDecision,
    *,
    chapter_id: str,
    actor_agent_id: str | None = None,
) -> str:
    """Append the decision to the local consent ledger. Returns event_sha256.

    `chapter_id` is the scoping identifier — same column as
    chapter-runtime's `chapter_audit`. For a standalone (chapter-less)
    device agent, pass a stable local ID like "local:{did_key}".
    """
    detail = {
        "capability": req.capability,
        "scope": req.scope,
        "context": req.context,
        "provenance": req.provenance,
        "source_ref": req.source_ref,
        # Rationale is logged for human review but not routed on.
        "rationale": (req.rationale or "")[:2000],
        "extra": req.extra,
        "decision_reason": decision.reason,
    }
    outcome_map: dict[DecisionState, str] = {
        "reject": "denied",
        "prompt": "deferred",
        "approved": "ok",
    }
    event = ledger.record(
        chapter_id=chapter_id,
        action=f"consent.{decision.state}",
        actor_agent_id=actor_agent_id,
        target_type="capability",
        target_id=req.capability,
        outcome=outcome_map[decision.state],
        detail=detail,
    )
    # sm-aae: the same verdict as a signed, per-agent-chained pre-action
    # envelope — refusals included ("we said no" is provable, not an absence).
    # "prompt" maps to `conditional`: execution is authorized only on a user
    # approval, which emits its own `authorized` envelope. Never blocks the
    # gate (see consent/aae_emit.py).
    aae_outcome: dict[DecisionState, str] = {
        "reject": "denied",
        "prompt": "conditional",
        "approved": "authorized",
    }
    aae_emit.emit_decision(
        capability=req.capability,
        scope=req.scope,
        params={
            "context": req.context,
            "provenance": req.provenance,
            "source_ref": req.source_ref or "",
            "decision_reason": decision.reason,
            "consent_event_sha256": event["event_sha256"],
        },
        policy_id=f"consent-gate:{decision.reason}",
        outcome=aae_outcome[decision.state],
    )
    return event["event_sha256"]


# ── Convenience: evaluate + record in one call ──────────────────────


def check_and_record(
    req: ActionRequest,
    *,
    chapter_id: str,
    actor_agent_id: str | None = None,
) -> ConsentDecision:
    """Run the gate and persist the decision atomically.

    Returns the decision enriched with its event_sha256. This is what
    most callers want — the two-step split is only useful when a test
    needs to inspect the pre-persistence decision.
    """
    decision = evaluate(req)
    event_hash = record_decision(
        req,
        decision,
        chapter_id=chapter_id,
        actor_agent_id=actor_agent_id,
    )
    # Frozen dataclasses can't be mutated — return a fresh copy.
    return ConsentDecision(
        state=decision.state,
        reason=decision.reason,
        event_sha256=event_hash,
    )


# ── User-initiated approval (UI tray side) ──────────────────────────


def deny(
    req: ActionRequest,
    *,
    chapter_id: str,
    prompt_event_sha256: str,
    actor_agent_id: str | None = None,
) -> str:
    """Record a user denial for a previously-prompted request.

    Mirror of approve(): writes a ``consent.denied`` row whose detail
    links back to the original ``consent.prompt`` event via
    ``prompt_event_sha256``. The pending-queue resolver looks for that
    field; without it, the prompt never disappears from the inbox
    even though the user clicked Deny. (Prior bug.)
    """
    detail = {
        "capability": req.capability,
        "scope": req.scope,
        "context": req.context,
        "provenance": req.provenance,
        "source_ref": req.source_ref,
        "prompt_event_sha256": prompt_event_sha256,
        "extra": req.extra,
        "decision_reason": "user_denied",
    }
    event = ledger.record(
        chapter_id=chapter_id,
        action="consent.denied",
        actor_agent_id=actor_agent_id,
        target_type="capability",
        target_id=req.capability,
        outcome="denied",
        detail=detail,
    )
    # sm-aae: the user's "no" as a signed, chained envelope (refusals are
    # first-class artifacts, not silent absences).
    aae_emit.emit_decision(
        capability=req.capability,
        scope=req.scope,
        params={
            "context": req.context,
            "provenance": req.provenance,
            "source_ref": req.source_ref or "",
            "prompt_event_sha256": prompt_event_sha256,
            "decision_reason": "user_denied",
            "consent_event_sha256": event["event_sha256"],
        },
        policy_id="consent-gate:user_denied",
        outcome="denied",
    )
    return event["event_sha256"]


def approve(
    req: ActionRequest,
    *,
    chapter_id: str,
    prompt_event_sha256: str,
    actor_agent_id: str | None = None,
) -> str:
    """Record a user approval for a previously-prompted request.

    Only called after the tray UI collected an explicit user click.
    Writes a `consent.approved` row whose detail links back to the
    `consent.prompt` event that was originally raised, plus a fresh
    expiry timestamp equal to `now + APPROVAL_TTL`.

    Returns the event_sha256 of the approval row. Executors consume
    this id via `find_valid_approval()` right before running.

    This function does NOT re-run `evaluate()` — an attacker who
    hijacks the UI cannot bypass the untrusted-provenance reject by
    calling approve() directly, because the executor also re-checks
    `find_valid_approval()` binds to the SAME request shape the
    planner originally proposed.
    """
    now = datetime.now(UTC)
    expires_at = now + APPROVAL_TTL
    detail = {
        "capability": req.capability,
        "scope": req.scope,
        "context": req.context,
        "provenance": req.provenance,
        "source_ref": req.source_ref,
        "prompt_event_sha256": prompt_event_sha256,
        "expires_at": expires_at.isoformat(),
        "extra": req.extra,
    }
    event = ledger.record(
        chapter_id=chapter_id,
        action="consent.approved",
        actor_agent_id=actor_agent_id,
        target_type="capability",
        target_id=req.capability,
        outcome="ok",
        detail=detail,
    )
    # sm-aae: the explicit user grant as a signed, chained pre-action permit.
    aae_emit.emit_decision(
        capability=req.capability,
        scope=req.scope,
        params={
            "context": req.context,
            "provenance": req.provenance,
            "source_ref": req.source_ref or "",
            "prompt_event_sha256": prompt_event_sha256,
            "expires_at": expires_at.isoformat(),
            "decision_reason": "user_approved",
            "consent_event_sha256": event["event_sha256"],
        },
        policy_id="consent-gate:user_approved",
        outcome="authorized",
    )
    return event["event_sha256"]


def find_valid_approval(
    req: ActionRequest,
    *,
    chapter_id: str,
    now: datetime | None = None,
) -> dict | None:
    """Return the most-recent non-expired, verified approval matching `req`.

    Match criteria: same capability, scope, context, and provenance —
    plus expiry timestamp still in the future. Matching is deliberately
    strict: a tiny change to any of those fields forces a fresh prompt.

    Every candidate row is checked with :func:`ledger.verify_row` before it is
    honoured. The row's ``expires_at`` and its four match fields are read out
    of the ledger, so without that check anything able to write the SQLite file
    can append an approval for any capability with any expiry and have it
    honoured. Recomputing a correct ``event_sha256`` is trivial; producing a
    valid Ed25519 signature over it is not, which is what the check turns on.

    A row that fails verification is skipped and logged; the scan continues.
    Refusing the whole ledger on one bad row would let a single corrupt or
    hand-appended row disable every future approval — a denial of service on
    the consent system, and one an attacker who can write the file could
    trigger deliberately. Skipping is also the fail-closed direction for this
    decision: an unverified row is never acted on.

    Whether the ledger as a whole is intact and in order is a different
    question with its own answer surface, :func:`ledger.verify_chain`. It is
    not called here: it is O(chain) against this function's O(1), and on a
    ledger that grows with every consent decision that cost is unbounded.
    """
    now = now or datetime.now(UTC)
    consumed = _consumed_approval_shas()
    candidates = ledger.list_events(action="consent.approved", limit=50)
    for ev in candidates:
        if ev.get("chapter_id") != chapter_id:
            continue
        verified, reason = ledger.verify_row(ev)
        if not verified:
            print(
                f"[consent][ERROR] approval {str(ev.get('event_sha256'))[:8]} failed "
                f"verification ({reason}) and was NOT honored — the consent ledger has "
                f"a row that record() did not write; run ledger.verify_chain() and read "
                f"its 'authenticated' field, not 'ok'"
            )
            continue
        # One-shot: an approval that has been consumed (tombstoned via
        # mark_consumed) is spent — skip it so a tray-approved action can't
        # also auto-fire on the next autonomous cycle within the TTL.
        #
        # The ONE exception is an approval this process is executing right
        # now (consume-before-execute, see claim_approval): it is tombstoned
        # BEFORE its runner fires, and the runners re-check this function
        # themselves, so the in-flight set is what admits that single
        # execution. A crash empties the set; the tombstone stays.
        if ev.get("event_sha256") in consumed and ev.get("event_sha256") not in _in_flight:
            continue
        det = ev.get("detail") or {}
        if (
            det.get("capability") != req.capability
            or det.get("scope") != req.scope
            or det.get("context") != req.context
            or det.get("provenance") != req.provenance
        ):
            continue
        try:
            exp = datetime.fromisoformat(det["expires_at"])
        except (KeyError, ValueError):
            continue
        if exp <= now:
            continue
        return ev
    return None


def find_recent_denial(
    req: ActionRequest,
    *,
    chapter_id: str,
    now: datetime | None = None,
) -> dict | None:
    """Return a matching ``consent.denied`` within :data:`DENIAL_COOLDOWN`, else None.

    The negative mirror of :func:`find_valid_approval`. The executor calls this
    to SUPPRESS re-prompting an action the user recently denied — otherwise the
    planner (which doesn't remember it already asked) re-proposes it every cycle
    and the same prompt keeps coming back. Matches on the same four fields
    (capability, scope, context, provenance), so denying ``fetch(evil.com)``
    suppresses only that, not ``fetch(good.com)``. The window is measured from
    the denial's own ``occurred_at`` (no expiry is stored on the row).
    """
    now = now or datetime.now(UTC)
    cleared = _cleared_denial_shas()
    for ev in ledger.list_events(action="consent.denied", limit=50):
        if ev.get("chapter_id") != chapter_id:
            continue
        # The user lifted this suppression early (clear_denial) — no longer
        # suppressing, so the action can be re-proposed.
        if ev.get("event_sha256") in cleared:
            continue
        det = ev.get("detail") or {}
        if (
            det.get("capability") != req.capability
            or det.get("scope") != req.scope
            or det.get("context") != req.context
            or det.get("provenance") != req.provenance
        ):
            continue
        try:
            occurred = datetime.fromisoformat(ev["occurred_at"])
        except (KeyError, ValueError):
            continue
        if now - occurred > DENIAL_COOLDOWN:
            continue
        return ev
    return None


def _cleared_denial_shas() -> set[str]:
    """Denial event_sha256s the user has explicitly cleared (lifted) via
    :func:`clear_denial`. Mirror of :func:`_consumed_approval_shas`."""
    out: set[str] = set()
    for ev in ledger.list_events(action="consent.denial_cleared", limit=500):
        sha = (ev.get("detail") or {}).get("denial_event_sha256")
        if sha:
            out.add(str(sha))
    return out


def clear_denial(
    denial_event_sha256: str,
    *,
    chapter_id: str,
    actor_agent_id: str | None = None,
) -> int:
    """Lift a suppression early so the action can be re-surfaced.

    A misclicked Deny, or an action whose situation legitimately changed,
    shouldn't be silently suppressed for the full cooldown. This tombstones the
    named denial — and any OTHER still-active denial of the SAME action
    (capability, scope, context, provenance) — so :func:`find_recent_denial` no
    longer matches and the planner may propose it again. Returns how many
    denials were cleared (0 if the sha isn't a known denial).
    """
    denials = ledger.list_events(action="consent.denied", limit=200)
    target = next((e for e in denials if e.get("event_sha256") == denial_event_sha256), None)
    if target is None:
        return 0
    td = target.get("detail") or {}
    key = (td.get("capability"), td.get("scope"), td.get("context"), td.get("provenance"))

    already = _cleared_denial_shas()
    cleared = 0
    for ev in denials:
        if ev.get("chapter_id") != chapter_id:
            continue
        d = ev.get("detail") or {}
        if (d.get("capability"), d.get("scope"), d.get("context"), d.get("provenance")) != key:
            continue
        sha = ev.get("event_sha256")
        if not sha or sha in already:
            continue
        ledger.record(
            chapter_id=chapter_id,
            action="consent.denial_cleared",
            actor_agent_id=actor_agent_id,
            target_type="denial",
            target_id=sha,
            outcome="ok",
            detail={"denial_event_sha256": sha},
        )
        cleared += 1
    return cleared


def _consumed_approval_shas() -> set[str]:
    """The set of approval event_sha256s that have a `consent.consumed`
    tombstone — i.e. approvals that have already fired and must not fire
    again. Symmetric to ``server._is_resolved`` hiding resolved prompts."""
    out: set[str] = set()
    for ev in ledger.list_events(action="consent.consumed", limit=200):
        sha = (ev.get("detail") or {}).get("approval_event_sha256")
        if sha:
            out.add(str(sha))
    return out


def is_consumed(approval_event_sha256: str) -> bool:
    """Whether a ``consent.consumed`` tombstone exists for this approval."""
    return approval_event_sha256 in _consumed_approval_shas()


def mark_consumed(
    approval_event_sha256: str,
    *,
    chapter_id: str,
    actor_agent_id: str | None = None,
    execution: str = "unknown",
) -> str:
    """Tombstone an approval so it can never fire again (one-shot).

    A user-click approval authorizes a SINGLE execution. The tombstone is a
    `consent.consumed` row referencing the approval; from then on
    :func:`find_valid_approval` skips it. This is what stops a tray-approved
    action from ALSO auto-firing on the next autonomous think cycle while the
    approval's TTL is still live. Repetition without re-prompting is the
    graduation system's job, not a reusable approval.

    ORDER: the tombstone is written BEFORE the action runs (see
    :func:`claim_approval`), so ``execution`` is ``"unknown"`` at the moment
    it is written — the row says "consumed; execution outcome unknown". The
    outcome, once observed, is a separate ``consent.executed`` row
    (:func:`release_execution`); an approval with a tombstone and no executed
    row is one whose runner never reported, and it stays spent. A spent but
    unexecuted approval is the correct failure direction; the previous order
    (run, then tombstone) let a crash between the two re-fire the action on
    the next cycle.
    """
    event = ledger.record(
        chapter_id=chapter_id,
        action="consent.consumed",
        actor_agent_id=actor_agent_id,
        target_type="approval",
        target_id=approval_event_sha256,
        outcome="ok",
        detail={"approval_event_sha256": approval_event_sha256, "execution": execution},
    )
    return event["event_sha256"]


#: Approvals THIS process is executing right now — consumed in the ledger,
#: admitted for exactly one execution. In memory on purpose: a crash empties
#: it and the ledger tombstone is what survives, which is the direction that
#: never double-executes. Guarded because the HTTP approve path runs runners
#: off the event loop in a worker thread.
_in_flight: set[str] = set()
_in_flight_lock = threading.Lock()
#: Serialises find-then-consume so two threads cannot both claim one approval.
_claim_lock = threading.Lock()

#: Ledger outcome for a ``consent.executed`` row, by what the runner reported.
_EXECUTION_OUTCOME: dict[str, str] = {
    "ok": "ok",
    "fail": "fail",
    "denied": "denied",
    "pending_approval": "deferred",
    "error": "fail",
}


def claim_approval(
    req: ActionRequest,
    *,
    chapter_id: str,
    actor_agent_id: str | None = None,
) -> dict | None:
    """Find a valid approval for ``req`` and CONSUME it, atomically, before
    anything runs. Returns the approval row, or None.

    This is the consume-before-execute step. The tombstone is durable before
    the runner is invoked, so no crash, kill or raise between the runner and
    the ledger can leave the approval live to re-fire on the next cycle. The
    approval's sha is then held in the in-flight set so the runner's own
    ``find_valid_approval`` re-check honours it for this one execution; the
    caller MUST pair every successful claim with :func:`release_execution`
    (in a ``finally``), which drops it from the set and records the outcome.

    Held under one lock from lookup to tombstone: without it two threads
    could both find the approval valid, both consume, and both run.
    """
    with _claim_lock:
        approval = find_valid_approval(req, chapter_id=chapter_id)
        if approval is None:
            return None
        sha = str(approval["event_sha256"])
        if sha in _in_flight:
            # Already claimed by this process for an execution still running.
            return None
        # The tombstone MUST persist before anything runs. The realistic
        # transient failure is a SQLite BUSY under lock contention, which
        # clears in milliseconds, so retry briefly; a persistent failure
        # propagates and the caller does NOT execute — the approval stays
        # valid and unspent for a later cycle, which is the closed direction.
        last_err: Exception | None = None
        for attempt in range(3):
            try:
                mark_consumed(sha, chapter_id=chapter_id, actor_agent_id=actor_agent_id, execution="unknown")
                last_err = None
                break
            except Exception as e:  # noqa: BLE001 — transient; retry, then escalate
                last_err = e
                time.sleep(0.05 * (attempt + 1))
        if last_err is not None:
            raise last_err
        with _in_flight_lock:
            _in_flight.add(sha)
        return approval


def release_execution(
    approval_event_sha256: str,
    *,
    chapter_id: str,
    execution: str,
    actor_agent_id: str | None = None,
    error: str | None = None,
) -> str | None:
    """Record what the runner reported for a claimed approval and drop it from
    the in-flight set. ``execution`` is a ``ToolOutcome`` or ``"error"``.

    The in-flight entry is removed FIRST, unconditionally: a ledger that
    cannot take the executed row must not leave the approval admitted for a
    second execution. Returns the executed row's sha, or None if that write
    failed (the tombstone from the claim still stands, so the approval stays
    spent either way; the outcome is then unknown, which is what the missing
    row says).
    """
    with _in_flight_lock:
        _in_flight.discard(approval_event_sha256)
    detail: dict[str, object] = {"approval_event_sha256": approval_event_sha256, "execution": execution}
    if error:
        detail["error"] = error[:2000]
    try:
        event = ledger.record(
            chapter_id=chapter_id,
            action="consent.executed",
            actor_agent_id=actor_agent_id,
            target_type="approval",
            target_id=approval_event_sha256,
            outcome=_EXECUTION_OUTCOME.get(execution, "fail"),
            detail=detail,
        )
    except Exception as e:  # noqa: BLE001 — the tombstone already holds; report, do not hide
        print(
            f"[consent][ERROR] executed row for approval {approval_event_sha256[:8]} could not be "
            f"written ({type(e).__name__}: {e}); the approval is spent and its outcome is recorded "
            f"nowhere — the runner reported {execution!r}"
        )
        return None
    return event["event_sha256"]


def _reset_in_flight_for_tests() -> None:
    with _in_flight_lock:
        _in_flight.clear()


# Keep a small debug helper for assertions — useful in tests + REPL.
def _as_dict(req: ActionRequest) -> dict[str, object]:
    return asdict(req)
