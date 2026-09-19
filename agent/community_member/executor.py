"""Executor — runs a `Plan` through the consent gate + capability runners.

The executor is the boundary between plan (what the LLM proposed) and
action (what the runtime actually did). Its guarantees:

  1. Every proposal goes through `consent.gate.check_and_record` before
     any runner is invoked. An untrusted-only proposal is rejected
     without reaching the capability runner.
  2. Runners return structured `ToolOutput` objects whose `provenance`
     is pinned by the capability. Browser outputs MUST be "untrusted";
     the executor raises if a runner returns anything else. This
     prevents a runner from laundering web content as trusted.
  3. `ExecutionResult` carries the original proposal + the decision +
     the output (if any) + any error. The caller (agent.think() loop)
     uses this to decide what to feed back into the next planner
     turn, always converting tool outputs into typed
     `UntrustedContext` / `SemiTrustedContext` — never as free-text
     additions to the TRUSTED bucket.

This module is intentionally small. Routing + provenance enforcement
only. Capability runners live next to each action surface (e.g.,
`actions.browser.BrowserExecutor` supplies the runner for
"browser.navigate").
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Literal

from community_member.consent import gate
from community_member.consent.gate import ActionRequest, ConsentDecision, Provenance
from community_member.planner import Plan

if TYPE_CHECKING:
    from community_member.graduation import GraduationStore
    from community_member.habits import HabitModel

__all__ = [
    "KNOWN_CAPABILITIES",
    "REFUSED_OUTCOMES",
    "ExecutionResult",
    "Runner",
    "RunnerMap",
    "ToolOutput",
    "execute_plan",
]


# Capability whitelist — anything outside this set is rejected at the
# gate before a consent prompt is even raised. This closes the
# LLM-hallucination hole observed during dogfood: the planner
# occasionally invents capability strings like "agent.record_insight"
# that have no executor and no security review. Allowing them through
# means the user can approve a no-op AND that the audit log is
# polluted with bogus rows that look like real proposals.
#
# Adding a new capability requires:
#   1. An executor in actions/<surface>.py
#   2. A runner adapter in runners.py (next PR)
#   3. R/S tests for the new surface
#   4. Updating this set + a security-review note in the PR
KNOWN_CAPABILITIES: frozenset[str] = frozenset(
    {
        "browser.navigate",
        "browser.extract",
        "fs.read",
        "fs.write",
        "shell.exec",
        "net.http",
        "desktop.click",
        "desktop.type",
        "desktop.read_screen",
        # skill.invoke deviates from the actions/<surface>.py checklist
        # above: its runner dispatches to skill_runtime.invoke_tool (a
        # consent-checked skill call), not a surface executor. Security
        # rationale: skill output is pinned untrusted (below), and
        # skill.invoke is excluded from BOTH auto-approve paths
        # (_NO_AUTO_APPROVE) because the approval match-key is
        # capability+scope+context and a skill's real arguments live in
        # `extra` — auto-approving would blanket-authorize every argument.
        "skill.invoke",
    }
)

# Capabilities that must NEVER be auto-approved (neither by graduation nor
# by the trust threshold). The auto-approve match-key is
# (capability, scope, context) — it does not include `extra`, where a
# skill call carries its actual arguments (url, path, command). Letting
# skill.invoke graduate/trust-auto-approve would therefore authorize ALL
# arguments for a skill once any one was approved (and the trust path
# fires on the very first proposal, with no history). So skill.invoke
# always routes to a real user prompt; it only executes on an explicit
# click matched by gate.find_valid_approval.
_NO_AUTO_APPROVE: frozenset[str] = frozenset({"skill.invoke"})


ToolOutcome = Literal["ok", "fail", "denied", "pending_approval"]

# Outcomes meaning the action did not happen because something refused it —
# as opposed to "fail", where it ran and went wrong.
#
# A refusal can come from a bound that runs AFTER the consent gate has already
# approved: the sandbox policy, or a runner re-checking the approval. So the
# gate's decision is not enough to say what happened to an action, and callers
# that classify results read this rather than `ConsentDecision.state`.
#
# One place, because two readers already need it: `runtime.make_think_outcome`
# partitions on it, and the guard in `tests/test_thinkoutcome_refusal.py`
# asserts nothing in this set can be classified as approved. A new refusing
# outcome is covered by adding it here.
REFUSED_OUTCOMES: frozenset[str] = frozenset({"denied"})


@dataclass(frozen=True)
class ToolOutput:
    """Structured return from a capability runner.

    `content` carries the data the runner produced (page text, file
    bytes as str, shell stdout, etc.). The planner may read `content`
    only via the typed context buckets — never raw. `provenance` on a
    ToolOutput describes the CONTENT, not the authorization that let
    the action run.
    """

    capability: str
    scope: str
    outcome: ToolOutcome
    content: str = ""
    provenance: Provenance = "untrusted"
    source_ref: str | None = None
    extra: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class ExecutionResult:
    """One proposal's outcome after execute_plan sees it through."""

    proposal: ActionRequest
    decision: ConsentDecision
    output: ToolOutput | None = None
    error: str | None = None


# Runner signature: given an ActionRequest, produce a ToolOutput. Any
# exception is caught by execute_plan and wrapped into ExecutionResult.
Runner = Callable[[ActionRequest], ToolOutput]
RunnerMap = dict[str, Runner]


# Capabilities whose outputs are definitionally untrusted — enforced by
# the executor. If a runner for one of these returns a non-untrusted
# output, we raise: this prevents a misbehaving runner from laundering
# web/email/shell content up into the "trusted" bucket.
_ALWAYS_UNTRUSTED_OUTPUTS = frozenset(
    {
        "browser.navigate",
        "browser.extract",
        "shell.exec",
        "fs.read",  # file content is untrusted (could be attacker-written)
        # Desktop surfaces — the OS and the pixels on screen are
        # external inputs, never user intent. A driver that returns
        # ``trusted`` for any of these is a bug; rejecting it here
        # closes the laundering hole.
        "desktop.click",
        "desktop.type",
        "desktop.read_screen",
        # A skill tool can fetch URLs, read files, etc. — its output is
        # external data, never user intent. Pinning untrusted prevents a
        # skill from laundering content into the trusted planner bucket.
        "skill.invoke",
    }
)


def execute_plan(
    plan: Plan,
    runners: RunnerMap,
    *,
    chapter_id: str,
    actor_agent_id: str | None = None,
    habit_model: HabitModel | None = None,
    graduation_store: GraduationStore | None = None,
    context_sha256: str | None = None,
    local_trust: int | None = None,
    chapter_trust: int | None = None,
) -> tuple[ExecutionResult, ...]:
    """Execute each proposal in `plan` through gate + runner.

    Decision order per proposal:

      1. Capability whitelist check — unknown capability → reject.
      2. If habit_model + graduation_store + context_sha256 are
         supplied, try `auto_approve_if_graduated`. A graduated bucket
         yields an approval hash and the runner is invoked
         immediately.
      3. If local_trust or chapter_trust are supplied AND the action's
         provenance is "trusted", try `auto_approve_if_trusted`.
         When effective trust >= AUTO_APPROVE_THRESHOLD, the action
         auto-approves with `decision_reason="trust_threshold"` and
         the trust scores recorded in the audit row. Untrusted-
         provenance actions are unconditionally NOT auto-approved
         here; that's the prompt-injection defense layer.
      4. Else CLAIM an existing valid user-clicked approval via
         `gate.claim_approval`, which tombstones it in the ledger BEFORE
         the runner is invoked (consume-before-execute). If found, treat
         as approved, invoke the runner, and record the outcome with
         `gate.release_execution` whether or not the runner returned.
      5. Else fall back to `gate.check_and_record` which writes a
         prompt row + returns "prompt".

    Returns a tuple of `ExecutionResult`, one per proposal, in plan
    order. Never raises — every failure mode is captured as a field
    on the result, so the caller can feed the full list back into
    the next planner turn without handling half-broken state.
    """

    def _observe_safe(proposal_, decision_state_: str) -> None:
        """Record one user-decision observation in the habit model.
        Best-effort — never raises into the caller. WIRE-5: this is
        the missing wire that makes graduation-tier counts move."""
        if habit_model is None or not context_sha256:
            return
        if decision_state_ not in ("approved", "reject"):
            return
        from datetime import UTC, datetime

        try:
            habit_model.observe(
                capability=proposal_.capability,
                scope=proposal_.scope,
                context_sha256=context_sha256,
                decision="approved" if decision_state_ == "approved" else "denied",
                recorded_at=datetime.now(UTC).isoformat(),
            )
        except Exception:
            pass

    results: list[ExecutionResult] = []
    for proposal in plan.proposals:
        # ── (1) Capability whitelist ────────────────────────────
        if proposal.capability not in KNOWN_CAPABILITIES:
            decision = ConsentDecision(state="reject", reason="unknown_capability")
            event_hash = gate.record_decision(
                proposal,
                decision,
                chapter_id=chapter_id,
                actor_agent_id=actor_agent_id,
            )
            # NOTE: no habit observation for unknown caps — they'd
            # pollute the buckets with phantom (cap, scope) tuples
            # that the planner can never re-emit.
            results.append(
                ExecutionResult(
                    proposal=proposal,
                    decision=ConsentDecision(
                        state="reject",
                        reason="unknown_capability",
                        event_sha256=event_hash,
                    ),
                )
            )
            continue

        # ── (1.5) Recently denied? Suppress — don't re-prompt ───
        # If the user denied this exact action within the cooldown, reject it
        # here BEFORE any auto-approve or prompt path. The planner keeps
        # re-proposing (it doesn't remember asking), but the user already said
        # no, so it must not reach the tray again — and a recent "no" overrides
        # graduation/trust for the window. No new ledger row: the original
        # consent.denied is the record; writing one per cycle would just spam.
        try:
            recent_denial = gate.find_recent_denial(proposal, chapter_id=chapter_id)
        except Exception:
            recent_denial = None
        if recent_denial is not None:
            results.append(
                ExecutionResult(
                    proposal=proposal,
                    decision=ConsentDecision(state="reject", reason="recently_denied"),
                )
            )
            continue

        # ── (1.6) S3: untrusted provenance is never executable ──
        # The single load-bearing defense against indirect prompt injection
        # (consent/gate.evaluate). An approval row minted for an untrusted
        # proposal MUST NOT be honored by the graduation / trust /
        # find_valid_approval paths below — each of those sets an "approved"
        # decision WITHOUT re-running evaluate(), which is where the untrusted
        # reject lives. Route an untrusted proposal straight to the gate (which
        # rejects and records it via evaluate's S3 rule) and stop, before any
        # auto-approve path can override the verdict. Without this, injected
        # web/email content proposing a previously-approved (cap, scope,
        # context, provenance) tuple would execute.
        if proposal.provenance == "untrusted":
            reject = gate.check_and_record(proposal, chapter_id=chapter_id, actor_agent_id=actor_agent_id)
            _observe_safe(proposal, "reject")
            results.append(ExecutionResult(proposal=proposal, decision=reject))
            continue

        # ── (2) Auto-approve if graduated ───────────────────────
        # _NO_AUTO_APPROVE caps (skill.invoke) skip both auto-approve
        # paths — their arguments live in `extra`, outside the match-key.
        decision: ConsentDecision | None = None
        _may_auto_approve = proposal.capability not in _NO_AUTO_APPROVE
        if _may_auto_approve and habit_model is not None and graduation_store is not None and context_sha256:
            try:
                from community_member.graduation import auto_approve_if_graduated

                auto_hash = auto_approve_if_graduated(
                    proposal,
                    context_sha256=context_sha256,
                    chapter_id=chapter_id,
                    habit_model=habit_model,
                    graduation_store=graduation_store,
                    actor_agent_id=actor_agent_id,
                )
            except Exception:
                auto_hash = None
            if auto_hash is not None:
                decision = ConsentDecision(
                    state="approved",
                    reason="graduated",
                    event_sha256=auto_hash,
                )

        # ── (2.5) Auto-approve if effective trust >= threshold ──
        if decision is None and _may_auto_approve and (local_trust is not None or chapter_trust is not None):
            try:
                from community_member.identity_trust import auto_approve_if_trusted

                trust_hash = auto_approve_if_trusted(
                    proposal,
                    chapter_id=chapter_id,
                    local_trust=int(local_trust or 0),
                    chapter_trust=int(chapter_trust or 0),
                    actor_agent_id=actor_agent_id,
                )
            except Exception:
                trust_hash = None
            if trust_hash is not None:
                decision = ConsentDecision(
                    state="approved",
                    reason="trust_threshold",
                    event_sha256=trust_hash,
                )

        # ── (3) Existing user-clicked approval? CLAIM it. ───────
        # One-shot (G2): a user-click approval authorizes exactly ONE
        # execution. It is tombstoned HERE, before the runner fires — not
        # after. The previous order (run, then mark_consumed) left the
        # approval live inside its TTL if the process died between the two,
        # and the next cycle re-fired the action: a duplicate external
        # action. A claim that is then never executed (no runner, a crash
        # before the runner) leaves a spent approval and an unknown outcome,
        # which is the failure direction a consent system must prefer.
        # Graduation and trust auto-approvals are policy, not one-shot, and
        # are not claimed.
        if decision is None:
            try:
                approval = gate.claim_approval(proposal, chapter_id=chapter_id, actor_agent_id=actor_agent_id)
            except Exception:
                approval = None
            if approval is not None:
                decision = ConsentDecision(
                    state="approved",
                    reason="user_approved",
                    event_sha256=approval["event_sha256"],
                )

        # ── (4) Fallback: write prompt + return pending ─────────
        if decision is None:
            decision = gate.check_and_record(
                proposal,
                chapter_id=chapter_id,
                actor_agent_id=actor_agent_id,
            )
        if decision.state == "reject":
            _observe_safe(proposal, "reject")
            results.append(ExecutionResult(proposal=proposal, decision=decision))
            continue
        if decision.state == "prompt":
            # W1 path: the executor does not block waiting for the
            # tray UI to collect user approval. It returns a
            # pending_approval placeholder so the caller can report
            # "these need approval" back to the human. The actual
            # follow-up flow (UI approval → re-submit with approval
            # hash) is the tray-UI PR's job.
            pending = ToolOutput(
                capability=proposal.capability,
                scope=proposal.scope,
                outcome="pending_approval",
                content="",
                provenance="trusted",  # our own metadata, not tool output
                source_ref=None,
                extra={"prompt_event_sha256": decision.event_sha256},
            )
            results.append(ExecutionResult(proposal=proposal, decision=decision, output=pending))
            continue
        # decision.state == "approved" — graduated bucket OR
        # find_valid_approval matched a prior user click. WIRE-5:
        # observe the approval so the habit model's posterior moves
        # toward graduation on the next cycle.
        _observe_safe(proposal, "approved")
        # A claimed approval is released whatever happens below: the runner
        # returned, raised, or was never registered. Release records the
        # outcome as a `consent.executed` row and drops the in-flight
        # admission; the tombstone from the claim is already durable.
        claimed_sha = decision.event_sha256 if decision.reason == "user_approved" else None

        def _release(execution: str, error: str | None = None) -> None:
            if claimed_sha:
                gate.release_execution(
                    claimed_sha,
                    chapter_id=chapter_id,
                    execution=execution,
                    actor_agent_id=actor_agent_id,
                    error=error,
                )

        runner = runners.get(proposal.capability)
        if runner is None:
            err = f"no runner registered for capability {proposal.capability!r}"
            _release("error", err)
            results.append(ExecutionResult(proposal=proposal, decision=decision, error=err))
            continue
        try:
            output = runner(proposal)
        except Exception as e:
            err = f"{type(e).__name__}: {e}"
            _release("error", err)
            results.append(ExecutionResult(proposal=proposal, decision=decision, error=err))
            continue
        except BaseException:
            # A crash escaping the executor (SystemExit, KeyboardInterrupt, a
            # kill turned into an exception): the approval is already spent
            # in the ledger; record that the outcome was not observed.
            _release("error", "runner interrupted before reporting")
            raise
        _release(output.outcome)
        # Provenance-guard: runners for always-untrusted capabilities
        # cannot produce a trusted or semi-trusted output.
        if proposal.capability in _ALWAYS_UNTRUSTED_OUTPUTS and output.provenance != "untrusted":
            results.append(
                ExecutionResult(
                    proposal=proposal,
                    decision=decision,
                    error=(
                        f"capability {proposal.capability!r} output "
                        f"provenance must be 'untrusted', got {output.provenance!r}"
                    ),
                )
            )
            continue
        results.append(ExecutionResult(proposal=proposal, decision=decision, output=output))
    return tuple(results)
