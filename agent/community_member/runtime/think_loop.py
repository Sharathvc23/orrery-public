"""One end-to-end think cycle — plan_from_llm → execute_plan → classify.

`think_v2` is the single entry point a caller uses to run the v2
autonomous loop. It wraps:

  1. `plan_from_llm(ctx, llm, model=...)` — ask the LLM for a Plan
  2. `execute_plan(plan, runners, chapter_id=...)` — route each
     proposal through the consent gate + runner
  3. Classify the results into `approved`, `pending_approval`,
     `rejected`, `errored`, `no_runner` — so the caller can decide
     what to surface to the user without re-walking the result list

Nothing stateful lives here. The consent ledger holds the audit
trail; the habit engine (W3) will hold learning state; this module
is pure composition.

Explicit non-goals:
  * No retry-on-approval loop. `think_v2` runs once and returns; an approval
    arrives separately, through `POST /api/local/consent/approve`, which
    records the click and executes the action itself.
  * No side-effecting LLM client management. Caller owns the client.
  * No chapter network calls. Chapter integration goes through the
    runners the caller hands in, not via this glue.

Who reads the result: `LocalAgent.run` prints the four bucket counts as its
per-cycle summary line. That is the only consumer of the partition in this
repository.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from community_member import llm_skip
from community_member.executor import REFUSED_OUTCOMES, ExecutionResult, RunnerMap, execute_plan
from community_member.llm_skip import SkipInputs
from community_member.planner import Plan, PlannerContext
from community_member.planner_llm import LLMClient, plan_from_llm

__all__ = ["ThinkOutcome", "make_think_outcome", "think_v2"]


@dataclass(frozen=True)
class ThinkOutcome:
    """Result of one `think_v2` cycle.

    `plan` is the raw Plan the LLM produced (empty if the model
    refused or returned malformed output).
    `results` is the full ExecutionResult tuple in plan order.
    The named buckets below are partitions of `results` — every
    ExecutionResult lands in exactly one of them, so
    `len(results) == sum(len(b) for b in [approved, pending_approval, rejected, errored])`.
    """

    plan: Plan
    results: tuple[ExecutionResult, ...]
    approved: tuple[ExecutionResult, ...] = field(default_factory=tuple)
    pending_approval: tuple[ExecutionResult, ...] = field(default_factory=tuple)
    rejected: tuple[ExecutionResult, ...] = field(default_factory=tuple)
    errored: tuple[ExecutionResult, ...] = field(default_factory=tuple)

    @property
    def produced_nothing(self) -> bool:
        """The cycle spent a model call and no work came of it.

        The caller backs off on this, because repeating such a cycle buys
        another model call and the same result until something outside the loop
        changes.

        ⚠️ THIS REPLACES ``fully_refused``, WHICH ASKED A NARROWER QUESTION THAN
        THE ONE THE CALLER NEEDS. That predicate was
        ``bool(results) and len(rejected) == len(results)``, so it answered
        False for the two states that actually occur:

        * AN EMPTY CYCLE. The planner proposing nothing was reasoned about as "a
          different condition from the runtime refusing everything" — true, and
          irrelevant to the caller, which is asking whether the last call bought
          anything. It did not.
        * A PENDING-ONLY CYCLE. The old docstring argued that backing off would
          "make it sluggish exactly when someone is about to approve". That is
          not how approval works here: ``POST /api/local/consent/approve``
          executes the action immediately through the agent's runners and
          tombstones the approval so the loop cannot re-fire it — it exists
          precisely to close the "I clicked Approve, why did nothing happen?"
          gap. Nothing about a human's approval waits on this loop's cadence, so
          the sluggishness the exclusion was protecting against does not exist,
          while the cost it caused — a full model call per interval re-proposing
          what a human has not answered yet — does.

        An errored cycle is NOT included: an error is a different condition with
        its own handling on the retryable path, and attempting work that failed
        is not the same as producing nothing to attempt.
        """
        return not self.approved and not self.errored


def make_think_outcome(plan: Plan, results: tuple[ExecutionResult, ...]) -> ThinkOutcome:
    """Partition `results` into the four named buckets.

    The buckets name WHAT HAPPENED TO THE ACTION, which is not the same fact as
    what the consent gate decided. They were the same while the gate was the
    only bound that could refuse; they diverged once a bound could refuse after
    the gate approved — the sandbox policy, or a runner re-checking the
    approval. So the classifier reads the final outcome the runner reported,
    and falls back to `decision.state` only where there is no outcome to read.

    Classification rule, in order:
      * `error is not None` → errored (runner raised, no runner registered,
        provenance guard tripped)
      * output reports an outcome in `executor.REFUSED_OUTCOMES` → rejected,
        whatever `decision.state` says. An approved-then-refused action did
        not happen, and counting it as approved is how a policy refusal
        became invisible to the only thing that reads these buckets.
      * `decision.state == "approved"` AND `output is not None` → approved
      * `decision.state == "prompt"` → pending_approval
      * `decision.state == "reject"` → rejected
      * anything else (approved with no output, an unknown state) → errored,
        so no classification gap goes silent

    Every result lands in exactly one bucket:
    ``len(results) == len(approved) + len(pending_approval) + len(rejected)
    + len(errored)``.

    What consumes this today: the agent's per-cycle summary line
    (`LocalAgent.run`), which prints the four counts. Nothing else reads the
    buckets — an earlier version of this docstring claimed a tray UI consumer
    that does not exist in this repository.
    """
    approved: list[ExecutionResult] = []
    pending: list[ExecutionResult] = []
    rejected: list[ExecutionResult] = []
    errored: list[ExecutionResult] = []

    for r in results:
        if r.error is not None:
            errored.append(r)
            continue
        if r.output is not None and r.output.outcome in REFUSED_OUTCOMES:
            rejected.append(r)
            continue
        if r.decision.state == "approved" and r.output is not None:
            approved.append(r)
            continue
        if r.decision.state == "prompt":
            pending.append(r)
            continue
        if r.decision.state == "reject":
            rejected.append(r)
            continue
        # Fall-through: covers the weird shapes (approved but no
        # output, or an unknown state). Treated as errored so no
        # classification gap goes silent.
        errored.append(r)

    return ThinkOutcome(
        plan=plan,
        results=results,
        approved=tuple(approved),
        pending_approval=tuple(pending),
        rejected=tuple(rejected),
        errored=tuple(errored),
    )


def think_v2(
    ctx: PlannerContext,
    llm: LLMClient,
    *,
    model: str,
    runners: RunnerMap | None = None,
    chapter_id: str,
    actor_agent_id: str | None = None,
    max_tokens: int = 800,
    habit_model=None,
    graduation_store=None,
    context_sha256: str | None = None,
    local_trust: int | None = None,
    chapter_trust: int | None = None,
    skip_inputs: SkipInputs | None = None,
    principal: str = "",
) -> ThinkOutcome:
    """Run one end-to-end think cycle.

    Parameters
    ----------
    ctx
        PlannerContext with the user task and typed context buckets.
        Callers construct this from their local state (recent user
        messages, pending chapter intents, web content the agent
        fetched earlier).
    llm
        OpenAI-compatible client (duck-typed via `LLMClient`).
    model
        LLM model name, e.g. "grok-3-mini".
    runners
        Capability → runner map. For W1 the executor mostly returns
        `pending_approval` for trusted proposals (no runner needed)
        and rejects untrusted proposals (ditto). Runners matter once
        graduation goes live in W4+. Defaults to empty.
    chapter_id
        Scoping identifier for the consent ledger. Use
        `"local:{did_key}"` for standalone device agents.
    actor_agent_id
        Optional actor id recorded on every ledger row written by
        this cycle.
    max_tokens
        Forwarded to plan_from_llm; caps the LLM's output size.

    Returns
    -------
    ThinkOutcome with the Plan, all ExecutionResults, and the four
    partitioned buckets.
    """
    # ── skip a request nothing could have changed the answer to ──────────
    #
    # Measured: twenty real cycles produced twenty requests and ONE distinct
    # body, because PlannerContext is built from static config plus the skill
    # catalogue. The key covers the rendered prompt itself plus the external
    # state that can change an outcome without changing the prompt, so a cycle
    # is only skipped when both are unchanged.
    #
    # skip_inputs is None by default and that means NO SKIP. A caller that
    # cannot say what its external state is cannot be given a safe skip, so the
    # unsafe case is the one that requires no argument rather than the easy one.
    memo = None
    key = ""
    if skip_inputs is not None and llm_skip.skip_enabled():
        key = llm_skip.plan_key(ctx, model=model, max_tokens=max_tokens, inputs=skip_inputs)
        store = skip_inputs.store or llm_skip.memo_store()
        memo = store.get(key, max_age_s=llm_skip.skip_max_age_s())

    if memo is not None:
        # Counted, always. A skip that is not counted cannot be defended and a
        # regression in it cannot be seen; the streak is what makes a wedged
        # skip observable rather than silent.
        _record_skip(principal=principal, model=model, streak=memo.streak)
        return memo.value

    plan = plan_from_llm(ctx, llm, model=model, max_tokens=max_tokens)
    results = execute_plan(
        plan,
        runners or {},
        chapter_id=chapter_id,
        actor_agent_id=actor_agent_id,
        habit_model=habit_model,
        graduation_store=graduation_store,
        context_sha256=context_sha256,
        local_trust=local_trust,
        chapter_trust=chapter_trust,
    )
    outcome = make_think_outcome(plan, results)
    if key:
        (skip_inputs.store or llm_skip.memo_store()).put(key, outcome)
    return outcome


def _record_skip(*, principal: str, model: str, streak: int) -> None:
    """Put one skip on the meter. Never raises.

    Telemetry must not be able to take down the think loop: a meter that can
    break the thing it measures is worse than no meter. The streak is recorded
    as part of the reason so a wedge shows up as a growing bucket rather than
    needing a separate counter.
    """
    try:
        from community_member import llm_meter

        llm_meter.record_skip(
            side="agent",
            callsite="think_v2.plan",
            principal=principal or "unknown",
            provider="",
            model=model,
            reason=llm_skip.SKIP_REASON,
        )
    except Exception:  # noqa: BLE001 — a meter failure must not stop a cycle
        pass
