"""
Think Cycle — autonomous agent behavior.
"""

import json
import random
import re
import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import llm_config
import llm_elide
import llm_runtime
from a2ui_helpers import build_insight_card, build_introduction_card, build_thought_card

# State — set by init()
pg_request: Callable[..., Awaitable] | None = None

def _pg() -> Callable[..., Awaitable]:
    """The injected pg_request, or a LOUD failure if init() never ran — the
    old unguarded calls crashed with a bare 'NoneType' object is not callable
    (R2 whole-app sweep)."""
    if pg_request is None:
        raise RuntimeError("think_cycle.init() was never called — no pg_request injected")
    return pg_request

members: dict = {}
federation: dict = {}
llm: Any = None


def _planner_offline(what: str) -> bool:
    """Whether this cycle must serve its deterministic outcome instead of calling.

    Two conditions, and both matter. ``llm is None`` is the strict path — no
    client was built because no credential resolved. ``planner_enabled()`` is the
    existing check for a chapter whose client exists but points at a provider the
    operator never chose.

    Printed rather than raised, and returned rather than thrown, because a
    chapter with no model is a supported state: it keeps its portal, its surfaces
    and its federation. What it must not do is post the roster to a provider
    nobody configured.
    """
    if llm is not None and llm_config.planner_enabled():
        return False
    print(f"  {what} skipped: no LLM provider configured — no request was made")
    return True

AGENT_ID = ""
AGENT_NAME = ""
AGENT_DESCRIPTION = ""
AGENT_FOCUS = ""
# How many distinct skills the insight prompt names. Bounds the one org prompt
# that grows without limit as a chapter does — 145 tokens on a bare fixture,
# 1,335 on a realistic 300-skill chapter. The WATERMARK is unbounded; only the
# prompt is sampled. See think_insight.
INSIGHT_SKILL_SAMPLE = 40


def _sample_for_prompt(items: list[str], limit: int) -> tuple[list[str], str]:
    """An evenly spread sample of ``items``, and a note saying it is one.

    Returns the full list and an empty note when it already fits, so a small
    chapter's prompt is unchanged and reads as complete — which it is.

    ⚠️ THE NOTE IS NOT DECORATION. Without it a reader cannot tell a sampled list
    from a complete one, and neither can the model: "Local skills: a, b, c" reads
    as the whole capability set of the chapter either way, and an analyst asked
    what is MISSING from a list it believes is complete will answer confidently
    about a gap that is not there.
    """
    if limit <= 0 or len(items) <= limit:
        return list(items), ""
    step = len(items) / limit
    sampled = [items[min(int(i * step), len(items) - 1)] for i in range(limit)]
    # Dedupe defensively while keeping order; int() collisions are possible at
    # the tail for some ratios and a repeated skill would read as an error.
    #
    # `dict.fromkeys` rather than the seen-set comprehension: dicts preserve
    # insertion order, so this dedupes and keeps order in one call. The idiom it
    # replaces — `if not (x in seen or seen.add(x))` — is correct at runtime,
    # because set.add returns None and None is falsy, but it USES THE RETURN
    # VALUE OF A None-RETURNING CALL, which mypy strict rejects outright. Being
    # right at runtime is not the same as being expressible, and the version that
    # needs no explanation is the better one anyway.
    spread = list(dict.fromkeys(sampled))
    return spread, f" ({len(spread)} sampled of {len(items)})"


DEFAULT_LLM_MODEL = llm_config.DEFAULT_MODEL
# The fast tier, named rather than looked up. Every site using it caps output at
# 100 tokens or fewer and forces no tool_choice — see llm_config's tiering block.
FAST_MODEL = llm_config.FAST_MODEL
_knowledge_cache: dict = {}

# Injected helpers
remember: Any = None
recent_memories: Any = None
get_intelligence_context: Any = None
log_activity: Any = None
log_agent_thought: Any = None
conv_store = None
build_member_system_prompt = None

# Injected modules
activity_tracker: Any = None
sovereign_runtime_mod = None
intents_mod = None
outcome_tracker_mod = None
federation_discovery_mod = None

think_cycle_count = 0


def init(**kw):
    g = globals()
    for k, v in kw.items():
        if k in g:
            g[k] = v


# AUTONOMOUS THINK CYCLE
# ============================================================
think_cycle_count = 0


async def run_cycle():
    """Autonomous thinking — the agent proposes, leaders approve, then it acts.

    Governance-aware cycle order: introductions and cross-chapter actions go
    through the approval queue; only in-chapter autonomy remains direct.
    """
    global think_cycle_count
    think_cycle_count += 1
    cycle_types = [
        "introduction_propose",  # writes to pending_approvals, no direct action
        "insight",
        "conversation",  # only between already-approved matched pairs
        "evolve",
        "event_propose",  # event proposals go through approval too
        "digest",
        "reflect",
        "sovereign_think",
        "intent_match",
        "approvals_sweep",  # expire stale + execute approved proposals
        "chapter_broadcast",  # auto-fanout chapter.digest.weekly to peers (PR4)
        "retention_sweep",  # daily retention sweeper — runs at most once / 24h, dry-run by default
    ]
    cycle_type = think_cycle_count % len(cycle_types)

    print(f"Think cycle #{think_cycle_count} (type={cycle_types[cycle_type]})")

    try:
        if cycle_type == 0:
            await think_introduction_propose()
        elif cycle_type == 1:
            await think_insight()
        elif cycle_type == 2:
            await think_conversation()
        elif cycle_type == 3:
            await think_evolve()
        elif cycle_type == 4:
            await think_event()
        elif cycle_type == 5:
            await think_digest()
        elif cycle_type == 6:
            await think_reflect()
        elif cycle_type == 7:
            await sovereign_runtime_mod.think_sovereign_cycle(members)
        elif cycle_type == 8:
            await think_intent_match()
        elif cycle_type == 9:
            await think_approvals_sweep()
        elif cycle_type == 10:
            await think_chapter_broadcast()
        elif cycle_type == 11:
            await think_retention_sweep()
    except Exception as e:
        # ⚠️ DO NOT SWALLOW. ``agent_scheduler.after_failure`` decides
        # terminal-vs-retryable for this loop, and it can only decide about a
        # failure that reaches the caller. Returning normally here is what made
        # that half of the discipline unreachable — a sustained 401 kept the
        # cadence at full rate and cost 418 org calls a day, forever, because
        # every cycle looked like a success to the scheduler.
        #
        # The caller catches this and routes it; the heartbeat loop is not put
        # at risk by raising.
        print(f"Think cycle error: {e}")
        raise


# In-memory cooldown — retention sweep runs at most once per 24h per
# container. Reset on container restart (acceptable: a redeploy =
# new day for retention purposes). Avoids running the sweep every
# 25min when the think cycle rotates through type 16.
_last_retention_sweep_at: float = 0.0


async def think_retention_sweep() -> None:
    """Daily retention-sweep cycle. Gated by:
      1. ``CHAPTER_RETENTION_SWEEP_ENABLED`` env (default true)
      2. 24-hour in-memory cooldown
      3. ``CHAPTER_RETENTION_SWEEP_DRY_RUN`` env (default true)

    On run, calls ``retention.sweep_once`` then ``emit_audit_for_sweep``
    so the result lands in ``chapter_audit_events`` either way (dry-run
    or live). Operators inspect the audit log for several days before
    flipping DRY_RUN=false.
    """
    global _last_retention_sweep_at
    import time

    try:
        import retention
    except ImportError:
        return

    if not retention.is_sweep_enabled():
        return

    now = time.monotonic()
    if (now - _last_retention_sweep_at) < (24 * 3600):
        return

    dry_run = retention.is_dry_run_mode()
    print(f"[retention] sweep starting (dry_run={dry_run})")

    try:
        from chapter_agent import AGENT_ID, pg_request

        result = await retention.sweep_once(pg_request, AGENT_ID, dry_run=dry_run)
        await retention.emit_audit_for_sweep(result, AGENT_ID)
        print(
            f"[retention] sweep complete: dry_run={result['dry_run']} "
            f"total_{('would_delete' if dry_run else 'deleted')}={result['total_deleted']}"
        )
        _last_retention_sweep_at = now
    except Exception as e:  # noqa: BLE001
        # Fire-and-forget telemetry pattern — retention failure MUST NOT
        # disrupt the think cycle.
        print(f"[retention] sweep failed: {type(e).__name__}: {e}")


async def think_intent_match():
    """Re-match active intents against current projections and federation."""
    active = await intents_mod.get_active_intents()
    if not active:
        return
    # Re-match the most recent active intent
    intent = active[0]
    intent_id = intent.get("id", "")
    if intent_id:
        await intents_mod.match_intent(intent_id)
        await intents_mod.match_intent_federation(intent_id, federation)


async def think_introduction_propose():
    """Find complementary members and WRITE A PROPOSAL to the approval queue.

    Governance change: this cycle no longer sends introductions directly.
    It proposes to the chapter's leaders via `pending_approvals`, who
    approve or reject. Approved proposals are then executed by
    think_approvals_sweep (which synthesises the conversation + logs activity).

    Rate limits applied here:
      - Skip pairs that had an introduction proposed or executed in the last 30 days
      - Skip cross-chapter pairs if chapter_federation_policy blocks that peer
    """
    all_members = []
    for mid, m in members.items():
        all_members.append(
            {
                "agent_id": mid,
                "name": m["name"],
                "skills": m.get("skills", []),
                "chapter": AGENT_NAME,
                "chapter_id": AGENT_ID,
            }
        )

    for fid, finfo in federation.items():
        remote_members = await federation_discovery_mod.query_chapter_members(fid)
        for rm in remote_members:
            all_members.append({**rm, "chapter": finfo["name"], "chapter_id": fid})

    if len(all_members) < 2:
        return

    # Persistent dedup — survives restarts. Kept: this list is a hard exclusion
    # the model must honour, not the "do not repeat recent themes" prose that
    # exists to paper over re-asking. That prose is gone from the gated types.
    recent_pairs = await recent_memories("intro_pair", 20)
    recent_pairs_text = ""
    if recent_pairs:
        recent_pairs_text = "\n\nDO NOT pair these — they were recently introduced:\n" + "\n".join(
            f"- {p.replace('|', ' & ')}" for p in recent_pairs
        )

    # The prompt takes a bounded slice, because that is what keeps it small.
    members_json = json.dumps(all_members[:30], indent=2)

    # ⚠️ THE WATERMARK TAKES THE FULL ROSTER, NOT THE SLICE ABOVE. A value that
    # was truncated, sampled or capped for prompt-size reasons cannot double as
    # the change detector for the thing it was truncated from. Hashing
    # members_json made this gate blind past member 30: a joiner lands outside
    # the slice, the serialisation is unchanged, the watermark does not move,
    # and the type stops running on a roster that genuinely changed — visible
    # only as an absence, because nothing alerts on an introduction that was
    # never proposed. The org this runs on had 23 members when that was found.
    #
    # The recent-pairs cap above is the OTHER direction and is safe:
    # recent_memories returns the NEWEST 20, so a new exclusion always lands
    # inside the window and what falls off the end is the oldest. Both are
    # caps; only a cap that can hide a NEW entry can hide a change.
    #
    # 61% of this org's daily input tokens were this one serialisation, re-sent
    # every 24 minutes for a list that changes about once a day.
    wm = llm_elide.watermark(
        roster=all_members,
        roster_size=len(all_members),
        recent_pairs_text=recent_pairs_text,
        agent_name=AGENT_NAME,
    )
    run, why = await llm_elide.should_run("introduction_propose", wm, recent_memories=recent_memories)
    if not run:
        print(f"  Intro elided: {why}")
        return
    if _planner_offline("Introduction propose"):
        return
    try:
        response = llm.chat.completions.create(
            model=DEFAULT_LLM_MODEL,
            messages=[
                {
                    "role": "system",
                    "content": f"You are the community manager for {AGENT_NAME}. Your job is to connect people across NANDA chapters. Always pick DIFFERENT pairs — variety is key.",
                },
                {
                    "role": "user",
                    "content": f"""Here are members across the NANDA federation:

{members_json}

Pick TWO members from DIFFERENT chapters whose skills complement each other. Explain why they should meet.{recent_pairs_text}

Respond in this exact JSON format:
{{"member_a": {{"agent_id": "...", "name": "...", "chapter": "..."}}, "member_b": {{"agent_id": "...", "name": "...", "chapter": "..."}}, "reason": "one sentence why they should connect"}}""",
                },
            ],
            max_tokens=300,
        )
        text = response.choices[0].message.content or ""
        # Extract JSON from response
        json_match = re.search(r"\{.*\}", text, re.DOTALL)
        if not json_match:
            return
        intro = json.loads(json_match.group(0))
    except Exception as e:
        print(f"Introduction think failed: {e}")
        return

    member_a = intro.get("member_a", {})
    member_b = intro.get("member_b", {})
    reason = intro.get("reason", "Complementary skills")
    a_id = member_a.get("agent_id", "")
    b_id = member_b.get("agent_id", "")

    if not a_id or not b_id or a_id == b_id:
        return

    # Cool-down: skip if this pair was already proposed/approved/executed recently
    try:
        import governance

        if await governance.recent_introduction_exists(a_id, b_id):
            print(f"  Intro cool-down: skipping {a_id} × {b_id}")
            return
    except ImportError:
        pass

    # Confidence score — use LLM-reported qualitative fit until we wire
    # real pgvector similarity. Cap at 0.9 so leader review always adds value.
    confidence = 0.7
    payload = {
        "pair": [a_id, b_id],
        "member_a": member_a,
        "member_b": member_b,
        "reason": reason,
        "cross_chapter": member_a.get("chapter_id") != member_b.get("chapter_id"),
    }

    try:
        import governance

        created = await governance.propose(
            kind="introduction",
            proposer_agent_id=AGENT_ID,
            target_agent_id=a_id,
            payload=payload,
            peer_chapter_id=member_b.get("chapter_id") if payload["cross_chapter"] else None,
            confidence=confidence,
        )
        if created:
            print(f"  Intro proposed: {member_a.get('name')} × {member_b.get('name')} (pending leader approval)")
        await llm_elide.record_run("introduction_propose", wm, remember=remember)
    except Exception as e:
        print(f"Intro proposal failed: {e}")


async def think_approvals_sweep():
    """Expire stale proposals + execute any leaders have approved since last sweep.

    Runs after every full cycle rotation (~24 min). For each approved
    proposal of a supported kind, run the action and mark executed.
    """
    try:
        import governance
    except ImportError:
        return

    expired = await governance.sweep_expired()
    if expired:
        print(f"  Approvals sweep: {expired} proposal(s) expired")

    # Execute approved introductions that haven't been dispatched yet
    if pg_request is None:
        return
    try:
        approved = await pg_request(
            "GET",
            "pending_approvals",
            params={
                "chapter_id": f"eq.{AGENT_ID}",
                "status": "eq.approved",
                "order": "approved_at.asc",
                "limit": "20",
            },
        )
    except Exception as e:
        print(f"Approvals sweep read failed: {e}")
        return

    rows = list(approved or [])
    for index, row in enumerate(rows):
        kind = row.get("kind")
        try:
            if kind == "introduction":
                await _execute_approved_introduction(row)
                await governance.mark_executed(row["id"])
            elif kind == "broadcast":
                # PR5: a member-proposed broadcast got leader approval.
                # Execute via broadcast.send_broadcast with the CHAPTER
                # agent as sender — peers see it as a sanctioned server
                # message, not the proposer's voice. The proposer is
                # preserved on the pending_approvals row for audit.
                import broadcast as broadcast_mod

                payload = row.get("payload") or {}
                if broadcast_mod.is_initialized() and payload.get("title") and payload.get("body"):
                    result = await broadcast_mod.send_broadcast(
                        sender_agent_id=AGENT_ID,
                        title=str(payload["title"])[:200],
                        body=str(payload["body"])[:8000],
                        tags=list(payload.get("tags") or [])[:20],
                        audience=str(payload.get("audience") or "all"),
                    )
                    if "error" not in result:
                        await governance.mark_executed(row["id"])
                        print(
                            f"  broadcast executed: {result.get('broadcast_id')!r} "
                            f"proposed_by={row.get('proposer_agent_id')}"
                        )
                    else:
                        print(f"  broadcast execute failed: {result.get('error')}")
        except llm_runtime.LLMCallBudgetExceeded as e:
            # ⚠️ A NAMED REFUSAL THAT IS RECORDED, NOT A SILENT TRUNCATION. This
            # loop makes two LLM calls per approved row and was measured making
            # forty sequential calls in one cycle at its own row limit of twenty.
            # The bound is on latency and rate-limit headroom rather than on
            # spend — all forty cost 1,897 tokens in total — and the thing that
            # must not happen when it bites is somebody's approved introductions
            # quietly not happening.
            #
            # Nothing is lost: a row is only marked executed after it succeeds,
            # so every row from here on is still `approved` and the next sweep
            # takes it. What would lose work is carrying on and failing each of
            # them individually, or stopping without saying so.
            deferred = len(rows) - index
            print(
                f"  Approvals sweep STOPPED at the per-cycle LLM call limit: {e} "
                f"{deferred} approval(s) deferred to the next sweep (executed {index} this cycle)"
            )
            break
        except Exception as e:
            print(f"Execute approved {kind} {row.get('id')} failed: {e}")

    # Auto-tune hyperparameters + auto-promote pending nominations.
    # Both are safe no-ops when disabled / within warmup / below min samples.
    try:
        import policy as policy_mod

        tune_summary = await policy_mod.tune_cycle()
        if tune_summary:
            for key, change in tune_summary.items():
                print(f"  Policy tuned: {key} {change['old']} -> {change['new']} ({change['reason']})")

        # Trust auto-tuner (PR-E of trust-events series). Adjusts the
        # `trust.delta_scale` chapter_policy key based on whether
        # newcomers are reaching the federate threshold.
        trust_tune = await policy_mod.tune_trust_cycle()
        if trust_tune.get("applied"):
            change = trust_tune["applied"]
            print(f"  Trust tuned: trust.delta_scale {change['old']} -> {change['new']} ({change['reason']})")

        # WIRE-3: daily trust crons. Each self-throttles to once per
        # 24h, so calling on every think tick is harmless. Decay
        # appends inactive_decay rows for agents idle > 60d; drift
        # check alarms on agents.trust_score ≠ SUM(delta) replay.
        import trust_cron as trust_cron_mod

        decay_summary = await trust_cron_mod.run_decay_sweep_if_due()
        if decay_summary.get("ran"):
            print(f"  Trust decay sweep: swept={decay_summary['swept']} decay_emitted={decay_summary['decay_emitted']}")
        drift_summary = await trust_cron_mod.run_drift_check_if_due()
        if drift_summary.get("ran") and drift_summary.get("drift_count", 0) > 0:
            print(
                f"  ⚠️  Trust drift detected: {drift_summary['drift_count']} agent(s) "
                f"have agents.trust_score ≠ SUM(delta) replay"
            )

        promo_result = await policy_mod.auto_promote_cycle()
        for promoted in promo_result.get("promoted", []):
            print(
                f"  Auto-promoted: {promoted['nominee']} -> {promoted['target_role']} "
                f"(trust={promoted['trust']:.1f}, endorsements={promoted['endorsements']}, "
                f"tenure={promoted['tenure_days']}d)"
            )
    except Exception as e:
        print(f"Policy/autopromote sweep failed: {e}")

    # Federation self-healing — probe quarantined peers every ~30 min.
    # view federation_probe_due filters for peers whose last probe is
    # older than 30m, so calling every sweep is safe.
    try:
        import federation_policy as fed_mod

        probe_result = await fed_mod.probe_quarantined()
        for recovered in probe_result.get("recovered", []):
            print(f"  Federation probe: {recovered} recovered")
        if probe_result.get("still_down"):
            print(f"  Federation probe: still down: {probe_result['still_down']}")
    except Exception as e:
        print(f"Federation probe failed: {e}")


async def _execute_approved_introduction(approval_row: dict):
    """Dispatch the actual introduction once a leader has approved it.

    Separated so the LLM-driven conversation synthesis only runs on
    human-approved pairs — no wasted inference on rejected proposals.
    """
    payload = approval_row.get("payload") or {}
    member_a = payload.get("member_a", {})
    member_b = payload.get("member_b", {})
    reason = payload.get("reason", "Complementary skills")

    conversation = []
    if _planner_offline("Introduction"):
        return
    try:
        resp_a = llm.chat.completions.create(
            model=DEFAULT_LLM_MODEL,
            messages=[
                {
                    "role": "system",
                    "content": f"You are {member_a.get('name', '?')} from {member_a.get('chapter', '?')}.",
                },
                {
                    "role": "user",
                    "content": f"Introduce yourself to {member_b.get('name', '?')} in one sentence. Context: {reason}",
                },
            ],
            max_tokens=50,
        )
        msg_a = resp_a.choices[0].message.content or ""
        conversation.append({"speaker": member_a.get("agent_id", "?"), "text": msg_a})

        resp_b = llm.chat.completions.create(
            model=DEFAULT_LLM_MODEL,
            messages=[
                {
                    "role": "system",
                    "content": f"You are {member_b.get('name', '?')} from {member_b.get('chapter', '?')}.",
                },
                {
                    "role": "user",
                    "content": f'{member_a.get("name", "?")} said: "{msg_a}"\n\nRespond in one sentence suggesting a collaboration.',
                },
            ],
            max_tokens=50,
        )
        msg_b = resp_b.choices[0].message.content or ""
        conversation.append({"speaker": member_b.get("agent_id", "?"), "text": msg_b})
    except Exception as e:
        print(f"Approved intro conversation failed: {e}")

    a2ui = build_introduction_card(member_a, member_b, reason, conversation)

    pair_key = f"{member_a.get('agent_id', '')}|{member_b.get('agent_id', '')}"
    await remember("intro_pair", pair_key)

    await activity_tracker.track(
        member_a.get("agent_id", ""),
        "introduction_received",
        {"partner": member_b.get("name", "?"), "reason": reason[:100]},
    )
    await activity_tracker.track(
        member_b.get("agent_id", ""),
        "introduction_received",
        {"partner": member_a.get("name", "?"), "reason": reason[:100]},
    )

    targets = [member_a, member_b]
    thought_text = (
        f"Introduced {member_a.get('name', '?')} ({member_a.get('chapter', '?')}) to "
        f"{member_b.get('name', '?')} ({member_b.get('chapter', '?')}): {reason}"
    )
    await log_agent_thought("introduction", thought_text, a2ui, targets)

    conv_summary = " | ".join([f"@{c['speaker']}: {c['text'][:80]}" for c in conversation])
    await log_activity(None, None, f"intro-{uuid.uuid4().hex[:8]}", thought_text, conv_summary, is_cross_chapter=True)
    print(f"  Intro dispatched (leader-approved): {member_a.get('name')} × {member_b.get('name')}")


async def think_insight():
    """Generate an insight about the federation."""
    total_members = len(members)
    total_chapters = len(federation) + 1
    skills_all = []
    for m in members.values():
        skills_all.extend(m.get("skills", []))

    # Sorted, not set-iteration order. The prompt below renders this list, and
    # set iteration over strings depends on PYTHONHASHSEED — so before this the
    # same federation produced a different prompt in every process, which both
    # defeats any watermark and means "identical prompt" counts measured against
    # one process understated the repetition across restarts.
    skills_sorted = sorted(set(skills_all))
    federation_sorted = sorted(federation.keys())

    # This prompt is the one org prompt that grows without limit as a chapter
    # does: 145 tokens on a bare fixture, 1,335 on a realistic 300-skill /
    # 245-member chapter. So the PROMPT takes a bounded sample.
    #
    # ⚠️ SPREAD ACROSS THE SORTED LIST, NOT THE FIRST N OF IT. `skills_sorted` is
    # alphabetical, so a head slice would show a chapter's "a" skills and call it
    # a picture of the chapter. An evenly spaced sample is deterministic — same
    # input, same prompt, which the sort above exists to guarantee — and is
    # actually representative of the range.
    skills_shown, skills_note = _sample_for_prompt(skills_sorted, INSIGHT_SKILL_SAMPLE)

    # The "Do NOT repeat these recent themes" list is gone. It existed to paper
    # over re-asking a question nothing had changed the answer to; the watermark
    # answers that directly, and the 24h floor is what keeps this type novel.
    intel = get_intelligence_context()
    # ⚠️ THE WATERMARK TAKES THE FULL SKILL SET, NOT THE SAMPLE ABOVE. A value
    # truncated, sampled or capped for prompt-size reasons cannot double as the
    # change detector for the thing it was truncated from. Hashing the sample
    # would make this gate blind to any skill outside it: a chapter gains a
    # capability, the sample does not happen to include it, the watermark does
    # not move, and insight stops running on a federation that genuinely
    # changed — visible only as an absence. That is the introduction gate's bug
    # exactly, and a SAMPLE is worse than a head slice for it, because a new
    # entry can land outside a sample at any position rather than only past the
    # end.
    #
    # `skills_sorted` here, `skills_shown` in the prompt. The two are different
    # values on purpose and the sample size travels with the prompt so a reader
    # can tell a sampled list from a complete one.
    wm = llm_elide.watermark(
        total_members=total_members,
        total_chapters=total_chapters,
        federation=federation_sorted,
        skills=skills_sorted,
        skills_total=len(skills_sorted),
        intelligence_context=intel,
    )
    run, why = await llm_elide.should_run("insight", wm, recent_memories=recent_memories)
    if not run:
        print(f"  Insight elided: {why}")
        return

    if _planner_offline("Insight"):
        return
    try:
        response = llm.chat.completions.create(
            model=FAST_MODEL,
            messages=[
                {
                    "role": "system",
                    "content": f"You are an analyst for {AGENT_NAME}, part of the NANDA federation. Be specific and novel — never repeat generic themes.",
                },
                {
                    "role": "user",
                    "content": f"""Analyze this federation:
- {total_chapters} chapters, {total_members} local members
- Federation chapters: {", ".join(federation_sorted)}
- Local skills{skills_note}: {", ".join(skills_shown)}{intel}

Generate ONE brief, NOVEL insight — what's strong, what's missing, or a collaboration opportunity. Title on first line, then 1-2 sentences max.""",
                },
            ],
            max_tokens=100,
        )
        text = response.choices[0].message.content or ""
    except Exception as e:
        print(f"Insight think failed: {e}")
        return

    lines = text.strip().split("\n", 1)
    title = lines[0].strip().strip("#").strip("*").strip()
    body = lines[1].strip() if len(lines) > 1 else text

    data_points = [
        f"{total_chapters} chapters in federation",
        f"{total_members} local members",
        f"Top skills: {', '.join(list(set(skills_all))[:5])}",
    ]

    a2ui = build_insight_card(title, body, data_points)
    await log_agent_thought("insight", f"{title}: {body}", a2ui)
    await remember("insight_title", title[:80])
    await llm_elide.record_run("insight", wm, remember=remember)
    print(f"  Insight: {title}")


async def think_conversation():
    """Two local members discuss a topic relevant to the chapter.

    ⚠️ DELIBERATELY NOT WATERMARK-GATED, for two independent reasons, either of
    which is sufficient. Recorded here so the next person to look at the token
    bill does not add the gate without re-deriving them.

    IT IS NOT A DETERMINISTIC FUNCTION OF STATE. The pair is chosen by
    ``random.sample`` and the seed topic by ``random.choice``, so two runs with
    byte-identical org state produce different prompts by construction. A
    watermark over what the prompt serialises therefore never matches and saves
    nothing; a watermark that excluded the randomness would suppress a cycle
    whose output genuinely would have differed. There is no honest third option.

    ITS OUTPUT IS READ. The claim that these rows have no read path does not
    survive checking. ``log_agent_thought`` writes ``agent_thoughts``, whose own
    docstring calls it the public thoughts feed, and five distinct paths read
    it: ``surfaces.build_activity_surface`` (which its own comment records as
    served to ANONYMOUS callers), the dashboard's Recent Activity section, a
    member profile's recent contributions, a public chapter_agent endpoint, and
    a chapter surface's Recent Thoughts. Three further internal readers —
    ``think_digest``, ``think_reflect`` and ``think_evolve`` — take their input
    from the same table. Eliding this type empties a public feed, which is a
    feature regression rather than a saving.

    The second reason also explains why the gated types buy less than their
    share of the call count suggests: ``think_reflect`` and ``think_evolve``
    read ``agent_thoughts``, so their watermarks move whenever this type
    writes. The durable saving is in the types whose inputs are org state, not
    in the types whose inputs are this one's output.
    """
    if len(members) < 2:
        return

    member_ids = list(members.keys())
    a_id, b_id = random.sample(member_ids, 2)
    a, b = members[a_id], members[b_id]

    # Dedup topics
    recent_topics = await recent_memories("conversation_topic", 10)
    topic_seeds = [
        "a recent industry trend",
        "a technical challenge",
        "a collaboration opportunity",
        "an emerging market",
        "a tool or framework",
        "a case study",
        "a controversial opinion",
        "a prediction for next year",
    ]
    seed = random.choice(topic_seeds)
    dedup_text = ""
    if recent_topics:
        dedup_text = f" Do NOT discuss these recent topics: {', '.join(recent_topics[:5])}"
    if _planner_offline("Conversation"):
        return
    try:
        topic_resp = llm.chat.completions.create(
            model=FAST_MODEL,
            messages=[
                {
                    "role": "system",
                    "content": f"You work at {AGENT_NAME} ({AGENT_FOCUS}). Be creative and specific — never repeat generic topics.",
                },
                {
                    "role": "user",
                    "content": f"Suggest ONE specific discussion topic about {seed} that {a['name']} ({a['description']}) and {b['name']} ({b['description']}) would find interesting. Be specific — name real technologies, companies, or events. Just the topic, one sentence.{dedup_text}",
                },
            ],
            max_tokens=60,
        )
        topic = topic_resp.choices[0].message.content or f"The future of {AGENT_FOCUS}"
    except Exception:
        topic = f"The future of {AGENT_FOCUS}"

    # Have them converse (3 exchanges)
    conversation = []
    if _planner_offline("Conversation"):
        return
    try:
        # A starts
        resp_a1 = llm.chat.completions.create(
            model=FAST_MODEL,
            messages=[
                {"role": "system", "content": build_member_system_prompt(a_id, a)},
                {
                    "role": "user",
                    "content": f"Start a conversation with {b['name']} about: {topic}. One sentence only.",
                },
            ],
            max_tokens=60,
        )
        msg_a1 = resp_a1.choices[0].message.content or ""
        conversation.append({"speaker": a_id, "text": msg_a1})

        # B responds
        resp_b1 = llm.chat.completions.create(
            model=FAST_MODEL,
            messages=[
                {"role": "system", "content": build_member_system_prompt(b_id, b)},
                {"role": "user", "content": f'{a["name"]} said: "{msg_a1}"\n\nRespond in one sentence.'},
            ],
            max_tokens=60,
        )
        msg_b1 = resp_b1.choices[0].message.content or ""
        conversation.append({"speaker": b_id, "text": msg_b1})

        # A follows up
        resp_a2 = llm.chat.completions.create(
            model=FAST_MODEL,
            messages=[
                {"role": "system", "content": build_member_system_prompt(a_id, a)},
                {"role": "user", "content": f'{b["name"]} said: "{msg_b1}"\n\nOne sentence follow-up.'},
            ],
            max_tokens=60,
        )
        msg_a2 = resp_a2.choices[0].message.content or ""
        conversation.append({"speaker": a_id, "text": msg_a2})
    except Exception as e:
        print(f"Conversation think failed: {e}")

    # Build A2UI
    targets = [
        {"agent_id": a_id, "name": a["name"], "chapter": AGENT_NAME},
        {"agent_id": b_id, "name": b["name"], "chapter": AGENT_NAME},
    ]
    thought_text = f"Discussion between @{a_id} and @{b_id}: {topic}"
    a2ui = build_thought_card(
        "conversation",
        f"{a['name']} × {b['name']}: {topic}",
        "\n".join([f"@{c['speaker']}: {c['text']}" for c in conversation]),
        targets,
    )

    # Track conversation activity for both participants
    await activity_tracker.track(a_id, "conversation", {"topic": topic[:100], "partner": b["name"]})
    await activity_tracker.track(b_id, "conversation", {"topic": topic[:100], "partner": a["name"]})

    await log_agent_thought("conversation", thought_text, a2ui, targets)

    # Also log as activity
    conv_summary = " | ".join([f"@{c['speaker']}: {c['text'][:60]}" for c in conversation])
    await log_activity(a_id, a["name"], f"convo-{uuid.uuid4().hex[:8]}", topic, conv_summary)

    await remember("conversation_topic", topic[:80])
    print(f"  Conversation: {a['name']} × {b['name']} on '{topic[:50]}'")


# Profile types that are NOT individuals — organisation listings with no place
# in a community event. This is an EXCLUSION set, and the polarity is the whole
# point.
#
# ⚠️ IT WAS AN INCLUSION ALLOWLIST FIRST, AND THAT WAS A LIVE BUG. The allowlist
# was {"member", "startup_team"}. The CHECK constraint on the column permits
# exactly seven values — founder, developer, investor, mentor, researcher,
# leader, member (infra/init.sql, `agents_profile_type_check`; no migration
# widens it, and there are only two .sql files in the repo). The allowlist and
# the schema overlapped on ONE value. So six of seven legal values — every one
# of them an ordinary individual — read as "not an individual", and think_event
# returned early and proposed nothing for any org whose members are typed
# anything but literally "member". Ordinary data, silent loss of the behaviour.
#
# ⚠️ AND FAIL-CLOSED WAS THE WRONG REFLEX HERE. Refusing on unknown input is
# right for authorization — it is why the listing-consent gate in
# community_member/owner.py refuses everything it cannot positively verify. This
# is not authorization. It decides whether to ask an LLM for a workshop idea. The
# costs are asymmetric and point the other way: closed, real people silently lose
# a feature; open, a business might appear in an event prompt. So this gate FAILS
# OPEN, and the mechanical guard below is what keeps that honest.
#
# ⚠️ AND IT CANNOT FIRE ON DB-SOURCED MEMBERS TODAY. "business" is not a legal
# value of that column, POST /api/members does not transmit profile_type at all
# (a2a_client.register_member's payload has no such field; chapter_agent.py:446
# hardcodes "member"), and "startup_team" is synthesised into an API RESPONSE at
# chapter_agent.py:4319 from a STARTUP- id prefix — it never comes back through
# the column either. The only path that can currently reach this set is a
# hand-authored org config (seed_members passes profile_type through unchecked).
# The wizard's PROFILE_TYPE_BUSINESS lives in agent-LOCAL state and never leaves
# the machine. Stated rather than implied, because a gate that reads like a
# filter while being unreachable is worse than no gate.
#
# server/tests/test_think_event_profile_gate.py derives the legal values from
# infra/init.sql and asserts none of them lands in here — so widening the CHECK
# (or adding a type here) fails loudly instead of quietly deleting think_event
# for a legitimate member type, which is exactly how this went wrong the first
# time.
BUSINESS_PROFILE_TYPES = frozenset({"business"})


def _is_individual(member: dict) -> bool:
    """Whether this member is a person/team rather than an organisation listing.

    Unknown or missing profile_type reads as an individual. Missing already fell
    back to ``member`` — the historical default every other reader of this column
    assumes (``consent_gate``, ``surfaces``, ``agent_export``) — and unknown now
    does too, so a member type nobody thought to enumerate keeps its community
    behaviour instead of silently losing it.
    """
    return (member.get("profile_type") or "member") not in BUSINESS_PROFILE_TYPES


async def think_event():
    """Propose a community event among this org's INDIVIDUAL members.

    Gated on profile_type: an org made only of business listings has no
    community events to propose, and this returns without inventing one. The
    docstring used to claim it worked from "skills and interests" — it only ever
    read ``skills``; ``interests`` appeared in the prose and never in the code.
    """
    # An org of businesses is a service directory, not a community. Nothing to
    # propose, and proposing anyway is how a service catalogue becomes a meetup.
    if not any(_is_individual(m) for m in members.values()):
        return

    # Check if we have too many pending events already
    existing = await pg_request(
        "GET",
        "agent_events",
        params={
            "chapter_agent_id": f"eq.{AGENT_ID}",
            "status": "eq.proposed",
            "select": "id",
        },
    )
    if existing and len(existing) >= 5:
        return  # Don't spam events

    # Gather context from INDIVIDUAL members only — a business's offerings are
    # not a signal about what event a community would want.
    member_skills = set()
    member_names = []
    for mid, m in members.items():
        if not _is_individual(m):
            continue
        for s in m.get("skills", []):
            member_skills.add(s)
        if not mid.startswith("STARTUP-"):
            member_names.append(m["name"])

    # Dedup events
    recent_events = await recent_memories("event_title", 10)
    dedup_text = ""
    if recent_events:
        dedup_text = "\n\nDo NOT propose events similar to these (already proposed):\n" + "\n".join(
            f"- {e}" for e in recent_events
        )

    if _planner_offline("Event"):
        return
    try:
        response = llm.chat.completions.create(
            model=DEFAULT_LLM_MODEL,
            messages=[
                {
                    "role": "system",
                    "content": f"You are the community manager for {AGENT_NAME} ({AGENT_FOCUS}). Propose ONE specific, actionable, NOVEL community event. Respond ONLY with valid JSON.",
                },
                {
                    "role": "user",
                    "content": f"""Propose an event for our chapter. We have {sum(1 for m in members.values() if _is_individual(m))} members with skills: {", ".join(list(member_skills)[:15])}.

Some members: {", ".join(member_names[:8])}{get_intelligence_context()}{dedup_text}

Event types: workshop, meetup, hackathon, talk, panel, social, demo_day

JSON format:
{{"title": "specific event name", "description": "2-3 sentences about the event", "event_type": "workshop|meetup|hackathon|talk|panel|social|demo_day", "reason": "why this event would benefit members", "suggested_speakers": ["member name 1", "member name 2"]}}""",
                },
            ],
            max_tokens=200,
        )
        text = response.choices[0].message.content or ""
        json_match = re.search(r"\{.*\}", text, re.DOTALL)
        if not json_match:
            return
        event_data = json.loads(json_match.group(0))
    except Exception as e:
        print(f"Event think failed: {e}")
        return

    # Build A2UI
    title = event_data.get("title", "Community Event")
    a2ui = build_thought_card("observation", f"Event Proposal: {title}", event_data.get("description", ""))

    # Store event
    await pg_request(
        "POST",
        "agent_events",
        body={
            "chapter_agent_id": AGENT_ID,
            "title": title,
            "description": event_data.get("description", ""),
            "event_type": event_data.get("event_type", "workshop"),
            "proposed_by_agent": AGENT_ID,
            "proposed_reason": event_data.get("reason", ""),
            "suggested_speakers": event_data.get("suggested_speakers", []),
            "status": "proposed",
            "a2ui_surface": a2ui,
        },
    )

    # Track event proposal activity for suggested speakers
    for speaker in event_data.get("suggested_speakers", [])[:5]:
        await activity_tracker.track(speaker, "event_proposed", {"event": title[:100]})

    await log_agent_thought("observation", f"Proposed event: {title} — {event_data.get('reason', '')}", a2ui)
    await remember("event_title", title[:80])
    print(f"  Event proposed: {title}")


async def _maybe_publish_weekly_to_bus():
    """Publish chapter.digest.weekly to the event bus IF it's been ≥7 days
    since the last one for this chapter.

    This is intentionally INDEPENDENT of the legacy 24h gate on
    agent_digests — the legacy table tracks chapter-side digest content
    cadence; the event_log tracks subscriber broadcast cadence. Those
    cadences don't have to match. (PR originally nested this under
    the legacy gate; PR-fix decouples them.)

    Best-effort: any error here is swallowed so the digest cycle never
    gets wedged by a transient bus failure.
    """
    try:
        import digest as digest_mod

        last_pub = await pg_request(
            "GET",
            "event_log",
            params={
                "event_type": "eq.chapter.digest.weekly",
                "publisher_agent_id": f"eq.{AGENT_ID}",
                "order": "created_at.desc",
                "limit": "1",
                "select": "id,created_at",
            },
        )
        if last_pub:
            last_iso = last_pub[0]["created_at"].replace("Z", "+00:00")
            last_dt = datetime.fromisoformat(last_iso)
            if datetime.now(UTC) - last_dt < timedelta(days=7):
                return  # inside 7d window
        event_id = await digest_mod.publish_digest(window_days=7)
        if event_id is not None:
            print(f"  chapter.digest.weekly published (event_id={event_id})")
        else:
            print("  chapter.digest.weekly publish returned no id")
    except Exception as e:
        print(f"  chapter.digest.weekly publish failed: {e}")


async def think_digest():
    """Generate a weekly chapter digest summarizing activity."""
    # Event-bus broadcast is INDEPENDENT of the legacy 24h gate on
    # agent_digests below — see _maybe_publish_weekly_to_bus docstring.
    # It runs first so a freshly-deployed server starts emitting on the
    # bus immediately, without waiting for the 24h legacy window to expire.
    await _maybe_publish_weekly_to_bus()

    # Only generate the legacy agent_digests row if it's been > 24h.
    last_digest = await pg_request(
        "GET",
        "agent_digests",
        params={
            "chapter_agent_id": f"eq.{AGENT_ID}",
            "order": "created_at.desc",
            "limit": "1",
        },
    )
    if last_digest:
        last_time = datetime.fromisoformat(last_digest[0]["created_at"].replace("Z", "+00:00"))
        if datetime.now(UTC) - last_time < timedelta(hours=24):
            return  # Too soon

    # Gather stats
    thoughts = await pg_request(
        "GET",
        "agent_thoughts",
        params={
            "chapter_agent_id": f"eq.{AGENT_ID}",
            "order": "created_at.desc",
            "limit": "20",
            "select": "thought_type,thought_text,created_at",
        },
    )
    thought_types = {}
    for t in thoughts or []:
        tt = t.get("thought_type", "?")
        thought_types[tt] = thought_types.get(tt, 0) + 1

    highlights = []
    if thought_types:
        highlights.append(
            f"{sum(thought_types.values())} agent activities: {', '.join(f'{v} {k}s' for k, v in thought_types.items())}"
        )
    highlights.append(f"{len(members)} members active")
    highlights.append(f"{len(federation)} federated chapters")

    # Generate summary via Grok
    if _planner_offline("Digest"):
        return
    try:
        response = llm.chat.completions.create(
            model=DEFAULT_LLM_MODEL,
            messages=[
                {
                    "role": "system",
                    "content": f"Write a brief, engaging weekly digest for {AGENT_NAME}. 3-4 sentences summarizing community highlights. Be specific.",
                },
                {
                    "role": "user",
                    "content": f"Chapter: {AGENT_NAME}\nFocus: {AGENT_FOCUS}\nHighlights:\n"
                    + "\n".join(f"- {h}" for h in highlights),
                },
            ],
            max_tokens=150,
        )
        summary = response.choices[0].message.content or "Active week for the chapter."
    except Exception:
        summary = "Active week for the chapter."

    a2ui = build_thought_card("insight", f"Weekly Digest — {AGENT_NAME}", summary)

    await pg_request(
        "POST",
        "agent_digests",
        body={
            "chapter_agent_id": AGENT_ID,
            "title": f"Weekly Digest — {AGENT_NAME}",
            "period_start": (datetime.now(UTC) - timedelta(days=7)).isoformat(),
            "period_end": datetime.now(UTC).isoformat(),
            "content_json": {"summary": summary, "highlights": highlights, "thought_types": thought_types},
            "highlights": highlights,
            "a2ui_surface": a2ui,
        },
    )

    await log_agent_thought("insight", f"Weekly Digest: {summary[:100]}", a2ui)
    print("  Digest published")


async def think_reflect():
    """Reflect on recent activity and build long-term knowledge model."""
    # Only reflect if enough activity has accumulated
    recent_thoughts = await pg_request(
        "GET",
        "agent_thoughts",
        params={
            "chapter_agent_id": f"eq.{AGENT_ID}",
            "order": "created_at.desc",
            "limit": "30",
            "select": "thought_type,thought_text",
        },
    )
    recent_activity = await pg_request(
        "GET",
        "agent_activity",
        params={
            "chapter_agent_id": f"eq.{AGENT_ID}",
            "order": "created_at.desc",
            "limit": "30",
            "select": "member_name,user_message_snippet,is_cross_chapter",
        },
    )

    if not recent_thoughts or len(recent_thoughts) < 5:
        return  # Not enough data to reflect on

    # Build skill graph
    skill_graph: dict[str, int] = {}
    for mid, m in members.items():
        if mid.startswith("STARTUP-"):
            continue
        for skill in m.get("skills", []):
            skill_graph[skill.lower()] = skill_graph.get(skill.lower(), 0) + 1

    # Engagement model
    type_counts: dict[str, int] = {}
    for t in recent_thoughts or []:
        tt = t.get("thought_type", "?")
        type_counts[tt] = type_counts.get(tt, 0) + 1

    # Active members
    active_members = set()
    for a in recent_activity or []:
        name = a.get("member_name")
        if name:
            active_members.add(name)

    # Get outcome feedback for the reflection
    outcome_context = await outcome_tracker_mod.get_outcome_context_for_reflection()

    if _planner_offline("Reflect"):
        return
    try:
        response = llm.chat.completions.create(
            model=DEFAULT_LLM_MODEL,
            messages=[
                {
                    "role": "system",
                    "content": f"You are {AGENT_NAME}'s reflection engine. Analyze recent activity and produce structured observations about the chapter. Respond ONLY with valid JSON.",
                },
                {
                    "role": "user",
                    "content": f"""Analyze our chapter's recent activity and produce intelligence:

Members: {len(members)} total, {len(active_members)} active recently
Skill distribution: {json.dumps(dict(sorted(skill_graph.items(), key=lambda x: -x[1])[:15]))}
Activity breakdown: {json.dumps(type_counts)}
Federation: {len(federation)} chapters connected
Cross-chapter activity: {sum(1 for a in (recent_activity or []) if a.get("is_cross_chapter"))} cross-chapter interactions
{outcome_context}

Recent thought samples:
{chr(10).join(f"- [{t['thought_type']}] {t['thought_text'][:80]}" for t in (recent_thoughts or [])[:10])}

Produce JSON with:
{{"patterns": ["2-3 observed patterns about how the chapter operates"],
  "skill_gaps": ["2-3 skills the chapter needs but doesn't have"],
  "trending_topics": ["3-4 topics members are discussing most"],
  "recommendations": ["2-3 specific actions to improve the chapter, informed by feedback data"],
  "member_insights": ["2-3 observations about member behavior"]}}""",
                },
            ],
            max_tokens=400,
        )
        text = response.choices[0].message.content or ""
        json_match = re.search(r"\{.*\}", text, re.DOTALL)
        if not json_match:
            return
        knowledge = json.loads(json_match.group(0))
    except Exception as e:
        print(f"Reflect failed: {e}")
        return

    # Store/update knowledge model
    knowledge_data = {
        "patterns": knowledge.get("patterns", []),
        "skill_gaps": knowledge.get("skill_gaps", []),
        "trending_topics": knowledge.get("trending_topics", []),
        "recommendations": knowledge.get("recommendations", []),
        "member_insights": knowledge.get("member_insights", []),
        "skill_graph": dict(sorted(skill_graph.items(), key=lambda x: -x[1])[:20]),
        "type_counts": type_counts,
        "active_members": list(active_members),
        "member_count": len(members),
        "last_reflected": datetime.now(UTC).isoformat(),
    }

    # Upsert — try PATCH first, POST if not exists
    existing = await pg_request(
        "GET",
        "agent_knowledge",
        params={
            "chapter_agent_id": f"eq.{AGENT_ID}",
            "knowledge_type": "eq.chapter_intelligence",
            "limit": "1",
        },
    )
    if existing:
        await pg_request(
            "PATCH",
            "agent_knowledge", params={"chapter_agent_id": f"eq.{AGENT_ID}", "knowledge_type": "eq.chapter_intelligence"},
            body={
                "knowledge_data": knowledge_data,
                "confidence": 0.7,
                "updated_at": datetime.now(UTC).isoformat(),
            },
        )
    else:
        await pg_request(
            "POST",
            "agent_knowledge",
            body={
                "chapter_agent_id": AGENT_ID,
                "knowledge_type": "chapter_intelligence",
                "knowledge_data": knowledge_data,
                "confidence": 0.7,
            },
        )

    # Update in-memory cache
    _knowledge_cache["chapter_intelligence"] = knowledge_data

    # sm-federation §4: the reflection just changed what this community knows, so
    # publish it to the signed feed peers subscribe to. Content-deduped, so a
    # cycle that produced nothing new appends nothing — an append-only log that
    # grows without new information makes a subscriber re-verify a chain of
    # duplicates to learn nothing.
    # publish_if_changed never raises into its caller — the guarantee lives in the
    # function rather than in a try/except at each call site, because one of the
    # two sites had one and the other did not, and the one that did not took a
    # boot down.
    import federation_feed
    import federation_intelligence
    import sovereign_identity

    await federation_feed.publish_if_changed(
        pg_request,
        sovereign_identity._ed25519_keypairs.get(AGENT_ID),
        federation_intelligence.get_our_summary(),
        generated_at=datetime.now(UTC).isoformat(),
    )

    # Log reflection as thought
    summary = f"Patterns: {', '.join(knowledge.get('patterns', [])[:2])}. Gaps: {', '.join(knowledge.get('skill_gaps', [])[:2])}"
    a2ui = build_insight_card(
        "Chapter Reflection",
        summary,
        [
            f"{len(members)} members, {len(active_members)} active",
            f"Top skills: {', '.join(list(skill_graph.keys())[:5])}",
            f"Recommendations: {', '.join(knowledge.get('recommendations', [])[:2])}",
        ],
    )
    await log_agent_thought("insight", f"Reflected: {summary[:120]}", a2ui)
    print(
        f"  Reflection complete — {len(knowledge.get('patterns', []))} patterns, {len(knowledge.get('recommendations', []))} recommendations"
    )


async def think_evolve():
    """Activity-weighted evolution — active members evolve faster with context-relevant skills."""
    if not members:
        return

    # Pick member weighted by activity (active members more likely)
    member_id = activity_tracker.pick_weighted_member(members)
    if not member_id:
        return
    member = members[member_id]
    old_skills = list(member.get("skills", []))
    activity_score = activity_tracker.get_activity_score(member_id)

    # Get this member's personal activity history (not general server activity)
    member_activity = await activity_tracker.get_member_activity_summary(member_id)

    # Also get recent server thoughts for broader context
    recent_thoughts = await pg_request(
        "GET",
        "agent_thoughts",
        params={
            "chapter_agent_id": f"eq.{AGENT_ID}",
            "order": "created_at.desc",
            "limit": "5",
            "select": "thought_type,thought_text",
        },
    )
    thought_summary = "\n".join([f"- [{t['thought_type']}] {t['thought_text'][:80]}" for t in (recent_thoughts or [])])

    if _planner_offline("Evolve"):
        return
    try:
        response = llm.chat.completions.create(
            model=FAST_MODEL,
            messages=[
                {
                    "role": "system",
                    "content": "You help AI agents evolve based on their actual behavior and interactions.",
                },
                {
                    "role": "user",
                    "content": f"""Agent @{member_id} ({member["name"]}) has these skills: {", ".join(old_skills)}
Current personality: {member.get("personality", "")[:100]}
Activity score: {activity_score:.1f} (higher = more active)

{member_id}'s recent personal activity:
{member_activity}

Chapter context:
{thought_summary}

Based on @{member_id}'s PERSONAL activity (not generic chapter activity), suggest ONE evolution:
- A new skill that reflects what they've actually been doing (one word)
- A personality trait that matches their behavior (one sentence)

If they have no activity, suggest a foundational skill based on their existing profile.

Respond in JSON: {{"new_skill": "...", "personality_addition": "..."}}""",
                },
            ],
            max_tokens=80,
        )
        text = response.choices[0].message.content or ""
        json_match = re.search(r"\{.*\}", text, re.DOTALL)
        if not json_match:
            return
        evolution = json.loads(json_match.group(0))
    except Exception as e:
        print(f"Evolution failed: {e}")
        return

    new_skill = evolution.get("new_skill", "")
    personality_addition = evolution.get("personality_addition", "")

    # Apply evolution
    if new_skill and new_skill not in member.get("skills", []):
        member.setdefault("skills", []).append(new_skill)

    if personality_addition:
        current = member.get("personality", "")
        member["personality"] = f"{current} {personality_addition}".strip()

    # Persist evolution to Postgres
    await pg_request(
        "PATCH",
        "agents", params={"agent_id": f"eq.{member_id}"},
        body={
            "skills": member.get("skills", []),
            "config": {
                "personality": member.get("personality", ""),
                "voice": member.get("voice", "helpful"),
                "virtual": True,
                "parent_chapter": AGENT_ID,
            },
        },
    )

    # Log evolution with trigger context
    trigger = f"activity_score={activity_score:.1f}, recent={member_activity[:80]}"
    await activity_tracker.log_evolution(member_id, old_skills, new_skill, personality_addition, trigger)

    # Log it as thought
    evolution_text = f"@{member_id} evolved: +skill '{new_skill}', personality: '{personality_addition}'"
    a2ui = build_thought_card(
        "evolution",
        f"@{member_id} Evolved",
        evolution_text,
        [{"agent_id": member_id, "name": member["name"], "chapter": AGENT_NAME}],
    )
    await log_agent_thought("observation", evolution_text, a2ui)

    print(f"  Evolution: @{member_id} +{new_skill}")


# ── chapter_broadcast cycle (PR4) ──────────────────────────────────


async def think_chapter_broadcast():
    """Auto-fanout the most recent chapter.digest.weekly to peers.

    Off by default — chapters opt in via the policy key
    ``chapter_broadcast.enabled``. When enabled the cycle:

      1. Honours ``chapter_broadcast.min_interval_hours`` (default 12h)
         to avoid flooding peers when a backlog of unbroadcast digests
         exists at enable-time.
      2. Finds the latest ``chapter.digest.weekly`` event from this
         chapter's own event_log that has NOT already been broadcast.
         (Dedup is driven by broadcast_log on the digest's title
         field — the digest's headline becomes the broadcast title,
         so an already-fanned-out digest is a duplicate by title.)
      3. Calls broadcast.send_broadcast() with audience='all'.

    Why use event_log + broadcast_log instead of a "broadcast_pending"
    table: every digest already lives in event_log; every broadcast
    already lives in broadcast_log. A separate queue table would be
    a fourth piece of state to keep consistent. The two existing
    tables tell us "what could be broadcast" and "what already was",
    and the cycle bridges them.
    """
    import policy as policy_mod

    enabled = await policy_mod.get_bool("chapter_broadcast.enabled", default=False)
    if not enabled:
        return

    import broadcast as broadcast_mod

    if not broadcast_mod.is_initialized():
        return  # Not yet wired (chapter still booting); next tick will try.

    min_interval = await policy_mod.get_int("chapter_broadcast.min_interval_hours", default=12)
    min_interval = max(1, min(int(min_interval), 168))  # 1h–1 week

    hours_since = await broadcast_mod.hours_since_last_broadcast()
    if hours_since is not None and hours_since < float(min_interval):
        # Rate-limit the cycle — too soon since last broadcast.
        return

    # Look for the most recent digest event from this server that we
    # haven't already broadcast. The dedup key is the digest's headline
    # (which becomes the broadcast title) — see _digest_already_broadcast.
    digest_event = await _find_undispatched_digest()
    if not digest_event:
        return

    payload = digest_event.get("payload") or {}
    headline = (payload.get("headline") or "Weekly chapter digest").strip()[:200]
    summary = (payload.get("summary_markdown") or "").strip()[:8000]
    if not summary:
        # Fall back to a deterministic body if the LLM-composed summary
        # is missing. Better to broadcast a minimal digest than skip
        # entirely — the recipient can still see counts via the event.
        summary = (
            f"Week of {payload.get('window_start', '?')} — "
            f"{payload.get('new_member_count', 0)} new members, "
            f"{payload.get('intent_published_count', 0)} intents."
        )

    result = await broadcast_mod.send_broadcast(
        sender_agent_id=AGENT_ID,
        title=headline,
        body=summary,
        tags=["digest", "weekly", "auto-broadcast"],
        audience="all",
    )
    print(f"  chapter_broadcast: sent {result.get('broadcast_id')!r} -> {result.get('federation')}")


async def _find_undispatched_digest() -> dict | None:
    """Return the most recent chapter.digest.weekly event from THIS
    chapter's event_log that hasn't been broadcast yet, or None.

    Dedup driven by broadcast_log on title match. The digest's
    headline is the broadcast title (see think_chapter_broadcast),
    so a duplicate title within the last 30 days means we've already
    fanned it out.
    """
    rows = await _pg()(
        "GET",
        "event_log",
        params={
            "event_type": "eq.chapter.digest.weekly",
            "publisher_agent_id": f"eq.{AGENT_ID}",
            "order": "id.desc",
            "limit": "1",
            "select": "id,payload",
        },
    )
    if not rows:
        return None
    candidate = rows[0]
    headline = ((candidate.get("payload") or {}).get("headline") or "Weekly chapter digest").strip()[:200]

    # Has this headline already been broadcast?
    existing = await _pg()(
        "GET",
        "broadcast_log",
        params={
            "chapter_id": f"eq.{AGENT_ID}",
            "title": f"eq.{headline}",
            "limit": "1",
        },
    )
    if existing:
        return None
    return candidate
