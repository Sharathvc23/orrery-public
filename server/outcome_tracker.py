"""
Outcome Tracker — closed feedback loop for agent actions.

Records feedback signals on agent actions (intros, events, polls, startups)
and computes quality scores. The reflection cycle uses outcomes to improve
future action generation.

Feedback flows:
1. Agent generates action (intro, event, poll) → logged with action_id
2. Member gives feedback (positive/negative via A2UI button) → stored as outcome
3. Quality score computed per action type
4. Reflection cycle reads outcomes → adjusts recommendations
5. High-quality patterns amplified, low-quality deprioritized
"""

from collections.abc import Awaitable, Callable

_pg_request: Callable[..., Awaitable] | None = None

def _pg() -> Callable[..., Awaitable]:
    """The injected pg_request, or a LOUD failure if init() never ran — the
    old unguarded calls crashed with a bare 'NoneType' object is not callable
    (R2 whole-app sweep)."""
    if _pg_request is None:
        raise RuntimeError("outcome_tracker.init() was never called — no pg_request injected")
    return _pg_request

_agent_id = ""

# Cached quality scores per action type
_quality_cache: dict[str, dict] = {}


def init(pg_request, agent_id):
    global _pg_request, _agent_id
    _pg_request = pg_request
    _agent_id = agent_id


async def record_feedback(
    action_id: str, action_type: str, signal: str, agent_id: str = "", feedback_data: dict | None = None
):
    """Record a feedback signal on an agent action."""
    quality = {"positive": 1.0, "negative": -1.0, "rsvp": 0.5, "skip": -0.2}.get(signal, 0)

    await _pg()(
        "POST",
        "agent_action_outcomes",
        body={
            "chapter_agent_id": _agent_id,
            "action_id": action_id,
            "action_type": action_type,
            "agent_id": agent_id or None,
            "signal": signal,
            "quality_score": quality,
            "feedback_data": feedback_data or {},
        },
    )

    # Invalidate cache
    _quality_cache.pop(action_type, None)

    # ARP — when a member rates an agent's action (positive / negative
    # / rsvp / skip), that rating is itself a decision the member made
    # on their own behalf. Emit a receipt so the rating shows up on
    # the member's /page/today timeline. Fire-and-forget; telemetry
    # must not break the feedback loop itself.
    if agent_id:
        try:
            import asyncio as _asyncio

            import arp as arp_mod

            principal_did = arp_mod.did_key_for_member(agent_id)
            if principal_did:
                pretty_type = action_type.replace("_", " ")
                pretty_signal = signal.replace("_", " ")
                _asyncio.create_task(
                    arp_mod.emit_chapter_action(
                        principal_did=principal_did,
                        category="decision_made",
                        human_summary=f"You rated a {pretty_type} as {pretty_signal}.",
                        machine_payload={
                            "action_type_label": "outcome_feedback",
                            "action_id": action_id,
                            "rated_action_type": action_type,
                            "signal": signal,
                            "quality_score": quality,
                        },
                    )
                )
        except Exception:  # noqa: BLE001
            pass


async def get_quality_scores() -> dict[str, dict]:
    """Get quality statistics per action type.

    Returns: { action_type: { positive: N, negative: N, avg_quality: float, total: N } }
    """
    if _quality_cache:
        return _quality_cache

    data = await _pg()(
        "GET",
        "agent_action_outcomes",
        params={
            "chapter_agent_id": f"eq.{_agent_id}",
            "select": "action_type,signal,quality_score",
        },
    )
    if not data:
        return {}

    scores: dict[str, dict] = {}
    for row in data:
        atype = row.get("action_type", "unknown")
        if atype not in scores:
            scores[atype] = {"positive": 0, "negative": 0, "total": 0, "quality_sum": 0}
        scores[atype]["total"] += 1
        scores[atype]["quality_sum"] += row.get("quality_score", 0)
        if row.get("signal") == "positive":
            scores[atype]["positive"] += 1
        elif row.get("signal") == "negative":
            scores[atype]["negative"] += 1

    for atype, s in scores.items():
        s["avg_quality"] = round(s["quality_sum"] / max(s["total"], 1), 2)
        s["success_rate"] = round(s["positive"] / max(s["total"], 1) * 100)
        del s["quality_sum"]

    _quality_cache.update(scores)
    return scores


async def get_outcome_context_for_reflection() -> str:
    """Build a text summary of outcomes for the reflection LLM prompt.

    This is how outcomes feed back into the intelligence model.
    """
    scores = await get_quality_scores()
    if not scores:
        return ""

    lines = ["\nAction Outcome Feedback:"]
    for atype, s in scores.items():
        lines.append(
            f"- {atype}: {s['total']} feedback signals, "
            f"{s['positive']} positive, {s['negative']} negative, "
            f"success rate {s['success_rate']}%, avg quality {s['avg_quality']}"
        )

    # Get recent specific feedback for detail
    recent = await _pg()(
        "GET",
        "agent_action_outcomes",
        params={
            "chapter_agent_id": f"eq.{_agent_id}",
            "order": "created_at.desc",
            "limit": "5",
            "select": "action_type,signal,feedback_data",
        },
    )
    if recent:
        lines.append("Recent feedback:")
        for r in recent:
            detail = r.get("feedback_data", {}).get("detail", "")
            lines.append(f"  - {r.get('action_type', '?')}: {r.get('signal', '?')}{' — ' + detail if detail else ''}")

    return "\n".join(lines)


async def get_action_quality(action_type: str) -> float:
    """Get average quality for a specific action type. Used to weight future actions."""
    scores = await get_quality_scores()
    type_scores = scores.get(action_type, {})
    return type_scores.get("avg_quality", 0)
