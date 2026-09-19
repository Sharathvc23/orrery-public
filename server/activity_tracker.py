"""
Activity Tracker — per-member interaction tracking + reputation system.

Records every meaningful member interaction and increments reputation
counters. Feeds into weighted evolution (active members evolve faster
with context-relevant skills).

Activity types:
- introduction_received: member was introduced to someone
- introduction_given: member introduced others (chapter agent acting)
- conversation: member participated in a conversation
- poll_vote: member voted in a poll
- event_rsvp: member RSVPed to an event
- event_proposed: member proposed an event
- startup_collaboration: member joined a startup team
- member_thought: member's agent generated a thought (Phase 1 runtime)
"""

import asyncio
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta

# Injected by chapter_agent.py
_pg_request: Callable[..., Awaitable] | None = None

def _pg() -> Callable[..., Awaitable]:
    """The injected pg_request, or a LOUD failure if init() never ran — the
    old unguarded calls crashed with a bare 'NoneType' object is not callable
    (R2 whole-app sweep)."""
    if _pg_request is None:
        raise RuntimeError("activity_tracker.init() was never called — no pg_request injected")
    return _pg_request

_agent_id = ""

# In-memory activity counts for weighted evolution (reset on restart, rebuilt from DB)
_activity_scores: dict[str, float] = {}  # agent_id → activity score


def init(pg_request, agent_id):
    global _pg_request, _agent_id
    _pg_request = pg_request
    _agent_id = agent_id


async def track(agent_id: str, activity_type: str, activity_data: dict | None = None):
    """Record an activity and increment reputation."""
    # Persist activity
    asyncio.create_task(_persist_activity(agent_id, activity_type, activity_data or {}))

    # Update in-memory score
    _activity_scores[agent_id] = _activity_scores.get(agent_id, 0) + _score_for(activity_type)

    # Increment reputation counter
    asyncio.create_task(_increment_reputation(agent_id, activity_type))


def _score_for(activity_type: str) -> float:
    """Weight different activity types for evolution selection."""
    return {
        "introduction_received": 2.0,
        "conversation": 1.5,
        "poll_vote": 1.0,
        "event_rsvp": 1.5,
        "event_proposed": 3.0,
        "startup_collaboration": 3.0,
        "member_thought": 0.5,
        "introduction_given": 1.0,
        "intent_submitted": 2.0,
        "intent_matched": 3.0,
        "intent_accepted": 2.5,
        "intent_introduced": 4.0,
        "agent_conversation": 3.0,
    }.get(activity_type, 1.0)


def _reputation_field(activity_type: str) -> str | None:
    """Map activity type to reputation counter field."""
    return {
        "introduction_received": "introductions",
        "introduction_given": "introductions",
        "conversation": "contributions",
        "poll_vote": "votes",
        "event_rsvp": "events",
        "event_proposed": "events",
        "startup_collaboration": "sprints",
        "member_thought": "contributions",
        "intent_submitted": "contributions",
        "intent_matched": "introductions",
        "intent_accepted": "introductions",
        "intent_introduced": "introductions",
        "agent_conversation": "contributions",
    }.get(activity_type)


async def _persist_activity(agent_id: str, activity_type: str, data: dict):
    """Save activity to Postgres."""
    await _pg()(
        "POST",
        "agent_member_activity",
        body={
            "chapter_agent_id": _agent_id,
            "agent_id": agent_id,
            "activity_type": activity_type,
            "activity_data": data,
        },
    )


async def _increment_reputation(agent_id: str, activity_type: str):
    """Increment the appropriate reputation counter on the agents table."""
    field = _reputation_field(activity_type)
    if not field:
        return

    # Fetch current reputation
    data = await _pg()(
        "GET",
        "agents",
        params={
            "agent_id": f"eq.{agent_id}",
            "select": "reputation",
        },
    )
    if not data:
        return

    rep = data[0].get("reputation") or {"introductions": 0, "sprints": 0, "votes": 0, "events": 0, "contributions": 0}
    rep[field] = rep.get(field, 0) + 1

    await _pg()(
        "PATCH",
        "agents", params={"agent_id": f"eq.{agent_id}"},
        body={
            "reputation": rep,
        },
    )


def get_activity_score(agent_id: str) -> float:
    """Get cumulative activity score for a member."""
    return _activity_scores.get(agent_id, 0)


def get_weighted_members(members: dict) -> list[tuple[str, float]]:
    """Return members sorted by activity score (highest first).

    Every member gets a baseline score of 1.0 so inactive members
    still have a chance of being selected, just lower probability.
    """
    weighted = []
    for mid in members:
        score = max(1.0, _activity_scores.get(mid, 0))
        weighted.append((mid, score))
    weighted.sort(key=lambda x: -x[1])
    return weighted


def pick_weighted_member(members: dict) -> str | None:
    """Select a member weighted by activity score."""
    import random

    if not members:
        return None

    weighted = get_weighted_members(members)
    total = sum(s for _, s in weighted)
    r = random.uniform(0, total)
    cumulative = 0.0
    for mid, score in weighted:
        cumulative += score
        if r <= cumulative:
            return mid
    return weighted[-1][0]  # Fallback


async def get_member_activity(agent_id: str, limit: int = 20) -> list[dict]:
    """Fetch recent activity for a specific member."""
    data = await _pg()(
        "GET",
        "agent_member_activity",
        params={
            "agent_id": f"eq.{agent_id}",
            "order": "created_at.desc",
            "limit": str(limit),
            "select": "activity_type,activity_data,created_at",
        },
    )
    return data or []


async def get_member_activity_summary(agent_id: str) -> str:
    """Build a text summary of a member's recent activity for evolution prompts."""
    activities = await get_member_activity(agent_id, limit=10)
    if not activities:
        return "No recent activity recorded."

    lines = []
    for a in activities:
        atype = a.get("activity_type", "unknown").replace("_", " ")
        adata = a.get("activity_data", {})
        detail = adata.get("summary", adata.get("topic", adata.get("partner", "")))
        lines.append(f"- {atype}{': ' + str(detail) if detail else ''}")

    return "\n".join(lines)


async def load_scores():
    """Load activity scores from Postgres on startup (last 7 days)."""
    cutoff = (datetime.now(UTC) - timedelta(days=7)).isoformat()
    data = await _pg_request(
        "GET",
        "agent_member_activity",
        params={
            "chapter_agent_id": f"eq.{_agent_id}",
            "created_at": f"gt.{cutoff}",
            "select": "agent_id,activity_type",
        },
    )
    if not data:
        return

    for row in data:
        aid = row.get("agent_id", "")
        atype = row.get("activity_type", "")
        if aid:
            _activity_scores[aid] = _activity_scores.get(aid, 0) + _score_for(atype)

    active = sum(1 for s in _activity_scores.values() if s > 0)
    print(f"[ActivityTracker] Loaded scores for {active} members from last 7 days")


async def get_chapter_activity_summary(days: int = 7) -> dict:
    """Aggregate activity across the chapter for the last N days.

    Returns: {total_activities, active_members, by_type: {type: count}, top_members: [(id, count)]}
    """
    cutoff = (datetime.now(UTC) - timedelta(days=days)).isoformat()
    data = await _pg()(
        "GET",
        "agent_member_activity",
        params={
            "chapter_agent_id": f"eq.{_agent_id}",
            "created_at": f"gt.{cutoff}",
            "select": "agent_id,activity_type",
        },
    )
    if not data:
        return {"total_activities": 0, "active_members": 0, "by_type": {}, "top_members": []}

    by_type: dict[str, int] = {}
    by_member: dict[str, int] = {}
    for row in data:
        atype = row.get("activity_type", "unknown")
        aid = row.get("agent_id", "")
        by_type[atype] = by_type.get(atype, 0) + 1
        if aid:
            by_member[aid] = by_member.get(aid, 0) + 1

    top_members = sorted(by_member.items(), key=lambda x: -x[1])[:10]
    return {
        "total_activities": len(data),
        "active_members": len(by_member),
        "by_type": by_type,
        "top_members": top_members,
    }


async def log_evolution(
    agent_id: str, old_skills: list[str], new_skill: str, personality_addition: str, trigger_activity: str
):
    """Log an evolution event to the evolution log table."""
    await _pg()(
        "POST",
        "agent_evolution_log",
        body={
            "chapter_agent_id": _agent_id,
            "agent_id": agent_id,
            "old_skills": old_skills,
            "new_skill": new_skill,
            "personality_addition": personality_addition,
            "trigger_activity": trigger_activity,
            "activity_score": _activity_scores.get(agent_id, 0),
        },
    )
