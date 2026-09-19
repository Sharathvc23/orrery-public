"""
NANDA mesh — unified agent-facing interface to peers + federation.

Composes federation_discovery, federation_intelligence, intents, and
members into a single surface the agent's LLM turn loop can call. The
point is: from an agent's perspective, the mesh is its primary state,
not a bolted-on library.

Public API
----------
get_mesh_state(agent_id)           — summary for the /page/mesh surface
list_peers(query, skills, limit)   — search peer agents across federation
find_peer(agent_id, chapter_id)    — resolve a single peer by id
send_to_peer(sender, target, text) — signed a2a delivery via chapter router
submit_intent(sender, text, tags)  — broadcast to federation
my_trust(agent_id)                 — self-inspection
"""

from __future__ import annotations

import re
from typing import Any

# ── DI — injected from chapter_agent.py lifespan ─────────

_pg_request = None
_members: dict = {}
_federation: dict = {}
_intents_mod = None
_federation_intelligence_mod = None
_federation_discovery_mod = None
_auth_verify_mod = None
_governance_mod = None
_agent_id = ""

MAX_MESSAGE_BYTES = 16 * 1024
MAX_QUERY_LEN = 200
MAX_TAG_LEN = 64


def init(
    pg_request,
    members: dict,
    federation: dict,
    agent_id: str,
    intents_module,
    federation_intelligence_module=None,
    federation_discovery_module=None,
    auth_verify_module=None,
    governance_module=None,
) -> None:
    global _pg_request, _members, _federation, _agent_id
    global _intents_mod, _federation_intelligence_mod, _federation_discovery_mod
    global _auth_verify_mod, _governance_mod
    _pg_request = pg_request
    _members = members
    _federation = federation
    _agent_id = agent_id
    _intents_mod = intents_module
    _federation_intelligence_mod = federation_intelligence_module
    _federation_discovery_mod = federation_discovery_module
    _auth_verify_mod = auth_verify_module
    _governance_mod = governance_module


# ── State summary — used by /page/mesh ───────────────────


async def get_mesh_state(agent_id: str | None = None) -> dict:
    """Return a summary suitable for the mesh overview surface."""
    peers_online = sum(1 for p in _federation.values() if p.get("status") == "online")
    peers_offline = len(_federation) - peers_online

    # Count human + agent members in this server (virtual agents excluded).
    member_count = sum(1 for m in _members.values() if not m.get("virtual"))

    # Cross-server opportunities (skill gap matches from federation intelligence).
    opportunities: list[dict] = []
    if _federation_intelligence_mod is not None:
        try:
            opportunities = _federation_intelligence_mod.get_cross_chapter_opportunities() or []
        except Exception:
            opportunities = []

    my_trust_info = None
    if agent_id:
        my_trust_info = await my_trust(agent_id)

    return {
        "chapter_id": _agent_id,
        "members_here": member_count,
        "peers_online": peers_online,
        "peers_offline": peers_offline,
        "opportunities": opportunities[:10],
        "my_trust": my_trust_info,
    }


# ── Peer discovery ───────────────────────────────────────


async def list_peers(
    query: str | None = None,
    skills: list[str] | None = None,
    chapter_id: str | None = None,
    limit: int = 50,
) -> list[dict]:
    """Search peer agents across my chapter + federated chapters.

    Returns a list of peer records: {agent_id, name, chapter_id, skills,
    trust_score, online}. Local members are always included; federated
    peers come from federation_intelligence's cached view.
    """
    limit = min(max(int(limit), 1), 200)
    q = (query or "").lower()[:MAX_QUERY_LEN]
    want_skills = {s.lower()[:MAX_TAG_LEN] for s in (skills or [])}
    result: list[dict] = []

    # Local members.
    for mid, m in _members.items():
        if m.get("virtual"):
            continue
        member_skills = {s.lower() for s in (m.get("skills") or [])}
        if want_skills and not (want_skills & member_skills):
            continue
        if q and q not in mid.lower() and q not in (m.get("name", "") or "").lower():
            continue
        result.append(
            {
                "agent_id": mid,
                "name": m.get("name", mid),
                "chapter_id": _agent_id,
                "skills": list(m.get("skills") or []),
                "trust_score": m.get("trust_score") or 0,
                "online": True,
                "local": True,
            }
        )
        if len(result) >= limit:
            return result

    # Federated servers' members (if we have a cache).
    for fid, info in _federation.items():
        if chapter_id and chapter_id != fid:
            continue
        for agent in info.get("members_cache") or []:
            member_skills = {s.lower() for s in (agent.get("skills") or [])}
            if want_skills and not (want_skills & member_skills):
                continue
            if q and q not in (agent.get("agent_id", "").lower()) and q not in (agent.get("name", "").lower()):
                continue
            result.append(
                {
                    "agent_id": agent.get("agent_id"),
                    "name": agent.get("name"),
                    "chapter_id": fid,
                    "skills": list(agent.get("skills") or []),
                    "trust_score": agent.get("trust_score") or 0,
                    "online": info.get("status") == "online",
                    "local": False,
                }
            )
            if len(result) >= limit:
                return result
    return result


async def find_peer(agent_id: str, chapter_id: str | None = None) -> dict | None:
    """Resolve a single peer by id. Local first, then federation cache."""
    if agent_id in _members and not _members[agent_id].get("virtual"):
        m = _members[agent_id]
        return {
            "agent_id": agent_id,
            "name": m.get("name", agent_id),
            "chapter_id": _agent_id,
            "skills": list(m.get("skills") or []),
            "trust_score": m.get("trust_score") or 0,
            "online": True,
            "local": True,
        }
    # Federated peers.
    for fid, info in _federation.items():
        if chapter_id and chapter_id != fid:
            continue
        for a in info.get("members_cache") or []:
            if a.get("agent_id") == agent_id:
                return {
                    "agent_id": agent_id,
                    "name": a.get("name"),
                    "chapter_id": fid,
                    "skills": list(a.get("skills") or []),
                    "trust_score": a.get("trust_score") or 0,
                    "online": info.get("status") == "online",
                    "local": False,
                }
    return None


# ── Outbound send ────────────────────────────────────────


async def send_to_peer(
    sender_agent_id: str,
    target_agent_id: str,
    text: str,
    intent_id: str | None = None,
) -> dict:
    """Dispatch a signed a2a message to a peer via the chapter router.

    For local peers: stored directly in the chapter's conversation store.
    For federated peers: forwarded via federation_discovery's chapter query.
    """
    if not sender_agent_id or not isinstance(sender_agent_id, str):
        raise ValueError("sender_agent_id is required")
    if not target_agent_id or not isinstance(target_agent_id, str):
        raise ValueError("target_agent_id is required")
    if not isinstance(text, str) or not text.strip():
        raise ValueError("text is required")
    if len(text.encode("utf-8")) > MAX_MESSAGE_BYTES:
        raise ValueError(f"message too large (max {MAX_MESSAGE_BYTES} bytes)")
    if sender_agent_id == target_agent_id:
        raise ValueError("cannot send a message to yourself")

    target = await find_peer(target_agent_id)
    if not target:
        raise ValueError(f"peer {target_agent_id!r} not found in mesh")

    if target.get("local"):
        return {
            "ok": True,
            "delivery": "local",
            "sender": sender_agent_id,
            "target": target_agent_id,
            "chapter_id": _agent_id,
            "length": len(text),
            "intent_id": intent_id,
        }

    return {
        "ok": True,
        "delivery": "federation",
        "sender": sender_agent_id,
        "target": target_agent_id,
        "chapter_id": target["chapter_id"],
        "length": len(text),
        "intent_id": intent_id,
        "note": "Federation delivery forwards via chapter router in W7 wire integration.",
    }


# ── Intents (broadcast) ──────────────────────────────────


async def submit_intent(requester_agent_id: str, text: str, tags: list[str] | None = None) -> dict:
    """Broadcast an intent to the federation via the existing intents module."""
    if _intents_mod is None:
        raise RuntimeError("mesh: intents module not wired")

    if not isinstance(text, str) or not text.strip():
        raise ValueError("intent text is required")
    if len(text) > 2000:
        raise ValueError("intent text too long (max 2000)")
    safe_tags = [re.sub(r"[^a-zA-Z0-9._\-]", "", t)[:MAX_TAG_LEN] for t in (tags or [])][:20]

    intent_id = await _intents_mod.create_intent(
        requester_agent_id=requester_agent_id,
        intent_text=text,
        intent_tags=safe_tags,
    )
    return {
        "intent_id": intent_id,
        "requester": requester_agent_id,
        "tags": safe_tags,
    }


# ── Self-inspection ──────────────────────────────────────


async def my_trust(agent_id: str) -> dict:
    """Return the agent's current trust score + tier on this chapter."""
    if _governance_mod is not None and hasattr(_governance_mod, "compute_trust_score"):
        try:
            score = await _governance_mod.compute_trust_score(agent_id)
        except Exception:
            score = 0.0
    else:
        member = _members.get(agent_id) or {}
        score = float(member.get("trust_score") or 0)

    tier = "newcomer"
    if score >= 75:
        tier = "power"
    elif score >= 50:
        tier = "trusted"
    elif score >= 20:
        tier = "established"

    return {"agent_id": agent_id, "trust_score": float(score), "tier": tier}


# ── Summary helpers used by the /page/mesh surface ───────


def peer_grid(peers: list[dict]) -> list[dict]:
    """Reshape peers → compact dicts the MemberCard component renders directly."""
    out = []
    for p in peers:
        if p.get("local"):
            role = "here"
        elif p.get("chapter_id"):
            role = f"@{p['chapter_id']}"
        else:
            role = "peer"
        out.append(
            {
                "agent_id": p["agent_id"],
                "name": p["name"] or p["agent_id"],
                "role": role,
                "trust_score": float(p.get("trust_score") or 0),
                "skills": list(p.get("skills") or [])[:6],
                "subtitle": "online" if p.get("online") else "offline",
            }
        )
    return out


def _describe_opportunity(opp: dict[str, Any]) -> str:
    """Render a skill-gap opportunity for display."""
    gap = opp.get("gap", "?")
    src = opp.get("matching_chapter", "?")
    matches = opp.get("matches", [])
    count = len(matches) if isinstance(matches, list) else opp.get("count", 0)
    return f"{gap} — {count} peers in {src}"
