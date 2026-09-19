"""
Agent Export/Import — portable agent identity and memory.

Export: produces a single JSON file containing the agent's full state:
  - AgentFacts (NandaAgentFacts compliant)
  - Skills, interests, reputation
  - Identity (DID, public key — private key excluded by default)
  - Evolution history
  - Conversation threads
  - Private memory (only if ownership proven via signature)
  - Projection settings

Import: creates a new agent in a chapter from an exported file.
  - Validates the export format
  - Checks agent_id doesn't already exist (no silent overwrite)
  - Registers with chapter agent + federation
  - Rebuilds projections and embeddings

This is how agents move between chapters, back up, or go local.
"""

from collections.abc import Awaitable, Callable
from datetime import UTC, datetime

import llm_config

_pg_request: Callable[..., Awaitable] | None = None

def _pg() -> Callable[..., Awaitable]:
    """The injected pg_request, or a LOUD failure if init() never ran — the
    old unguarded calls crashed with a bare 'NoneType' object is not callable
    (R2 whole-app sweep)."""
    if _pg_request is None:
        raise RuntimeError("agent_export.init() was never called — no pg_request injected")
    return _pg_request

_agent_id = ""

EXPORT_VERSION = "1.0"


def init(pg_request, agent_id):
    global _pg_request, _agent_id
    _pg_request = pg_request
    _agent_id = agent_id


async def export_agent(agent_id: str) -> dict:
    """Export an agent's full portable state as a JSON-serializable dict.

    Args:
        agent_id: The agent to export

    Returns:
        Portable agent state dict, or {"error": "..."} on failure
    """
    # Load agent record
    agent_data = await _pg()(
        "GET",
        "agents",
        params={
            "agent_id": f"eq.{agent_id}",
        },
    )
    if not agent_data:
        return {"error": f"Agent '{agent_id}' not found"}

    agent = agent_data[0]

    # Load evolution history
    evolutions = (
        await _pg()(
            "GET",
            "agent_evolution_log",
            params={
                "agent_id": f"eq.{agent_id}",
                "order": "created_at.desc",
                "limit": "50",
                "select": "new_skill,personality_addition,trigger_activity,activity_score,created_at",
            },
        )
        or []
    )

    # Load conversation threads
    from_threads = (
        await _pg()(
            "GET",
            "agent_conversation_threads",
            params={
                "from_agent_id": f"eq.{agent_id}",
                "order": "updated_at.desc",
                "limit": "20",
                "select": "id,to_agent_id,topic,status,messages,message_count,created_at",
            },
        )
        or []
    )
    to_threads = (
        await _pg()(
            "GET",
            "agent_conversation_threads",
            params={
                "to_agent_id": f"eq.{agent_id}",
                "order": "updated_at.desc",
                "limit": "20",
                "select": "id,from_agent_id,topic,status,messages,message_count,created_at",
            },
        )
        or []
    )

    # Load activity summary
    activities = (
        await _pg()(
            "GET",
            "agent_member_activity",
            params={
                "agent_id": f"eq.{agent_id}",
                "order": "created_at.desc",
                "limit": "50",
                "select": "activity_type,activity_data,created_at",
            },
        )
        or []
    )

    # Load projection
    projection = await _pg()(
        "GET",
        "agent_projections",
        params={
            "agent_id": f"eq.{agent_id}",
            "select": "projection_data,visibility_settings",
        },
    )

    # Build export
    export_data = {
        "version": EXPORT_VERSION,
        "exported_at": datetime.now(UTC).isoformat(),
        "exported_from": _agent_id,
        "agent": {
            "agent_id": agent.get("agent_id"),
            "name": agent.get("name"),
            "description": agent.get("description"),
            "skills": agent.get("skills", []),
            "profile_type": agent.get("profile_type", "member"),
            "interests": agent.get("interests", []),
            "availability": agent.get("availability", "active"),
            "reputation": agent.get("reputation", {}),
            "agent_facts": agent.get("agent_facts", {}),
            "llm_provider": agent.get("llm_provider"),
            "llm_model": agent.get("llm_model"),
        },
        "identity": {
            "did": (agent.get("agent_facts") or {}).get("provider", {}).get("did"),
            "public_key": _extract_public_key(agent.get("agent_facts", {})),
        },
        "evolution_history": [
            {
                "skill": e.get("new_skill"),
                "personality": e.get("personality_addition"),
                "trigger": e.get("trigger_activity"),
                "score": e.get("activity_score"),
                "date": e.get("created_at"),
            }
            for e in evolutions
        ],
        "conversations": [
            {
                "thread_id": t.get("id"),
                "partner": t.get("to_agent_id") or t.get("from_agent_id"),
                "topic": t.get("topic"),
                "status": t.get("status"),
                "message_count": t.get("message_count"),
                "messages": t.get("messages", []),
                "created_at": t.get("created_at"),
            }
            for t in from_threads + to_threads
        ],
        "activity_summary": [
            {
                "type": a.get("activity_type"),
                "data": a.get("activity_data"),
                "date": a.get("created_at"),
            }
            for a in activities
        ],
        "projection": {
            "data": projection[0].get("projection_data", {}) if projection else {},
            "visibility": projection[0].get("visibility_settings", {}) if projection else {},
        },
    }

    return export_data


async def import_agent(export_data: dict, registering_profile_id: str = "") -> dict:
    """Import an agent from an exported JSON file into this chapter.

    Args:
        export_data: The exported agent state dict
        registering_profile_id: Postgres user ID to link the agent to

    Returns:
        {"imported": True, "agent_id": "..."} or {"error": "..."}
    """
    if export_data.get("version") != EXPORT_VERSION:
        return {"error": f"Unsupported export version: {export_data.get('version')}"}

    agent = export_data.get("agent", {})
    agent_id = agent.get("agent_id", "")
    if not agent_id:
        return {"error": "Missing agent_id in export"}

    # Check if agent_id already exists
    existing = await _pg()(
        "GET",
        "agents",
        params={
            "agent_id": f"eq.{agent_id}",
            "select": "id",
        },
    )
    if existing:
        return {
            "error": f"Agent '{agent_id}' already exists in this chapter. Use a different agent_id or delete the existing one first."
        }

    # Create agent record
    await _pg()(
        "POST",
        "agents",
        body={
            "agent_id": agent_id,
            "name": agent.get("name", f"@{agent_id}"),
            "description": agent.get("description", ""),
            "skills": agent.get("skills", []),
            "status": "active",
            "llm_provider": agent.get("llm_provider") or llm_config.PROVIDER,
            "llm_model": agent.get("llm_model") or llm_config.DEFAULT_MODEL,
            "profile_type": agent.get("profile_type", "member"),
            "interests": agent.get("interests", []),
            "availability": agent.get("availability", "active"),
            "reputation": agent.get("reputation", {}),
            "agent_facts": agent.get("agent_facts", {}),
            "chapter_id": "a0000000-0000-0000-0000-000000000001",
            "config": {
                "imported": True,
                "imported_from": export_data.get("exported_from", ""),
                "imported_at": datetime.now(UTC).isoformat(),
                "parent_chapter": _agent_id,
                "voice": "helpful",
                "virtual": True,
            },
            **({"profile_id": registering_profile_id} if registering_profile_id else {}),
        },
    )

    # Import evolution history
    for evo in export_data.get("evolution_history", [])[:50]:
        await _pg()(
            "POST",
            "agent_evolution_log",
            body={
                "chapter_agent_id": _agent_id,
                "agent_id": agent_id,
                "old_skills": [],
                "new_skill": evo.get("skill", ""),
                "personality_addition": evo.get("personality", ""),
                "trigger_activity": f"imported: {evo.get('trigger', '')}",
                "activity_score": evo.get("score", 0),
            },
        )

    # Import private memory if present
    for mem in export_data.get("private_memory", []):
        if registering_profile_id:
            await _pg()(
                "POST",
                "agent_private_memory",
                body={
                    "owner_id": registering_profile_id,
                    "agent_id": agent_id,
                    "memory_type": mem.get("type", "note"),
                    "memory_key": mem.get("key", ""),
                    "memory_value": mem.get("value", {}),
                },
            )

    # Build projection
    import projections

    proj = projections.build_projection(
        agent_id,
        {
            "skills": agent.get("skills", []),
            "name": agent.get("name", ""),
            "description": agent.get("description", ""),
            "config": {"interests": agent.get("interests", [])},
        },
    )

    import embeddings

    embedding = await embeddings.embed_projection(proj)
    body = {"agent_id": agent_id, "chapter_agent_id": _agent_id, "projection_data": proj}
    if embedding:
        body["embedding"] = embedding
    await _pg()("POST", "agent_projections", body=body)

    print(f"[Export] Imported @{agent_id} from {export_data.get('exported_from', '?')}")
    return {
        "imported": True,
        "agent_id": agent_id,
        "skills": len(agent.get("skills", [])),
        "evolution_entries": len(export_data.get("evolution_history", [])),
        "private_memories": len(export_data.get("private_memory", [])),
    }


def _extract_public_key(agent_facts: dict) -> str:
    """Extract public key from AgentFacts DID field."""
    did = (agent_facts or {}).get("provider", {}).get("did", "")
    # both the W3C and the legacy provider.did formats parse; junk
    # (including legacy HMAC carriers) yields "" instead of a fake "key".
    from sovereign_identity import pubkey_from_provider_did

    return pubkey_from_provider_did(did)
