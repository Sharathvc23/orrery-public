"""
Chapter Helpers — ConversationStore, memory, logging.
"""

import asyncio
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime

import thought_redaction

# Injected state
pg_request: Callable[..., Awaitable] | None = None

def _pg() -> Callable[..., Awaitable]:
    """The injected pg_request, or a LOUD failure if init() never ran — the
    old unguarded calls crashed with a bare 'NoneType' object is not callable
    (R2 whole-app sweep)."""
    if pg_request is None:
        raise RuntimeError("chapter_helpers.init() was never called — no pg_request injected")
    return pg_request

AGENT_ID = ""
AGENT_NAME = ""
AGENT_DB_UUID = ""


def init(sb_req, agent_id, agent_name, uuid, cache):
    global pg_request, AGENT_ID, AGENT_NAME, AGENT_DB_UUID, _knowledge_cache
    pg_request = sb_req
    AGENT_ID = agent_id
    AGENT_NAME = agent_name
    AGENT_DB_UUID = uuid
    _knowledge_cache = cache


# CONVERSATION STORE — in-memory cache + Postgres persistence
# ============================================================
class ConversationStore:
    def __init__(self):
        self._cache: dict[str, list[dict]] = {}

    async def load(self, conversation_id: str) -> list[dict]:
        if conversation_id in self._cache:
            return self._cache[conversation_id]
        # Try Postgres
        data = await _pg()(
            "GET",
            "agent_conversations",
            params={
                "conversation_id": f"eq.{conversation_id}",
                "select": "messages",
                "limit": "1",
            },
        )
        if data and isinstance(data, list) and len(data) > 0:
            messages = data[0].get("messages", [])
            self._cache[conversation_id] = messages
            return messages
        self._cache[conversation_id] = []
        return []

    async def append(self, agent_uuid: str, conversation_id: str, user_msg: str, assistant_msg: str):
        messages = await self.load(conversation_id)
        now = datetime.now(UTC).isoformat()
        messages.append({"role": "user", "content": user_msg, "ts": now})
        messages.append({"role": "assistant", "content": assistant_msg, "ts": now})
        # Cap at 100 messages
        if len(messages) > 100:
            messages = messages[-100:]
        self._cache[conversation_id] = messages
        # Persist to Postgres (fire and forget)
        if agent_uuid:
            asyncio.create_task(self._persist(agent_uuid, conversation_id, messages))

    async def _persist(self, agent_uuid: str, conversation_id: str, messages: list[dict]):
        await _pg()(
            "POST",
            "agent_conversations",
            body={
                "agent_id": agent_uuid,
                "conversation_id": conversation_id,
                "messages": messages,
                "title": f"Conversation {conversation_id[:8]}",
            },
        )


conv_store = ConversationStore()


# ============================================================
# AGENT MEMORY — short-term dedup + long-term knowledge
# ============================================================
_knowledge_cache: dict[str, dict] = {}


async def remember(memory_type: str, memory_key: str, value: dict | None = None) -> None:
    """Store a short-term memory for dedup (expires in 7 days)."""
    await _pg()(
        "POST",
        "agent_memory",
        body={
            "chapter_agent_id": AGENT_ID,
            "memory_type": memory_type,
            "memory_key": memory_key[:200],
            "memory_value": value or {},
        },
    )


async def recent_memories(memory_type: str, limit: int = 10) -> list[str]:
    """Get recent memory keys of a given type (not expired)."""
    data = await _pg()(
        "GET",
        "agent_memory",
        params={
            "chapter_agent_id": f"eq.{AGENT_ID}",
            "memory_type": f"eq.{memory_type}",
            "expires_at": f"gt.{datetime.now(UTC).isoformat()}",
            "order": "created_at.desc",
            "limit": str(limit),
            "select": "memory_key",
        },
    )
    return [d["memory_key"] for d in (data or [])]


async def load_knowledge() -> None:
    """Load long-term knowledge models from Postgres into cache."""
    global _knowledge_cache
    data = await _pg()(
        "GET",
        "agent_knowledge",
        params={
            "chapter_agent_id": f"eq.{AGENT_ID}",
        },
    )
    if data:
        for k in data:
            _knowledge_cache[k["knowledge_type"]] = k["knowledge_data"]
        print(f"Loaded {len(data)} knowledge models")


def get_intelligence_context() -> str:
    """Get chapter intelligence as context string for LLM prompts."""
    intel = _knowledge_cache.get("chapter_intelligence", {})
    if not intel:
        return ""
    parts = []
    if intel.get("trending_topics"):
        parts.append(f"Trending topics: {', '.join(intel['trending_topics'][:5])}")
    if intel.get("skill_gaps"):
        parts.append(f"Skill gaps: {', '.join(intel['skill_gaps'][:5])}")
    if intel.get("recommendations"):
        parts.append(f"Recommendations: {', '.join(intel['recommendations'][:3])}")
    if intel.get("patterns"):
        parts.append(f"Patterns: {', '.join(intel['patterns'][:3])}")
    return "\n\nChapter Intelligence:\n" + "\n".join(f"- {p}" for p in parts) if parts else ""


# ============================================================
# ACTIVITY LOGGER — writes to agent_activity table
# ============================================================
async def log_activity(
    member_agent_id: str | None,
    member_name: str | None,
    conversation_id: str,
    user_msg: str,
    agent_response: str,
    is_cross_chapter: bool = False,
):
    """Log an exchange to the public activity feed."""
    await _pg()(
        "POST",
        "agent_activity",
        body={
            "chapter_agent_id": AGENT_ID,
            "chapter_name": AGENT_NAME,
            "member_agent_id": member_agent_id,
            "member_name": member_name,
            "conversation_id": conversation_id,
            "user_message_snippet": user_msg[:200],
            "agent_response_snippet": agent_response[:200],
            "is_cross_chapter": is_cross_chapter,
        },
    )


async def log_agent_thought(
    thought_type: str,
    thought_text: str,
    a2ui_surface: dict | None = None,
    targets: list[dict] | None = None,
    member_agent_id: str | None = None,
    member_name: str | None = None,
):
    """Log an autonomous thought to the public thoughts feed.

    THE PROSE IS REDACTED HERE, AT WRITE. ``thought_text`` is a sentence the
    agent composed, and ``think_conversation`` builds it one ``"@{speaker}:
    {text}"`` line per turn — so a handle lives inside the sentence rather
    than in a column a reader could drop from a ``select``. Redacting at read
    in N places is the pattern that produced the leak this closes:
    ``/api/thoughts`` filtered, ``build_activity_surface`` did not, and
    nothing detected the difference. Data at rest that never carried the
    handle cannot be leaked by a surface added next year.

    ``member_agent_id`` is still stored unredacted, deliberately: it is a
    column, so each read surface decides whether to select it, and internal
    readers need it to attribute a thought. The prose is the part no
    ``select`` can reach.
    """
    await _pg()(
        "POST",
        "agent_thoughts",
        body={
            "chapter_agent_id": AGENT_ID,
            "chapter_name": AGENT_NAME,
            "member_agent_id": member_agent_id,
            "member_name": member_name,
            "thought_type": thought_type,
            "thought_text": thought_redaction.redact_handles(thought_text),
            "a2ui_surface": a2ui_surface,
            "targets": targets or [],
        },
    )
