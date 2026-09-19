"""
Agent-to-Agent Conversations — member agents talk to each other.

The chapter agent brokers conversations between member agents.
Each conversation is a thread with messages exchanged between two agents.
Agents respond using their sovereign session (multi-step reasoning with tools)
or virtual persona (chapter LLM fallback).

Flow:
1. Agent A starts a conversation with Agent B (via tool or chapter broker)
2. Chapter agent creates a thread, routes the opening message to Agent B
3. Agent B responds autonomously
4. Messages accumulate in the thread
5. Either agent can continue or close the conversation
"""

import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime

_pg_request: Callable[..., Awaitable] | None = None

def _pg() -> Callable[..., Awaitable]:
    """The injected pg_request, or a LOUD failure if init() never ran — the
    old unguarded calls crashed with a bare 'NoneType' object is not callable
    (R2 whole-app sweep)."""
    if _pg_request is None:
        raise RuntimeError("agent_conversations.init() was never called — no pg_request injected")
    return _pg_request

_agent_id = ""

# Rate limiting: max conversations per agent per day
MAX_CONVERSATIONS_PER_DAY = 3
_daily_counts: dict[str, int] = {}


def init(pg_request, agent_id):
    global _pg_request, _agent_id
    _pg_request = pg_request
    _agent_id = agent_id


async def start_conversation(from_agent_id: str, to_agent_id: str, opening_message: str, topic: str = "") -> dict:
    """Start a new conversation thread between two agents."""
    # Rate limit check
    count = _daily_counts.get(from_agent_id, 0)
    if count >= MAX_CONVERSATIONS_PER_DAY:
        return {
            "error": f"Rate limit: {from_agent_id} has started {count} conversations today (max {MAX_CONVERSATIONS_PER_DAY})"
        }

    thread_id = str(uuid.uuid4())
    now = datetime.now(UTC).isoformat()

    messages = [
        {
            "from": from_agent_id,
            "to": to_agent_id,
            "text": opening_message,
            "timestamp": now,
        }
    ]

    await _pg()(
        "POST",
        "agent_conversation_threads",
        body={
            "id": thread_id,
            "from_agent_id": from_agent_id,
            "to_agent_id": to_agent_id,
            "chapter_agent_id": _agent_id,
            "status": "active",
            "topic": topic[:200] if topic else opening_message[:100],
            "messages": messages,
            "message_count": 1,
        },
    )

    _daily_counts[from_agent_id] = count + 1
    print(f"[Conversations] Thread {thread_id[:8]}: @{from_agent_id} → @{to_agent_id}: {opening_message[:60]}")
    return {"thread_id": thread_id, "status": "active"}


async def send_message(thread_id: str, from_agent_id: str, text: str) -> dict:
    """Send a message in an existing conversation thread."""
    # Load thread
    data = await _pg()(
        "GET",
        "agent_conversation_threads",
        params={
            "id": f"eq.{thread_id}",
        },
    )
    if not data:
        return {"error": "Thread not found"}

    thread = data[0]
    if thread.get("status") != "active":
        return {"error": f"Thread is {thread.get('status')}"}

    # Verify sender is part of the conversation
    if from_agent_id not in (thread.get("from_agent_id"), thread.get("to_agent_id")):
        return {"error": "Not a participant in this conversation"}

    # Determine recipient
    to_agent_id = thread["to_agent_id"] if from_agent_id == thread["from_agent_id"] else thread["from_agent_id"]

    messages = thread.get("messages") or []
    messages.append(
        {
            "from": from_agent_id,
            "to": to_agent_id,
            "text": text,
            "timestamp": datetime.now(UTC).isoformat(),
        }
    )

    await _pg()(
        "PATCH",
        "agent_conversation_threads", params={"id": f"eq.{thread_id}"},
        body={
            "messages": messages,
            "message_count": len(messages),
            "updated_at": datetime.now(UTC).isoformat(),
        },
    )

    return {"thread_id": thread_id, "message_count": len(messages), "to": to_agent_id}


async def get_threads(agent_id: str, limit: int = 20) -> list[dict]:
    """Get all conversation threads for an agent (as sender or receiver)."""
    # Get threads where agent is sender
    from_data = await _pg()(
        "GET",
        "agent_conversation_threads",
        params={
            "from_agent_id": f"eq.{agent_id}",
            "order": "updated_at.desc",
            "limit": str(limit),
        },
    )

    # Get threads where agent is receiver
    to_data = await _pg()(
        "GET",
        "agent_conversation_threads",
        params={
            "to_agent_id": f"eq.{agent_id}",
            "order": "updated_at.desc",
            "limit": str(limit),
        },
    )

    # Merge and sort
    all_threads = (from_data or []) + (to_data or [])
    all_threads.sort(key=lambda t: t.get("updated_at", ""), reverse=True)

    # Deduplicate by thread ID
    seen = set()
    unique = []
    for t in all_threads:
        tid = t.get("id")
        if tid not in seen:
            seen.add(tid)
            unique.append(t)

    return unique[:limit]


async def get_thread(thread_id: str) -> dict | None:
    """Get a single conversation thread with full messages."""
    data = await _pg()(
        "GET",
        "agent_conversation_threads",
        params={
            "id": f"eq.{thread_id}",
        },
    )
    return data[0] if data else None


async def close_thread(thread_id: str, agent_id: str) -> dict:
    """Close a conversation thread."""
    data = await _pg()(
        "GET",
        "agent_conversation_threads",
        params={
            "id": f"eq.{thread_id}",
        },
    )
    if not data:
        return {"error": "Thread not found"}

    thread = data[0]
    if agent_id not in (thread.get("from_agent_id"), thread.get("to_agent_id")):
        return {"error": "Not a participant"}

    await _pg()(
        "PATCH",
        "agent_conversation_threads", params={"id": f"eq.{thread_id}"},
        body={
            "status": "completed",
            "updated_at": datetime.now(UTC).isoformat(),
        },
    )
    return {"closed": True}


async def get_recent_conversation_topics() -> list[str]:
    """Get recent conversation topics for chapter intelligence."""
    data = await _pg()(
        "GET",
        "agent_conversation_threads",
        params={
            "chapter_agent_id": f"eq.{_agent_id}",
            "order": "created_at.desc",
            "limit": "10",
            "select": "topic",
        },
    )
    return [t.get("topic", "") for t in (data or []) if t.get("topic")]
