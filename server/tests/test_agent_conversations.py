"""
Adversarial tests for agent_conversations.py — prosecution-grade.

- P1: State transition proofs (thread lifecycle)
- P3: Security invariants (rate limiting, participant verification)
- C2: Every happy path gets a hostile path
- C5: Boundary proofs (rate limits exactly at threshold)
"""

import pytest

import agent_conversations


class FakePostgresRequest:
    def __init__(self):
        self.calls = []
        self.threads: dict[str, dict] = {}

    async def __call__(self, method, table, params=None, body=None):
        self.calls.append((method, table, params, body))

        if method == "POST" and table == "agent_conversation_threads":
            tid = body.get("id", "fake")
            self.threads[tid] = body
            return [body]

        if method == "GET" and table == "agent_conversation_threads":
            if not params:
                return list(self.threads.values())
            # Filter by params
            results = list(self.threads.values())
            for key, val in (params or {}).items():
                if key in ("order", "limit", "select"):
                    continue
                if isinstance(val, str) and val.startswith("eq."):
                    filter_val = val.replace("eq.", "")
                    results = [t for t in results if str(t.get(key, "")) == filter_val]
            return results

        if method == "PATCH" and table.startswith("agent_conversation_threads"):
            # The id filter now rides in params=, not baked into the path.
            tid = str((params or {}).get("id", "")).replace("eq.", "")
            if not tid and "eq." in table:
                tid = table.split("eq.")[1]
            if tid in self.threads:
                self.threads[tid].update(body)
            return None

        return None


@pytest.fixture
def conv_env():
    fake_sb = FakePostgresRequest()
    agent_conversations.init(pg_request=fake_sb, agent_id="test-chapter")
    agent_conversations._daily_counts.clear()
    return fake_sb


# ═══════════════════════════════════════════════
# P1: STATE TRANSITION PROOFS
# ═══════════════════════════════════════════════


# HAPPY: Start conversation creates thread with correct state
@pytest.mark.asyncio
async def test_start_conversation_creates_thread(conv_env):
    result = await agent_conversations.start_conversation("alice", "bob", "Hi Bob!", "test topic")
    assert "thread_id" in result
    assert result["status"] == "active"
    # Verify Postgres got the POST
    post_calls = [c for c in conv_env.calls if c[0] == "POST"]
    assert len(post_calls) == 1
    body = post_calls[0][3]
    assert body["from_agent_id"] == "alice"
    assert body["to_agent_id"] == "bob"
    assert body["message_count"] == 1
    assert len(body["messages"]) == 1
    assert body["messages"][0]["text"] == "Hi Bob!"


# HAPPY → FAILURE: Send message to closed thread rejected
@pytest.mark.asyncio
async def test_send_to_closed_thread_rejected(conv_env):
    result = await agent_conversations.start_conversation("alice", "bob", "Hi")
    thread_id = result["thread_id"]
    await agent_conversations.close_thread(thread_id, "alice")
    # Thread is now completed
    send_result = await agent_conversations.send_message(thread_id, "alice", "More text")
    assert "error" in send_result


# ═══════════════════════════════════════════════
# P3: SECURITY INVARIANTS — RATE LIMITING
# ═══════════════════════════════════════════════


# BOUNDARY: Exactly at rate limit (C5)
@pytest.mark.asyncio
async def test_rate_limit_at_boundary(conv_env):
    for i in range(agent_conversations.MAX_CONVERSATIONS_PER_DAY):
        result = await agent_conversations.start_conversation("spammer", f"target-{i}", f"msg-{i}")
        assert "error" not in result, f"Should allow conversation {i + 1}"


# BOUNDARY: One over rate limit — must reject
@pytest.mark.asyncio
async def test_rate_limit_exceeded(conv_env):
    for i in range(agent_conversations.MAX_CONVERSATIONS_PER_DAY):
        await agent_conversations.start_conversation("spammer", f"t-{i}", f"m-{i}")
    # One more should fail
    result = await agent_conversations.start_conversation("spammer", "one-more", "blocked")
    assert "error" in result
    assert "Rate limit" in result["error"]


# SECURITY: Non-participant can't send message
@pytest.mark.asyncio
async def test_non_participant_rejected(conv_env):
    result = await agent_conversations.start_conversation("alice", "bob", "Hi")
    thread_id = result["thread_id"]
    # Eve tries to inject a message
    send_result = await agent_conversations.send_message(thread_id, "eve", "Injected!")
    assert "error" in send_result
    assert "Not a participant" in send_result["error"]


# SECURITY: Non-participant can't close thread
@pytest.mark.asyncio
async def test_non_participant_cant_close(conv_env):
    result = await agent_conversations.start_conversation("alice", "bob", "Hi")
    result2 = await agent_conversations.close_thread(result["thread_id"], "eve")
    assert "error" in result2


# ═══════════════════════════════════════════════
# ADVERSARIAL
# ═══════════════════════════════════════════════


# ADVERSARIAL: SQL injection in message text
@pytest.mark.asyncio
async def test_sql_injection_in_message(conv_env):
    result = await agent_conversations.start_conversation("alice", "bob", "'; DROP TABLE agents; --")
    assert "thread_id" in result  # Doesn't crash


# ADVERSARIAL: Very long message
@pytest.mark.asyncio
async def test_very_long_message(conv_env):
    result = await agent_conversations.start_conversation("alice", "bob", "x" * 100000)
    assert "thread_id" in result


# ADVERSARIAL: Empty agent IDs
@pytest.mark.asyncio
async def test_empty_agent_ids(conv_env):
    result = await agent_conversations.start_conversation("", "", "hi")
    # Should still create (validation happens at API layer)
    assert "thread_id" in result or "error" in result


# ADVERSARIAL: Send message to nonexistent thread
@pytest.mark.asyncio
async def test_send_to_nonexistent_thread(conv_env):
    result = await agent_conversations.send_message("nonexistent-uuid", "alice", "hello")
    assert "error" in result
    assert "not found" in result["error"].lower()


# ADVERSARIAL: Close nonexistent thread
@pytest.mark.asyncio
async def test_close_nonexistent_thread(conv_env):
    result = await agent_conversations.close_thread("nonexistent-uuid", "alice")
    assert "error" in result


# EDGE: Get threads for agent with no conversations
@pytest.mark.asyncio
async def test_get_threads_empty(conv_env):
    threads = await agent_conversations.get_threads("ghost")
    assert threads == []


# EDGE: Both participants can send messages
@pytest.mark.asyncio
async def test_both_participants_can_send(conv_env):
    result = await agent_conversations.start_conversation("alice", "bob", "Hi Bob")
    tid = result["thread_id"]
    r2 = await agent_conversations.send_message(tid, "bob", "Hi Alice")
    assert "error" not in r2
    r3 = await agent_conversations.send_message(tid, "alice", "How are you?")
    assert "error" not in r3
    assert r3["message_count"] == 3


# EDGE: Agent sees threads where they're the sender
@pytest.mark.asyncio
async def test_agent_sees_sent_threads(conv_env):
    await agent_conversations.start_conversation("alice", "bob", "Thread 1")
    await agent_conversations.start_conversation("alice", "charlie", "Thread 2")
    threads = await agent_conversations.get_threads("alice")
    assert len(threads) >= 2
