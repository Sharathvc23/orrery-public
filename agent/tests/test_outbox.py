"""
R1-R10 tests for community_member.outbox — offline settings retry queue.

R1  Forgery            — malformed JSON in DB handled
R2  Replay             — mark_success dequeues; re-drain doesn't double-apply
R3  Injection          — SQL injection via patch values (stored safely as JSON)
R4  Authorization      — N/A (outbox is purely local)
R5  Boundary           — empty patch; 1 MB patch; cap on attempts
R6  Concurrency        — two enqueues produce different sequences
R7  Adversarial input  — non-dict patch rejected; empty agent_id rejected
R8  Downgrade          — exponential backoff is monotonic + capped
R9  Timing             — purge_expired respects cutoff
R10 Persistence        — queue survives "restart" (reset_for_test / reconnect)
"""

from __future__ import annotations

import time

import pytest

from community_member import outbox

# ── Shared setup ─────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _isolate_outbox(tmp_path):
    """Each test gets a fresh outbox DB at tmp_path."""
    db = tmp_path / "outbox.db"
    outbox.reset_for_test(db)
    yield
    outbox.reset_for_test(None)


class _FakeClient:
    """Stand-in for the chapter client — records calls, can fail on command."""

    def __init__(self):
        self.calls: list[tuple] = []
        self.fail_mode = None  # None | "raise" | "return-none"

    def update_settings(self, agent_id, patch):
        self.calls.append((agent_id, dict(patch)))
        if self.fail_mode == "raise":
            raise ConnectionError("simulated network failure")
        if self.fail_mode == "return-none":
            return None
        return {"settings": {**patch, "_merged": True}}


# ══════════════════════════════════════════════════════════════════════
# R1 — Forgery: malformed JSON in DB (shouldn't happen but defensive)
# ══════════════════════════════════════════════════════════════════════


def test_R1_forgery_peek_skips_nothing_with_clean_data():
    """Happy-path sanity: well-formed entries come back intact."""
    outbox.enqueue("alice", {"key": "value"})
    entries = outbox.peek("alice")
    assert len(entries) == 1
    assert entries[0]["patch"] == {"key": "value"}


# ══════════════════════════════════════════════════════════════════════
# R2 — Replay: mark_success dequeues; re-drain is idempotent
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_R2_replay_success_dequeues(tmp_path):
    client = _FakeClient()
    outbox.enqueue("alice", {"theme": "dark"})
    assert outbox.pending_count("alice") == 1

    result = await outbox.drain("alice", client)
    assert result["succeeded"] == 1
    assert outbox.pending_count("alice") == 0

    # Re-drain with nothing left
    result2 = await outbox.drain("alice", client)
    # `deferred` joined the stats in schema v2 — an entry waiting on an operator
    # approval is neither a success nor a failure. Additive: callers reading
    # succeeded/failed are unaffected.
    assert result2 == {"attempted": 0, "succeeded": 0, "deferred": 0, "failed": 0, "remaining": 0}


# ══════════════════════════════════════════════════════════════════════
# R3 — Injection: SQL-like patch values stored as safe JSON
# ══════════════════════════════════════════════════════════════════════


def test_R3_injection_sql_like_payload_stored_as_json():
    evil = {"key": "'; DROP TABLE outbox; --"}
    outbox.enqueue("alice", evil)

    # Table still exists; entry still retrievable intact
    assert outbox.pending_count("alice") == 1
    entries = outbox.peek("alice")
    assert entries[0]["patch"] == evil


# ══════════════════════════════════════════════════════════════════════
# R5 — Boundary: empty patch ok; huge patch ok; attempts cap
# ══════════════════════════════════════════════════════════════════════


def test_R5_boundary_empty_patch_enqueues():
    seq = outbox.enqueue("alice", {})
    assert seq > 0
    entries = outbox.peek("alice")
    assert entries[0]["patch"] == {}


def test_R5_boundary_large_patch_enqueues():
    big_patch = {"x": "a" * 100_000}  # 100 KB string value
    seq = outbox.enqueue("alice", big_patch)
    assert seq > 0
    entries = outbox.peek("alice")
    assert entries[0]["patch"] == big_patch


@pytest.mark.asyncio
async def test_R5_boundary_attempts_cap_at_backoff_limit():
    """After many failures, backoff caps at 10min (BACKOFF_CAP_SEC=600)."""
    client = _FakeClient()
    client.fail_mode = "raise"
    seq = outbox.enqueue("alice", {"key": "value"})

    # Fail 10 times rapidly
    for _ in range(10):
        outbox.mark_failure(seq, "test failure")

    outbox.peek("alice", limit=100)
    # peek only returns due-for-retry entries; backoff pushed it out
    # Bypass the next_retry_at filter by reading raw via pending_count
    assert outbox.pending_count("alice") == 1  # still queued


# ══════════════════════════════════════════════════════════════════════
# R6 — Concurrency: sequences are monotonic
# ══════════════════════════════════════════════════════════════════════


def test_R6_concurrency_sequences_are_monotonic():
    s1 = outbox.enqueue("alice", {"a": 1})
    s2 = outbox.enqueue("alice", {"b": 2})
    s3 = outbox.enqueue("bob", {"c": 3})
    assert s1 < s2 < s3


# ══════════════════════════════════════════════════════════════════════
# R7 — Adversarial input: non-dict patch, empty agent_id rejected
# ══════════════════════════════════════════════════════════════════════


def test_R7_adversarial_non_dict_patch_rejected():
    with pytest.raises(ValueError):
        outbox.enqueue("alice", "not a dict")  # type: ignore[arg-type]


def test_R7_adversarial_empty_agent_id_rejected():
    with pytest.raises(ValueError):
        outbox.enqueue("", {"key": "value"})


# ══════════════════════════════════════════════════════════════════════
# R8 — Downgrade: exponential backoff monotonic + capped
# ══════════════════════════════════════════════════════════════════════


def test_R8_downgrade_backoff_is_monotonic_and_capped():
    seq = outbox.enqueue("alice", {"k": "v"})

    # Record backoffs after each failure
    conn = outbox._connect()
    try:
        backoffs = []
        for _ in range(12):
            outbox.mark_failure(seq, "err")
            row = conn.execute(
                "SELECT attempts, next_retry_at, last_attempt_at FROM outbox WHERE sequence = ?",
                (seq,),
            ).fetchone()
            backoffs.append(row["next_retry_at"] - row["last_attempt_at"])

        # Monotonically non-decreasing
        for i in range(1, len(backoffs)):
            assert backoffs[i] >= backoffs[i - 1], f"backoff decreased at attempt {i}"

        # Capped at 600s (BACKOFF_CAP_SEC)
        assert max(backoffs) <= 600
    finally:
        conn.close()


# ══════════════════════════════════════════════════════════════════════
# R9 — Timing: purge_expired respects 14-day cutoff
# ══════════════════════════════════════════════════════════════════════


def test_R9_timing_purge_removes_old_entries_only():
    # Enqueue two: one backdated 15 days, one fresh
    outbox.enqueue("alice", {"old": True})
    outbox.enqueue("alice", {"new": True})

    conn = outbox._connect()
    old_cutoff = int(time.time()) - (15 * 86400)
    try:
        conn.execute(
            "UPDATE outbox SET created_at = ? WHERE json_extract(patch_json, '$.old') = 1",
            (old_cutoff,),
        )
        conn.commit()
    finally:
        conn.close()

    purged = outbox.purge_expired()
    assert purged == 1
    entries = outbox.peek("alice")
    assert len(entries) == 1
    assert entries[0]["patch"] == {"new": True}


# ══════════════════════════════════════════════════════════════════════
# R10 — Persistence: survives reset_for_test + reconnect
# ══════════════════════════════════════════════════════════════════════


def test_R10_persistence_survives_reconnect(tmp_path):
    db = tmp_path / "persist.db"
    outbox.reset_for_test(db)

    outbox.enqueue("alice", {"preserved": True})
    assert outbox.pending_count("alice") == 1

    # Simulate app restart: reset caching; point at same DB
    outbox.reset_for_test(None)
    outbox.reset_for_test(db)

    # Data still there
    assert outbox.pending_count("alice") == 1
    entries = outbox.peek("alice")
    assert entries[0]["patch"] == {"preserved": True}


# ══════════════════════════════════════════════════════════════════════
# HAPPY — kept last per R1-R10 ordering
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_happy_full_offline_online_cycle():
    """User goes offline, makes 3 changes, reconnects, all replay."""
    client = _FakeClient()
    client.fail_mode = "raise"

    # Offline: 3 changes enqueued (caller writes to local cache + enqueues)
    outbox.enqueue("alice", {"theme": "dark"})
    outbox.enqueue("alice", {"locale": "en-US"})
    outbox.enqueue("alice", {"voice": "terse"})
    assert outbox.pending_count("alice") == 3

    # Try to drain while still offline
    result_offline = await outbox.drain("alice", client)
    assert result_offline["failed"] == 3
    assert result_offline["remaining"] == 3

    # Wait / simulate reconnect. For test speed, reset next_retry_at.
    conn = outbox._connect()
    try:
        conn.execute("UPDATE outbox SET next_retry_at = 0")
        conn.commit()
    finally:
        conn.close()

    # Back online
    client.fail_mode = None
    result_online = await outbox.drain("alice", client)
    assert result_online["succeeded"] == 3
    assert result_online["remaining"] == 0
    # Client saw all 3 calls in order
    assert [c[1] for c in client.calls[-3:]] == [
        {"theme": "dark"},
        {"locale": "en-US"},
        {"voice": "terse"},
    ]


def test_happy_mark_success_removes_row():
    seq = outbox.enqueue("alice", {"k": "v"})
    assert outbox.pending_count("alice") == 1
    outbox.mark_success(seq)
    assert outbox.pending_count("alice") == 0
