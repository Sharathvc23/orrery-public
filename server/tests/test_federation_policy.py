"""
Tests for federation_policy.py — per-peer state machine + backoff + probe.

Classification: HAPPY / EDGE / FAILURE / ADVERSARIAL
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

import federation_policy as fp


class _FakePostgres:
    def __init__(self):
        self.tables: dict[str, list[dict]] = {
            "federation_policy": [],
            "federation_policy_history": [],
            "federation_probe_due": [],
        }

    async def __call__(self, method, table_or_path, params=None, body=None):
        table = table_or_path.split("?")[0]
        if method == "GET":
            rows = list(self.tables.get(table, []))
            if params:
                rows = self._filter(rows, params)
            return rows
        if method == "POST":
            body = dict(body or {})
            body.setdefault("id", f"id-{len(self.tables[table]) + 1}")
            body.setdefault("created_at", datetime.now(UTC).isoformat())
            self.tables.setdefault(table, []).append(body)
            return [body]
        if method == "PATCH":
            filters = self._parse_path_filters(table_or_path)
            matched = []
            for row in self.tables.get(table, []):
                if all(self._match(row, k, v) for k, v in filters.items()):
                    row.update(body or {})
                    matched.append(row)
            return matched
        return None

    @staticmethod
    def _parse_path_filters(path):
        if "?" not in path:
            return {}
        _, qs = path.split("?", 1)
        return dict(pair.split("=", 1) for pair in qs.split("&"))

    def _filter(self, rows, params):
        out = list(rows)
        for k, v in (params or {}).items():
            if k in ("select", "order", "limit"):
                continue
            out = [r for r in out if self._match(r, k, v)]
        return out

    @staticmethod
    def _match(row, key, predicate):
        if "." not in predicate:
            return row.get(key) == predicate
        op, val = predicate.split(".", 1)
        rv = row.get(key)
        if op == "eq":
            if val == "null":
                return rv is None
            return str(rv) == val
        return True


@pytest.fixture
def env():
    sb = _FakePostgres()
    fp.init(pg_request=sb, agent_id="test-chapter")
    return sb


# ═══════════════════════════════════════════════
# PURE HELPERS
# ═══════════════════════════════════════════════


def test_next_backoff_doubles():
    assert fp.next_backoff(360) == 720
    assert fp.next_backoff(720) == 1440


def test_next_backoff_capped_at_max():
    """C5: backoff never exceeds max_backoff_seconds."""
    assert fp.next_backoff(1800) == 3600
    assert fp.next_backoff(3600) == 3600
    assert fp.next_backoff(99999) == 3600


def test_next_backoff_minimum_is_baseline():
    """EDGE: if current is below baseline, at minimum double baseline."""
    assert fp.next_backoff(60, baseline=360) == 720


def test_reset_backoff_returns_baseline():
    assert fp.reset_backoff() == fp.BASELINE_BACKOFF_SECONDS


def test_should_exchange_blocked_never():
    """ADVERSARIAL: blocked peer never exchanges, regardless of state."""
    assert fp.should_exchange_now("online", None, None, 0, blocked=True) is False
    assert fp.should_exchange_now("quarantined", None, None, 0, blocked=True) is False


def test_should_exchange_online_yes():
    assert fp.should_exchange_now("online", None, None, 360, blocked=False) is True


def test_should_exchange_unknown_yes():
    """HAPPY: never seen this peer → allow first probe."""
    assert fp.should_exchange_now("unknown", None, None, 360, blocked=False) is True


def test_should_exchange_degraded_respects_backoff():
    """C5: degraded peer only re-tried after backoff_seconds elapsed."""
    now = datetime.now(UTC)
    recent_failure = now - timedelta(seconds=60)  # 1 min ago
    # backoff=360 → should NOT exchange yet
    assert (
        fp.should_exchange_now(
            "degraded",
            None,
            recent_failure,
            360,
            blocked=False,
            now=now,
        )
        is False
    )
    # backoff=30 → elapsed 60s > 30s → YES
    assert (
        fp.should_exchange_now(
            "degraded",
            None,
            recent_failure,
            30,
            blocked=False,
            now=now,
        )
        is True
    )


def test_should_exchange_quarantined_respects_backoff():
    now = datetime.now(UTC)
    recent_failure = now - timedelta(seconds=60)
    assert (
        fp.should_exchange_now(
            "quarantined",
            None,
            recent_failure,
            3600,
            blocked=False,
            now=now,
        )
        is False
    )


def test_state_after_success():
    assert fp.state_after_success("unknown") == "online"
    assert fp.state_after_success("degraded") == "online"
    assert fp.state_after_success("quarantined") == "online"
    assert fp.state_after_success("online") == "online"


def test_state_after_success_preserves_block():
    """ADVERSARIAL: a probed blocked peer stays blocked even if reachable."""
    assert fp.state_after_success("blocked") == "blocked"


def test_state_after_failure_escalates():
    assert fp.state_after_failure("online", 1) == "degraded"
    assert fp.state_after_failure("degraded", 2) == "degraded"
    assert fp.state_after_failure("degraded", 3) == "quarantined"
    assert fp.state_after_failure("quarantined", 10) == "quarantined"


def test_state_after_failure_preserves_block():
    assert fp.state_after_failure("blocked", 99) == "blocked"


# ═══════════════════════════════════════════════
# SUPABASE-BACKED OPERATIONS
# ═══════════════════════════════════════════════


@pytest.mark.asyncio
async def test_upsert_peer_creates_row(env):
    """HAPPY: first time seeing a peer creates a seed row."""
    result = await fp.upsert_peer("TEST-boston-chapter", "https://boston.example.com")
    assert result is not None
    assert result["peer_chapter_id"] == "TEST-boston-chapter"
    assert result["state"] == "unknown"
    assert result["backoff_seconds"] == fp.BASELINE_BACKOFF_SECONDS


@pytest.mark.asyncio
async def test_upsert_peer_idempotent(env):
    """EDGE: upserting the same peer twice doesn't duplicate."""
    await fp.upsert_peer("TEST-boston-chapter", "https://boston.example.com")
    await fp.upsert_peer("TEST-boston-chapter", "https://boston.example.com")
    assert len(env.tables["federation_policy"]) == 1


@pytest.mark.asyncio
async def test_upsert_peer_updates_endpoint(env):
    """EDGE: endpoint change propagates without losing state."""
    await fp.upsert_peer("TEST-boston-chapter", "https://old.example.com")
    await fp.upsert_peer("TEST-boston-chapter", "https://new.example.com")
    assert env.tables["federation_policy"][0]["peer_endpoint"] == "https://new.example.com"


@pytest.mark.asyncio
async def test_record_success_transitions_unknown_to_online(env):
    await fp.upsert_peer("TEST-boston-chapter")
    await fp.record_success("TEST-boston-chapter", "https://boston.example.com")
    row = env.tables["federation_policy"][0]
    assert row["state"] == "online"
    assert row["consecutive_failures"] == 0
    assert row["backoff_seconds"] == fp.BASELINE_BACKOFF_SECONDS


@pytest.mark.asyncio
async def test_record_failure_escalates_to_degraded(env):
    await fp.upsert_peer("TEST-boston-chapter")
    await fp.record_failure("TEST-boston-chapter", "connection refused")
    row = env.tables["federation_policy"][0]
    assert row["state"] == "degraded"
    assert row["consecutive_failures"] == 1
    # Backoff doubled from baseline
    assert row["backoff_seconds"] == fp.BASELINE_BACKOFF_SECONDS * 2


@pytest.mark.asyncio
async def test_three_failures_quarantine(env):
    await fp.upsert_peer("TEST-boston-chapter")
    await fp.record_failure("TEST-boston-chapter", "err1")
    await fp.record_failure("TEST-boston-chapter", "err2")
    await fp.record_failure("TEST-boston-chapter", "err3")
    row = env.tables["federation_policy"][0]
    assert row["state"] == "quarantined"
    assert row["consecutive_failures"] == 3


@pytest.mark.asyncio
async def test_success_after_failures_recovers_state(env):
    await fp.upsert_peer("TEST-boston-chapter")
    await fp.record_failure("TEST-boston-chapter", "err1")
    await fp.record_failure("TEST-boston-chapter", "err2")
    await fp.record_success("TEST-boston-chapter")
    row = env.tables["federation_policy"][0]
    assert row["state"] == "online"
    assert row["consecutive_failures"] == 0
    assert row["backoff_seconds"] == fp.BASELINE_BACKOFF_SECONDS
    # Recovery event logged
    events = [h["event"] for h in env.tables["federation_policy_history"]]
    assert "recover" in events


@pytest.mark.asyncio
async def test_failures_on_blocked_peer_ignored(env):
    """ADVERSARIAL: blocked peer's state never drifts from blocked, even on failure spam."""
    await fp.upsert_peer("evil-peer")
    await fp.block_peer("evil-peer", "leader-1", reason="sends spam")
    await fp.record_failure("evil-peer", "err")
    await fp.record_failure("evil-peer", "err")
    row = env.tables["federation_policy"][0]
    assert row["state"] == "blocked"
    # consecutive_failures not incremented on blocked
    assert row["consecutive_failures"] == 0


@pytest.mark.asyncio
async def test_block_peer_sets_blocked_by(env):
    result = await fp.block_peer("TEST-boston-chapter", "leader-1", reason="not aligned")
    assert result["ok"]
    row = env.tables["federation_policy"][0]
    assert row["state"] == "blocked"
    assert row["blocked_by"] == "leader-1"
    assert "not aligned" in row["blocked_reason"]


@pytest.mark.asyncio
async def test_unblock_clears_state(env):
    await fp.block_peer("TEST-boston-chapter", "leader-1", reason="temp")
    result = await fp.unblock_peer("TEST-boston-chapter", "leader-1")
    assert result["ok"]
    row = env.tables["federation_policy"][0]
    assert row["state"] == "unknown"
    assert row["blocked_by"] is None
    assert row["consecutive_failures"] == 0


@pytest.mark.asyncio
async def test_unblock_unknown_peer_returns_not_found(env):
    result = await fp.unblock_peer("nonexistent", "leader-1")
    assert result["error"] == "not_found"


@pytest.mark.asyncio
async def test_unblock_already_unblocked_returns_error(env):
    await fp.upsert_peer("TEST-boston-chapter")
    result = await fp.unblock_peer("TEST-boston-chapter", "leader-1")
    assert result["error"] == "not_blocked"
    assert result["current_state"] == "unknown"


@pytest.mark.asyncio
async def test_should_exchange_with_blocked_false(env):
    await fp.upsert_peer("TEST-boston-chapter")
    await fp.block_peer("TEST-boston-chapter", "leader-1")
    allowed = await fp.should_exchange_with("TEST-boston-chapter")
    assert allowed is False


@pytest.mark.asyncio
async def test_should_exchange_with_unknown_peer_true(env):
    """HAPPY: unseen peer → allow first exchange attempt."""
    allowed = await fp.should_exchange_with("brand-new-peer")
    assert allowed is True


# ═══════════════════════════════════════════════
# PROBE
# ═══════════════════════════════════════════════


@pytest.mark.asyncio
async def test_probe_empty_queue_no_op(env):
    """EDGE: no quarantined peers → empty result."""
    result = await fp.probe_quarantined()
    assert result == {"recovered": [], "still_down": []}


# ═══════════════════════════════════════════════
# HISTORY
# ═══════════════════════════════════════════════


@pytest.mark.asyncio
async def test_history_logged_on_block(env):
    await fp.upsert_peer("TEST-boston-chapter")
    await fp.block_peer("TEST-boston-chapter", "leader-1", reason="test")
    hist = await fp.history_for("TEST-boston-chapter")
    events = [h["event"] for h in hist]
    assert "block" in events


@pytest.mark.asyncio
async def test_history_captures_transitions(env):
    await fp.upsert_peer("TEST-boston-chapter")
    await fp.record_success("TEST-boston-chapter")
    await fp.record_failure("TEST-boston-chapter", "err1")
    await fp.record_failure("TEST-boston-chapter", "err2")
    await fp.record_failure("TEST-boston-chapter", "err3")
    await fp.record_success("TEST-boston-chapter")
    hist = await fp.history_for("TEST-boston-chapter")
    events = [h["event"] for h in hist]
    # Should have: seed, success, failure (degraded), quarantine, recover
    assert "seed" in events
    assert "quarantine" in events
    assert "recover" in events


# ── DID pinning: trust-on-first-use for attested peer identities ──


DID_A = "did:key:z6MkAAAAoriginalpeerkeyAAAA"
DID_B = "did:key:z6MkBBBBswappedbyregistryBB"


@pytest.mark.asyncio
async def test_first_attested_sighting_pins(env):
    """HAPPY: TOFU — first attested DID is persisted and history logs did_pin."""
    status, pinned = await fp.check_and_pin_did("acme", DID_A, "https://acme.example.com")
    assert (status, pinned) == ("pinned", DID_A)
    row = env.tables["federation_policy"][0]
    assert row["pinned_did"] == DID_A
    assert row["pinned_at"] is not None
    assert "did_pin" in [h["event"] for h in await fp.history_for("acme")]


@pytest.mark.asyncio
async def test_same_did_matches_pin(env):
    """HAPPY: re-discovery with the same DID is a match, not a re-pin."""
    await fp.check_and_pin_did("acme", DID_A)
    status, pinned = await fp.check_and_pin_did("acme", DID_A)
    assert (status, pinned) == ("match", DID_A)


@pytest.mark.asyncio
async def test_different_did_is_mismatch_and_pin_survives(env):
    """ADVERSARIAL: a registry re-keying a peer — mismatch reported, the
    original pin kept, and the swap is on the audit trail."""
    await fp.check_and_pin_did("acme", DID_A)
    status, pinned = await fp.check_and_pin_did("acme", DID_B)
    assert (status, pinned) == ("mismatch", DID_A)
    assert env.tables["federation_policy"][0]["pinned_did"] == DID_A
    assert "did_mismatch" in [h["event"] for h in await fp.history_for("acme")]


@pytest.mark.asyncio
async def test_clear_did_pin_allows_rotation(env):
    """HAPPY: leader clears the pin (accepting a key rotation) → next attested
    sighting pins the NEW key."""
    await fp.check_and_pin_did("acme", DID_A)
    result = await fp.clear_did_pin("acme", "leader-1")
    assert result["ok"]
    assert env.tables["federation_policy"][0]["pinned_did"] is None
    status, pinned = await fp.check_and_pin_did("acme", DID_B)
    assert (status, pinned) == ("pinned", DID_B)
    events = [h["event"] for h in await fp.history_for("acme")]
    assert "did_unpin" in events


@pytest.mark.asyncio
async def test_clear_did_pin_errors(env):
    """EDGE: clearing an unknown peer → not_found; an unpinned peer → not_pinned."""
    assert (await fp.clear_did_pin("ghost", "leader-1"))["error"] == "not_found"
    await fp.upsert_peer("acme")
    assert (await fp.clear_did_pin("acme", "leader-1"))["error"] == "not_pinned"


@pytest.mark.asyncio
async def test_pin_without_database_degrades():
    """EDGE: no Postgres → ("no_database", None), never raises."""
    fp.init(pg_request=None, agent_id="test-chapter")
    assert await fp.check_and_pin_did("acme", DID_A) == ("no_database", None)
    assert (await fp.clear_did_pin("acme", "leader-1"))["error"] == "no_database"
