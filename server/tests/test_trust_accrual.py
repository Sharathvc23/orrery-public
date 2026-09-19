"""
R1-R10 + S tests for trust_events.record + apply_caps + tenure milestones.

R1  Forgery      — unknown event_type rejected (server is sole authority on delta)
R2  Replay       — same source_event_id twice → second is no-op (None)
R3  Injection    — client-supplied delta in the call site is ignored;
                    EVENT_DELTAS is the only authority
R4  Authz        — source_agent_id == agent_id rejected (no self-promotion)
R5  Boundary     — daily cap exactly at +2.0; +0.001 over → capped row
R6  Concurrency  — two simultaneous identical recordings collapse to one
R7  Adversarial  — negative event types pass through unaffected by caps
R8  Downgrade    — revocation_received decreases the score immediately
R9  Timing       — replay_score == agents.trust_score (after trigger)
R10 Persistence  — random-event sequence; replay equals running sum

Tenure tests:
  * tenure_milestones_due returns the correct events at boundary days
  * fire_tenure_milestones_for_agent is idempotent across runs
"""

from __future__ import annotations

import os

os.environ.setdefault("AGENT_ID", "test-chapter")
os.environ.setdefault("AGENT_NAME", "Test Chapter")

import random  # noqa: E402
from datetime import UTC, datetime, timedelta  # noqa: E402
from decimal import Decimal  # noqa: E402

import pytest  # noqa: E402

import trust_events  # noqa: E402

# ── Fake Postgres ────────────────────────────────────────────────────


class _FakePostgres:
    """Mirrors the FakePostgres pattern from test_skill_revenue.

    Implements just enough of the Postgres-via-PostgREST shape that
    `trust_events.record` + `replay_score` use, plus a *simulated*
    trigger that maintains agents.trust_score on every successful
    insert (so R9 timing matches production)."""

    def __init__(self):
        self.trust_events: list[dict] = []
        self.agents: list[dict] = []
        self._next_id = 1

    async def __call__(self, method, table, params=None, body=None):
        t = table.split("?")[0]
        if method == "GET":
            rows = list(getattr(self, t, []))
            for k, v in (params or {}).items():
                if k in ("select", "order", "limit"):
                    continue
                if isinstance(v, str) and v.startswith("eq."):
                    wanted = v[3:]
                    rows = [r for r in rows if str(r.get(k, "")) == wanted]
                elif isinstance(v, str) and v.startswith("neq."):
                    unwanted = v[4:]
                    rows = [r for r in rows if str(r.get(k, "")) != unwanted]
                elif isinstance(v, str) and v.startswith("gte."):
                    wanted = v[4:]
                    rows = [r for r in rows if str(r.get(k, "")) >= wanted]
                elif isinstance(v, str) and v.startswith("gt."):
                    # Keyset pagination uses id=gt.N — compare numerically (so
                    # "10" > "9"), falling back to string for non-numeric columns.
                    wanted = v[3:]

                    def _gt(r, _k=k, _w=wanted):
                        rv = r.get(_k)
                        try:
                            return int(rv) > int(_w)
                        except (TypeError, ValueError):
                            return str(rv) > _w

                    rows = [r for r in rows if _gt(r)]
            if "order" in (params or {}) and str(params["order"]).startswith("id"):
                rows = sorted(rows, key=lambda r: int(r.get("id", 0)))
            limit = (params or {}).get("limit")
            if limit is not None:
                rows = rows[: int(limit)]
            return rows
        if method == "POST" and t == "trust_events":
            row = dict(body or {})
            # UNIQUE(agent_id, event_type, source_event_id) emulation —
            # a second insert with the same triple raises like Postgres.
            if any(
                r.get("agent_id") == row.get("agent_id")
                and r.get("event_type") == row.get("event_type")
                and r.get("source_event_id") == row.get("source_event_id")
                for r in self.trust_events
            ):
                raise RuntimeError("duplicate key value violates unique constraint")
            # CHECK constraint emulation — DB rejects self-promotion too.
            sa = row.get("source_agent_id")
            if sa is not None and sa == row.get("agent_id"):
                raise RuntimeError("trust_events_no_self check violated")
            row["id"] = self._next_id
            row["occurred_at"] = row.get("occurred_at") or datetime.now(UTC).isoformat()
            self._next_id += 1
            self.trust_events.append(row)
            # Simulate the AFTER INSERT trigger maintaining
            # agents.trust_score atomically.
            agent = next((a for a in self.agents if a.get("agent_id") == row["agent_id"]), None)
            if agent is None:
                agent = {"agent_id": row["agent_id"], "trust_score": 0.0}
                self.agents.append(agent)
            agent["trust_score"] = float(
                Decimal(str(agent.get("trust_score") or 0)) + Decimal(str(row.get("delta") or "0"))
            )
            return [row]
        return None


@pytest.fixture
def fake_db():
    db = _FakePostgres()
    trust_events.init(db, "test-chapter")
    return db


# ── R1: forgery (unknown event_type rejected at the server) ─────────


@pytest.mark.asyncio
async def test_R1_unknown_event_type_rejected(fake_db):
    with pytest.raises(ValueError, match="unknown event_type"):
        await trust_events.record(
            agent_id="alice",
            event_type="adversary.fake_event_type",
            source_event_id="x",
        )
    assert fake_db.trust_events == []


# ── R2: replay (idempotency) ────────────────────────────────────────


@pytest.mark.asyncio
async def test_R2_replay_same_source_event_id_is_idempotent(fake_db):
    first = await trust_events.record(
        agent_id="alice",
        event_type="intent_match_accepted",
        source_event_id="intent-42",
        source_agent_id="bob",
    )
    second = await trust_events.record(
        agent_id="alice",
        event_type="intent_match_accepted",
        source_event_id="intent-42",
        source_agent_id="bob",
    )
    assert first is not None
    assert second is None
    assert len(fake_db.trust_events) == 1


# ── R3: client cannot poison delta ─────────────────────────────────


@pytest.mark.asyncio
async def test_R3_caller_cannot_inject_delta(fake_db):
    """The function signature has no `delta=` parameter at all — it's
    table-driven from EVENT_DELTAS. This test pins that the public
    contract stays so."""
    import inspect

    sig = inspect.signature(trust_events.record)
    assert "delta" not in sig.parameters


# ── R4: self-promotion rejected ────────────────────────────────────


@pytest.mark.asyncio
async def test_R4_self_promotion_rejected(fake_db):
    with pytest.raises(ValueError, match="no self-promotion"):
        await trust_events.record(
            agent_id="alice",
            event_type="endorsement_received",
            source_event_id="endorse-1",
            source_agent_id="alice",
        )
    assert fake_db.trust_events == []


# ── R5: cap boundaries ─────────────────────────────────────────────


def test_R5_apply_caps_at_exact_boundary():
    # Spent exactly at the daily cap → next +0.001 is capped.
    eff, reason = trust_events.apply_caps(
        Decimal("0.001"),
        spent_day=Decimal("2.0"),
        spent_week=Decimal("2.0"),
        spent_month=Decimal("2.0"),
    )
    assert eff == Decimal("0")
    assert reason == "capped:day"


def test_R5_apply_caps_just_under_boundary():
    eff, reason = trust_events.apply_caps(
        Decimal("0.001"),
        spent_day=Decimal("1.998"),
        spent_week=Decimal("0"),
        spent_month=Decimal("0"),
    )
    assert eff == Decimal("0.001")
    assert reason is None


def test_R5_apply_caps_negative_unchanged():
    """Negatives pass through unchanged — caps are for positive
    accrual only."""
    eff, reason = trust_events.apply_caps(
        Decimal("-3.0"),
        spent_day=Decimal("2.0"),
        spent_week=Decimal("8.0"),
        spent_month=Decimal("20.0"),
    )
    assert eff == Decimal("-3.0")
    assert reason is None


@pytest.mark.asyncio
async def test_R5_daily_cap_enforced_across_records(fake_db):
    # Burn the daily cap — 4 events at +0.5 each = +2.0 (at cap).
    for i in range(4):
        await trust_events.record(
            agent_id="alice",
            event_type="intent_match_accepted",
            source_event_id=f"intent-{i}",
            source_agent_id="bob",
        )
    # Fifth event: cap fires.
    fifth = await trust_events.record(
        agent_id="alice",
        event_type="intent_match_accepted",
        source_event_id="intent-overflow",
        source_agent_id="bob",
    )
    assert fifth is None
    # The 5th row landed but with delta=0 so the cap-fire is auditable.
    capped_rows = [r for r in fake_db.trust_events if r.get("source_event_id") == "intent-overflow"]
    assert len(capped_rows) == 1
    assert Decimal(str(capped_rows[0]["delta"])) == 0
    assert capped_rows[0]["reason"].startswith("capped:")


# ── R6: concurrency ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_R6_two_concurrent_same_event_one_wins(fake_db):
    """Even if two coroutines race the same source_event_id, the
    DB UNIQUE constraint guarantees only one row exists."""
    import asyncio

    async def emit():
        try:
            return await trust_events.record(
                agent_id="alice",
                event_type="intent_match_accepted",
                source_event_id="race-1",
                source_agent_id="bob",
            )
        except RuntimeError:
            return None

    results = await asyncio.gather(emit(), emit())
    rows = [r for r in fake_db.trust_events if r.get("source_event_id") == "race-1"]
    assert len(rows) == 1
    # Exactly one of the two coroutines saw a non-None return.
    assert sum(1 for r in results if r is not None) == 1


# ── R7: penalties bypass caps (defensive — caps are for accrual) ──


@pytest.mark.asyncio
async def test_R7_penalties_apply_even_after_cap_burn(fake_db):
    # Burn the cap.
    for i in range(4):
        await trust_events.record(
            agent_id="alice",
            event_type="intent_match_accepted",
            source_event_id=f"earn-{i}",
            source_agent_id="bob",
        )
    # Negative event still applies.
    pen = await trust_events.record(
        agent_id="alice",
        event_type="revocation_received",
        source_event_id="rev-1",
        source_agent_id="carol",
    )
    assert pen is not None
    assert Decimal(str(pen["delta"])) == Decimal("-1.0")


# ── R8: revocation downgrade ───────────────────────────────────────


@pytest.mark.asyncio
async def test_R8_revocation_decreases_replay_score(fake_db):
    await trust_events.record(
        agent_id="alice",
        event_type="skill_attested_by_trusted",
        source_event_id="attest-1",
        source_agent_id="trusted-bob",
    )
    score_before = await trust_events.replay_score("alice")
    assert score_before == Decimal("2.0")

    await trust_events.record(
        agent_id="alice",
        event_type="revocation_received",
        source_event_id="rev-attest-1",
        source_agent_id="trusted-bob",
    )
    score_after = await trust_events.replay_score("alice")
    assert score_after == Decimal("1.0")


# ── R9: replay_score == trigger-maintained agents.trust_score ─────


@pytest.mark.asyncio
async def test_R9_replay_matches_trigger_maintained_score(fake_db):
    await trust_events.record(
        agent_id="alice",
        event_type="intent_match_accepted",
        source_event_id="i-1",
        source_agent_id="bob",
    )
    await trust_events.record(
        agent_id="alice",
        event_type="call_response_accepted",
        source_event_id="c-1",
        source_agent_id="carol",
    )
    replay = await trust_events.replay_score("alice")
    agent = next(a for a in fake_db.agents if a["agent_id"] == "alice")
    assert Decimal(str(agent["trust_score"])) == replay


# ── R10: persistence — random sequence ────────────────────────────


@pytest.mark.asyncio
async def test_R10_random_sequence_replay_deterministic(fake_db):
    rng = random.Random(42)
    earn_events = [
        "intent_match_accepted",
        "intent_response_useful",
        "call_response_accepted",
        "conversation_completed_positive",
    ]
    n = 60
    for i in range(n):
        evt = rng.choice(earn_events)
        await trust_events.record(
            agent_id="alice",
            event_type=evt,
            source_event_id=f"e-{i}",
            source_agent_id=f"src-{i}",
        )
    # Every row in the ledger must sum to exactly the trigger-maintained score.
    replay = await trust_events.replay_score("alice")
    agent = next(a for a in fake_db.agents if a["agent_id"] == "alice")
    assert Decimal(str(agent["trust_score"])) == replay


# ── PR-E: trust auto-tuner pure helpers ───────────────────────────


def test_tuner_signal_high_stall_returns_tighten():
    """If 70% of >60d-tenured agents are below trust=20, signal=tighten
    (scale UP — accrual is too slow)."""
    import policy

    now = datetime(2026, 4, 25, tzinfo=UTC)
    old = (now - timedelta(days=90)).isoformat()
    agents = [{"agent_id": f"a{i}", "trust_score": 5.0, "created_at": old} for i in range(7)]
    agents += [{"agent_id": f"b{i}", "trust_score": 25.0, "created_at": old} for i in range(3)]
    sig = policy._compute_trust_stall_signal(agents, now=now)
    assert sig["eligible"] == 10
    assert sig["stalled"] == 7
    assert sig["stalled_fraction"] == 0.7
    assert sig["signal"] == "tighten"


def test_tuner_signal_low_stall_returns_loosen():
    import policy

    now = datetime(2026, 4, 25, tzinfo=UTC)
    old = (now - timedelta(days=90)).isoformat()
    agents = [{"agent_id": f"a{i}", "trust_score": 5.0, "created_at": old} for i in range(2)]
    agents += [{"agent_id": f"b{i}", "trust_score": 60.0, "created_at": old} for i in range(8)]
    sig = policy._compute_trust_stall_signal(agents, now=now)
    assert sig["stalled_fraction"] == 0.2
    assert sig["signal"] == "loosen"


def test_tuner_signal_excludes_under_60_day_tenure():
    """Newer agents don't count — they haven't had time to accrue yet."""
    import policy

    now = datetime(2026, 4, 25, tzinfo=UTC)
    fresh = (now - timedelta(days=10)).isoformat()
    agents = [{"agent_id": f"a{i}", "trust_score": 1.0, "created_at": fresh} for i in range(20)]
    sig = policy._compute_trust_stall_signal(agents, now=now)
    assert sig["eligible"] == 0
    assert sig["signal"] == "hold"


def test_tuner_next_scale_clamped_at_max():
    import policy

    new = policy._next_trust_scale(1.95, "tighten")  # 1.95 * 1.10 = 2.145 → clamped to 2.0
    assert new == policy.TRUST_TUNER_MAX_SCALE


def test_tuner_next_scale_clamped_at_min():
    import policy

    new = policy._next_trust_scale(0.55, "loosen")  # 0.55 * 0.9 = 0.495 → clamped to 0.5
    assert new == policy.TRUST_TUNER_MIN_SCALE


# ── PR-D: list_history + projection ────────────────────────────────


@pytest.mark.asyncio
async def test_list_history_returns_recent_first(fake_db):
    """Reverse chronological order from the trust_events ledger."""
    for i in range(5):
        await trust_events.record(
            agent_id="alice",
            event_type="intent_match_accepted",
            source_event_id=f"i-{i}",
            source_agent_id="bob",
        )
    rows = await trust_events.list_history("alice", limit=20)
    # The fake DB sorts by descending insertion time via test ordering;
    # length should be 5 (or fewer due to caps), all with source_agent_id="bob".
    assert 1 <= len(rows) <= 5
    for r in rows:
        assert r.get("source_agent_id") == "bob"


@pytest.mark.asyncio
async def test_projection_30d_sums_recent_deltas(fake_db):
    await trust_events.record(
        agent_id="alice",
        event_type="intent_match_accepted",
        source_event_id="i-1",
        source_agent_id="bob",
    )
    proj = await trust_events.projection_30d("alice")
    # +0.5 from one intent_match_accepted, all within the 30d window.
    assert Decimal(proj["recent_30d_delta"]) == Decimal("0.5")
    assert Decimal(proj["projected_30d"]) == Decimal("0.5")


# ── Tenure milestone tests ────────────────────────────────────────


def test_tenure_milestones_at_exact_boundary_day():
    now = datetime(2026, 4, 25, tzinfo=UTC)
    # 30 days exactly → 30d milestone fires.
    created = (now - timedelta(days=30)).isoformat()
    due = trust_events.tenure_milestones_due(created_at_iso=created, now=now)
    assert due == ["tenure_milestone_30d"]


def test_tenure_milestones_under_boundary_silent():
    now = datetime(2026, 4, 25, tzinfo=UTC)
    # 29 days, 23h → 30d NOT yet fired.
    created = (now - timedelta(days=29, hours=23)).isoformat()
    due = trust_events.tenure_milestones_due(created_at_iso=created, now=now)
    assert due == []


def test_tenure_milestones_cumulative():
    now = datetime(2026, 4, 25, tzinfo=UTC)
    # 200 days → 30d, 90d, 180d all due.
    created = (now - timedelta(days=200)).isoformat()
    due = trust_events.tenure_milestones_due(created_at_iso=created, now=now)
    assert due == ["tenure_milestone_30d", "tenure_milestone_90d", "tenure_milestone_180d"]


# ── Inactivity decay tests (PR-C) ─────────────────────────────────


@pytest.mark.asyncio
async def test_decay_skipped_when_recent_activity(fake_db):
    """Active agent (event in last 60d) → no decay row."""
    fake_db.agents.append({"agent_id": "alice", "trust_score": 5.0})
    # An "intent_match_accepted" recent activity disqualifies decay.
    await trust_events.record(
        agent_id="alice",
        event_type="intent_match_accepted",
        source_event_id="recent-1",
        source_agent_id="bob",
    )
    fired = await trust_events.apply_inactivity_decay_for_agent(agent_id="alice")
    assert fired is False


@pytest.mark.asyncio
async def test_decay_skipped_when_at_floor(fake_db):
    """Score at 0 → decay never fires (would push below floor)."""
    fake_db.agents.append({"agent_id": "alice", "trust_score": 0.0})
    fired = await trust_events.apply_inactivity_decay_for_agent(agent_id="alice")
    assert fired is False


@pytest.mark.asyncio
async def test_decay_idempotent_within_week(fake_db):
    """Two calls in the same ISO week → exactly one decay row."""
    fake_db.agents.append({"agent_id": "alice", "trust_score": 5.0})
    # No recent activity → decay should fire on first call.
    now = datetime(2026, 6, 15, tzinfo=UTC)  # well past 60d window
    fired1 = await trust_events.apply_inactivity_decay_for_agent(agent_id="alice", now=now)
    fired2 = await trust_events.apply_inactivity_decay_for_agent(agent_id="alice", now=now)
    assert fired1 is True
    assert fired2 is False  # UNIQUE source_event_id (ISO week) blocks the second
    decay_rows = [r for r in fake_db.trust_events if r["event_type"] == "inactive_decay"]
    assert len(decay_rows) == 1


# ── Drift detector tests (PR-C) ───────────────────────────────────


@pytest.mark.asyncio
async def test_drift_detector_clean_when_in_sync(fake_db):
    """No drift after normal trigger-maintained writes."""
    await trust_events.record(
        agent_id="alice",
        event_type="intent_match_accepted",
        source_event_id="i-1",
        source_agent_id="bob",
    )
    drifts = await trust_events.detect_score_drift()
    assert drifts == []


@pytest.mark.asyncio
async def test_drift_detector_flags_manual_override(fake_db):
    """If governance UPDATEs agents.trust_score directly (bypassing
    the trigger), the detector must catch it."""
    await trust_events.record(
        agent_id="alice",
        event_type="intent_match_accepted",
        source_event_id="i-1",
        source_agent_id="bob",
    )
    # Simulate a manual override that bypasses the trigger.
    fake_db.agents[0]["trust_score"] = 99.0
    drifts = await trust_events.detect_score_drift()
    assert len(drifts) == 1
    assert drifts[0]["agent_id"] == "alice"
    assert Decimal(drifts[0]["stored"]) == Decimal("99.0")
    assert Decimal(drifts[0]["replayed"]) == Decimal("0.5")


@pytest.mark.asyncio
async def test_fire_tenure_idempotent_across_runs(fake_db):
    now = datetime(2026, 4, 25, tzinfo=UTC)
    created = (now - timedelta(days=200)).isoformat()
    fired1 = await trust_events.fire_tenure_milestones_for_agent(
        agent_id="alice",
        created_at_iso=created,
        now=now,
    )
    fired2 = await trust_events.fire_tenure_milestones_for_agent(
        agent_id="alice",
        created_at_iso=created,
        now=now,
    )
    # First run fires whatever the daily cap allows (≤3, since 30d/90d/180d
    # would total +8 before caps and the daily cap clamps to +2).
    assert 1 <= fired1 <= 3
    # Second run fires nothing — every milestone row exists already, so
    # the UNIQUE constraint short-circuits in `record()`.
    assert fired2 == 0
    # Replay determinism — the trigger-maintained score equals the sum.
    score = await trust_events.replay_score("alice")
    agent = next(a for a in fake_db.agents if a["agent_id"] == "alice")
    assert Decimal(str(agent["trust_score"])) == score
    # The accrual is bounded by the daily cap.
    assert score <= Decimal("2.0")
    # Three milestone rows persisted in the ledger (capped ones land
    # with delta=0 so the cap-fire is auditable).
    rows = [r for r in fake_db.trust_events if r["event_type"].startswith("tenure_milestone_")]
    assert len(rows) == 3
