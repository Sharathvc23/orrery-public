"""
Tests for policy.py — chapter hyperparameter auto-tuning + auto-promote.

Classification: HAPPY / EDGE / FAILURE / ADVERSARIAL
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

import policy


class _FakePostgres:
    def __init__(self):
        self.tables: dict[str, list[dict]] = {
            "chapter_policy": [],
            "chapter_policy_history": [],
            "agents": [],
            "chapter_role_nominations": [],
            "agent_action_outcomes": [],
            "pending_approvals": [],
            "chapter_calls": [],
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
        out = []
        for row in rows:
            ok = True
            for k, v in params.items():
                if k in ("select", "order", "limit"):
                    continue
                if not self._match(row, k, v):
                    ok = False
                    break
            if ok:
                out.append(row)
        return out

    @staticmethod
    def _match(row, key, predicate):
        if "." not in predicate:
            return row.get(key) == predicate
        op, val = predicate.split(".", 1)
        rv = row.get(key)
        if op == "eq":
            if val == "true":
                return rv is True
            if val == "false":
                return rv is False
            if val == "null":
                return rv is None
            return str(rv) == val
        if op == "gte":
            return str(rv) >= val
        if op == "in":
            return str(rv) in val.strip("()").split(",")
        return True


@pytest.fixture
def env():
    sb = _FakePostgres()
    policy.init(pg_request=sb, agent_id="test-chapter")
    policy.invalidate_cache()
    return sb


def _seed_policy(env, key, value, baseline=None, value_type="float", auto_tuned=True, pinned=False, last_updated=None):
    env.tables["chapter_policy"].append(
        {
            "chapter_id": "test-chapter",
            "key": key,
            "value": value,
            "baseline": baseline if baseline is not None else value,
            "value_type": value_type,
            "auto_tuned": auto_tuned,
            "pinned_by": "leader-1" if pinned else None,
            "last_updated": last_updated or (datetime.now(UTC) - timedelta(days=30)).isoformat(),
        }
    )


# ═══════════════════════════════════════════════
# READ + CACHE
# ═══════════════════════════════════════════════


@pytest.mark.asyncio
async def test_get_float_returns_cached_value(env):
    _seed_policy(env, "intro.confidence_floor", 0.65)
    v = await policy.get_float("intro.confidence_floor", 0.99)
    assert v == 0.65


@pytest.mark.asyncio
async def test_get_missing_key_returns_default(env):
    v = await policy.get_float("nonexistent.key", 0.42)
    assert v == 0.42


@pytest.mark.asyncio
async def test_get_bool_respects_type(env):
    _seed_policy(env, "autopromote.enabled", True, value_type="bool")
    assert await policy.get_bool("autopromote.enabled") is True


@pytest.mark.asyncio
async def test_get_int_coerces(env):
    _seed_policy(env, "intro.cooldown_days", 45, value_type="int")
    assert await policy.get_int("intro.cooldown_days", 30) == 45


# ═══════════════════════════════════════════════
# BOUNDS
# ═══════════════════════════════════════════════


def test_clamp_never_below_half_baseline():
    """C5: attempting to set value to 0.01 when baseline=0.5 clamps to 0.25 (0.5x)."""
    clamped = policy._clamp_numeric(0.01, 0.5)
    assert clamped == 0.25


def test_clamp_never_above_double_baseline():
    """C5: attempting 1000 when baseline=100 clamps to 200 (2x)."""
    clamped = policy._clamp_numeric(1000.0, 100.0)
    assert clamped == 200.0


def test_clamp_zero_baseline_no_op():
    """EDGE: baseline=0 disables bounds."""
    assert policy._clamp_numeric(42.0, 0.0) == 42.0


def test_step_tighten_raises_value():
    assert policy._step(0.5, "tighten") == pytest.approx(0.55)


def test_step_loosen_lowers_value():
    assert policy._step(0.5, "loosen") == pytest.approx(0.45)


def test_step_unknown_direction_noop():
    """ADVERSARIAL: unknown direction returns unchanged (no silent drift)."""
    assert policy._step(0.5, "sideways") == 0.5


# ═══════════════════════════════════════════════
# HEURISTIC PROPOSALS
# ═══════════════════════════════════════════════


def test_intro_tighten_on_high_rejection():
    """HAPPY: > 50% rejection rate tightens the confidence floor."""
    result = policy.propose_intro_adjustment(0.7, 0.7, approvals=2, rejections=8, expired=0)
    assert result is not None
    new_val, reason = result
    assert new_val > 0.7
    assert "tighten" in reason


def test_intro_loosen_on_high_approval():
    """HAPPY: > 85% approval + enough samples loosens."""
    result = policy.propose_intro_adjustment(0.7, 0.7, approvals=9, rejections=1, expired=0)
    assert result is not None
    new_val, reason = result
    assert new_val < 0.7
    assert "loosen" in reason


def test_intro_no_change_with_middling_rates():
    """EDGE: 60/40 acceptance → no tune."""
    result = policy.propose_intro_adjustment(0.7, 0.7, approvals=6, rejections=4, expired=0)
    assert result is None


def test_intro_skipped_when_below_min_samples():
    """EDGE: 3 total outcomes < AUTO_TUNE_MIN_SAMPLES → no tune."""
    result = policy.propose_intro_adjustment(0.7, 0.7, approvals=1, rejections=2, expired=0)
    assert result is None


def test_intro_clamped_on_extreme_tighten():
    """ADVERSARIAL: even with 100% rejection, new floor can't exceed 2x baseline."""
    # Hit the upper clamp: current already near max
    result = policy.propose_intro_adjustment(1.5, 0.7, approvals=0, rejections=10, expired=0)
    assert result is not None
    new_val, _ = result
    assert new_val <= 0.7 * 2.0 + 1e-9


def test_cooldown_extends_when_rejected_pairs_repeat():
    result = policy.propose_cooldown_adjustment(
        current_days=30,
        baseline_days=30,
        repeated_pair_rejections=5,
        window_days=14,
    )
    assert result is not None
    new_days, reason = result
    assert new_days > 30
    assert "extend" in reason.lower()


def test_cooldown_no_change_with_few_repeats():
    result = policy.propose_cooldown_adjustment(30, 30, repeated_pair_rejections=2, window_days=14)
    assert result is None


def test_relevance_floor_tightens_on_low_quality():
    """HAPPY: 80% low-quality responses → raise floor."""
    result = policy.propose_relevance_floor_adjustment(
        current_floor=0.5,
        baseline_floor=0.5,
        low_quality_responses=8,
        high_quality_responses=2,
        unreached_calls=0,
    )
    assert result is not None
    new_val, reason = result
    assert new_val > 0.5
    assert "tighten" in reason


def test_relevance_floor_loosens_when_calls_unreached():
    """HAPPY: many calls with no responses → lower floor to encourage matches."""
    result = policy.propose_relevance_floor_adjustment(
        current_floor=0.5,
        baseline_floor=0.5,
        low_quality_responses=0,
        high_quality_responses=0,
        unreached_calls=10,
    )
    assert result is not None
    new_val, reason = result
    assert new_val < 0.5
    assert "loosen" in reason


def test_relevance_floor_no_change_with_good_signal():
    """EDGE: mix of high quality + a few unreached → stable."""
    result = policy.propose_relevance_floor_adjustment(
        current_floor=0.5,
        baseline_floor=0.5,
        low_quality_responses=1,
        high_quality_responses=9,
        unreached_calls=2,
    )
    assert result is None


# ═══════════════════════════════════════════════
# TUNE CYCLE — integration with fake Postgres
# ═══════════════════════════════════════════════


@pytest.mark.asyncio
async def test_tune_cycle_skips_pinned(env):
    """ADVERSARIAL: pinned keys are not touched by auto-tune."""
    _seed_policy(env, "intro.confidence_floor", 0.7, pinned=True)
    # Seed heavy rejection signal
    for _ in range(20):
        env.tables["pending_approvals"].append(
            {
                "chapter_id": "test-chapter",
                "kind": "introduction",
                "status": "rejected",
                "created_at": datetime.now(UTC).isoformat(),
                "payload": {"pair": ["a", "b"]},
            }
        )
    result = await policy.tune_cycle()
    # intro.confidence_floor should NOT appear — it's pinned
    assert "intro.confidence_floor" not in result
    # value unchanged
    row = env.tables["chapter_policy"][0]
    assert row["value"] == 0.7


@pytest.mark.asyncio
async def test_tune_cycle_skips_within_warmup(env):
    """EDGE: key updated < 14 days ago is in warmup → no tune."""
    fresh = (datetime.now(UTC) - timedelta(days=3)).isoformat()
    _seed_policy(env, "intro.confidence_floor", 0.7, last_updated=fresh)
    for _ in range(20):
        env.tables["pending_approvals"].append(
            {
                "chapter_id": "test-chapter",
                "kind": "introduction",
                "status": "rejected",
                "created_at": datetime.now(UTC).isoformat(),
                "payload": {"pair": ["a", "b"]},
            }
        )
    result = await policy.tune_cycle()
    assert "intro.confidence_floor" not in result


@pytest.mark.asyncio
async def test_tune_cycle_tunes_confidence_floor_on_rejection(env):
    """HAPPY: out-of-warmup, unpinned, high rejection → tune fires and persists."""
    _seed_policy(env, "intro.confidence_floor", 0.7, baseline=0.7)
    for _ in range(20):
        env.tables["pending_approvals"].append(
            {
                "chapter_id": "test-chapter",
                "kind": "introduction",
                "status": "rejected",
                "created_at": datetime.now(UTC).isoformat(),
                "payload": {"pair": [f"a{_}", "b"]},
            }
        )
    result = await policy.tune_cycle()
    assert "intro.confidence_floor" in result
    new_value = env.tables["chapter_policy"][0]["value"]
    assert new_value > 0.7
    # History written
    hist = env.tables["chapter_policy_history"]
    assert any(h["key"] == "intro.confidence_floor" and "auto_tune" in h["reason"] for h in hist)


@pytest.mark.asyncio
async def test_tune_cycle_with_no_signal_no_change(env):
    """EDGE: 0 outcomes in window → all keys unchanged, no history rows."""
    _seed_policy(env, "intro.confidence_floor", 0.7)
    result = await policy.tune_cycle()
    assert result == {}
    assert env.tables["chapter_policy"][0]["value"] == 0.7


# ═══════════════════════════════════════════════
# PIN / UNPIN / OVERRIDE
# ═══════════════════════════════════════════════


@pytest.mark.asyncio
async def test_pin_freezes_key(env):
    _seed_policy(env, "intro.confidence_floor", 0.7)
    result = await policy.pin("intro.confidence_floor", "leader-1", reason="wait for more data")
    assert result["ok"]
    assert env.tables["chapter_policy"][0]["pinned_by"] == "leader-1"


@pytest.mark.asyncio
async def test_unpin_releases_key(env):
    _seed_policy(env, "intro.confidence_floor", 0.7, pinned=True)
    result = await policy.unpin("intro.confidence_floor", "leader-1")
    assert result["ok"]
    assert env.tables["chapter_policy"][0]["pinned_by"] is None


@pytest.mark.asyncio
async def test_pin_missing_key_returns_error(env):
    result = await policy.pin("nonexistent", "leader-1")
    assert result["error"] == "not_found"


@pytest.mark.asyncio
async def test_override_writes_history(env):
    _seed_policy(env, "approval.ttl_hours", 72, value_type="int", auto_tuned=False)
    await policy.override("approval.ttl_hours", 24, "admin-1", reason="weekend sprint")
    hist = env.tables["chapter_policy_history"]
    assert any(h["key"] == "approval.ttl_hours" and h["reason"].startswith("admin_override") for h in hist)


# ═══════════════════════════════════════════════
# AUTO-PROMOTE
# ═══════════════════════════════════════════════


@pytest.mark.asyncio
async def test_auto_promote_skipped_when_flag_off(env):
    """HAPPY default: autopromote.enabled=false short-circuits the cycle."""
    _seed_policy(env, "autopromote.enabled", False, value_type="bool", auto_tuned=False)
    env.tables["chapter_role_nominations"].append(
        {
            "id": "n1",
            "chapter_id": "test-chapter",
            "status": "pending",
            "nominee_agent_id": "alice",
            "target_role": "advisor",
            "endorsements": [{"signal": "up"}] * 5,
        }
    )
    env.tables["agents"].append(
        {
            "agent_id": "alice",
            "trust_score": 99.0,
            "created_at": (datetime.now(UTC) - timedelta(days=60)).isoformat(),
        }
    )
    result = await policy.auto_promote_cycle()
    assert result["reason"] == "flag_off"
    assert result["promoted"] == []


@pytest.mark.asyncio
async def test_auto_promote_advisor_when_all_thresholds_met(env):
    """HAPPY: trust 60 + 3 up endorsements + 30d tenure → auto-promoted to advisor."""
    _seed_policy(env, "autopromote.enabled", True, value_type="bool", auto_tuned=False)
    _seed_policy(env, "autopromote.advisor_trust_min", 50.0, value_type="float", auto_tuned=False)
    _seed_policy(env, "autopromote.advisor_endorsements_min", 2, value_type="int", auto_tuned=False)
    _seed_policy(env, "autopromote.advisor_tenure_days", 14, value_type="int", auto_tuned=False)
    env.tables["chapter_role_nominations"].append(
        {
            "id": "n1",
            "chapter_id": "test-chapter",
            "status": "pending",
            "nominee_agent_id": "alice",
            "target_role": "advisor",
            "endorsements": [{"signal": "up"}, {"signal": "up"}, {"signal": "up"}],
        }
    )
    env.tables["agents"].append(
        {
            "agent_id": "alice",
            "trust_score": 60.0,
            "chapter_role": "member",
            "created_at": (datetime.now(UTC) - timedelta(days=30)).isoformat(),
        }
    )
    result = await policy.auto_promote_cycle()
    assert len(result["promoted"]) == 1
    assert result["promoted"][0]["target_role"] == "advisor"
    # Nomination resolved
    nom = env.tables["chapter_role_nominations"][0]
    assert nom["status"] == "approved"
    # Agent role upgraded
    alice = env.tables["agents"][0]
    assert alice["chapter_role"] == "advisor"


@pytest.mark.asyncio
async def test_auto_promote_skips_below_trust(env):
    """ADVERSARIAL: trust below threshold → skipped with explanation."""
    _seed_policy(env, "autopromote.enabled", True, value_type="bool", auto_tuned=False)
    _seed_policy(env, "autopromote.advisor_trust_min", 50.0, value_type="float", auto_tuned=False)
    _seed_policy(env, "autopromote.advisor_endorsements_min", 2, value_type="int", auto_tuned=False)
    _seed_policy(env, "autopromote.advisor_tenure_days", 14, value_type="int", auto_tuned=False)
    env.tables["chapter_role_nominations"].append(
        {
            "id": "n1",
            "chapter_id": "test-chapter",
            "status": "pending",
            "nominee_agent_id": "bob",
            "target_role": "advisor",
            "endorsements": [{"signal": "up"}] * 5,
        }
    )
    env.tables["agents"].append(
        {
            "agent_id": "bob",
            "trust_score": 20.0,
            "chapter_role": "member",
            "created_at": (datetime.now(UTC) - timedelta(days=90)).isoformat(),
        }
    )
    result = await policy.auto_promote_cycle()
    assert result["promoted"] == []
    assert len(result["skipped"]) == 1
    assert "trust" in result["skipped"][0]["reason"]


@pytest.mark.asyncio
async def test_auto_promote_down_endorsements_cancel_up(env):
    """C5: net endorsements = up - down, so 3 up + 2 down = 1 net → below threshold=2."""
    _seed_policy(env, "autopromote.enabled", True, value_type="bool", auto_tuned=False)
    _seed_policy(env, "autopromote.advisor_trust_min", 50.0, value_type="float", auto_tuned=False)
    _seed_policy(env, "autopromote.advisor_endorsements_min", 2, value_type="int", auto_tuned=False)
    _seed_policy(env, "autopromote.advisor_tenure_days", 14, value_type="int", auto_tuned=False)
    env.tables["chapter_role_nominations"].append(
        {
            "id": "n1",
            "chapter_id": "test-chapter",
            "status": "pending",
            "nominee_agent_id": "carol",
            "target_role": "advisor",
            "endorsements": [
                {"signal": "up"},
                {"signal": "up"},
                {"signal": "up"},
                {"signal": "down"},
                {"signal": "down"},
            ],
        }
    )
    env.tables["agents"].append(
        {
            "agent_id": "carol",
            "trust_score": 80.0,
            "chapter_role": "member",
            "created_at": (datetime.now(UTC) - timedelta(days=90)).isoformat(),
        }
    )
    result = await policy.auto_promote_cycle()
    assert result["promoted"] == []
    assert "endorsements" in result["skipped"][0]["reason"]


@pytest.mark.asyncio
async def test_auto_promote_leader_requires_higher_bar(env):
    """EDGE: same nominee qualifies for advisor but not leader at same thresholds."""
    _seed_policy(env, "autopromote.enabled", True, value_type="bool", auto_tuned=False)
    _seed_policy(env, "autopromote.leader_trust_min", 75.0, value_type="float", auto_tuned=False)
    _seed_policy(env, "autopromote.leader_endorsements_min", 3, value_type="int", auto_tuned=False)
    _seed_policy(env, "autopromote.leader_tenure_days", 60, value_type="int", auto_tuned=False)
    env.tables["chapter_role_nominations"].append(
        {
            "id": "n1",
            "chapter_id": "test-chapter",
            "status": "pending",
            "nominee_agent_id": "dave",
            "target_role": "leader",
            "endorsements": [{"signal": "up"}, {"signal": "up"}],  # only 2, need 3
        }
    )
    env.tables["agents"].append(
        {
            "agent_id": "dave",
            "trust_score": 80.0,
            "chapter_role": "member",
            "created_at": (datetime.now(UTC) - timedelta(days=90)).isoformat(),
        }
    )
    result = await policy.auto_promote_cycle()
    assert result["promoted"] == []
    # Reason mentions endorsements shortfall
    assert any("endorsements" in s["reason"] for s in result["skipped"])
