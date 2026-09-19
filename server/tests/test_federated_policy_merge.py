"""
R1-R10 tests for federated_policy_merge.merge_peer_snapshots.

R1  Forgery            — peer claims unrealistic values
R2  Replay             — None (merge is stateless; replay is an upstream concern)
R3  Injection          — malformed PeerSnapshot fields
R4  Authorization      — merge respects baseline clamp (cannot escalate)
R5  Boundary           — at/over MIN_PEERS_FOR_MERGE, MIN_SAMPLES_FROM_PEER
R6  Concurrency        — merge is pure (no shared state)
R7  Adversarial        — MAD filter excludes outlier peer
R8  Downgrade          — merge is bounded by MAX_DELTA_FRACTION (±10%)
R9  Timing             — N/A (no time dependency; upstream handles)
R10 Persistence        — returns None when no change; explainable reason
"""

from __future__ import annotations

from federated_policy_merge import (
    BASELINE_MAX_FRACTION,
    BASELINE_MIN_FRACTION,
    MAD_THRESHOLD,
    MAX_DELTA_FRACTION,
    MIN_PEERS_FOR_MERGE,
    MIN_SAMPLES_FROM_PEER,
    PeerSnapshot,
    merge_peer_snapshots,
)


def _snap(chapter, key, value, sample_size=50, confidence=1.0):
    return PeerSnapshot(
        chapter_id=chapter,
        key=key,
        value=value,
        baseline=0.5,  # ignored in merge (we pass explicit baseline param)
        sample_size=sample_size,
        confidence=confidence,
    )


# ══════════════════════════════════════════════════════════════════════
# R1 — Forgery: peer claims wildly unrealistic value → MAD filter
# ══════════════════════════════════════════════════════════════════════


def test_R1_forgery_wild_outlier_excluded():
    # Honest peers are slightly above our current value — so a legitimate
    # merge should produce a non-None result; the test is that the outlier
    # doesn't move the merge dramatically.
    snaps = [
        _snap("boston", "intro.confidence_floor", 0.73),
        _snap("london", "intro.confidence_floor", 0.75),
        _snap("bangalore", "intro.confidence_floor", 0.74),
        _snap("attacker", "intro.confidence_floor", 99.9),  # obvious outlier
    ]
    result = merge_peer_snapshots("intro.confidence_floor", current_value=0.7, baseline=0.7, peer_snapshots=snaps)
    assert result is not None
    assert "attacker" in result.excluded_peers
    # Merged value stays near the honest peers (bounded by ±10% delta from 0.7)
    assert 0.7 < result.new_value <= 0.77
    # Crucially: nowhere near what the attacker claimed
    assert result.new_value < 1.0


# ══════════════════════════════════════════════════════════════════════
# R3 — Injection: mismatched key
# ══════════════════════════════════════════════════════════════════════


def test_R3_injection_mismatched_key_ignored():
    snaps = [
        _snap("boston", "other.key", 0.1),  # wrong key
        _snap("london", "other.key", 0.1),  # wrong key
    ]
    result = merge_peer_snapshots("intro.confidence_floor", 0.7, 0.7, snaps)
    assert result is None  # no relevant snapshots


# ══════════════════════════════════════════════════════════════════════
# R4 — Authorization: baseline clamp cannot be escaped
# ══════════════════════════════════════════════════════════════════════


def test_R4_authz_cannot_exceed_2x_baseline():
    # All peers agree on a value WAY above baseline — should clamp to 2x
    snaps = [
        _snap("a", "k", 10.0),  # 10x
        _snap("b", "k", 10.0),
        _snap("c", "k", 10.0),
    ]
    baseline = 0.5
    result = merge_peer_snapshots("k", current_value=0.6, baseline=baseline, peer_snapshots=snaps)
    assert result is not None
    # Even with unanimous peer majority, we clamp to baseline*2
    # BUT also clamped by ±10% from current (0.6) → at most 0.66.
    # So final is ~0.66, well within 2x baseline (=1.0)
    assert result.new_value <= baseline * BASELINE_MAX_FRACTION


def test_R4_authz_cannot_drop_below_0_5x_baseline():
    snaps = [_snap("a", "k", 0.01), _snap("b", "k", 0.01), _snap("c", "k", 0.01)]
    baseline = 0.5
    result = merge_peer_snapshots("k", current_value=0.4, baseline=baseline, peer_snapshots=snaps)
    assert result is not None
    # ±10% clamp also applies; 0.4 * 0.9 = 0.36 which is > 0.5*0.5 = 0.25
    # so the delta clamp wins, but test the invariant anyway
    assert result.new_value >= baseline * BASELINE_MIN_FRACTION


# ══════════════════════════════════════════════════════════════════════
# R5 — Boundary: MIN_PEERS_FOR_MERGE + MIN_SAMPLES_FROM_PEER
# ══════════════════════════════════════════════════════════════════════


def test_R5_boundary_below_min_peers_returns_none():
    snaps = [_snap("a", "k", 0.7)]  # only 1 peer
    assert merge_peer_snapshots("k", 0.7, 0.7, snaps) is None


def test_R5_boundary_exactly_min_peers_accepted():
    snaps = [_snap("a", "k", 0.8), _snap("b", "k", 0.8)]
    result = merge_peer_snapshots("k", 0.7, 0.7, snaps)
    assert result is not None


def test_R5_boundary_snapshot_below_min_samples_ignored():
    snaps = [
        _snap("a", "k", 0.8, sample_size=MIN_SAMPLES_FROM_PEER - 1),  # ignored
        _snap("b", "k", 0.8, sample_size=MIN_SAMPLES_FROM_PEER),
    ]
    # Only 'b' qualifies; below MIN_PEERS_FOR_MERGE → None
    result = merge_peer_snapshots("k", 0.7, 0.7, snaps)
    assert result is None


# ══════════════════════════════════════════════════════════════════════
# R6 — Concurrency: merge is stateless
# ══════════════════════════════════════════════════════════════════════


def test_R6_concurrency_merge_is_pure():
    snaps = [_snap("a", "k", 0.75), _snap("b", "k", 0.72), _snap("c", "k", 0.78)]
    results = [merge_peer_snapshots("k", 0.7, 0.7, snaps) for _ in range(10)]
    # All results identical
    assert all(r.new_value == results[0].new_value for r in results)


# ══════════════════════════════════════════════════════════════════════
# R7 — Adversarial: one outlier doesn't move the result much
# ══════════════════════════════════════════════════════════════════════


def test_R7_adversarial_one_evil_peer_cannot_swing_value():
    """One peer claiming a value very different from the rest is filtered.
    With 4 honest peers + 1 outlier, the merge should be dominated by the
    honest consensus."""
    snaps = [
        _snap("a", "k", 0.70),
        _snap("b", "k", 0.71),
        _snap("c", "k", 0.69),
        _snap("d", "k", 0.72),
        _snap("evil", "k", 5.0),  # wildly out of band
    ]
    result = merge_peer_snapshots("k", 0.7, 0.7, snaps)
    assert result is not None
    assert "evil" in result.excluded_peers
    # Merged value sits in the honest cluster, not between honest mean + 5
    assert 0.67 <= result.new_value <= 0.73


def test_R7_adversarial_unanimous_attackers_bounded_by_delta_clamp():
    """Even if ALL peers agree on a bad value, the ±10% delta clamp
    prevents a single-cycle jump past the local tuner's safety margin.
    This is defense-in-depth: MAD fails if the adversary controls
    enough peers, but the delta clamp still limits damage per cycle."""
    snaps = [_snap(f"p{i}", "k", 100.0) for i in range(5)]
    result = merge_peer_snapshots("k", current_value=0.7, baseline=0.7, peer_snapshots=snaps)
    assert result is not None
    # Must not exceed current + 10%
    assert result.new_value <= 0.7 * (1 + MAX_DELTA_FRACTION) + 1e-9


# ══════════════════════════════════════════════════════════════════════
# R8 — Downgrade: ±10% delta clamp
# ══════════════════════════════════════════════════════════════════════


def test_R8_downgrade_delta_clamp_upper_bound():
    snaps = [_snap(f"p{i}", "k", 2.0) for i in range(5)]
    result = merge_peer_snapshots("k", 1.0, baseline=1.0, peer_snapshots=snaps)
    assert result is not None
    assert result.new_value <= 1.1 + 1e-9


def test_R8_downgrade_delta_clamp_lower_bound():
    snaps = [_snap(f"p{i}", "k", 0.0) for i in range(5)]
    result = merge_peer_snapshots("k", 1.0, baseline=1.0, peer_snapshots=snaps)
    assert result is not None
    assert result.new_value >= 0.9 - 1e-9


# ══════════════════════════════════════════════════════════════════════
# R10 — Persistence: returns None for no-op; reason explains change
# ══════════════════════════════════════════════════════════════════════


def test_R10_persistence_no_change_returns_none():
    """If all peers agree exactly with our current value, merge returns
    None (no write to audit log)."""
    snaps = [_snap("a", "k", 0.5), _snap("b", "k", 0.5), _snap("c", "k", 0.5)]
    assert merge_peer_snapshots("k", 0.5, 0.5, snaps) is None


def test_R10_persistence_reason_is_explainable():
    snaps = [
        _snap("boston", "k", 0.72),
        _snap("london", "k", 0.73),
        _snap("tokyo", "k", 0.74),
    ]
    result = merge_peer_snapshots("k", 0.7, 0.7, snaps)
    assert result is not None
    assert "federation_merge" in result.reason
    # Reason should name contributing peers
    assert any(peer in result.reason for peer in ("boston", "london", "tokyo"))


# ══════════════════════════════════════════════════════════════════════
# HAPPY — kept last per R1-R10 ordering
# ══════════════════════════════════════════════════════════════════════


def test_happy_three_peer_consensus_moves_value_modestly():
    """3 peers all say 0.75; our value is 0.70 — we move toward 0.75,
    bounded by ±10% delta (so max 0.77)."""
    snaps = [_snap(c, "k", 0.75) for c in ("boston", "london", "tokyo")]
    result = merge_peer_snapshots("k", 0.7, 0.7, snaps)
    assert result is not None
    assert 0.7 < result.new_value <= 0.77
    assert sorted(result.contributing_peers) == ["boston", "london", "tokyo"]
    assert result.excluded_peers == []


def test_happy_module_constants_sensible():
    """Regression guard on the bounds constants — if these change, a lot
    of invariants downstream break."""
    assert MAX_DELTA_FRACTION == 0.10
    assert BASELINE_MIN_FRACTION == 0.5
    assert BASELINE_MAX_FRACTION == 2.0
    assert MAD_THRESHOLD == 3.0
    assert MIN_PEERS_FOR_MERGE >= 2
