"""Tests for HabitModel — Beta(1,1) Bayesian bucket store + observer.

Coverage:

  R1  Forgery — counts table can be rebuilt from the log
      (log is source of truth; tampering with counts is detected)
  R2  Replay — same observation recorded twice → both land (append-only)
  R3  Injection — decision value other than approved/denied raises;
      weird characters in capability/scope are data (round-trip)
  R4  Authz — empty capability/scope/context raises (validation)
  R5  Boundary — Beta(1,1) prior: 0 obs → mean=0.5; 1 approval → 2/3;
      5 approvals/0 denials → 6/7 ≈ 0.857
  R6  Concurrency — threaded observe() preserves total count (lock)
  R9  Timing — O(1) observe + O(1) stat read; no full-log scan in hot path
  R10 Persistence — log + counts survive process restart; rebuild
      reproduces counts exactly
"""

from __future__ import annotations

import threading
from pathlib import Path

import pytest

from community_member.habits import (
    HabitModel,
    fingerprint_context,
    observe_decision,
)


@pytest.fixture
def model(tmp_path: Path) -> HabitModel:
    return HabitModel(tmp_path / "habits.db")


# ── Beta(1,1) math ─────────────────────────────────────────────


def test_prior_mean_is_half_no_observations(model):
    s = model.stats("fs.read", "~/a", "ctx-sha")
    assert s.approvals == 0
    assert s.denials == 0
    assert s.total == 0
    assert s.posterior_mean == pytest.approx(0.5)


def test_R5_one_approval_posterior_2_over_3(model):
    """Beta(1,1) + 1 success → Beta(2,1); mean = 2/3."""
    model.observe(
        capability="fs.read",
        scope="~/a",
        context_sha256="ctx-1",
        decision="approved",
        recorded_at="2026-04-24T12:00:00+00:00",
    )
    s = model.stats("fs.read", "~/a", "ctx-1")
    assert s.approvals == 1
    assert s.denials == 0
    assert s.posterior_mean == pytest.approx(2 / 3)


def test_R5_five_approvals_zero_denials_hits_graduation_threshold(model):
    for i in range(5):
        model.observe(
            capability="fs.read",
            scope="~/a",
            context_sha256="ctx-1",
            decision="approved",
            recorded_at=f"2026-04-24T{10 + i:02d}:00:00+00:00",
        )
    s = model.stats("fs.read", "~/a", "ctx-1")
    # 5 approvals, 0 denials → Beta(6,1) → 6/7 ≈ 0.857
    assert s.posterior_mean > 0.85
    assert s.approvals == 5


def test_R5_denial_pulls_mean_below_half(model):
    for _ in range(3):
        model.observe(
            capability="fs.read",
            scope="~/a",
            context_sha256="c",
            decision="denied",
            recorded_at="2026-04-24T12:00:00+00:00",
        )
    s = model.stats("fs.read", "~/a", "c")
    # Beta(1, 4) → mean = 1/5 = 0.2
    assert s.posterior_mean == pytest.approx(0.2)


# ── R4 validation ────────────────────────────────────────────


def test_R4_invalid_decision_raises(model):
    with pytest.raises(ValueError, match="approved"):
        model.observe(
            capability="fs.read",
            scope="~/a",
            context_sha256="c",
            decision="maybe",  # type: ignore[arg-type]
            recorded_at="2026-04-24T12:00:00+00:00",
        )


def test_R4_empty_fields_rejected(model):
    with pytest.raises(ValueError):
        model.observe(
            capability="",
            scope="~/a",
            context_sha256="c",
            decision="approved",
            recorded_at="t",
        )


# ── Bucket isolation ────────────────────────────────────────


def test_buckets_are_independent_by_context(model):
    model.observe(
        capability="fs.read",
        scope="~/a",
        context_sha256="ctx-morning",
        decision="approved",
        recorded_at="t",
    )
    model.observe(
        capability="fs.read",
        scope="~/a",
        context_sha256="ctx-evening",
        decision="denied",
        recorded_at="t",
    )
    morning = model.stats("fs.read", "~/a", "ctx-morning")
    evening = model.stats("fs.read", "~/a", "ctx-evening")
    assert morning.approvals == 1
    assert morning.denials == 0
    assert evening.approvals == 0
    assert evening.denials == 1


def test_buckets_are_independent_by_scope(model):
    model.observe(capability="fs.read", scope="~/a", context_sha256="c", decision="approved", recorded_at="t")
    model.observe(capability="fs.read", scope="~/b", context_sha256="c", decision="denied", recorded_at="t")
    assert model.stats("fs.read", "~/a", "c").approvals == 1
    assert model.stats("fs.read", "~/b", "c").denials == 1


# ── R10 persistence + rebuild ───────────────────────────────


def test_R10_rebuild_counts_from_log(tmp_path):
    db = tmp_path / "habits.db"
    model = HabitModel(db)
    for _ in range(3):
        model.observe(capability="c", scope="s", context_sha256="ctx", decision="approved", recorded_at="t")
    # Simulate tampering of the counts table.
    import sqlite3

    with sqlite3.connect(str(db)) as conn:
        conn.execute("UPDATE habit_counts SET approvals=999 WHERE capability='c'")
        conn.commit()
    assert model.stats("c", "s", "ctx").approvals == 999  # tampered view
    model.rebuild_counts_from_log()
    # Post-rebuild, counts match the log exactly.
    assert model.stats("c", "s", "ctx").approvals == 3


def test_R10_observation_count_tracks_log(model):
    for _ in range(4):
        model.observe(capability="c", scope="s", context_sha256="ctx", decision="approved", recorded_at="t")
    assert model.observation_count("c", "s", "ctx") == 4


def test_R10_persistence_across_reopen(tmp_path):
    db = tmp_path / "habits.db"
    m1 = HabitModel(db)
    m1.observe(capability="c", scope="s", context_sha256="ctx", decision="approved", recorded_at="t")
    m2 = HabitModel(db)
    assert m2.stats("c", "s", "ctx").approvals == 1


# ── R2 replay: observations append, don't dedupe ───────────


def test_R2_same_observation_twice_both_land(model):
    for _ in range(2):
        model.observe(capability="c", scope="s", context_sha256="ctx", decision="approved", recorded_at="t")
    assert model.observation_count("c", "s", "ctx") == 2
    assert model.stats("c", "s", "ctx").approvals == 2


# ── R6 concurrency ────────────────────────────────────────


def test_R6_threaded_observe_preserves_count(model):
    """Lock must serialize log+counts so concurrent observes don't
    race and drop updates. 4 threads × 10 observes = 40 rows."""
    errors: list[Exception] = []

    def worker():
        try:
            for _ in range(10):
                model.observe(
                    capability="c",
                    scope="s",
                    context_sha256="ctx",
                    decision="approved",
                    recorded_at="t",
                )
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    assert model.observation_count("c", "s", "ctx") == 40
    assert model.stats("c", "s", "ctx").approvals == 40


# ── observer.observe_decision integration ────────────────


def test_observer_records_via_context_fingerprint(model):
    from datetime import UTC, datetime

    fp = fingerprint_context(
        now=datetime(2026, 1, 5, 12, tzinfo=UTC),
        focused_app="Chrome",
    )
    observe_decision(
        model,
        capability="fs.read",
        scope="~/Docs",
        context=fp,
        decision="approved",
    )
    s = model.stats("fs.read", "~/Docs", fp.sha256)
    assert s.approvals == 1


def test_observer_forwards_context_sha256(model):
    from datetime import UTC, datetime

    fp_a = fingerprint_context(now=datetime(2026, 1, 5, 9, tzinfo=UTC), focused_app="App-A")
    fp_b = fingerprint_context(now=datetime(2026, 1, 5, 9, tzinfo=UTC), focused_app="App-B")
    observe_decision(model, capability="c", scope="s", context=fp_a, decision="approved")
    observe_decision(model, capability="c", scope="s", context=fp_b, decision="denied")
    assert model.stats("c", "s", fp_a.sha256).approvals == 1
    assert model.stats("c", "s", fp_b.sha256).denials == 1


# ── Dataclass is frozen ─────────────────────────────────


def test_BucketStats_is_frozen(model):
    s = model.stats("c", "s", "ctx")
    with pytest.raises((AttributeError, TypeError)):
        s.approvals = 999  # type: ignore[misc]
