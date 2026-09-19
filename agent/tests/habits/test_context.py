"""Tests for habits.context.fingerprint_context — deterministic fingerprint.

Coverage:

  R1  Forgery — user cannot spoof fingerprint via focused_app input;
      the hash of different inputs is different
  R3  Injection — unicode / control chars in focused_app are data
      (get hashed, don't crash)
  R5  Boundary — hour 0, hour 23; weekday 0 (Mon), weekday 6 (Sun)
      all produce distinct fingerprints
  R6  Concurrency — pure function, stateless
  R9  Timing — deterministic: same inputs → same sha256
  R10 Persistence — the fingerprint depends ONLY on the documented
      inputs; sanity check: changing one input changes the hash
"""

from __future__ import annotations

from datetime import UTC, datetime

from community_member.habits.context import (
    ActionHistoryRef,
    fingerprint_context,
)


def _t(hour=12, day_index=0):
    """Build a datetime for a specific hour/weekday (2026 has Jan 5 = Mon)."""
    # 2026-01-05 was a Monday. Adding day_index advances through the week.
    return datetime(2026, 1, 5 + day_index, hour, 0, tzinfo=UTC)


# ── R9: deterministic ────────────────────────────────────────────


def test_R9_same_inputs_same_hash():
    fp1 = fingerprint_context(now=_t(), focused_app="Chrome")
    fp2 = fingerprint_context(now=_t(), focused_app="Chrome")
    assert fp1.sha256 == fp2.sha256


def test_R9_inputs_are_exposed():
    fp = fingerprint_context(now=_t(hour=15), focused_app="Slack")
    assert fp.inputs["hour_of_day"] == 15
    assert fp.inputs["focused_app"] == "Slack"


# ── R5: boundary — hour + weekday distinctness ─────────────────


def test_R5_hour_0_vs_23():
    a = fingerprint_context(now=_t(hour=0), focused_app="x")
    b = fingerprint_context(now=_t(hour=23), focused_app="x")
    assert a.sha256 != b.sha256


def test_R5_different_weekdays_different_fingerprint():
    mon = fingerprint_context(now=_t(day_index=0), focused_app="x")  # Mon
    sun = fingerprint_context(now=_t(day_index=6), focused_app="x")  # Sun
    assert mon.sha256 != sun.sha256


def test_R5_same_hour_same_weekday_different_week_same_fingerprint():
    """Hour + weekday only — absolute date does NOT leak into the
    fingerprint. Reading arxiv at 2 AM Saturday should bucket together
    whether it's this week or next."""
    # Two Mondays at noon, a week apart.
    a = fingerprint_context(now=datetime(2026, 1, 5, 12, tzinfo=UTC), focused_app="x")
    b = fingerprint_context(now=datetime(2026, 1, 12, 12, tzinfo=UTC), focused_app="x")
    assert a.sha256 == b.sha256


# ── R1 / R7: different inputs → different fingerprint ────────


def test_R1_focused_app_change_shifts_fingerprint():
    a = fingerprint_context(now=_t(), focused_app="Chrome")
    b = fingerprint_context(now=_t(), focused_app="Slack")
    assert a.sha256 != b.sha256


def test_R1_prior_actions_change_shifts_fingerprint():
    priors_a = [ActionHistoryRef("browser.navigate", "https://a")]
    priors_b = [ActionHistoryRef("browser.navigate", "https://b")]
    a = fingerprint_context(now=_t(), focused_app="x", prior_actions=priors_a)
    b = fingerprint_context(now=_t(), focused_app="x", prior_actions=priors_b)
    assert a.sha256 != b.sha256


# ── Prior actions are capped at 3 ────────────────────────────


def test_prior_actions_beyond_3_dont_affect_fingerprint():
    """Only the last 3 priors count. A 5th-back action should not
    shift the fingerprint so momentary deep history doesn't destabilize
    the bucket."""
    base = [ActionHistoryRef("c", f"s{i}") for i in range(3)]
    extended = [ActionHistoryRef("c", "old0"), ActionHistoryRef("c", "old1"), *base]
    a = fingerprint_context(now=_t(), focused_app="x", prior_actions=base)
    b = fingerprint_context(now=_t(), focused_app="x", prior_actions=extended)
    # Both truncate to the same last-3, so same fingerprint.
    assert a.sha256 == b.sha256


# ── R3: weird inputs are data, don't crash ──────────────────


def test_R3_unicode_focused_app():
    fp = fingerprint_context(now=_t(), focused_app="中文 💻 \x00control")
    # 64 hex chars.
    assert len(fp.sha256) == 64


def test_R3_empty_prior_actions_list():
    # Empty list is distinct from None (both fall through to ()).
    a = fingerprint_context(now=_t(), focused_app="x", prior_actions=None)
    b = fingerprint_context(now=_t(), focused_app="x", prior_actions=[])
    assert a.sha256 == b.sha256


# ── R6: no module state ─────────────────────────────────────


def test_R6_pure_function_no_state():
    results = {fingerprint_context(now=_t(), focused_app="Chrome").sha256 for _ in range(20)}
    assert len(results) == 1  # all identical


# ── R10: the documented inputs are the ONLY inputs ──────────


def test_R10_fingerprint_inputs_match_documented_fields():
    fp = fingerprint_context(now=_t(hour=9), focused_app="Chrome")
    assert set(fp.inputs.keys()) == {
        "hour_of_day",
        "day_of_week",
        "focused_app",
        "prior_actions_sha256",
    }


def test_fingerprint_is_frozen():
    fp = fingerprint_context(now=_t(), focused_app="x")
    try:
        fp.sha256 = "tampered"  # type: ignore[misc]
    except (AttributeError, TypeError):
        return  # expected
    raise AssertionError("ContextFingerprint should be frozen")
