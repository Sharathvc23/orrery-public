"""Tests for chapter/metrics.py — Prometheus exposition format.

Covers:
- HAPPY: counters increment correctly; render shape is valid Prometheus text.
- HAPPY: gauges set/overwrite; federation peer state machine updates atomically.
- ADVERSARIAL: hostile reason strings (with quotes / control chars) are
  sanitized before reaching the label set.
- EDGE: render emits zero-baseline rows for counters that haven't been
  touched, so dashboards don't flap "no data" before first traffic.
- EDGE: chapter_id label propagates through every line of output.

Out of scope:
- The /metrics HTTP endpoint itself — covered by the conformance suite
  (test_R10_persistence_metrics_returns_prometheus_text).
"""

from __future__ import annotations

import pytest

import metrics


@pytest.fixture(autouse=True)
def _reset_metrics():
    """Each test runs against a fresh counter set."""
    metrics.reset_for_tests()
    yield
    metrics.reset_for_tests()


# ── HAPPY: counters increment + render ──────────────────────────


def test_render_emits_zero_baseline_when_no_traffic():
    out = metrics.render(chapter_id="bay")
    assert "nanda_chapter_signing_failures_total" in out
    assert "nanda_chapter_tofu_bootstraps_total" in out
    # Each counter has at least one zero baseline line so dashboards see
    # "0 events" rather than "no data".
    assert 'nanda_chapter_tofu_bootstraps_total{chapter_id="bay"} 0' in out


def test_record_request_buckets_by_status_class():
    metrics.record_request("POST", 200)
    metrics.record_request("POST", 201)  # also 2xx
    metrics.record_request("POST", 401)
    out = metrics.render(chapter_id="bay")
    assert 'nanda_chapter_requests_total{chapter_id="bay",method="POST",status_class="2xx"} 2' in out
    assert 'nanda_chapter_requests_total{chapter_id="bay",method="POST",status_class="4xx"} 1' in out


def test_record_signing_failure_groups_by_reason():
    metrics.record_signing_failure("invalid_signature")
    metrics.record_signing_failure("invalid_signature")
    metrics.record_signing_failure("key_mismatch")
    out = metrics.render(chapter_id="bay")
    assert 'nanda_chapter_signing_failures_total{chapter_id="bay",reason="invalid_signature"} 2' in out
    assert 'nanda_chapter_signing_failures_total{chapter_id="bay",reason="key_mismatch"} 1' in out


def test_record_tofu_and_key_mismatch_increments_specific_counters():
    metrics.record_tofu_bootstrap()
    metrics.record_tofu_bootstrap()
    metrics.record_key_mismatch()
    out = metrics.render(chapter_id="bay")
    assert 'nanda_chapter_tofu_bootstraps_total{chapter_id="bay"} 2' in out
    assert 'nanda_chapter_tofu_key_mismatches_total{chapter_id="bay"} 1' in out


def test_record_rate_limit_capacity_rejection_has_zero_baseline_and_increments():
    name = "nanda_chapter_rate_limit_capacity_rejections_total"
    out = metrics.render(chapter_id="bay")
    assert f"# HELP {name} " in out
    assert f"# TYPE {name} counter" in out
    assert f'{name}{{chapter_id="bay"}} 0' in out

    metrics.record_rate_limit_capacity_rejection()
    out = metrics.render(chapter_id="bay")
    assert f'{name}{{chapter_id="bay"}} 1' in out


# ── HAPPY: gauges + federation state machine ───────────────────


def test_set_members_total_updates_gauge():
    metrics.set_members_total(42)
    out = metrics.render(chapter_id="bay")
    assert 'nanda_chapter_members_total{chapter_id="bay"} 42' in out

    metrics.set_members_total(43)
    out = metrics.render(chapter_id="bay")
    assert 'nanda_chapter_members_total{chapter_id="bay"} 43' in out
    # Old value is replaced, not appended.
    assert out.count("nanda_chapter_members_total{chapter_id=") == 1


def test_set_federation_state_resets_other_states_for_same_peer():
    """A peer in state=online MUST have value 1 for online and 0 for
    degraded/offline. Otherwise a Grafana panel summing over states
    will double-count during transitions.
    """
    metrics.set_federation_state("london", "online")
    out = metrics.render(chapter_id="bay")
    assert 'peer="london",state="online"} 1' in out
    assert 'peer="london",state="degraded"} 0' in out
    assert 'peer="london",state="offline"} 0' in out

    metrics.set_federation_state("london", "degraded")
    out = metrics.render(chapter_id="bay")
    assert 'peer="london",state="online"} 0' in out
    assert 'peer="london",state="degraded"} 1' in out


# ── ADVERSARIAL: input sanitization ─────────────────────────────


def test_record_signing_failure_sanitizes_hostile_reason():
    """A hostile or unexpected `reason` (e.g. injected via a malformed
    header) must not break the Prometheus text format. We pin the
    sanitization to alnum + underscore — anything else is stripped or
    replaced with 'unknown'.
    """
    metrics.record_signing_failure('"; DROP TABLE foo; --')
    out = metrics.render(chapter_id="bay")
    # The dangerous chars must not appear in the rendered output.
    assert '"; DROP' not in out
    # We DO see the sanitized form (alnum survivors).
    assert 'reason="DROPTABLEfoo"' in out or 'reason="DROPTABLE"' in out


def test_record_signing_failure_with_empty_reason_uses_unknown():
    metrics.record_signing_failure("")
    out = metrics.render(chapter_id="bay")
    assert 'reason="unknown"' in out


def test_set_federation_state_strips_quote_chars_in_peer_name():
    metrics.set_federation_state('peer"injected', "online")
    out = metrics.render(chapter_id="bay")
    # Quote stripped — Prometheus label values cannot legally contain
    # unescaped quotes, and we avoid both injection and parse breakage.
    assert "peerinjected" in out
    assert 'peer"injected' not in out


# ── EDGE: chapter_id label is mandatory and consistent ─────────


def test_chapter_id_label_present_on_every_metric_line():
    metrics.record_request("GET", 200)
    metrics.record_tofu_bootstrap()
    metrics.set_members_total(5)
    metrics.set_federation_state("london", "online")
    out = metrics.render(chapter_id="bay")
    # Every non-comment, non-empty line carrying the metric value must
    # mention chapter_id="bay" so multi-chapter aggregation queries are
    # uniformly labelled.
    for line in out.splitlines():
        if line.startswith("#") or not line.strip():
            continue
        assert 'chapter_id="bay"' in line, f"missing chapter_id label on: {line}"


def test_render_with_empty_chapter_id_omits_label_cleanly():
    """Operator may render without a chapter_id during boot before
    AGENT_ID is set. Output must still parse."""
    metrics.record_tofu_bootstrap()
    out = metrics.render(chapter_id="")
    assert "nanda_chapter_tofu_bootstraps_total 1" in out
    # And no malformed `{}` either.
    assert "{}" not in out


def test_render_text_format_has_help_and_type_for_every_counter():
    out = metrics.render(chapter_id="bay")
    for name in (
        "nanda_chapter_requests_total",
        "nanda_chapter_signing_failures_total",
        "nanda_chapter_tofu_bootstraps_total",
        "nanda_chapter_tofu_key_mismatches_total",
        "nanda_chapter_replay_rejections_total",
        "nanda_chapter_rate_limit_capacity_rejections_total",
        "nanda_chapter_members_total",
        "nanda_chapter_federation_peer_state",
    ):
        assert f"# HELP {name}" in out, f"missing HELP for {name}"
        assert f"# TYPE {name}" in out, f"missing TYPE for {name}"
