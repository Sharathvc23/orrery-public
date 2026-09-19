"""
Tests for agent_telemetry.py — request metrics, evaluations, and telemetry.

Classification: HAPPY / EDGE / FAILURE / ADVERSARIAL
"""

import pytest

from agent_telemetry import AgentTelemetry


@pytest.fixture
def telem():
    return AgentTelemetry(max_samples=100)


# ── HAPPY: Latency and throughput ───────────────────────────


def test_latency_p50_p99(telem):
    """HAPPY: p50 and p99 latencies computed correctly."""
    for i in range(100):
        telem.record_request(float(i))  # 0-99ms

    result = telem.get_telemetry()
    assert result["latency_p50_ms"] == 50.0  # Median
    assert result["latency_p99_ms"] == 99.0  # 99th percentile


def test_error_rate_calculation(telem):
    """HAPPY: Error rate is accurate percentage."""
    for _ in range(80):
        telem.record_request(10.0, is_error=False)
    for _ in range(20):
        telem.record_request(10.0, is_error=True)

    result = telem.get_telemetry()
    assert result["error_rate_pct"] == 20.0


def test_throughput_rpm(telem):
    """HAPPY: Throughput RPM is computed from request count and uptime."""
    for _ in range(60):
        telem.record_request(5.0)

    result = telem.get_telemetry()
    # Should be > 0 RPM
    assert result["throughput_rpm"] > 0


def test_evaluations_formula(telem):
    """HAPPY: Performance score computed from activity + think cycles + reliability."""
    for _ in range(50):
        telem.record_request(10.0, is_error=False)

    evals = telem.get_evaluations(activity_score=50.0, think_cycles=100)

    assert 0 <= evals["performanceScore"] <= 5.0
    assert evals["totalInteractions"] == 50
    assert evals["avgResponseTimeMs"] == 10.0


def test_evaluations_high_activity(telem):
    """HAPPY: High activity score increases performance score."""
    low = telem.get_evaluations(activity_score=1.0, think_cycles=1)

    telem2 = AgentTelemetry()
    high = telem2.get_evaluations(activity_score=100.0, think_cycles=200)

    assert high["performanceScore"] > low["performanceScore"]


# ── EDGE: Empty state ───────────────────────────────────────


def test_empty_telemetry_no_crash(telem):
    """EDGE: No requests recorded returns null values, not crash."""
    result = telem.get_telemetry()

    assert result["enabled"] is True
    assert result["latency_p50_ms"] is None
    assert result["latency_p99_ms"] is None
    assert result["throughput_rpm"] is None
    assert result["last_updated"] is not None


def test_all_errors(telem):
    """EDGE: 100% error rate computed correctly."""
    for _ in range(10):
        telem.record_request(100.0, is_error=True)

    result = telem.get_telemetry()
    assert result["error_rate_pct"] == 100.0


# ── ADVERSARIAL: Bad inputs ─────────────────────────────────


def test_negative_latency_clamped(telem):
    """ADVERSARIAL: Negative latency clamped to 0, doesn't corrupt stats."""
    telem.record_request(-500.0)
    telem.record_request(100.0)

    result = telem.get_telemetry()
    assert result["latency_p50_ms"] >= 0


def test_massive_latency(telem):
    """ADVERSARIAL: Very large latency doesn't crash."""
    telem.record_request(999999999.0)
    result = telem.get_telemetry()
    assert result["latency_p50_ms"] == 999999999.0
