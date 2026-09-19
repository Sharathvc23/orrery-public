"""GET /api/trust/drift-status — public, read-only replay-determinism check.

The full operator view (/api/admin/trust/drift) is admin-gated; this public
sibling lets a conformance verifier (or any auditor) confirm
``drift_count == 0`` without admin credentials — a chapter cannot hide trust
drift behind an admin gate. Same computation, no authorization.

Classification: HAPPY / EDGE / ADVERSARIAL.
"""

import os

os.environ.setdefault("AGENT_ID", "test-chapter")
os.environ.setdefault("AGENT_NAME", "Test Chapter")
os.environ.setdefault("XAI_API_KEY", "test-key")

import chapter_agent  # noqa: E402
import trust_events  # noqa: E402


async def test_drift_status_clean_is_zero(monkeypatch):  # HAPPY
    async def fake_drift():
        return []

    monkeypatch.setattr(trust_events, "detect_score_drift", fake_drift)
    result = await chapter_agent.trust_drift_status()
    assert result == {"drift_count": 0, "drifts": []}


async def test_drift_status_surfaces_drift(monkeypatch):  # EDGE — the public integrity signal
    async def fake_drift():
        return [{"agent_id": "a", "expected": 5, "actual": 7}]

    monkeypatch.setattr(trust_events, "detect_score_drift", fake_drift)
    result = await chapter_agent.trust_drift_status()
    assert result["drift_count"] == 1
    assert result["drifts"] == [{"agent_id": "a", "expected": 5, "actual": 7}]


def test_drift_status_is_not_auth_gated():  # ADVERSARIAL — must stay PUBLIC
    """The endpoint must not be in the auth-required GET set, and its handler
    must take no request (so it cannot call the admin gate). If a future change
    gates it, conformance test_T1 would 401 again — this pins it open."""
    import inspect

    import auth_verify

    required = getattr(auth_verify, "REQUIRE_AUTH_GET_PATHS", set())
    assert "/api/trust/drift-status" not in required
    assert list(inspect.signature(chapter_agent.trust_drift_status).parameters) == []
