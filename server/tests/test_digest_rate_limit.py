"""Per-path tight rate limit on /api/digest/build.

The generic 30/min POST ceiling is fine for normal writes, but a
digest build reads 5000 event_log rows + asks the LLM to summarise.
A runaway script can melt the LLM bill or pin DB connections in
seconds, even WITHIN the 30/min budget.

This test pins the new EXPENSIVE_WRITE_LIMITS map: /api/digest/build
gets 5/min by default (configurable via the map). Other POSTs still
use the generic 30/min ceiling.
"""

from __future__ import annotations

import os

os.environ.setdefault("AGENT_ID", "test-chapter")
os.environ.setdefault("AGENT_NAME", "Test Chapter")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

import auth_verify  # noqa: E402
import chapter_agent  # noqa: E402


@pytest.fixture
def client(monkeypatch):
    """TestClient with a clean rate-limit bucket per test.

    /api/digest/build requires a credential (audit M11), so the digest
    requests below carry the operator bearer — through the REAL middleware
    and the real handler check, not an is_open_path override. This fixture
    used to open the path by monkeypatching the classifier; the handler now
    refuses an anonymous caller on its own, so that bypass would 401 before
    reaching the rate-limit assertions.
    """
    chapter_agent._rate_limit_store.clear()

    # Known bearer token for the digest calls (the middleware and the handler
    # both verify it against the admin module).
    from tests._admin_fixtures import initialize_admin_token

    initialize_admin_token(monkeypatch)

    # /api/members is self-signed-open already; it is the "other write" the
    # generic-ceiling test drives.
    real_is_open = auth_verify.is_open_path

    def _open_for_test(method: str, path: str) -> bool:
        if path in ("/api/members", "/api/members/"):
            return True
        return real_is_open(method, path)

    monkeypatch.setattr(auth_verify, "is_open_path", _open_for_test)

    # Stub digest builder so we don't actually call Postgres.
    async def _fake_build(window_days: int = 7) -> dict:
        return {
            "window_start": "2026-05-04T00:00:00+00:00",
            "window_end": "2026-05-11T00:00:00+00:00",
            "new_member_count": 0,
            "intent_published_count": 0,
            "intent_matched_count": 0,
            "top_intents": [],
            "new_members": [],
            "federation_changes": [],
            "headline": "stub",
            "summary_markdown": "stub",
        }

    monkeypatch.setattr(chapter_agent.digest_mod, "build_digest", _fake_build)
    yield TestClient(chapter_agent.app)
    chapter_agent._rate_limit_store.clear()


def _digest_body() -> dict:
    return {"window_days": 1, "publish": False}


_BEARER = {"X-Admin-Token": "f" * 64}


# ── Tight ceiling on /api/digest/build ──────────────────────────────


def test_digest_build_has_tight_per_path_ceiling(client, monkeypatch):
    """EXPENSIVE_WRITE_LIMITS maps /api/digest/build → 5. After 5
    consecutive POSTs within a window, the 6th must return 429 with
    the documented headers."""
    monkeypatch.setitem(chapter_agent.EXPENSIVE_WRITE_LIMITS, "/api/digest/build", 3)

    # 3 builds allowed (the configured ceiling).
    for i in range(3):
        resp = client.post("/api/digest/build", json=_digest_body(), headers=_BEARER)
        assert resp.status_code == 200, f"build {i + 1} unexpectedly throttled: {resp.text[:200]}"

    # 4th hits 429 — the tight ceiling fires BEFORE the generic 30/min.
    resp = client.post("/api/digest/build", json=_digest_body(), headers=_BEARER)
    assert resp.status_code == 429
    body = resp.json()
    assert "rate" in body["error"].lower()
    assert body.get("limit_per_window") == 3
    assert body.get("window_seconds") == chapter_agent.RATE_LIMIT_WINDOW
    assert resp.headers.get("Retry-After") == str(chapter_agent.RATE_LIMIT_WINDOW)


def test_digest_build_default_ceiling_is_5(client):
    """Documented default: 5 per minute. A future tuning must update
    EXPENSIVE_WRITE_LIMITS, not silently lower the value here."""
    assert chapter_agent.EXPENSIVE_WRITE_LIMITS["/api/digest/build"] == 5


# ── Generic ceiling still applies to other writes ───────────────────


def test_other_writes_keep_generic_ceiling(client, monkeypatch):
    """A POST that isn't in EXPENSIVE_WRITE_LIMITS uses the generic
    30/min ceiling, NOT the tighter digest ceiling. We don't want the
    map to accidentally apply to siblings via fuzzy matching."""
    # Set a SUPER-tight digest ceiling — but the test path is /api/feedback,
    # which is unrelated; it should still allow 30+ requests.
    monkeypatch.setitem(chapter_agent.EXPENSIVE_WRITE_LIMITS, "/api/digest/build", 1)
    # Override the generic limit to a small number so the test is fast.
    monkeypatch.setattr(chapter_agent, "RATE_LIMIT_MAX", 10)

    # Stub members so register_member doesn't try to talk to Postgres.
    monkeypatch.setattr(chapter_agent, "members", {})
    monkeypatch.setattr(chapter_agent, "PUBLIC_URL", "")

    # 10 register-attempts allowed under the generic ceiling.
    for i in range(10):
        resp = client.post(
            "/api/members",
            json={"agent_id": f"victim-{i}", "name": f"V{i}"},
        )
        assert resp.status_code == 200, f"register {i + 1} threw {resp.status_code}: {resp.text[:200]}"

    # 11th hits 429 with the GENERIC limit value.
    resp = client.post("/api/members", json={"agent_id": "victim-11", "name": "V11"})
    assert resp.status_code == 429
    assert resp.json().get("limit_per_window") == 10  # the generic ceiling


def test_expensive_path_is_exact_match_not_prefix(client, monkeypatch):
    """Defensive: a sibling path that PREFIXES the digest one must NOT
    inherit the tight ceiling. We use exact-match in the lookup so
    /api/digest/preview (hypothetical future) doesn't get throttled
    because someone added /api/digest to the map."""
    # Map a hypothetical sibling — should NOT throttle our actual build path.
    monkeypatch.setitem(chapter_agent.EXPENSIVE_WRITE_LIMITS, "/api/digest", 1)
    monkeypatch.setitem(chapter_agent.EXPENSIVE_WRITE_LIMITS, "/api/digest/build", 5)

    # The build endpoint uses ITS OWN ceiling (5), not the /api/digest one.
    assert chapter_agent._expensive_write_ceiling("/api/digest/build") == 5
    assert chapter_agent._expensive_write_ceiling("/api/digest/preview") is None
    assert chapter_agent._expensive_write_ceiling("/api/members") is None
