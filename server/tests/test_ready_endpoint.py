"""That change — /ready proves the loops; /health stays liveness.

`/health` hardcoded `status: "ok"` and never probed the DB, so a DB outage was
invisible to a load balancer while `/health` still said `ok` (liveness masquerading
as readiness). The fix splits the concerns: `/health` is cheap liveness, and a new
`/ready` round-trips the database, returning 503 when a configured dependency is down.

Classification: HAPPY / EDGE / FAILURE.
"""

from __future__ import annotations

import os

os.environ.setdefault("AGENT_ID", "test-chapter")
os.environ.setdefault("AGENT_NAME", "Test Chapter")

import importlib  # noqa: E402
import sys  # noqa: E402

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402


@pytest.fixture
def chapter_app(monkeypatch):
    monkeypatch.setenv("AGENT_ID", "test-ready-chapter")
    monkeypatch.setenv("AGENT_NAME", "Test Ready Chapter")
    monkeypatch.setenv("PUBLIC_URL", "http://localhost:7000")
    sys.modules.pop("chapter_agent", None)
    return importlib.import_module("chapter_agent")


def test_ready_when_no_database_configured(chapter_app, monkeypatch):
    """Dev / in-memory mode: no DATABASE_URL → no backing loop to prove → ready."""
    monkeypatch.setattr(chapter_app, "_HAS_DATABASE", False)
    client = TestClient(chapter_app.app)

    r = client.get("/ready")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ready"
    assert body["checks"]["database"] == "not_configured"


def test_ready_db_down_is_not_ready_while_health_stays_live(chapter_app, monkeypatch):
    """The regression: a DB-down chapter must NOT report ready (503), yet
    /health must still be liveness-ok — proving the split closed the masquerade."""
    monkeypatch.setattr(chapter_app, "_HAS_DATABASE", True)
    import pg_store

    async def _down():
        return False

    monkeypatch.setattr(pg_store, "db_ping", _down)
    client = TestClient(chapter_app.app)

    r = client.get("/ready")
    assert r.status_code == 503
    body = r.json()
    assert body["status"] == "not_ready"
    assert body["checks"]["database"] == "down"

    # Liveness is unaffected — the process is up. This is the point of the split.
    live = client.get("/health")
    assert live.status_code == 200
    assert live.json()["status"] == "ok"


def test_ready_db_up_is_ready(chapter_app, monkeypatch):
    monkeypatch.setattr(chapter_app, "_HAS_DATABASE", True)
    import pg_store

    async def _up():
        return True

    monkeypatch.setattr(pg_store, "db_ping", _up)
    client = TestClient(chapter_app.app)

    r = client.get("/ready")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ready"
    assert body["checks"]["database"] == "up"


def test_ready_is_publicly_reachable():
    """/ready must be auth-open (same class as /health) so an unauthenticated LB
    or orchestrator can probe it."""
    import auth_verify

    assert auth_verify.is_open_path("GET", "/ready") is True
    assert auth_verify.requires_auth("GET", "/ready") is False
