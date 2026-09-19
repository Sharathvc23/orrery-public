"""P0 — build provenance on /health.

/version already resolves the running commit (baked _version.json or
GIT_COMMIT/GIT_BRANCH/BUILD_TIMESTAMP env), but /health was NOT wired to it —
its payload had no commit field at all, so `git_commit` read as null/absent at
runtime. /health is the endpoint smoke-tests and orchestrators poll, so the
stale-deploy signal the PR postmortem demanded was missing exactly where
it's checked. This locks /health to the same resolver as /version.

Classification: HAPPY / EDGE.
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
    monkeypatch.setenv("AGENT_ID", "test-health-chapter")
    monkeypatch.setenv("AGENT_NAME", "Test Health Chapter")
    monkeypatch.setenv("XAI_API_KEY", "test")
    monkeypatch.setenv("PUBLIC_URL", "http://localhost:7000")
    sys.modules.pop("chapter_agent", None)
    return importlib.import_module("chapter_agent")


def test_HAPPY_health_includes_git_commit_from_env(chapter_app, monkeypatch):
    """/health surfaces the same commit /version does — the stale-deploy
    signal must be present where orchestrators actually poll."""
    monkeypatch.setenv("GIT_COMMIT", "abc1234")
    client = TestClient(chapter_app.app)

    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["git_commit"] == "abc1234"


def test_EDGE_health_git_commit_reports_head_or_honest_unknown(chapter_app, monkeypatch):
    """Local dev with nothing baked/injected → the real HEAD from the .git
    checkout (local-dev fallback), or an explicit 'unknown' when there's
    no checkout — NEVER a missing key or a stale hardcoded SHA."""
    for var in ("APP_GIT_COMMIT", "GIT_COMMIT", "GIT_BRANCH", "BUILD_TIMESTAMP", "RAILWAY_GIT_COMMIT_SHA"):
        monkeypatch.delenv(var, raising=False)
    client = TestClient(chapter_app.app)

    r = client.get("/health")
    assert r.status_code == 200
    expected = chapter_app._local_git("rev-parse", "--short", "HEAD") or "unknown"
    assert r.json()["git_commit"] == expected


def test_HAPPY_version_and_health_agree_on_commit(chapter_app, monkeypatch):
    """Both endpoints resolve the commit the same way — no drift."""
    monkeypatch.setenv("GIT_COMMIT", "feed1234")
    client = TestClient(chapter_app.app)

    assert client.get("/health").json()["git_commit"] == client.get("/version").json()["git_commit"]
