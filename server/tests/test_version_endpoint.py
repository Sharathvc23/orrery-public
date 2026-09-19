"""Tests for the /version endpoint that powers post-deploy smoke checks.

Classification: HAPPY / EDGE / FAILURE

The endpoint reads GIT_COMMIT / GIT_BRANCH / BUILD_TIMESTAMP from env
(baked at Docker build time). Tests verify:

  HAPPY    — with all three env vars set, returns the expected JSON shape
  EDGE     — with vars unset, returns 'unknown' for each missing field
             (legitimate local-dev behavior)
  EDGE     — endpoint is open (no auth required) — operators MUST be
             able to read it from external smoke-test scripts that
             don't hold admin credentials
  FAILURE  — there shouldn't be any failure modes; this is a pure
             env-read endpoint
"""

from __future__ import annotations

import os

os.environ.setdefault("AGENT_ID", "test-chapter")
os.environ.setdefault("AGENT_NAME", "Test Chapter")

import importlib
import sys

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def chapter_app(monkeypatch):
    """Spin up a fresh chapter_agent module with env baked in."""
    monkeypatch.setenv("AGENT_ID", "test-version-chapter")
    monkeypatch.setenv("AGENT_NAME", "Test Version Chapter")
    monkeypatch.setenv("XAI_API_KEY", "test")
    monkeypatch.setenv("PUBLIC_URL", "http://localhost:7000")
    sys.modules.pop("chapter_agent", None)
    return importlib.import_module("chapter_agent")


# ══════════════════════════════════════════════════════════════════════
# HAPPY
# ══════════════════════════════════════════════════════════════════════


def test_HAPPY_version_endpoint_returns_baked_envs(chapter_app, monkeypatch):
    """With GIT_COMMIT/GIT_BRANCH/BUILD_TIMESTAMP set, the endpoint
    surfaces all three plus protocol/ARP versions."""
    monkeypatch.setenv("GIT_COMMIT", "abc1234")
    monkeypatch.setenv("GIT_BRANCH", "main")
    monkeypatch.setenv("BUILD_TIMESTAMP", "2026-05-22T03:14:15Z")
    client = TestClient(chapter_app.app)

    r = client.get("/version")
    assert r.status_code == 200
    body = r.json()
    assert body["git_commit"] == "abc1234"
    assert body["git_branch"] == "main"
    assert body["build_timestamp"] == "2026-05-22T03:14:15Z"
    assert body["protocol_version"] == "0.3"
    assert body["arp_version"] == "0.1"
    assert body["agent_id"] == "test-version-chapter"


def test_HAPPY_version_endpoint_is_open_no_auth_required(chapter_app, monkeypatch):
    """Operators MUST be able to hit /version without admin creds —
    that's the whole point: external smoke tests need this signal."""
    monkeypatch.setenv("GIT_COMMIT", "deadbeef")
    client = TestClient(chapter_app.app)

    # No auth headers at all
    r = client.get("/version")
    assert r.status_code == 200
    assert r.json()["git_commit"] == "deadbeef"


# ══════════════════════════════════════════════════════════════════════
# EDGE — missing env vars
# ══════════════════════════════════════════════════════════════════════


def test_EDGE_missing_envs_default_to_unknown(chapter_app, monkeypatch, tmp_path):
    """Local dev / pytest runs without GIT_COMMIT set should not crash
    the endpoint. Returns 'unknown' for each missing field — clearly
    signals to smoke-test scripts that this image wasn't built with
    version metadata baked in."""
    # also strip the deploy-time / platform sources, and point the
    # module at a stub path so the local-.git fallback can't fire — this test is
    # the true "no version metadata anywhere" case.
    for var in ("APP_GIT_COMMIT", "APP_GIT_BRANCH", "APP_BUILD_TIMESTAMP",
                "GIT_COMMIT", "GIT_BRANCH", "BUILD_TIMESTAMP",
                "RAILWAY_GIT_COMMIT_SHA", "RAILWAY_GIT_BRANCH"):
        monkeypatch.delenv(var, raising=False)
    stub = tmp_path / "chapter_agent.py"
    stub.write_text("# stub")
    monkeypatch.setattr(chapter_app, "__file__", str(stub))
    monkeypatch.setattr(chapter_app, "_BUILD_INFO_CACHE", None)
    client = TestClient(chapter_app.app)

    r = client.get("/version")
    assert r.status_code == 200
    body = r.json()
    assert body["git_commit"] == "unknown"
    assert body["git_branch"] == "unknown"
    assert body["build_timestamp"] == "unknown"


def test_EDGE_partial_envs_only_those_present(chapter_app, monkeypatch, tmp_path):
    """If only GIT_COMMIT is set (e.g., partial CI config), the other
    two report 'unknown' independently — no all-or-nothing."""
    for var in ("APP_GIT_COMMIT", "APP_GIT_BRANCH", "APP_BUILD_TIMESTAMP",
                "GIT_BRANCH", "BUILD_TIMESTAMP", "RAILWAY_GIT_COMMIT_SHA", "RAILWAY_GIT_BRANCH"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("GIT_COMMIT", "feed1234")
    # stub path so the local-.git fallback can't fill git_branch
    stub = tmp_path / "chapter_agent.py"
    stub.write_text("# stub")
    monkeypatch.setattr(chapter_app, "__file__", str(stub))
    monkeypatch.setattr(chapter_app, "_BUILD_INFO_CACHE", None)
    client = TestClient(chapter_app.app)

    body = client.get("/version").json()
    assert body["git_commit"] == "feed1234"
    assert body["git_branch"] == "unknown"
    assert body["build_timestamp"] == "unknown"
