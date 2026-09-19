"""Tests for /version's _version.json baked-file preference path.

Mirrors and extends chapter/tests/test_version_endpoint.py — which
covered the env-var path — by exercising the new baked-file
path added in PR. Together the suites prove:

  - When _version.json exists → /version reads it (highest priority)
  - When _version.json is absent → /version falls back to env vars
  - When neither is present → /version returns "unknown" everywhere

Classification: HAPPY / EDGE / FAILURE.
"""

from __future__ import annotations

import json
import os

import pytest

os.environ.setdefault("AGENT_ID", "test-version-chapter")
os.environ.setdefault("AGENT_NAME", "Test Version Chapter")

from fastapi.testclient import TestClient

import chapter_agent


@pytest.fixture(autouse=True)
def _reset_build_info(monkeypatch):
    """Build info is memoized, and the deploy-time / platform sources
    must not leak between tests — reset both around every test."""
    for var in (
        "APP_GIT_COMMIT",
        "APP_GIT_BRANCH",
        "APP_BUILD_TIMESTAMP",
        "RAILWAY_GIT_COMMIT_SHA",
        "RAILWAY_GIT_BRANCH",
    ):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(chapter_agent, "_BUILD_INFO_CACHE", None)


@pytest.fixture
def client():
    return TestClient(chapter_agent.app)


@pytest.fixture
def version_file_path(tmp_path, monkeypatch):
    """Redirect chapter_agent's _version.json lookup to a tmp path so
    tests don't clobber a real file in the repo."""
    fake_module_path = tmp_path / "chapter_agent.py"
    fake_module_path.write_text("# stub")
    monkeypatch.setattr(chapter_agent, "__file__", str(fake_module_path))
    return tmp_path / "_version.json"


def _clear_version_env(monkeypatch):
    """Strip the build-arg env vars so the fallback layer doesn't
    contaminate baked-file tests."""
    for var in ("GIT_COMMIT", "GIT_BRANCH", "BUILD_TIMESTAMP"):
        monkeypatch.delenv(var, raising=False)


# ══════════════════════════════════════════════════════════════════════
# HAPPY — baked file wins
# ══════════════════════════════════════════════════════════════════════


def test_HAPPY_baked_file_populates_version_fields(client, version_file_path, monkeypatch):
    _clear_version_env(monkeypatch)
    version_file_path.write_text(
        json.dumps(
            {
                "git_commit": "abc1234",
                "git_branch": "main",
                "build_timestamp": "2026-05-22T03:00:00Z",
            }
        )
    )

    resp = client.get("/version")
    assert resp.status_code == 200
    body = resp.json()
    assert body["git_commit"] == "abc1234"
    assert body["git_branch"] == "main"
    assert body["build_timestamp"] == "2026-05-22T03:00:00Z"


def test_HAPPY_baked_file_beats_env_vars(client, version_file_path, monkeypatch):
    """Layer 1 (file) MUST win over layer 2 (env)."""
    monkeypatch.setenv("GIT_COMMIT", "should-not-win")
    monkeypatch.setenv("GIT_BRANCH", "should-not-win")
    version_file_path.write_text(
        json.dumps(
            {
                "git_commit": "abc1234",
                "git_branch": "main",
                "build_timestamp": "2026-05-22T03:00:00Z",
            }
        )
    )

    resp = client.get("/version")
    assert resp.json()["git_commit"] == "abc1234"


# ══════════════════════════════════════════════════════════════════════
# EDGE — env-var fallback when file absent
# ══════════════════════════════════════════════════════════════════════


def test_EDGE_env_var_fallback_when_file_absent(client, version_file_path, monkeypatch):
    """No file → /version reads from build-arg env vars."""
    # version_file_path NOT created
    monkeypatch.setenv("GIT_COMMIT", "envcommit")
    monkeypatch.setenv("GIT_BRANCH", "envbranch")
    monkeypatch.setenv("BUILD_TIMESTAMP", "2026-01-01T00:00:00Z")

    resp = client.get("/version")
    body = resp.json()
    assert body["git_commit"] == "envcommit"
    assert body["git_branch"] == "envbranch"
    assert body["build_timestamp"] == "2026-01-01T00:00:00Z"


def test_EDGE_partial_file_falls_back_per_field(client, version_file_path, monkeypatch):
    """File present but missing a field → that field falls back to env."""
    monkeypatch.setenv("GIT_BRANCH", "envbranch")
    version_file_path.write_text(json.dumps({"git_commit": "abc1234"}))

    resp = client.get("/version")
    body = resp.json()
    assert body["git_commit"] == "abc1234"  # from file
    assert body["git_branch"] == "envbranch"  # from env (file missing this field)


def test_EDGE_malformed_file_falls_back_to_env(client, version_file_path, monkeypatch):
    """A corrupt JSON file MUST NOT crash /version — fall back to env."""
    monkeypatch.setenv("GIT_COMMIT", "envrecover")
    version_file_path.write_text("{not valid json")

    resp = client.get("/version")
    assert resp.status_code == 200
    assert resp.json()["git_commit"] == "envrecover"


# ══════════════════════════════════════════════════════════════════════
# FAILURE — neither file nor env → "unknown"
# ══════════════════════════════════════════════════════════════════════


def test_FAILURE_no_file_no_env_returns_unknown(client, version_file_path, monkeypatch):
    _clear_version_env(monkeypatch)
    # version_file_path NOT created

    resp = client.get("/version")
    assert resp.status_code == 200
    body = resp.json()
    assert body["git_commit"] == "unknown"
    assert body["git_branch"] == "unknown"
    assert body["build_timestamp"] == "unknown"


def test_HAPPY_endpoint_always_returns_protocol_versions(client, version_file_path, monkeypatch):
    """Regardless of layer used, /version always reports protocol
    + arp versions (these are baked into the source code, not env)."""
    _clear_version_env(monkeypatch)
    resp = client.get("/version")
    body = resp.json()
    assert body["protocol_version"] == "0.3"
    assert body["arp_version"] == "0.1"


# ── That change: Railway-provided provenance fallback ───────────────────────────
# Live services reported git_commit "unknown" because Railway builds never
# pass docker build args — the platform's own RAILWAY_GIT_COMMIT_SHA is the
# provenance source there, and with it the stale-deploy guard actually
# fires in prod.


def _no_baked_file(monkeypatch, tmp_path):
    fake = tmp_path / "chapter_agent.py"
    fake.write_text("# stub")
    monkeypatch.setattr(chapter_agent, "__file__", str(fake))


def test_railway_sha_fallback_when_nothing_else_wired(monkeypatch, tmp_path):
    """HAPPY: no baked file, no GIT_COMMIT — the Railway SHA reports,
    shortened to the 7-char convention."""
    _no_baked_file(monkeypatch, tmp_path)
    for var in ("GIT_COMMIT", "GIT_BRANCH", "BUILD_TIMESTAMP"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("RAILWAY_GIT_COMMIT_SHA", "b13f969aabbccddeeff00112233445566778899a")
    monkeypatch.setenv("RAILWAY_GIT_BRANCH", "main")
    info = chapter_agent._resolve_build_info()
    assert info["git_commit"] == "b13f969"
    assert info["git_branch"] == "main"


def test_explicit_git_commit_still_wins_over_railway(monkeypatch, tmp_path):
    """EDGE: the docker build-arg path (CI/compose) outranks the platform env."""
    _no_baked_file(monkeypatch, tmp_path)
    monkeypatch.setenv("GIT_COMMIT", "abc1234")
    monkeypatch.setenv("RAILWAY_GIT_COMMIT_SHA", "b13f969aabbccddeeff00112233445566778899a")
    assert chapter_agent._resolve_build_info()["git_commit"] == "abc1234"


def test_health_serves_railway_provenance(monkeypatch, tmp_path, client):
    """HAPPY: /health (where orchestrators poll) reports the Railway SHA —
    the stale-deploy guard has a real value to compare in prod."""
    _no_baked_file(monkeypatch, tmp_path)
    for var in ("GIT_COMMIT", "GIT_BRANCH", "BUILD_TIMESTAMP"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("RAILWAY_GIT_COMMIT_SHA", "b13f969aabbccddeeff00112233445566778899a")
    assert client.get("/health").json()["git_commit"] == "b13f969"


# ── That change: APP_GIT_COMMIT — the deploy-time-injected stamp for `railway up` ────
# `railway up` uploads the local working tree WITHOUT .git and does NOT populate
# RAILWAY_GIT_COMMIT_SHA, so build-time git + the platform var both miss — the
# live mesh reported a stale commit. A deploy-time env var set fresh on every
# deploy is the authoritative source, above every stale-prone baked layer.


def test_app_git_commit_is_authoritative(monkeypatch, tmp_path):
    """APP_GIT_COMMIT outranks a (possibly stale) baked file, GIT_COMMIT, AND
    the Railway platform var — it is the freshest, deploy-time source."""
    version_file = tmp_path / "chapter_agent.py"
    version_file.write_text("# stub")
    monkeypatch.setattr(chapter_agent, "__file__", str(version_file))
    (tmp_path / "_version.json").write_text(json.dumps({"git_commit": "stale00", "git_branch": "old"}))
    monkeypatch.setenv("GIT_COMMIT", "buildarg1")
    monkeypatch.setenv("RAILWAY_GIT_COMMIT_SHA", "railway0aabbccddeeff")
    monkeypatch.setenv("APP_GIT_COMMIT", "deadbeefcafe1234567890")
    monkeypatch.setenv("APP_GIT_BRANCH", "production")
    info = chapter_agent._resolve_build_info()
    assert info["git_commit"] == "deadbeefcafe1234567890"  # verbatim (== the deployed HEAD)
    assert info["git_branch"] == "production"


def test_unset_everything_is_honest_unknown_not_stale(monkeypatch, tmp_path):
    """With NO deploy-time source, no baked file, no platform var, and no .git
    checkout, /health reports an honest 'unknown' — never a stale hardcoded SHA."""
    version_file = tmp_path / "chapter_agent.py"  # a stub path => no .git next to it
    version_file.write_text("# stub")
    monkeypatch.setattr(chapter_agent, "__file__", str(version_file))
    for var in ("APP_GIT_COMMIT", "GIT_COMMIT", "GIT_BRANCH", "BUILD_TIMESTAMP", "RAILWAY_GIT_COMMIT_SHA"):
        monkeypatch.delenv(var, raising=False)
    info = chapter_agent._resolve_build_info()
    assert info["git_commit"] == "unknown"


def test_local_git_checkout_reports_real_head(monkeypatch):
    """LOCAL DEV: with a real .git checkout and no env/file, /health reports the
    actual HEAD (not 'unknown') — accurate provenance without any deploy wiring."""
    for var in ("APP_GIT_COMMIT", "GIT_COMMIT", "GIT_BRANCH", "BUILD_TIMESTAMP", "RAILWAY_GIT_COMMIT_SHA"):
        monkeypatch.delenv(var, raising=False)
    real_head = chapter_agent._local_git("rev-parse", "--short", "HEAD")
    if not real_head:
        pytest.skip("no .git checkout available")
    assert chapter_agent._resolve_build_info()["git_commit"] == real_head
