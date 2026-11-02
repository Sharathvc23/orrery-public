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


# ── when the two deploy paths disagree, /health says so ──────────────────
#
# APP_GIT_COMMIT is the freshest source for a `railway up` upload: .git is
# excluded there and RAILWAY_GIT_COMMIT_SHA describes the CONNECTED repo's head
# rather than the tree that was uploaded. That is why it outranks the platform
# var, and test_app_git_commit_is_authoritative pins it.
#
# But it is a service VARIABLE, so it sticks. A later github-connected build does
# not clear it, and the stamp then describes a deploy that is no longer running.
# Measured on the live org server 2026-10-30: /health reported e5e1a3e, left by
# the previous `railway up`, while the running deployment was 048f745 built from a
# merge. Flipping the priority would just move the same lie to the `railway up`
# case, so when both exist and disagree neither is asserted as THE commit.


def _build_info(chapter_app):
    chapter_app._BUILD_INFO_CACHE = None  # cached per process; /health is polled hot
    return chapter_app._resolve_build_info()


def test_HAPPY_the_stamp_still_wins_when_the_two_agree(chapter_app, monkeypatch):
    sha = "048f745584690272cc496bc7baa571c27eaccc77"
    monkeypatch.setenv("RAILWAY_GIT_COMMIT_SHA", sha)
    monkeypatch.setenv("APP_GIT_COMMIT", "048f745")

    info = _build_info(chapter_app)

    assert info["git_commit"] == "048f745"
    assert "provenance_conflict" not in info


def test_HAPPY_a_disagreement_is_declared_not_silently_resolved(chapter_app, monkeypatch):
    # The live failure: a stale stamp from `railway up` outliving a merge build.
    monkeypatch.setenv("RAILWAY_GIT_COMMIT_SHA", "048f745584690272cc496bc7baa571c27eaccc77")
    monkeypatch.setenv("APP_GIT_COMMIT", "e5e1a3eca3c69ba35f3d7f67ca25f6ca921b4f3e")

    info = _build_info(chapter_app)

    assert info["provenance_conflict"] is True
    assert info["platform_commit"] == "048f745584690272cc496bc7baa571c27eaccc77"
    # The stamp is still reported, so nothing that parsed `git_commit` breaks —
    # but it is no longer the only thing a reader sees.
    assert info["git_commit"] == "e5e1a3eca3c69ba35f3d7f67ca25f6ca921b4f3e"


def test_EDGE_railway_up_with_no_platform_var_reports_no_conflict(chapter_app, monkeypatch):
    # The hole this resolver was written for: `railway up` excludes .git and the
    # platform var is absent, so the stamp is simply correct and uncontested.
    monkeypatch.delenv("RAILWAY_GIT_COMMIT_SHA", raising=False)
    monkeypatch.setenv("APP_GIT_COMMIT", "abc1234")

    info = _build_info(chapter_app)

    assert info["git_commit"] == "abc1234"
    assert "provenance_conflict" not in info


# ── …and it says so where monitors poll, not only in the resolver ────────
#
# The resolver computing the conflict is worthless if /health and /version
# select only `git_commit` from it: a poller then sees the disputed stamp and
# nothing else. These drive the endpoints themselves.

STAMP = "e5e1a3eca3c69ba35f3d7f67ca25f6ca921b4f3e"
PLATFORM = "048f745584690272cc496bc7baa571c27eaccc77"


def _get_both(chapter_app):
    chapter_app._BUILD_INFO_CACHE = None  # cached per process; resolve against this test's env
    client = TestClient(chapter_app.app)
    return client.get("/health").json(), client.get("/version").json()


@pytest.mark.parametrize("endpoint", [0, 1], ids=["health", "version"])
def test_HAPPY_both_endpoints_carry_the_conflict(chapter_app, monkeypatch, endpoint):
    monkeypatch.setenv("RAILWAY_GIT_COMMIT_SHA", PLATFORM)
    monkeypatch.setenv("APP_GIT_COMMIT", STAMP)

    body = _get_both(chapter_app)[endpoint]

    assert body["git_commit"] == STAMP
    assert body["platform_commit"] == PLATFORM
    assert body["provenance_conflict"] is True


@pytest.mark.parametrize("endpoint", [0, 1], ids=["health", "version"])
def test_HAPPY_both_endpoints_stay_quiet_when_the_two_agree(chapter_app, monkeypatch, endpoint):
    monkeypatch.setenv("RAILWAY_GIT_COMMIT_SHA", PLATFORM)
    monkeypatch.setenv("APP_GIT_COMMIT", PLATFORM[:7])

    body = _get_both(chapter_app)[endpoint]

    assert body["git_commit"] == PLATFORM[:7]
    assert "platform_commit" not in body
    assert "provenance_conflict" not in body


def test_EDGE_full_hashes_sharing_seven_characters_still_conflict(chapter_app, monkeypatch):
    # A 7-character prefix compare called these the same commit. Two full hashes
    # are compared in full; only a SHORT stamp is matched as a prefix.
    platform = "048f745584690272cc496bc7baa571c27eaccc77"
    stamp = "048f745" + "0" * 33
    assert platform[:7] == stamp[:7] and platform != stamp
    monkeypatch.setenv("RAILWAY_GIT_COMMIT_SHA", platform)
    monkeypatch.setenv("APP_GIT_COMMIT", stamp)

    health, _ = _get_both(chapter_app)

    assert health["provenance_conflict"] is True
    assert health["git_commit"] == stamp
    assert health["platform_commit"] == platform


def test_EDGE_the_conflict_advice_names_the_source_that_supplied_the_stamp(chapter_app, monkeypatch, capsys):
    # With APP_GIT_COMMIT unset the stamp came from GIT_COMMIT; telling the
    # operator to clear APP_GIT_COMMIT would resolve nothing.
    monkeypatch.delenv("APP_GIT_COMMIT", raising=False)
    monkeypatch.setenv("GIT_COMMIT", STAMP)
    monkeypatch.setenv("RAILWAY_GIT_COMMIT_SHA", PLATFORM)

    info = _build_info(chapter_app)

    assert info["provenance_conflict"] is True
    line = next(ln for ln in capsys.readouterr().out.splitlines() if "[build-info] CONFLICT" in ln)
    assert "(from GIT_COMMIT)" in line
    assert "APP_GIT_COMMIT" not in line


def test_EDGE_an_unknown_placeholder_is_not_a_conflict(chapter_app, monkeypatch):
    # The image bakes GIT_COMMIT=unknown when nothing stamped it. That is an
    # absent stamp, not one that disagrees with the platform.
    monkeypatch.delenv("APP_GIT_COMMIT", raising=False)
    monkeypatch.setenv("GIT_COMMIT", "unknown")
    monkeypatch.setenv("RAILWAY_GIT_COMMIT_SHA", PLATFORM)

    info = _build_info(chapter_app)

    assert "provenance_conflict" not in info
