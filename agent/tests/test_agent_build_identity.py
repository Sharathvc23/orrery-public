"""A member agent reports its OWN build, and nothing passes the org's off as it.

Measured 2026-11-01 on a live member agent: the only agent route carrying a
commit was ``/api/health``, which proxied the org's ``/health`` verbatim — so
its ``git_commit`` was the org server's, read completely plausibly, and was
used to attest the wrong service. Every test here drives the org and the agent
with DIFFERENT commits: a test that only checked "a commit is present" passed
on the broken state.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from community_member import build_info

AGENT_COMMIT = "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678"
ORG_COMMIT = "ed5659779ec66c893765502fd63ba37ff814beed"

BAKE_SCRIPT = Path(__file__).resolve().parents[1] / "infra" / "bake_build_info.py"
DOCKERFILE = Path(__file__).resolve().parents[1] / "infra" / "Dockerfile.agent"

pytestmark = pytest.mark.no_local_token


def _load_bake():
    spec = importlib.util.spec_from_file_location("bake_build_info", BAKE_SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


bake = _load_bake()


@pytest.fixture
def baked(tmp_path, monkeypatch):
    """Bake a build file the way the image does — into tmp_path, never the
    package dir, where a stray copy would ship in the next image."""
    path = tmp_path / "_build_info.json"
    path.write_text(
        json.dumps(bake.build_info({"GIT_COMMIT": AGENT_COMMIT, "GIT_BRANCH": "main", "BUILD_TIMESTAMP": "t0"}))
    )
    monkeypatch.setattr(build_info, "BUILD_INFO_FILE", path)
    return path


@pytest.fixture
def client(tmp_path, monkeypatch, baked):
    monkeypatch.setenv("COMMUNITY_MEMBER_HOME", str(tmp_path))
    from community_member import server
    from community_member.config import Config

    cfg = Config(home=tmp_path)
    cfg.agent_id = "chief-scientist"
    app = server.create_app(cfg)
    monkeypatch.setattr(
        server._client, "health", lambda: {"status": "ok", "agent_id": "astrocity", "git_commit": ORG_COMMIT}
    )
    return TestClient(app)


# ── The agent's own stamp ─────────────────────────────────────────────


def test_version_reports_the_agents_baked_commit_not_the_orgs(client):
    body = client.get("/version").json()
    assert body["git_commit"] == AGENT_COMMIT
    assert body["git_commit"] != ORG_COMMIT
    assert body["service"] == "agent"
    assert body["agent_id"] == "chief-scientist"
    assert body["git_branch"] == "main"
    assert body["build_timestamp"] == "t0"


def test_version_is_open_without_the_local_token(client):
    assert client.get("/version").status_code == 200


def test_a_runtime_git_commit_variable_cannot_move_the_stamp(client, monkeypatch):
    """The org's stamp lied because it was an env var a service variable could
    set. The agent's is a baked file; a same-named variable changes nothing."""
    for name in ("GIT_COMMIT", "APP_GIT_COMMIT", "RAILWAY_GIT_COMMIT_SHA"):
        monkeypatch.setenv(name, "0000000deadbeef")
    assert client.get("/version").json()["git_commit"] == AGENT_COMMIT


def test_no_baked_file_is_an_honest_unknown(client, tmp_path, monkeypatch):
    monkeypatch.setattr(build_info, "BUILD_INFO_FILE", tmp_path / "absent.json")
    monkeypatch.setenv("GIT_COMMIT", AGENT_COMMIT)
    assert client.get("/version").json()["git_commit"] == "unknown"


def test_an_unreadable_baked_file_degrades_to_unknown_loudly(tmp_path, caplog):
    path = tmp_path / "_build_info.json"
    path.write_text("{not json")
    assert build_info.read_build_info(path)["git_commit"] == "unknown"
    assert "not JSON" in caplog.text


# ── /api/health is the org's, and says so ─────────────────────────────


def test_api_health_carries_no_build_stamp_at_the_top_level(client):
    """``jq .git_commit`` on the old response returned the ORG's commit. The
    top level now names nothing about a build, so that read finds nothing."""
    body = client.get("/api/health").json()
    assert "git_commit" not in body
    assert body["payload"] == "org"
    assert body["agent_build"] == "/version"
    assert body["org"]["git_commit"] == ORG_COMMIT
    assert body["status"] == "ok"


def test_the_two_surfaces_disagree_when_the_services_do(client):
    org = client.get("/api/health").json()["org"]["git_commit"]
    agent = client.get("/version").json()["git_commit"]
    assert (org, agent) == (ORG_COMMIT, AGENT_COMMIT)


def test_an_unreachable_org_is_still_labelled(client, monkeypatch):
    from community_member import server

    def _down():
        raise RuntimeError("connection refused")

    monkeypatch.setattr(server._client, "health", _down)
    body = client.get("/api/health").json()
    assert body["status"] == "chapter_unreachable"
    assert body["payload"] == "org"
    assert "git_commit" not in body


# ── The bake ──────────────────────────────────────────────────────────


def test_bake_round_trips_through_the_reader(tmp_path, monkeypatch):
    monkeypatch.setenv("GIT_COMMIT", AGENT_COMMIT)
    monkeypatch.setenv("GIT_BRANCH", "main")
    monkeypatch.setenv("BUILD_TIMESTAMP", "2026-11-01T00:00:00Z")
    monkeypatch.delenv("RAILWAY_GIT_COMMIT_SHA", raising=False)
    path = tmp_path / "_build_info.json"
    assert bake.main(["bake", str(path)]) == 0
    assert build_info.read_build_info(path) == {
        "git_commit": AGENT_COMMIT,
        "git_branch": "main",
        "build_timestamp": "2026-11-01T00:00:00Z",
    }


def test_bake_with_nothing_set_is_unknown():
    assert bake.build_info({})["git_commit"] == "unknown"


def test_bake_records_an_explicit_build_arg_that_disagrees_with_the_builder(tmp_path):
    """Railway hands a service variable named GIT_COMMIT to the builder as a
    --build-arg, so a stale one would be baked in for good. Both are recorded."""
    info = bake.build_info({"GIT_COMMIT": "e5e1a3e", "RAILWAY_GIT_COMMIT_SHA": AGENT_COMMIT})
    assert info["provenance_conflict"] is True
    assert info["platform_commit"] == AGENT_COMMIT
    path = tmp_path / "_build_info.json"
    path.write_text(json.dumps(info))
    read = build_info.read_build_info(path)
    assert read["provenance_conflict"] is True
    assert read["platform_commit"] == AGENT_COMMIT


def test_two_full_hashes_sharing_seven_characters_conflict():
    other = AGENT_COMMIT[:7] + "f" * (len(AGENT_COMMIT) - 7)
    assert other != AGENT_COMMIT
    assert bake.build_info({"GIT_COMMIT": other, "RAILWAY_GIT_COMMIT_SHA": AGENT_COMMIT})["provenance_conflict"]


def test_the_railway_default_is_not_a_conflict():
    """The Dockerfile defaults GIT_COMMIT to the builder's commit — the normal
    github-connected build. A short stamp of the same commit is not one either."""
    assert "provenance_conflict" not in bake.build_info(
        {"GIT_COMMIT": AGENT_COMMIT, "RAILWAY_GIT_COMMIT_SHA": AGENT_COMMIT}
    )
    assert "provenance_conflict" not in bake.build_info(
        {"GIT_COMMIT": AGENT_COMMIT[:7], "RAILWAY_GIT_COMMIT_SHA": AGENT_COMMIT}
    )


def test_the_image_bakes_before_it_installs_and_exports_no_stamp_env():
    """Order matters: the bake must land in the source tree before the package
    is installed, or the wheel carries none. And no ENV may carry the stamp —
    that is the variable a runtime service setting would shadow."""
    text = DOCKERFILE.read_text()
    bake_at = text.index("RUN python infra/bake_build_info.py community_member/_build_info.json")
    install_at = text.index('pip install --no-cache-dir --no-deps ".[ed25519]"')
    assert bake_at < install_at
    assert "ARG GIT_COMMIT=${RAILWAY_GIT_COMMIT_SHA:-unknown}" in text
    env_lines = [ln for ln in text.splitlines() if ln.strip().startswith("ENV ")]
    assert not [ln for ln in env_lines if "GIT_COMMIT" in ln or "BUILD_TIMESTAMP" in ln]
