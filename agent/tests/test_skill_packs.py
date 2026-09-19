"""Skill packs — bundled, offline skill bundles a user installs in one click.

Covers the pack engine (manifests → active set → loaded skills), the new offline
skills (calc/tasks; the LLM ones error cleanly without a model), the HTTP
endpoints, and the live agent refresh on install.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from community_member import keystore
from community_member import skill_runtime as sr
from community_member.config import Config
from community_member.server import create_app


@pytest.fixture
def tmp_env(tmp_path: Path, monkeypatch):
    from community_member import config as config_mod

    monkeypatch.setenv("COMMUNITY_MEMBER_HOME", str(tmp_path))
    monkeypatch.setattr(config_mod, "CONFIG_DIR", tmp_path)
    # skill_runtime imported CONFIG_DIR by value — repoint it too.
    monkeypatch.setattr(sr, "CONFIG_DIR", tmp_path)
    keystore.reset_for_tests(dir_override=tmp_path)
    return tmp_path


# ── Pack engine ───────────────────────────────────────────────────


def test_default_active_pack_is_starter_only(tmp_env):
    assert sr.active_pack_ids() == {"starter"}
    names = {s.name for s in sr.load_active_pack_skills()}
    assert {"datetime", "web-fetch", "files", "calc"} <= names
    assert "summarize" not in names  # team not active yet


def test_installing_team_activates_its_skills(tmp_env):
    sr.set_pack_installed("team", True)
    assert sr.active_pack_ids() == {"starter", "team"}
    names = {s.name for s in sr.load_active_pack_skills()}
    assert {"summarize", "draft", "tasks"} <= names

    sr.set_pack_installed("team", False)
    names = {s.name for s in sr.load_active_pack_skills()}
    assert "summarize" not in names


def test_list_packs_for_ui_shape(tmp_env):
    packs = {p["id"]: p for p in sr.list_packs_for_ui()}
    assert packs["starter"]["default"] and packs["starter"]["installed"]
    assert packs["starter"]["can_uninstall"] is False
    assert packs["team"]["installed"] is False
    # skills carry name + capabilities for the UI
    assert any(s["name"] == "calc" for s in packs["starter"]["skills"])


# ── The new offline skills ────────────────────────────────────────


def _tool(name, tool):
    sr.set_pack_installed("team", True)
    skill = next(s for s in sr.load_active_pack_skills() if s.name == name)
    return skill.tools[tool]


def test_calc_evaluates_and_refuses_code(tmp_env):
    ev = _tool("calc", "evaluate")
    assert ev({"expression": "2 + 2 * 10"})["result"] == 22
    assert "error" in ev({"expression": "__import__('os').system('x')"})


def test_calc_refuses_giant_exponent_fast(tmp_env):
    # `9**9**9` is short but would compute an astronomical int — must be
    # rejected (and return promptly), not hang.
    import time

    ev = _tool("calc", "evaluate")
    t0 = time.monotonic()
    res = ev({"expression": "9**9**9"})
    assert "error" in res
    assert time.monotonic() - t0 < 1.0
    # ordinary powers still work
    assert ev({"expression": "2**10"})["result"] == 1024


def test_tasks_roundtrip(tmp_env):
    add = _tool("tasks", "add_task")
    lst = _tool("tasks", "list_tasks")
    done = _tool("tasks", "complete_task")
    add({"text": "Email the board"})
    out = lst({})
    assert out["open"] == 1
    tid = out["tasks"][0]["id"]
    assert done({"id": tid})["completed"] == tid
    assert lst({})["open"] == 0


def test_llm_skill_errors_without_a_model(tmp_env):
    # No provider/key configured → clean error, not a crash.
    res = _tool("summarize", "summarize")({"text": "hello world"})
    assert "error" in res


# ── Endpoints ─────────────────────────────────────────────────────


@pytest.fixture
def cfg(tmp_env) -> Config:
    c = Config()
    c.agent_id = "alice"
    c.provider = "ollama"
    c.model = "test"
    return c


@pytest.fixture
def client(cfg) -> TestClient:
    return TestClient(create_app(cfg, agent=None))


def test_packs_endpoint_install_uninstall(client):
    packs = {p["id"]: p for p in client.get("/api/local/packs").json()["packs"]}
    assert packs["starter"]["installed"] and not packs["team"]["installed"]

    assert client.post("/api/local/packs/team/install").json() == {"installed": "team"}
    packs = {p["id"]: p for p in client.get("/api/local/packs").json()["packs"]}
    assert packs["team"]["installed"] and packs["team"]["can_uninstall"]

    assert client.post("/api/local/packs/team/uninstall").json() == {"uninstalled": "team"}
    assert not {p["id"]: p for p in client.get("/api/local/packs").json()["packs"]}["team"]["installed"]


def test_cannot_uninstall_default_pack(client):
    assert client.post("/api/local/packs/starter/uninstall").status_code == 400


def test_unknown_pack_is_404(client):
    assert client.post("/api/local/packs/nope/install").status_code == 404


def test_install_refreshes_the_live_agent(cfg):
    from community_member.agent import LocalAgent

    agent = LocalAgent(cfg)
    before = {s.name for s in agent.loaded_skills}
    assert "summarize" not in before

    client = TestClient(create_app(cfg, agent=agent))
    client.post("/api/local/packs/team/install")

    after = {s.name for s in agent.loaded_skills}
    assert "summarize" in after  # agent reloaded; team skills now live
