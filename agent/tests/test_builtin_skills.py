"""Built-in starter-pack skills + their wiring into the agent's tool loop.

Covers three layers:
  1. ``load_builtin_skills()`` discovers the bundled skills and reads their
     manifests/capabilities.
  2. Each skill's tools do what they claim (datetime/web-fetch/files), and the
     ``files`` sandbox refuses to escape its workspace.
  3. ``LocalAgent`` exposes the skills as OpenAI tool defs, auto-grants the
     built-ins' capabilities, and dispatches a ``skill__*`` call end-to-end
     through ``execute_tool`` — the path the chat panel and think loop use.
"""

from __future__ import annotations

import asyncio
import json

import pytest

from community_member import config as cm_config
from community_member import skill_runtime as sr

# ═══════════════════════════════════════════════════════════════
# load_builtin_skills
# ═══════════════════════════════════════════════════════════════


def test_builtin_skills_discovered():
    loaded = sr.load_builtin_skills()
    by_name = {s.name: s for s in loaded}
    assert {"datetime", "web-fetch", "files"} <= set(by_name)

    assert by_name["datetime"].declared_capabilities == []
    assert by_name["web-fetch"].declared_capabilities == ["net.http"]
    assert set(by_name["files"].declared_capabilities) == {"fs.read", "fs.write"}

    # Each exposes its tools with JSON-Schema parameters.
    assert set(by_name["datetime"].tool_specs) == {"now", "today"}
    assert set(by_name["files"].tool_specs) == {"read_file", "write_file", "list_dir"}
    assert by_name["web-fetch"].tool_specs["fetch"]["parameters"]["required"] == ["url"]


def test_builtin_capabilities_are_not_high_risk():
    """Starter skills must run once granted — none may sit in the high-risk
    set (which would force a per-call consent prompt)."""
    for skill in sr.load_builtin_skills():
        assert not (set(skill.declared_capabilities) & sr.HIGH_RISK_CAPABILITIES)


# ═══════════════════════════════════════════════════════════════
# datetime
# ═══════════════════════════════════════════════════════════════


def _tool(loaded, name, tool):
    skill = next(s for s in loaded if s.name == name)
    return skill.tools[tool]


def test_datetime_now_and_today():
    loaded = sr.load_builtin_skills()
    now = _tool(loaded, "datetime", "now")({})
    assert now["timezone"] == "UTC"
    assert now["iso8601"].endswith("+00:00")
    today = _tool(loaded, "datetime", "today")({})
    assert today["date"] == now["date"]


# ═══════════════════════════════════════════════════════════════
# web-fetch (no network — argument validation only)
# ═══════════════════════════════════════════════════════════════


def test_web_fetch_rejects_non_http_scheme():
    fetch = _tool(sr.load_builtin_skills(), "web-fetch", "fetch")
    assert "error" in fetch({"url": "file:///etc/passwd"})
    assert "error" in fetch({"url": "ftp://example.com"})
    assert "error" in fetch({"url": ""})


# ═══════════════════════════════════════════════════════════════
# files (sandboxed to CONFIG_DIR/workspace)
# ═══════════════════════════════════════════════════════════════


@pytest.fixture
def tmp_config_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(cm_config, "CONFIG_DIR", tmp_path / "cm-home")
    return tmp_path / "cm-home"


def test_files_write_read_roundtrip(tmp_config_dir):
    loaded = sr.load_builtin_skills()
    write = _tool(loaded, "files", "write_file")
    read = _tool(loaded, "files", "read_file")

    out = write({"path": "notes/hello.txt", "content": "hi there"})
    assert out["ok"] and out["path"] == "notes/hello.txt"
    assert (tmp_config_dir / "workspace" / "notes" / "hello.txt").read_text() == "hi there"

    got = read({"path": "notes/hello.txt"})
    assert got["content"] == "hi there"


def test_files_list_dir(tmp_config_dir):
    loaded = sr.load_builtin_skills()
    _tool(loaded, "files", "write_file")({"path": "a.txt", "content": "x"})
    _tool(loaded, "files", "write_file")({"path": "sub/b.txt", "content": "y"})
    listing = _tool(loaded, "files", "list_dir")({"path": "."})
    assert "a.txt" in listing["entries"]
    assert "sub/" in listing["entries"]


@pytest.mark.parametrize("escape", ["../../etc/passwd", "../outside.txt", "/etc/passwd"])
def test_files_refuses_workspace_escape(tmp_config_dir, escape):
    loaded = sr.load_builtin_skills()
    assert "error" in _tool(loaded, "files", "read_file")({"path": escape})
    assert "error" in _tool(loaded, "files", "write_file")({"path": escape, "content": "x"})


def test_files_rejects_sibling_prefix_escape(tmp_config_dir):
    """A path resolving to a sibling that merely shares the workspace prefix
    (``workspace-evil``) must be refused, not just ``../``."""
    loaded = sr.load_builtin_skills()
    # '../workspace-evil/x' resolves next to (not under) the workspace dir.
    res = _tool(loaded, "files", "write_file")({"path": "../workspace-evil/x", "content": "x"})
    assert "error" in res


# ═══════════════════════════════════════════════════════════════
# agent wiring: tool defs, auto-grants, end-to-end dispatch
# ═══════════════════════════════════════════════════════════════


@pytest.fixture
def agent(tmp_config_dir, monkeypatch):
    monkeypatch.setenv("COMMUNITY_MEMBER_HOME", str(tmp_config_dir))
    from community_member.agent import AGENT_TOOLS, LocalAgent
    from community_member.config import Config

    cfg = Config()
    cfg.provider = "ollama"
    cfg.model = "test-model"
    a = LocalAgent(cfg)
    a._AGENT_TOOLS_LEN = len(AGENT_TOOLS)  # for the all_tools assertion
    return a


def test_agent_exposes_skill_tools_in_openai_shape(agent):
    names = [d["function"]["name"] for d in agent.skill_tool_defs]
    assert "skill__datetime_at_1_0_0__now" in names
    assert any(n.endswith("__fetch") for n in names)
    for d in agent.skill_tool_defs:
        assert d["type"] == "function"
        params = d["function"]["parameters"]
        assert params["type"] == "object"  # OpenAI rejects a bare {}

    # all_tools is the union; dispatch map keys match the def names exactly.
    assert len(agent.all_tools) == agent._AGENT_TOOLS_LEN + len(agent.skill_tool_defs)
    assert set(agent._skill_dispatch) == set(names)


def test_agent_autogrants_builtin_capabilities(agent):
    assert agent.skill_grants["web-fetch@1.0.0"] == {"net.http"}
    assert agent.skill_grants["files@1.0.0"] == {"fs.read", "fs.write"}
    assert agent.skill_grants["datetime@1.0.0"] == set()


def test_execute_tool_dispatches_skill_end_to_end(agent):
    out = asyncio.run(agent.execute_tool("skill__datetime_at_1_0_0__now", {}))
    assert json.loads(out)["timezone"] == "UTC"


def test_execute_tool_files_skill_roundtrip(agent):
    w = asyncio.run(agent.execute_tool("skill__files_at_1_0_0__write_file", {"path": "x.txt", "content": "yo"}))
    assert json.loads(w)["ok"]
    r = asyncio.run(agent.execute_tool("skill__files_at_1_0_0__read_file", {"path": "x.txt"}))
    assert json.loads(r)["content"] == "yo"


def test_execute_tool_unknown_skill_is_clean_error(agent):
    out = asyncio.run(agent.execute_tool("skill__missing_at_1_0_0__nope", {}))
    assert "Unknown tool" in json.loads(out)["error"]
