"""Drive the real server with ``langchain-mcp-adapters`` — the SECOND,
independent oracle. See test_stdio_oracle.py's module docstring for why the
oracle can't be code this repository wrote.

This is the concrete claim the whole unit exists to make true: "someone
points their existing [LangChain] agent at Orrery" — so this file drives the
server through the actual library a LangChain-based caller would use,
``MultiServerMCPClient``, and invokes the LangChain-wrapped ``BaseTool``
objects it returns exactly the way an agent's tool-calling loop would.
"""

from __future__ import annotations

import os
from pathlib import Path

from langchain_mcp_adapters.client import MultiServerMCPClient

REPO_ROOT = Path(__file__).resolve().parents[1]


def _server_config(home: Path) -> dict:
    env = dict(os.environ)
    env["COMMUNITY_MEMBER_HOME"] = str(home)
    env["COMMUNITY_MEMBER_KEYSTORE"] = "device"
    env["PYTHONPATH"] = f"{REPO_ROOT / 'agent'}:{os.environ.get('PYTHONPATH', '')}"
    return {
        "orrery": {
            "transport": "stdio",
            "command": "python3",
            "args": ["-m", "mcp_server"],
            "env": env,
            "cwd": str(REPO_ROOT),
        }
    }


def _bootstrap_identity(home: Path) -> None:
    from community_member.config import Config

    cfg = Config(home=home)
    cfg.agent_id = "langchain-oracle-agent"
    cfg.name = "LangChain Oracle Agent"
    cfg.ensure_keypair()
    cfg.save()


async def test_langchain_gets_exactly_the_six_tools_as_basetools(tmp_path: Path) -> None:
    client = MultiServerMCPClient(_server_config(tmp_path))
    tools = await client.get_tools()
    names = {t.name for t in tools}
    assert names == {
        "register_agent",
        "request_grant",
        "check_grant",
        "issue_receipt",
        "verify_receipt",
        "resolve_peer",
    }
    # Every one is a real LangChain BaseTool an agent's tool-calling loop can
    # bind directly — not a raw MCP object needing translation this repo
    # would have to write.
    from langchain_core.tools import BaseTool

    assert all(isinstance(t, BaseTool) for t in tools)


async def test_resolve_peer_invoked_as_a_langchain_tool(tmp_path: Path) -> None:
    client = MultiServerMCPClient(_server_config(tmp_path))
    tools = await client.get_tools()
    resolve_peer = next(t for t in tools if t.name == "resolve_peer")

    result = await resolve_peer.ainvoke({"locator": "", "index": None})
    text = result[0]["text"] if isinstance(result, list) else str(result)
    assert '"ok": false' in text
    assert '"reason": "no_locator"' in text


async def test_a_refusal_reaches_the_langchain_caller_as_the_tool_result(tmp_path: Path) -> None:
    """langchain-mcp-adapters' default (handle_tool_errors=True) turns an MCP
    isError result into the tool's own returned text rather than a raised
    exception — so a LangChain agent's loop sees the refusal as ordinary tool
    output it can reason about, not a crash it has to catch."""
    client = MultiServerMCPClient(_server_config(tmp_path))
    tools = await client.get_tools()
    register_agent = next(t for t in tools if t.name == "register_agent")

    result = await register_agent.ainvoke({})
    text = result[0]["text"] if isinstance(result, list) else str(result)
    assert "community-member wizard --express --name" in text


async def test_request_grant_via_langchain_never_returns_approved(tmp_path: Path) -> None:
    """The core guarantee, reasserted through the SECOND independent oracle:
    a LangChain-driven caller gets exactly the same non-approval property
    the stock SDK oracle and the direct unit tests already prove."""
    _bootstrap_identity(tmp_path)
    client = MultiServerMCPClient(_server_config(tmp_path))
    tools = await client.get_tools()
    request_grant = next(t for t in tools if t.name == "request_grant")

    result = await request_grant.ainvoke(
        {"capability": "test.capability", "scope": "test", "context": "ctx", "provenance": "untrusted"}
    )
    text = result[0]["text"] if isinstance(result, list) else str(result)
    assert '"state": "reject"' in text
    assert '"state": "approved"' not in text
