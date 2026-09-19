"""Drive the real server over stdio with the STOCK ``mcp`` SDK client.

⚠️ WHY THIS FILE EXISTS RATHER THAN ASSERTING AGAINST server.py DIRECTLY.
Every interop test this repository owned drove its own code against its own
code, which is exactly why an A2A spec drift went unnoticed for months (see
README.md's "What Orrery does NOT do" section). The oracle for "does this
speak MCP" cannot be a client this repository wrote — it has to be the
library everything else in the MCP ecosystem is built on. This file spawns
the real ``python -m mcp_server`` subprocess and talks to it exactly the way
any other MCP client would: over stdin/stdout, through ``mcp.ClientSession``.

test_langchain_oracle.py is the second, independent oracle — driving the same
server through langchain-mcp-adapters, the library that makes "a LangChain
agent can point at this" true rather than assumed.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

os.environ.setdefault("COMMUNITY_MEMBER_KEYSTORE", "device")

REPO_ROOT = Path(__file__).resolve().parents[1]


def _server_env(home: Path) -> dict[str, str]:
    env = dict(os.environ)
    env["COMMUNITY_MEMBER_HOME"] = str(home)
    env["COMMUNITY_MEMBER_KEYSTORE"] = "device"
    env["PYTHONPATH"] = f"{REPO_ROOT / 'agent'}:{os.environ.get('PYTHONPATH', '')}"
    return env


async def _call(home: Path, name: str, arguments: dict[str, Any] | None = None):
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "mcp_server"],
        env=_server_env(home),
        cwd=str(REPO_ROOT),
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            return await session.call_tool(name, arguments or {})


async def _list_tools(home: Path):
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "mcp_server"],
        env=_server_env(home),
        cwd=str(REPO_ROOT),
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            return await session.list_tools()


async def test_the_server_advertises_exactly_the_six_named_tools(tmp_path: Path) -> None:
    """Not "at least these six" — EXACTLY these six. A seventh tool appearing
    silently (a reasoning/planning tool, say) is precisely the drift this
    unit's own scope line forbids."""
    result = await _list_tools(tmp_path)
    names = {t.name for t in result.tools}
    assert names == {
        "register_agent",
        "request_grant",
        "check_grant",
        "issue_receipt",
        "verify_receipt",
        "resolve_peer",
    }


async def test_resolve_peer_over_the_real_transport(tmp_path: Path) -> None:
    result = await _call(tmp_path, "resolve_peer", {"locator": "", "index": None})
    assert result.isError is False
    assert result.structuredContent["ok"] is False
    assert result.structuredContent["reason"] == "no_locator"


async def test_register_agent_refusal_surfaces_as_an_mcp_tool_error(tmp_path: Path) -> None:
    """A ToolError raised in tools.py must reach the CLIENT as isError=True
    with the refusal text — not as a transport-level crash, and not silently
    swallowed into an empty success."""
    result = await _call(tmp_path, "register_agent", {})
    assert result.isError is True
    text = result.content[0].text
    assert "community-member wizard --express --name" in text


async def test_request_grant_over_the_real_transport_never_returns_approved(tmp_path: Path) -> None:
    """The core guarantee (see test_tools.py), reasserted through the actual
    wire protocol rather than a direct function call — a model-facing client
    really does get "reject"/"prompt" and nothing else."""
    _bootstrap_identity(tmp_path)

    result = await _call(
        tmp_path,
        "request_grant",
        {"capability": "test.capability", "scope": "test", "context": "ctx", "provenance": "untrusted"},
    )
    assert result.isError is False
    assert result.structuredContent["state"] == "reject"


def _bootstrap_identity(home: Path) -> None:
    """Mint a signed identity directly on disk at ``home`` — the same shape
    test_tools.py's ``_signed_identity`` builds — so a subprocess launched
    against this ``COMMUNITY_MEMBER_HOME`` finds a configured agent."""
    from community_member.config import Config

    cfg = Config(home=home)
    cfg.agent_id = "oracle-agent"
    cfg.name = "Oracle Agent"
    cfg.ensure_keypair()
    cfg.save()
