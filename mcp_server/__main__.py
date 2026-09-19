"""``python -m mcp_server`` — run the stdio MCP server. See README.md for the
client config an owner points LangChain, Claude, or Cursor at."""

from __future__ import annotations

from .server import main

if __name__ == "__main__":
    main()
