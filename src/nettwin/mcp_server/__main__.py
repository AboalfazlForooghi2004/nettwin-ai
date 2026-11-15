"""Allow ``python -m nettwin.mcp_server`` to run the MCP server."""

from nettwin.mcp_server.server import main

if __name__ == "__main__":
    raise SystemExit(main())
