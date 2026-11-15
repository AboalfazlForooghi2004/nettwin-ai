#!/usr/bin/env python3
"""NetTwin AI — MCP demo: the six acceptance demonstration calls.

Runs the MCP tools in-process (the same handlers the stdio server exposes)
and prints their JSON outputs.

Usage:
    python scripts/demo_mcp.py
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from nettwin.data.loader import load_topology  # noqa: E402
from nettwin.mcp_server import create_server  # noqa: E402


def call(server, name: str, arguments: dict) -> dict:
    async def _invoke():
        return await server.call_tool(name, arguments)

    result = asyncio.run(_invoke())
    return json.loads(result.content[0].text)


def section(title: str, body: dict) -> None:
    print(f"\n{'=' * 72}")
    print(f"  {title}")
    print(f"{'=' * 72}")
    print(json.dumps(body, indent=2))


def main() -> int:
    fixtures = REPO_ROOT / "fixtures"

    # Server A: healthy topology ------------------------------------------------
    healthy = load_topology(fixtures / "healthy.yaml")
    healthy_snapshot = healthy.model_dump(mode="json")
    server = create_server(healthy)

    section("1. list_devices", call(server, "list_devices", {}))
    section("2. list_vrfs", call(server, "list_vrfs", {}))

    section(
        "3. check_connectivity — Tenant A app -> PostgreSQL (Case A)",
        call(
            server,
            "check_connectivity",
            {"source_id": "ep-a-app", "destination_id": "ep-pg"},
        ),
    )

    # Server B: missing-route topology ------------------------------------------
    broken = load_topology(fixtures / "missing_route.yaml")
    broken_server = create_server(broken)
    section(
        "4. diagnose_connectivity — missing route (Case B)",
        call(
            broken_server,
            "diagnose_connectivity",
            {"source_id": "ep-a-app", "destination_id": "ep-pg"},
        ),
    )

    section(
        "5. simulate_route_removal — what-if on healthy topology (Case D)",
        call(
            server,
            "simulate_route_removal",
            {
                "route_id": "leaf-a1-svc-10-100-1",
                "source_id": "ep-a-app",
                "destination_id": "ep-pg",
            },
        ),
    )

    # 6. Confirm the original topology is unchanged -----------------------------
    unchanged = healthy.model_dump(mode="json") == healthy_snapshot
    recheck = call(
        server,
        "check_connectivity",
        {"source_id": "ep-a-app", "destination_id": "ep-pg"},
    )
    section(
        "6. original topology unchanged after simulation",
        {
            "original_topology_unchanged": unchanged,
            "routes_present": len(healthy.routes),
            "links_up": all(link.state.value == "up" for link in healthy.links),
            "recheck_status": recheck["status"],
            "recheck_summary": recheck["summary"],
        },
    )
    print("\nDemo complete: original model intact, all calls read-only.")
    return 0 if unchanged and recheck["status"] == "reachable" else 1


if __name__ == "__main__":
    raise SystemExit(main())
