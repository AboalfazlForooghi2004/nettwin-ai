"""MCP integration tests (TASK-006): tools, envelopes, safety, stdio."""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any

import pytest
from mcp.server.mcpserver.exceptions import ToolError

from nettwin.data.loader import load_topology
from nettwin.domain.models import DiagnosticStatus, LinkState
from nettwin.mcp_server import READ_ONLY_TOOLS, create_server
from nettwin.mcp_server.server import main as mcp_main

REQUIRED_TOOLS = {
    "list_devices",
    "list_vrfs",
    "get_topology_summary",
    "get_endpoint_details",
    "check_connectivity",
    "diagnose_connectivity",
    "simulate_route_removal",
    "simulate_link_failure",
}


def _run(coro):
    return asyncio.run(coro)


def call(server, name: str, arguments: dict[str, Any] | None = None):
    async def _invoke():
        return await server.call_tool(name, arguments or {})

    return _run(_invoke())


def list_tools(server):
    async def _invoke():
        return await server.list_tools()

    return _run(_invoke())


def payload(result) -> dict[str, Any]:
    """Parse the JSON text content of a tool result."""
    return json.loads(result.content[0].text)


@pytest.fixture
def healthy_server(fixtures_dir: Path):
    topology = load_topology(fixtures_dir / "healthy.yaml")
    return create_server(topology), topology


@pytest.fixture
def missing_route_server(fixtures_dir: Path):
    topology = load_topology(fixtures_dir / "missing_route.yaml")
    return create_server(topology), topology


@pytest.fixture
def isolation_server(fixtures_dir: Path):
    topology = load_topology(fixtures_dir / "tenant_isolation.yaml")
    return create_server(topology), topology


# ----------------------------------------------------------------------
# Registration & security
# ----------------------------------------------------------------------


def test_all_required_tools_registered(healthy_server) -> None:
    server, _ = healthy_server
    tools = list_tools(server)
    names = {tool.name for tool in tools}
    assert names == REQUIRED_TOOLS == READ_ONLY_TOOLS
    assert len(tools) == 8
    for tool in tools:
        assert tool.description, f"{tool.name} has no description"


def test_no_write_capable_tools_exposed(healthy_server) -> None:
    server, _ = healthy_server
    forbidden_fragments = (
        "execute",
        "exec",
        "write",
        "deploy",
        "configure",
        "ssh",
        "command",
        "shell",
        "remediate",
        "modify",
        "delete",
        "remove_config",
    )
    for name in READ_ONLY_TOOLS:
        assert not any(fragment in name for fragment in forbidden_fragments)
    # Simulations are explicit what-if analyses, not writes.
    assert "simulate_route_removal" in READ_ONLY_TOOLS
    assert "simulate_link_failure" in READ_ONLY_TOOLS


def test_unknown_tool_rejected(healthy_server) -> None:
    server, _ = healthy_server
    with pytest.raises(ToolError, match="Unknown tool"):
        _run(server.call_tool("run_shell", {"command": "rm -rf /"}))


# ----------------------------------------------------------------------
# Read tools
# ----------------------------------------------------------------------


def test_list_devices(healthy_server) -> None:
    server, _ = healthy_server
    result = call(server, "list_devices")
    assert result.is_error is False
    body = payload(result)
    assert body["ok"] is True
    assert body["error"] is None
    assert "4 devices" in body["summary"]
    ids = {info["device"]["id"] for info in body["devices"]}
    assert ids == {"leaf-a1", "leaf-b1", "edge-a1", "svc-leaf"}
    leaf = next(
        info for info in body["devices"] if info["device"]["id"] == "leaf-a1"
    )
    assert leaf["interface_count"] == 2
    # Structured output is available to MCP clients.
    assert result.structured_content["ok"] is True


def test_list_vrfs(healthy_server) -> None:
    server, _ = healthy_server
    body = payload(call(server, "list_vrfs"))
    assert body["ok"] is True
    assert len(body["vrfs"]) == 3
    tenant_a = next(info for info in body["vrfs"] if info["vrf"]["id"] == "TENANT_A")
    assert tenant_a["vrf"]["tenant_id"] == "tenant-a"
    assert tenant_a["interface_count"] == 3
    assert tenant_a["endpoint_count"] == 1
    assert tenant_a["route_count"] == 3
    service = next(info for info in body["vrfs"] if info["vrf"]["id"] == "SERVICE")
    assert service["endpoint_count"] == 1


def test_get_topology_summary(healthy_server) -> None:
    server, _ = healthy_server
    body = payload(call(server, "get_topology_summary"))
    assert body["ok"] is True
    summary = body["topology"]
    assert summary["counts"] == {
        "devices": 4,
        "interfaces": 8,
        "links": 3,
        "vrfs": 3,
        "routes": 7,
        "endpoints": 3,
        "services": 1,
    }
    assert summary["connected_components"] == [
        ["edge-a1", "leaf-a1", "leaf-b1", "svc-leaf"]
    ]
    assert summary["tenant_boundary_violations"] == []
    assert summary["services"][0]["id"] == "svc-postgres"
    assert "do not imply" in summary["note"].lower() or "Structural" in summary[
        "note"
    ]


def test_get_endpoint_details(healthy_server) -> None:
    server, _ = healthy_server
    body = payload(
        call(server, "get_endpoint_details", {"endpoint_id": "ep-pg"})
    )
    assert body["ok"] is True
    details = body["endpoint_details"]
    assert details["endpoint"]["ip_address"] == "10.100.1.20"
    assert details["endpoint"]["vrf_id"] == "SERVICE"
    assert details["vrf"]["id"] == "SERVICE"
    assert details["device"]["id"] == "svc-leaf"
    assert details["service"]["id"] == "svc-postgres"
    assert details["service"]["allowed_vrfs"] == ["TENANT_A", "TENANT_B"]
    assert "svc-postgres" in body["summary"]

    # Same IP, different VRF: identity comes from the endpoint id + VRF.
    body_a = payload(
        call(server, "get_endpoint_details", {"endpoint_id": "ep-a-app"})
    )
    assert body_a["endpoint_details"]["endpoint"]["vrf_id"] == "TENANT_A"
    assert body_a["endpoint_details"]["service"] is None


def test_get_endpoint_details_unknown_id(healthy_server) -> None:
    server, _ = healthy_server
    body = payload(
        call(server, "get_endpoint_details", {"endpoint_id": "ghost"})
    )
    assert body["ok"] is False
    assert body["error"]["code"] == "endpoint_not_found"
    assert "ghost" in body["error"]["message"]


# ----------------------------------------------------------------------
# Connectivity & diagnostics
# ----------------------------------------------------------------------


def test_check_connectivity_healthy(healthy_server) -> None:
    server, _ = healthy_server
    result = call(
        server, "check_connectivity",
        {"source_id": "ep-a-app", "destination_id": "ep-pg"},
    )
    body = payload(result)
    assert body["ok"] is True
    assert body["status"] == "reachable"
    assert body["source_id"] == "ep-a-app"
    assert body["destination_id"] == "ep-pg"
    assert body["vrf_id"] == "TENANT_A"
    assert body["finding_codes"] == []
    assert body["limitations"]
    assert "reachable" in body["summary"]
    assert result.structured_content["status"] == "reachable"


def test_check_connectivity_unknown_endpoint(healthy_server) -> None:
    server, _ = healthy_server
    body = payload(
        call(
            server, "check_connectivity",
            {"source_id": "ghost", "destination_id": "ep-pg"},
        )
    )
    assert body["ok"] is False
    assert body["error"]["code"] == "endpoint_not_found"


def test_diagnose_connectivity_healthy_has_evidence(healthy_server) -> None:
    server, _ = healthy_server
    body = payload(
        call(
            server, "diagnose_connectivity",
            {"source_id": "ep-a-app", "destination_id": "ep-pg"},
        )
    )
    assert body["ok"] is True
    assert body["status"] == "reachable"
    assert body["findings"] == []
    assert body["recommendations"] == []
    assert len(body["evidence"]) >= 5
    assert body["limitations"]
    types = {item["type"] for item in body["evidence"]}
    assert {"endpoint_resolution", "route_lookup", "link_traversal",
            "vrf_handoff", "arrival"} <= types


def test_diagnose_missing_route_fixture(missing_route_server) -> None:
    server, _ = missing_route_server
    body = payload(
        call(
            server, "diagnose_connectivity",
            {"source_id": "ep-a-app", "destination_id": "ep-pg"},
        )
    )
    assert body["status"] == "unreachable"
    assert body["finding_codes"] == ["MISSING_ROUTE"]
    finding = body["findings"][0]
    assert finding["code"] == "MISSING_ROUTE"
    assert finding["severity"] == "high"
    assert finding["evidence"][0]["type"] == "route_lookup"
    assert finding["evidence"][0]["matched_route"] is None
    assert finding["recommendations"]
    assert "MISSING_ROUTE" in body["summary"]
    # Tenant B still reachable on this topology.
    body_b = payload(
        call(
            server, "check_connectivity",
            {"source_id": "ep-b-app", "destination_id": "ep-pg"},
        )
    )
    assert body_b["status"] == "reachable"


def test_tenant_isolation_through_mcp(isolation_server) -> None:
    server, _ = isolation_server
    body = payload(
        call(
            server, "diagnose_connectivity",
            {"source_id": "ep-a-app", "destination_id": "ep-b-app"},
        )
    )
    assert body["status"] == "unreachable"
    assert body["finding_codes"] == ["TENANT_ISOLATION"]
    finding = body["findings"][0]
    assert finding["severity"] == "critical"
    assert finding["evidence"][0]["type"] == "tenant_boundary"
    assert finding["evidence"][0]["result"] == "denied"


# ----------------------------------------------------------------------
# Simulations
# ----------------------------------------------------------------------


def test_simulate_route_removal_tool(healthy_server) -> None:
    server, topology = healthy_server
    before = topology.model_dump(mode="json")
    body = payload(
        call(
            server, "simulate_route_removal",
            {
                "route_id": "leaf-a1-svc-10-100-1",
                "source_id": "ep-a-app",
                "destination_id": "ep-pg",
            },
        )
    )
    assert body["ok"] is True
    assert body["baseline_status"] == "reachable"
    assert body["simulated_status"] == "unreachable"
    assert [f["code"] for f in body["new_findings"]] == ["MISSING_ROUTE"]
    assert body["resolved_findings"] == []
    assert body["simulation_id"]
    assert body["change"]["type"] == "remove_route"
    assert body["affected_endpoints"] == ["ep-a-app", "ep-pg"]
    assert body["limitations"]
    # Original topology untouched.
    assert topology.model_dump(mode="json") == before
    assert "leaf-a1-svc-10-100-1" in {r.id for r in topology.routes}


def test_simulate_link_failure_tool(healthy_server) -> None:
    server, topology = healthy_server
    before = topology.model_dump(mode="json")
    body = payload(
        call(
            server, "simulate_link_failure",
            {
                "link_id": "link-a-uplink",
                "source_id": "ep-a-app",
                "destination_id": "ep-pg",
            },
        )
    )
    assert body["ok"] is True
    assert body["baseline_status"] == "reachable"
    assert body["simulated_status"] == "unreachable"
    assert [f["code"] for f in body["new_findings"]] == ["LINK_DOWN"]
    assert body["change"]["type"] == "disable_link"
    assert topology.model_dump(mode="json") == before
    assert all(link.state is LinkState.UP for link in topology.links)


def test_simulation_errors_are_structured(healthy_server) -> None:
    server, _ = healthy_server
    unknown_route = payload(
        call(
            server, "simulate_route_removal",
            {"route_id": "ghost", "source_id": "ep-a-app",
             "destination_id": "ep-pg"},
        )
    )
    assert unknown_route["ok"] is False
    assert unknown_route["error"]["code"] == "route_not_found"

    unknown_link = payload(
        call(
            server, "simulate_link_failure",
            {"link_id": "ghost", "source_id": "ep-a-app",
             "destination_id": "ep-pg"},
        )
    )
    assert unknown_link["ok"] is False
    assert unknown_link["error"]["code"] == "link_not_found"

    unknown_endpoint = payload(
        call(
            server, "simulate_route_removal",
            {"route_id": "leaf-a1-svc-10-100-1", "source_id": "ghost",
             "destination_id": "ep-pg"},
        )
    )
    assert unknown_endpoint["ok"] is False
    assert unknown_endpoint["error"]["code"] == "endpoint_not_found"


# ----------------------------------------------------------------------
# Malformed input (schema validation by the MCP SDK)
# ----------------------------------------------------------------------


def test_missing_required_argument_raises_tool_error(healthy_server) -> None:
    server, _ = healthy_server
    with pytest.raises(ToolError, match="Field required"):
        _run(server.call_tool("check_connectivity", {"source_id": "ep-a-app"}))


def test_wrong_argument_type_raises_tool_error(healthy_server) -> None:
    server, _ = healthy_server
    with pytest.raises(ToolError, match="valid string"):
        _run(
            server.call_tool(
                "diagnose_connectivity",
                {"source_id": 123, "destination_id": "ep-pg"},
            )
        )


def test_empty_arguments_raise_tool_error(healthy_server) -> None:
    server, _ = healthy_server
    with pytest.raises(ToolError, match="Field required"):
        _run(server.call_tool("get_endpoint_details", {}))


# ----------------------------------------------------------------------
# Read-only guarantee: running every tool leaves the model unchanged
# ----------------------------------------------------------------------


def test_all_tools_leave_topology_unchanged(healthy_server) -> None:
    server, topology = healthy_server
    before = topology.model_dump(mode="json")

    call(server, "list_devices")
    call(server, "list_vrfs")
    call(server, "get_topology_summary")
    call(server, "get_endpoint_details", {"endpoint_id": "ep-pg"})
    call(
        server, "check_connectivity",
        {"source_id": "ep-a-app", "destination_id": "ep-pg"},
    )
    call(
        server, "diagnose_connectivity",
        {"source_id": "ep-b-app", "destination_id": "ep-pg"},
    )
    call(
        server, "simulate_route_removal",
        {"route_id": "leaf-a1-svc-10-100-1", "source_id": "ep-a-app",
         "destination_id": "ep-pg"},
    )
    call(
        server, "simulate_link_failure",
        {"link_id": "link-svc", "source_id": "ep-a-app",
         "destination_id": "ep-pg"},
    )

    assert topology.model_dump(mode="json") == before
    assert all(link.state is LinkState.UP for link in topology.links)
    assert len(topology.routes) == 7


# ----------------------------------------------------------------------
# Server startup (real stdio subprocess)
# ----------------------------------------------------------------------


def test_server_starts_over_stdio(fixtures_dir: Path) -> None:
    from mcp.client.session import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client

    async def scenario():
        src_dir = str(fixtures_dir.parent / "src")
        existing_pythonpath = os.environ.get("PYTHONPATH", "")
        params = StdioServerParameters(
            command=sys.executable,
            args=["-m", "nettwin.mcp_server"],
            env={
                **os.environ,
                "NETTWIN_TOPOLOGY": str(fixtures_dir / "healthy.yaml"),
                # Child must import nettwin even without an editable install.
                "PYTHONPATH": src_dir
                + (os.pathsep + existing_pythonpath if existing_pythonpath else ""),
            },
        )
        async with stdio_client(params, errlog=sys.stderr) as (read, write):
            async with ClientSession(read, write) as session:
                init = await session.initialize()
                tools = await session.list_tools()
                result = await session.call_tool(
                    "check_connectivity",
                    {"source_id": "ep-a-app", "destination_id": "ep-pg"},
                )
                return init, tools, result

    init, tools, result = _run(scenario())
    assert init.server_info.name == "nettwin-ai"
    assert {tool.name for tool in tools.tools} == REQUIRED_TOOLS
    assert result.is_error is False
    body = json.loads(result.content[0].text)
    assert body["status"] == "reachable"


def test_entry_point_fails_cleanly_on_missing_topology(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    monkeypatch.setenv("NETTWIN_TOPOLOGY", str(tmp_path / "missing.yaml"))
    exit_code = mcp_main()
    assert exit_code == 1
    captured = capsys.readouterr()
    assert "failed to load topology" in captured.err


def test_entry_point_fails_on_invalid_topology(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("devices: not-a-list\n", encoding="utf-8")
    monkeypatch.setenv("NETTWIN_TOPOLOGY", str(bad))
    assert mcp_main() == 1
    assert "failed to load topology" in capsys.readouterr().err


# ----------------------------------------------------------------------
# Response contract
# ----------------------------------------------------------------------


def test_diagnose_response_contains_required_fields(healthy_server) -> None:
    server, _ = healthy_server
    body = payload(
        call(
            server, "diagnose_connectivity",
            {"source_id": "ep-a-app", "destination_id": "ep-pg"},
        )
    )
    for key in ("status", "summary", "findings", "evidence", "limitations"):
        assert key in body
    assert isinstance(body["status"], str)
    assert isinstance(body["summary"], str)
    assert isinstance(body["findings"], list)
    assert isinstance(body["evidence"], list)
    assert isinstance(body["limitations"], list)


def test_simulation_response_contains_required_fields(healthy_server) -> None:
    server, _ = healthy_server
    body = payload(
        call(
            server, "simulate_route_removal",
            {"route_id": "leaf-a1-svc-10-100-1", "source_id": "ep-a-app",
             "destination_id": "ep-pg"},
        )
    )
    for key in (
        "simulation_id",
        "change",
        "baseline_status",
        "simulated_status",
        "new_findings",
        "resolved_findings",
        "unchanged_findings",
        "affected_endpoints",
        "limitations",
        "summary",
    ):
        assert key in body


def test_status_values_are_explicit(healthy_server) -> None:
    server, _ = healthy_server
    body = payload(
        call(
            server, "check_connectivity",
            {"source_id": "ep-a-app", "destination_id": "ep-pg"},
        )
    )
    assert body["status"] in {status.value for status in DiagnosticStatus}
