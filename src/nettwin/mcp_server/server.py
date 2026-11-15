"""NetTwin AI MCP server — read-only network intelligence tools (TASK-006).

Architecture rules
------------------
- Handlers call application services only (``NetworkGraph``,
  ``DiagnosticEngine``, ``WhatIfEngine``); no network logic lives here.
- The server is strictly read-only: it exposes no shell, no Python
  execution, no SSH, no configuration deployment, and no write operations.
- Every response is a structured, predictable envelope carrying
  ``ok``/``summary`` plus the relevant status, findings, evidence, and
  limitations (or an explicit ``error``).
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

from mcp.server.mcpserver import MCPServer
from pydantic import BaseModel, ConfigDict

from nettwin.data.loader import load_topology
from nettwin.diagnostics import DiagnosticEngine
from nettwin.domain.models import (
    VRF,
    Device,
    DiagnosticFinding,
    DiagnosticResult,
    DiagnosticStatus,
    Endpoint,
    EvidenceItem,
    Service,
    Topology,
)
from nettwin.errors import (
    EndpointNotFoundError,
    NetTwinError,
    ObjectNotFoundError,
    TopologyValidationError,
)
from nettwin.graph import NetworkGraph
from nettwin.simulation import SimulationChange, SimulationReport, WhatIfEngine

logger = logging.getLogger("nettwin.mcp")

DEFAULT_TOPOLOGY_PATH = "fixtures/healthy.yaml"
TOPOLOGY_ENV_VAR = "NETTWIN_TOPOLOGY"

# Every tool this server exposes — keep in sync with the @server.tool
# registrations below. Anything not in this set must not exist: the server
# is read-only by design.
READ_ONLY_TOOLS = frozenset(
    {
        "list_devices",
        "list_vrfs",
        "get_topology_summary",
        "get_endpoint_details",
        "check_connectivity",
        "diagnose_connectivity",
        "simulate_route_removal",
        "simulate_link_failure",
    }
)


# ----------------------------------------------------------------------
# Response envelopes
# ----------------------------------------------------------------------


class ErrorDetail(BaseModel):
    """Structured error payload for tool-level failures."""

    model_config = ConfigDict(extra="forbid")

    code: str
    message: str


class DeviceInfo(BaseModel):
    """A device plus its interface count."""

    model_config = ConfigDict(extra="forbid")

    device: Device
    interface_count: int


class VrfInfo(BaseModel):
    """A VRF plus usage counts."""

    model_config = ConfigDict(extra="forbid")

    vrf: VRF
    interface_count: int
    endpoint_count: int
    route_count: int


class TopologySummary(BaseModel):
    """High-level structural summary of the modeled topology."""

    model_config = ConfigDict(extra="forbid")

    counts: dict[str, int]
    device_ids: list[str]
    vrf_ids: list[str]
    connected_components: list[list[str]]
    tenant_boundary_violations: list[str]
    services: list[Service]
    note: str


class EndpointDetails(BaseModel):
    """Endpoint identity with its VRF, device, and any exposing service."""

    model_config = ConfigDict(extra="forbid")

    endpoint: Endpoint
    vrf: VRF
    device: Device | None
    service: Service | None


class ToolResponse(BaseModel):
    """Uniform envelope for the read/query MCP tools."""

    model_config = ConfigDict(extra="forbid")

    ok: bool
    summary: str = ""
    status: DiagnosticStatus | None = None
    error: ErrorDetail | None = None
    devices: list[DeviceInfo] | None = None
    vrfs: list[VrfInfo] | None = None
    topology: TopologySummary | None = None
    endpoint_details: EndpointDetails | None = None
    source_id: str | None = None
    destination_id: str | None = None
    vrf_id: str | None = None
    findings: list[DiagnosticFinding] | None = None
    evidence: list[EvidenceItem] | None = None
    recommendations: list[str] | None = None
    finding_codes: list[str] | None = None
    limitations: list[str] | None = None


class SimulationResponse(ToolResponse):
    """Envelope for what-if simulation tools (extends ToolResponse)."""

    model_config = ConfigDict(extra="forbid")

    simulation_id: str | None = None
    change: SimulationChange | None = None
    baseline_status: DiagnosticStatus | None = None
    simulated_status: DiagnosticStatus | None = None
    baseline_findings: list[DiagnosticFinding] | None = None
    simulated_findings: list[DiagnosticFinding] | None = None
    new_findings: list[DiagnosticFinding] | None = None
    resolved_findings: list[DiagnosticFinding] | None = None
    unchanged_findings: list[DiagnosticFinding] | None = None
    affected_endpoints: list[str] | None = None


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------


def _error_code(exc: NetTwinError) -> str:
    if isinstance(exc, EndpointNotFoundError):
        return "endpoint_not_found"
    if isinstance(exc, ObjectNotFoundError):
        return f"{exc.kind.lower()}_not_found"
    if isinstance(exc, TopologyValidationError):
        return "topology_validation_error"
    return "nettwin_error"


def _error_response(exc: NetTwinError, *, simulation: bool = False):
    detail = ErrorDetail(code=_error_code(exc), message=str(exc))
    response_cls = SimulationResponse if simulation else ToolResponse
    logger.info("tool error (%s): %s", detail.code, exc)
    return response_cls(ok=False, summary=f"Error: {exc}", error=detail)


def _connectivity_summary(result: DiagnosticResult) -> str:
    base = (
        f"{result.source_id} -> {result.destination_id} "
        f"(VRF {result.vrf_id}): {result.status.value}"
    )
    if result.status is DiagnosticStatus.REACHABLE:
        return f"{base} — modeled path found"
    if result.status is DiagnosticStatus.UNREACHABLE:
        codes = ", ".join(f.code.value for f in result.findings) or "unspecified"
        return f"{base} — confirmed failure ({codes})"
    if result.status is DiagnosticStatus.INCOMPLETE:
        return f"{base} — required model data missing; not a confirmed failure"
    return f"{base} — model lacks data to decide; not a confirmed failure"


def _dedupe(items: list[str]) -> list[str]:
    return list(dict.fromkeys(items))


# ----------------------------------------------------------------------
# Server factory
# ----------------------------------------------------------------------


def create_server(topology: Topology) -> MCPServer:
    """Create an MCP server with all read-only NetTwin tools registered.

    Args:
        topology: A validated topology; the server (and its simulations)
            never mutate it.

    Returns:
        A configured ``MCPServer`` instance.
    """
    graph = NetworkGraph(topology)
    diagnostics = DiagnosticEngine(graph)
    whatif = WhatIfEngine(topology)

    server = MCPServer(
        name="nettwin-ai",
        instructions=(
            "NetTwin AI exposes READ-ONLY network intelligence tools over a "
            "modeled topology. Every status and finding is produced by "
            "deterministic diagnostics with structured evidence. No device "
            "is ever contacted or modified; simulations run on copies of "
            "the model."
        ),
    )

    @server.tool(
        description=(
            "List all modeled network devices with their interface counts. "
            "Read-only."
        )
    )
    def list_devices() -> ToolResponse:
        devices = graph.list_devices()
        infos = [
            DeviceInfo(
                device=device,
                interface_count=len(graph.get_device_interfaces(device.id)),
            )
            for device in devices
        ]
        return ToolResponse(
            ok=True,
            summary=f"{len(infos)} devices modeled",
            devices=infos,
        )

    @server.tool(
        description=(
            "List all modeled VRFs with interface/endpoint/route counts and "
            "tenant ids. Read-only."
        )
    )
    def list_vrfs() -> ToolResponse:
        vrfs = graph.list_vrfs()
        infos = [
            VrfInfo(
                vrf=vrf,
                interface_count=len(graph.get_vrf_interfaces(vrf.id)),
                endpoint_count=sum(
                    1
                    for endpoint in graph.list_endpoints()
                    if endpoint.vrf_id == vrf.id
                ),
                route_count=sum(
                    1
                    for route in graph.topology.routes
                    if route.vrf_id == vrf.id
                ),
            )
            for vrf in vrfs
        ]
        return ToolResponse(
            ok=True,
            summary=f"{len(infos)} VRFs modeled",
            vrfs=infos,
        )

    @server.tool(
        description=(
            "Return a high-level topology summary: object counts, device and "
            "VRF ids, connected components, tenant-boundary violations, and "
            "services. Structural only — use diagnose_connectivity for "
            "reachability. Read-only."
        )
    )
    def get_topology_summary() -> ToolResponse:
        topology_obj = graph.topology
        counts = {
            "devices": len(topology_obj.devices),
            "interfaces": len(topology_obj.interfaces),
            "links": len(topology_obj.links),
            "vrfs": len(topology_obj.vrfs),
            "routes": len(topology_obj.routes),
            "endpoints": len(topology_obj.endpoints),
            "services": len(topology_obj.services),
        }
        summary = TopologySummary(
            counts=counts,
            device_ids=graph.list_device_ids(),
            vrf_ids=graph.list_vrf_ids(),
            connected_components=[
                sorted(component)
                for component in graph.connected_components()
            ],
            tenant_boundary_violations=graph.find_tenant_boundary_violations(),
            services=graph.list_services(),
            note=(
                "Structural summary only; graph paths do not imply "
                "reachability. Run diagnose_connectivity for evidence-based "
                "results."
            ),
        )
        return ToolResponse(
            ok=True,
            summary=(
                f"{counts['devices']} devices, {counts['vrfs']} VRFs, "
                f"{counts['links']} links, {counts['routes']} routes"
            ),
            topology=summary,
        )

    @server.tool(
        description=(
            "Get details for one endpoint by its endpoint id (never by IP "
            "alone): VRF, device, and any service exposing it. Read-only."
        )
    )
    def get_endpoint_details(endpoint_id: str) -> ToolResponse:
        try:
            endpoint = graph.get_endpoint(endpoint_id)
            vrf = graph.get_vrf(endpoint.vrf_id)
            device = (
                graph.get_device(endpoint.device_id)
                if endpoint.device_id is not None
                else None
            )
            service = graph.find_service_for_endpoint(endpoint.id)
        except NetTwinError as exc:
            return _error_response(exc)
        location = device.id if device is not None else "unattached"
        exposed = (
            f", exposed by service {service.name!r} ({service.id}) to "
            f"{', '.join(service.allowed_vrfs)}"
            if service is not None
            else ""
        )
        return ToolResponse(
            ok=True,
            summary=(
                f"Endpoint {endpoint.id} ({endpoint.ip_address}) in VRF "
                f"{vrf.id} on {location}{exposed}"
            ),
            endpoint_details=EndpointDetails(
                endpoint=endpoint,
                vrf=vrf,
                device=device,
                service=service,
            ),
        )

    @server.tool(
        description=(
            "Check connectivity between two endpoint ids and return the "
            "explicit status (reachable/unreachable/unknown/incomplete), "
            "finding codes, and limitations. Read-only."
        )
    )
    def check_connectivity(source_id: str, destination_id: str) -> ToolResponse:
        try:
            result = diagnostics.analyze(source_id, destination_id)
        except NetTwinError as exc:
            return _error_response(exc)
        return ToolResponse(
            ok=True,
            status=result.status,
            summary=_connectivity_summary(result),
            source_id=result.source_id,
            destination_id=result.destination_id,
            vrf_id=result.vrf_id,
            finding_codes=[finding.code.value for finding in result.findings],
            limitations=result.limitations,
        )

    @server.tool(
        description=(
            "Run the deterministic diagnostic engine between two endpoint "
            "ids and return status, findings with structured evidence, "
            "recommendations, and limitations. Read-only."
        )
    )
    def diagnose_connectivity(
        source_id: str, destination_id: str
    ) -> ToolResponse:
        try:
            result = diagnostics.analyze(source_id, destination_id)
        except NetTwinError as exc:
            return _error_response(exc)
        return ToolResponse(
            ok=True,
            status=result.status,
            summary=_connectivity_summary(result),
            source_id=result.source_id,
            destination_id=result.destination_id,
            vrf_id=result.vrf_id,
            findings=result.findings,
            evidence=result.evidence,
            finding_codes=[finding.code.value for finding in result.findings],
            recommendations=_dedupe(
                [
                    recommendation
                    for finding in result.findings
                    for recommendation in finding.recommendations
                ]
            ),
            limitations=result.limitations,
        )

    @server.tool(
        description=(
            "Simulate removing a route on a copy of the topology and return "
            "the baseline-vs-simulated impact report (new/resolved/"
            "unchanged findings, affected endpoints, limitations). The "
            "original topology is never modified. Read-only."
        )
    )
    def simulate_route_removal(
        route_id: str, source_id: str, destination_id: str
    ) -> SimulationResponse:
        try:
            report = whatif.simulate_route_removal(
                route_id, source_id, destination_id
            )
        except NetTwinError as exc:
            return _error_response(exc, simulation=True)
        return _simulation_response(report)

    @server.tool(
        description=(
            "Simulate disabling a link on a copy of the topology and return "
            "the baseline-vs-simulated impact report (new/resolved/"
            "unchanged findings, affected endpoints, limitations). The "
            "original topology is never modified. Read-only."
        )
    )
    def simulate_link_failure(
        link_id: str, source_id: str, destination_id: str
    ) -> SimulationResponse:
        try:
            report = whatif.simulate_link_failure(
                link_id, source_id, destination_id
            )
        except NetTwinError as exc:
            return _error_response(exc, simulation=True)
        return _simulation_response(report)

    return server


def _simulation_response(report: SimulationReport) -> SimulationResponse:
    """Convert a ``SimulationReport`` into the MCP envelope."""
    return SimulationResponse(
        ok=True,
        status=report.simulated_status,
        summary=(
            f"Baseline {report.baseline_status.value} -> simulated "
            f"{report.simulated_status.value}: {report.change.description}"
        ),
        source_id=report.source_id,
        destination_id=report.destination_id,
        simulation_id=report.simulation_id,
        change=report.change,
        baseline_status=report.baseline_status,
        simulated_status=report.simulated_status,
        baseline_findings=report.baseline_findings,
        simulated_findings=report.simulated_findings,
        new_findings=report.new_findings,
        resolved_findings=report.resolved_findings,
        unchanged_findings=report.unchanged_findings,
        affected_endpoints=report.affected_endpoints,
        limitations=report.limitations,
    )


# ----------------------------------------------------------------------
# Entry point
# ----------------------------------------------------------------------


def main() -> int:
    """Run the NetTwin AI MCP server over stdio.

    The topology path comes from ``NETTWIN_TOPOLOGY`` (default:
    ``fixtures/healthy.yaml``).

    Returns:
        Process exit code.
    """
    logging.basicConfig(
        level=logging.INFO, format="%(levelname)s %(name)s: %(message)s"
    )
    topology_path = Path(os.environ.get(TOPOLOGY_ENV_VAR, DEFAULT_TOPOLOGY_PATH))
    try:
        topology = load_topology(topology_path)
    except TopologyValidationError as exc:
        print(f"NetTwin MCP: failed to load topology: {exc}", file=sys.stderr)
        return 1
    logger.info("loaded topology from %s", topology_path)
    server = create_server(topology)
    server.run(transport="stdio")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
