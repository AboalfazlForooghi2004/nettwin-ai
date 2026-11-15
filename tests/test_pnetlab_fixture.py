"""PNETLab real-topology fixture tests (Phase 1, Mode 1).

Validates that the approved real-lab fixture (`pnetlab_topology.yaml`)
loads through the existing loader/domain model, represents the documented
inventory faithfully, and produces the expected deterministic diagnostics —
including the honest ``unknown`` / ``MISSING_ROUTE`` outcomes around the
FortiGate probes, which are explained against the *modeled* routing table
rather than suppressed.

These are model-based tests only: ``unknown`` means the model lacks
forwarding information, never a live connectivity result.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
from pathlib import Path

from nettwin.data.loader import load_topology
from nettwin.diagnostics import DiagnosticEngine
from nettwin.domain.models import DiagnosticStatus, FindingCode, LinkState
from nettwin.graph import NetworkGraph
from nettwin.mcp_server import create_server
from nettwin.simulation import WhatIfEngine

DEVICE_IDS = {"r2", "r2-1", "r2-2", "r2-3", "r2-4", "fortigate", "fortigate-1"}

REACHABLE_PAIRS = [
    ("ep-lo-r2-1", "ep-lo-r2-3"),  # via R2-2 (representative ECMP path)
    ("ep-lo-r2-1", "ep-lo-r2-4"),  # direct via R2-4
    ("ep-lo-r2-1", "ep-lo-r2"),    # out to the core switch
    ("ep-lo-r2", "ep-lo-r2-4"),
    ("ep-lo-r2-3", "ep-lo-r2-1"),  # via R2-2 (representative ECMP path)
    ("ep-lo-r2-4", "ep-lo-r2-2"),  # via R2-3
    ("ep-lo-r2-2", "ep-lo-r2"),    # via R2-3
    ("ep-lo-r2", "ep-lo-r2-2"),
    ("ep-lo-r2-4", "ep-lo-r2-3"),  # adjacent
]

# The three FortiGate-probe cases: expected, explained outcomes (see the
# dedicated explanation tests below for the evidence-level assertions).
SPECIAL_PAIRS = [
    (
        "ep-lo-r2",
        "ep-fgt-p2",
        DiagnosticStatus.UNKNOWN,
        [FindingCode.INSUFFICIENT_DATA],
    ),
    (
        "ep-fgt-p2",
        "ep-lo-r2-1",
        DiagnosticStatus.UNREACHABLE,
        [FindingCode.MISSING_ROUTE],
    ),
    (
        "ep-fgt-p2",
        "ep-fgt1-p2",
        DiagnosticStatus.UNREACHABLE,
        [FindingCode.MISSING_ROUTE],
    ),
]


def _engine(path) -> tuple:
    topology = load_topology(path)
    return topology, DiagnosticEngine(NetworkGraph(topology))


# ----------------------------------------------------------------------
# Structure: the reported characteristics must match the actual file
# ----------------------------------------------------------------------


def test_pnetlab_structure_counts(fixtures_dir: Path) -> None:
    topology = load_topology(fixtures_dir / "pnetlab_topology.yaml")
    assert len(topology.devices) == 7
    assert len(topology.interfaces) == 21
    assert len(topology.links) == 7
    assert len(topology.vrfs) == 1
    assert len(topology.routes) == 56
    assert len(topology.endpoints) == 7
    assert len(topology.services) == 0
    assert {d.id for d in topology.devices} == DEVICE_IDS
    # Single flat lab table: every interface and endpoint sits in GLOBAL.
    assert [v.id for v in topology.vrfs] == ["GLOBAL"]
    assert all(i.vrf_id == "GLOBAL" for i in topology.interfaces)
    assert all(e.vrf_id == "GLOBAL" for e in topology.endpoints)
    # Route protocol split (verified by counter during Phase 1).
    protocol_split = {}
    for route in topology.routes:
        protocol_split[route.protocol] = protocol_split.get(route.protocol, 0) + 1
    assert protocol_split == {"connected": 20, "ospf": 35, "static": 1}


def test_pnetlab_addressing_and_default_route(fixtures_dir: Path) -> None:
    topology = load_topology(fixtures_dir / "pnetlab_topology.yaml")
    addresses = {i.id: [str(a) for a in i.ipv4_addresses] for i in topology.interfaces}
    # External edge and SVI-based core design.
    assert addresses["r21-e02"] == ["192.168.98.34/27"]
    assert addresses["r2-vlan23"] == ["10.0.23.1/30"]
    assert addresses["r23-e00"] == ["10.0.23.2/30"]
    assert addresses["r2-vlan12"] == ["10.0.12.1/30"]
    assert addresses["fgt-p2"] == ["10.0.12.2/30"]
    assert addresses["fgt1-p2"] == ["10.0.12.6/30"]
    # Loopback anchors /32 per device.
    loopbacks = {
        i.device_id: str(i.ipv4_addresses[0])
        for i in topology.interfaces
        if i.name == "Loopback0"
    }
    assert loopbacks == {
        "r2": "10.255.255.2/32",
        "r2-1": "10.255.255.1/32",
        "r2-2": "10.255.255.3/32",
        "r2-3": "10.255.255.4/32",
        "r2-4": "10.255.255.5/32",
    }
    # Static default on the external edge [USER-confirmed inventory].
    default = next(r for r in topology.routes if r.id == "r21-s-default")
    assert str(default.destination_prefix) == "0.0.0.0/0"
    assert str(default.next_hop) == "192.168.98.62"
    assert default.outgoing_interface_id == "r21-e02"
    assert default.protocol == "static" and default.active


def test_pnetlab_single_component_no_violations(fixtures_dir: Path) -> None:
    topology = load_topology(fixtures_dir / "pnetlab_topology.yaml")
    graph = NetworkGraph(topology)
    components = graph.connected_components()
    assert len(components) == 1
    assert components[0] == DEVICE_IDS
    assert graph.find_tenant_boundary_violations() == []
    assert all(link.state is LinkState.UP for link in topology.links)


# ----------------------------------------------------------------------
# Diagnostic matrix: 9 reachable loopback pairs + 3 explained FGT probes
# ----------------------------------------------------------------------


def test_pnetlab_diagnostic_matrix(fixtures_dir: Path) -> None:
    _, engine = _engine(fixtures_dir / "pnetlab_topology.yaml")

    for source, destination in REACHABLE_PAIRS:
        result = engine.analyze(source, destination)
        assert result.status is DiagnosticStatus.REACHABLE, (
            f"{source}->{destination}: {result.status}"
        )
        assert result.findings == []
        # Reachability is proven by an evidence chain, not assumed.
        assert [item.type for item in result.evidence][-1] == "arrival"
        assert result.limitations

    for source, destination, status, codes in SPECIAL_PAIRS:
        result = engine.analyze(source, destination)
        assert result.status is status, f"{source}->{destination}: {result.status}"
        assert [f.code for f in result.findings] == codes


def test_fgt_missing_route_explained_by_modeled_table(fixtures_dir: Path) -> None:
    """ep-fgt-p2 -> ep-lo-r2-1 is MISSING_ROUTE *because of modeled routing*.

    FortiGate's modeled table contains exactly one connected prefix
    (10.0.12.0/30) and no default route (documented Phase-1 gap), so no
    route covers 10.255.255.1 — the finding must trace to that fact.
    """
    topology, engine = _engine(fixtures_dir / "pnetlab_topology.yaml")
    fgt_routes = [r for r in topology.routes if r.device_id == "fortigate"]
    assert [r.id for r in fgt_routes] == ["fgt-c-10-0-12-0"]
    assert str(fgt_routes[0].destination_prefix) == "10.0.12.0/30"
    # Documented gap: no default route is modeled for the FortiGate.
    assert not any(
        r.device_id == "fortigate" and r.destination_prefix.prefixlen == 0
        for r in topology.routes
    )

    result = engine.analyze("ep-fgt-p2", "ep-lo-r2-1")
    assert result.status is DiagnosticStatus.UNREACHABLE
    finding = result.findings[0]
    assert finding.code is FindingCode.MISSING_ROUTE
    lookup = finding.evidence[0]
    assert lookup.type == "route_lookup"
    assert lookup.device_id == "fortigate"
    assert lookup.matched_route is None
    assert lookup.result == "no_matching_route"
    assert lookup.covering_routes == []
    assert "10.255.255.1" in lookup.destination


def test_fgt_to_fgt1_prefix_not_covered(fixtures_dir: Path) -> None:
    """ep-fgt-p2 -> ep-fgt1-p2: 10.0.12.6 is outside 10.0.12.0/30.

    FortiGate-1's own segment (10.0.12.4/30) is not in FortiGate's table,
    so the destination has no covering route on the forwarding device.
    """
    topology, engine = _engine(fixtures_dir / "pnetlab_topology.yaml")
    connected = next(
        r for r in topology.routes if r.id == "fgt-c-10-0-12-0"
    )
    destination = ipaddress.ip_address("10.0.12.6")
    assert destination not in connected.destination_prefix

    result = engine.analyze("ep-fgt-p2", "ep-fgt1-p2")
    assert result.status is DiagnosticStatus.UNREACHABLE
    assert [f.code for f in result.findings] == [FindingCode.MISSING_ROUTE]
    lookup = result.findings[0].evidence[0]
    assert lookup.result == "no_matching_route"
    assert lookup.covering_routes == []


def test_onlink_delivery_reports_unknown_not_success(fixtures_dir: Path) -> None:
    """ep-lo-r2 -> ep-fgt-p2 is `unknown`, NOT reachable.

    The engine has no L2/ARP neighbor model: a connected route without a
    next hop cannot describe final on-link delivery to another device, so
    the honest result is INSUFFICIENT_DATA/unknown. Unknown must never be
    reported as a successful connectivity test.
    """
    _, engine = _engine(fixtures_dir / "pnetlab_topology.yaml")
    result = engine.analyze("ep-lo-r2", "ep-fgt-p2")
    assert result.status is DiagnosticStatus.UNKNOWN
    assert result.status is not DiagnosticStatus.REACHABLE
    assert [f.code for f in result.findings] == [FindingCode.INSUFFICIENT_DATA]
    finding = result.findings[0]
    onlink = [
        item
        for item in finding.evidence
        if item.type == "route_lookup"
        and item.result == "onlink_without_local_delivery"
    ]
    assert onlink, "expected on-link delivery evidence on the modeled route"
    assert onlink[0].matched_route == "r2-c-10-0-12-0"


# ----------------------------------------------------------------------
# What-if on the reference model (copies only; original stays intact)
# ----------------------------------------------------------------------


def test_what_if_route_removal_asymmetric_impact(fixtures_dir: Path) -> None:
    topology = load_topology(fixtures_dir / "pnetlab_topology.yaml")
    before = topology.model_dump(mode="json")
    engine = WhatIfEngine(topology)

    # Removing R2-2's route to R2-3 breaks R2-1 -> R2-3 via R2-2…
    forward = engine.simulate_route_removal(
        "r22-o-10-255-255-4", "ep-lo-r2-1", "ep-lo-r2-3"
    )
    assert forward.baseline_status is DiagnosticStatus.REACHABLE
    assert forward.simulated_status is DiagnosticStatus.UNREACHABLE
    assert [f.code for f in forward.new_findings] == [FindingCode.MISSING_ROUTE]

    # …while the reverse direction (R2-3 -> R2-1) uses other routes.
    reverse = engine.simulate_route_removal(
        "r22-o-10-255-255-4", "ep-lo-r2-3", "ep-lo-r2-1"
    )
    assert reverse.baseline_status is DiagnosticStatus.REACHABLE
    assert reverse.simulated_status is DiagnosticStatus.REACHABLE
    assert reverse.new_findings == []

    # Original model untouched.
    assert "r22-o-10-255-255-4" in {r.id for r in topology.routes}
    assert topology.model_dump(mode="json") == before


def test_what_if_link_failure(fixtures_dir: Path) -> None:
    topology = load_topology(fixtures_dir / "pnetlab_topology.yaml")
    engine = WhatIfEngine(topology)
    report = engine.simulate_link_failure(
        "lnk-r23-r22", "ep-lo-r2-1", "ep-lo-r2-3"
    )
    assert report.baseline_status is DiagnosticStatus.REACHABLE
    assert report.simulated_status is DiagnosticStatus.UNREACHABLE
    assert [f.code for f in report.new_findings] == [FindingCode.LINK_DOWN]
    link = next(link for link in topology.links if link.id == "lnk-r23-r22")
    assert link.state is LinkState.UP  # original unchanged


# ----------------------------------------------------------------------
# MCP surface on the real fixture
# ----------------------------------------------------------------------


def test_mcp_summary_and_connectivity(fixtures_dir: Path) -> None:
    topology = load_topology(fixtures_dir / "pnetlab_topology.yaml")
    server = create_server(topology)

    async def _invoke(name: str, arguments: dict | None = None):
        return await server.call_tool(name, arguments or {})

    summary = json.loads(asyncio.run(_invoke("get_topology_summary")).content[0].text)
    assert summary["ok"] is True
    assert summary["topology"]["counts"] == {
        "devices": 7,
        "interfaces": 21,
        "links": 7,
        "vrfs": 1,
        "routes": 56,
        "endpoints": 7,
        "services": 0,
    }
    assert summary["topology"]["connected_components"] == [sorted(DEVICE_IDS)]
    assert summary["topology"]["tenant_boundary_violations"] == []

    check = json.loads(
        asyncio.run(
            _invoke(
                "check_connectivity",
                {"source_id": "ep-lo-r2-1", "destination_id": "ep-lo-r2-4"},
            )
        ).content[0].text
    )
    assert check["ok"] is True
    assert check["status"] == "reachable"
    assert check["finding_codes"] == []
