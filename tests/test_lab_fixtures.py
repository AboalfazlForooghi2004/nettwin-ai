"""HQ lab fixture tests: switches + firewalls, exact IPs, full scenario."""

from __future__ import annotations

from pathlib import Path

from nettwin.data.loader import load_topology
from nettwin.diagnostics import DiagnosticEngine
from nettwin.domain.models import DiagnosticStatus, FindingCode, LinkState
from nettwin.graph import NetworkGraph
from nettwin.simulation import WhatIfEngine


def _engine(path) -> tuple:
    topology = load_topology(path)
    return topology, DiagnosticEngine(NetworkGraph(topology))


# ----------------------------------------------------------------------
# Structure
# ----------------------------------------------------------------------


def test_lab_healthy_structure(fixtures_dir: Path) -> None:
    topology = load_topology(fixtures_dir / "lab_hq.yaml")
    assert len(topology.devices) == 6
    assert len(topology.interfaces) == 21
    assert len(topology.links) == 6
    assert len(topology.routes) == 19
    assert {v.id for v in topology.vrfs} == {"BLUE", "GREEN", "DMZ", "BRANCH", "MGMT"}
    assert len(topology.endpoints) == 4
    assert len(topology.services) == 1
    # Two firewalls, four switches.
    firewall_ids = {d.id for d in topology.devices if "fw-" in d.id}
    switch_ids = {d.id for d in topology.devices if "sw-" in d.id}
    assert firewall_ids == {"fw-edge-1", "fw-branch-1"}
    assert switch_ids == {"sw-blue-1", "sw-green-1", "sw-core-1", "sw-dmz-1"}
    # Exact management addresses are modeled.
    mgmt = {
        d.id: str(d.management_address) for d in topology.devices
    }
    assert mgmt["fw-edge-1"] == "192.168.100.1"
    assert mgmt["sw-core-1"] == "192.168.100.11"


def test_lab_missing_route_differs_by_exactly_one_route(fixtures_dir: Path) -> None:
    healthy = load_topology(fixtures_dir / "lab_hq.yaml")
    broken = load_topology(fixtures_dir / "lab_hq_missing_route.yaml")
    healthy_ids = {r.id for r in healthy.routes}
    broken_ids = {r.id for r in broken.routes}
    assert healthy_ids - broken_ids == {"r-blue-to-dmz"}
    assert broken_ids - healthy_ids == set()


def test_lab_overlapping_prefixes_stay_isolated(fixtures_dir: Path) -> None:
    _, engine = _engine(fixtures_dir / "lab_hq.yaml")
    matches = engine.graph.find_endpoints_by_ip("10.10.1.10")
    assert {(e.id, e.vrf_id) for e in matches} == {
        ("pc-blue", "BLUE"),
        ("pc-green", "GREEN"),
    }
    # No link crosses VRFs and no cross-tenant adjacency exists.
    for link in engine.graph.topology.links:
        src = engine.graph.get_interface(link.source_interface_id).vrf_id
        dst = engine.graph.get_interface(link.destination_interface_id).vrf_id
        assert src == dst, f"link {link.id} crosses VRFs"
    assert engine.graph.find_tenant_boundary_violations() == []


# ----------------------------------------------------------------------
# Connectivity matrix (the lab acceptance cases)
# ----------------------------------------------------------------------


def test_healthy_connectivity_matrix(fixtures_dir: Path) -> None:
    _, engine = _engine(fixtures_dir / "lab_hq.yaml")
    expected = [
        ("pc-blue", "web-dmz", DiagnosticStatus.REACHABLE),
        ("pc-green", "web-dmz", DiagnosticStatus.REACHABLE),
        ("pc-branch", "web-dmz", DiagnosticStatus.REACHABLE),
        ("pc-blue", "pc-green", DiagnosticStatus.UNREACHABLE),
    ]
    for source, destination, status in expected:
        result = engine.analyze(source, destination)
        assert result.status is status, f"{source}->{destination}: {result.status}"


def test_blue_path_evidence_chain(fixtures_dir: Path) -> None:
    _, engine = _engine(fixtures_dir / "lab_hq.yaml")
    result = engine.analyze("pc-blue", "web-dmz")
    types = [item.type for item in result.evidence]
    # Three route lookups (access -> core -> firewall), then the service
    # handoff into DMZ, then arrival.
    assert types.count("route_lookup") == 3
    assert "vrf_handoff" in types
    handoff = next(i for i in result.evidence if i.type == "vrf_handoff")
    assert handoff.result == "permitted"
    assert handoff.to_vrf_id == "DMZ"
    assert types[-1] == "arrival"
    assert result.limitations


def test_branch_path_crosses_both_firewalls(fixtures_dir: Path) -> None:
    _, engine = _engine(fixtures_dir / "lab_hq.yaml")
    result = engine.analyze("pc-branch", "web-dmz")
    assert result.status is DiagnosticStatus.REACHABLE
    devices_visited = {
        i.device_id for i in result.evidence if i.type == "route_lookup"
    }
    assert {"fw-branch-1", "fw-edge-1"} <= devices_visited


def test_tenant_isolation_blue_to_green(fixtures_dir: Path) -> None:
    _, engine = _engine(fixtures_dir / "lab_hq.yaml")
    result = engine.analyze("pc-blue", "pc-green")
    assert result.status is DiagnosticStatus.UNREACHABLE
    finding = result.findings[0]
    assert finding.code is FindingCode.TENANT_ISOLATION
    assert finding.severity.value == "critical"
    assert finding.evidence[0].type == "tenant_boundary"


def test_missing_route_fixture_matrix(fixtures_dir: Path) -> None:
    _, engine = _engine(fixtures_dir / "lab_hq_missing_route.yaml")
    blue = engine.analyze("pc-blue", "web-dmz")
    assert blue.status is DiagnosticStatus.UNREACHABLE
    assert [f.code for f in blue.findings] == [FindingCode.MISSING_ROUTE]
    assert blue.findings[0].evidence[0].device_id == "sw-blue-1"
    # The other paths are unaffected.
    assert engine.analyze("pc-green", "web-dmz").status is (
        DiagnosticStatus.REACHABLE
    )
    assert engine.analyze("pc-branch", "web-dmz").status is (
        DiagnosticStatus.REACHABLE
    )


# ----------------------------------------------------------------------
# What-if on the lab
# ----------------------------------------------------------------------


def test_lab_what_if_route_removal(fixtures_dir: Path) -> None:
    topology = load_topology(fixtures_dir / "lab_hq.yaml")
    engine = WhatIfEngine(topology)
    report = engine.simulate_route_removal("r-blue-to-dmz", "pc-blue", "web-dmz")
    assert report.baseline_status is DiagnosticStatus.REACHABLE
    assert report.simulated_status is DiagnosticStatus.UNREACHABLE
    assert [f.code for f in report.new_findings] == [FindingCode.MISSING_ROUTE]
    # Original intact.
    assert "r-blue-to-dmz" in {r.id for r in topology.routes}


def test_lab_what_if_wan_tunnel_failure(fixtures_dir: Path) -> None:
    topology = load_topology(fixtures_dir / "lab_hq.yaml")
    engine = WhatIfEngine(topology)
    report = engine.simulate_link_failure("lnk-wan-tunnel", "pc-branch", "web-dmz")
    assert report.baseline_status is DiagnosticStatus.REACHABLE
    assert report.simulated_status is DiagnosticStatus.UNREACHABLE
    assert [f.code for f in report.new_findings] == [FindingCode.LINK_DOWN]
    link = next(link for link in topology.links if link.id == "lnk-wan-tunnel")
    assert link.state is LinkState.UP  # original unchanged
