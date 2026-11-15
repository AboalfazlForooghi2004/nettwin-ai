"""Diagnostic engine tests (TASK-004): findings, evidence, statuses."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from nettwin.data.loader import load_topology, load_topology_dict
from nettwin.diagnostics import DiagnosticEngine
from nettwin.domain.models import (
    AdminState,
    DiagnosticResult,
    DiagnosticStatus,
    FindingCode,
    FindingSeverity,
    LinkState,
    OperState,
    Route,
    Service,
    Topology,
)
from nettwin.errors import EndpointNotFoundError, ObjectNotFoundError
from nettwin.graph import NetworkGraph


def engine_for(topology: Topology) -> DiagnosticEngine:
    return DiagnosticEngine(NetworkGraph(topology))


@pytest.fixture
def healthy_engine(fixtures_dir: Path) -> DiagnosticEngine:
    return engine_for(load_topology(fixtures_dir / "healthy.yaml"))


@pytest.fixture
def missing_route_engine(fixtures_dir: Path) -> DiagnosticEngine:
    return engine_for(load_topology(fixtures_dir / "missing_route.yaml"))


@pytest.fixture
def isolation_engine(fixtures_dir: Path) -> DiagnosticEngine:
    return engine_for(load_topology(fixtures_dir / "tenant_isolation.yaml"))


def _codes(result: DiagnosticResult) -> set[str]:
    return {finding.code.value for finding in result.findings}


def _finding(result: DiagnosticResult, code: FindingCode):
    matches = [f for f in result.findings if f.code is code]
    assert len(matches) == 1, f"expected exactly one {code.value}"
    return matches[0]


# ----------------------------------------------------------------------
# Case A: healthy connectivity
# ----------------------------------------------------------------------


def test_healthy_tenant_a_to_postgres_reachable(
    healthy_engine: DiagnosticEngine,
) -> None:
    result = healthy_engine.analyze("ep-a-app", "ep-pg")
    assert result.status is DiagnosticStatus.REACHABLE
    assert result.findings == []
    assert result.source_id == "ep-a-app"
    assert result.destination_id == "ep-pg"
    assert result.vrf_id == "TENANT_A"
    assert result.analysis_id
    assert result.limitations  # always documented

    types = [item.type for item in result.evidence]
    assert types[0] == "endpoint_resolution"
    assert "route_lookup" in types
    assert "link_traversal" in types
    assert "vrf_handoff" in types
    assert types[-1] == "arrival"

    handoffs = [i for i in result.evidence if i.type == "vrf_handoff"]
    assert all(h.result == "permitted" for h in handoffs)
    lookups = [i for i in result.evidence if i.type == "route_lookup"]
    assert lookups[0].matched_route == "leaf-a1-svc-10-100-1"
    assert lookups[0].result == "matched"


def test_healthy_tenant_b_to_postgres_reachable(
    healthy_engine: DiagnosticEngine,
) -> None:
    result = healthy_engine.analyze("ep-b-app", "ep-pg")
    assert result.status is DiagnosticStatus.REACHABLE
    assert result.findings == []
    assert result.vrf_id == "TENANT_B"


def test_same_endpoint_is_reachable(healthy_engine: DiagnosticEngine) -> None:
    result = healthy_engine.analyze("ep-a-app", "ep-a-app")
    assert result.status is DiagnosticStatus.REACHABLE
    assert result.findings == []


def test_endpoint_ids_required_not_ips(healthy_engine: DiagnosticEngine) -> None:
    # An IP address alone must never identify an endpoint.
    with pytest.raises(EndpointNotFoundError):
        healthy_engine.analyze("10.10.10.10", "ep-pg")
    with pytest.raises(EndpointNotFoundError):
        healthy_engine.analyze("ep-a-app", "10.100.1.20")
    with pytest.raises(EndpointNotFoundError):
        healthy_engine.analyze("ghost", "ep-pg")


# ----------------------------------------------------------------------
# Case B: missing route
# ----------------------------------------------------------------------


def test_missing_route_fixture_yields_missing_route(
    missing_route_engine: DiagnosticEngine,
) -> None:
    result = missing_route_engine.analyze("ep-a-app", "ep-pg")
    assert result.status is DiagnosticStatus.UNREACHABLE
    assert _codes(result) == {"MISSING_ROUTE"}

    finding = _finding(result, FindingCode.MISSING_ROUTE)
    assert finding.severity is FindingSeverity.HIGH
    assert finding.status is DiagnosticStatus.UNREACHABLE
    assert finding.source_id == "ep-a-app"
    assert finding.destination_id == "ep-pg"
    assert finding.vrf_id == "TENANT_A"
    assert finding.recommendations
    assert finding.evidence

    lookup = finding.evidence[0]
    assert lookup.type == "route_lookup"
    assert lookup.device_id == "leaf-a1"
    assert lookup.vrf_id == "TENANT_A"
    assert lookup.matched_route is None
    assert lookup.result == "no_matching_route"


def test_missing_route_still_reachable_for_tenant_b(
    missing_route_engine: DiagnosticEngine,
) -> None:
    result = missing_route_engine.analyze("ep-b-app", "ep-pg")
    assert result.status is DiagnosticStatus.REACHABLE


def test_inactive_route_yields_missing_route_with_evidence(
    fixtures_dir: Path,
) -> None:
    topology = load_topology(fixtures_dir / "healthy.yaml")
    route = next(r for r in topology.routes if r.id == "leaf-a1-svc-10-100-1")
    route.active = False
    result = engine_for(topology).analyze("ep-a-app", "ep-pg")

    assert result.status is DiagnosticStatus.UNREACHABLE
    finding = _finding(result, FindingCode.MISSING_ROUTE)
    lookup = finding.evidence[0]
    assert lookup.result == "no_active_route"
    assert lookup.inactive_covering_routes == ["leaf-a1-svc-10-100-1"]
    assert any("Inactive route" in note for note in result.limitations)


# ----------------------------------------------------------------------
# Case C: tenant isolation
# ----------------------------------------------------------------------


def test_tenant_isolation_fixture_denies_cross_tenant(
    isolation_engine: DiagnosticEngine,
) -> None:
    result = isolation_engine.analyze("ep-a-app", "ep-b-app")
    assert result.status is DiagnosticStatus.UNREACHABLE
    assert _codes(result) == {"TENANT_ISOLATION"}

    finding = _finding(result, FindingCode.TENANT_ISOLATION)
    assert finding.severity is FindingSeverity.CRITICAL
    assert finding.vrf_id == "TENANT_A"
    assert finding.recommendations

    boundary = finding.evidence[0]
    assert boundary.type == "tenant_boundary"
    assert boundary.result == "denied"
    assert boundary.decision == "denied_cross_tenant"


def test_service_denying_source_vrf_yields_tenant_isolation(
    fixtures_dir: Path,
) -> None:
    topology = load_topology(fixtures_dir / "healthy.yaml")
    service = next(s for s in topology.services if s.id == "svc-postgres")
    service.allowed_vrfs = ["TENANT_B"]  # Tenant A loses access
    result = engine_for(topology).analyze("ep-a-app", "ep-pg")

    assert result.status is DiagnosticStatus.UNREACHABLE
    assert _codes(result) == {"TENANT_ISOLATION"}
    # Tenant B keeps its explicit access.
    assert engine_for(topology).analyze("ep-b-app", "ep-pg").status is (
        DiagnosticStatus.REACHABLE
    )


def test_walk_time_handoff_into_other_tenant_denied(
    fixtures_dir: Path,
) -> None:
    """A route that forwards into the other tenant's VRF is isolated."""
    topology = load_topology(fixtures_dir / "healthy.yaml")
    route = next(r for r in topology.routes if r.id == "edge-a1-tenanta-svc-10-100-1")
    route.outgoing_interface_id = "edge-a1:eth2"  # TENANT_B interface
    route.next_hop = "10.100.20.1"  # leaf-b1:eth1 (TENANT_B)
    result = engine_for(topology).analyze("ep-a-app", "ep-pg")

    assert result.status is DiagnosticStatus.UNREACHABLE
    assert _codes(result) == {"TENANT_ISOLATION"}
    finding = _finding(result, FindingCode.TENANT_ISOLATION)
    assert finding.evidence[0].type == "vrf_handoff"
    assert finding.evidence[0].result == "denied"


# ----------------------------------------------------------------------
# INTERFACE_DOWN / LINK_DOWN
# ----------------------------------------------------------------------


def test_interface_down_detected(fixtures_dir: Path) -> None:
    topology = load_topology(fixtures_dir / "healthy.yaml")
    iface = next(i for i in topology.interfaces if i.id == "leaf-a1:eth1")
    iface.oper_state = OperState.DOWN
    result = engine_for(topology).analyze("ep-a-app", "ep-pg")

    assert result.status is DiagnosticStatus.UNREACHABLE
    assert _codes(result) == {"INTERFACE_DOWN"}
    finding = _finding(result, FindingCode.INTERFACE_DOWN)
    assert finding.severity is FindingSeverity.HIGH
    state = finding.evidence[0]
    assert state.type == "interface_state"
    assert state.interface_id == "leaf-a1:eth1"
    assert state.oper_state == "down"
    assert state.result == "down"


def test_peer_interface_down_detected(fixtures_dir: Path) -> None:
    topology = load_topology(fixtures_dir / "healthy.yaml")
    iface = next(i for i in topology.interfaces if i.id == "edge-a1:eth1")
    iface.admin_state = AdminState.DOWN
    result = engine_for(topology).analyze("ep-a-app", "ep-pg")

    assert result.status is DiagnosticStatus.UNREACHABLE
    finding = _finding(result, FindingCode.INTERFACE_DOWN)
    assert finding.evidence[0].interface_id == "edge-a1:eth1"


def test_link_down_detected(fixtures_dir: Path) -> None:
    topology = load_topology(fixtures_dir / "healthy.yaml")
    link = next(link for link in topology.links if link.id == "link-a-uplink")
    link.state = LinkState.DOWN
    result = engine_for(topology).analyze("ep-a-app", "ep-pg")

    assert result.status is DiagnosticStatus.UNREACHABLE
    assert _codes(result) == {"LINK_DOWN"}
    finding = _finding(result, FindingCode.LINK_DOWN)
    assert finding.severity is FindingSeverity.HIGH
    traversal = next(i for i in finding.evidence if i.type == "link_traversal")
    assert traversal.link_id == "link-a-uplink"
    assert traversal.result == "down"


def test_admin_down_interface_detected(fixtures_dir: Path) -> None:
    topology = load_topology(fixtures_dir / "healthy.yaml")
    iface = next(i for i in topology.interfaces if i.id == "leaf-a1:eth1")
    iface.admin_state = AdminState.DOWN
    result = engine_for(topology).analyze("ep-a-app", "ep-pg")
    assert result.status is DiagnosticStatus.UNREACHABLE
    finding = _finding(result, FindingCode.INTERFACE_DOWN)
    assert finding.evidence[0].admin_state == "down"


# ----------------------------------------------------------------------
# VRF_MISMATCH
# ----------------------------------------------------------------------


def test_requested_vrf_context_mismatch_is_incomplete(
    healthy_engine: DiagnosticEngine,
) -> None:
    result = healthy_engine.analyze(
        "ep-a-app", "ep-pg", source_vrf_id="TENANT_B"
    )
    assert result.status is DiagnosticStatus.INCOMPLETE
    finding = _finding(result, FindingCode.VRF_MISMATCH)
    assert finding.status is DiagnosticStatus.INCOMPLETE
    assert finding.evidence[0].type == "vrf_context"
    # Never reported as a confirmed failure.
    assert result.status is not DiagnosticStatus.UNREACHABLE


def test_unknown_requested_vrf_raises(healthy_engine: DiagnosticEngine) -> None:
    with pytest.raises(ObjectNotFoundError, match="VRF not found"):
        healthy_engine.analyze("ep-a-app", "ep-pg", source_vrf_id="GHOST")


def test_same_tenant_cross_vrf_without_relationship_is_mismatch() -> None:
    data: dict[str, Any] = {
        "devices": [
            {"id": "r1", "name": "R1", "vendor": "acme", "platform": "ios"}
        ],
        "vrfs": [
            {"id": "V1", "name": "V1", "tenant_id": "tenant-a"},
            {"id": "V2", "name": "V2", "tenant_id": "tenant-a"},
        ],
        "interfaces": [
            {
                "id": "r1:v1",
                "device_id": "r1",
                "name": "v1",
                "vrf_id": "V1",
                "ipv4_addresses": ["10.1.1.1/24"],
                "admin_state": "up",
                "oper_state": "up",
            },
            {
                "id": "r1:v2",
                "device_id": "r1",
                "name": "v2",
                "vrf_id": "V2",
                "ipv4_addresses": ["10.2.2.1/24"],
                "admin_state": "up",
                "oper_state": "up",
            },
        ],
        "links": [],
        "routes": [],
        "endpoints": [
            {
                "id": "ep1",
                "name": "E1",
                "ip_address": "10.1.1.10",
                "vrf_id": "V1",
                "device_id": "r1",
            },
            {
                "id": "ep2",
                "name": "E2",
                "ip_address": "10.2.2.10",
                "vrf_id": "V2",
                "device_id": "r1",
            },
        ],
        "services": [],
    }
    result = engine_for(load_topology_dict(data)).analyze("ep1", "ep2")
    assert result.status is DiagnosticStatus.UNREACHABLE
    assert _codes(result) == {"VRF_MISMATCH"}
    finding = _finding(result, FindingCode.VRF_MISMATCH)
    assert finding.evidence[0].decision == "denied_no_explicit_relationship"


def test_walk_time_handoff_into_wrong_same_tenant_vrf() -> None:
    """Route hands off into a VRF that is not the destination's VRF."""
    data: dict[str, Any] = {
        "devices": [
            {"id": "r1", "name": "R1", "vendor": "acme", "platform": "ios"},
            {"id": "r2", "name": "R2", "vendor": "acme", "platform": "ios"},
        ],
        "vrfs": [
            {"id": "VRF_A", "name": "VRF_A", "tenant_id": "tenant-a"},
            {"id": "VRF_M", "name": "VRF_M", "tenant_id": "tenant-a"},
            {"id": "VRF_S", "name": "VRF_S", "tenant_id": "tenant-s"},
        ],
        "interfaces": [
            {
                "id": "r1:a",
                "device_id": "r1",
                "name": "a",
                "vrf_id": "VRF_A",
                "ipv4_addresses": ["10.0.1.1/30"],
                "admin_state": "up",
                "oper_state": "up",
            },
            {
                "id": "r1:m",
                "device_id": "r1",
                "name": "m",
                "vrf_id": "VRF_M",
                "ipv4_addresses": ["10.0.9.1/30"],
                "admin_state": "up",
                "oper_state": "up",
            },
            {
                "id": "r2:m",
                "device_id": "r2",
                "name": "m",
                "vrf_id": "VRF_M",
                "ipv4_addresses": ["10.0.9.2/30"],
                "admin_state": "up",
                "oper_state": "up",
            },
            {
                "id": "r2:s",
                "device_id": "r2",
                "name": "s",
                "vrf_id": "VRF_S",
                "ipv4_addresses": ["10.0.2.1/30"],
                "admin_state": "up",
                "oper_state": "up",
            },
        ],
        "links": [
            {
                "id": "link-mm",
                "source_interface_id": "r1:m",
                "destination_interface_id": "r2:m",
                "state": "up",
            }
        ],
        "routes": [
            {
                "id": "r1-misdirect",
                "device_id": "r1",
                "vrf_id": "VRF_A",
                "destination_prefix": "10.0.2.0/24",
                "next_hop": "10.0.9.2",
                "outgoing_interface_id": "r1:m",
                "protocol": "static",
                "active": True,
            }
        ],
        "endpoints": [
            {
                "id": "ep-src",
                "name": "Src",
                "ip_address": "10.0.1.2",
                "vrf_id": "VRF_A",
                "device_id": "r1",
            },
            {
                "id": "ep-dst",
                "name": "Dst",
                "ip_address": "10.0.2.2",
                "vrf_id": "VRF_S",
                "device_id": "r2",
            },
        ],
        "services": [
            {
                "id": "svc-x",
                "name": "X",
                "endpoint_id": "ep-dst",
                "protocol": "tcp",
                "port": 443,
                "allowed_vrfs": ["VRF_A"],
            }
        ],
    }
    result = engine_for(load_topology_dict(data)).analyze("ep-src", "ep-dst")
    assert result.status is DiagnosticStatus.UNREACHABLE
    assert _codes(result) == {"VRF_MISMATCH"}
    finding = _finding(result, FindingCode.VRF_MISMATCH)
    assert finding.evidence[0].type == "vrf_handoff"
    assert finding.evidence[0].result == "denied"


# ----------------------------------------------------------------------
# INSUFFICIENT_DATA: incomplete vs unknown
# ----------------------------------------------------------------------


def test_unattached_endpoint_is_incomplete(fixtures_dir: Path) -> None:
    topology = load_topology(fixtures_dir / "healthy.yaml")
    endpoint = next(e for e in topology.endpoints if e.id == "ep-a-app")
    endpoint.device_id = None
    result = engine_for(topology).analyze("ep-a-app", "ep-pg")

    assert result.status is DiagnosticStatus.INCOMPLETE
    finding = _finding(result, FindingCode.INSUFFICIENT_DATA)
    assert finding.status is DiagnosticStatus.INCOMPLETE
    # Incomplete must never be reported as a confirmed failure.
    assert result.status is not DiagnosticStatus.UNREACHABLE


def test_missing_link_is_unknown_not_unreachable(fixtures_dir: Path) -> None:
    topology = load_topology(fixtures_dir / "healthy.yaml")
    link = next(link for link in topology.links if link.id == "link-svc")
    topology.links.remove(link)
    result = engine_for(topology).analyze("ep-a-app", "ep-pg")

    assert result.status is DiagnosticStatus.UNKNOWN
    finding = _finding(result, FindingCode.INSUFFICIENT_DATA)
    assert finding.status is DiagnosticStatus.UNKNOWN
    assert finding.evidence[0].result == "no_modeled_link"
    # Unknown must never be reported as a confirmed failure.
    assert result.status is not DiagnosticStatus.UNREACHABLE


# ----------------------------------------------------------------------
# NEXT_HOP_UNRESOLVED / ROUTE_LOOP
# ----------------------------------------------------------------------


def test_unresolvable_next_hop_detected(fixtures_dir: Path) -> None:
    topology = load_topology(fixtures_dir / "healthy.yaml")
    route = next(r for r in topology.routes if r.id == "leaf-a1-svc-10-100-1")
    route.next_hop = "10.100.10.9"  # no peer holds this address
    result = engine_for(topology).analyze("ep-a-app", "ep-pg")

    assert result.status is DiagnosticStatus.UNREACHABLE
    assert _codes(result) == {"NEXT_HOP_UNRESOLVED"}
    finding = _finding(result, FindingCode.NEXT_HOP_UNRESOLVED)
    resolution = next(i for i in finding.evidence if i.type == "next_hop_resolution")
    assert resolution.result == "next_hop_not_on_peer"
    assert resolution.next_hop == "10.100.10.9"


def test_route_loop_detected(fixtures_dir: Path) -> None:
    topology = load_topology(fixtures_dir / "healthy.yaml")
    route = next(r for r in topology.routes if r.id == "edge-a1-tenanta-svc-10-100-1")
    route.outgoing_interface_id = "edge-a1:eth1"  # back toward leaf-a1
    route.next_hop = "10.100.10.1"  # leaf-a1:eth1
    result = engine_for(topology).analyze("ep-a-app", "ep-pg")

    assert result.status is DiagnosticStatus.UNREACHABLE
    assert _codes(result) == {"ROUTE_LOOP"}
    finding = _finding(result, FindingCode.ROUTE_LOOP)
    loop_evidence = finding.evidence[0]
    assert loop_evidence.type == "route_loop"
    assert loop_evidence.device_id == "leaf-a1"
    assert loop_evidence.vrf_id == "TENANT_A"


def test_next_hop_only_route_still_resolves(fixtures_dir: Path) -> None:
    """A route with next_hop but no outgoing interface resolves recursively."""
    topology = load_topology(fixtures_dir / "healthy.yaml")
    route = next(r for r in topology.routes if r.id == "leaf-a1-svc-10-100-1")
    route.outgoing_interface_id = None
    result = engine_for(topology).analyze("ep-a-app", "ep-pg")
    assert result.status is DiagnosticStatus.REACHABLE
    resolution = next(
        i for i in result.evidence if i.type == "next_hop_resolution"
    )
    assert resolution.peer_interface_id == "edge-a1:eth1"


# ----------------------------------------------------------------------
# Evidence / result contract
# ----------------------------------------------------------------------


def test_every_finding_has_evidence_and_context(
    healthy_engine: DiagnosticEngine,
    missing_route_engine: DiagnosticEngine,
    isolation_engine: DiagnosticEngine,
    fixtures_dir: Path,
) -> None:
    results = [
        missing_route_engine.analyze("ep-a-app", "ep-pg"),
        isolation_engine.analyze("ep-a-app", "ep-b-app"),
        engine_for(load_topology(fixtures_dir / "healthy.yaml")).analyze(
            "ep-a-app", "ep-pg", source_vrf_id="TENANT_B"
        ),
    ]
    for result in results:
        assert result.findings
        for finding in result.findings:
            assert finding.id
            assert finding.evidence, f"{finding.code} missing evidence"
            assert finding.recommendations
            assert finding.severity in set(FindingSeverity)
            assert finding.status in set(DiagnosticStatus)
            assert finding.source_id or finding.destination_id
            for item in finding.evidence:
                assert item.type


def test_evidence_references_modeled_objects(healthy_engine: DiagnosticEngine) -> None:
    result = healthy_engine.analyze("ep-a-app", "ep-pg")
    topology = healthy_engine.graph.topology
    route_ids = {r.id for r in topology.routes}
    link_ids = {link.id for link in topology.links}
    for item in result.evidence:
        if item.type == "route_lookup" and item.matched_route is not None:
            assert item.matched_route in route_ids
        if item.type == "link_traversal" and item.link_id is not None:
            assert item.link_id in link_ids
        if item.type == "endpoint_resolution":
            assert item.vrf_id in {v.id for v in topology.vrfs}


def test_analysis_is_deterministic(fixtures_dir: Path) -> None:
    topology = load_topology(fixtures_dir / "missing_route.yaml")
    engine = engine_for(topology)
    first = engine.analyze("ep-a-app", "ep-pg")
    second = engine.analyze("ep-a-app", "ep-pg")
    assert first.status == second.status
    assert [f.id for f in first.findings] == [f.id for f in second.findings]
    assert [f.code for f in first.findings] == [f.code for f in second.findings]
    assert [i.type for i in first.evidence] == [i.type for i in second.evidence]


def test_engine_works_without_any_ai_layer(healthy_engine: DiagnosticEngine) -> None:
    """Sanity: the engine is pure deterministic code over the model."""
    import nettwin.diagnostics.engine as engine_module

    assert not any(
        name in vars(engine_module)
        for name in ("openai", "anthropic", "llm", "prompt", "chat")
    )
    assert healthy_engine.analyze("ep-a-app", "ep-pg").status.value == "reachable"


# ----------------------------------------------------------------------
# Type sanity: unused imports stay honest
# ----------------------------------------------------------------------


def test_domain_types_used() -> None:
    # Guards against accidental removal of types the tests rely on.
    assert Route.model_config["extra"] == "forbid"
    assert Service.model_config["extra"] == "forbid"
    assert LinkState.UP.value == "up"
