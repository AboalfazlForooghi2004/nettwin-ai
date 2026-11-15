"""Network graph engine tests (TASK-003): construction, queries, isolation."""

from __future__ import annotations

from pathlib import Path

import pytest

from nettwin.data.loader import load_topology, load_topology_dict
from nettwin.domain.models import LinkState
from nettwin.errors import EndpointNotFoundError, ObjectNotFoundError
from nettwin.graph import BoundaryDecision, NetworkGraph
from nettwin.graph.network_graph import TenantBoundaryResult


@pytest.fixture
def healthy(fixtures_dir: Path) -> NetworkGraph:
    return NetworkGraph(load_topology(fixtures_dir / "healthy.yaml"))


@pytest.fixture
def isolation(fixtures_dir: Path) -> NetworkGraph:
    return NetworkGraph(load_topology(fixtures_dir / "tenant_isolation.yaml"))


# ----------------------------------------------------------------------
# Construction
# ----------------------------------------------------------------------


def test_graph_builds_all_node_kinds(healthy: NetworkGraph) -> None:
    kinds: dict[str, int] = {}
    for _node, data in healthy.graph.nodes(data=True):
        kinds[data["kind"]] = kinds.get(data["kind"], 0) + 1
    assert kinds == {
        "device": 4,
        "vrf": 3,
        "interface": 8,
        "endpoint": 3,
        "service": 1,
    }


def test_graph_represents_links_and_vrf_membership(healthy: NetworkGraph) -> None:
    edge_data = {
        data["kind"] for _, _, data in healthy.graph.edges(data=True)
    }
    assert edge_data == {
        "has_interface",
        "member_of",
        "link",
        "in_vrf",
        "attached_to",
        "exposes",
        "allows",
    }
    # VRF membership edge: TENANT_A -- leaf-a1:eth0
    assert healthy.graph.has_edge(("vrf", "TENANT_A"), ("interface", "leaf-a1:eth0"))
    # Service allows both tenant VRFs
    assert healthy.graph.has_edge(("service", "svc-postgres"), ("vrf", "TENANT_A"))
    assert healthy.graph.has_edge(("service", "svc-postgres"), ("vrf", "TENANT_B"))


def test_interface_nodes_carry_vrf_context(healthy: NetworkGraph) -> None:
    data = healthy.graph.nodes[("interface", "leaf-a1:eth0")]
    assert data["vrf_id"] == "TENANT_A"
    assert data["device_id"] == "leaf-a1"
    assert data["ipv4_addresses"] == ["10.10.10.1/24"]


# ----------------------------------------------------------------------
# Object retrieval & errors
# ----------------------------------------------------------------------


def test_getters_return_modeled_objects(healthy: NetworkGraph) -> None:
    assert healthy.get_device("leaf-a1").name == "Tenant A Leaf 1"
    assert healthy.get_vrf("TENANT_A").tenant_id == "tenant-a"
    assert healthy.get_endpoint("ep-pg").device_id == "svc-leaf"
    assert healthy.get_service("svc-postgres").port == 5432
    assert healthy.get_interface("leaf-a1:eth1").vrf_id == "TENANT_A"
    assert healthy.get_link("link-svc").state.value == "up"


def test_unknown_ids_raise_explicit_errors(healthy: NetworkGraph) -> None:
    with pytest.raises(ObjectNotFoundError, match="device not found: 'ghost'"):
        healthy.get_device("ghost")
    with pytest.raises(ObjectNotFoundError, match="VRF not found: 'GHOST'"):
        healthy.get_vrf("GHOST")
    with pytest.raises(ObjectNotFoundError, match="interface not found"):
        healthy.get_interface("ghost:eth0")
    with pytest.raises(ObjectNotFoundError, match="link not found"):
        healthy.get_link("ghost-link")
    with pytest.raises(ObjectNotFoundError, match="service not found"):
        healthy.get_service("ghost-svc")
    with pytest.raises(EndpointNotFoundError, match="endpoint not found: 'ghost'"):
        healthy.get_endpoint("ghost")


def test_list_helpers(healthy: NetworkGraph) -> None:
    assert {d.id for d in healthy.list_devices()} == {
        "leaf-a1",
        "leaf-b1",
        "edge-a1",
        "svc-leaf",
    }
    assert {v.id for v in healthy.list_vrfs()} == {"TENANT_A", "TENANT_B", "SERVICE"}
    assert {e.id for e in healthy.list_endpoints()} == {
        "ep-a-app",
        "ep-b-app",
        "ep-pg",
    }
    assert [s.id for s in healthy.list_services()] == ["svc-postgres"]


# ----------------------------------------------------------------------
# Topology queries
# ----------------------------------------------------------------------


def test_device_interfaces_query(healthy: NetworkGraph) -> None:
    leaf_a_ifaces = [i.id for i in healthy.get_device_interfaces("leaf-a1")]
    assert leaf_a_ifaces == ["leaf-a1:eth0", "leaf-a1:eth1"]
    svc_ifaces = [i.id for i in healthy.get_device_interfaces("svc-leaf")]
    assert svc_ifaces == ["svc-leaf:eth0"]


def test_vrf_interfaces_query(healthy: NetworkGraph) -> None:
    tenant_a = {i.id for i in healthy.get_vrf_interfaces("TENANT_A")}
    assert tenant_a == {"leaf-a1:eth0", "leaf-a1:eth1", "edge-a1:eth1"}
    # Every returned interface really belongs to the requested VRF.
    for iface in healthy.get_vrf_interfaces("TENANT_A"):
        assert iface.vrf_id == "TENANT_A"
    assert healthy.get_vrf_devices("SERVICE") == ["edge-a1", "svc-leaf"]


def test_neighbor_queries(healthy: NetworkGraph) -> None:
    assert healthy.get_neighbors("leaf-a1") == ["edge-a1"]
    assert healthy.get_neighbors("leaf-b1") == ["edge-a1"]
    assert healthy.get_neighbors("edge-a1") == ["leaf-a1", "leaf-b1", "svc-leaf"]
    assert healthy.get_neighbors("svc-leaf") == ["edge-a1"]
    # Peers of an uplink interface
    peers = healthy.get_interface_neighbors("leaf-a1:eth1")
    assert [p.id for p in peers] == ["edge-a1:eth1"]
    # Unconnected access port has no neighbors
    assert healthy.get_interface_neighbors("leaf-a1:eth0") == []


def test_neighbor_query_respects_link_state(healthy: NetworkGraph) -> None:
    # Structural query includes the neighbor...
    assert "edge-a1" in healthy.get_neighbors("leaf-a1")
    # ...but an up-only query excludes links that are down.
    topology = healthy.topology
    link = next(link for link in topology.links if link.id == "link-a-uplink")
    link.state = LinkState.DOWN
    rebuilt = NetworkGraph(topology)
    assert rebuilt.get_neighbors("leaf-a1", require_link_up=True) == []
    assert rebuilt.get_neighbors("leaf-a1") == ["edge-a1"]  # structural unchanged
    link.state = LinkState.UP  # restore original state


def test_connected_components(healthy: NetworkGraph) -> None:
    components = healthy.connected_components()
    assert components == [{"edge-a1", "leaf-a1", "leaf-b1", "svc-leaf"}]


def test_connected_components_respect_link_state(healthy: NetworkGraph) -> None:
    topology = healthy.topology
    link = next(link for link in topology.links if link.id == "link-svc")
    link.state = LinkState.DOWN
    rebuilt = NetworkGraph(topology)
    components = rebuilt.connected_components(require_link_up=True)
    assert {"leaf-a1", "leaf-b1", "edge-a1"} in components
    assert {"svc-leaf"} in components
    link.state = LinkState.UP  # restore original state


def test_service_and_allowed_vrfs_queries(healthy: NetworkGraph) -> None:
    service = healthy.get_service("svc-postgres")
    assert service.name == "PostgreSQL"
    assert healthy.get_service_allowed_vrfs("svc-postgres") == ["TENANT_A", "TENANT_B"]
    assert healthy.find_service_for_endpoint("ep-pg").id == "svc-postgres"
    assert healthy.find_service_for_endpoint("ep-a-app") is None


# ----------------------------------------------------------------------
# VRF isolation & overlapping prefixes
# ----------------------------------------------------------------------


def test_overlapping_ip_lookup_returns_all_vrfs(healthy: NetworkGraph) -> None:
    matches = healthy.find_endpoints_by_ip("10.10.10.10")
    assert {(e.id, e.vrf_id) for e in matches} == {
        ("ep-a-app", "TENANT_A"),
        ("ep-b-app", "TENANT_B"),
    }
    # Same IP, different VRFs — never a single shared endpoint.
    assert {e.vrf_id for e in matches} == {"TENANT_A", "TENANT_B"}
    assert healthy.find_endpoints_by_ip("203.0.113.5") == []


def test_vrf_components_never_mix_tenants(healthy: NetworkGraph) -> None:
    tenant_a_components = healthy.get_vrf_components("TENANT_A")
    assert {"leaf-a1", "edge-a1"} in tenant_a_components
    # leaf-b1 (TENANT_B) must never appear in a TENANT_A component.
    for component in tenant_a_components:
        assert "leaf-b1" not in component
        assert "svc-leaf" not in component

    tenant_b_components = healthy.get_vrf_components("TENANT_B")
    assert {"leaf-b1", "edge-a1"} in tenant_b_components
    for component in tenant_b_components:
        assert "leaf-a1" not in component

    service_components = healthy.get_vrf_components("SERVICE")
    assert service_components == [{"edge-a1", "svc-leaf"}]
    for component in service_components:
        assert "leaf-a1" not in component
        assert "leaf-b1" not in component


def test_no_link_crosses_vrfs_in_healthy(healthy: NetworkGraph) -> None:
    for link in healthy.topology.links:
        source_vrf = healthy.get_interface(link.source_interface_id).vrf_id
        dest_vrf = healthy.get_interface(link.destination_interface_id).vrf_id
        assert source_vrf == dest_vrf, f"link {link.id} crosses VRFs"


def test_cross_tenant_boundary_denied(healthy: NetworkGraph) -> None:
    result = healthy.check_tenant_boundary("TENANT_A", "TENANT_B")
    assert isinstance(result, TenantBoundaryResult)
    assert result.allowed is False
    assert result.decision is BoundaryDecision.DENIED_CROSS_TENANT
    assert "tenant-a" in result.reason and "tenant-b" in result.reason


def test_same_vrf_boundary_allowed(healthy: NetworkGraph) -> None:
    result = healthy.check_tenant_boundary("TENANT_A", "TENANT_A")
    assert result.allowed is True
    assert result.decision is BoundaryDecision.ALLOWED_SAME_VRF


def test_explicit_service_allows_cross_vrf(healthy: NetworkGraph) -> None:
    service = healthy.get_service("svc-postgres")
    result = healthy.check_tenant_boundary(
        "TENANT_A", "SERVICE", service=service
    )
    assert result.allowed is True
    assert result.decision is BoundaryDecision.ALLOWED_EXPLICIT_SERVICE
    assert "svc-postgres" in result.reason

    # Service does NOT allow an unrelated VRF.
    denied = healthy.check_tenant_boundary("TENANT_B", "TENANT_A", service=service)
    assert denied.allowed is False
    assert denied.decision in {
        BoundaryDecision.DENIED_CROSS_TENANT,
        BoundaryDecision.DENIED_NO_EXPLICIT_RELATIONSHIP,
    }


def test_cross_vrf_without_service_denied(healthy: NetworkGraph) -> None:
    result = healthy.check_tenant_boundary("TENANT_A", "SERVICE")
    assert result.allowed is False
    assert result.decision is BoundaryDecision.DENIED_CROSS_TENANT


def test_boundary_check_rejects_unknown_vrf(healthy: NetworkGraph) -> None:
    with pytest.raises(ObjectNotFoundError, match="VRF not found"):
        healthy.check_tenant_boundary("GHOST", "TENANT_A")


def test_isolation_fixture_cross_tenant_denied(isolation: NetworkGraph) -> None:
    result = isolation.check_tenant_boundary("TENANT_A", "TENANT_B")
    assert result.allowed is False
    assert result.decision is BoundaryDecision.DENIED_CROSS_TENANT


def test_isolation_fixture_no_implicit_path(isolation: NetworkGraph) -> None:
    # Every VRF-scoped component is tenant-pure.
    for vrf in ("TENANT_A", "TENANT_B"):
        for component in isolation.get_vrf_components(vrf):
            devices = set(component)
            assert not (
                "leaf-a1" in devices and "leaf-b1" in devices
            ), f"VRF {vrf} component {devices} mixes tenants"
    # Same-IP endpoints remain distinct objects in distinct VRFs.
    matches = isolation.find_endpoints_by_ip("10.10.10.10")
    assert len(matches) == 2
    assert len({e.vrf_id for e in matches}) == 2
    # No boundary violations in a clean model.
    assert isolation.find_tenant_boundary_violations() == []


def test_tenant_boundary_violation_detected() -> None:
    """A link joining two tenants' VRFs is flagged as an isolation violation."""
    data = {
        "devices": [
            {"id": "r1", "name": "R1", "vendor": "acme", "platform": "ios"},
            {"id": "r2", "name": "R2", "vendor": "acme", "platform": "ios"},
        ],
        "vrfs": [
            {"id": "TENANT_A", "name": "TENANT_A", "tenant_id": "tenant-a"},
            {"id": "TENANT_B", "name": "TENANT_B", "tenant_id": "tenant-b"},
        ],
        "interfaces": [
            {
                "id": "r1:eth0",
                "device_id": "r1",
                "name": "eth0",
                "vrf_id": "TENANT_A",
                "ipv4_addresses": ["10.1.1.1/30"],
                "admin_state": "up",
                "oper_state": "up",
            },
            {
                "id": "r2:eth0",
                "device_id": "r2",
                "name": "eth0",
                "vrf_id": "TENANT_B",
                "ipv4_addresses": ["10.1.1.2/30"],
                "admin_state": "up",
                "oper_state": "up",
            },
        ],
        "links": [
            {
                "id": "leaky-link",
                "source_interface_id": "r1:eth0",
                "destination_interface_id": "r2:eth0",
                "state": "up",
            }
        ],
        "routes": [],
        "endpoints": [],
        "services": [],
    }
    graph = NetworkGraph(load_topology_dict(data))
    assert graph.find_tenant_boundary_violations() == ["leaky-link"]
    # Structural components see the adjacency, but boundary validation flags it.
    assert graph.connected_components() == [{"r1", "r2"}]
