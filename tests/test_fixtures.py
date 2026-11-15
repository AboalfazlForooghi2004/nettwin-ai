"""Fixture tests (TASK-002): healthy, missing-route, and tenant-isolation."""

from __future__ import annotations

from pathlib import Path

from nettwin.data.loader import load_topology
from nettwin.domain.models import Topology

HEALTHY_ROUTE_IDS = {
    "leaf-a1-conn-10-10-10",
    "leaf-a1-svc-10-100-1",
    "edge-a1-tenanta-svc-10-100-1",
    "leaf-b1-conn-10-10-10",
    "leaf-b1-svc-10-100-1",
    "edge-a1-tenantb-svc-10-100-1",
    "svc-leaf-conn-10-100-1",
}
MISSING_ROUTE_ID = "leaf-a1-svc-10-100-1"


def test_healthy_fixture_loads(fixtures_dir: Path) -> None:
    topology = load_topology(fixtures_dir / "healthy.yaml")
    assert len(topology.devices) == 4
    assert len(topology.vrfs) == 3
    assert {v.id for v in topology.vrfs} == {"TENANT_A", "TENANT_B", "SERVICE"}


def test_healthy_fixture_has_shared_postgres_service(fixtures_dir: Path) -> None:
    topology = load_topology(fixtures_dir / "healthy.yaml")
    service = next(s for s in topology.services if s.id == "svc-postgres")
    assert service.name == "PostgreSQL"
    assert service.protocol == "tcp"
    assert service.port == 5432
    assert service.allowed_vrfs == ["TENANT_A", "TENANT_B"]

    endpoint = next(e for e in topology.endpoints if e.id == service.endpoint_id)
    assert str(endpoint.ip_address) == "10.100.1.20"
    assert endpoint.vrf_id == "SERVICE"
    assert endpoint.device_id == "svc-leaf"


def test_healthy_fixture_overlapping_prefixes_stay_isolated(fixtures_dir: Path) -> None:
    topology = load_topology(fixtures_dir / "healthy.yaml")
    ep_a = next(e for e in topology.endpoints if e.id == "ep-a-app")
    ep_b = next(e for e in topology.endpoints if e.id == "ep-b-app")
    assert str(ep_a.ip_address) == str(ep_b.ip_address) == "10.10.10.10"
    assert ep_a.vrf_id == "TENANT_A"
    assert ep_b.vrf_id == "TENANT_B"
    assert ep_a.device_id != ep_b.device_id
    # Interfaces in different VRFs may share the same prefix.
    leaf_a_if = next(i for i in topology.interfaces if i.id == "leaf-a1:eth0")
    leaf_b_if = next(i for i in topology.interfaces if i.id == "leaf-b1:eth0")
    assert str(leaf_a_if.ipv4_addresses[0]) == str(leaf_b_if.ipv4_addresses[0])


def test_healthy_fixture_has_no_cross_tenant_route_leak(fixtures_dir: Path) -> None:
    """No route in a tenant VRF forwards into another tenant's VRF.

    The only cross-VRF routes are explicit service handoffs into the SERVICE
    VRF (edge-a1:eth3), which the service's allowed_vrfs explicitly permits.
    """
    topology = load_topology(fixtures_dir / "healthy.yaml")
    iface_by_id = {i.id: i for i in topology.interfaces}
    for route in topology.routes:
        if route.outgoing_interface_id is None:
            continue
        iface_vrf = iface_by_id[route.outgoing_interface_id].vrf_id
        if iface_vrf != route.vrf_id:
            assert route.vrf_id in {"TENANT_A", "TENANT_B"}
            assert iface_vrf == "SERVICE"
            service = next(s for s in topology.services if s.id == "svc-postgres")
            assert route.vrf_id in service.allowed_vrfs


def test_missing_route_fixture_loads_and_differs_exactly(fixtures_dir: Path) -> None:
    healthy = load_topology(fixtures_dir / "healthy.yaml")
    broken = load_topology(fixtures_dir / "missing_route.yaml")

    healthy_ids = {r.id for r in healthy.routes}
    broken_ids = {r.id for r in broken.routes}
    assert healthy_ids == HEALTHY_ROUTE_IDS
    assert broken_ids == HEALTHY_ROUTE_IDS - {MISSING_ROUTE_ID}
    assert MISSING_ROUTE_ID not in broken_ids

    # Everything else is identical to the healthy topology.
    assert {d.id for d in broken.devices} == {d.id for d in healthy.devices}
    assert {i.id for i in broken.interfaces} == {i.id for i in healthy.interfaces}
    assert {link.id for link in broken.links} == {link.id for link in healthy.links}
    assert {e.id for e in broken.endpoints} == {e.id for e in healthy.endpoints}
    assert {s.id for s in broken.services} == {s.id for s in healthy.services}


def test_tenant_isolation_fixture_loads(fixtures_dir: Path) -> None:
    topology = load_topology(fixtures_dir / "tenant_isolation.yaml")
    assert len(topology.vrfs) == 2
    assert topology.services == []
    ep_a = next(e for e in topology.endpoints if e.id == "ep-a-app")
    ep_b = next(e for e in topology.endpoints if e.id == "ep-b-app")
    assert str(ep_a.ip_address) == str(ep_b.ip_address) == "10.10.10.10"
    assert (ep_a.vrf_id, ep_b.vrf_id) == ("TENANT_A", "TENANT_B")


def test_tenant_isolation_fixture_has_no_cross_vrf_forwarding(
    fixtures_dir: Path,
) -> None:
    """No route or link may forward traffic from one tenant VRF into another."""
    topology = load_topology(fixtures_dir / "tenant_isolation.yaml")
    iface_by_id = {i.id: i for i in topology.interfaces}
    for route in topology.routes:
        assert route.vrf_id in {"TENANT_A", "TENANT_B"}
        if route.outgoing_interface_id is not None:
            assert iface_by_id[route.outgoing_interface_id].vrf_id == route.vrf_id
    for link in topology.links:
        source_vrf = iface_by_id[link.source_interface_id].vrf_id
        dest_vrf = iface_by_id[link.destination_interface_id].vrf_id
        assert source_vrf == dest_vrf, (
            f"link {link.id} crosses VRFs: {source_vrf} -> {dest_vrf}"
        )


def test_all_fixtures_are_valid_topology_objects(fixtures_dir: Path) -> None:
    for name in ("healthy.yaml", "missing_route.yaml", "tenant_isolation.yaml"):
        topology = load_topology(fixtures_dir / name)
        assert isinstance(topology, Topology)
        assert topology.devices, f"{name} must contain devices"
