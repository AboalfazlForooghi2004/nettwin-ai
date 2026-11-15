"""VRF-aware network topology graph built with NetworkX.

The graph represents devices, interfaces, links, VRF membership, endpoints,
and services as typed nodes/edges. Every query preserves VRF context: IP
address equality never implies connectivity, and overlapping prefixes in
different VRFs never merge into a shared path.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

import networkx as nx

from nettwin.domain.models import (
    VRF,
    Device,
    Endpoint,
    Interface,
    Link,
    LinkState,
    Service,
    Topology,
)
from nettwin.errors import EndpointNotFoundError, ObjectNotFoundError


class BoundaryDecision(StrEnum):
    """Outcome of a tenant-boundary check."""

    ALLOWED_SAME_VRF = "allowed_same_vrf"
    ALLOWED_EXPLICIT_SERVICE = "allowed_explicit_service"
    DENIED_CROSS_TENANT = "denied_cross_tenant"
    DENIED_NO_EXPLICIT_RELATIONSHIP = "denied_no_explicit_relationship"


@dataclass(frozen=True)
class TenantBoundaryResult:
    """Deterministic tenant-boundary decision with a human-readable reason."""

    allowed: bool
    decision: BoundaryDecision
    source_vrf_id: str
    destination_vrf_id: str
    reason: str


class NetworkGraph:
    """A VRF-aware topology graph derived from a validated ``Topology``."""

    def __init__(self, topology: Topology) -> None:
        self._topology = topology
        self._graph: nx.MultiGraph = nx.MultiGraph()

        self._devices: dict[str, Device] = {d.id: d for d in topology.devices}
        self._interfaces: dict[str, Interface] = {i.id: i for i in topology.interfaces}
        self._links: dict[str, Link] = {link.id: link for link in topology.links}
        self._vrfs: dict[str, VRF] = {v.id: v for v in topology.vrfs}
        self._endpoints: dict[str, Endpoint] = {e.id: e for e in topology.endpoints}
        self._services: dict[str, Service] = {s.id: s for s in topology.services}

        self._interfaces_by_device: dict[str, list[Interface]] = {}
        for iface in topology.interfaces:
            self._interfaces_by_device.setdefault(iface.device_id, []).append(iface)

        self._links_by_interface: dict[str, list[Link]] = {}
        for link in topology.links:
            self._links_by_interface.setdefault(link.source_interface_id, []).append(link)
            self._links_by_interface.setdefault(
                link.destination_interface_id, []
            ).append(link)

        self._services_by_endpoint: dict[str, Service] = {}
        for service in topology.services:
            self._services_by_endpoint[service.endpoint_id] = service

        self._build()

    # ------------------------------------------------------------------
    # Build
    # ------------------------------------------------------------------

    def _build(self) -> None:
        graph = self._graph

        for device in self._topology.devices:
            graph.add_node(
                ("device", device.id),
                kind="device",
                name=device.name,
                vendor=device.vendor,
                platform=device.platform,
            )

        for vrf in self._topology.vrfs:
            graph.add_node(
                ("vrf", vrf.id),
                kind="vrf",
                name=vrf.name,
                tenant_id=vrf.tenant_id,
            )

        for iface in self._topology.interfaces:
            graph.add_node(
                ("interface", iface.id),
                kind="interface",
                device_id=iface.device_id,
                vrf_id=iface.vrf_id,
                admin_state=iface.admin_state.value,
                oper_state=iface.oper_state.value,
                ipv4_addresses=[str(addr) for addr in iface.ipv4_addresses],
            )
            graph.add_edge(
                ("device", iface.device_id),
                ("interface", iface.id),
                kind="has_interface",
            )
            if iface.vrf_id is not None:
                graph.add_edge(
                    ("vrf", iface.vrf_id),
                    ("interface", iface.id),
                    kind="member_of",
                )

        for link in self._topology.links:
            graph.add_edge(
                ("interface", link.source_interface_id),
                ("interface", link.destination_interface_id),
                kind="link",
                link_id=link.id,
                state=link.state.value,
            )

        for endpoint in self._topology.endpoints:
            graph.add_node(
                ("endpoint", endpoint.id),
                kind="endpoint",
                name=endpoint.name,
                ip_address=str(endpoint.ip_address),
                vrf_id=endpoint.vrf_id,
                device_id=endpoint.device_id,
            )
            graph.add_edge(
                ("endpoint", endpoint.id),
                ("vrf", endpoint.vrf_id),
                kind="in_vrf",
            )
            if endpoint.device_id is not None:
                graph.add_edge(
                    ("endpoint", endpoint.id),
                    ("device", endpoint.device_id),
                    kind="attached_to",
                )

        for service in self._topology.services:
            graph.add_node(
                ("service", service.id),
                kind="service",
                name=service.name,
                protocol=service.protocol,
                port=service.port,
            )
            graph.add_edge(
                ("service", service.id),
                ("endpoint", service.endpoint_id),
                kind="exposes",
            )
            for vrf_id in service.allowed_vrfs:
                graph.add_edge(("service", service.id), ("vrf", vrf_id), kind="allows")

    # ------------------------------------------------------------------
    # Accessors
    # ------------------------------------------------------------------

    @property
    def topology(self) -> Topology:
        """The validated topology this graph was built from."""
        return self._topology

    @property
    def graph(self) -> nx.MultiGraph:
        """The underlying NetworkX graph (read-only usage expected)."""
        return self._graph

    def list_devices(self) -> list[Device]:
        return list(self._topology.devices)

    def list_vrfs(self) -> list[VRF]:
        return list(self._topology.vrfs)

    def list_endpoints(self) -> list[Endpoint]:
        return list(self._topology.endpoints)

    def list_services(self) -> list[Service]:
        return list(self._topology.services)

    def list_device_ids(self) -> list[str]:
        """Sorted device ids."""
        return sorted(self._devices)

    def list_vrf_ids(self) -> list[str]:
        """Sorted VRF ids."""
        return sorted(self._vrfs)

    def get_device(self, device_id: str) -> Device:
        try:
            return self._devices[device_id]
        except KeyError:
            raise ObjectNotFoundError("device", device_id) from None

    def get_interface(self, interface_id: str) -> Interface:
        try:
            return self._interfaces[interface_id]
        except KeyError:
            raise ObjectNotFoundError("interface", interface_id) from None

    def get_link(self, link_id: str) -> Link:
        try:
            return self._links[link_id]
        except KeyError:
            raise ObjectNotFoundError("link", link_id) from None

    def get_vrf(self, vrf_id: str) -> VRF:
        try:
            return self._vrfs[vrf_id]
        except KeyError:
            raise ObjectNotFoundError("VRF", vrf_id) from None

    def get_endpoint(self, endpoint_id: str) -> Endpoint:
        try:
            return self._endpoints[endpoint_id]
        except KeyError:
            raise EndpointNotFoundError(
                f"endpoint not found: {endpoint_id!r}"
            ) from None

    def get_service(self, service_id: str) -> Service:
        try:
            return self._services[service_id]
        except KeyError:
            raise ObjectNotFoundError("service", service_id) from None

    # ------------------------------------------------------------------
    # Topology queries
    # ------------------------------------------------------------------

    def get_device_interfaces(self, device_id: str) -> list[Interface]:
        """Interfaces of a device, in topology order."""
        self.get_device(device_id)
        return list(self._interfaces_by_device.get(device_id, []))

    def get_vrf_interfaces(self, vrf_id: str) -> list[Interface]:
        """Interfaces bound to a VRF, in topology order."""
        self.get_vrf(vrf_id)
        return [i for i in self._topology.interfaces if i.vrf_id == vrf_id]

    def get_vrf_devices(self, vrf_id: str) -> list[str]:
        """Sorted device ids owning at least one interface in the VRF."""
        return sorted({i.device_id for i in self.get_vrf_interfaces(vrf_id)})

    def get_neighbors(
        self, device_id: str, *, require_link_up: bool = False
    ) -> list[str]:
        """Device ids directly reachable across links from ``device_id``.

        Args:
            device_id: Source device.
            require_link_up: When true, ignore links whose state is down.

        Returns:
            Sorted, de-duplicated peer device ids (never includes self).
        """
        self.get_device(device_id)
        peers: set[str] = set()
        for iface in self._interfaces_by_device.get(device_id, []):
            for link in self._links_by_interface.get(iface.id, []):
                if require_link_up and link.state is not LinkState.UP:
                    continue
                peer_iface_id = (
                    link.destination_interface_id
                    if link.source_interface_id == iface.id
                    else link.source_interface_id
                )
                peer_device_id = self._interfaces[peer_iface_id].device_id
                if peer_device_id != device_id:
                    peers.add(peer_device_id)
        return sorted(peers)

    def get_interface_neighbors(
        self, interface_id: str, *, require_link_up: bool = False
    ) -> list[Interface]:
        """Peer interfaces directly connected across links."""
        self.get_interface(interface_id)
        peers: list[Interface] = []
        for link in self._links_by_interface.get(interface_id, []):
            if require_link_up and link.state is not LinkState.UP:
                continue
            peer_iface_id = (
                link.destination_interface_id
                if link.source_interface_id == interface_id
                else link.source_interface_id
            )
            peers.append(self._interfaces[peer_iface_id])
        return peers

    def connected_components(self, *, require_link_up: bool = False) -> list[set[str]]:
        """Device-level connected components over topology links.

        Components are structural (link state is ignored unless
        ``require_link_up`` is set). Routing and VRF context are NOT applied:
        a graph path alone never proves reachability.
        """
        device_graph: nx.Graph = nx.Graph()
        device_graph.add_nodes_from(self._devices)
        for link in self._topology.links:
            if require_link_up and link.state is not LinkState.UP:
                continue
            source_device = self._interfaces[link.source_interface_id].device_id
            dest_device = self._interfaces[link.destination_interface_id].device_id
            if source_device != dest_device:
                device_graph.add_edge(source_device, dest_device)
        components = list(nx.connected_components(device_graph))
        return sorted(components, key=lambda component: sorted(component))

    def get_vrf_components(self, vrf_id: str) -> list[set[str]]:
        """Connected components of devices using links inside a single VRF.

        Links whose endpoints sit in different VRFs are excluded, so traffic
        can never be inferred to cross a VRF boundary through this query.
        """
        vrf_interfaces = self.get_vrf_interfaces(vrf_id)
        vrf_iface_ids = {iface.id for iface in vrf_interfaces}
        device_graph: nx.Graph = nx.Graph()
        device_graph.add_nodes_from(i.device_id for i in vrf_interfaces)
        for link in self._topology.links:
            if (
                link.source_interface_id in vrf_iface_ids
                and link.destination_interface_id in vrf_iface_ids
            ):
                source_device = self._interfaces[link.source_interface_id].device_id
                dest_device = self._interfaces[link.destination_interface_id].device_id
                if source_device != dest_device:
                    device_graph.add_edge(source_device, dest_device)
        components = list(nx.connected_components(device_graph))
        return sorted(components, key=lambda component: sorted(component))

    def find_endpoints_by_ip(self, ip_address: str) -> list[Endpoint]:
        """All endpoints with the given IP, across ALL VRFs.

        Overlapping IPs are expected; the result never implies connectivity
        between the returned endpoints — VRF context must be compared
        separately.
        """
        normalized = str(ip_address)
        return [
            endpoint
            for endpoint in self._topology.endpoints
            if str(endpoint.ip_address) == normalized
        ]

    def get_service_allowed_vrfs(self, service_id: str) -> list[str]:
        """Explicitly allowed VRFs for a service (empty when none)."""
        return list(self.get_service(service_id).allowed_vrfs)

    def find_service_for_endpoint(self, endpoint_id: str) -> Service | None:
        """Service exposing the given endpoint, if any is modeled."""
        self.get_endpoint(endpoint_id)
        return self._services_by_endpoint.get(endpoint_id)

    # ------------------------------------------------------------------
    # Tenant boundary validation
    # ------------------------------------------------------------------

    def check_tenant_boundary(
        self,
        source_vrf_id: str,
        destination_vrf_id: str,
        *,
        service: Service | None = None,
    ) -> TenantBoundaryResult:
        """Decide whether crossing from one VRF to another is permitted.

        Rules (in order):
        1. Same VRF → allowed.
        2. Destination endpoint's service explicitly allows the source VRF →
           allowed (the only modeled cross-VRF permission).
        3. Different tenants → denied (cross-tenant isolation).
        4. Otherwise → denied: cross-VRF traffic requires an explicitly
           modeled relationship (no implicit route leaking).
        """
        source_vrf = self.get_vrf(source_vrf_id)
        destination_vrf = self.get_vrf(destination_vrf_id)

        if source_vrf.id == destination_vrf.id:
            return TenantBoundaryResult(
                allowed=True,
                decision=BoundaryDecision.ALLOWED_SAME_VRF,
                source_vrf_id=source_vrf.id,
                destination_vrf_id=destination_vrf.id,
                reason=f"source and destination share VRF {source_vrf.id!r}",
            )

        if service is not None:
            service_endpoint = self.get_endpoint(service.endpoint_id)
            if (
                service_endpoint.vrf_id == destination_vrf.id
                and source_vrf.id in service.allowed_vrfs
            ):
                return TenantBoundaryResult(
                    allowed=True,
                    decision=BoundaryDecision.ALLOWED_EXPLICIT_SERVICE,
                    source_vrf_id=source_vrf.id,
                    destination_vrf_id=destination_vrf.id,
                    reason=(
                        f"service {service.id!r} explicitly allows VRF "
                        f"{source_vrf.id!r} to reach its endpoint in VRF "
                        f"{destination_vrf.id!r}"
                    ),
                )

        source_tenant = source_vrf.tenant_id
        destination_tenant = destination_vrf.tenant_id
        if (
            source_tenant is not None
            and destination_tenant is not None
            and source_tenant != destination_tenant
        ):
            return TenantBoundaryResult(
                allowed=False,
                decision=BoundaryDecision.DENIED_CROSS_TENANT,
                source_vrf_id=source_vrf.id,
                destination_vrf_id=destination_vrf.id,
                reason=(
                    f"VRF {source_vrf.id!r} belongs to tenant {source_tenant!r} and "
                    f"VRF {destination_vrf.id!r} belongs to tenant "
                    f"{destination_tenant!r}; cross-tenant access requires an "
                    f"explicitly permitted service relationship"
                ),
            )

        return TenantBoundaryResult(
            allowed=False,
            decision=BoundaryDecision.DENIED_NO_EXPLICIT_RELATIONSHIP,
            source_vrf_id=source_vrf.id,
            destination_vrf_id=destination_vrf.id,
            reason=(
                f"no explicit service or routing relationship is modeled between "
                f"VRF {source_vrf.id!r} and VRF {destination_vrf.id!r}"
            ),
        )

    def find_tenant_boundary_violations(self) -> list[str]:
        """Link ids that implicitly connect interfaces of different tenants.

        A link whose two ends sit in VRFs owned by different tenants is an
        implicit cross-tenant adjacency (a tenant-isolation violation in the
        model). VRF handoffs inside a device are not links and are instead
        validated by the diagnostic engine against service permissions.
        """
        violations: list[str] = []
        for link in self._topology.links:
            source_vrf_id = self._interfaces[link.source_interface_id].vrf_id
            destination_vrf_id = self._interfaces[
                link.destination_interface_id
            ].vrf_id
            if (
                source_vrf_id is None
                or destination_vrf_id is None
                or source_vrf_id == destination_vrf_id
            ):
                continue
            source_tenant = self._vrfs[source_vrf_id].tenant_id
            destination_tenant = self._vrfs[destination_vrf_id].tenant_id
            if (
                source_tenant is not None
                and destination_tenant is not None
                and source_tenant != destination_tenant
            ):
                violations.append(link.id)
        return sorted(violations)
