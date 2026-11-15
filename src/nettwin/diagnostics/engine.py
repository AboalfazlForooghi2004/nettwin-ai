"""Deterministic, evidence-based diagnostic engine (TASK-004).

The engine answers one question: does the *modeled* network provide a valid
path from a source endpoint to a destination endpoint?

Design rules
------------
- No LLM involvement: every status and finding comes from deterministic code.
- Endpoint identity is (endpoint id + VRF), never an IP address alone.
- Reachability requires routing + VRF context; a graph path alone proves
  nothing.
- Every finding carries structured evidence referencing modeled objects.
- Missing information yields ``unknown``/``incomplete`` — never a confirmed
  ``unreachable``.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

from nettwin.domain.models import (
    DiagnosticFinding,
    DiagnosticResult,
    DiagnosticStatus,
    Endpoint,
    EvidenceItem,
    FindingCode,
    FindingSeverity,
    Interface,
    Link,
    Route,
    Service,
)
from nettwin.graph import NetworkGraph

logger = logging.getLogger("nettwin.diagnostics")

BASE_LIMITATIONS: list[str] = [
    "Modeled-network analyzer: results reflect the YAML topology model, "
    "not live device state.",
    "Simplified routing: per-hop longest-prefix match within a single VRF "
    "table; no ECMP, policy routing, or recursive FIB fallback.",
    "VRF handoffs are only permitted at explicit service boundaries "
    "(service.allowed_vrfs); there is no implicit route leaking.",
]

_SEVERITY_BY_CODE: dict[FindingCode, FindingSeverity] = {
    FindingCode.TENANT_ISOLATION: FindingSeverity.CRITICAL,
    FindingCode.MISSING_ROUTE: FindingSeverity.HIGH,
    FindingCode.INTERFACE_DOWN: FindingSeverity.HIGH,
    FindingCode.LINK_DOWN: FindingSeverity.HIGH,
    FindingCode.VRF_MISMATCH: FindingSeverity.HIGH,
    FindingCode.NEXT_HOP_UNRESOLVED: FindingSeverity.HIGH,
    FindingCode.ROUTE_LOOP: FindingSeverity.HIGH,
    FindingCode.INSUFFICIENT_DATA: FindingSeverity.MEDIUM,
}


class _Failure:
    """Internal carrier for a blocking finding plus its result status."""

    def __init__(self, finding: DiagnosticFinding, status: DiagnosticStatus) -> None:
        self.finding = finding
        self.status = status
        self.code = finding.code


class DiagnosticEngine:
    """Runs deterministic connectivity diagnostics over a ``NetworkGraph``."""

    def __init__(self, graph: NetworkGraph) -> None:
        self._graph = graph
        self._routes_by_table: dict[tuple[str, str], list[Route]] = {}
        for route in graph.topology.routes:
            self._routes_by_table.setdefault(
                (route.device_id, route.vrf_id), []
            ).append(route)

    @property
    def graph(self) -> NetworkGraph:
        return self._graph

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(
        self,
        source_id: str,
        destination_id: str,
        *,
        source_vrf_id: str | None = None,
    ) -> DiagnosticResult:
        """Analyze modeled connectivity between two endpoints.

        Args:
            source_id: Source endpoint id (an IP address is NOT accepted as
                an identifier).
            destination_id: Destination endpoint id.
            source_vrf_id: Optional VRF context expected for the source; a
                mismatch produces a VRF_MISMATCH finding with incomplete
                status.

        Returns:
            A ``DiagnosticResult`` with explicit status, findings, evidence,
            and limitations.

        Raises:
            EndpointNotFoundError: If either endpoint id is unknown.
        """
        analysis_id = uuid.uuid4().hex[:16]
        source = self._graph.get_endpoint(source_id)
        destination = self._graph.get_endpoint(destination_id)

        evidence: list[EvidenceItem] = [
            _endpoint_resolution_evidence(source),
            _endpoint_resolution_evidence(destination),
        ]

        # --- VRF context validation -----------------------------------
        if source_vrf_id is not None:
            self._graph.get_vrf(source_vrf_id)  # explicit error for unknown VRF
            if source_vrf_id != source.vrf_id:
                finding = self._finding(
                    FindingCode.VRF_MISMATCH,
                    f"VRF_MISMATCH:context:{source.id}",
                    source=source,
                    destination=destination,
                    vrf_id=source.vrf_id,
                    title="Requested VRF context does not match source endpoint",
                    description=(
                        f"Request asked for VRF context {source_vrf_id!r} but "
                        f"endpoint {source.id!r} is modeled in VRF "
                        f"{source.vrf_id!r}."
                    ),
                    evidence=[
                        EvidenceItem(
                            type="vrf_context",
                            endpoint_id=source.id,
                            requested_vrf_id=source_vrf_id,
                            endpoint_vrf_id=source.vrf_id,
                            result="mismatch",
                        )
                    ],
                    recommendations=[
                        "Re-issue the request with the endpoint's modeled VRF, "
                        "or correct the endpoint's VRF in the topology model.",
                    ],
                    status=DiagnosticStatus.INCOMPLETE,
                )
                return self._result(
                    analysis_id,
                    source,
                    destination,
                    DiagnosticStatus.INCOMPLETE,
                    [finding],
                    evidence,
                )

        # --- Endpoint attachment completeness --------------------------
        if source.device_id is None or destination.device_id is None:
            missing = sorted(
                endpoint.id
                for endpoint in (source, destination)
                if endpoint.device_id is None
            )
            finding = self._finding(
                FindingCode.INSUFFICIENT_DATA,
                f"INSUFFICIENT_DATA:attachment:{','.join(missing)}",
                source=source,
                destination=destination,
                vrf_id=source.vrf_id,
                title="Endpoint is not attached to a device",
                description=(
                    f"Endpoint(s) {', '.join(missing)} have no device_id, so "
                    f"forwarding cannot be evaluated."
                ),
                evidence=[
                    EvidenceItem(
                        type="endpoint_attachment",
                        endpoint_id=endpoint.id,
                        device_id=None,
                        result="unattached",
                    )
                    for endpoint in (source, destination)
                    if endpoint.device_id is None
                ],
                recommendations=[
                    "Attach the endpoint to a device in the topology model "
                    "(set device_id).",
                ],
                status=DiagnosticStatus.INCOMPLETE,
            )
            return self._result(
                analysis_id,
                source,
                destination,
                DiagnosticStatus.INCOMPLETE,
                [finding],
                evidence,
            )

        # --- Tenant boundary validation --------------------------------
        source_vrf = self._graph.get_vrf(source.vrf_id)
        destination_vrf = self._graph.get_vrf(destination.vrf_id)
        service = self._graph.find_service_for_endpoint(destination.id)
        boundary = self._graph.check_tenant_boundary(
            source.vrf_id, destination.vrf_id, service=service
        )
        boundary_evidence = EvidenceItem(
            type="tenant_boundary",
            source_vrf_id=boundary.source_vrf_id,
            destination_vrf_id=boundary.destination_vrf_id,
            source_tenant_id=source_vrf.tenant_id,
            destination_tenant_id=destination_vrf.tenant_id,
            decision=boundary.decision.value,
            reason=boundary.reason,
            result="allowed" if boundary.allowed else "denied",
        )
        evidence.append(boundary_evidence)
        if not boundary.allowed:
            code = (
                FindingCode.TENANT_ISOLATION
                if boundary.decision.value == "denied_cross_tenant"
                else FindingCode.VRF_MISMATCH
            )
            subject = f"{source.vrf_id}->{destination.vrf_id}"
            finding = self._finding(
                code,
                f"{code.value}:{subject}",
                source=source,
                destination=destination,
                vrf_id=source.vrf_id,
                title=(
                    "Cross-tenant access denied"
                    if code is FindingCode.TENANT_ISOLATION
                    else "Cross-VRF access has no explicit relationship"
                ),
                description=boundary.reason,
                evidence=[boundary_evidence],
                recommendations=(
                    [
                        "Model an explicit service relationship "
                        "(service.allowed_vrfs) if this traffic is intended.",
                        "Never rely on matching IP addresses across tenants.",
                    ]
                    if code is FindingCode.TENANT_ISOLATION
                    else [
                        "Model an explicit routing or service relationship "
                        "between the two VRFs.",
                        "Verify the destination endpoint's VRF is correct.",
                    ]
                ),
                status=DiagnosticStatus.UNREACHABLE,
            )
            logger.info(
                "analysis %s: %s -> %s denied (%s)",
                analysis_id,
                source.id,
                destination.id,
                code.value,
            )
            return self._result(
                analysis_id,
                source,
                destination,
                DiagnosticStatus.UNREACHABLE,
                [finding],
                evidence,
            )

        logger.info(
            "analysis %s: %s (%s) -> %s (%s): boundary %s",
            analysis_id,
            source.id,
            source.vrf_id,
            destination.id,
            destination.vrf_id,
            boundary.decision.value,
        )
        return self._walk(analysis_id, source, destination, service, evidence)

    # ------------------------------------------------------------------
    # Forwarding walk
    # ------------------------------------------------------------------

    def _walk(
        self,
        analysis_id: str,
        source: Endpoint,
        destination: Endpoint,
        service: Service | None,
        evidence: list[EvidenceItem],
    ) -> DiagnosticResult:
        current_device = source.device_id
        current_vrf = source.vrf_id
        assert current_device is not None  # validated before the walk
        visited: set[tuple[str, str]] = set()
        limitations = list(BASE_LIMITATIONS)

        while True:
            state = (current_device, current_vrf)

            # --- loop guard --------------------------------------------
            if state in visited:
                finding = self._finding(
                    FindingCode.ROUTE_LOOP,
                    f"ROUTE_LOOP:{current_device}:{current_vrf}",
                    source=source,
                    destination=destination,
                    vrf_id=current_vrf,
                    title="Forwarding loop in the model",
                    description=(
                        f"Route walking revisited device {current_device!r} "
                        f"in VRF {current_vrf!r}; the modeled next hops form "
                        f"a loop toward {destination.ip_address}."
                    ),
                    evidence=[
                        EvidenceItem(
                            type="route_loop",
                            device_id=current_device,
                            vrf_id=current_vrf,
                            destination=str(destination.ip_address),
                            result="loop_detected",
                        )
                    ],
                    recommendations=[
                        f"Break the next-hop loop on {current_device} in "
                        f"VRF {current_vrf}.",
                    ],
                    status=DiagnosticStatus.UNREACHABLE,
                )
                logger.info(
                    "analysis %s: route loop at %s/%s",
                    analysis_id,
                    current_device,
                    current_vrf,
                )
                return self._result(
                    analysis_id,
                    source,
                    destination,
                    DiagnosticStatus.UNREACHABLE,
                    [finding],
                    evidence,
                    limitations,
                )
            visited.add(state)

            # --- arrival check ------------------------------------------
            if (
                current_device == destination.device_id
                and current_vrf == destination.vrf_id
            ):
                evidence.append(
                    EvidenceItem(
                        type="arrival",
                        device_id=current_device,
                        vrf_id=current_vrf,
                        endpoint_id=destination.id,
                        result="reached",
                    )
                )
                logger.info(
                    "analysis %s: %s reachable at %s/%s",
                    analysis_id,
                    destination.id,
                    current_device,
                    current_vrf,
                )
                return self._result(
                    analysis_id,
                    source,
                    destination,
                    DiagnosticStatus.REACHABLE,
                    [],
                    evidence,
                    limitations,
                )

            # --- local delivery after permitted service handoff ---------
            if (
                current_device == destination.device_id
                and current_vrf != destination.vrf_id
                and service is not None
                and service.endpoint_id == destination.id
                and current_vrf in service.allowed_vrfs
            ):
                evidence.append(
                    EvidenceItem(
                        type="vrf_handoff",
                        device_id=current_device,
                        from_vrf_id=current_vrf,
                        to_vrf_id=destination.vrf_id,
                        service_id=service.id,
                        result="permitted",
                    )
                )
                evidence.append(
                    EvidenceItem(
                        type="arrival",
                        device_id=current_device,
                        vrf_id=destination.vrf_id,
                        endpoint_id=destination.id,
                        result="reached",
                    )
                )
                return self._result(
                    analysis_id,
                    source,
                    destination,
                    DiagnosticStatus.REACHABLE,
                    [],
                    evidence,
                    limitations,
                )

            # --- longest-prefix route lookup ----------------------------
            route, lookup_evidence, inactive_ids = self._lookup_route(
                current_device, current_vrf, destination.ip_address
            )
            evidence.extend(lookup_evidence)
            if inactive_ids:
                limitations.append(
                    f"Inactive route(s) {', '.join(sorted(inactive_ids))} "
                    f"cover the destination on {current_device} in "
                    f"{current_vrf} but are not eligible."
                )
            if route is None:
                finding = self._finding(
                    FindingCode.MISSING_ROUTE,
                    f"MISSING_ROUTE:{current_device}:{current_vrf}",
                    source=source,
                    destination=destination,
                    vrf_id=current_vrf,
                    title="No active route to destination",
                    description=(
                        f"Device {current_device!r} has no active route in "
                        f"VRF {current_vrf} covering "
                        f"{destination.ip_address} "
                        f"(longest-prefix match found nothing)."
                    ),
                    evidence=lookup_evidence,
                    recommendations=[
                        f"Add a route to {destination.ip_address} on "
                        f"{current_device} in VRF {current_vrf}.",
                        "Verify the routing protocol is adjaced and "
                        "advertising the prefix.",
                    ],
                    status=DiagnosticStatus.UNREACHABLE,
                )
                logger.info(
                    "analysis %s: missing route on %s/%s for %s",
                    analysis_id,
                    current_device,
                    current_vrf,
                    destination.ip_address,
                )
                return self._result(
                    analysis_id,
                    source,
                    destination,
                    DiagnosticStatus.UNREACHABLE,
                    [finding],
                    evidence,
                    limitations,
                )

            # --- forward one hop ----------------------------------------
            hop = self._resolve_hop(
                source,
                route,
                current_device,
                current_vrf,
                destination,
                service,
            )
            evidence.extend(hop["evidence"])
            failure: _Failure | None = hop["failure"]
            if failure is not None:
                logger.info(
                    "analysis %s: hop failure %s at %s/%s",
                    analysis_id,
                    failure.code.value,
                    current_device,
                    current_vrf,
                )
                return self._result(
                    analysis_id,
                    source,
                    destination,
                    failure.status,
                    [failure.finding],
                    evidence,
                    limitations,
                )

            current_device = hop["next_device"]
            current_vrf = hop["next_vrf"]

    # ------------------------------------------------------------------
    # Routing helpers
    # ------------------------------------------------------------------

    def _lookup_route(
        self, device_id: str, vrf_id: str, destination_ip: Any
    ) -> tuple[Route | None, list[EvidenceItem], list[str]]:
        """Longest-prefix match among active routes in one VRF table.

        Returns:
            ``(matched route or None, evidence items, inactive covering
            route ids)``.
        """
        table = self._routes_by_table.get((device_id, vrf_id), [])
        covering = [
            route
            for route in table
            if route.destination_prefix.version == destination_ip.version
            and destination_ip in route.destination_prefix
        ]
        covering.sort(
            key=lambda route: (-route.destination_prefix.prefixlen, route.id)
        )
        active = [route for route in covering if route.active]
        inactive_ids = [route.id for route in covering if not route.active]

        matched = active[0] if active else None
        if matched is not None:
            result = "matched"
        elif covering:
            result = "no_active_route"
        else:
            result = "no_matching_route"

        evidence = [
            EvidenceItem(
                type="route_lookup",
                device_id=device_id,
                vrf_id=vrf_id,
                destination=str(destination_ip),
                matched_route=matched.id if matched is not None else None,
                matched_prefix=(
                    str(matched.destination_prefix)
                    if matched is not None
                    else None
                ),
                covering_routes=[route.id for route in covering],
                inactive_covering_routes=inactive_ids,
                result=result,
            )
        ]
        return matched, evidence, inactive_ids

    def _resolve_hop(
        self,
        source: Endpoint,
        route: Route,
        current_device: str,
        current_vrf: str,
        destination: Endpoint,
        service: Service | None,
    ) -> dict:
        """Validate interface/link/next-hop state and resolve the next hop.

        Returns a dict with ``evidence`` (list), ``failure`` (``_Failure`` or
        ``None``), ``next_device``, ``next_vrf``.
        """
        evidence: list[EvidenceItem] = []
        out_interface: Interface | None = None
        out_state_evidence: EvidenceItem | None = None

        if route.outgoing_interface_id is not None:
            out_interface = self._graph.get_interface(route.outgoing_interface_id)

            # --- interface state (source side) -------------------------
            out_state_evidence = EvidenceItem(
                type="interface_state",
                interface_id=out_interface.id,
                device_id=out_interface.device_id,
                vrf_id=out_interface.vrf_id,
                admin_state=out_interface.admin_state.value,
                oper_state=out_interface.oper_state.value,
                result="up" if out_interface.is_up else "down",
            )
            evidence.append(out_state_evidence)
            if not out_interface.is_up:
                finding = self._finding(
                    FindingCode.INTERFACE_DOWN,
                    f"INTERFACE_DOWN:{out_interface.id}",
                    source=source,
                    destination=destination,
                    vrf_id=current_vrf,
                    title="Required interface is down",
                    description=(
                        f"Interface {out_interface.id!r} on device "
                        f"{out_interface.device_id!r} is "
                        f"admin={out_interface.admin_state.value}/"
                        f"oper={out_interface.oper_state.value}."
                    ),
                    evidence=[out_state_evidence],
                    recommendations=[
                        f"Check admin/oper state of {out_interface.id} on "
                        f"{out_interface.device_id}.",
                    ],
                    status=DiagnosticStatus.UNREACHABLE,
                )
                return {
                    "evidence": evidence,
                    "failure": _Failure(finding, DiagnosticStatus.UNREACHABLE),
                    "next_device": current_device,
                    "next_vrf": current_vrf,
                }

        # --- resolve peer via next hop / outgoing interface -------------
        resolution = self._resolve_peer(
            source, route, out_interface, current_device, current_vrf,
            destination,
        )
        evidence.extend(resolution["evidence"])
        if resolution["failure"] is not None:
            return {
                "evidence": evidence,
                "failure": resolution["failure"],
                "next_device": current_device,
                "next_vrf": current_vrf,
            }

        link: Link = resolution["link"]
        peer_interface: Interface = resolution["peer_interface"]

        # --- link state -------------------------------------------------
        link_up = link.state.value == "up"
        link_evidence = EvidenceItem(
            type="link_traversal",
            link_id=link.id,
            source_interface_id=link.source_interface_id,
            destination_interface_id=link.destination_interface_id,
            result="up" if link_up else "down",
        )
        evidence.append(link_evidence)
        if not link_up:
            finding_evidence = (
                [out_state_evidence, link_evidence]
                if out_state_evidence is not None
                else [link_evidence]
            )
            finding = self._finding(
                FindingCode.LINK_DOWN,
                f"LINK_DOWN:{link.id}",
                source=source,
                destination=destination,
                vrf_id=current_vrf,
                title="Required link is down",
                description=(
                    f"Link {link.id!r} between "
                    f"{link.source_interface_id!r} and "
                    f"{link.destination_interface_id!r} is down."
                ),
                evidence=finding_evidence,
                recommendations=[
                    f"Verify the physical/logical link {link.id!r}.",
                ],
                status=DiagnosticStatus.UNREACHABLE,
            )
            return {
                "evidence": evidence,
                "failure": _Failure(finding, DiagnosticStatus.UNREACHABLE),
                "next_device": current_device,
                "next_vrf": current_vrf,
            }

        # --- interface state (peer side) -------------------------------
        peer_state_evidence = EvidenceItem(
            type="interface_state",
            interface_id=peer_interface.id,
            device_id=peer_interface.device_id,
            vrf_id=peer_interface.vrf_id,
            admin_state=peer_interface.admin_state.value,
            oper_state=peer_interface.oper_state.value,
            result="up" if peer_interface.is_up else "down",
        )
        evidence.append(peer_state_evidence)
        if not peer_interface.is_up:
            finding = self._finding(
                FindingCode.INTERFACE_DOWN,
                f"INTERFACE_DOWN:{peer_interface.id}",
                source=source,
                destination=destination,
                vrf_id=current_vrf,
                title="Peer interface is down",
                description=(
                    f"Interface {peer_interface.id!r} on device "
                    f"{peer_interface.device_id!r} is "
                    f"admin={peer_interface.admin_state.value}/"
                    f"oper={peer_interface.oper_state.value}."
                ),
                evidence=[peer_state_evidence],
                recommendations=[
                    f"Check admin/oper state of {peer_interface.id} on "
                    f"{peer_interface.device_id}.",
                ],
                status=DiagnosticStatus.UNREACHABLE,
            )
            return {
                "evidence": evidence,
                "failure": _Failure(finding, DiagnosticStatus.UNREACHABLE),
                "next_device": current_device,
                "next_vrf": current_vrf,
            }

        # --- VRF handoff check -----------------------------------------
        peer_vrf = peer_interface.vrf_id
        if peer_vrf != current_vrf:
            permitted = (
                peer_vrf == destination.vrf_id
                and service is not None
                and service.endpoint_id == destination.id
                and current_vrf in service.allowed_vrfs
            )
            handoff_evidence = EvidenceItem(
                type="vrf_handoff",
                device_id=peer_interface.device_id,
                from_vrf_id=current_vrf,
                to_vrf_id=peer_vrf,
                service_id=service.id if service is not None else None,
                result="permitted" if permitted else "denied",
            )
            evidence.append(handoff_evidence)
            if not permitted:
                same_tenant = _same_tenant(self._graph, current_vrf, peer_vrf)
                code = (
                    FindingCode.VRF_MISMATCH
                    if same_tenant
                    else FindingCode.TENANT_ISOLATION
                )
                subject = (
                    f"handoff:{peer_interface.device_id}:"
                    f"{current_vrf}->{peer_vrf}"
                )
                finding = self._finding(
                    code,
                    f"{code.value}:{subject}",
                    source=source,
                    destination=destination,
                    vrf_id=current_vrf,
                    title=(
                        "Route forwards into a non-permitted VRF"
                        if code is FindingCode.VRF_MISMATCH
                        else "Route handoff crosses a tenant boundary"
                    ),
                    description=(
                        f"Route {route.id!r} on {current_device!r} in VRF "
                        f"{current_vrf!r} forwards out "
                        f"{peer_interface.id!r} into VRF {peer_vrf!r}, which "
                        f"is not the destination VRF "
                        f"{destination.vrf_id!r} under a permitted service "
                        f"relationship."
                    ),
                    evidence=[handoff_evidence],
                    recommendations=[
                        "Correct the route's outgoing interface/VRF.",
                        "Model an explicit service relationship if this "
                        "handoff is intended.",
                    ],
                    status=DiagnosticStatus.UNREACHABLE,
                )
                return {
                    "evidence": evidence,
                    "failure": _Failure(finding, DiagnosticStatus.UNREACHABLE),
                    "next_device": current_device,
                    "next_vrf": current_vrf,
                }

        return {
            "evidence": evidence,
            "failure": None,
            "next_device": peer_interface.device_id,
            "next_vrf": peer_vrf if peer_vrf is not None else current_vrf,
        }

    def _resolve_peer(
        self,
        source: Endpoint,
        route: Route,
        out_interface: Interface | None,
        current_device: str,
        current_vrf: str,
        destination: Endpoint,
    ) -> dict:
        """Resolve the next-hop peer interface and traversable link.

        Returns a dict with ``evidence``, ``failure``, ``link``,
        ``peer_interface``.
        """
        evidence: list[EvidenceItem] = []

        if out_interface is not None:
            links = self._links_on(out_interface.id)
            if not links:
                finding = self._insufficient_data_finding(
                    source=source,
                    destination=destination,
                    subject=f"no-link:{out_interface.id}",
                    vrf_id=current_vrf,
                    description=(
                        f"No link is modeled on interface "
                        f"{out_interface.id!r}, so the next hop "
                        f"{route.next_hop} cannot be traced."
                    ),
                    evidence=[
                        EvidenceItem(
                            type="link_traversal",
                            interface_id=out_interface.id,
                            device_id=out_interface.device_id,
                            result="no_modeled_link",
                        )
                    ],
                )
                return {
                    "evidence": evidence,
                    "failure": _Failure(finding, DiagnosticStatus.UNKNOWN),
                    "link": None,
                    "peer_interface": None,
                }

            if route.next_hop is None:
                # On-link/connected claim while not yet at the destination
                # device: the model does not describe how to reach the
                # endpoint from here.
                finding = self._insufficient_data_finding(
                    source=source,
                    destination=destination,
                    subject=f"onlink:{route.id}",
                    vrf_id=current_vrf,
                    description=(
                        f"Route {route.id!r} on {current_device!r} claims "
                        f"{route.destination_prefix} is on-link via "
                        f"{out_interface.id!r}, but the destination endpoint "
                        f"is attached to another device; the model lacks "
                        f"forwarding information for this hop."
                    ),
                    evidence=[
                        EvidenceItem(
                            type="route_lookup",
                            device_id=current_device,
                            vrf_id=current_vrf,
                            destination=str(destination.ip_address),
                            matched_route=route.id,
                            result="onlink_without_local_delivery",
                        )
                    ],
                )
                return {
                    "evidence": evidence,
                    "failure": _Failure(finding, DiagnosticStatus.UNKNOWN),
                    "link": None,
                    "peer_interface": None,
                }

            # Choose the link whose peer holds the next-hop address.
            candidates: list[tuple[Link, Interface]] = []
            for link in links:
                peer = self._other_end(link, out_interface.id)
                if route.next_hop in {addr.ip for addr in peer.ipv4_addresses}:
                    candidates.append((link, peer))
            if not candidates:
                resolution_evidence = EvidenceItem(
                    type="next_hop_resolution",
                    next_hop=str(route.next_hop),
                    outgoing_interface_id=out_interface.id,
                    result="next_hop_not_on_peer",
                )
                evidence.append(resolution_evidence)
                finding = self._next_hop_finding(
                    source=source,
                    destination=destination,
                    route=route,
                    current_device=current_device,
                    current_vrf=current_vrf,
                    description=(
                        f"Route {route.id!r} on {current_device!r} in VRF "
                        f"{current_vrf!r} has next hop {route.next_hop}, but "
                        f"no peer of {out_interface.id!r} holds that address."
                    ),
                    evidence=evidence,
                )
                return {
                    "evidence": evidence,
                    "failure": _Failure(finding, DiagnosticStatus.UNREACHABLE),
                    "link": None,
                    "peer_interface": None,
                }
            candidates.sort(key=lambda item: item[0].id)
            link, peer = candidates[0]
            evidence.append(
                EvidenceItem(
                    type="next_hop_resolution",
                    next_hop=str(route.next_hop),
                    outgoing_interface_id=out_interface.id,
                    peer_device_id=peer.device_id,
                    peer_interface_id=peer.id,
                    result="resolved",
                )
            )
            return {
                "evidence": evidence,
                "failure": None,
                "link": link,
                "peer_interface": peer,
            }

        # No outgoing interface: recursive lookup of the next hop by address.
        assert route.next_hop is not None
        candidates = [
            iface
            for iface in self._graph.topology.interfaces
            if iface.device_id != current_device
            and route.next_hop in {addr.ip for addr in iface.ipv4_addresses}
        ]
        # Prefer same-VRF interfaces, then stable id order.
        candidates.sort(
            key=lambda iface: (0 if iface.vrf_id == current_vrf else 1, iface.id)
        )
        if not candidates:
            resolution_evidence = EvidenceItem(
                type="next_hop_resolution",
                next_hop=str(route.next_hop),
                outgoing_interface_id=None,
                result="next_hop_not_found",
            )
            evidence.append(resolution_evidence)
            finding = self._next_hop_finding(
                source=source,
                destination=destination,
                route=route,
                current_device=current_device,
                current_vrf=current_vrf,
                description=(
                    f"Route {route.id!r} on {current_device!r} in VRF "
                    f"{current_vrf!r} has next hop {route.next_hop}, but no "
                    f"modeled interface holds that address."
                ),
                evidence=evidence,
            )
            return {
                "evidence": evidence,
                "failure": _Failure(finding, DiagnosticStatus.UNREACHABLE),
                "link": None,
                "peer_interface": None,
            }

        peer = candidates[0]
        evidence.append(
            EvidenceItem(
                type="next_hop_resolution",
                next_hop=str(route.next_hop),
                outgoing_interface_id=None,
                peer_device_id=peer.device_id,
                peer_interface_id=peer.id,
                result="resolved",
            )
        )

        # Find a link between the current device and the peer interface.
        links = [
            link
            for link in self._links_on(peer.id)
            if self._other_end(link, peer.id).device_id == current_device
        ]
        if not links:
            finding = self._insufficient_data_finding(
                source=source,
                destination=destination,
                subject=f"no-link:{route.id}",
                vrf_id=current_vrf,
                description=(
                    f"Next hop {route.next_hop} of route {route.id!r} "
                    f"resolves to {peer.id!r} on {peer.device_id!r}, but no "
                    f"link from {current_device!r} is modeled."
                ),
                evidence=evidence,
            )
            return {
                "evidence": evidence,
                "failure": _Failure(finding, DiagnosticStatus.UNKNOWN),
                "link": None,
                "peer_interface": None,
            }
        links.sort(key=lambda link: (0 if link.state.value == "up" else 1, link.id))
        return {
            "evidence": evidence,
            "failure": None,
            "link": links[0],
            "peer_interface": peer,
        }

    # ------------------------------------------------------------------
    # Finding helpers
    # ------------------------------------------------------------------

    def _links_on(self, interface_id: str) -> list[Link]:
        return [
            link
            for link in self._graph.topology.links
            if interface_id
            in (link.source_interface_id, link.destination_interface_id)
        ]

    def _other_end(self, link: Link, interface_id: str) -> Interface:
        other_id = (
            link.destination_interface_id
            if link.source_interface_id == interface_id
            else link.source_interface_id
        )
        return self._graph.get_interface(other_id)

    def _finding(
        self,
        code: FindingCode,
        finding_id: str,
        *,
        source: Endpoint | None,
        destination: Endpoint | None,
        vrf_id: str | None,
        title: str,
        description: str,
        evidence: list[EvidenceItem],
        recommendations: list[str],
        status: DiagnosticStatus,
    ) -> DiagnosticFinding:
        return DiagnosticFinding(
            id=finding_id,
            code=code,
            severity=_SEVERITY_BY_CODE[code],
            title=title,
            description=description,
            source_id=source.id if source is not None else None,
            destination_id=destination.id if destination is not None else None,
            vrf_id=vrf_id,
            evidence=evidence,
            recommendations=recommendations,
            status=status,
        )

    def _next_hop_finding(
        self,
        *,
        source: Endpoint,
        destination: Endpoint,
        route: Route,
        current_device: str,
        current_vrf: str,
        description: str,
        evidence: list[EvidenceItem],
    ) -> DiagnosticFinding:
        return self._finding(
            FindingCode.NEXT_HOP_UNRESOLVED,
            f"NEXT_HOP_UNRESOLVED:{route.id}",
            source=source,
            destination=destination,
            vrf_id=current_vrf,
            title="Route next hop cannot be resolved",
            description=description,
            evidence=evidence,
            recommendations=[
                f"Correct the next hop of route {route.id!r} on "
                f"{current_device!r}, or model the missing adjacency.",
            ],
            status=DiagnosticStatus.UNREACHABLE,
        )

    def _insufficient_data_finding(
        self,
        *,
        source: Endpoint,
        destination: Endpoint,
        subject: str,
        vrf_id: str | None,
        description: str,
        evidence: list[EvidenceItem],
    ) -> DiagnosticFinding:
        return self._finding(
            FindingCode.INSUFFICIENT_DATA,
            f"INSUFFICIENT_DATA:{subject}",
            source=source,
            destination=destination,
            vrf_id=vrf_id,
            title="Model lacks data required to decide reachability",
            description=description,
            evidence=evidence,
            recommendations=[
                "Complete the topology model (links/attachments) for this hop.",
            ],
            status=DiagnosticStatus.UNKNOWN,
        )

    def _result(
        self,
        analysis_id: str,
        source: Endpoint,
        destination: Endpoint,
        status: DiagnosticStatus,
        findings: list[DiagnosticFinding],
        evidence: list[EvidenceItem],
        limitations: list[str] | None = None,
    ) -> DiagnosticResult:
        return DiagnosticResult(
            analysis_id=analysis_id,
            source_id=source.id,
            destination_id=destination.id,
            status=status,
            vrf_id=source.vrf_id,
            findings=findings,
            evidence=evidence,
            limitations=limitations
            if limitations is not None
            else list(BASE_LIMITATIONS),
        )


def _endpoint_resolution_evidence(endpoint: Endpoint) -> EvidenceItem:
    return EvidenceItem(
        type="endpoint_resolution",
        endpoint_id=endpoint.id,
        ip_address=str(endpoint.ip_address),
        vrf_id=endpoint.vrf_id,
        device_id=endpoint.device_id,
        result="resolved",
    )


def _same_tenant(graph: NetworkGraph, vrf_a: str, vrf_b: str) -> bool:
    tenant_a = graph.get_vrf(vrf_a).tenant_id
    tenant_b = graph.get_vrf(vrf_b).tenant_id
    if tenant_a is None or tenant_b is None:
        return False
    return tenant_a == tenant_b
