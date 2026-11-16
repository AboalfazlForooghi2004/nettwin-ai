"""OSPF LSDB → logical topology reconstruction (Phase 2.6).

Takes the parsed LSDB of one or more devices and reconstructs:

* OSPF routers (by Router ID),
* **transit networks as first-class nodes** with their membership,
* stub networks as prefixes owned by a router,
* point-to-point logical edges, only where genuinely reciprocal.

The central rule, stated once: **a transit network is a node, not an edge.** A
multi-access segment with five routers produces one ``OspfTransitNetwork`` with
five members. It never produces ten router-to-router edges, and it never
produces a :class:`nettwin.domain.models.Link` — that type is reserved for
layer-2 adjacency confirmed by CDP.

Every derived object carries ``source_lsas`` and an explicit
:class:`OspfEvidenceState`, and conflicting evidence is reported rather than
resolved silently.
"""

from __future__ import annotations

import ipaddress
from collections import defaultdict
from dataclasses import dataclass, field

from nettwin.domain.models import Topology
from nettwin.domain.ospf_models import (
    OspfCdpRelation,
    OspfCorrelation,
    OspfEvidenceState,
    OspfInstance,
    OspfInterface,
    OspfLinkType,
    OspfLogicalEdge,
    OspfLsaRef,
    OspfLsaSummary,
    OspfNeighbor,
    OspfNetworkLsa,
    OspfRoute,
    OspfRouter,
    OspfRouterLsa,
    OspfStubNetwork,
    OspfTopology,
    OspfTransitNetwork,
)

#: Command names used as evidence tags, matching what was actually dispatched.
EV_ROUTER_LSA = "ospf-router-lsa"
EV_NETWORK_LSA = "ospf-network-lsa"
EV_NEIGHBOR = "ospf-neighbor"
EV_ROUTE = "ospf-route"


@dataclass
class OspfDeviceData:
    """Everything one device contributed, before cross-device reconstruction."""

    device_id: str
    process_id: str = ""
    router_id: str = ""
    neighbors: list[OspfNeighbor] = field(default_factory=list)
    interfaces: list[OspfInterface] = field(default_factory=list)
    database_summary: list[OspfLsaSummary] = field(default_factory=list)
    router_lsas: list[OspfRouterLsa] = field(default_factory=list)
    network_lsas: list[OspfNetworkLsa] = field(default_factory=list)
    routes: list[OspfRoute] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def _prefix_or_none(address: str, mask: str) -> str | None:
    try:
        return str(ipaddress.ip_network(f"{address}/{mask}", strict=False))
    except ValueError:
        return None


def _contains(prefix: str | None, address: str) -> bool:
    if not prefix or not address:
        return False
    try:
        return ipaddress.ip_address(address) in ipaddress.ip_network(prefix, strict=False)
    except ValueError:
        return False


def _lsa_ref(lsa: OspfRouterLsa | OspfNetworkLsa, lsa_type: int) -> OspfLsaRef:
    return OspfLsaRef(
        device_id=lsa.device_id or "unknown",
        area=lsa.area,
        lsa_type=lsa_type,
        link_state_id=lsa.link_state_id or "unknown",
        advertising_router=lsa.advertising_router or "unknown",
        sequence=lsa.sequence,
        checksum=lsa.checksum,
        age=lsa.age,
        command=lsa.command,
    )


# --------------------------------------------------------------------------- #
# Type 3: transit network correlation
# --------------------------------------------------------------------------- #


def _transit_key(area: str, dr_address: str) -> tuple[str, str]:
    """The join key between a Type-1 transit link and a Type-2 LSA."""
    return (area, dr_address)


def reconstruct_transit_networks(
    router_lsas: list[OspfRouterLsa],
    network_lsas: list[OspfNetworkLsa],
    warnings: list[str],
) -> list[OspfTransitNetwork]:
    """Correlate Router LSA transit records with Network LSAs.

    For each Network LSA the DR address is the join key. Every router whose own
    Router LSA contains a transit link pointing at that DR is a candidate
    member; the member's interface address comes from that same link's
    ``Link Data``.

    Evidence states:

    * ``confirmed``  — the Type-1 members and the Type-2 attached list agree.
    * ``partial``    — only one side is present in the LSDB.
    * ``inconsistent`` — both present and they disagree.
    * ``unresolved`` — the DR address cannot be tied to a prefix at all.
    """
    # (area, dr) -> {router_id: interface_address}
    transit_members: dict[tuple[str, str], dict[str, str]] = defaultdict(dict)
    for lsa in router_lsas:
        for link in lsa.links:
            if link.link_type is not OspfLinkType.TRANSIT:
                continue
            key = _transit_key(lsa.area, link.link_id)
            transit_members[key][lsa.advertising_router] = link.link_data

    networks: list[OspfTransitNetwork] = []
    consumed_keys: set[tuple[str, str]] = set()

    for lsa in network_lsas:
        key = _transit_key(lsa.area, lsa.link_state_id)
        consumed_keys.add(key)
        prefix = lsa.prefix
        type1_members = dict(transit_members.get(key, {}))
        type2_members = list(lsa.attached_routers)

        notes: list[str] = []
        sources = [_lsa_ref(lsa, 2)]
        evidence = [EV_NETWORK_LSA]

        if type1_members:
            sources.append(
                _lsa_ref(
                    next(
                        r
                        for r in router_lsas
                        if r.area == lsa.area
                        and r.advertising_router in type1_members
                    ),
                    1,
                )
            )
            evidence.append(EV_ROUTER_LSA)

        # Membership union, so a router that only appears on one side is kept
        # visible instead of vanishing — with the disagreement recorded.
        members = sorted(set(type2_members) | set(type1_members))

        if type1_members and type2_members:
            only_1 = sorted(set(type1_members) - set(type2_members))
            only_2 = sorted(set(type2_members) - set(type1_members))
            if only_1 or only_2:
                state = OspfEvidenceState.INCONSISTENT
                if only_1:
                    notes.append(
                        "router(s) claim membership in their Router LSA but are absent "
                        f"from the Network LSA attached list: {', '.join(only_1)}"
                    )
                if only_2:
                    notes.append(
                        "Network LSA lists router(s) whose Router LSA does not reference "
                        f"this DR: {', '.join(only_2)}"
                    )
                warnings.append(
                    f"OSPF transit network {prefix or lsa.link_state_id}: "
                    f"Type 1 and Type 2 disagree ({'; '.join(notes)})"
                )
            else:
                state = OspfEvidenceState.CONFIRMED
        elif type2_members or type1_members:
            state = OspfEvidenceState.PARTIAL
            if not type1_members:
                notes.append(
                    "no Router LSA in the collected LSDB references this DR — "
                    "membership rests on the Network LSA alone"
                )
            if not type2_members:
                notes.append(
                    "no Network LSA for this DR — membership rests on Router LSAs alone"
                )
        else:
            state = OspfEvidenceState.UNRESOLVED
            notes.append("no member information from either LSA type")

        if prefix is None:
            state = OspfEvidenceState.UNRESOLVED
            notes.append("Network Mask missing — the segment prefix cannot be computed")
            warnings.append(
                f"OSPF transit network at DR {lsa.link_state_id}: prefix unresolved "
                "(no usable Network Mask)"
            )

        # Validate each member's interface address against the segment prefix.
        interface_addresses: dict[str, str] = {}
        for router_id, address in type1_members.items():
            if not address:
                continue
            interface_addresses[router_id] = address
            if prefix and not _contains(prefix, address):
                notes.append(
                    f"router {router_id} reports interface address {address} which is "
                    f"not inside {prefix}"
                )
                if state is OspfEvidenceState.CONFIRMED:
                    state = OspfEvidenceState.INCONSISTENT
                    warnings.append(
                        f"OSPF transit network {prefix}: router {router_id} interface "
                        f"{address} is outside the advertised prefix"
                    )

        networks.append(
            OspfTransitNetwork(
                id=f"ospf-transit-{lsa.area}-{lsa.link_state_id}",
                area=lsa.area,
                prefix=prefix,
                dr_address=lsa.link_state_id,
                advertising_router=lsa.advertising_router,
                member_router_ids=members,
                member_interface_addresses=interface_addresses,
                source_lsas=sources,
                evidence=sorted(set(evidence)),
                state=state,
                notes=notes,
            )
        )

    # A transit segment known ONLY from Router LSAs (no Network LSA collected).
    for key, members in sorted(transit_members.items()):
        if key in consumed_keys:
            continue
        area, dr = key
        warnings.append(
            f"OSPF transit network at DR {dr} (area {area}) is referenced by "
            f"{len(members)} Router LSA(s) but no Network LSA was collected — "
            "membership is partial"
        )
        networks.append(
            OspfTransitNetwork(
                id=f"ospf-transit-{area}-{dr}",
                area=area,
                prefix=None,
                dr_address=dr,
                advertising_router="",
                member_router_ids=sorted(members),
                member_interface_addresses=dict(members),
                source_lsas=[],
                evidence=[EV_ROUTER_LSA],
                state=OspfEvidenceState.PARTIAL,
                notes=[
                    "Network LSA (Type 2) not present in the collected LSDB; the "
                    "segment prefix and the DR's own view are unknown"
                ],
            )
        )

    return networks


# --------------------------------------------------------------------------- #
# Type 4/5: point-to-point edges and stub networks
# --------------------------------------------------------------------------- #


def reconstruct_point_to_point_edges(
    router_lsas: list[OspfRouterLsa], warnings: list[str]
) -> list[OspfLogicalEdge]:
    """Build P2P logical edges only where *both* sides provide Type-1 evidence.

    A Type-1 point-to-point link names the peer Router ID in ``Link ID``. The
    edge is emitted only when the peer's own Router LSA independently contains a
    point-to-point link back to the first router on the same subnet. One-sided
    P2P evidence stays a warning, never an edge.
    """
    # (area, adv_router) -> list of p2p (peer_id, local_address, metric)
    p2p: dict[tuple[str, str], list[tuple[str, str, int | None]]] = defaultdict(list)
    for lsa in router_lsas:
        for link in lsa.links:
            if link.link_type is not OspfLinkType.POINT_TO_POINT:
                continue
            p2p[(lsa.area, lsa.advertising_router)].append(
                (link.link_id, link.link_data, link.metric)
            )

    edges: list[OspfLogicalEdge] = []
    seen: set[tuple[str, str, str]] = set()
    for (area, router), peers in sorted(p2p.items()):
        for peer_id, local_address, metric in peers:
            reverse = p2p.get((area, peer_id), [])
            reciprocal = any(reverse_peer == router for reverse_peer, _, _ in reverse)
            key = (area, *sorted((router, peer_id)))
            if key in seen:
                continue
            if not reciprocal:
                warnings.append(
                    f"OSPF point-to-point link {router} -> {peer_id} (area {area}) has "
                    "no reciprocal Router LSA — kept as one-sided, not an edge"
                )
                continue
            seen.add(key)
            peer_addresses = [a for p, a, _ in reverse if p == router]
            prefix = None
            if local_address and peer_addresses:
                for plen in range(31, 23, -1):
                    candidate = _prefix_or_none(local_address, str(
                        ipaddress.IPv4Network(f"0.0.0.0/{plen}").netmask
                    ))
                    if candidate and _contains(candidate, peer_addresses[0]):
                        prefix = candidate
                        break
            source_lsas = [
                _lsa_ref(lsa, 1)
                for lsa in router_lsas
                if lsa.area == area and lsa.advertising_router in {router, peer_id}
            ]
            edges.append(
                OspfLogicalEdge(
                    source_router_id=router,
                    destination_router_id=peer_id,
                    prefix=prefix,
                    area=area,
                    destination_interface="",
                    source_lsas=source_lsas,
                    state=OspfEvidenceState.CONFIRMED,
                    notes=[
                        "reciprocal Type 1 point-to-point evidence on both routers",
                        f"metric {metric}" if metric is not None else "metric not reported",
                    ],
                )
            )
    return edges


def reconstruct_stub_networks(
    router_lsas: list[OspfRouterLsa],
) -> list[OspfStubNetwork]:
    """Every stub link becomes a prefix owned by its advertising router.

    Stub networks never create routers or edges — they are prefix ownership
    statements, nothing more.
    """
    stubs: list[OspfStubNetwork] = []
    seen: set[tuple[str, str, str]] = set()
    for lsa in router_lsas:
        for link in lsa.links:
            if link.link_type is not OspfLinkType.STUB:
                continue
            prefix = link.prefix
            if not prefix:
                continue
            key = (lsa.area, lsa.advertising_router, prefix)
            if key in seen:
                continue
            seen.add(key)
            stubs.append(
                OspfStubNetwork(
                    prefix=prefix,
                    advertising_router=lsa.advertising_router,
                    area=lsa.area,
                    metric=link.metric,
                    source_lsa=_lsa_ref(lsa, 1),
                    device_id=lsa.device_id,
                )
            )
    return stubs


# --------------------------------------------------------------------------- #
# Assembly
# --------------------------------------------------------------------------- #


def build_ospf_topology(
    devices: list[OspfDeviceData],
    *,
    physical: Topology | None = None,
) -> OspfTopology:
    """Assemble the whole OSPF view from every collected device.

    ``physical`` is optional and used only for CDP correlation at the end —
    OSPF reconstruction itself never reads it.
    """
    topology = OspfTopology()
    warnings: list[str] = []

    router_lsas: list[OspfRouterLsa] = []
    network_lsas: list[OspfNetworkLsa] = []

    for device in devices:
        warnings.extend(f"{device.device_id}: {w}" for w in device.warnings)
        topology.neighbors.extend(device.neighbors)
        topology.interfaces.extend(device.interfaces)
        topology.database_summary.extend(device.database_summary)
        topology.router_lsas.extend(device.router_lsas)
        topology.network_lsas.extend(device.network_lsas)
        topology.routes.extend(device.routes)
        router_lsas.extend(device.router_lsas)
        network_lsas.extend(device.network_lsas)

        if device.process_id or device.router_id:
            areas = sorted({i.area for i in device.interfaces if i.area})
            topology.instances.append(
                OspfInstance(
                    device_id=device.device_id,
                    process_id=device.process_id or "unknown",
                    router_id=device.router_id,
                    areas=[],
                )
            )
            # Record which interfaces sit in which area, per device.
            by_area: dict[str, list[str]] = defaultdict(list)
            for iface in device.interfaces:
                if iface.area:
                    by_area[iface.area].append(iface.name)
            if topology.instances:
                from nettwin.domain.ospf_models import OspfArea

                topology.instances[-1].areas = [
                    OspfArea(area=area, interfaces=sorted(by_area[area]))
                    for area in sorted(by_area) or areas
                ]

    # --- routers ---------------------------------------------------------- #
    router_ids: dict[str, set[str]] = defaultdict(set)     # router_id -> devices
    process_ids: dict[str, set[str]] = defaultdict(set)
    areas_by_router: dict[str, set[str]] = defaultdict(set)

    for device in devices:
        own = [lsa.advertising_router for lsa in device.router_lsas if lsa.device_id == device.device_id]
        candidates = {device.router_id, *own} - {""}
        for router_id in candidates:
            router_ids[router_id].add(device.device_id)
            if device.process_id:
                process_ids[router_id].add(device.process_id)

    for lsa in router_lsas:
        areas_by_router[lsa.advertising_router].add(lsa.area)
    for lsa in network_lsas:
        for attached in lsa.attached_routers:
            areas_by_router[attached].add(lsa.area)

    for router_id in sorted(set(router_ids) | set(areas_by_router)):
        owning = sorted(router_ids.get(router_id, set()))
        topology.routers.append(
            OspfRouter(
                router_id=router_id,
                device_id=owning[0] if owning else "",
                process_ids=sorted(process_ids.get(router_id, set())),
                areas=sorted(areas_by_router.get(router_id, set())),
                collected=bool(owning),
            )
        )

    # --- reconstructed relationships -------------------------------------- #
    topology.transit_networks = reconstruct_transit_networks(
        router_lsas, network_lsas, warnings
    )
    topology.logical_edges = reconstruct_point_to_point_edges(router_lsas, warnings)
    topology.stub_networks = reconstruct_stub_networks(router_lsas)

    # --- honesty notes ----------------------------------------------------- #
    if not router_lsas:
        # Two very different situations, both reported precisely:
        #   * nothing OSPF-shaped arrived at all -> the device does not run OSPF
        #   * OSPF answered but the LSDB had no Router LSAs -> evidence gap
        any_ospf_signal = bool(
            topology.neighbors
            or topology.interfaces
            or topology.database_summary
            or topology.network_lsas
            or topology.routes
        )
        if not any_ospf_signal:
            warnings.append(
                "no OSPF evidence collected — this device does not appear to run OSPF, "
                "so no logical topology was reconstructed (nothing invented)"
            )
        else:
            warnings.append(
                "no Router LSA (Type 1) collected — OSPF logical topology cannot be "
                "reconstructed from the evidence available (nothing invented)"
            )
    if not network_lsas and router_lsas:
        warnings.append(
            "no Network LSA (Type 2) collected — transit membership has only "
            "Router LSA evidence"
        )
    if not topology.neighbors and devices and any_ospf_signal:
        warnings.append(
            "no OSPF neighbor rows collected — operational adjacency state unknown"
        )

    topology.warnings = warnings

    if physical is not None:
        topology.correlations = correlate_with_cdp(topology, physical)

    return topology


# --------------------------------------------------------------------------- #
# CDP correlation
# --------------------------------------------------------------------------- #


def correlate_with_cdp(ospf: OspfTopology, physical: Topology) -> list[OspfCorrelation]:
    """Compare OSPF-derived relationships with CDP-derived links — never merge.

    Correlation is per-pair, and it reports rather than resolves:

    * ``cdp_confirmed`` — CDP links the same two devices and the OSPF transit
      prefix contains one of that link's interface addresses.
    * ``cdp_missing``   — OSPF shows the relationship, CDP saw nothing between
      them. Normal when the segment runs through an unmanaged switch.
    * ``cdp_disagrees`` — CDP links the two devices but no OSPF transit prefix
      covers either interface address.
    * ``no_cdp_data``   — no CDP links exist for either device at all.
    """
    iface_by_id = {i.id: i for i in physical.interfaces}
    device_by_id = {d.id: d for d in physical.devices}

    # device_id -> set of CDP-linked device ids
    cdp_pairs: dict[tuple[str, str], list[str]] = {}
    for link in physical.links:
        src = iface_by_id.get(link.source_interface_id)
        dst = iface_by_id.get(link.destination_interface_id)
        if not src or not dst:
            continue
        key = tuple(sorted((src.device_id, dst.device_id)))
        addresses = [str(a).split("/")[0] for a in src.ipv4_addresses]
        addresses += [str(a).split("/")[0] for a in dst.ipv4_addresses]
        cdp_pairs.setdefault(key, []).extend(addresses)  # type: ignore[arg-type]

    devices_with_cdp = {d for pair in cdp_pairs for d in pair}
    router_to_device = {
        r.router_id: r.device_id for r in ospf.routers if r.device_id
    }

    correlations: list[OspfCorrelation] = []
    for network in ospf.transit_networks:
        for member in network.member_router_ids:
            member_device = router_to_device.get(member)
            if not member_device:
                continue
            for other in network.member_router_ids:
                if other == member:
                    continue
                other_device = router_to_device.get(other)
                if not other_device:
                    continue
                key = tuple(sorted((member_device, other_device)))
                addresses = cdp_pairs.get(key)  # type: ignore[arg-type]
                relation_id = f"{network.id}:{member}-{other}"

                if addresses is None:
                    state = (
                        OspfCdpRelation.NO_CDP_DATA
                        if member_device not in devices_with_cdp
                        and other_device not in devices_with_cdp
                        else OspfCdpRelation.CDP_MISSING
                    )
                    detail = (
                        "no CDP link exists between "
                        f"{device_by_id.get(member_device, member_device)} and "
                        f"{device_by_id.get(other_device, other_device)}"
                    )
                elif any(_contains(network.prefix, a) for a in addresses):
                    state = OspfCdpRelation.CDP_CONFIRMED
                    detail = (
                        f"CDP links these devices and the OSPF prefix "
                        f"{network.prefix} covers the link addressing"
                    )
                else:
                    state = OspfCdpRelation.CDP_DISAGREES
                    detail = (
                        f"CDP links these devices but no address on that link "
                        f"({', '.join(addresses) or 'none collected'}) falls inside "
                        f"the OSPF prefix {network.prefix}"
                    )
                correlations.append(
                    OspfCorrelation(
                        relation_id=relation_id, cdp_state=state, detail=detail
                    )
                )
    return correlations
