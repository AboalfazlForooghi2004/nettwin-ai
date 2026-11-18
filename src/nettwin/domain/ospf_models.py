"""Normalized OSPF domain models (Phase 2.6).

Deliberately a **separate namespace** from :mod:`nettwin.domain.models`. OSPF
produces a logical, SPF-derived view of the network; the physical view in
``domain.models`` is built from layer-2 neighbour evidence. Keeping them in
separate types is what stops an OSPF adjacency from silently becoming a cable.

Design rules applied here:

* No hardcoded process id, area id or router count — everything is carried per
  object, so a 2-process, 3-area device works exactly like the single-process
  lab.
* Every reconstructed relationship keeps ``source_lsas``: the LSAs it was
  derived from, with area / advertising router / LSID / sequence / checksum.
  Nothing is asserted without a traceable origin.
* ``OspfEvidenceState`` is mandatory on every derived relationship, so
  "confirmed" is a claim the model makes explicitly rather than a default.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field, StrictInt

#: LS Age (RFC 2328 §12.1.1) as it must be represented in the domain.
#:
#: ``StrictInt`` because the lax ``int | None`` accepted ``True`` as age 1 and
#: ``"12"`` as age 12 — Pydantic coerced them before any validator could object,
#: and ``True`` then compared as a genuinely young, winning age. Age is a
#: 16-bit unsigned seconds counter saturating at ``MaxAge``, so the range is
#: enforced here as well as in the pipeline: a value outside it never describes
#: a conforming LSDB.
#:
#: ``None`` stays explicitly allowed — a missing LSA header is a legitimate
#: absence of evidence, and downstream code treats it as unresolved rather than
#: as agreement.
OspfAge = Annotated[StrictInt, Field(ge=0, le=3600)]


class OspfEvidenceState(StrEnum):
    """How well the reconstructed relationship is evidenced."""

    CONFIRMED = "confirmed"
    """Type 1 and Type 2 evidence agree (or reciprocal P2P evidence)."""

    PARTIAL = "partial"
    """Only one relevant evidence source is available."""

    INCONSISTENT = "inconsistent"
    """Type 1 and Type 2 evidence conflict. Never silently resolved."""

    UNRESOLVED = "unresolved"
    """Router ID / interface / prefix association cannot be determined."""


class OspfLinkType(StrEnum):
    """Router LSA (Type 1) link types."""

    POINT_TO_POINT = "point-to-point"
    TRANSIT = "transit"
    STUB = "stub"
    VIRTUAL = "virtual"
    UNKNOWN = "unknown"


class OspfRouteType(StrEnum):
    """``show ip ospf route`` type column, normalized."""

    CONNECTED = "connected"
    INTRA_AREA = "intra-area"
    INTER_AREA = "inter-area"
    EXTERNAL_1 = "external-1"
    EXTERNAL_2 = "external-2"
    NSSA_1 = "nssa-1"
    NSSA_2 = "nssa-2"
    UNKNOWN = "unknown"


class OspfCdpRelation(StrEnum):
    """How one OSPF logical relationship lines up with CDP evidence."""

    CDP_CONFIRMED = "cdp_confirmed"
    CDP_MISSING = "cdp_missing"
    CDP_DISAGREES = "cdp_disagrees"
    NO_CDP_DATA = "no_cdp_data"


# --------------------------------------------------------------------------- #
# LSA references — the provenance anchor for everything below
# --------------------------------------------------------------------------- #


class OspfLsaRef(BaseModel):
    """A pointer to one LSA in one device's LSDB."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    device_id: str = Field(min_length=1)
    area: str = Field(min_length=1)
    lsa_type: int = Field(ge=1, le=11)
    link_state_id: str = Field(min_length=1)
    advertising_router: str = Field(min_length=1)
    sequence: str = ""
    checksum: str = ""
    age: int | None = None
    command: str = ""
    """The CLI command this came from, so the evidence is traceable."""


# --------------------------------------------------------------------------- #
# Raw LSDB records
# --------------------------------------------------------------------------- #


class OspfLsaSummary(BaseModel):
    """One row of ``show ip ospf database``."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    area: str
    lsa_type: int
    link_state_id: str
    advertising_router: str
    age: int | None = None
    sequence: str = ""
    checksum: str = ""
    link_count: int | None = None
    device_id: str = ""
    """The device whose LSDB this row was read from — an *observer*, not the
    originator. Defaulted so existing consumers keep working."""


class OspfLsaLink(BaseModel):
    """One link record inside a Router LSA."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    link_type: OspfLinkType
    link_id: str = ""
    link_data: str = ""
    network_mask: str = ""
    metric: int | None = None
    mtid: str = ""

    @property
    def prefix(self) -> str | None:
        """``link_id/mask`` for a stub link, when both parts exist."""
        if self.link_type is not OspfLinkType.STUB or not self.link_id or not self.network_mask:
            return None
        try:
            import ipaddress

            return str(ipaddress.ip_network(f"{self.link_id}/{self.network_mask}", strict=False))
        except ValueError:
            return None


class OspfRouterLsa(BaseModel):
    """A Router LSA (Type 1) with its parsed links."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    area: str
    link_state_id: str
    advertising_router: str
    sequence: str = ""
    checksum: str = ""
    age: OspfAge | None = None
    number_of_links: int | None = None
    options: str = ""
    """``Options: (No TOS-capability, DC)`` verbatim.

    RFC 2328 §13.2: a change in the Options field makes two LSAs different
    instances, so it is part of the content fingerprint. IOS prints it as
    free text rather than a bitmask, so it is stored as reported.
    """

    ls_length: int | None = None
    """``Length: 60`` — the LSA's total length in bytes (RFC 2328 §13.2)."""

    links: list[OspfLsaLink] = Field(default_factory=list)
    device_id: str = ""
    command: str = ""
    observed_by: list[str] = Field(default_factory=list)
    """Every device whose LSDB contained this LSA.

    An OSPF LSDB is flooded, so in a five-router area all five routers hold all
    five Router LSAs. ``device_id`` is the observer that supplied *this* copy;
    ``observed_by`` is the full set, which is what stops five observers from
    looking like five distinct LSAs without throwing the provenance away.
    """

    observed_instances: list[dict[str, str]] = Field(default_factory=list)
    """What each observer reported for this LSA, when they differed.

    ``[{"observer": "r3", "sequence": "80000002", "checksum": "0x5E6F",
    "age": "1418"}]``. Empty when every observer agreed. Kept so a resolved
    conflict is auditable after the winner has been chosen.
    """

    def link_count_mismatch(self) -> str | None:
        """Describe the disagreement between the declared and actual link count.

        ``Number of Links`` counts the link records in the LSA body (RFC 2328
        §A.4.2). If it disagrees with the parsed links, the body was truncated,
        mistranscribed or misparsed — evidence that contradicts itself.

        This is deliberately a *query* rather than a validator. The parser
        builds an LSA incrementally: it assigns ``number_of_links`` when it
        reads that line, then attaches links as it walks the body. A model
        validator would fire on the intermediate state and reject every real
        LSA. The check belongs where the object is *complete* — see
        :func:`nettwin.collect.ospf_parsers.parse_show_ip_ospf_database_router`
        and :func:`nettwin.collect.ospf_topology.canonical_router_lsas`.

        Returns ``None`` when consistent, or when no count was reported (an
        absence of evidence, not a contradiction).
        """
        if self.number_of_links is None or self.number_of_links == len(self.links):
            return None
        return (
            f"LSA {self.link_state_id or '?'} declares {self.number_of_links} "
            f"link(s) but {len(self.links)} were parsed"
        )


class OspfNetworkLsa(BaseModel):
    """A Network LSA (Type 2) — a transit network's DR view."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    area: str
    link_state_id: str
    """The Designated Router's interface address on this segment."""
    advertising_router: str
    network_mask: str = ""
    attached_routers: list[str] = Field(default_factory=list)
    sequence: str = ""
    checksum: str = ""
    age: OspfAge | None = None
    options: str = ""
    """``Options:`` verbatim — part of the LSA content (RFC 2328 §13.2)."""

    ls_length: int | None = None
    """``Length:`` in bytes — part of the LSA content (RFC 2328 §13.2)."""

    device_id: str = ""
    command: str = ""
    observed_by: list[str] = Field(default_factory=list)
    """Every device whose LSDB contained this LSA (see ``OspfRouterLsa``)."""

    observed_membership: list[dict[str, Any]] = Field(default_factory=list)
    """What each observer reported as the attached-router list.

    ``[{"observer": "r3", "attached_routers": [...], "sequence": "80000002",
    "checksum": "0x5E6F"}]``. The canonical ``attached_routers`` comes from the
    winning instance alone; this preserves the other reports as evidence
    without merging stale members back into the canonical LSA.
    """

    @property
    def prefix(self) -> str | None:
        """Network prefix from the DR address and the LSA's mask, if both exist."""
        if not self.link_state_id or not self.network_mask:
            return None
        try:
            import ipaddress

            network = ipaddress.ip_network(
                f"{self.link_state_id}/{self.network_mask}", strict=False
            )
            return str(network)
        except ValueError:
            return None


# --------------------------------------------------------------------------- #
# Device-level operational state
# --------------------------------------------------------------------------- #


class OspfNeighbor(BaseModel):
    """One row of ``show ip ospf neighbor``."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    device_id: str
    local_interface: str
    neighbor_router_id: str
    neighbor_address: str
    state: str
    """Raw state as printed, e.g. ``FULL/BDR``."""
    priority: str = ""
    dead_time: str = ""
    area: str = ""
    process_id: str = ""
    evidence: str = "ospf-neighbor"

    @property
    def adjacency_state(self) -> str:
        """The adjacency half of ``FULL/BDR``."""
        return self.state.split("/")[0].strip().upper()

    @property
    def role(self) -> str:
        """The DR/BDR role half, or empty when IOS printed none."""
        parts = self.state.split("/")
        return parts[1].strip() if len(parts) > 1 else ""


class OspfInterface(BaseModel):
    """One row of ``show ip ospf interface brief``."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    device_id: str
    name: str
    process_id: str = ""
    area: str = ""
    ip_address: str = ""
    mask: str = ""
    cost: int | None = None
    state: str = ""
    neighbors_full: int | None = None
    neighbors_total: int | None = None

    @property
    def prefix(self) -> str | None:
        if not self.ip_address or not self.mask:
            return None
        try:
            import ipaddress

            return str(
                ipaddress.ip_network(f"{self.ip_address}/{self.mask}", strict=False)
            )
        except ValueError:
            return None


class OspfArea(BaseModel):
    """One area on one device."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    area: str
    interfaces: list[str] = Field(default_factory=list)


class OspfInstance(BaseModel):
    """One OSPF process on one device."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    device_id: str
    process_id: str
    router_id: str = ""
    vrf: str = "default"
    protocol_version: int = 2
    areas: list[OspfArea] = Field(default_factory=list)


class OspfRoute(BaseModel):
    """One row of ``show ip ospf route``.

    ``connected`` rows are the device's *own* interface networks. They are OSPF
    state, but they are not OSPF-*learned*: the flag exists so they can never be
    counted as learned routes.
    """

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    device_id: str
    prefix: str
    route_type: OspfRouteType
    cost: int | None = None
    next_hop: str | None = None
    outgoing_interface: str = ""
    area: str = ""
    learned: bool = True
    raw_type: str = ""


# --------------------------------------------------------------------------- #
# Reconstructed logical topology
# --------------------------------------------------------------------------- #


class OspfTransitNetwork(BaseModel):
    """A transit network (a Type-2-evidenced multi-access segment).

    This is a **first-class node**, not an edge. Three routers on one LAN
    produce one of these with three members — never three point-to-point links.
    """

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    id: str
    area: str
    prefix: str | None = None
    dr_address: str
    advertising_router: str
    member_router_ids: list[str] = Field(default_factory=list)
    #: router_id -> its interface address on this segment, where resolvable.
    member_interface_addresses: dict[str, str] = Field(default_factory=dict)
    source_lsas: list[OspfLsaRef] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    state: OspfEvidenceState = OspfEvidenceState.PARTIAL
    notes: list[str] = Field(default_factory=list)


class OspfStubNetwork(BaseModel):
    """A stub network: a prefix advertised by a router. Never a node or an edge."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    prefix: str
    advertising_router: str
    area: str
    metric: int | None = None
    source_lsa: OspfLsaRef | None = None
    device_id: str = ""


class OspfLogicalEdge(BaseModel):
    """A router-to-router logical adjacency, only where genuinely evidenced.

    Used for point-to-point segments with reciprocal Type-1 evidence. It is a
    *logical* edge: it is not a :class:`nettwin.domain.models.Link` and is never
    added to ``Topology.links``.
    """

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    source_router_id: str
    destination_router_id: str
    prefix: str | None = None
    area: str
    source_interface: str = ""
    destination_interface: str = ""
    source_lsas: list[OspfLsaRef] = Field(default_factory=list)
    state: OspfEvidenceState = OspfEvidenceState.PARTIAL
    notes: list[str] = Field(default_factory=list)


class OspfRouter(BaseModel):
    """One OSPF router, keyed by Router ID (which is stable and device-independent)."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    router_id: str
    device_id: str = ""
    """Set only when a collected device is proven to own this Router ID."""
    process_ids: list[str] = Field(default_factory=list)
    areas: list[str] = Field(default_factory=list)
    collected: bool = False
    """False when the router appears only in the LSDB of others."""


class OspfCorrelation(BaseModel):
    """The CDP-vs-OSPF comparison for one logical relationship."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    relation_id: str
    cdp_state: OspfCdpRelation
    detail: str = ""


class OspfTopology(BaseModel):
    """Everything OSPF taught us, kept apart from the physical topology."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    instances: list[OspfInstance] = Field(default_factory=list)
    routers: list[OspfRouter] = Field(default_factory=list)
    neighbors: list[OspfNeighbor] = Field(default_factory=list)
    interfaces: list[OspfInterface] = Field(default_factory=list)
    database_summary: list[OspfLsaSummary] = Field(default_factory=list)
    router_lsas: list[OspfRouterLsa] = Field(default_factory=list)
    network_lsas: list[OspfNetworkLsa] = Field(default_factory=list)
    transit_networks: list[OspfTransitNetwork] = Field(default_factory=list)
    stub_networks: list[OspfStubNetwork] = Field(default_factory=list)
    logical_edges: list[OspfLogicalEdge] = Field(default_factory=list)
    routes: list[OspfRoute] = Field(default_factory=list)
    correlations: list[OspfCorrelation] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)

    # -- convenience ------------------------------------------------------- #

    def router_ids(self) -> list[str]:
        return sorted({r.router_id for r in self.routers})

    def state_counts(self) -> dict[str, int]:
        """How many reconstructed relationships sit in each evidence state."""
        counts: dict[str, int] = {}
        for item in [*self.transit_networks, *self.logical_edges]:
            counts[str(item.state)] = counts.get(str(item.state), 0) + 1
        return counts

    def lsa_counts(self) -> dict[str, int]:
        """Canonical LSA counts, plus how many observers saw each one.

        ``observed`` is deliberately *not* the length of a list: an LSA seen by
        five routers is one LSA and five observations, and conflating those two
        numbers is what made a five-router run report 25 transit networks.
        """
        router_observations = sum(
            len(lsa.observed_by) or 1 for lsa in self.router_lsas
        )
        network_observations = sum(
            len(lsa.observed_by) or 1 for lsa in self.network_lsas
        )
        return {
            "router_lsas": len(self.router_lsas),
            "network_lsas": len(self.network_lsas),
            "router_lsa_observations": router_observations,
            "network_lsa_observations": network_observations,
            "observers": len(
                {
                    observer
                    for lsa in [*self.router_lsas, *self.network_lsas]
                    for observer in lsa.observed_by
                }
            ),
            "transit_networks": len(self.transit_networks),
            "stub_networks": len(self.stub_networks),
            "logical_edges": len(self.logical_edges),
        }

    def learned_routes(self, device_id: str | None = None) -> list[OspfRoute]:
        """Only the OSPF-*learned* routes — ``Connected`` rows excluded."""
        return [
            r
            for r in self.routes
            if r.learned and (device_id is None or r.device_id == device_id)
        ]

    def connected_routes(self, device_id: str | None = None) -> list[OspfRoute]:
        """The device's own interface networks as OSPF reports them."""
        return [
            r
            for r in self.routes
            if not r.learned and (device_id is None or r.device_id == device_id)
        ]
