"""NetTwin AI domain models.

These Pydantic models are the source of truth for network state. They depend
only on Pydantic — never on MCP, LLM, or I/O libraries.

Conventions
-----------
- ``id`` values are unique within their collection.
- Overlapping IP addresses across different VRFs are allowed and expected:
  an IP address alone never identifies an endpoint.
- Cross-VRF relationships must be explicit (routes with a documented service
  handoff, or services with ``allowed_vrfs``).
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    IPvAnyAddress,
    IPvAnyInterface,
    IPvAnyNetwork,
    field_validator,
    model_validator,
)


class AdminState(StrEnum):
    """Interface administrative state."""

    UP = "up"
    DOWN = "down"


class OperState(StrEnum):
    """Interface operational state."""

    UP = "up"
    DOWN = "down"


class LinkState(StrEnum):
    """Topology link state."""

    UP = "up"
    DOWN = "down"


class FindingSeverity(StrEnum):
    """Deterministic severity levels for diagnostic findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class DiagnosticStatus(StrEnum):
    """Explicit diagnostic statuses.

    ``unknown`` and ``incomplete`` must never be reported as a confirmed
    ``reachable`` or ``unreachable`` result.
    """

    REACHABLE = "reachable"
    UNREACHABLE = "unreachable"
    UNKNOWN = "unknown"
    INCOMPLETE = "incomplete"


class FindingCode(StrEnum):
    """Required diagnostic finding codes (extensible when justified).

    ``ROUTE_LOOP`` and ``NEXT_HOP_UNRESOLVED`` were added because the walk
    must terminate on forwarding loops and must distinguish an unresolvable
    next hop from a missing route (both are confirmed failures in the model).
    """

    MISSING_ROUTE = "MISSING_ROUTE"
    INTERFACE_DOWN = "INTERFACE_DOWN"
    LINK_DOWN = "LINK_DOWN"
    VRF_MISMATCH = "VRF_MISMATCH"
    TENANT_ISOLATION = "TENANT_ISOLATION"
    INSUFFICIENT_DATA = "INSUFFICIENT_DATA"
    ROUTE_LOOP = "ROUTE_LOOP"
    NEXT_HOP_UNRESOLVED = "NEXT_HOP_UNRESOLVED"


class Device(BaseModel):
    """A network device."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    vendor: str = Field(min_length=1)
    platform: str = Field(min_length=1)
    management_address: IPvAnyAddress | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class Interface(BaseModel):
    """A device interface, optionally bound to a VRF."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    id: str = Field(min_length=1)
    device_id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    vrf_id: str | None = None
    ipv4_addresses: list[IPvAnyInterface] = Field(default_factory=list)
    admin_state: AdminState
    oper_state: OperState

    @property
    def is_up(self) -> bool:
        """True when the interface is administratively and operationally up."""
        return self.admin_state is AdminState.UP and self.oper_state is OperState.UP


class VRF(BaseModel):
    """A VRF / routing table, optionally scoped to a tenant."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    tenant_id: str | None = None
    description: str = ""


class Link(BaseModel):
    """A physical/logical link between two interfaces."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    id: str = Field(min_length=1)
    source_interface_id: str = Field(min_length=1)
    destination_interface_id: str = Field(min_length=1)
    state: LinkState


class Route(BaseModel):
    """A route in a device's VRF-specific routing table.

    ``next_hop`` is optional because connected routes have no next hop; a route
    must define at least one of ``next_hop`` / ``outgoing_interface_id`` so it
    can be resolved by the diagnostic engine.
    """

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    id: str = Field(min_length=1)
    device_id: str = Field(min_length=1)
    vrf_id: str = Field(min_length=1)
    destination_prefix: IPvAnyNetwork
    next_hop: IPvAnyAddress | None = None
    outgoing_interface_id: str | None = None
    protocol: str = Field(min_length=1)
    active: bool

    @model_validator(mode="after")
    def _require_forwarding_reference(self) -> Route:
        if self.next_hop is None and self.outgoing_interface_id is None:
            raise ValueError(
                f"route {self.id!r} must define next_hop and/or outgoing_interface_id"
            )
        return self


class Endpoint(BaseModel):
    """A logical endpoint identified by id + VRF context (never by IP alone)."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    ip_address: IPvAnyAddress
    vrf_id: str = Field(min_length=1)
    device_id: str | None = None


class Service(BaseModel):
    """A service exposed by an endpoint, with explicitly allowed VRFs."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    endpoint_id: str = Field(min_length=1)
    protocol: str = Field(min_length=1)
    port: int = Field(ge=1, le=65535)
    allowed_vrfs: list[str] = Field(default_factory=list)

    @field_validator("protocol", mode="before")
    @classmethod
    def _normalize_protocol(cls, value: object) -> object:
        # Field validator (not an after-validator): assigning inside an
        # after-validator would re-trigger validation under
        # validate_assignment and recurse forever.
        if isinstance(value, str):
            return value.lower()
        return value


class EvidenceItem(BaseModel):
    """One structured, traceable evidence entry.

    Flat JSON object with a ``type`` discriminator plus arbitrary typed fields
    (e.g. ``device_id``, ``vrf_id``, ``matched_route``, ``result``).
    """

    model_config = ConfigDict(extra="allow", validate_assignment=True)

    type: str = Field(min_length=1)


class DiagnosticFinding(BaseModel):
    """A deterministic diagnostic finding with evidence and recommendations."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    id: str = Field(min_length=1)
    code: FindingCode
    severity: FindingSeverity
    title: str = Field(min_length=1)
    description: str = Field(min_length=1)
    source_id: str | None = None
    destination_id: str | None = None
    vrf_id: str | None = None
    evidence: list[EvidenceItem] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    status: DiagnosticStatus


class DiagnosticResult(BaseModel):
    """Result of one connectivity analysis (data model §8)."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    analysis_id: str = Field(min_length=1)
    source_id: str = Field(min_length=1)
    destination_id: str = Field(min_length=1)
    status: DiagnosticStatus
    vrf_id: str | None = None
    findings: list[DiagnosticFinding] = Field(default_factory=list)
    evidence: list[EvidenceItem] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class Topology(BaseModel):
    """A complete, validated network topology loaded from a fixture."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    devices: list[Device] = Field(default_factory=list)
    interfaces: list[Interface] = Field(default_factory=list)
    links: list[Link] = Field(default_factory=list)
    vrfs: list[VRF] = Field(default_factory=list)
    routes: list[Route] = Field(default_factory=list)
    endpoints: list[Endpoint] = Field(default_factory=list)
    services: list[Service] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_references(self) -> Topology:
        """Reject duplicate ids and invalid cross-references with full context."""
        errors: list[str] = []

        collections: dict[str, list[Any]] = {
            "devices": self.devices,
            "interfaces": self.interfaces,
            "links": self.links,
            "vrfs": self.vrfs,
            "routes": self.routes,
            "endpoints": self.endpoints,
            "services": self.services,
        }
        for kind, items in collections.items():
            seen: set[str] = set()
            duplicates: set[str] = set()
            for item in items:
                if item.id in seen:
                    duplicates.add(item.id)
                seen.add(item.id)
            if duplicates:
                errors.append(
                    f"duplicate {kind} id(s): {', '.join(sorted(duplicates))}"
                )

        device_ids = {d.id for d in self.devices}
        vrf_ids = {v.id for v in self.vrfs}
        interface_ids = {i.id for i in self.interfaces}
        endpoint_ids = {e.id for e in self.endpoints}

        for iface in self.interfaces:
            if iface.device_id not in device_ids:
                errors.append(
                    f"interface {iface.id!r} references unknown device {iface.device_id!r}"
                )
            if iface.vrf_id is not None and iface.vrf_id not in vrf_ids:
                errors.append(
                    f"interface {iface.id!r} references unknown VRF {iface.vrf_id!r}"
                )

        for link in self.links:
            if link.source_interface_id not in interface_ids:
                errors.append(
                    f"link {link.id!r} references unknown interface "
                    f"{link.source_interface_id!r}"
                )
            if link.destination_interface_id not in interface_ids:
                errors.append(
                    f"link {link.id!r} references unknown interface "
                    f"{link.destination_interface_id!r}"
                )
            if link.source_interface_id == link.destination_interface_id:
                errors.append(
                    f"link {link.id!r} connects interface "
                    f"{link.source_interface_id!r} to itself"
                )

        interface_by_id = {i.id: i for i in self.interfaces}
        for route in self.routes:
            if route.device_id not in device_ids:
                errors.append(
                    f"route {route.id!r} references unknown device {route.device_id!r}"
                )
            if route.vrf_id not in vrf_ids:
                errors.append(f"route {route.id!r} references unknown VRF {route.vrf_id!r}")
            if (
                route.outgoing_interface_id is not None
                and route.outgoing_interface_id not in interface_ids
            ):
                errors.append(
                    f"route {route.id!r} references unknown interface "
                    f"{route.outgoing_interface_id!r}"
                )
            elif route.outgoing_interface_id is not None:
                owner = interface_by_id[route.outgoing_interface_id].device_id
                if owner != route.device_id:
                    errors.append(
                        f"route {route.id!r} outgoing interface "
                        f"{route.outgoing_interface_id!r} belongs to device "
                        f"{owner!r}, not {route.device_id!r}"
                    )

        for endpoint in self.endpoints:
            if endpoint.vrf_id not in vrf_ids:
                errors.append(
                    f"endpoint {endpoint.id!r} references unknown VRF {endpoint.vrf_id!r}"
                )
            if endpoint.device_id is not None and endpoint.device_id not in device_ids:
                errors.append(
                    f"endpoint {endpoint.id!r} references unknown device "
                    f"{endpoint.device_id!r}"
                )

        for service in self.services:
            if service.endpoint_id not in endpoint_ids:
                errors.append(
                    f"service {service.id!r} references unknown endpoint "
                    f"{service.endpoint_id!r}"
                )
            for vrf_id in service.allowed_vrfs:
                if vrf_id not in vrf_ids:
                    errors.append(
                        f"service {service.id!r} references unknown VRF {vrf_id!r}"
                    )

        if errors:
            raise ValueError("; ".join(errors))
        return self
