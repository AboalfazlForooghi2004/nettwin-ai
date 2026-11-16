"""FortiGate / FortiOS → normalized domain models (Phase 2.5).

Mirrors ``cisco_ios.map_to_topology``: one device's parsed observations in,
the *same* ``Device``/``Interface``/``VRF``/``Route`` objects out, so ``merge``,
``links`` and everything downstream work unchanged for both vendors.

Deliberate limitations, all reported rather than papered over:

* FortiOS ``get system interface`` reports one admin state string, not a
  separate link state. ``admin_state`` therefore carries it and ``oper_state``
  is derived *only* when the same string evidences link status; otherwise it
  stays ``down`` and a warning says the operational state was not evidenced.
  A link is never reported ``up`` on unsupported evidence.
* An interface whose ``ip:`` is ``0.0.0.0 0.0.0.0`` gets no address at all.
* Routes name an interface, never an id. A route whose interface name does not
  resolve is kept without ``outgoing_interface_id`` (never invented, never
  silently dropped).
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any

from nettwin.collect.fortios_parsers import (
    FortiosInterface,
    FortiosLldpNeighbor,
    FortiosRoute,
    FortiosStatus,
    parse_lldp_neighbors,
    parse_routing_table,
    parse_system_interface,
    parse_system_status,
)
from nettwin.domain.models import (
    VRF,
    AdminState,
    Device,
    Interface,
    OperState,
    Route,
    Topology,
)

#: Command names used as keys in the collected text mapping.
CMD_STATUS = "get system status"
CMD_INTERFACE = "get system interface"
CMD_ROUTES = "get router info routing-table all"
CMD_LLDP = "get system lldp neighbors"

FORTIOS_VENDOR = "fortinet"
FORTIOS_PLATFORM_FALLBACK = "FortiGate"


@dataclass
class FortiosObservations:
    """Everything a FortiGate run learned, kept JSON-serializable."""

    host: str
    device_id: str | None = None
    status: FortiosStatus = field(default_factory=FortiosStatus)
    interfaces: list[FortiosInterface] = field(default_factory=list)
    routes: list[FortiosRoute] = field(default_factory=list)
    #: Non-empty only when the operator enabled LLDP reception on the device.
    lldp_neighbors: list[FortiosLldpNeighbor] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "device_id": self.device_id,
            "status": {
                "hostname": self.status.hostname,
                "platform": self.status.platform,
                "model": self.status.model,
                "version": self.status.version,
                "build": self.status.build,
                "serial": self.status.serial,
                "vdom": self.status.vdom,
            },
            "interfaces": [
                {
                    "name": i.name,
                    "ip_addresses": i.ip_addresses,
                    "admin_state": i.admin_state,
                    "raw_status": i.raw_status,
                    "type": i.iface_type,
                }
                for i in self.interfaces
            ],
            "routes": [
                {
                    "prefix": r.prefix,
                    "protocol": r.protocol,
                    "next_hop": r.next_hop,
                    "interface": r.interface,
                    "vrf": r.vrf,
                    "distance": r.distance,
                    "metric": r.metric,
                }
                for r in self.routes
            ],
            "lldp_neighbors": [
                {
                    "local_interface": n.local_interface,
                    "remote_device": n.remote_device,
                    "remote_interface": n.remote_interface,
                    "remote_platform": n.remote_platform,
                    "remote_ip": n.remote_ip,
                }
                for n in self.lldp_neighbors
            ],
            "warnings": list(self.warnings),
        }


def parse_observations(host: str, outputs: dict[str, str]) -> FortiosObservations:
    """Turn raw command output into observations. Never raises on bad input."""
    observations = FortiosObservations(host=host)

    status_text = outputs.get(CMD_STATUS, "")
    status, status_warnings = parse_system_status(status_text)
    observations.status = status
    observations.warnings.extend(status_warnings)

    iface_text = outputs.get(CMD_INTERFACE, "")
    interfaces, iface_warnings = parse_system_interface(iface_text)
    observations.interfaces = interfaces
    observations.warnings.extend(iface_warnings)

    route_text = outputs.get(CMD_ROUTES, "")
    routes, route_warnings = parse_routing_table(route_text)
    observations.routes = routes
    observations.warnings.extend(route_warnings)

    # Neighbour evidence is optional and usually absent: FortiGate does not
    # receive LLDP unless the operator turned it on. Absence is recorded as a
    # fact about the device, never converted into an inferred link.
    if CMD_LLDP in outputs:
        lldp, lldp_warnings = parse_lldp_neighbors(outputs[CMD_LLDP])
        observations.lldp_neighbors = lldp
        observations.warnings.extend(lldp_warnings)

    return observations


def _interface_id(device_id: str, name: str) -> str:
    return f"{device_id}-{name.lower()}"


def _mask_to_prefix(mask: str) -> int | None:
    try:
        return ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
    except ValueError:
        return None


def _state_pair(raw_status: str) -> tuple[AdminState, OperState]:
    """FortiOS reports one string; split it honestly.

    ``up`` clearly means both layers are up. ``down``/``disable`` means the
    interface is not passing traffic, so both layers are ``down``. Anything
    else leaves the operational state ``down`` — the conservative choice —
    and the caller warns that the state was not evidenced.
    """
    lowered = raw_status.strip().lower()
    if lowered in {"up", "enable", "enabled"}:
        return AdminState.UP, OperState.UP
    if lowered in {"down", "disable", "disabled"}:
        return AdminState.DOWN, OperState.DOWN
    return AdminState.DOWN, OperState.DOWN


def map_to_topology(
    observations: FortiosObservations, device_id: str
) -> tuple[Topology, list[str]]:
    """Build a single-device ``Topology`` from FortiGate observations."""
    warnings: list[str] = list(observations.warnings)
    status = observations.status

    hostname = status.hostname or observations.host
    if not status.hostname:
        warnings.append(
            f"hostname not evidenced — falling back to the collected host {observations.host!r}"
        )

    model = status.model or status.platform or FORTIOS_PLATFORM_FALLBACK
    if not status.model and not status.platform:
        warnings.append(
            "model not evidenced — platform recorded as "
            f"{FORTIOS_PLATFORM_FALLBACK!r} rather than guessed"
        )

    management_address: str | None = None
    try:
        management_address = str(ipaddress.ip_address(observations.host))
    except ValueError:
        management_address = None   # hostname, not an address — kept out of the typed field

    metadata: dict[str, Any] = {
        "fortios_version": status.version or None,
        "fortios_build": status.build or None,
        "serial": status.serial or None,
        "model": model if status.model else None,
        "vdom": status.vdom or None,
        "collected_at": None,
        "collector": "nettwin.collect.fortios",
        "source_host": observations.host,
    }
    device = Device(
        id=device_id,
        name=hostname,
        vendor=FORTIOS_VENDOR,   # evidenced by the "Version: FortiGate-..." line
        platform=model,
        management_address=management_address,
        metadata={k: v for k, v in metadata.items() if v is not None},
    )

    # Interfaces -----------------------------------------------------------
    interfaces: list[Interface] = []
    name_to_id: dict[str, str] = {}
    name_to_id_lower: dict[str, str] = {}
    for item in observations.interfaces:
        if not item.name:
            continue
        iface_id = _interface_id(device_id, item.name)
        if item.admin_state == "unknown":
            warnings.append(
                f"interface {item.name}: status {item.raw_status!r} not recognized — "
                "recorded down (state not evidenced, never assumed up)"
            )
        admin_state, oper_state = _state_pair(item.raw_status)
        interfaces.append(
            Interface(
                id=iface_id,
                device_id=device_id,
                name=item.name,
                vrf_id="GLOBAL",
                ipv4_addresses=list(item.ip_addresses),
                admin_state=admin_state,
                oper_state=oper_state,
            )
        )
        name_to_id[item.name] = iface_id
        name_to_id_lower[item.name.lower()] = iface_id

    if not interfaces:
        warnings.append("no interfaces collected — interface set unavailable")

    def resolve_interface(name: str | None) -> str | None:
        if not name:
            return None
        return name_to_id.get(name) or name_to_id_lower.get(name.lower())

    # VRFs -----------------------------------------------------------------
    vrf_ids = sorted({route.vrf for route in observations.routes}) or ["0"]
    vrfs = [VRF(id="GLOBAL", name="default")]
    vrf_map: dict[str, str] = {}
    if vrf_ids != ["0"] or len(vrf_ids) > 1:
        for raw_vrf in vrf_ids:
            vrf_id = f"VRF{raw_vrf}" if raw_vrf != "0" else "GLOBAL"
            if vrf_id == "GLOBAL":
                vrf_map[raw_vrf] = "GLOBAL"
                continue
            vrf_map[raw_vrf] = vrf_id
            vrfs.append(VRF(id=vrf_id, name=f"VRF {raw_vrf}"))
    else:
        vrf_map["0"] = "GLOBAL"

    # Routes ---------------------------------------------------------------
    routes: list[Route] = []
    seen_route_ids: set[str] = set()
    for index, raw in enumerate(observations.routes):
        outgoing_id = resolve_interface(raw.interface)
        if raw.interface and outgoing_id is None:
            warnings.append(
                f"route {raw.prefix}: interface {raw.interface!r} not present in "
                "collected interfaces — route kept without an outgoing interface "
                "(not invented)"
            )
        if raw.next_hop is None and outgoing_id is None:
            warnings.append(
                f"route {raw.prefix}: neither a next hop nor a resolvable interface — "
                "not representable, skipped"
            )
            continue
        route_id = (
            f"{device_id}-r{index:02d}-"
            f"{raw.prefix.replace('/', '-').replace('.', '_')}-vrf{raw.vrf}"
        )
        if route_id in seen_route_ids:
            warnings.append(f"route {raw.prefix}: duplicate id in VRF {raw.vrf} — skipped")
            continue
        seen_route_ids.add(route_id)
        routes.append(
            Route(
                id=route_id,
                device_id=device_id,
                vrf_id=vrf_map.get(raw.vrf, "GLOBAL"),
                destination_prefix=raw.prefix,
                next_hop=raw.next_hop,
                outgoing_interface_id=outgoing_id,
                protocol=raw.protocol,
                active=raw.active,
            )
        )

    topology = Topology(
        devices=[device],
        interfaces=interfaces,
        links=[],
        vrfs=vrfs,
        routes=routes,
        endpoints=[],
        services=[],
    )
    return topology, warnings
