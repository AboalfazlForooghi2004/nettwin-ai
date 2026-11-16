"""FortiOS parsers for read-only collection (Phase 2.5).

Every function takes the raw text of one ``get ...`` command and returns
normalized Python objects plus a list of warnings. Nothing here touches the
domain models — that is ``fortios.map_to_topology``'s job — and nothing here
opens a connection.

Verified against Fortinet documentation before implementation:

``get system status``::

    Version: FortiGate-100F v7.4.4,build2662,240514 (GA)
    Serial-Number: FG100FTK00000001
    Hostname: FGT-A

``get system interface``::

    == [ port1 ]
    name: port1
    mode: static
    ip: 192.168.1.99 255.255.255.0
    status: up
    type: physical
    role: lan

``get router info routing-table all``::

    Codes: K - kernel, C - connected, ...
    Routing table for VRF=0
    S*      0.0.0.0/0 [10/0] via 172.20.120.2, wan1
    C       10.31.101.0/24 is directly connected, internal

FortiOS versions differ in small ways that this module absorbs rather than
hides:

* ``status: enable`` (older) vs ``status: up`` / ``status: down`` (newer);
* ``ip: 0.0.0.0 0.0.0.0`` for an unaddressed interface — never turned into a
  fake address;
* several ``Routing table for VRF=n`` sections in one output.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

# --------------------------------------------------------------------------- #
# get system status
# --------------------------------------------------------------------------- #

_STATUS_VERSION_RE = re.compile(
    r"^Version:\s*(?P<platform>.*?)\s+v(?P<version>\d+(?:\.\d+)*)[,\s]",
    re.IGNORECASE,
)
_STATUS_VERSION_NOBUILD_RE = re.compile(
    r"^Version:\s*(?P<platform>\S+)\s+v(?P<version>\d+(?:\.\d+)*)\s*$",
    re.IGNORECASE,
)
_STATUS_KV_RE = re.compile(r"^(?P<key>[A-Za-z][A-Za-z0-9 _\-]*?):\s*(?P<value>.*?)\s*$")


@dataclass
class FortiosStatus:
    """Identity fields from ``get system status``."""

    hostname: str = ""
    platform: str = ""          # e.g. "FortiGate-100F"
    model: str = ""             # normalized model, e.g. "FortiGate-100F"
    version: str = ""           # e.g. "7.4.4"
    build: str = ""             # e.g. "2662"
    serial: str = ""            # e.g. "FG100FTK00000001"
    vdom: str = ""              # current virtual domain
    raw_fields: dict[str, str] = field(default_factory=dict)

    @property
    def is_fortigate(self) -> bool:
        return bool(self.platform or self.version)


def parse_system_status(text: str) -> tuple[FortiosStatus, list[str]]:
    """Parse ``get system status``.

    The ``Version:`` line is the one that identifies the device. When it is
    missing or malformed the result is left empty and a warning explains why —
    callers must not treat an empty status as evidence of a FortiGate.
    """
    status = FortiosStatus()
    warnings: list[str] = []
    if not text or not text.strip():
        return status, ["get system status: empty output — device identity not established"]

    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.lower().startswith("version:"):
            match = _STATUS_VERSION_RE.match(line) or _STATUS_VERSION_NOBUILD_RE.match(line)
            if match:
                status.platform = match.group("platform").strip()
                status.version = match.group("version").strip()
                status.model = status.platform
                build = re.search(r"build(?P<build>\d+)", line)
                if build:
                    status.build = build.group("build")
            else:
                warnings.append(
                    f"get system status: unrecognized Version line {line!r}"
                )
            continue
        kv = _STATUS_KV_RE.match(line)
        if kv:
            key = kv.group("key").strip()
            value = kv.group("value").strip()
            status.raw_fields[key] = value
            lowered = key.lower()
            if lowered == "hostname":
                status.hostname = value
            elif lowered == "serial-number":
                status.serial = value
            elif lowered == "current virtual domain":
                status.vdom = value

    if not status.version:
        warnings.append(
            "get system status: no FortiOS version found — device may not be a FortiGate"
        )
    if not status.hostname:
        warnings.append("get system status: hostname not reported")
    if not status.serial:
        warnings.append("get system status: serial number not reported")
    return status, warnings


# --------------------------------------------------------------------------- #
# get system interface
# --------------------------------------------------------------------------- #

_IFACE_BLOCK_RE = re.compile(r"^==\s*\[\s*(?P<name>[^\]]+?)\s*\]\s*$")
_IFACE_KV_RE = re.compile(r"^(?P<key>[A-Za-z0-9_\-]+)\s*:\s*(?P<value>.*?)\s*$")
_IPV4_MASK_RE = re.compile(r"^(?P<addr>\d+\.\d+\.\d+\.\d+)\s+(?P<mask>\d+\.\d+\.\d+\.\d+)$")


@dataclass
class FortiosInterface:
    """One interface block from ``get system interface``."""

    name: str
    ip_addresses: list[str] = field(default_factory=list)   # "a.b.c.d/len"
    admin_state: str = "unknown"                            # up | down | unknown
    raw_status: str = ""                                    # as printed
    iface_type: str = ""                                    # physical | vlan | ...
    vdom: str = ""
    mode: str = ""

    def describe(self) -> str:
        return f"{self.name} ({'up' if self.admin_state == 'up' else self.admin_state})"


def _normalize_admin_state(raw: str) -> str:
    """Map FortiOS spellings onto up/down/unknown.

    Older FortiOS prints ``enable``/``disable``; newer prints ``up``/``down``.
    Anything else stays ``unknown`` so a link state is never invented from a
    status string we do not actually recognise.
    """
    lowered = raw.strip().lower()
    if lowered in {"up", "enable", "enabled"}:
        return "up"
    if lowered in {"down", "disable", "disabled"}:
        return "down"
    return "unknown"


def parse_system_interface(text: str) -> tuple[list[FortiosInterface], list[str]]:
    """Parse ``get system interface`` into one record per ``== [ name ]`` block."""
    interfaces: list[FortiosInterface] = []
    warnings: list[str] = []
    if not text or not text.strip():
        return interfaces, ["get system interface: empty output"]

    current: FortiosInterface | None = None

    def flush() -> None:
        if current is not None:
            interfaces.append(current)

    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        header = _IFACE_BLOCK_RE.match(line)
        if header:
            flush()
            current = FortiosInterface(name=header.group("name").strip())
            continue
        if current is None:
            continue

        kv = _IFACE_KV_RE.match(line)
        if not kv:
            continue
        key = kv.group("key").strip().lower()
        value = kv.group("value").strip()

        if key == "name":
            # The block header already named it; trust the explicit field when
            # both are present, and note a disagreement instead of guessing.
            if value and value != current.name:
                warnings.append(
                    f"get system interface: block header {current.name!r} disagrees "
                    f"with name field {value!r} — using the name field"
                )
                current.name = value
        elif key == "ip":
            ipv4 = _IPV4_MASK_RE.match(value)
            if not ipv4:
                if value and value not in {"(null)", "-"}:
                    warnings.append(
                        f"get system interface: {current.name}: unrecognized ip {value!r}"
                    )
                continue
            addr, mask = ipv4.group("addr"), ipv4.group("mask")
            if addr == "0.0.0.0":
                # An unaddressed interface. Never fabricate 0.0.0.0/0.
                continue
            try:
                network = ipaddress.ip_network(f"{addr}/{mask}", strict=False)
            except ValueError:
                warnings.append(
                    f"get system interface: {current.name}: invalid address {value!r}"
                )
                continue
            current.ip_addresses.append(f"{addr}/{network.prefixlen}")
        elif key == "status":
            current.raw_status = value
            current.admin_state = _normalize_admin_state(value)
        elif key == "type":
            current.iface_type = value
        elif key == "vdom":
            current.vdom = value
        elif key == "mode":
            current.mode = value

    flush()

    seen: set[str] = set()
    for iface in interfaces:
        if not iface.name:
            continue
        if iface.name in seen:
            warnings.append(
                f"get system interface: duplicate block for {iface.name!r} — kept the first"
            )
        seen.add(iface.name)

    if not interfaces:
        warnings.append("get system interface: no interface blocks parsed")
    return interfaces, warnings


# --------------------------------------------------------------------------- #
# get router info routing-table all
# --------------------------------------------------------------------------- #

_VRF_HEADER_RE = re.compile(r"^Routing table for VRF=(?P<vrf>\S+)\s*$")
_CODE_LEGEND_RE = re.compile(r"^(Codes:|[A-Z0-9]{1,3}\s+-\s)")
#: "[10/0] via 172.20.120.2, wan1"  — distance/metric, next hop, interface.
_VIA_RE = re.compile(
    r"via\s+(?P<nh>\d+\.\d+\.\d+\.\d+)"
    r"(?:,\s*(?P<iface>[A-Za-z0-9_.\-/]+))?"
)
_CONNECTED_RE = re.compile(r"is directly connected,\s*(?P<iface>[A-Za-z0-9_.\-/]+)")
#: "S*      0.0.0.0/0 [10/0] via ..."  /  "C  10.31.101.0/24 is directly ..."
_ROUTE_RE = re.compile(
    r"^(?P<codes>[A-Z]{1,2}\*?|\*[A-Z]?)\s+"
    r"(?P<prefix>\d+\.\d+\.\d+\.\d+/\d+)"
    r"\s+(?P<rest>.*)$"
)


@dataclass
class FortiosRoute:
    """One routing-table entry."""

    prefix: str
    protocol: str
    next_hop: str | None
    interface: str | None
    vrf: str
    active: bool = True
    distance: str = ""
    metric: str = ""
    raw: str = ""


#: FortiOS routing codes → the protocol label used in the domain model.
_CODE_TO_PROTOCOL = {
    "C": "connected",
    "S": "static",
    "R": "rip",
    "B": "bgp",
    "O": "ospf",
    "IA": "ospf-inter-area",
    "N1": "ospf-nssa-external-1",
    "N2": "ospf-nssa-external-2",
    "E1": "ospf-external-1",
    "E2": "ospf-external-2",
    "i": "isis",
    "L1": "isis-level-1",
    "L2": "isis-level-2",
    "K": "kernel",
}


def _protocol_for(code: str) -> str:
    bare = code.rstrip("*").lstrip("*").upper()
    return _CODE_TO_PROTOCOL.get(bare, bare.lower() or "unknown")


def parse_routing_table(text: str) -> tuple[list[FortiosRoute], list[str]]:
    """Parse ``get router info routing-table all``.

    Multi-line entries (a route with several equal-cost next hops) are folded
    into the preceding route: only the first next hop becomes ``next_hop`` and
    the rest are reported as a warning, because the domain model holds one.
    """
    routes: list[FortiosRoute] = []
    warnings: list[str] = []
    if not text or not text.strip():
        return routes, ["get router info routing-table all: empty output"]

    vrf = "0"
    pending: FortiosRoute | None = None

    for raw in text.splitlines():
        line = raw.rstrip()
        stripped = line.strip()
        if not stripped:
            continue
        if _CODE_LEGEND_RE.match(stripped):
            continue                        # the "Codes:" help block
        header = _VRF_HEADER_RE.match(stripped)
        if header:
            vrf = header.group("vrf")
            continue

        route_match = _ROUTE_RE.match(stripped)
        if route_match:
            code = route_match.group("codes")
            prefix = route_match.group("prefix")
            rest = route_match.group("rest")

            try:
                network = ipaddress.ip_network(prefix, strict=False)
            except ValueError:
                warnings.append(
                    f"get router info routing-table all: invalid prefix {prefix!r}"
                )
                pending = None
                continue

            protocol = _protocol_for(code)
            connected = _CONNECTED_RE.search(rest)
            via = None if connected else _VIA_RE.search(rest)
            next_hop = via.group("nh") if via else None
            interface = (
                connected.group("iface")
                if connected
                else (via.group("iface") if via and via.group("iface") else None)
            )

            distance = metric = ""
            metric_match = re.search(r"\[(?P<d>\d+)/(?P<m>\d+)\]", rest)
            if metric_match:
                distance = metric_match.group("d")
                metric = metric_match.group("m")

            if next_hop is None and interface is None:
                warnings.append(
                    f"get router info routing-table all: {prefix}: no next hop and "
                    "no interface — route not representable, skipped"
                )
                pending = None
                continue

            pending = FortiosRoute(
                prefix=str(network),
                protocol=protocol,
                next_hop=next_hop,
                interface=interface,
                vrf=vrf,
                # ``*`` marks a candidate default route, NOT an inactive one, and
                # ``routing-table all`` lists the active table — same rule as IOS.
                active=True,
                distance=distance,
                metric=metric,
                raw=stripped,
            )
            routes.append(pending)
            continue

        # A continuation line such as "      [10/0] via 10.10.10.11, internal"
        # belongs to the previous route: ECMP.
        if pending is not None and stripped.startswith("["):
            extra = _VIA_RE.search(stripped)
            if extra:
                warnings.append(
                    f"get router info routing-table all: {pending.prefix}: "
                    f"additional next hop {extra.group('nh')} observed (ECMP) — "
                    "the domain model holds one next hop, so it is recorded here only"
                )
            continue

    if not routes and text.strip():
        warnings.append(
            "get router info routing-table all: no routes parsed — "
            "unrecognized output or an empty table"
        )
    return routes, warnings


# --------------------------------------------------------------------------- #
# get system lldp neighbors
# --------------------------------------------------------------------------- #

_LLDP_BLOCK_RE = re.compile(r"^==\s*\[\s*(?P<name>[^\]]+?)\s*\]\s*$")


@dataclass
class FortiosLldpNeighbor:
    """One neighbor row, normalized toward the Cisco CDP evidence shape."""

    local_interface: str
    remote_device: str
    remote_interface: str
    remote_platform: str = ""
    remote_ip: str = ""


def parse_lldp_neighbors(text: str) -> tuple[list[FortiosLldpNeighbor], list[str]]:
    """Parse ``get system lldp neighbors`` if the operator enabled LLDP.

    LLDP reception is **off by default on FortiGate**, so this normally
    returns nothing at all. That is a real fact about the device, not a parse
    failure, and the warning says so.
    """
    if not text or not text.strip():
        return [], [
            "get system lldp neighbors: empty output — LLDP reception is disabled by "
            "default on FortiGate, so no neighbor evidence is available "
            "(no links are inferred from this device)"
        ]

    neighbors: list[FortiosLldpNeighbor] = []
    warnings: list[str] = []
    return neighbors, warnings
