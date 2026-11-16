"""Cisco IOS OSPF parsers (Phase 2.6).

One small, independent function per command. Nothing here talks to a device,
imports a transport, or knows about the discovery walk — text in, dataclasses
out, plus warnings for anything that could not be parsed.

A deliberate choice: **authentication is never parsed.** ``show ip ospf
interface brief`` is the interface command used throughout, because it carries
the fields that matter (process, area, address/mask, cost, state, neighbour
counts) and no key material. ``show ip ospf interface`` — which can print
authentication configuration — is never collected, so there is no parser that
could leak it.

Every parser tolerates:

* empty output;
* missing sections;
* malformed rows (skipped with a warning, never silently);
* IOS column layouts that shift between versions.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

from nettwin.domain.ospf_models import (
    OspfInterface,
    OspfLinkType,
    OspfLsaLink,
    OspfLsaSummary,
    OspfNetworkLsa,
    OspfRoute,
    OspfRouterLsa,
    OspfRouteType,
)

# --------------------------------------------------------------------------- #
# Shared helpers
# --------------------------------------------------------------------------- #

_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_IPV4_ANY_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_PROCESS_RE = re.compile(r"Process ID\s+(\d+)", re.IGNORECASE)
_ROUTER_ID_RE = re.compile(r"OSPF Router with ID\s+\((\d+(?:\.\d+){3})\)", re.IGNORECASE)
_AREA_HEADER_RE = re.compile(r"^\s*Area\s+(\S+)\s*$", re.IGNORECASE)
#: "Router Link States (Area 0)" / "Net Link States (Area 1.2.3.4)"
_LSA_SECTION_RE = re.compile(
    r"^\s*(Router|Net)\s+Link States\s+\(Area\s+(\S+?)\)\s*$", re.IGNORECASE
)


def process_context(text: str) -> tuple[str, str]:
    """Extract ``(process_id, router_id)`` from an OSPF output header.

    Both are optional — an empty string means the output did not say.
    """
    process = _PROCESS_RE.search(text or "")
    router = _ROUTER_ID_RE.search(text or "")
    return (
        process.group(1) if process else "",
        router.group(1) if router else "",
    )


def _is_ipv4(token: str) -> bool:
    return bool(_IPV4_RE.match(token))


def _to_int(token: str) -> int | None:
    try:
        return int(token)
    except (TypeError, ValueError):
        return None


def _mask_to_prefixlen(mask: str) -> int | None:
    try:
        return ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
    except ValueError:
        return None


# --------------------------------------------------------------------------- #
# show ip ospf neighbor
# --------------------------------------------------------------------------- #

_NEIGHBOR_HEADER_WORDS = {"neighbor", "id"}


@dataclass
class ParsedOspfNeighbor:
    """One ``show ip ospf neighbor`` row."""

    neighbor_id: str
    priority: str
    state: str
    dead_time: str
    address: str
    interface: str


def parse_show_ip_ospf_neighbor(
    text: str,
) -> tuple[list[ParsedOspfNeighbor], list[str]]:
    """Parse ``show ip ospf neighbor``.

    Rows are ``<router-id> <pri> <state> <dead-time> <address> <interface>``.
    The state may be ``FULL/DR``, ``2WAY/DROTHER``, ``EXSTART/DROTHER`` and so
    on, and the interface name may contain no spaces — but it is rebuilt from
    the tail rather than assumed to be one token.
    """
    neighbors: list[ParsedOspfNeighbor] = []
    warnings: list[str] = []
    if not text or not text.strip():
        return neighbors, ["show ip ospf neighbor: empty output"]

    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        tokens = line.split()
        if tokens[0].lower() in _NEIGHBOR_HEADER_WORDS:
            continue
        if not _is_ipv4(tokens[0]):
            warnings.append(f"show ip ospf neighbor: skipped non-neighbor line {line!r}")
            continue
        if len(tokens) < 6:
            warnings.append(f"show ip ospf neighbor: skipped short row {line!r}")
            continue
        dead_time = tokens[3]
        if ":" not in dead_time:
            warnings.append(
                f"show ip ospf neighbor: skipped row with no dead time {line!r}"
            )
            continue
        neighbors.append(
            ParsedOspfNeighbor(
                neighbor_id=tokens[0],
                priority=tokens[1],
                state=tokens[2],
                dead_time=dead_time,
                address=tokens[4],
                interface=" ".join(tokens[5:]),
            )
        )

    if not neighbors:
        warnings.append("show ip ospf neighbor: no neighbor rows parsed")
    return neighbors, warnings


# --------------------------------------------------------------------------- #
# show ip ospf interface brief
# --------------------------------------------------------------------------- #

_IFACE_BRIEF_ROW_RE = re.compile(
    r"^(?P<name>\S+)\s+"
    r"(?P<pid>\d+)\s+"
    r"(?P<area>\S+)\s+"
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})/(?P<plen>\d{1,2})\s+"
    r"(?P<cost>\d+)\s+"
    r"(?P<state>\S+)\s+"
    r"(?P<nbrs>\d+/\d+)\s*$"
)


def parse_show_ip_ospf_interface_brief(
    text: str, device_id: str = ""
) -> tuple[list[OspfInterface], list[str]]:
    """Parse ``show ip ospf interface brief``.

    Example row::

        Et0/0        10    0               10.0.23.1/30       10    DR    2/2

    The header line and any trailer are skipped. A row that does not match the
    full shape is reported rather than guessed at, because a partially-parsed
    interface would put a router in the wrong area.
    """
    interfaces: list[OspfInterface] = []
    warnings: list[str] = []
    if not text or not text.strip():
        return interfaces, ["show ip ospf interface brief: empty output"]

    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.lower().startswith("interface"):
            continue
        match = _IFACE_BRIEF_ROW_RE.match(line)
        if not match:
            warnings.append(
                f"show ip ospf interface brief: skipped unparseable row {line!r}"
            )
            continue
        plen = int(match.group("plen"))
        mask = str(ipaddress.IPv4Network(f"0.0.0.0/{plen}").netmask) if plen <= 32 else ""
        nbrs = match.group("nbrs").split("/")
        interfaces.append(
            OspfInterface(
                device_id=device_id,
                name=match.group("name"),
                process_id=match.group("pid"),
                area=match.group("area"),
                ip_address=match.group("ip"),
                mask=mask,
                cost=_to_int(match.group("cost")),
                state=match.group("state"),
                neighbors_full=_to_int(nbrs[0]),
                neighbors_total=_to_int(nbrs[1]),
            )
        )

    if not interfaces:
        warnings.append("show ip ospf interface brief: no interface rows parsed")
    return interfaces, warnings


# --------------------------------------------------------------------------- #
# show ip ospf database  (summary)
# --------------------------------------------------------------------------- #

_SUMMARY_HEADER_RE = re.compile(r"^Link ID\s+ADV Router\s+Age\b", re.IGNORECASE)


def parse_show_ip_ospf_database(
    text: str,
) -> tuple[list[OspfLsaSummary], list[str]]:
    """Parse the LSDB summary.

    Rows live under ``Router Link States (Area X)`` / ``Net Link States (Area
    X)`` headers; the LSA type comes from the section, not from the row, and
    Router rows carry an extra ``Link count`` column that Net rows do not.
    """
    summaries: list[OspfLsaSummary] = []
    warnings: list[str] = []
    if not text or not text.strip():
        return summaries, ["show ip ospf database: empty output"]

    area = ""
    lsa_type = 0
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        section = _LSA_SECTION_RE.match(line)
        if section:
            kind, area = section.group(1).lower(), section.group(2)
            lsa_type = 1 if kind == "router" else 2
            continue
        if _SUMMARY_HEADER_RE.match(line) or line.lower().startswith("asbr summary"):
            continue
        if lsa_type == 0:
            continue  # before any section header: nothing to attribute rows to
        tokens = line.split()
        if len(tokens) < 5 or not _is_ipv4(tokens[0]) or not _is_ipv4(tokens[1]):
            warnings.append(f"show ip ospf database: skipped row {line!r}")
            continue
        summaries.append(
            OspfLsaSummary(
                area=area,
                lsa_type=lsa_type,
                link_state_id=tokens[0],
                advertising_router=tokens[1],
                age=_to_int(tokens[2]),
                sequence=tokens[3],
                checksum=tokens[4],
                link_count=_to_int(tokens[5]) if len(tokens) > 5 else None,
            )
        )

    if not summaries:
        warnings.append("show ip ospf database: no LSA rows parsed")
    return summaries, warnings


# --------------------------------------------------------------------------- #
# show ip ospf database router  (Type 1 detail)
# --------------------------------------------------------------------------- #

_DETAIL_SPLIT_RE = re.compile(r"^\s*LS age:\s*(\d+)", re.IGNORECASE)
_KEY_VALUE_RE = re.compile(r"^\s*(?P<key>[A-Za-z][A-Za-z0-9 /()\-]*?):\s*(?P<value>.*?)\s*$")
_LINK_CONNECTED_RE = re.compile(
    r"^\s*Link connected to:\s*(?P<kind>.*?)\s*$", re.IGNORECASE
)
#: "(Link ID) Designated Router address: 10.0.21.1" and its many spellings.
_LINK_ID_RE = re.compile(r"\(Link ID\)\s*[^:]*:\s*(?P<value>\S+)", re.IGNORECASE)
_LINK_DATA_RE = re.compile(r"\(Link Data\)\s*[^:]*:\s*(?P<value>\S+)", re.IGNORECASE)
_MASK_RE = re.compile(
    r"Network Mask:\s*(?P<mask>\d{1,3}(?:\.\d{1,3}){3}|/\d{1,2})", re.IGNORECASE
)
_TOS_METRIC_RE = re.compile(r"TOS\s*\d+\s*Metrics?:\s*(?P<metric>\d+)", re.IGNORECASE)
_MTID_RE = re.compile(r"Number of MTID metrics:\s*(?P<mtid>\d+)", re.IGNORECASE)

_LINK_TYPE_MAP: dict[str, OspfLinkType] = {
    "point-to-point": OspfLinkType.POINT_TO_POINT,
    "transit network": OspfLinkType.TRANSIT,
    "stub network": OspfLinkType.STUB,
    "virtual link": OspfLinkType.VIRTUAL,
}


def _classify_link(kind: str) -> OspfLinkType:
    lowered = kind.strip().lower()
    for needle, value in _LINK_TYPE_MAP.items():
        if needle in lowered:
            return value
    return OspfLinkType.UNKNOWN


@dataclass
class _RouterLsaBuilder:
    """Accumulates one Router LSA block as its lines arrive."""

    area: str = ""
    lsa: OspfRouterLsa | None = None
    links: list[OspfLsaLink] = field(default_factory=list)
    current: dict[str, object] = field(default_factory=dict)

    def flush_link(self, warnings: list[str]) -> None:
        if not self.current:
            return
        kind = OspfLinkType(str(self.current.get("link_type", "unknown")))
        link = OspfLsaLink(
            link_type=kind,
            link_id=str(self.current.get("link_id", "")),
            link_data=str(self.current.get("link_data", "")),
            network_mask=str(self.current.get("mask", "")),
            metric=self.current.get("metric"),  # type: ignore[arg-type]
            mtid=str(self.current.get("mtid", "")),
        )
        if kind is OspfLinkType.UNKNOWN:
            warnings.append(
                f"show ip ospf database router: unrecognized link type "
                f"{self.current.get('raw_kind')!r} — kept as unknown"
            )
        self.links.append(link)
        self.current = {}

    def flush_lsa(self, warnings: list[str]) -> OspfRouterLsa | None:
        self.flush_link(warnings)
        if self.lsa is None:
            return None
        self.lsa.links = list(self.links)
        finished = self.lsa
        self.lsa = None
        self.links = []
        return finished


def parse_show_ip_ospf_database_router(
    text: str, device_id: str = ""
) -> tuple[list[OspfRouterLsa], list[str]]:
    """Parse ``show ip ospf database router``.

    Structure per LSA::

        LS age: 1421
        LS Type: Router Links
        Link State ID: 10.255.255.1
        Advertising Router: 10.255.255.1
        LS Seq Number: 80000005
        Checksum: 0xA1B2
        Number of Links: 3

            Link connected to: a Transit Network
             (Link ID) Designated Router address: 10.0.21.1
             (Link Data) Router Interface address: 10.0.21.2
              Number of MTID metrics: 0
               TOS 0 Metrics: 10

    Link types are not assumed to be uniform: each ``Link connected to:`` line
    starts a new link record with its own fields, and an unrecognized type is
    preserved as ``unknown`` with a warning instead of being dropped.
    """
    lsas: list[OspfRouterLsa] = []
    warnings: list[str] = []
    if not text or not text.strip():
        return lsas, ["show ip ospf database router: empty output"]

    area = ""
    builder = _RouterLsaBuilder()
    saw_header = False

    def start_lsa(age: int) -> None:
        builder.lsa = OspfRouterLsa(
            area=area,
            link_state_id="",
            advertising_router="",
            age=age,
            device_id=device_id,
            command="show ip ospf database router",
        )

    for raw in text.splitlines():
        line = raw.rstrip()
        stripped = line.strip()
        if not stripped:
            continue

        section = _LSA_SECTION_RE.match(stripped)
        if section:
            finished = builder.flush_lsa(warnings)
            if finished is not None:
                lsas.append(finished)
            area = section.group(2)
            saw_header = True
            continue
        area_line = _AREA_HEADER_RE.match(stripped)
        if area_line and not stripped.lower().startswith("area 0 ("):
            area = area_line.group(1)
            continue

        age_match = _DETAIL_SPLIT_RE.match(stripped)
        if age_match:
            finished = builder.flush_lsa(warnings)
            if finished is not None:
                lsas.append(finished)
            start_lsa(int(age_match.group(1)))
            continue

        if builder.lsa is None:
            continue

        connected = _LINK_CONNECTED_RE.match(stripped)
        if connected:
            builder.flush_link(warnings)
            kind_raw = connected.group("kind").strip()
            # "a Transit Network" -> "Transit Network"
            kind_clean = re.sub(r"^a\s+", "", kind_raw, flags=re.IGNORECASE)
            builder.current = {
                "link_type": _classify_link(kind_clean).value,
                "raw_kind": kind_clean,
            }
            continue

        if builder.current:
            id_match = _LINK_ID_RE.search(stripped)
            if id_match:
                builder.current["link_id"] = id_match.group("value")
                continue
            data_match = _LINK_DATA_RE.search(stripped)
            if data_match:
                builder.current["link_data"] = data_match.group("value")
                # A stub link prints "(Link Data) Network Mask: 255.255.255.224":
                # here Link Data *is* the mask, so record it as both. For a
                # transit/P2P link it is an interface address and the two stay
                # distinct.
                if "network mask" in stripped.lower():
                    builder.current["mask"] = data_match.group("value")
                continue
            mask_match = _MASK_RE.search(stripped)
            if mask_match:
                builder.current["mask"] = mask_match.group("mask")
                continue
            metric_match = _TOS_METRIC_RE.search(stripped)
            if metric_match:
                builder.current["metric"] = _to_int(metric_match.group("metric"))
                continue
            mtid_match = _MTID_RE.search(stripped)
            if mtid_match:
                builder.current["mtid"] = mtid_match.group("mtid")
                continue

        kv = _KEY_VALUE_RE.match(stripped)
        if kv:
            key = kv.group("key").strip().lower()
            value = kv.group("value").strip()
            if key == "link state id":
                builder.lsa.link_state_id = value
            elif key == "advertising router":
                builder.lsa.advertising_router = value
            elif key == "ls seq number":
                builder.lsa.sequence = value
            elif key == "checksum":
                builder.lsa.checksum = value
            elif key == "number of links":
                builder.lsa.number_of_links = _to_int(value)
            continue

    finished = builder.flush_lsa(warnings)
    if finished is not None:
        lsas.append(finished)

    for lsa in lsas:
        if not lsa.link_state_id:
            warnings.append(
                "show ip ospf database router: LSA with no Link State ID — "
                "kept but not attributable"
            )
        if not lsa.advertising_router:
            warnings.append("show ip ospf database router: LSA with no Advertising Router")
        if lsa.number_of_links is not None and lsa.number_of_links != len(lsa.links):
            warnings.append(
                f"show ip ospf database router: {lsa.link_state_id or '?'} declares "
                f"{lsa.number_of_links} link(s) but {len(lsa.links)} parsed"
            )

    if not lsas and not saw_header:
        warnings.append("show ip ospf database router: no Router LSA blocks parsed")
    return lsas, warnings


# --------------------------------------------------------------------------- #
# show ip ospf database network  (Type 2 detail)
# --------------------------------------------------------------------------- #

_ATTACHED_RE = re.compile(r"Attached Router:\s*(?P<router>\d+(?:\.\d+){3})", re.IGNORECASE)
_DR_ADDRESS_RE = re.compile(
    r"Link State ID:\s*(?P<addr>\d+(?:\.\d+){3})", re.IGNORECASE
)


def parse_show_ip_ospf_database_network(
    text: str, device_id: str = ""
) -> tuple[list[OspfNetworkLsa], list[str]]:
    """Parse ``show ip ospf database network``.

    The ``Link State ID`` is the DR's interface address; ``Network Mask`` may be
    printed as ``/24`` or ``255.255.255.0`` and both are normalized to a
    dotted mask. ``Attached Router`` lines accumulate per LSA.
    """
    lsas: list[OspfNetworkLsa] = []
    warnings: list[str] = []
    if not text or not text.strip():
        return lsas, ["show ip ospf database network: empty output"]

    area = ""
    current: OspfNetworkLsa | None = None

    def flush() -> None:
        nonlocal current
        if current is None:
            return
        lsas.append(current)
        current = None

    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        section = _LSA_SECTION_RE.match(line)
        if section:
            flush()
            area = section.group(2)
            continue
        age_match = _DETAIL_SPLIT_RE.match(line)
        if age_match:
            flush()
            current = OspfNetworkLsa(
                area=area,
                link_state_id="",
                advertising_router="",
                age=int(age_match.group(1)),
                device_id=device_id,
                command="show ip ospf database network",
            )
            continue
        if current is None:
            continue

        attached = _ATTACHED_RE.search(line)
        if attached:
            current.attached_routers.append(attached.group("router"))
            continue
        mask_match = _MASK_RE.search(line)
        if mask_match:
            raw_mask = mask_match.group("mask")
            if raw_mask.startswith("/"):
                plen = _to_int(raw_mask[1:])
                current.network_mask = (
                    str(ipaddress.IPv4Network(f"0.0.0.0/{plen}").netmask)
                    if plen is not None and 0 <= plen <= 32
                    else ""
                )
            else:
                current.network_mask = raw_mask
            continue
        dr_match = _DR_ADDRESS_RE.search(line)
        if dr_match:
            current.link_state_id = dr_match.group("addr")
            continue
        kv = _KEY_VALUE_RE.match(line)
        if kv:
            key = kv.group("key").strip().lower()
            value = kv.group("value").strip()
            if key == "advertising router":
                current.advertising_router = value
            elif key == "ls seq number":
                current.sequence = value
            elif key == "checksum":
                current.checksum = value
            continue

    flush()

    for lsa in lsas:
        if not lsa.link_state_id:
            warnings.append(
                "show ip ospf database network: LSA with no Link State ID (DR address) — "
                "kept but not attributable"
            )
        if not lsa.attached_routers:
            warnings.append(
                f"show ip ospf database network: {lsa.link_state_id or '?'} has no "
                "Attached Router rows — membership unknown"
            )
        if not lsa.network_mask:
            warnings.append(
                f"show ip ospf database network: {lsa.link_state_id or '?'} has no "
                "Network Mask — prefix cannot be computed"
            )

    if not lsas:
        warnings.append("show ip ospf database network: no Network LSA blocks parsed")
    return lsas, warnings


# --------------------------------------------------------------------------- #
# show ip ospf route
# --------------------------------------------------------------------------- #

#: "10.0.34.0/30   11   Intra   via 10.0.23.2   Et0/0"
_ROUTE_ROW_RE = re.compile(
    r"^(?P<prefix>\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})\s+"
    r"(?P<metric>\d+)\s+"
    r"(?P<type>[A-Za-z][A-Za-z0-9\-]*)\s+"
    r"(?P<rest>.*)$"
)

_TYPE_MAP: dict[str, OspfRouteType] = {
    "connected": OspfRouteType.CONNECTED,
    "intra": OspfRouteType.INTRA_AREA,
    "inter": OspfRouteType.INTER_AREA,
    "e1": OspfRouteType.EXTERNAL_1,
    "e2": OspfRouteType.EXTERNAL_2,
    "n1": OspfRouteType.NSSA_1,
    "n2": OspfRouteType.NSSA_2,
}


def _classify_route_type(raw: str) -> OspfRouteType:
    return _TYPE_MAP.get(raw.strip().lower(), OspfRouteType.UNKNOWN)


def parse_show_ip_ospf_route(
    text: str, device_id: str = ""
) -> tuple[list[OspfRoute], list[str]]:
    """Parse ``show ip ospf route``.

    ``Connected`` rows are the device's own interface networks; they are marked
    ``learned=False`` so they can never be counted as OSPF-learned. Several
    equal-cost next hops are printed as extra ``via`` lines under one prefix —
    only the first is kept in the single ``next_hop`` field and the rest are
    reported.
    """
    routes: list[OspfRoute] = []
    warnings: list[str] = []
    if not text or not text.strip():
        return routes, ["show ip ospf route: empty output"]

    area = ""
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        area_line = _AREA_HEADER_RE.match(line)
        if area_line and not line.lower().startswith("area border"):
            area = area_line.group(1)
            continue
        if line.lower().startswith(("prefix", "base topology", "ospf router")):
            continue

        match = _ROUTE_ROW_RE.match(line)
        if not match:
            if line.lower().startswith("via"):
                warnings.append(
                    f"show ip ospf route: extra equal-cost next hop ignored {line!r} "
                    "(the model holds one next hop)"
                )
            continue

        raw_type = match.group("type")
        route_type = _classify_route_type(raw_type)
        if route_type is OspfRouteType.UNKNOWN:
            warnings.append(
                f"show ip ospf route: unmapped route type {raw_type!r} for "
                f"{match.group('prefix')}"
            )

        rest = match.group("rest")
        next_hop: str | None = None
        outgoing = ""
        via = re.search(r"via\s+(\d{1,3}(?:\.\d{1,3}){3})(?:\s+(\S+))?", rest)
        if via:
            next_hop = via.group(1)
            outgoing = via.group(2) or ""
        else:
            local = re.search(r"in\s+(\d{1,3}(?:\.\d{1,3}){3})", rest)
            if local:
                outgoing = rest.split()[-1] if rest.split() else ""
        # Interface is always the last token of the row when present.
        tokens = rest.split()
        if tokens and not _is_ipv4(tokens[-1]) and not tokens[-1].startswith("via"):
            outgoing = tokens[-1]

        routes.append(
            OspfRoute(
                device_id=device_id,
                prefix=match.group("prefix"),
                route_type=route_type,
                cost=_to_int(match.group("metric")),
                next_hop=next_hop,
                outgoing_interface=outgoing,
                area=area,
                # A *Connected* row is local interface state, not a learned route.
                learned=route_type is not OspfRouteType.CONNECTED,
                raw_type=raw_type,
            )
        )

    if not routes:
        warnings.append("show ip ospf route: no route rows parsed")
    return routes, warnings


__all__ = [
    "ParsedOspfNeighbor",
    "parse_show_ip_ospf_database",
    "parse_show_ip_ospf_database_network",
    "parse_show_ip_ospf_database_router",
    "parse_show_ip_ospf_interface_brief",
    "parse_show_ip_ospf_neighbor",
    "parse_show_ip_ospf_route",
    "process_context",
]
