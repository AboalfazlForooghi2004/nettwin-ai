"""Pure parsers for sanitized Cisco IOS 15.2 CLI outputs (Phase 2 MVP).

Each parser is a deterministic function of its text input: the same output
text always yields the same result. Parsers never invent values — any field
that cannot be extracted from the text is returned as ``None`` (or the row is
skipped with an explanatory warning) so callers can mark it unavailable.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# --------------------------------------------------------------------------- #
# Parsed record types
# --------------------------------------------------------------------------- #


@dataclass
class ParsedVersion:
    """Identity extracted from ``show version``."""

    hostname: str | None = None
    ios_version: str | None = None
    model: str | None = None


@dataclass
class InterfaceBrief:
    """One row of ``show ip interface brief``."""

    name: str
    ip_address: str | None
    status: str
    protocol: str
    admin_state: str  # "up" | "down"
    oper_state: str  # "up" | "down"


@dataclass
class ParsedRoute:
    """One routing-table entry from ``show ip route``.

    ``next_hops`` preserves *every* observed next hop (ECMP) as a list of
    dicts with keys ``next_hop`` (str | None — None for directly connected /
    local routes) and ``outgoing_interface`` (str | None).
    """

    prefix: str
    protocol: str
    protocol_code: str
    ad: int | None
    metric: int | None
    next_hops: list[dict] = field(default_factory=list)
    candidate_default: bool = False


@dataclass
class OspfNeighbor:
    """One row of ``show ip ospf neighbor``."""

    neighbor_id: str
    priority: str
    state: str
    dead_time: str
    address: str
    interface: str


@dataclass
class CdpNeighbor:
    """One row of ``show cdp neighbors``."""

    device_id: str
    local_interface: str  # normalized (e.g. Ethernet0/0)
    holdtime: str
    capabilities: str
    platform: str
    port_id: str  # normalized remote interface


# --------------------------------------------------------------------------- #
# Shared helpers
# --------------------------------------------------------------------------- #

# Interface abbreviation expansion for CDP rows ("Eth 0/0" -> Ethernet0/0).
_IFACE_ABBREV = {
    "eth": "ethernet",
    "fast": "fastethernet",
    "faste": "fastethernet",
    "gig": "gigabitethernet",
    "gige": "gigabitethernet",
    "ten": "tengigabitethernet",
    "twe": "tengigabitethernet",
    "lo": "loopback",
    "vl": "vlan",
    "se": "serial",
    "po": "port-channel",
    "mgmt": "management",
}


def normalize_interface(raw: str) -> str:
    """Normalize a short interface name (``Eth 0/0``) to IOS long form."""
    compact = raw.strip().replace(" ", "")
    match = re.match(r"^([A-Za-z-]+?)(\d+(?:/\d+)*[a-z]?)$", compact)
    if not match:
        return raw.strip()
    prefix, num = match.group(1), match.group(2)
    expanded = _IFACE_ABBREV.get(prefix.lower())
    if expanded is None:
        return compact
    return _expand(expanded, num)


def _expand(expanded: str, num: str) -> str:
    # Preserve canonical casing: Ethernet, FastEthernet, GigabitEthernet,
    # TenGigabitEthernet, Loopback, Vlan, Serial, Port-Channel, Management.
    casing = {
        "ethernet": "Ethernet",
        "fastethernet": "FastEthernet",
        "gigabitethernet": "GigabitEthernet",
        "tengigabitethernet": "TenGigabitEthernet",
        "loopback": "Loopback",
        "vlan": "Vlan",
        "serial": "Serial",
        "port-channel": "Port-channel",
        "management": "Management",
    }
    return f"{casing.get(expanded, expanded.capitalize())}{num}"


# --------------------------------------------------------------------------- #
# show version
# --------------------------------------------------------------------------- #

_VERSION_RE = re.compile(r"Version\s+(\d+\.\d+(?:\([0-9A-Za-z]+\))?[^\s,]*)")
_MODEL_RE = re.compile(r"^cisco\s+(\S+)\s+\(", re.MULTILINE)
_UPTIME_RE = re.compile(r"^(.+?)\s+uptime is\s", re.MULTILINE)


def parse_show_version(text: str) -> tuple[ParsedVersion, list[str]]:
    """Extract hostname, IOS version and platform model from ``show version``."""
    warnings: list[str] = []
    parsed = ParsedVersion()
    uptime = _UPTIME_RE.search(text)
    if uptime:
        candidate = uptime.group(1).strip()
        # First line may contain the software title; the hostname line is the
        # one where the captured text looks like a bare hostname.
        for line in text.splitlines():
            if " uptime is " in line:
                parsed.hostname = line.split(" uptime is")[0].strip()
                break
        if not parsed.hostname:
            parsed.hostname = candidate or None
    if not parsed.hostname:
        warnings.append("show version: hostname/uptime line not found (unavailable)")
    version = _VERSION_RE.search(text)
    if version:
        parsed.ios_version = version.group(1)
    else:
        warnings.append("show version: Version string not found (unavailable)")
    model = _MODEL_RE.search(text)
    if model:
        parsed.model = model.group(1)
    else:
        warnings.append("show version: processor/model line not found (unavailable)")
    return parsed, warnings


# --------------------------------------------------------------------------- #
# show ip interface brief
# --------------------------------------------------------------------------- #


def parse_show_ip_interface_brief(text: str) -> tuple[list[InterfaceBrief], list[str]]:
    """Parse ``show ip interface brief`` rows (deterministic, fixed columns)."""
    interfaces: list[InterfaceBrief] = []
    warnings: list[str] = []
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line.strip():
            continue
        if line.lstrip().startswith("Interface"):
            continue  # header
        if set(line.strip()) <= set("- "):
            continue
        tokens = line.split()
        # name IP-Address OK? Method Status Protocol  (Status may contain spaces)
        if len(tokens) < 6 or tokens[2] not in {"YES", "NO"}:
            warnings.append(f"show ip interface brief: skipped unparseable row: {line.strip()!r}")
            continue
        name = tokens[0]
        ip = None if tokens[1] == "unassigned" else tokens[1]
        protocol = tokens[-1]
        status = " ".join(tokens[4:-1])
        admin_state = "down" if "administratively" in status.lower() else "up"
        oper_state = "up" if (status.lower() == "up" and protocol.lower() == "up") else "down"
        interfaces.append(
            InterfaceBrief(
                name=name,
                ip_address=ip,
                status=status,
                protocol=protocol,
                admin_state=admin_state,
                oper_state=oper_state,
            )
        )
    if not interfaces:
        warnings.append("show ip interface brief: no interface rows parsed")
    return interfaces, warnings


# --------------------------------------------------------------------------- #
# show ip route
# --------------------------------------------------------------------------- #

_ROUTE_ENTRY_RE = re.compile(
    # Protocol codes may contain digits (E2, N1, L2, IA, EX1, ...).
    r"^(?P<codes>[A-Za-z0-9*]+(?:\s+[A-Za-z0-9*]+)*)\s+"
    r"(?P<prefix>\d+\.\d+\.\d+\.\d+/\d+)\s+(?P<rest>.+)$"
)
_VIA_RE = re.compile(
    r"via\s+(?P<nh>\d+\.\d+\.\d+\.\d+)"
    r"(?:,\s*(?P<uptime>[^,]+))?"
    r"(?:,\s*(?P<iface>[A-Za-z][A-Za-z0-9_./-]*))?"
)


def _via_groups(via: re.Match[str]) -> tuple[str, str | None]:
    """Return (next_hop, outgoing_interface) tolerating uptime omission."""
    nh = via.group("nh")
    uptime = (via.group("uptime") or "").strip()
    iface = via.group("iface")
    if iface is None and uptime and uptime[0].isalpha():
        # No uptime field: what looks like uptime is actually the interface.
        iface = uptime
    return nh, iface
_DIRECT_RE = re.compile(r"is directly connected(?:,\s*(?P<iface>[A-Za-z][A-Za-z0-9_./-]*))?")
_ADMETRIC_RE = re.compile(r"\[(?P<ad>\d+)/(?P<metric>\d+)\]")

_PROTOCOL_BY_CODE = {
    "L": "local",
    "C": "connected",
    "S": "static",
    "O": "ospf",
    "B": "bgp",
    "E": "eigrp",
    "D": "eigrp",
    "R": "rip",
    "i": "isis",
}

_SKIP_LINE_RE = re.compile(
    r"(is subnetted|is variably subnetted|Gateway of last resort|^Codes:|^\s*[\*\[\(]?\s*"
    r"(via|O|S|C|L|B|D|R|i|E)\s*$)"
)


def parse_show_ip_route(text: str) -> tuple[list[ParsedRoute], list[str]]:
    """Parse the IOS routing table, preserving every next hop of ECMP entries."""
    routes: list[ParsedRoute] = []
    warnings: list[str] = []
    current: ParsedRoute | None = None
    seen_entries = False

    def flush() -> None:
        nonlocal current
        if current is not None:
            if not current.next_hops:
                warnings.append(
                    f"show ip route: entry {current.prefix} has no extractable next hop (unavailable)"
                )
                current.next_hops.append(
                    {"next_hop": None, "outgoing_interface": None}
                )
            routes.append(current)
            current = None

    for raw in text.splitlines():
        line = raw.rstrip()
        if not line.strip():
            flush()
            continue
        # Continuation lines: indented "via ..." or "[AD/M] via ..."
        stripped = line.strip()
        if stripped.startswith("via ") or stripped.startswith("["):
            if current is None:
                warnings.append(f"show ip route: orphan continuation line skipped: {stripped!r}")
                continue
            via = _VIA_RE.search(stripped)
            ad_metric = _ADMETRIC_RE.search(stripped)
            if ad_metric and current.ad is None:
                current.ad = int(ad_metric.group("ad"))
                current.metric = int(ad_metric.group("metric"))
            if via:
                nh, out_iface = _via_groups(via)
                current.next_hops.append({"next_hop": nh, "outgoing_interface": out_iface})
            else:
                warnings.append(f"show ip route: via not found on continuation: {stripped!r}")
            continue
        # Codes legend / headers / subnetted lines
        if stripped.startswith("Codes:") or _SKIP_LINE_RE.search(stripped):
            # "Codes:" block spans several lines; only skip while inside it.
            if stripped.startswith("Codes:"):
                continue
            flush()
            continue
        if re.match(r"^\s+\S", raw) and current is None and not _ROUTE_ENTRY_RE.match(stripped):
            # indented legend line inside Codes block
            continue

        entry = _ROUTE_ENTRY_RE.match(stripped)
        if entry:
            seen_entries = True
            flush()
            codes = entry.group("codes")
            prefix = entry.group("prefix")
            rest = entry.group("rest")
            if rest.lstrip().startswith("is subnetted") or rest.lstrip().startswith(
                "is variably subnetted"
            ):
                continue
            ad_metric = _ADMETRIC_RE.search(rest)
            protocol_code = codes.strip()
            first_token = protocol_code.split()[0] if protocol_code else ""
            bare = first_token.rstrip("*")
            protocol = _PROTOCOL_BY_CODE.get(bare, "unknown")
            if protocol == "unknown" and protocol_code:
                warnings.append(f"show ip route: unmapped protocol code {protocol_code!r} for {prefix}")
            candidate_default = ("*" in protocol_code.split()) or prefix == "0.0.0.0/0"
            current = ParsedRoute(
                prefix=prefix,
                protocol=protocol,
                protocol_code=protocol_code,
                ad=int(ad_metric.group("ad")) if ad_metric else None,
                metric=int(ad_metric.group("metric")) if ad_metric else None,
                next_hops=[],
                candidate_default=candidate_default,
            )
            direct = _DIRECT_RE.search(rest)
            if direct:
                current.next_hops.append(
                    {"next_hop": None, "outgoing_interface": direct.group("iface")}
                )
            via = _VIA_RE.search(rest)
            if via:
                nh, out_iface = _via_groups(via)
                current.next_hops.append({"next_hop": nh, "outgoing_interface": out_iface})
            continue
        if seen_entries and not stripped.startswith(" "):
            # Unexpected non-route content (trailer notes / malformed rows).
            warnings.append(f"show ip route: non-route line skipped: {stripped!r}")
            continue

    flush()
    if not routes:
        warnings.append("show ip route: no route entries parsed")
    return routes, warnings


# --------------------------------------------------------------------------- #
# show ip ospf neighbor
# --------------------------------------------------------------------------- #

_OSPF_HEADER_TOKENS = {"neighbor", "id", "pri", "state", "dead", "time", "address", "interface"}


def parse_show_ip_ospf_neighbor(text: str) -> tuple[list[OspfNeighbor], list[str]]:
    """Parse ``show ip ospf neighbor`` rows (one neighbor per row)."""
    neighbors: list[OspfNeighbor] = []
    warnings: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        tokens = line.split()
        if tokens[0].lower() in _OSPF_HEADER_TOKENS:
            continue
        if len(tokens) != 6 or not re.match(r"^\d+\.\d+\.\d+\.\d+$", tokens[0]):
            warnings.append(f"show ip ospf neighbor: skipped unparseable row: {line!r}")
            continue
        neighbors.append(
            OspfNeighbor(
                neighbor_id=tokens[0],
                priority=tokens[1],
                state=tokens[2],
                dead_time=tokens[3],
                address=tokens[4],
                interface=" ".join(tokens[5:]),
            )
        )
    return neighbors, warnings


# --------------------------------------------------------------------------- #
# show cdp neighbors
# --------------------------------------------------------------------------- #

_CDP_ROW_RE = re.compile(
    r"^(?P<dev>\S+)\s+"
    r"(?P<local>[A-Za-z][A-Za-z]*\s*\d+/\d+[a-z]?)\s+"
    r"(?P<hold>\d+)\s+"
    r"(?P<cap>[A-Za-z0-9 ]*?)\s{2,}"
    r"(?P<plat>\S+)\s+"
    r"(?P<port>[A-Za-z][A-Za-z]*\s*\d+/\d+[a-z]?)\s*$"
)
_CDP_HEADER_WORDS = {"deviceid", "local", "intrfce", "holdtme", "capability", "platform", "port"}


def parse_show_cdp_neighbors(text: str) -> tuple[list[CdpNeighbor], list[str]]:
    """Parse ``show cdp neighbors`` table rows (deterministic fixed columns)."""
    neighbors: list[CdpNeighbor] = []
    warnings: list[str] = []
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line.strip():
            continue
        if raw[:1].isspace():
            continue  # legend/continuation lines are indented; rows start at column 0
        lowered = line.lower()
        if lowered.startswith("device id") or "holdtme" in lowered:
            continue  # header row (tokens differ across IOS releases)
        first_word = line.split()[0].lower()
        if first_word in _CDP_HEADER_WORDS:
            continue
        if first_word in {"interface", "total"} or "cdp entries" in line.lower():
            continue
        match = _CDP_ROW_RE.match(line)
        if not match:
            warnings.append(f"show cdp neighbors: skipped unparseable row: {line.strip()!r}")
            continue
        neighbors.append(
            CdpNeighbor(
                device_id=match.group("dev"),
                local_interface=normalize_interface(match.group("local")),
                holdtime=match.group("hold"),
                capabilities=match.group("cap").strip(),
                platform=match.group("plat"),
                port_id=normalize_interface(match.group("port")),
            )
        )
    return neighbors, warnings
