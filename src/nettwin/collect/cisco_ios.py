"""Read-only Cisco IOS SSH collector (Phase 2 MVP).

Security invariants (enforced in code, verified by tests):

* Only the five explicit read-only commands in :data:`READ_ONLY_COMMANDS`
  are ever dispatched; anything else is rejected **before** a connection is
  attempted.
* No configuration mode, no enable mode, no ``write``/``reload``/``clear``
  commands can be issued through this class — configuration keywords are
  additionally hard-rejected as a second layer.
* Credentials are read from environment variables
  (``NETTWIN_DEVICE_USERNAME`` / ``NETTWIN_DEVICE_PASSWORD``) at collect
  time; they are never stored in observations, logs or errors (messages are
  sanitized before being raised).
* The application-side allowlist is a client-side safety net only — it does
  **not** replace device-side authorization (see docs/IOS_SSH_PROPOSED_CONFIG.md).

Transport: netmiko is an optional extra (``pip install -e ".[collect]"``) and
is imported lazily inside :func:`default_connect`; the collector core and its
tests run without any SSH library installed (mock session factories).
"""

from __future__ import annotations

import ipaddress
import os
import time
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol

from nettwin.collect import ios_parsers as parsers
from nettwin.domain.models import (
    VRF,
    Device,
    Interface,
    Route,
    Topology,
)
from nettwin.errors import NetTwinError

# --------------------------------------------------------------------------- #
# Allowlist — the ONLY commands this collector may ever dispatch
# --------------------------------------------------------------------------- #

READ_ONLY_COMMANDS: frozenset[str] = frozenset(
    {
        "show version",
        "show ip interface brief",
        "show ip route",
        "show ip ospf neighbor",
        "show cdp neighbors",
        # Phase 2.3: the only source of a neighbour's management IP, which
        # recursive discovery needs to open the nested SSH session. Read-only,
        # like every other entry — no configuration, no state change.
        "show cdp neighbors detail",
        # Phase 2.6: OSPF operational state and LSDB. All read-only `show`
        # commands; `show ip ospf interface` (which can print authentication
        # material) is deliberately NOT here.
        "show ip ospf interface brief",
        "show ip ospf database",
        "show ip ospf database router",
        "show ip ospf database network",
        "show ip ospf route",
    }
)

#: Deterministic default execution order.
#: The Phase-2 order is preserved verbatim; ``show cdp neighbors detail`` is
#: appended so existing callers see the same first five commands.
DEFAULT_COMMANDS: tuple[str, ...] = (
    "show version",
    "show ip interface brief",
    "show ip route",
    "show ip ospf neighbor",
    "show cdp neighbors",
    "show cdp neighbors detail",
    # Phase 2.6 — appended, so the phase-2 order is unchanged.
    "show ip ospf interface brief",
    "show ip ospf database",
    "show ip ospf database router",
    "show ip ospf database network",
    "show ip ospf route",
)

#: Commands whose failure must never cost us the rest of a device's evidence.
#: A router with no OSPF configured answers these with an error, a timeout, or
#: nothing at all — that is a normal, expected condition, not a collection
#: failure. Phase-2 CDP/interface/route evidence is gathered either way.
OPTIONAL_COMMANDS: frozenset[str] = frozenset(
    {
        "show ip ospf neighbor",
        "show ip ospf interface brief",
        "show ip ospf database",
        "show ip ospf database router",
        "show ip ospf database network",
        "show ip ospf route",
    }
)

# Second hard layer: fragments that must never appear in any dispatched
# command even if the allowlist above were ever edited by mistake.
_FORBIDDEN_FRAGMENTS: tuple[str, ...] = (
    "configure",
    "conf t",
    "terminal",
    "write",
    "copy",
    "reload",
    "clear",
    "erase",
    "debug",
    "send",
    "setup",
    "enable",
    "password",
    "username",
    "login",
    "show running-config",
    "show startup-config",
)

_USERNAME_ENV = "NETTWIN_DEVICE_USERNAME"
_PASSWORD_ENV = "NETTWIN_DEVICE_PASSWORD"


# --------------------------------------------------------------------------- #
# Errors
# --------------------------------------------------------------------------- #


class CollectorError(NetTwinError):
    """Base class for collector failures."""


class AllowlistViolation(CollectorError):
    """A command outside the read-only allowlist was rejected pre-connection."""


class CollectorConfigError(CollectorError):
    """Missing/invalid collector configuration (e.g. credentials not set)."""


class CollectorConnectionError(CollectorError):
    """SSH connection could not be established or was lost."""

    def __init__(self, message: str, kind: str) -> None:
        super().__init__(message)
        self.kind = kind  # "auth" | "timeout" | "unreachable" | "protocol"


class SessionFactory(Protocol):
    """Anything able to open a session; lets tests inject a mock SSH client."""

    def __call__(
        self,
        *,
        host: str,
        username: str,
        password: str,
        port: int,
        timeout: int,
    ) -> Any: ...


class Session(Protocol):
    """Minimal session surface used by the collector (netmiko-compatible)."""

    def send_command(self, command: str, read_timeout: float | None = None) -> str: ...

    def disconnect(self) -> None: ...


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _sanitize(message: str, secrets: Sequence[str]) -> str:
    """Replace any known secret with a placeholder before a message escapes."""
    for secret in secrets:
        if secret:
            message = message.replace(secret, "***")
    return message


def _classify_connect_failure(exc: BaseException) -> str:
    name = type(exc).__name__
    if "Authentication" in name:
        return "auth"
    if "Timeout" in name or "TimeoutException" in name:
        return "timeout"
    return "unreachable"


def default_connect(
    *,
    host: str,
    username: str,
    password: str,
    port: int,
    timeout: int,
    ) -> Any:
    """Open a read-only cisco_ios session via netmiko (lazy import).

    Raises :class:`CollectorConnectionError` with a sanitized message so
    credentials never leak into logs or tracebacks surfaced to callers.
    """
    try:
        from netmiko import ConnectHandler  # noqa: PLC0415  (optional dependency)
    except ImportError as exc:  # pragma: no cover - exercised only without extra
        raise CollectorConfigError(
            "netmiko is not installed; install the optional extra first: "
            'pip install -e ".[collect]"'
        ) from exc
    try:
        return ConnectHandler(
            device_type="cisco_ios",
            host=host,
            username=username,
            password=password,
            port=port,
            conn_timeout=timeout,
        )
    except Exception as exc:  # netmiko raises a family of socket/auth errors
        kind = _classify_connect_failure(exc)
        safe = _sanitize(f"{kind} failure connecting to {host}: {exc}", [password])
        raise CollectorConnectionError(safe, kind) from None


def _validate_command(command: str) -> None:
    """Reject anything outside the allowlist BEFORE any connection happens."""
    normalized = " ".join(command.strip().lower().split())
    if normalized not in READ_ONLY_COMMANDS:
        raise AllowlistViolation(
            f"command not in read-only allowlist (rejected before connect): {command!r}"
        )
    for fragment in _FORBIDDEN_FRAGMENTS:
        if fragment in normalized:
            raise AllowlistViolation(
                f"command contains forbidden configuration/privilege fragment "
                f"{fragment!r} (rejected before connect): {command!r}"
            )


# --------------------------------------------------------------------------- #
# Observation records
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class CommandResult:
    """Per-command outcome; ``output`` holds the raw device text (evidence)."""

    command: str
    status: str  # "ok" | "error" | "timeout"
    output: str = ""
    error: str | None = None
    duration_s: float = 0.0


@dataclass
class DeviceObservations:
    """Raw + parsed observations for one collection run (JSON-serializable)."""

    host: str
    device_id: str | None
    collected_at: str
    status: str  # "ok" | "partial" | "failed"
    commands: list[CommandResult] = field(default_factory=list)
    identity: dict[str, str | None] = field(default_factory=dict)
    interfaces: list[dict[str, Any]] = field(default_factory=list)
    routes: list[dict[str, Any]] = field(default_factory=list)
    ospf_neighbors: list[dict[str, Any]] = field(default_factory=list)
    cdp_neighbors: list[dict[str, Any]] = field(default_factory=list)
    #: Phase 2.3: ``show cdp neighbors detail`` blocks — the only place a
    #: neighbour's management IP appears. Empty for a Phase-2 style run.
    cdp_neighbors_detail: list[dict[str, Any]] = field(default_factory=list)
    #: Phase 2.6 — OSPF operational state and LSDB. Kept flat and
    #: JSON-serializable like every other observation so a run stays replayable.
    ospf_interfaces: list[dict[str, Any]] = field(default_factory=list)
    ospf_database: list[dict[str, Any]] = field(default_factory=list)
    ospf_router_lsas: list[dict[str, Any]] = field(default_factory=list)
    ospf_network_lsas: list[dict[str, Any]] = field(default_factory=list)
    ospf_routes: list[dict[str, Any]] = field(default_factory=list)
    #: ``(process_id, router_id)`` from the OSPF output header.
    ospf_context: dict[str, str] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# --------------------------------------------------------------------------- #
# Collector
# --------------------------------------------------------------------------- #


class CiscoIOSCollector:
    """Collect a fixed set of read-only IOS commands over SSH.

    Usage::

        collector = CiscoIOSCollector("192.168.98.34")
        observations = collector.collect()          # allowlisted commands only
        topology, warnings = map_to_topology(observations)
    """

    def __init__(
        self,
        host: str,
        *,
        port: int = 22,
        username: str | None = None,
        password: str | None = None,
        connect_timeout: int = 15,
        command_timeout: int = 30,
        connect_factory: SessionFactory | None = None,
    ) -> None:
        if not host or not host.strip():
            raise CollectorConfigError("host must be a non-empty IP or hostname")
        self._host = host.strip()
        self._port = port
        self._username = username
        self._password = password
        self._connect_timeout = connect_timeout
        self._command_timeout = command_timeout
        self._factory: SessionFactory = connect_factory or default_connect

    # -- credentials -------------------------------------------------------- #

    def _resolve_credentials(self) -> tuple[str, str]:
        username = self._username if self._username is not None else os.environ.get(_USERNAME_ENV)
        password = self._password if self._password is not None else os.environ.get(_PASSWORD_ENV)
        if not username or not password:
            raise CollectorConfigError(
                "device credentials are not configured: set "
                f"{_USERNAME_ENV} and {_PASSWORD_ENV} environment variables "
                "(or pass username=/password= explicitly). Values are never logged."
            )
        return username, password

    # -- main entry --------------------------------------------------------- #

    def collect(self, commands: Sequence[str] | None = None) -> DeviceObservations:
        """Run the allowlisted commands and parse their outputs.

        The allowlist is enforced *before* credentials are resolved or any
        connection attempt is made, so a rejected command can never open a
        session.
        """
        requested = list(commands) if commands is not None else list(DEFAULT_COMMANDS)
        if not requested:
            raise AllowlistViolation("empty command list rejected (nothing to collect)")
        for command in requested:
            _validate_command(command)

        username, password = self._resolve_credentials()
        secrets = (password,)

        observations = DeviceObservations(
            host=self._host,
            device_id=None,
            collected_at=datetime.now(UTC).isoformat(timespec="seconds"),
            status="failed",
        )

        session: Any = None
        try:
            session = self._factory(
                host=self._host,
                username=username,
                password=password,
                port=self._port,
                timeout=self._connect_timeout,
            )
        except CollectorConnectionError as exc:
            # Re-raise through the sanitizer: a custom factory might embed
            # secrets in its message before handing the error to us.
            raise CollectorConnectionError(
                _sanitize(str(exc), secrets), exc.kind
            ) from None
        except Exception as exc:  # custom factories may raise plain errors
            kind = _classify_connect_failure(exc)
            safe = _sanitize(f"{kind} failure connecting to {self._host}: {exc}", secrets)
            raise CollectorConnectionError(safe, kind) from None

        try:
            for command in requested:
                started = time.monotonic()
                try:
                    raw = session.send_command(command, read_timeout=self._command_timeout)
                    observations.commands.append(
                        CommandResult(
                            command=command,
                            status="ok",
                            output=str(raw),
                            duration_s=round(time.monotonic() - started, 3),
                        )
                    )
                except Exception as exc:
                    name = type(exc).__name__
                    status = "timeout" if "Timeout" in name else "error"
                    safe_error = _sanitize(f"{name}: {exc}", secrets)
                    observations.commands.append(
                        CommandResult(
                            command=command,
                            status=status,
                            error=safe_error,
                            duration_s=round(time.monotonic() - started, 3),
                        )
                    )
        finally:
            try:
                session.disconnect()
            except Exception as exc:  # still report; session is done either way
                observations.warnings.append(
                    _sanitize(f"session disconnect raised: {type(exc).__name__}", secrets)
                )

        self._parse_into(observations)
        observations.status = self._overall_status(observations)
        return observations

    # -- parsing ------------------------------------------------------------ #

    def _output_of(self, observations: DeviceObservations, command: str) -> str | None:
        for result in observations.commands:
            if result.command == command and result.status == "ok":
                return result.output
        return None

    def _parse_into(self, observations: DeviceObservations) -> None:
        """Parse each successful command; parser crashes become warnings."""

        def run(command: str, fn: Callable[[str], Any]) -> Any | None:
            text = self._output_of(observations, command)
            if text is None:
                observations.warnings.append(f"{command}: not collected — section unavailable")
                return None
            try:
                parsed, warns = fn(text)
                observations.warnings.extend(warns)
                return parsed
            except Exception as exc:
                observations.warnings.append(
                    f"{command}: parser failed ({type(exc).__name__}) — section unavailable"
                )
                return None

        version = run("show version", parsers.parse_show_version)
        if version is not None:
            observations.identity = {
                "hostname": version.hostname,
                "ios_version": version.ios_version,
                "model": version.model,
            }
            if version.hostname:
                observations.device_id = version.hostname.lower()

        brief = run("show ip interface brief", parsers.parse_show_ip_interface_brief)
        if brief is not None:
            observations.interfaces = [asdict(item) for item in brief]

        routes = run("show ip route", parsers.parse_show_ip_route)
        if routes is not None:
            observations.routes = [asdict(item) for item in routes]

        ospf = run("show ip ospf neighbor", parsers.parse_show_ip_ospf_neighbor)
        if ospf is not None:
            observations.ospf_neighbors = [asdict(item) for item in ospf]

        cdp = run("show cdp neighbors", parsers.parse_show_cdp_neighbors)
        if cdp is not None:
            observations.cdp_neighbors = [asdict(item) for item in cdp]

        cdp_detail = run("show cdp neighbors detail", parsers.parse_show_cdp_neighbors_detail)
        if cdp_detail is not None:
            observations.cdp_neighbors_detail = [asdict(item) for item in cdp_detail]

    @staticmethod
    def _overall_status(observations: DeviceObservations) -> str:
        """Overall device status.

        A failed *optional* command (see :data:`OPTIONAL_COMMANDS`) does not
        make a device partial: a router with no OSPF configured answers those
        with an error, and its CDP/interface/route evidence is still complete.
        Those failures are recorded as warnings instead, so the reason is never
        hidden — only the status stays ``ok``.
        """
        if not observations.commands:
            return "failed"
        required = [c for c in observations.commands if c.command not in OPTIONAL_COMMANDS]
        optional = [c for c in observations.commands if c.command in OPTIONAL_COMMANDS]
        ok_required = sum(1 for c in required if c.status == "ok")
        ok_optional = sum(1 for c in optional if c.status == "ok")
        if not required:
            return "partial" if ok_optional else "failed"
        if ok_required == len(required) and ok_optional == len(optional):
            parser_failed = any("parser failed" in w for w in observations.warnings)
            return "partial" if parser_failed else "ok"
        if ok_required == len(required):
            # Every required section succeeded. Optional sections may be absent
            # for two very different reasons, and they are not the same thing:
            #
            #   * an *error* — the device ran the command and declined it. On a
            #     router with no OSPF configured that is the expected answer, so
            #     it is a warning and the device stays "ok".
            #   * a *timeout* — the device went quiet mid-collection. That is a
            #     genuine anomaly worth flagging, so the device stays "partial".
            for command in optional:
                if command.status == "ok":
                    continue
                observations.warnings.append(
                    f"{command.command}: optional section unavailable "
                    f"({command.status}) — device evidence is otherwise complete"
                )
                if command.status == "timeout":
                    return "partial"
            return "ok"
        return "partial" if ok_required else "failed"


# --------------------------------------------------------------------------- #
# Mapping: observations -> existing domain Topology (read-only, additive)
# --------------------------------------------------------------------------- #


def map_to_topology(observations: DeviceObservations) -> tuple[Topology, list[str]]:
    """Map collected observations onto the **existing** domain model.

    Deliberate limitations (documented, never silently ignored):

    * ``Route`` in the domain model holds a single ``next_hop`` — for ECMP
      entries *all* next hops stay preserved in ``observations.routes``; the
      model receives the first next hop plus a warning stating the gap.
    * OSPF adjacency and CDP/L2 relationships have no schema objects — they
      are recorded in observations only; **no adjacency is ever inferred**
      from IPs or interface names.
    * Route AD/metric are not part of ``Route`` — preserved in observations.

    Mapping is deterministic: identity, interfaces, connected/static/OSPF
    routes come only from collected output; nothing is synthesized.
    """
    warnings: list[str] = []

    device_id = observations.device_id
    if not device_id:
        raise CollectorError(
            "cannot map observations: device hostname unavailable "
            "(show version did not yield a hostname — not inventing an identity)"
        )
    hostname = device_id  # already lowercased at parse time

    # Index collected data -------------------------------------------------
    connected_prefix: dict[str, str] = {}
    for route in observations.routes:
        if route.get("protocol") == "connected":
            for hop in route.get("next_hops", []):
                iface = hop.get("outgoing_interface")
                if iface:
                    connected_prefix[iface] = route["prefix"]

    # Candidate interfaces for next-hop resolution: every interface that has a
    # collected connected prefix (``C … is directly connected, <iface>``).
    # Prefix lengths come from the routing table, which is the evidence that
    # makes "next hop belongs to this prefix" a fact rather than a guess.
    resolvable_prefixes: dict[str, ipaddress.IPv4Network] = {}
    for iface, prefix in connected_prefix.items():
        try:
            resolvable_prefixes[iface] = ipaddress.IPv4Network(prefix, strict=False)
        except ValueError:  # pragma: no cover - parser already validates shape
            warnings.append(
                f"interface {iface}: connected prefix {prefix!r} is not a valid IPv4 "
                "network — next-hop resolution unavailable for it"
            )

    def resolve_interface(next_hop: str | None) -> tuple[str | None, str]:
        """Resolve a next hop to its outgoing interface using connected prefixes.

        Returns ``(interface, note)``. ``interface`` is ``None`` unless exactly
        one collected connected prefix contains the next hop — an ambiguous or
        impossible match is never turned into a made-up interface.
        """
        if not next_hop:
            return None, "no next-hop address to resolve against connected prefixes"
        try:
            address = ipaddress.IPv4Address(next_hop)
        except ValueError:
            return None, f"next hop {next_hop!r} is not a valid IPv4 address"
        candidates = sorted(
            iface
            for iface, network in resolvable_prefixes.items()
            if address in network
        )
        if len(candidates) == 1:
            return (
                candidates[0],
                f"next hop {next_hop} resolved to {candidates[0]} via unique connected "
                f"prefix {connected_prefix[candidates[0]]}",
            )
        if not candidates:
            return None, (
                f"next hop {next_hop} does not belong to any collected connected prefix "
                "— outgoing interface stays unresolved (not invented)"
            )
        return None, (
            f"next hop {next_hop} belongs to {len(candidates)} collected connected "
            f"prefixes ({', '.join(candidates)}) — ambiguous, outgoing interface stays "
            "unresolved (not invented)"
        )

    # Interfaces ------------------------------------------------------------
    interfaces: list[Interface] = []
    interface_ids: list[str] = []
    for item in observations.interfaces:
        name = item["name"]
        iface_id = f"{device_id}-{name.lower()}"
        interface_ids.append(iface_id)
        ip = item.get("ip_address")
        addresses: list[str] = []
        if ip:
            prefix = connected_prefix.get(name)
            if prefix:
                addresses.append(f"{ip}/{prefix.split('/')[1]}")
            else:
                warnings.append(
                    f"interface {name}: connected prefix for {ip} not found in collected "
                    "routes — IP marked unavailable (kept in observations, not invented)"
                )
        interfaces.append(
            Interface(
                id=iface_id,
                device_id=device_id,
                name=name,
                vrf_id="GLOBAL",
                ipv4_addresses=addresses,
                admin_state=item["admin_state"],
                oper_state=item["oper_state"],
            )
        )
    if not interfaces:
        warnings.append("no interfaces collected — interface set unavailable")

    # Routes ----------------------------------------------------------------
    routes: list[Route] = []
    name_to_id = {item["name"]: f"{device_id}-{item['name'].lower()}" for item in observations.interfaces}
    for index, raw in enumerate(observations.routes):
        next_hops = raw.get("next_hops") or []
        first = next_hops[0] if next_hops else {}
        next_hop = first.get("next_hop")
        outgoing = first.get("outgoing_interface")
        resolved_from_prefix = False
        if not outgoing:
            # IOS omits the outgoing interface on some rows (a default route
            # rendered as ``S* 0.0.0.0/0 [1/0] via 192.168.98.62``). Resolve it
            # only when the next hop sits inside exactly one collected
            # connected prefix; otherwise keep the route without inventing.
            resolved, note = resolve_interface(next_hop)
            if resolved:
                outgoing = resolved
                resolved_from_prefix = True
            warnings.append(f"route {raw['prefix']}: {note}")
        outgoing_id: str | None = name_to_id.get(outgoing) if outgoing else None
        if not outgoing_id:
            warnings.append(
                f"route {raw['prefix']}: outgoing interface {outgoing!r} not present in "
                "collected interfaces — route preserved with no outgoing interface "
                "(not invented, not dropped)"
            )
        if resolved_from_prefix:
            warnings.append(
                f"route {raw['prefix']}: outgoing interface {outgoing} was not present in "
                "the IOS output — resolved from the unique collected connected prefix"
            )
        if len(next_hops) > 1:
            hop_list = ", ".join(
                f"{h.get('next_hop') or 'connected'}({h.get('outgoing_interface')})"
                for h in next_hops
            )
            warnings.append(
                f"route {raw['prefix']} has {len(next_hops)} next-hops (ECMP): {hop_list} — "
                "ALL preserved in observations; model Route keeps the first next-hop only "
                "(schema limitation, no model change made)"
            )
        routes.append(
            Route(
                id=f"{device_id}-r{index:02d}-{raw['prefix'].replace('/', '-').replace('.', '_')}",
                device_id=device_id,
                vrf_id="GLOBAL",
                destination_prefix=raw["prefix"],
                next_hop=next_hop,
                outgoing_interface_id=outgoing_id,
                protocol=raw["protocol"],
                active=True,  # entry was present in the device's active table
            )
        )

    # OSPF / CDP observations (never mapped to schema objects) --------------
    if observations.ospf_neighbors:
        warnings.append(
            f"{len(observations.ospf_neighbors)} OSPF neighbor row(s) observed — "
            "schema has no adjacency object; recorded in observations only "
            "(adjacency NEVER inferred from IPs)"
        )
    if observations.cdp_neighbors:
        warnings.append(
            f"{len(observations.cdp_neighbors)} CDP neighbor row(s) observed — "
            "schema has no L2-neighborhood object; recorded in observations only"
        )
    if any(raw.get("ad") is not None for raw in observations.routes):
        warnings.append(
            "route AD/metric values observed but not representable in Route schema — "
            "preserved in observations only"
        )

    management_address: str | None = None
    try:
        management_address = str(ipaddress.ip_address(observations.host))
    except ValueError:
        management_address = None  # hostname — kept out of the typed field

    metadata = {
        "ios_version": observations.identity.get("ios_version"),
        "model": observations.identity.get("model"),
        "collected_at": observations.collected_at,
        "collector": "nettwin.collect.cisco_ios",
        "source_host": observations.host,
    }
    device = Device(
        id=device_id,
        name=hostname,
        vendor="cisco",  # evidenced by the "Cisco IOS Software" line in show version
        platform=str(observations.identity.get("model") or "unknown"),
        management_address=management_address,
        metadata={k: v for k, v in metadata.items() if v is not None},
    )
    vrf = VRF(id="GLOBAL", name="default")
    # Constructor runs Topology.validate_references (duplicate ids + refs).
    topology = Topology(
        devices=[device],
        interfaces=interfaces,
        links=[],
        vrfs=[vrf],
        routes=routes,
        endpoints=[],
        services=[],
    )
    return topology, warnings
