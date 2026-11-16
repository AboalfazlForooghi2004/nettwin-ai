"""Recursive multi-hop discovery (Phase 2.3, Tasks 2, 3 and 5).

Algorithm (breadth-first, which is also the natural SSH nesting order):

    queue = [seed]
    while queue and devices < max_devices:
        device = queue.pop(0)
        if device already visited or attempts exhausted: continue
        open session (root: workstation->device, nested: parent->device)
        run the read-only discovery commands
        parse ``show cdp neighbors detail``
        for each neighbour with an IP:
            record it as a node (collected / unreachable / limited)
            enqueue it with its discovery path
        close session (backtrack to the parent)
        if depth == max_depth: stop enqueuing children

Identity is the **normalized CDP Device ID**, not the IP: one device may
advertise several addresses, and the same device may be reached twice through
different paths. ``IpAliases`` records every address seen for an identity so a
re-visit can be short-circuited instead of re-collected.

Nothing is invented: a neighbour that cannot be reached stays in the topology
as a node with ``status="unreachable"`` and a reason.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING

from nettwin.collect import ios_parsers as parsers
from nettwin.collect.cisco_ios import (
    DEFAULT_COMMANDS,
    READ_ONLY_COMMANDS,
    CollectorError,
    DeviceObservations,
    map_to_topology,
)
from nettwin.collect.discovery.identity import (
    DeviceNameIndex,
    canonical_interface_display,
    normalize_device_key,
)
from nettwin.collect.nested.progress import DiscoveryObserver, NullProgress
from nettwin.collect.nested.prompts import failure_reason
from nettwin.collect.nested.session import (
    IosShellSession,
    NestedConnectError,
    SessionAuthError,
    SessionError,
    SessionLimits,
    SessionTimeoutError,
    Transport,
)
from nettwin.domain.models import Topology

if TYPE_CHECKING:  # pragma: no cover - typing only
    from nettwin.collect.discovery.links import LinkDiscoveryResult

#: Commands that are safe to run on any device, in discovery order.
#: ``DEFAULT_COMMANDS`` is the Phase-2 set; the detail command is what carries
#: the neighbour IPs. Both are inside the read-only allowlist.
DISCOVERY_COMMANDS: tuple[str, ...] = tuple(
    command for command in DEFAULT_COMMANDS if command in READ_ONLY_COMMANDS
)


class DeviceStatus(StrEnum):
    """How a discovered node ended up."""

    COLLECTED = "collected"
    UNREACHABLE = "unreachable"
    AUTH_FAILED = "auth_failed"
    TIMEOUT = "timeout"
    LIMIT_REACHED = "limit_reached"
    IDENTITY_CONFLICT = "identity_conflict"


@dataclass
class DiscoveredNode:
    """One device in the discovery tree."""

    identity: str                      # normalized CDP Device ID
    display_name: str                  # as reported by CDP
    status: DeviceStatus
    depth: int
    path: list[str] = field(default_factory=list)   # hosts/IPs root -> here
    ip_addresses: list[str] = field(default_factory=list)
    parent: str | None = None
    interfaces: list[str] = field(default_factory=list)
    platform: str = ""
    error: str | None = None
    attempts: int = 0
    observations: DeviceObservations | None = None
    topology: Topology | None = None

    @property
    def collected(self) -> bool:
        return self.status is DeviceStatus.COLLECTED and self.topology is not None


@dataclass
class DiscoveryEdge:
    """A CDP adjacency as seen from one side (not yet a confirmed Link)."""

    source: str                        # normalized identity of the reporting device
    target: str                        # normalized identity of the neighbour
    local_interface: str
    remote_interface: str
    #: The address this adjacency was dialled through (deterministic: the
    #: first address the neighbour advertised as its *entry* address).
    target_ip: str | None = None
    #: Every address the neighbour advertised in this block. Two routers may
    #: legitimately report different addresses for the same neighbour (one per
    #: link), so both are preserved here rather than collapsed into target_ip.
    target_ips: list[str] = field(default_factory=list)


@dataclass
class RecursiveDiscoveryResult:
    """Everything a recursive run produced."""

    nodes: list[DiscoveredNode] = field(default_factory=list)
    edges: list[DiscoveryEdge] = field(default_factory=list)
    topology: Topology | None = None
    #: Phase 2.5: the audit trail behind ``topology.links``.
    link_result: LinkDiscoveryResult | None = None
    warnings: list[str] = field(default_factory=list)
    visits: int = 0
    ssh_attempts: int = 0

    def node(self, identity: str) -> DiscoveredNode | None:
        key = normalize_device_key(identity)
        for node in self.nodes:
            if node.identity == key:
                return node
        return None

    @property
    def collected_nodes(self) -> list[DiscoveredNode]:
        return [n for n in self.nodes if n.collected]

    @property
    def failed_nodes(self) -> list[DiscoveredNode]:
        return [n for n in self.nodes if not n.collected]


#: Opens a session to the seed from the workstation.
RootSessionFactory = Callable[[str, str], IosShellSession]


class IpAliases:
    """Every IP seen for one device identity (Task 3)."""

    def __init__(self) -> None:
        self._by_identity: dict[str, list[str]] = {}
        self._owner: dict[str, str] = {}

    def add(self, identity: str, ip: str | None) -> None:
        if not ip:
            return
        bucket = self._by_identity.setdefault(identity, [])
        if ip not in bucket:
            bucket.append(ip)
        self._owner.setdefault(ip, identity)

    def of(self, identity: str) -> list[str]:
        return list(self._by_identity.get(identity, []))

    def identity_of_ip(self, ip: str) -> str | None:
        return self._owner.get(ip)

    def all_ips(self) -> set[str]:
        return set(self._owner)


class RecursiveDiscovery:
    """Breadth-first recursive discovery with explicit queues and limits."""

    def __init__(
        self,
        *,
        seed_host: str,
        username: str,
        password: str,
        limits: SessionLimits | None = None,
        root_factory: RootSessionFactory | None = None,
        nested_factory: Callable[..., Transport] | None = None,
        commands: Sequence[str] = DISCOVERY_COMMANDS,
        observer: DiscoveryObserver | None = None,
    ) -> None:
        self.seed_host = seed_host
        self._username = username
        self._password = password
        self.limits = limits or SessionLimits()
        if root_factory is None or nested_factory is None:
            raise ValueError(
                "recursive discovery needs explicit session factories: the nested "
                "SSH path is device-specific and must never be guessed"
            )
        self._root_factory = root_factory
        self._nested_factory = nested_factory
        for command in commands:
            if command not in READ_ONLY_COMMANDS:
                raise ValueError(f"refusing non-allowlisted discovery command: {command!r}")
        self._commands = tuple(commands)
        #: UI hooks. Purely observational: every call is a no-op by default
        #: and nothing in the walk reads back from it, so the algorithm's
        #: result is bit-identical with or without one.
        self._observer: DiscoveryObserver = observer or NullProgress()
        #: identity -> open session, so children are opened from a live parent.
        self._live_sessions: dict[str, IosShellSession] = {}
        self._last_session: IosShellSession | None = None
        #: every session ever opened, so teardown is exhaustive.
        self._all_sessions: list[IosShellSession] = []

    # -- main loop ---------------------------------------------------------- #

    def run(self) -> RecursiveDiscoveryResult:
        result = RecursiveDiscoveryResult()
        aliases = IpAliases()

        # Seed identity is the host until CDP or ``show version`` replaces it.
        seed_identity = normalize_device_key(self.seed_host)
        queue: deque[tuple[str, int, list[str], str | None]] = deque(
            [(seed_identity, 0, [self.seed_host], None)]
        )
        aliases.add(seed_identity, self.seed_host)
        self._observer.device_discovered(seed_identity, 0, [self.seed_host])

        visited: set[str] = set()
        nodes: dict[str, DiscoveredNode] = {}
        attempts: dict[str, int] = {}

        self._observer.discovery_started(
            self.seed_host, self.limits.max_depth, self.limits.max_devices
        )
        try:
            self._walk(queue, nodes, visited, attempts, aliases, result, seed_identity)
        finally:
            self.close_all()
            self._observer.discovery_finished()
        result.nodes = list(nodes.values())
        result.topology, link_warnings = _assemble_topology(result)
        result.warnings.extend(link_warnings)
        return result

    def _walk(self, queue, nodes, visited, attempts, aliases, result, seed_identity):
        while queue:
            identity, depth, path, parent = queue.popleft()
            if identity in visited:
                result.warnings.append(
                    f"cycle prevented: {identity!r} already discovered via "
                    f"{nodes[identity].path if identity in nodes else 'another path'}"
                )
                continue
            if len([n for n in nodes.values() if n.collected]) >= self.limits.max_devices:
                nodes[identity] = DiscoveredNode(
                    identity=identity,
                    display_name=identity,
                    status=DeviceStatus.LIMIT_REACHED,
                    depth=depth,
                    path=path,
                    parent=parent,
                    error=f"max_devices={self.limits.max_devices} reached",
                )
                result.warnings.append(
                    f"device limit reached: {identity!r} discovered but not collected"
                )
                continue

            attempts[identity] = attempts.get(identity, 0) + 1
            if attempts[identity] > self.limits.max_attempts_per_device:
                continue
            visited.add(identity)
            result.visits += 1

            node = DiscoveredNode(
                identity=identity,
                display_name=(nodes[identity].display_name if identity in nodes else identity),
                status=DeviceStatus.UNREACHABLE,
                depth=depth,
                path=path,
                parent=parent,
                attempts=attempts[identity],
            )
            self._last_session = None
            try:
                self._visit(node, aliases, result)
                self._observer.device_finished(node.identity, True)
            except NestedConnectError as exc:
                node.status = _status_for_kind(exc.kind)
                node.error = str(exc)
                # The seed is reached directly, not through a nested ssh, so
                # name the failing hop accurately.
                hop = "connect" if node.depth == 0 else "nested ssh"
                result.warnings.append(f"{identity}: {hop} failed ({exc.kind}): {exc}")
                self._observer.device_finished(identity, False, f"{hop} failed ({exc.kind})")
            except SessionAuthError as exc:
                node.status = DeviceStatus.AUTH_FAILED
                node.error = str(exc)
                result.warnings.append(f"{identity}: authentication failed: {exc}")
                self._observer.device_finished(identity, False, "authentication failed")
            except SessionTimeoutError as exc:
                node.status = DeviceStatus.TIMEOUT
                node.error = str(exc)
                result.warnings.append(f"{identity}: session timeout: {exc}")
                self._observer.device_finished(identity, False, "timeout")
            except SessionError as exc:
                node.status = DeviceStatus.UNREACHABLE
                node.error = str(exc)
                result.warnings.append(f"{identity}: session error: {exc}")
                self._observer.device_finished(identity, False, "session error")
            except CollectorError as exc:
                node.status = DeviceStatus.UNREACHABLE
                node.error = str(exc)
                result.warnings.append(f"{identity}: collection error: {exc}")
                self._observer.device_finished(identity, False, "collection error")
            except Exception as exc:  # noqa: BLE001 - one bad hop must not stop the walk
                node.status = DeviceStatus.UNREACHABLE
                node.error = f"{type(exc).__name__}: {exc}"
                result.warnings.append(
                    f"{identity}: unexpected {type(exc).__name__}: {exc} "
                    "(discovery continues with the other neighbours)"
                )

            # Identity is the device's own name when it reveals one, not the IP
            # we happened to dial (Task 3: IP is never the identifier).
            if node.collected and node.observations is not None:
                real_identity = normalize_device_key(
                    str(node.observations.device_id or "")
                )
                if real_identity and real_identity != node.identity:
                    if real_identity in nodes and nodes[real_identity] is not node:
                        node.status = DeviceStatus.IDENTITY_CONFLICT
                        node.error = (
                            f"device at {node.path[-1]} reports hostname "
                            f"{real_identity!r}, already discovered via another path"
                        )
                        result.warnings.append(node.error)
                    else:
                        previous = node.identity
                        visited.add(real_identity)
                        aliases.add(real_identity, node.path[-1])
                        node.identity = real_identity
                        identity = real_identity
                        # The live session was registered under the dialled
                        # identity; children look it up by the real one.
                        if previous in self._live_sessions:
                            self._live_sessions[real_identity] = self._live_sessions.pop(previous)

            if node.collected and self._last_session is not None:
                self._live_sessions[node.identity] = self._last_session
                self._last_session = None
            if node.depth > 0 and node.parent:
                # IOS allows one nested ssh per session: the parent's session is
                # now occupied by this child, so the next sibling must re-open.
                self._live_sessions.pop(node.parent, None)

            # DEFECT 1 FIX: a collected device's hostname frequently differs
            # from the CDP Device ID it was discovered under ("R2-3" vs
            # "R2-3.nettwin.lab"). The node is re-keyed to the real hostname
            # above, while an earlier sighting may already sit in ``nodes``
            # under the CDP name -- typically an unreachable "<no-ip>"
            # placeholder. Left alone, that placeholder survives as a SECOND
            # node for one physical device, and it is the one that gets
            # reported. Merge it away and register both spellings.
            self._name_index = getattr(self, "_name_index", DeviceNameIndex())
            for stale_key, stale_node in list(nodes.items()):
                if stale_key == identity:
                    continue
                # The index resolves a bare hostname to a collected FQDN (and
                # refuses when two devices would match), so it is the authority
                # on "is this the same box?" -- never a suffix guess.
                resolved_stale, _ = self._name_index.resolve(stale_key)
                same_device = (
                    stale_node is node
                    or normalize_device_key(stale_key) == normalize_device_key(identity)
                    or resolved_stale == identity
                )
                if not same_device:
                    continue
                if stale_node is not node and not stale_node.collected:
                    nodes.pop(stale_key, None)
                    result.warnings.append(
                        f"{stale_key!r} and {identity!r} are the same device "
                        f"(merged, kept path {node.path})"
                    )
                self._name_index.add(identity, stale_key)
            nodes[identity] = node
            if not node.collected:
                continue

            # enqueue children
            if depth >= self.limits.max_depth:
                if node.observations and node.observations.cdp_neighbors_detail:
                    result.warnings.append(
                        f"depth limit reached at {identity!r} "
                        f"(max_depth={self.limits.max_depth}) — neighbours not visited"
                    )
                continue

            detail_rows = node.observations.cdp_neighbors_detail if node.observations else []
            # A device can appear in more than one block (one per link, or a
            # short vs FQDN spelling). Only the FIRST sighting creates and
            # dials the node, so address-bearing blocks must come first --
            # otherwise an address-less block wins and the device is parked as
            # an unreachable "<no-ip>" even though its address was advertised
            # in the very same response.
            detail_rows = sorted(
                detail_rows,
                key=lambda row: 0 if (row.get("ip_addresses") or []) else 1,
            )
            if not hasattr(self, "_name_index"):
                self._name_index = DeviceNameIndex()
            for discovered in nodes.values():
                self._name_index.add(discovered.identity, discovered.display_name, discovered.identity)
            self._name_index.add(node.identity, node.display_name, node.identity)
            for detail in detail_rows:
                # Observations store dicts (asdict), not dataclasses.
                device_id = str(detail.get("device_id") or "")
                if not device_id:
                    continue
                # Resolve through the alias index so an FQDN and a bare
                # hostname are the same device (Task 3), never two nodes.
                resolved, resolve_note = self._name_index.resolve(device_id)
                child_identity = resolved or normalize_device_key(device_id)
                if resolved:
                    self._name_index.add(resolved, device_id)
                advertised = [str(ip) for ip in (detail.get("ip_addresses") or []) if ip]
                entry_ips = [str(ip) for ip in (detail.get("entry_addresses") or []) if ip]
                management_ips = [
                    str(ip) for ip in (detail.get("management_addresses") or []) if ip
                ]
                child_ip = self._pick_ip(
                    advertised, aliases, entry_addresses=entry_ips
                )
                # Every advertised address belongs to this one device: register
                # them all so a later mention of either address resolves to the
                # same identity (Task 3) and never creates a second node.
                for address in [*entry_ips, *management_ips, *advertised]:
                    aliases.add(child_identity, address)
                result.edges.append(
                    DiscoveryEdge(
                        source=identity,
                        target=child_identity,
                        local_interface=canonical_interface_display(
                            str(detail.get("local_interface") or "")
                        ),
                        remote_interface=canonical_interface_display(
                            str(detail.get("remote_interface") or "")
                        ),
                        target_ip=child_ip,
                        target_ips=advertised,
                    )
                )
                existing = nodes.get(child_identity)
                if existing is None:
                    # The same device may already be known under its other
                    # spelling ("R2-3" vs "R2-3.nettwin.lab"). Without this,
                    # a second node is created for one physical box -- which is
                    # how an unreachable "<no-ip>" duplicate came to be
                    # reported alongside a perfectly reachable node.
                    for other_key, other_node in nodes.items():
                        if other_key == child_identity:
                            continue
                        resolved_other, _ = self._name_index.resolve(other_key)
                        if (
                            normalize_device_key(other_key) == child_identity
                            or resolved_other == child_identity
                            or normalize_device_key(child_identity)
                            == normalize_device_key(other_key.split(".")[0])
                        ):
                            existing = other_node
                            child_identity = other_key
                            break
                if existing is not None:
                    # DEFECT 2 FIX: never discard a better path. A node first
                    # created without an address (or with a worse one) must be
                    # upgraded when a later block advertises a usable address,
                    # otherwise "<no-ip>" sticks forever even though the device
                    # plainly advertises 10.0.x.y.
                    self._upgrade_placeholder(existing, child_ip, path)
                    continue
                if child_ip is None:
                    nodes[child_identity] = DiscoveredNode(
                        identity=child_identity,
                        display_name=device_id,
                        status=DeviceStatus.UNREACHABLE,
                        depth=depth + 1,
                        path=[*path, "<no-ip>"],
                        parent=identity,
                        platform=str(detail.get("platform") or ""),
                        error=(
                            "neighbour advertises no IP address — cannot open a nested "
                            "session (never guessed)"
                        ),
                    )
                    self._name_index.add(child_identity, device_id, child_identity)
                    self._observer.device_discovered(child_identity, depth + 1, nodes[child_identity].path)
                    result.warnings.append(
                        f"{device_id}: no IP in CDP detail — not visited"
                    )
                    continue
                if child_ip in aliases.all_ips() and node_by_ip(nodes, child_ip):
                    continue
                # Teach the index about this brand-new node immediately: a
                # later block in the very same response may spell the device
                # differently ("R2-3.nettwin.lab" vs "R2-3") and must resolve
                # to this node instead of creating a second one.
                self._name_index.add(child_identity, device_id, child_identity)
                self._observer.device_discovered(
                    child_identity, depth + 1, [*path, child_ip]
                )
                queue.append((child_identity, depth + 1, [*path, child_ip], identity))

    @staticmethod
    def _upgrade_placeholder(
        node: DiscoveredNode, child_ip: str | None, parent_path: list[str]
    ) -> None:
        """Give an address-less placeholder node a real, advertised address.

        A neighbour can be seen twice: once by a block that carried no usable
        address (creating ``path=[..., "<no-ip>"]``) and once by a block that
        advertised one. Before this fix the second sighting was dropped by
        ``if existing is not None: continue``, so the placeholder stayed
        unreachable forever even though the address was right there.

        Only nodes that have NOT been collected are upgraded, and only with an
        address that was actually advertised -- nothing is guessed.
        """
        if node.collected or child_ip is None:
            return
        if "<no-ip>" not in node.path:
            return
        node.path = [*parent_path, child_ip]
        node.status = DeviceStatus.UNREACHABLE
        node.error = ""

    # -- one device --------------------------------------------------------- #

    def _visit(
        self, node: DiscoveredNode, aliases: IpAliases, result: RecursiveDiscoveryResult
    ) -> None:
        """Collect one device, opening it from the live parent when nested.

        IOS permits one nested ``ssh`` at a time per session, so the parent is
        kept **open** and the child is opened from it directly. That is exactly
        what an operator does, and it means backtracking is a single ``exit``
        rather than re-authenticating the whole chain.
        """
        via = "connecting to seed" if node.depth == 0 else "nested ssh"
        self._observer.device_started(node.identity, node.depth, node.path, via)
        session: IosShellSession
        if node.depth == 0:
            session = self._root_factory(node.path[-1], self._password)
            self._all_sessions.append(session)
        else:
            parent_session = self._live_sessions.get(_parent_key(node) or "")
            if parent_session is None:
                # The parent's session was consumed by an earlier child (IOS
                # allows one nested ssh per session). Re-open the chain from
                # the root, exactly as an operator would.
                parent_session = self._reopen_chain(node, result)
            result.ssh_attempts += 1
            session = parent_session.open_nested(
                neighbour_ip=node.path[-1],
                username=self._username,
                password=self._password,
                transport_factory=self._nested_factory,
            )
            self._all_sessions.append(session)

        session.open()
        try:
            collected: dict[str, str] = {}
            for command in self._commands:
                self._observer.command_started(node.identity, command)
                collected[command] = session.run_command(command)
            observations = self._observations_from(node, session, collected)
        except Exception:
            session.close()
            raise

        node.observations = observations
        node.status = DeviceStatus.COLLECTED
        node.interfaces = [item["name"] for item in observations.interfaces]
        if observations.identity.get("hostname"):
            node.display_name = str(observations.identity["hostname"])
        topology, _warnings = map_to_topology(observations)
        node.topology = topology
        for address in _interface_ips(observations):
            aliases.add(node.identity, address)
        # Hand the session back; the walk registers it under the device's FINAL
        # identity (which ``show version`` may have just revealed).
        self._last_session = session

    def _reopen_chain(
        self, node: DiscoveredNode, result: RecursiveDiscoveryResult
    ) -> IosShellSession:
        """Re-open root -> ... -> parent so a second child can be reached."""
        hops = node.path[1:-1]  # intermediate hops (exclude root, exclude target)
        session = self._root_factory(node.path[0], self._password)
        session.open()
        self._all_sessions.append(session)
        current = session
        for hop in hops:
            result.ssh_attempts += 1
            current = current.open_nested(
                neighbour_ip=hop,
                username=self._username,
                password=self._password,
                transport_factory=self._nested_factory,
            )
            self._all_sessions.append(current)
            current.open()
        return current

    def close_all(self) -> None:
        """Close every session ever opened, deepest first (explicit backtracking)."""
        unique: dict[int, IosShellSession] = {}
        for session in [*self._all_sessions, *self._live_sessions.values()]:
            unique[id(session)] = session
        for session in sorted(unique.values(), key=lambda s: -s.depth):
            try:
                session.close()
            except Exception:  # noqa: BLE001
                pass
        self._live_sessions.clear()
        self._all_sessions.clear()

    def _observations_from(
        self, node: DiscoveredNode, session: IosShellSession, collected: dict[str, str]
    ) -> DeviceObservations:
        observations = DeviceObservations(
            host=node.path[-1],
            device_id=None,
            collected_at="",
            status="ok",
        )
        parsed: dict[str, object] = {}
        for command, text in collected.items():
            parser = _PARSERS.get(command)
            if parser is None:
                continue
            value, warns = parser(text)  # type: ignore[operator]
            parsed[command] = value
            observations.warnings.extend(warns)

        version = parsed.get("show version")
        if isinstance(version, parsers.ParsedVersion):
            observations.identity = {
                "hostname": version.hostname,
                "ios_version": version.ios_version,
                "model": version.model,
            }
            if version.hostname:
                observations.device_id = version.hostname.lower()

        brief = parsed.get("show ip interface brief")
        if isinstance(brief, list):
            from dataclasses import asdict

            observations.interfaces = [asdict(item) for item in brief]
        routes = parsed.get("show ip route")
        if isinstance(routes, list):
            from dataclasses import asdict

            observations.routes = [asdict(item) for item in routes]
        ospf = parsed.get("show ip ospf neighbor")
        if isinstance(ospf, list):
            from dataclasses import asdict

            observations.ospf_neighbors = [asdict(item) for item in ospf]
        cdp = parsed.get("show cdp neighbors")
        if isinstance(cdp, list):
            from dataclasses import asdict

            observations.cdp_neighbors = [asdict(item) for item in cdp]
        detail = parsed.get("show cdp neighbors detail")
        if isinstance(detail, list):
            from dataclasses import asdict

            observations.cdp_neighbors_detail = [asdict(item) for item in detail]

        if not observations.device_id:
            observations.status = "partial"
            observations.warnings.append(
                "show version: hostname unavailable — device identity not established"
            )
        return observations

    @staticmethod
    def _pick_ip(
        addresses: Sequence[str],
        aliases: IpAliases,
        *,
        entry_addresses: Sequence[str] = (),
    ) -> str | None:
        """Choose the neighbour address to dial, deterministically.

        Preference order, and never a guess:

        1. the first ``Entry address(es)`` value — the address the neighbour
           declared for this adjacency, which is the one it answers on;
        2. otherwise the first ``Management address(es)`` value;
        3. otherwise the first advertised address at all.

        ``aliases`` is consulted only for a tie-break-free deterministic scan;
        no address is ever synthesised from a name or a subnet.
        """
        for candidate in (entry_addresses, addresses):
            for address in candidate:
                if address:
                    return address
        return None


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

_PARSERS = {
    "show version": parsers.parse_show_version,
    "show ip interface brief": parsers.parse_show_ip_interface_brief,
    "show ip route": parsers.parse_show_ip_route,
    "show ip ospf neighbor": parsers.parse_show_ip_ospf_neighbor,
    "show cdp neighbors": parsers.parse_show_cdp_neighbors,
    "show cdp neighbors detail": parsers.parse_show_cdp_neighbors_detail,
}


def _status_for_kind(kind: str) -> DeviceStatus:
    if kind == "auth":
        return DeviceStatus.AUTH_FAILED
    if kind == "timeout":
        return DeviceStatus.TIMEOUT
    return DeviceStatus.UNREACHABLE


def _interface_ips(observations: DeviceObservations) -> list[str]:
    return [
        str(item.get("ip_address"))
        for item in observations.interfaces
        if item.get("ip_address")
    ]


def _parent_key(node: DiscoveredNode) -> str | None:
    """Identity of the node's parent in the walk (None for the seed)."""
    return node.parent


def node_by_ip(nodes: dict[str, DiscoveredNode], ip: str) -> DiscoveredNode | None:
    for node in nodes.values():
        if ip in node.path:
            return node
    return None


def _assemble_topology(
    result: RecursiveDiscoveryResult,
) -> tuple[Topology | None, list[str]]:
    """Merge every collected device topology, then normalize links.

    Phase 2.5 wires in the link stage the recursive path previously skipped:
    ``discover_links`` is the same strict, two-sided matcher the non-recursive
    pipeline already used, so no new link logic is introduced here. Links are
    built **only** from CDP evidence collected on both sides; every row that
    does not satisfy the four-way agreement is reported, never bumped into a
    link.

    Returns the merged topology and the warnings to surface on the run report.
    """
    from nettwin.collect.discovery.links import collect_evidence, discover_links
    from nettwin.collect.discovery.merge import (
        DeviceCollection,
        merge_device_topologies,
    )

    collections = [
        DeviceCollection(
            entry_name=node.display_name,
            host=node.path[-1],
            observations=node.observations,
            topology=node.topology,
        )
        for node in result.collected_nodes
        if node.topology is not None
    ]
    if not collections:
        return None, []
    merge = merge_device_topologies(collections)
    topology = merge.topology
    warnings: list[str] = [f"merge: {w}" for w in merge.warnings]

    # --- Link normalization ------------------------------------------------
    rows_by_device: dict[str, list[dict]] = {}
    for collection in collections:
        device_id = collection.device_id
        observations = collection.observations
        if device_id and observations is not None:
            rows = list(observations.cdp_neighbors)
            # ``show cdp neighbors detail`` is the only place a neighbour's
            # management address appears; rows carrying it are preferred as
            # evidence but only the summary rows carry both interface names.
            if rows:
                rows_by_device[device_id] = rows
    evidence = collect_evidence(rows_by_device)
    link_result = discover_links(topology, evidence)

    result.link_result = link_result
    warnings.extend(f"links: {w}" for w in link_result.warnings)

    built = len(link_result.links)
    total_rows = sum(len(rows) for rows in rows_by_device.values())
    if total_rows == 0:
        warnings.append(
            "links: no CDP neighbour rows were collected on any device — "
            "no link can be confirmed (none invented)"
        )
    else:
        warnings.append(
            f"links: {built} link(s) confirmed from two-sided CDP evidence; "
            f"{len(link_result.candidates)} one-sided row(s) did not confirm"
        )

    connected = Topology(
        devices=topology.devices,
        interfaces=topology.interfaces,
        links=link_result.links,
        vrfs=topology.vrfs,
        routes=topology.routes,
        endpoints=topology.endpoints,
        services=topology.services,
    )
    return connected, warnings



def failure_summary(text: str) -> str:
    """Human-readable reason extracted from device output (never a secret)."""
    return failure_reason(text) or text.strip()[:200]
