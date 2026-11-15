"""End-to-end multi-device discovery orchestration (Phase 2.2, Task 1).

The SSH layer is injected so the whole pipeline runs offline in tests and
online on the operator machine with the *same* code path:

    inventory -> [CiscoIOSCollector per device] -> map_to_topology()
              -> merge_device_topologies() -> discover_links() -> Topology

Credentials are never touched here: ``CiscoIOSCollector`` reads
``NETTWIN_DEVICE_USERNAME`` / ``NETTWIN_DEVICE_PASSWORD`` itself.

A device that fails to collect is recorded in ``failures`` and the remaining
devices are still processed — one unreachable router must not destroy the
evidence gathered from the others.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime

from nettwin.collect.cisco_ios import (
    CiscoIOSCollector,
    CollectorError,
    DeviceObservations,
    map_to_topology,
)
from nettwin.collect.discovery.identity import normalize_device_key
from nettwin.collect.discovery.inventory import DeviceEntry, Inventory
from nettwin.collect.discovery.links import (
    LinkDiscoveryResult,
    collect_evidence,
    discover_links,
)
from nettwin.collect.discovery.merge import (
    DeviceCollection,
    MergeResult,
    merge_device_topologies,
)
from nettwin.domain.models import Topology

#: Signature of the per-device collector, injectable for offline tests.
CollectorFactory = Callable[[DeviceEntry], DeviceObservations]


def default_collector(entry: DeviceEntry) -> DeviceObservations:
    """Collect one device with the Phase-2.1 collector (allowlist unchanged)."""
    collector = CiscoIOSCollector(entry.host, port=entry.port)
    return collector.collect()


@dataclass
class DiscoveryReport:
    """Everything a topology discovery run produced, including what it did not."""

    topology: Topology | None
    collections: list[DeviceCollection] = field(default_factory=list)
    merge: MergeResult | None = None
    link_result: LinkDiscoveryResult | None = None
    failures: dict[str, str] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    collected_at: str = ""
    inventory_source: str | None = None

    @property
    def succeeded(self) -> bool:
        return self.topology is not None

    @property
    def device_ids(self) -> list[str]:
        return self.merge.device_ids if self.merge else []

    @property
    def link_provenance(self) -> dict[str, list[str]]:
        return self.link_result.provenance if self.link_result else {}


def discover_topology(
    inventory: Inventory,
    *,
    collect: CollectorFactory | None = None,
    collect_links: bool = True,
) -> DiscoveryReport:
    """Run collection, mapping, merging and CDP link discovery.

    Args:
        inventory: Validated inventory (see :func:`load_inventory`).
        collect: Optional per-device collector override (tests inject fixtures).
        collect_links: When false, merging still happens but no links are built.

    Returns:
        A :class:`DiscoveryReport`; ``topology`` is ``None`` only when *no*
        device could be collected at all.
    """
    collector = collect or default_collector
    report = DiscoveryReport(
        topology=None,
        collected_at=datetime.now(UTC).isoformat(timespec="seconds"),
        inventory_source=inventory.source,
    )

    collections: list[DeviceCollection] = []
    for entry in inventory:
        collection = DeviceCollection(entry_name=entry.name, host=entry.host)
        try:
            observations = collector(entry)
        except CollectorError as exc:
            collection.error = f"{type(exc).__name__}: {exc}"
            report.failures[entry.name] = collection.error
            collections.append(collection)
            continue
        except Exception as exc:  # noqa: BLE001 - never lose the other devices
            collection.error = f"unexpected {type(exc).__name__}: {exc}"
            report.failures[entry.name] = collection.error
            collections.append(collection)
            continue

        collection.observations = observations
        if observations.status == "failed":
            collection.error = (
                "collection failed: " + "; ".join(observations.warnings or ["unknown error"])
            )
            report.failures[entry.name] = collection.error
            collections.append(collection)
            continue
        try:
            topology, map_warnings = map_to_topology(observations)
        except CollectorError as exc:
            collection.error = f"mapping failed: {exc}"
            report.failures[entry.name] = collection.error
            collections.append(collection)
            continue
        collection.topology = topology
        collection.warnings.extend(map_warnings)
        collections.append(collection)

    report.collections = collections
    if not any(c.succeeded for c in collections):
        report.warnings.append(
            "no device could be collected — no topology produced "
            f"(failures: {', '.join(sorted(report.failures)) or 'none reported'})"
        )
        return report

    merge = merge_device_topologies(collections)
    report.merge = merge
    report.warnings.extend(merge.warnings)
    report.failures.update(merge.failures)

    topology = merge.topology
    if collect_links:
        rows_by_device: dict[str, list[dict]] = {}
        for collection in collections:
            if collection.succeeded and collection.observations is not None:
                device_id = collection.device_id
                if device_id:
                    rows_by_device[device_id] = collection.observations.cdp_neighbors
        evidence = collect_evidence(rows_by_device)
        link_result = discover_links(topology, evidence)
        report.link_result = link_result
        report.warnings.extend(link_result.warnings)
        topology = Topology(
            devices=topology.devices,
            interfaces=topology.interfaces,
            links=link_result.links,
            vrfs=topology.vrfs,
            routes=topology.routes,
            endpoints=topology.endpoints,
            services=topology.services,
        )

    report.topology = topology
    report.warnings.extend(_limitation_notes(topology, report))
    return report


def _limitation_notes(topology: Topology, report: DiscoveryReport) -> list[str]:
    """Honest, deterministic notes about what this run could not establish."""
    notes: list[str] = []
    if report.link_result is not None:
        created = len(report.link_result.links)
        notes.append(
            f"CDP link discovery: {created} link(s) built from two-sided evidence; "
            f"{len(report.link_result.warnings)} CDP row(s) did not produce a link "
            "(reasons recorded per row)"
        )
    devices_with_links = {
        iface_id
        for link in topology.links
        for iface_id in (link.source_interface_id, link.destination_interface_id)
    }
    unlinked = [
        i.name
        for i in topology.interfaces
        if i.id not in devices_with_links and not _is_loopback(i.name)
    ]
    if unlinked:
        notes.append(
            f"{len(unlinked)} interface(s) have no discovered link "
            "(no two-sided CDP evidence — never inferred from IP subnets or OSPF)"
        )
    if report.failures:
        notes.append(
            f"{len(report.failures)} device(s) failed to collect: "
            + ", ".join(sorted(report.failures))
            + " — their links cannot be confirmed from both sides"
        )
    return notes


def _is_loopback(name: str) -> bool:
    return name.lower().startswith("loopback")


def inventory_device_key(entry: DeviceEntry) -> str:
    """Stable key for an inventory entry (used for per-device output files)."""
    return normalize_device_key(entry.name)
