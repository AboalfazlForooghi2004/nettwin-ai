"""Merge per-device topologies into one ``Topology`` (Phase 2.2, Task 2).

Every input is the output of ``cisco_ios.map_to_topology()`` for one device,
so each one already contains exactly one device. Merging therefore never has
to invent a device: it only concatenates and de-duplicates, and it refuses to
produce a result whose ids collide.

What is preserved verbatim: interfaces (with their device), routes (with their
device and VRF), interface addresses. What is merged: the ``GLOBAL`` VRF (one
copy, because every collected device uses the same routing table name).

Nothing here creates or removes evidence. Links are *not* produced by this
module — see :mod:`nettwin.collect.discovery.links`.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from nettwin.collect.cisco_ios import DeviceObservations
from nettwin.domain.models import (
    VRF,
    Device,
    Interface,
    Link,
    Route,
    Topology,
)


class MergeError(Exception):
    """Two collected devices produced colliding ids (identity is ambiguous)."""


@dataclass
class DeviceCollection:
    """One device's collection outcome, success or failure kept separate."""

    entry_name: str
    host: str
    observations: DeviceObservations | None = None
    topology: Topology | None = None
    warnings: list[str] = field(default_factory=list)
    error: str | None = None

    @property
    def succeeded(self) -> bool:
        return self.topology is not None

    @property
    def device_id(self) -> str | None:
        if self.topology and self.topology.devices:
            return self.topology.devices[0].id
        return None


@dataclass
class MergeResult:
    """A merged topology plus everything that could not be merged."""

    topology: Topology
    device_ids: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    failures: dict[str, str] = field(default_factory=dict)

    @property
    def links(self) -> list[Link]:
        return self.topology.links


def merge_device_topologies(collections: list[DeviceCollection]) -> MergeResult:
    """Concatenate successful per-device topologies into one ``Topology``.

    Raises:
        MergeError: If two collected devices report the same device id (the
            same physical device reached twice under different inventory
            names) or if any id collides across devices. Silently keeping one
            of them would drop collected evidence, so this is a hard error.
    """
    warnings: list[str] = []
    failures: dict[str, str] = {}

    devices: list[Device] = []
    interfaces: list[Interface] = []
    routes: list[Route] = []
    vrfs: dict[str, VRF] = {}
    device_ids: list[str] = []

    for collection in collections:
        if not collection.succeeded:
            failures[collection.entry_name] = collection.error or "collection failed"
            continue
        assert collection.topology is not None  # narrowed by succeeded

        if collection.warnings:
            warnings.extend(f"{collection.entry_name}: {w}" for w in collection.warnings)

        for device in collection.topology.devices:
            if device.id in device_ids:
                raise MergeError(
                    f"device id {device.id!r} was produced by more than one collected "
                    f"device (inventory entries: "
                    f"{', '.join(c.entry_name for c in collections if c.device_id == device.id)}) "
                    "— identity is ambiguous, refusing to merge"
                )
            device_ids.append(device.id)
            devices.append(device)

        interfaces.extend(collection.topology.interfaces)
        routes.extend(collection.topology.routes)

        for vrf in collection.topology.vrfs:
            existing = vrfs.get(vrf.id)
            if existing is None:
                vrfs[vrf.id] = vrf
            elif existing != vrf:
                warnings.append(
                    f"VRF {vrf.id!r} differs between collected devices "
                    f"({existing.name!r} vs {vrf.name!r}) — keeping the first definition"
                )

    merged = Topology(
        devices=devices,
        interfaces=interfaces,
        links=[],  # links are added only by CDP two-sided evidence
        vrfs=sorted(vrfs.values(), key=lambda v: v.id),
        routes=routes,
        endpoints=[],
        services=[],
    )
    _assert_no_duplicates(merged)
    return MergeResult(
        topology=merged,
        device_ids=device_ids,
        warnings=warnings,
        failures=failures,
    )


def _assert_no_duplicates(topology: Topology) -> None:
    """Belt-and-braces check on top of ``Topology.validate_references``."""
    for kind, items in (
        ("device", topology.devices),
        ("interface", topology.interfaces),
        ("route", topology.routes),
        ("link", topology.links),
        ("vrf", topology.vrfs),
    ):
        seen: set[str] = set()
        for item in items:
            if item.id in seen:
                raise MergeError(
                    f"duplicate {kind} id {item.id!r} after merge — "
                    "refusing to produce an ambiguous topology"
                )
            seen.add(item.id)
