"""Multi-device topology discovery (Phase 2.2).

Layers, deliberately separated so each rule is testable without SSH:

``inventory``
    Load + validate an inventory YAML (device name / host / platform only —
    credentials always come from the environment, never from the file).

``identity``
    Normalize device and interface names to canonical keys. Normalization is
    *reversible* and *exact*: it never substring-matches, and a normalization
    that maps two distinct collected devices onto one key is reported as
    ambiguous instead of picking a winner.

``merge``
    Combine per-device ``map_to_topology()`` results into one ``Topology``
    without inventing or dropping anything (ids stay unique, routes stay on
    their own device).

``links``
    Build ``Link`` objects **only** from mutually consistent two-sided CDP
    evidence. One-sided CDP, OSPF adjacency, and IP-subnet similarity are
    never sufficient (see ``EvidenceRule``).

Nothing in this package touches the domain schema, the diagnostic engine, the
graph, or the simulation engine — it only produces objects that already exist
in ``nettwin.domain.models``.
"""

from __future__ import annotations

from nettwin.collect.discovery.identity import (
    DeviceNameIndex,
    InterfaceNameIndex,
    normalize_device_key,
    normalize_interface_key,
)
from nettwin.collect.discovery.inventory import (
    DeviceEntry,
    Inventory,
    InventoryError,
    load_inventory,
)
from nettwin.collect.discovery.links import (
    CdpEvidence,
    LinkDiscoveryResult,
    build_link_id,
    discover_links,
)
from nettwin.collect.discovery.merge import (
    DeviceCollection,
    MergeResult,
    merge_device_topologies,
)

__all__ = [
    "CdpEvidence",
    "DeviceCollection",
    "DeviceEntry",
    "DeviceNameIndex",
    "InterfaceNameIndex",
    "Inventory",
    "InventoryError",
    "LinkDiscoveryResult",
    "MergeResult",
    "build_link_id",
    "discover_links",
    "load_inventory",
    "merge_device_topologies",
    "normalize_device_key",
    "normalize_interface_key",
]
