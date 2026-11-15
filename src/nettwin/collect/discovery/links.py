"""CDP-based link discovery (Phase 2.2, Tasks 3 and 6).

A ``Link`` is created only when **both** devices in a merged topology report a
CDP row that agrees with the other side:

    R2-1: local Ethernet0/0  ->  R2-2.nettwin.lab  remote Ethernet0/1
    R2-2: local Ethernet0/1  ->  R2-1.nettwin.lab  remote Ethernet0/0

Agreement means all four of these hold:

1. both device names resolve to collected, distinct devices (Task 4);
2. both interface names resolve to interfaces that exist on those devices
   (Task 5, with the device's *own* names, never another device's);
3. R2-1's remote-interface claim equals R2-2's local interface;
4. R2-2's remote-interface claim equals R2-1's local interface.

Anything less is recorded as a warning and produces no link. In particular
this module never consults OSPF adjacency, IP subnets, or the presence of a
management address — those are not L2 evidence (Task 6).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from nettwin.collect.discovery.identity import (
    DeviceNameIndex,
    InterfaceNameIndex,
    canonical_interface_display,
    interface_is_subinterface,
    interface_parent_key,
    normalize_interface_key,
)
from nettwin.domain.models import Link, LinkState, Topology

#: CDP rows whose local interface is a *sub*-interface cannot establish an L2
#: link (CDP reports the physical parent); such rows are skipped explicitly.
_SUBINTERFACE_NOTE = (
    "local interface is a sub-interface — CDP reports physical ports; "
    "no link derived from it"
)


class EvidenceRule(StrEnum):
    """Why a link was or was not created (kept in the discovery report)."""

    BOTH_SIDES_AGREE = "both_sides_agree"
    ONE_SIDED_ONLY = "one_sided_only"
    REMOTE_DEVICE_NOT_COLLECTED = "remote_device_not_collected"
    AMBIGUOUS_DEVICE_NAME = "ambiguous_device_name"
    LOCAL_INTERFACE_UNKNOWN = "local_interface_unknown"
    REMOTE_INTERFACE_UNKNOWN = "remote_interface_unknown"
    AMBIGUOUS_INTERFACE_NAME = "ambiguous_interface_name"
    INCONSISTENT_SIDES = "inconsistent_sides"
    SELF_REFERENCE = "self_reference"
    SUBINTERFACE = "subinterface"


@dataclass(frozen=True)
class CdpEvidence:
    """One CDP row, already attributed to a collected device."""

    device_id: str
    local_interface_name: str
    remote_device_name: str
    remote_interface_name: str
    platform: str = ""

    def describe(self) -> str:
        return (
            f"{self.device_id}: {self.local_interface_name} -> "
            f"{self.remote_device_name}:{self.remote_interface_name}"
        )


@dataclass
class _EvidenceIndex:
    """Index CDP rows by (device, local interface key) for cross-matching."""

    by_device_and_local: dict[tuple[str, str], list[CdpEvidence]] = field(
        default_factory=dict
    )

    def add(self, evidence: CdpEvidence) -> None:
        key = (evidence.device_id, normalize_interface_key(evidence.local_interface_name))
        self.by_device_and_local.setdefault(key, []).append(evidence)

    def rows_for(self, device_id: str, interface_key: str) -> list[CdpEvidence]:
        return self.by_device_and_local.get((device_id, interface_key), [])


@dataclass
class LinkCandidate:
    """A rejected or accepted match, with the reason, for the report."""

    rule: EvidenceRule
    detail: str
    link: Link | None = None


@dataclass
class LinkDiscoveryResult:
    """Links plus the full audit trail of every CDP row considered."""

    links: list[Link] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    candidates: list[LinkCandidate] = field(default_factory=list)
    provenance: dict[str, list[str]] = field(default_factory=dict)
    matched_rows: int = 0


def build_link_id(interface_id_a: str, interface_id_b: str) -> str:
    """Deterministic, order-independent link id (``a--b`` with ``a <= b``)."""
    first, second = sorted((interface_id_a, interface_id_b))
    return f"{first}--{second}"


def _interface_index_for(topology: Topology, device_id: str) -> InterfaceNameIndex:
    return InterfaceNameIndex.from_interfaces(
        [(i.id, i.name) for i in topology.interfaces if i.device_id == device_id]
    )


def _device_name_index(topology: Topology) -> DeviceNameIndex:
    index = DeviceNameIndex()
    for device in topology.devices:
        index.add(device.id, device.name, device.id)
    return index


def collect_evidence(
    cdp_rows_by_device: dict[str, list[dict]],
) -> list[CdpEvidence]:
    """Convert ``observations.cdp_neighbors`` rows into attributed evidence."""
    evidence: list[CdpEvidence] = []
    for device_id, rows in cdp_rows_by_device.items():
        for row in rows:
            local = row.get("local_interface") or ""
            remote_iface = row.get("port_id") or ""
            remote_device = row.get("device_id") or ""
            if not (local and remote_iface and remote_device):
                continue
            evidence.append(
                CdpEvidence(
                    device_id=device_id,
                    local_interface_name=local,
                    remote_device_name=remote_device,
                    remote_interface_name=remote_iface,
                    platform=row.get("platform", "") or "",
                )
            )
    return evidence


def discover_links(topology: Topology, evidence: list[CdpEvidence]) -> LinkDiscoveryResult:
    """Create links only where two-sided CDP evidence agrees exactly."""
    result = LinkDiscoveryResult()
    if not topology.devices:
        result.warnings.append("link discovery skipped: topology has no devices")
        return result

    device_index = _device_name_index(topology)
    interface_indexes = {
        device.id: _interface_index_for(topology, device.id) for device in topology.devices
    }
    index = _EvidenceIndex()
    for item in evidence:
        index.add(item)

    seen_pairs: set[tuple[str, str]] = set()
    for item in evidence:
        outcome = _evaluate(item, topology, device_index, interface_indexes, index)
        result.candidates.append(outcome)
        if outcome.link is None:
            if outcome.rule is not EvidenceRule.BOTH_SIDES_AGREE:
                result.warnings.append(f"no link from {item.describe()}: {outcome.detail}")
            continue

        pair = tuple(sorted((outcome.link.source_interface_id, outcome.link.destination_interface_id)))
        if pair in seen_pairs:
            # The same physical link observed from a duplicate CDP row: keep one.
            result.candidates[-1] = LinkCandidate(
                rule=EvidenceRule.BOTH_SIDES_AGREE,
                detail=f"{outcome.detail}; duplicate of already-discovered link {outcome.link.id}",
                link=None,
            )
            continue
        seen_pairs.add(pair)
        result.links.append(outcome.link)
        result.provenance.setdefault(outcome.link.id, []).append(outcome.detail)
        result.matched_rows += 2  # both sides were consumed

    result.links.sort(key=lambda link: link.id)
    return result


def _evaluate(
    item: CdpEvidence,
    topology: Topology,
    device_index: DeviceNameIndex,
    interface_indexes: dict[str, InterfaceNameIndex],
    index: _EvidenceIndex,
) -> LinkCandidate:
    """Decide whether one CDP row participates in a fully confirmed link."""

    # --- the local side must be a real, non-sub interface on this device ---
    local_index = interface_indexes.get(item.device_id)
    if local_index is None:
        return LinkCandidate(
            EvidenceRule.LOCAL_INTERFACE_UNKNOWN,
            f"device {item.device_id!r} has no collected interfaces",
        )
    if interface_is_subinterface(item.local_interface_name):
        return LinkCandidate(EvidenceRule.SUBINTERFACE, _SUBINTERFACE_NOTE)

    local_interface_id, local_note = local_index.resolve(item.local_interface_name)
    if local_interface_id is None:
        rule = (
            EvidenceRule.AMBIGUOUS_INTERFACE_NAME
            if "ambiguous" in local_note
            else EvidenceRule.LOCAL_INTERFACE_UNKNOWN
        )
        return LinkCandidate(rule, f"local {local_note}")

    # --- the remote device must be collected (never invented) ---
    remote_device_id, remote_note = device_index.resolve(item.remote_device_name)
    if remote_device_id is None:
        rule = (
            EvidenceRule.AMBIGUOUS_DEVICE_NAME
            if "ambiguous" in remote_note
            else EvidenceRule.REMOTE_DEVICE_NOT_COLLECTED
        )
        return LinkCandidate(rule, f"remote device {remote_note}")
    if remote_device_id == item.device_id:
        return LinkCandidate(
            EvidenceRule.SELF_REFERENCE,
            f"row points back at its own device {remote_device_id!r} — not a link",
        )

    # --- the remote interface must exist on that device ---
    remote_index = interface_indexes.get(remote_device_id)
    if remote_index is None:  # pragma: no cover - merged topology always has one
        return LinkCandidate(
            EvidenceRule.REMOTE_INTERFACE_UNKNOWN,
            f"device {remote_device_id!r} has no collected interfaces",
        )
    if interface_is_subinterface(item.remote_interface_name):
        return LinkCandidate(EvidenceRule.SUBINTERFACE, _SUBINTERFACE_NOTE)
    remote_interface_id, remote_note = remote_index.resolve(item.remote_interface_name)
    if remote_interface_id is None:
        rule = (
            EvidenceRule.AMBIGUOUS_INTERFACE_NAME
            if "ambiguous" in remote_note
            else EvidenceRule.REMOTE_INTERFACE_UNKNOWN
        )
        return LinkCandidate(rule, f"remote {remote_note}")

    # --- reverse evidence: the other side must say the same thing ---
    reverse_key = (remote_device_id, normalize_interface_key(item.remote_interface_name))
    reverse_rows = index.rows_for(*reverse_key)
    if not reverse_rows:
        return LinkCandidate(
            EvidenceRule.ONE_SIDED_ONLY,
            f"device {remote_device_id!r} has no CDP row for local interface "
            f"{item.remote_interface_name!r} (one-sided evidence is not a link)",
        )

    agreeing: list[CdpEvidence] = []
    for reverse in reverse_rows:
        back_device_id, _ = device_index.resolve(reverse.remote_device_name)
        if back_device_id != item.device_id:
            continue
        back_interface_id, _ = local_index.resolve(reverse.remote_interface_name)
        if back_interface_id != local_interface_id:
            continue
        agreeing.append(reverse)

    if not agreeing:
        other = reverse_rows[0]
        return LinkCandidate(
            EvidenceRule.INCONSISTENT_SIDES,
            f"the two sides disagree: {item.device_id} says "
            f"{item.local_interface_name} <-> {item.remote_device_name}:"
            f"{item.remote_interface_name}, but {remote_device_id} says "
            f"{other.local_interface_name} <-> {other.remote_device_name}:"
            f"{other.remote_interface_name}",
        )

    first, second = sorted((local_interface_id, remote_interface_id))
    link = Link(
        id=build_link_id(first, second),
        source_interface_id=first,
        destination_interface_id=second,
        state=_link_state(topology, first, second),
    )
    result = LinkCandidate(
        rule=EvidenceRule.BOTH_SIDES_AGREE,
        detail=(
            f"{item.describe()} confirmed by {agreeing[0].describe()} "
            f"(interfaces {first} <-> {second})"
        ),
        link=link,
    )
    return result


def _link_state(topology: Topology, first_id: str, second_id: str) -> LinkState:
    """``up`` only when both endpoint interfaces are collected and up."""
    by_id = {i.id: i for i in topology.interfaces}
    first = by_id.get(first_id)
    second = by_id.get(second_id)
    if first is None or second is None:
        return LinkState.DOWN
    return LinkState.UP if (first.is_up and second.is_up) else LinkState.DOWN


def display_interface(raw: str) -> str:
    """Public helper so callers share one canonical display form."""
    return canonical_interface_display(raw)


def subinterface_parent(raw: str) -> str:
    """Public helper: parent key of a sub-interface name."""
    return interface_parent_key(raw)
