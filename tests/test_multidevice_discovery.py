"""Phase 2.2 — multi-device discovery tests. **OFFLINE ONLY.**

No SSH library is imported and no socket is opened: the collector is injected
as a function that returns ``DeviceObservations`` parsed from fixtures.

Fixture provenance (stated explicitly where synthetic):

* ``tests/data/live2026/*`` — real sanitized Phase-2.1 output from R2-1.
* ``tests/data/multidevice/r2-1.show_cdp_neighbors.txt`` — copy of the real
  R2-1 CDP output above.
* ``tests/data/multidevice/r2-2.*`` and ``r2-4.*`` — **SYNTHETIC**: written to
  mirror what R2-2 / R2-4 must report for the real R2-1 rows. They exist only
  so the two-sided matching rule can be tested without touching those devices.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from nettwin.collect.cisco_ios import DeviceObservations, map_to_topology
from nettwin.collect.discovery import (
    DeviceCollection,
    DeviceNameIndex,
    InterfaceNameIndex,
    InventoryError,
    build_link_id,
    discover_links,
    load_inventory,
    merge_device_topologies,
    normalize_device_key,
    normalize_interface_key,
)
from nettwin.collect.discovery.identity import (
    canonical_interface_display,
    device_match_keys,
    interface_is_subinterface,
)
from nettwin.collect.discovery.links import (
    CdpEvidence,
    EvidenceRule,
    collect_evidence,
)
from nettwin.collect.discovery.merge import MergeError
from nettwin.collect.discovery.pipeline import discover_topology

DATA = Path(__file__).parent / "data"
LIVE = DATA / "live2026"
MULTI = DATA / "multidevice"


# =========================================================================== #
# Helpers — build DeviceObservations without touching SSH
# =========================================================================== #


def _obs(
    device_id: str,
    *,
    host: str | None = None,
    interfaces: list[tuple[str, str, str]] | None = None,
    cdp: list[tuple[str, str, str, str]] | None = None,
    ospf: list[tuple[str, str, str, str, str, str]] | None = None,
    routes: list[dict] | None = None,
    model: str = "IOL",
) -> DeviceObservations:
    """Construct a minimal, internally consistent observation set.

    ``interfaces``: ``(name, ip, state)`` triples — a connected route is
    generated for each so mapping has the evidence it expects.
    ``cdp``: ``(local_iface, remote_device, remote_iface, platform)``.
    """
    interface_rows: list[dict] = []
    route_rows: list[dict] = list(routes or [])
    for name, ip, state in interfaces or []:
        interface_rows.append(
            {
                "name": name,
                "ip_address": ip,
                "status": state,
                "protocol": state,
                "admin_state": "up",
                "oper_state": state,
            }
        )
        if ip and state == "up":
            prefix = ip.rsplit(".", 1)[0] + ".0/24"
            route_rows.append(
                {
                    "prefix": prefix,
                    "protocol": "connected",
                    "protocol_code": "C",
                    "ad": None,
                    "metric": None,
                    "next_hops": [{"next_hop": None, "outgoing_interface": name}],
                    "candidate_default": False,
                }
            )
    cdp_rows = [
        {
            "device_id": remote_device,
            "local_interface": local,
            "holdtime": "150",
            "capabilities": "R S I",
            "platform": platform,
            "port_id": remote_iface,
        }
        for local, remote_device, remote_iface, platform in (cdp or [])
    ]
    ospf_rows = [
        {
            "neighbor_id": nid,
            "priority": pri,
            "state": st,
            "dead_time": dead,
            "address": addr,
            "interface": iface,
        }
        for nid, pri, st, dead, addr, iface in (ospf or [])
    ]
    return DeviceObservations(
        host=host or f"10.0.0.{abs(hash(device_id)) % 250 + 1}",
        device_id=device_id,
        collected_at="2026-11-15T12:00:00+00:00",
        status="ok",
        identity={"hostname": device_id.upper(), "ios_version": "15.2(4)M5", "model": model},
        interfaces=interface_rows,
        routes=route_rows,
        ospf_neighbors=ospf_rows,
        cdp_neighbors=cdp_rows,
        warnings=[],
    )


def _inventory(*devices: tuple[str, str]):
    return load_inventory(
        {"devices": [{"name": n, "host": h, "platform": "cisco_ios"} for n, h in devices]}
    )


def _collector_for(mapping: dict[str, DeviceObservations]):
    def _collect(entry):
        if entry.name not in mapping:
            raise AssertionError(f"unexpected collection attempt for {entry.name}")
        return mapping[entry.name]

    return _collect


def _merged_topology(*observations: DeviceObservations):
    collections = []
    for obs in observations:
        topology, warnings = map_to_topology(obs)
        collections.append(
            DeviceCollection(
                entry_name=obs.device_id or "?", host=obs.host, observations=obs,
                topology=topology, warnings=warnings,
            )
        )
    return merge_device_topologies(collections)


# =========================================================================== #
# Task 1 — Inventory
# =========================================================================== #


def test_inventory_loads_ordered_devices(tmp_path: Path) -> None:
    path = tmp_path / "inv.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "devices": [
                    {"name": "R2-1", "host": "192.168.98.34", "platform": "cisco_ios"},
                    {"name": "R2-2", "host": "192.168.98.35"},
                ]
            }
        ),
        encoding="utf-8",
    )
    inventory = load_inventory(path)
    assert [d.name for d in inventory] == ["R2-1", "R2-2"]
    assert [d.host for d in inventory] == ["192.168.98.34", "192.168.98.35"]
    assert inventory.devices[1].platform == "cisco_ios"  # default
    assert inventory.source == str(path)


def test_inventory_rejects_credentials(tmp_path: Path) -> None:
    path = tmp_path / "bad.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "devices": [
                    {
                        "name": "R2-1",
                        "host": "192.168.98.34",
                        "username": "admin",
                        "password": "secret",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(InventoryError, match="must not contain credentials"):
        load_inventory(path)


def test_inventory_rejects_duplicate_name_and_host(tmp_path: Path) -> None:
    duplicate_name = tmp_path / "dup-name.yaml"
    duplicate_name.write_text(
        yaml.safe_dump(
            {
                "devices": [
                    {"name": "R2-1", "host": "10.0.0.1"},
                    {"name": "R2-1", "host": "10.0.0.2"},
                ]
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(InventoryError, match="duplicates device name"):
        load_inventory(duplicate_name)

    duplicate_host = tmp_path / "dup-host.yaml"
    duplicate_host.write_text(
        yaml.safe_dump(
            {
                "devices": [
                    {"name": "R2-1", "host": "10.0.0.1"},
                    {"name": "R2-2", "host": "10.0.0.1"},
                ]
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(InventoryError, match="duplicates host"):
        load_inventory(duplicate_host)


def test_inventory_rejects_unknown_platform_and_missing_fields(tmp_path: Path) -> None:
    path = tmp_path / "inv.yaml"
    path.write_text(
        yaml.safe_dump({"devices": [{"name": "SW1", "host": "10.0.0.1", "platform": "nxos"}]}),
        encoding="utf-8",
    )
    with pytest.raises(InventoryError, match="unsupported platform"):
        load_inventory(path)

    path.write_text(yaml.safe_dump({"devices": [{"name": "R1"}]}), encoding="utf-8")
    with pytest.raises(InventoryError, match="missing 'host'"):
        load_inventory(path)


def test_shipped_pnetlab_inventory_parses() -> None:
    inventory = load_inventory(Path(__file__).parents[1] / "fixtures" / "pnetlab_inventory.yaml")
    assert [d.name for d in inventory] == ["R2-1", "R2-2", "R2-4"]
    assert inventory.by_name("R2-1").host == "192.168.98.34"


# =========================================================================== #
# Task 4 — Device identity resolution
# =========================================================================== #


def test_device_normalization_folds_case_and_whitespace() -> None:
    assert normalize_device_key("  R2-2.Nettwin.LAB ") == "r2-2.nettwin.lab"
    assert normalize_device_key("r2-2") == "r2-2"


def test_device_match_keys_offer_short_name_only_when_suffixed() -> None:
    keys, short = device_match_keys("R2-2.nettwin.lab")
    assert keys == ["r2-2.nettwin.lab", "r2-2"] and short == "r2-2"
    keys, short = device_match_keys("R2-2")
    assert keys == ["r2-2"] and short is None


def test_fqdn_resolves_to_collected_hostname() -> None:
    index = DeviceNameIndex()
    index.add("r2-1", "R2-1")
    index.add("r2-2", "R2-2")
    device_id, note = index.resolve("R2-2.nettwin.lab")
    assert device_id == "r2-2"
    assert "without domain suffix" in note


def test_ambiguous_short_name_is_never_resolved_arbitrarily() -> None:
    index = DeviceNameIndex()
    index.add("r2-2", "R2-2.nettwin.lab")     # same host, different domain
    index.add("r2-2b", "R2-2.other.lab")
    device_id, note = index.resolve("R2-2")
    assert device_id is None
    assert "ambiguous" in note


def test_unknown_device_name_is_not_resolved() -> None:
    index = DeviceNameIndex()
    index.add("r2-1", "R2-1")
    device_id, note = index.resolve("R2-99.nettwin.lab")
    assert device_id is None
    assert "no suffix guessing" in note


def test_no_substring_matching() -> None:
    """'R2' must not match 'R2-1'; substring matching is forbidden."""
    index = DeviceNameIndex()
    index.add("r2-1", "R2-1")
    device_id, _ = index.resolve("R2")
    assert device_id is None


# =========================================================================== #
# Task 5 — Interface name normalization
# =========================================================================== #


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Eth 0/0", "ethernet0/0"),
        ("Ethernet0/0", "ethernet0/0"),
        ("ETH 0/0", "ethernet0/0"),
        ("Gi0/1", "gigabitethernet0/1"),
        ("Gig0/1", "gigabitethernet0/1"),
        ("GigabitEthernet0/1", "gigabitethernet0/1"),
        ("Fa0/0", "fastethernet0/0"),
        ("FastEthernet0/0", "fastethernet0/0"),
        ("Te1/1", "tengigabitethernet1/1"),
        ("TenGigabitEthernet1/1", "tengigabitethernet1/1"),
        ("Lo0", "loopback0"),
        ("Vl50", "vlan50"),
    ],
)
def test_interface_normalization_table(raw: str, expected: str) -> None:
    assert normalize_interface_key(raw) == expected


def test_interface_display_form_matches_domain_names() -> None:
    assert canonical_interface_display("Eth 0/0") == "Ethernet0/0"
    assert canonical_interface_display("Gi0/1") == "GigabitEthernet0/1"


def test_unknown_interface_prefix_is_not_coerced() -> None:
    """An unknown type must not be mapped onto a known family."""
    assert normalize_interface_key("Xyz0/0") == "xyz0/0"
    assert canonical_interface_display("Xyz0/0") == "Xyz0/0"


def test_subinterface_detection() -> None:
    assert interface_is_subinterface("Eth0/0.100") is True
    assert interface_is_subinterface("Eth0/0") is False


def test_interface_index_reports_ambiguity() -> None:
    index = InterfaceNameIndex.from_interfaces(
        [("r2-1-ethernet0/0", "Ethernet0/0"), ("r2-1-ethernet0_0", "eth0/0")]
    )
    interface_id, note = index.resolve("Ethernet0/0")
    assert interface_id is None
    assert "ambiguous" in note


def test_interface_index_resolves_abbreviation_to_real_interface() -> None:
    index = InterfaceNameIndex.from_interfaces([("r2-1-ethernet0/1", "Ethernet0/1")])
    interface_id, _ = index.resolve("Eth 0/1")
    assert interface_id == "r2-1-ethernet0/1"


# =========================================================================== #
# Task 2 — Merge
# =========================================================================== #


def test_merge_combines_devices_without_duplicates() -> None:
    r1 = _obs("r2-1", interfaces=[("Ethernet0/0", "10.0.21.2", "up")])
    r2 = _obs("r2-2", interfaces=[("Ethernet0/1", "10.0.21.1", "up")])
    merge = _merged_topology(r1, r2)
    assert [d.id for d in merge.topology.devices] == ["r2-1", "r2-2"]
    assert len(merge.topology.vrfs) == 1  # GLOBAL merged, not duplicated
    assert merge.topology.vrfs[0].id == "GLOBAL"
    device_of = {i.id: i.device_id for i in merge.topology.interfaces}
    assert device_of["r2-1-ethernet0/0"] == "r2-1"
    assert device_of["r2-2-ethernet0/1"] == "r2-2"


def test_merge_keeps_routes_on_their_own_device() -> None:
    r1 = _obs("r2-1", interfaces=[("Ethernet0/0", "10.0.21.2", "up")])
    r2 = _obs("r2-2", interfaces=[("Ethernet0/1", "10.0.21.1", "up")])
    merge = _merged_topology(r1, r2)
    by_device: dict[str, int] = {}
    for route in merge.topology.routes:
        by_device[route.device_id] = by_device.get(route.device_id, 0) + 1
    assert by_device == {"r2-1": 1, "r2-2": 1}
    for route in merge.topology.routes:
        owner = next(i for i in merge.topology.interfaces if i.id == route.outgoing_interface_id)
        assert owner.device_id == route.device_id


def test_merge_refuses_duplicate_device_identity() -> None:
    r1 = _obs("r2-1", interfaces=[("Ethernet0/0", "10.0.21.2", "up")])
    r1_again = _obs("r2-1", interfaces=[("Ethernet0/0", "10.0.21.2", "up")])
    with pytest.raises(MergeError, match="identity is ambiguous"):
        _merged_topology(r1, r1_again)


def test_merge_records_failed_device_and_keeps_others() -> None:
    r1 = _obs("r2-1", interfaces=[("Ethernet0/0", "10.0.21.2", "up")])
    collections = []
    topology, warnings = map_to_topology(r1)
    collections.append(
        DeviceCollection("R2-1", r1.host, observations=r1, topology=topology, warnings=warnings)
    )
    collections.append(DeviceCollection("R2-2", "10.0.0.9", error="unreachable: timeout"))
    merge = merge_device_topologies(collections)
    assert [d.id for d in merge.topology.devices] == ["r2-1"]
    assert merge.failures == {"R2-2": "unreachable: timeout"}


# =========================================================================== #
# Task 3 + 6 — CDP two-sided link discovery (the required scenario table)
# =========================================================================== #


def test_two_sided_cdp_creates_link() -> None:
    r1 = _obs(
        "r2-1",
        interfaces=[("Ethernet0/0", "10.0.21.2", "up")],
        cdp=[("Ethernet0/0", "R2-2.nettwin.lab", "Ethernet0/1", "Linux Uni")],
    )
    r2 = _obs(
        "r2-2",
        interfaces=[("Ethernet0/1", "10.0.21.1", "up")],
        cdp=[("Ethernet0/1", "R2-1.nettwin.lab", "Ethernet0/0", "Linux Uni")],
    )
    merge = _merged_topology(r1, r2)
    evidence = collect_evidence({"r2-1": r1.cdp_neighbors, "r2-2": r2.cdp_neighbors})
    result = discover_links(merge.topology, evidence)

    assert result.warnings == []
    assert len(result.links) == 1
    link = result.links[0]
    assert link.source_interface_id == "r2-1-ethernet0/0"
    assert link.destination_interface_id == "r2-2-ethernet0/1"
    assert link.id == "r2-1-ethernet0/0--r2-2-ethernet0/1"
    assert str(link.state) == "up"
    assert link.id in result.provenance


def test_one_sided_cdp_creates_no_link() -> None:
    r1 = _obs(
        "r2-1",
        interfaces=[("Ethernet0/0", "10.0.21.2", "up")],
        cdp=[("Ethernet0/0", "R2-2.nettwin.lab", "Ethernet0/1", "Linux Uni")],
    )
    r2 = _obs("r2-2", interfaces=[("Ethernet0/1", "10.0.21.1", "up")], cdp=[])
    merge = _merged_topology(r1, r2)
    evidence = collect_evidence({"r2-1": r1.cdp_neighbors, "r2-2": r2.cdp_neighbors})
    result = discover_links(merge.topology, evidence)

    assert result.links == []
    assert any(c.rule is EvidenceRule.ONE_SIDED_ONLY for c in result.candidates)
    assert any("one-sided evidence is not a link" in w for w in result.warnings)


def test_remote_device_not_in_inventory_creates_no_link() -> None:
    r1 = _obs(
        "r2-1",
        interfaces=[("Ethernet0/0", "10.0.21.2", "up")],
        cdp=[("Ethernet0/0", "R2-99.nettwin.lab", "Ethernet0/1", "Linux Uni")],
    )
    merge = _merged_topology(r1)
    evidence = collect_evidence({"r2-1": r1.cdp_neighbors})
    result = discover_links(merge.topology, evidence)

    assert result.links == []
    assert any(c.rule is EvidenceRule.REMOTE_DEVICE_NOT_COLLECTED for c in result.candidates)


def test_remote_interface_missing_creates_no_link() -> None:
    r1 = _obs(
        "r2-1",
        interfaces=[("Ethernet0/0", "10.0.21.2", "up")],
        cdp=[("Ethernet0/0", "R2-2", "Ethernet0/9", "Linux Uni")],
    )
    r2 = _obs(
        "r2-2",
        interfaces=[("Ethernet0/1", "10.0.21.1", "up")],
        cdp=[("Ethernet0/9", "R2-1", "Ethernet0/0", "Linux Uni")],
    )
    merge = _merged_topology(r1, r2)
    evidence = collect_evidence({"r2-1": r1.cdp_neighbors, "r2-2": r2.cdp_neighbors})
    result = discover_links(merge.topology, evidence)

    assert result.links == []
    assert any(
        c.rule in {EvidenceRule.REMOTE_INTERFACE_UNKNOWN, EvidenceRule.LOCAL_INTERFACE_UNKNOWN}
        for c in result.candidates
    )


def test_ambiguous_device_name_creates_no_link() -> None:
    r1 = _obs(
        "r2-1",
        interfaces=[("Ethernet0/0", "10.0.21.2", "up")],
        cdp=[("Ethernet0/0", "R2-2.nettwin.lab", "Ethernet0/1", "Linux Uni")],
    )
    r2a = _obs("r2-2a", interfaces=[("Ethernet0/1", "10.0.21.1", "up")])
    r2b = _obs("r2-2b", interfaces=[("Ethernet0/1", "10.0.22.1", "up")])
    # Force the ambiguity: both collected devices advertise the short name R2-2.
    merge = _merged_topology(r1, r2a, r2b)
    for device in merge.topology.devices:
        if device.id in {"r2-2a", "r2-2b"}:
            device.name = "R2-2.nettwin.lab"
    evidence = collect_evidence({"r2-1": r1.cdp_neighbors})
    result = discover_links(merge.topology, evidence)

    assert result.links == []
    assert any(c.rule is EvidenceRule.AMBIGUOUS_DEVICE_NAME for c in result.candidates)


def test_abbreviated_interface_names_still_match() -> None:
    """R2-1 reports 'Eth 0/0', R2-2 reports 'Ethernet0/0' — same interface."""
    r1 = _obs(
        "r2-1",
        interfaces=[("Ethernet0/0", "10.0.21.2", "up")],
        cdp=[("Eth 0/0", "R2-2", "Eth 0/1", "Linux Uni")],
    )
    r2 = _obs(
        "r2-2",
        interfaces=[("Ethernet0/1", "10.0.21.1", "up")],
        cdp=[("Ethernet0/1", "R2-1", "Ethernet0/0", "Linux Uni")],
    )
    merge = _merged_topology(r1, r2)
    evidence = collect_evidence({"r2-1": r1.cdp_neighbors, "r2-2": r2.cdp_neighbors})
    result = discover_links(merge.topology, evidence)

    assert len(result.links) == 1
    assert result.links[0].source_interface_id == "r2-1-ethernet0/0"


def test_inconsistent_sides_create_no_link() -> None:
    """Both sides report each other, but disagree about which port is used."""
    r1 = _obs(
        "r2-1",
        interfaces=[("Ethernet0/0", "10.0.21.2", "up"), ("Ethernet0/2", "10.0.23.2", "up")],
        cdp=[("Ethernet0/0", "R2-2", "Ethernet0/1", "Linux Uni")],
    )
    r2 = _obs(
        "r2-2",
        interfaces=[("Ethernet0/1", "10.0.21.1", "up")],
        cdp=[("Ethernet0/1", "R2-1", "Ethernet0/2", "Linux Uni")],  # different local port
    )
    merge = _merged_topology(r1, r2)
    evidence = collect_evidence({"r2-1": r1.cdp_neighbors, "r2-2": r2.cdp_neighbors})
    result = discover_links(merge.topology, evidence)

    assert result.links == []
    assert any(c.rule is EvidenceRule.INCONSISTENT_SIDES for c in result.candidates)


def test_duplicate_evidence_rows_produce_one_link() -> None:
    r1 = _obs(
        "r2-1",
        interfaces=[("Ethernet0/0", "10.0.21.2", "up")],
        cdp=[
            ("Ethernet0/0", "R2-2", "Ethernet0/1", "Linux Uni"),
            ("Eth 0/0", "R2-2.nettwin.lab", "Eth 0/1", "Linux Uni"),  # same row, other spelling
        ],
    )
    r2 = _obs(
        "r2-2",
        interfaces=[("Ethernet0/1", "10.0.21.1", "up")],
        cdp=[("Ethernet0/1", "R2-1", "Ethernet0/0", "Linux Uni")],
    )
    merge = _merged_topology(r1, r2)
    evidence = collect_evidence({"r2-1": r1.cdp_neighbors, "r2-2": r2.cdp_neighbors})
    result = discover_links(merge.topology, evidence)

    assert len(result.links) == 1


def test_two_independent_parallel_links_are_both_kept() -> None:
    r1 = _obs(
        "r2-1",
        interfaces=[("Ethernet0/0", "10.0.21.2", "up"), ("Ethernet0/1", "10.0.41.2", "up")],
        cdp=[
            ("Ethernet0/0", "R2-2", "Ethernet0/1", "Linux Uni"),
            ("Ethernet0/1", "R2-2", "Ethernet0/2", "Linux Uni"),
        ],
    )
    r2 = _obs(
        "r2-2",
        interfaces=[
            ("Ethernet0/1", "10.0.21.1", "up"),
            ("Ethernet0/2", "10.0.41.1", "up"),
        ],
        cdp=[
            ("Ethernet0/1", "R2-1", "Ethernet0/0", "Linux Uni"),
            ("Ethernet0/2", "R2-1", "Ethernet0/1", "Linux Uni"),
        ],
    )
    merge = _merged_topology(r1, r2)
    evidence = collect_evidence({"r2-1": r1.cdp_neighbors, "r2-2": r2.cdp_neighbors})
    result = discover_links(merge.topology, evidence)

    assert len(result.links) == 2
    assert {link.id for link in result.links} == {
        "r2-1-ethernet0/0--r2-2-ethernet0/1",
        "r2-1-ethernet0/1--r2-2-ethernet0/2",
    }


def test_ospf_adjacency_without_cdp_creates_no_link() -> None:
    r1 = _obs(
        "r2-1",
        interfaces=[("Ethernet0/0", "10.0.21.2", "up")],
        ospf=[("10.255.255.2", "1", "FULL/BDR", "00:00:35", "10.0.21.1", "Ethernet0/0")],
        cdp=[],
    )
    r2 = _obs(
        "r2-2",
        interfaces=[("Ethernet0/1", "10.0.21.1", "up")],
        ospf=[("10.255.255.1", "1", "FULL/DR", "00:00:33", "10.0.21.2", "Ethernet0/1")],
        cdp=[],
    )
    merge = _merged_topology(r1, r2)
    evidence = collect_evidence({"r2-1": [], "r2-2": []})
    result = discover_links(merge.topology, evidence)

    assert result.links == []
    assert len(merge.topology.routes) == 2  # OSPF adjacency stays in observations only


def test_link_state_is_down_when_an_endpoint_is_down() -> None:
    r1 = _obs(
        "r2-1",
        interfaces=[("Ethernet0/0", "10.0.21.2", "down")],
        cdp=[("Ethernet0/0", "R2-2", "Ethernet0/1", "Linux Uni")],
    )
    r2 = _obs(
        "r2-2",
        interfaces=[("Ethernet0/1", "10.0.21.1", "up")],
        cdp=[("Ethernet0/1", "R2-1", "Ethernet0/0", "Linux Uni")],
    )
    # 'down' interfaces get no connected route, so the interface still exists
    merge = _merged_topology(r1, r2)
    evidence = collect_evidence({"r2-1": r1.cdp_neighbors, "r2-2": r2.cdp_neighbors})
    result = discover_links(merge.topology, evidence)
    assert len(result.links) == 1
    assert str(result.links[0].state) == "down"


def test_link_id_is_order_independent() -> None:
    assert build_link_id("a", "b") == build_link_id("b", "a") == "a--b"


def test_evidence_from_missing_device_yields_no_link() -> None:
    evidence = [
        CdpEvidence(
            device_id="r2-1",
            local_interface_name="Ethernet0/0",
            remote_device_name="R2-2",
            remote_interface_name="Ethernet0/1",
        )
    ]
    r1 = _obs("r2-1", interfaces=[("Ethernet0/0", "10.0.21.2", "up")])
    merge = _merged_topology(r1)
    result = discover_links(merge.topology, evidence)
    assert result.links == []


# =========================================================================== #
# Task 1 — End-to-end pipeline (mocked collector, real mapping/merging)
# =========================================================================== #


def test_pipeline_end_to_end_on_fixture_backed_devices() -> None:
    r2_1 = _obs(
        "r2-1",
        interfaces=[
            ("Ethernet0/0", "10.0.21.2", "up"),
            ("Ethernet0/1", "10.0.41.2", "up"),
            ("Loopback0", "10.255.255.1", "up"),
        ],
        cdp=[
            ("Ethernet0/0", "R2-2.nettwin.lab", "Ethernet0/1", "Linux Uni"),
            ("Ethernet0/1", "R2-4.nettwin.lab", "Ethernet0/1", "Linux Uni"),
        ],
        ospf=[
            ("10.255.255.2", "1", "FULL/BDR", "00:00:35", "10.0.21.1", "Ethernet0/0"),
            ("10.255.255.4", "1", "FULL/DR", "00:00:33", "10.0.41.1", "Ethernet0/1"),
        ],
    )
    r2_2 = _obs(
        "r2-2",
        interfaces=[("Ethernet0/1", "10.0.21.1", "up")],
        cdp=[("Ethernet0/1", "R2-1.nettwin.lab", "Ethernet0/0", "Linux Uni")],
    )
    r2_4 = _obs(
        "r2-4",
        interfaces=[("Ethernet0/1", "10.0.41.1", "up")],
        cdp=[("Ethernet0/1", "R2-1.nettwin.lab", "Ethernet0/1", "Linux Uni")],
    )
    inventory = _inventory(("R2-1", "10.0.0.1"), ("R2-2", "10.0.0.2"), ("R2-4", "10.0.0.4"))
    report = discover_topology(
        inventory, collect=_collector_for({"R2-1": r2_1, "R2-2": r2_2, "R2-4": r2_4})
    )

    assert report.succeeded
    assert report.failures == {}
    assert report.device_ids == ["r2-1", "r2-2", "r2-4"]
    assert report.topology is not None
    assert len(report.topology.devices) == 3
    assert len(report.topology.links) == 2
    link_pairs = {
        (link.source_interface_id, link.destination_interface_id)
        for link in report.topology.links
    }
    assert link_pairs == {
        ("r2-1-ethernet0/0", "r2-2-ethernet0/1"),
        ("r2-1-ethernet0/1", "r2-4-ethernet0/1"),
    }
    # no fabricated devices/endpoints, and every route keeps its owner
    assert {d.id for d in report.topology.devices} == {"r2-1", "r2-2", "r2-4"}
    assert report.topology.endpoints == []
    for route in report.topology.routes:
        assert route.device_id in {"r2-1", "r2-2", "r2-4"}


def test_pipeline_isolates_a_failing_device() -> None:
    r2_1 = _obs(
        "r2-1",
        interfaces=[("Ethernet0/0", "10.0.21.2", "up")],
        cdp=[("Ethernet0/0", "R2-2", "Ethernet0/1", "Linux Uni")],
    )

    def _collect(entry):
        if entry.name == "R2-2":
            from nettwin.collect.cisco_ios import CollectorConnectionError

            raise CollectorConnectionError("timeout failure connecting to host", "timeout")
        return r2_1

    inventory = _inventory(("R2-1", "10.0.0.1"), ("R2-2", "10.0.0.2"))
    report = discover_topology(inventory, collect=_collect)

    assert report.succeeded, "one failed device must not destroy the rest"
    assert set(report.failures) == {"R2-2"}
    assert report.device_ids == ["r2-1"]
    assert report.topology.links == [], "the R2-2 side was never collected"
    assert any("failed to collect" in w for w in report.warnings)


def test_pipeline_returns_no_topology_when_every_device_fails() -> None:
    def _collect(_entry):
        raise RuntimeError("boom")

    inventory = _inventory(("R2-1", "10.0.0.1"))
    report = discover_topology(inventory, collect=_collect)
    assert not report.succeeded
    assert report.topology is None
    assert "no topology produced" in " ".join(report.warnings)


def test_pipeline_no_links_mode_still_merges() -> None:
    r2_1 = _obs(
        "r2-1",
        interfaces=[("Ethernet0/0", "10.0.21.2", "up")],
        cdp=[("Ethernet0/0", "R2-2", "Ethernet0/1", "Linux Uni")],
    )
    r2_2 = _obs(
        "r2-2",
        interfaces=[("Ethernet0/1", "10.0.21.1", "up")],
        cdp=[("Ethernet0/1", "R2-1", "Ethernet0/0", "Linux Uni")],
    )
    inventory = _inventory(("R2-1", "10.0.0.1"), ("R2-2", "10.0.0.2"))
    report = discover_topology(
        inventory, collect=_collector_for({"R2-1": r2_1, "R2-2": r2_2}), collect_links=False
    )
    assert report.succeeded
    assert len(report.topology.devices) == 2
    assert report.topology.links == []


# =========================================================================== #
# Real Phase-2.1 fixtures still drive the parsers unchanged
# =========================================================================== #


def test_real_r2_1_cdp_fixture_feeds_the_two_sided_matcher() -> None:
    """The real R2-1 rows must pair with synthetic mirror rows for R2-2/R2-4."""
    from nettwin.collect import ios_parsers

    r2_1_rows, _ = ios_parsers.parse_show_cdp_neighbors(
        (MULTI / "r2-1.show_cdp_neighbors.txt").read_text(encoding="utf-8")
    )
    r2_2_rows, _ = ios_parsers.parse_show_cdp_neighbors(
        (MULTI / "r2-2.show_cdp_neighbors.txt").read_text(encoding="utf-8")
    )
    r2_4_rows, _ = ios_parsers.parse_show_cdp_neighbors(
        (MULTI / "r2-4.show_cdp_neighbors.txt").read_text(encoding="utf-8")
    )

    r2_1_cdp = [
        (r.local_interface, r.device_id, r.port_id, r.platform) for r in r2_1_rows
    ]
    r2_1 = _obs(
        "r2-1",
        interfaces=[("Ethernet0/0", "10.0.21.2", "up"), ("Ethernet0/1", "10.0.41.2", "up")],
        cdp=r2_1_cdp,
    )
    r2_2 = _obs(
        "r2-2",
        interfaces=[("Ethernet0/1", "10.0.21.1", "up")],
        cdp=[(r.local_interface, r.device_id, r.port_id, r.platform) for r in r2_2_rows],
    )
    r2_4 = _obs(
        "r2-4",
        interfaces=[("Ethernet0/1", "10.0.41.1", "up")],
        cdp=[(r.local_interface, r.device_id, r.port_id, r.platform) for r in r2_4_rows],
    )
    merge = _merged_topology(r2_1, r2_2, r2_4)
    evidence = collect_evidence(
        {
            "r2-1": r2_1.cdp_neighbors,
            "r2-2": r2_2.cdp_neighbors,
            "r2-4": r2_4.cdp_neighbors,
        }
    )
    result = discover_links(merge.topology, evidence)
    assert len(result.links) == 2
    assert all(str(link.state) == "up" for link in result.links)
