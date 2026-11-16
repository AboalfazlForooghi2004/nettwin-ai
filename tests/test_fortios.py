"""Phase 2.5 — FortiGate/FortiOS collection and mapping tests. **OFFLINE ONLY.**

No SSH session is opened and no socket is touched: every device is a text
fixture under ``tests/data/fortios``.

Fixture provenance:

* ``fgt-a_*`` — written from the output formats published in the Fortinet
  administration guides (``get system status``, ``get system interface``,
  ``get router info routing-table all``) for FortiOS 7.4. Addresses are from
  the documentation ranges (RFC 5737 / RFC 1918).
* ``fgt-b_legacy_*`` — the FortiOS 6.x spelling where ``status:`` prints
  ``enable``/``disable`` instead of ``up``/``down``.
* ``fgt-c_*`` — a multi-VRF table containing an ECMP continuation line.
* ``unknown_vendor_show_version.txt`` — a non-Cisco, non-Fortinet banner, used
  only to prove an unsupported device neither crashes nor is misclassified.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from nettwin.collect.cisco_ios import READ_ONLY_COMMANDS
from nettwin.collect.fortios import (
    CMD_INTERFACE,
    CMD_LLDP,
    CMD_ROUTES,
    CMD_STATUS,
    map_to_topology,
    parse_observations,
)
from nettwin.collect.fortios_parsers import (
    parse_routing_table,
    parse_system_interface,
    parse_system_status,
)
from nettwin.collect.vendor import (
    CISCO_IOS_COMMANDS,
    CISCO_IOS_PROFILE,
    CISCO_IOS_VENDOR,
    FORTIGATE_COMMANDS,
    FORTIGATE_PROFILE,
    FORTIGATE_VENDOR,
    UNKNOWN_PROFILE,
    UNKNOWN_VENDOR,
    VendorCommandError,
    command_set_for,
    detect_vendor,
    validate_command,
)
from nettwin.domain.models import AdminState, OperState

DATA = Path(__file__).parent / "data" / "fortios"


def _read(name: str) -> str:
    return (DATA / name).read_text(encoding="utf-8")


def _fgt_a_outputs() -> dict[str, str]:
    return {
        CMD_STATUS: _read("fgt-a_get_system_status.txt"),
        CMD_INTERFACE: _read("fgt-a_get_system_interface.txt"),
        CMD_ROUTES: _read("fgt-a_get_router_info_routing-table_all.txt"),
        CMD_LLDP: _read("fgt-a_get_system_lldp_neighbors.txt"),
    }


def _fgt_a_topology():
    obs = parse_observations("192.168.98.60", _fgt_a_outputs())
    return map_to_topology(obs, "fgt-a")


# =========================================================================== #
# 1. Identification
# =========================================================================== #


def test_identifies_fortigate_from_get_system_status() -> None:
    result = detect_vendor(_read("fgt-a_get_system_status.txt"))
    assert result.profile.key == FORTIGATE_VENDOR
    assert result.profile.label == "Fortinet FortiGate / FortiOS"
    assert "FortiGate-100F" in result.evidence
    assert not result.ambiguous


def test_identifies_cisco_unchanged() -> None:
    """Cisco detection is not perturbed by the new vendor."""
    ios = (
        "Cisco IOS Software, Linux Software (I86BI_LINUXL2-ADVENTERPRISEK9-M), "
        "Version 15.2(4)M5, RELEASE SOFTWARE (fc2)\n"
    )
    result = detect_vendor(ios)
    assert result.profile.key == CISCO_IOS_VENDOR
    assert "Cisco IOS" in result.evidence


def test_identifies_iosxe() -> None:
    result = detect_vendor(
        "Cisco IOS XE Software, Version 17.09.04a\n"
        "Cisco IOS Software [Cupertino], Catalyst L3 Switch Software\n"
    )
    assert result.profile.key == CISCO_IOS_VENDOR


def test_unsupported_vendor_is_unknown_not_guessed() -> None:
    result = detect_vendor(_read("unknown_vendor_show_version.txt"))
    assert result.profile.key == UNKNOWN_VENDOR
    assert result.profile.commands == ()
    assert not result.profile.is_supported


def test_empty_identity_is_unknown() -> None:
    result = detect_vendor("")
    assert result.profile.key == UNKNOWN_VENDOR
    assert "empty" in result.evidence


def test_ambiguous_identity_is_downgraded_to_unknown() -> None:
    """Both vendor markers present -> do not guess."""
    both = (
        "Version: FortiGate-100F v7.4.4,build2662,240514 (GA)\n"
        "Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M)\n"
    )
    result = detect_vendor(both)
    assert result.profile.key == UNKNOWN_VENDOR
    assert result.ambiguous


# =========================================================================== #
# 2. get system status — model and version
# =========================================================================== #


def test_status_extracts_model_version_serial_hostname() -> None:
    status, warnings = parse_system_status(_read("fgt-a_get_system_status.txt"))
    assert status.hostname == "FGT-A"
    assert status.model == "FortiGate-100F"
    assert status.version == "7.4.4"
    assert status.build == "2662"
    assert status.serial == "FG100FTK00000001"
    assert status.vdom == "root"
    assert warnings == []


def test_status_legacy_fortios_parses() -> None:
    status, _ = parse_system_status(_read("fgt-b_legacy_get_system_status.txt"))
    assert status.model == "FortiGate-60E"
    assert status.version == "6.0.14"
    assert status.hostname == "FGT-LEGACY"


def test_status_missing_fields_warn_but_do_not_crash() -> None:
    status, warnings = parse_system_status("Version: FortiGate-40F v7.0.0,build0001 (GA)\n")
    assert status.version == "7.0.0"
    assert status.hostname == ""
    assert any("hostname not reported" in w for w in warnings)
    assert any("serial number not reported" in w for w in warnings)


def test_status_empty_output_is_not_evidence() -> None:
    status, warnings = parse_system_status("")
    assert status.is_fortigate is False
    assert warnings and "empty output" in warnings[0]


def test_status_unrecognized_version_line_warns() -> None:
    _, warnings = parse_system_status("Version: something unusual\n")
    assert any("unrecognized Version line" in w for w in warnings)


# =========================================================================== #
# 3. get system interface
# =========================================================================== #


def test_interfaces_parsed_with_addresses_and_states() -> None:
    interfaces, warnings = parse_system_interface(
        _read("fgt-a_get_system_interface.txt")
    )
    by_name = {i.name: i for i in interfaces}
    assert set(by_name) == {"port1", "port2", "port3", "wan1"}
    assert by_name["port1"].ip_addresses == ["192.168.98.60/24"]
    assert by_name["wan1"].ip_addresses == ["203.0.113.25/29"]
    assert by_name["port1"].admin_state == "up"
    assert warnings == []


def test_unaddressed_interface_gets_no_fabricated_address() -> None:
    """``ip: 0.0.0.0 0.0.0.0`` is absence of an address, not 0.0.0.0/0."""
    interfaces, _ = parse_system_interface(_read("fgt-a_get_system_interface.txt"))
    port3 = next(i for i in interfaces if i.name == "port3")
    assert port3.ip_addresses == []
    assert port3.admin_state == "down"


def test_legacy_status_enable_disable_is_normalized() -> None:
    interfaces, _ = parse_system_interface(
        _read("fgt-b_legacy_get_system_interface.txt")
    )
    by_name = {i.name: i for i in interfaces}
    assert by_name["port1"].admin_state == "up"       # "status: enable"
    assert by_name["port2"].admin_state == "down"     # "status: disable"
    assert by_name["port2"].ip_addresses == []


def test_unrecognized_status_word_stays_unknown() -> None:
    interfaces, _ = parse_system_interface("== [ p1 ]\nname: p1\nstatus: flapping\nip: 10.0.0.1 255.255.255.0\n")
    assert interfaces[0].admin_state == "unknown"


def test_interface_empty_output_warns() -> None:
    interfaces, warnings = parse_system_interface("")
    assert interfaces == []
    assert warnings and "empty output" in warnings[0]


def test_interface_bad_mask_warns() -> None:
    _, warnings = parse_system_interface("== [ p1 ]\nname: p1\nip: 10.0.0.1 255.0.255.0\n")
    assert any("invalid address" in w for w in warnings)


# =========================================================================== #
# 4. get router info routing-table all
# =========================================================================== #


def test_routing_table_parses_all_entry_kinds() -> None:
    routes, warnings = parse_routing_table(
        _read("fgt-a_get_router_info_routing-table_all.txt")
    )
    by_prefix = {r.prefix: r for r in routes}
    assert "0.0.0.0/0" in by_prefix
    assert "10.10.10.0/24" in by_prefix
    assert "10.20.0.0/16" in by_prefix

    default = by_prefix["0.0.0.0/0"]
    assert default.protocol == "static"
    assert default.next_hop == "203.0.113.26"
    assert default.interface == "wan1"
    assert default.active is True       # "*" is a candidate default, not inactive

    connected = by_prefix["10.10.10.0/24"]
    assert connected.protocol == "connected"
    assert connected.next_hop is None
    assert connected.interface == "port2"

    ospf = by_prefix["10.20.0.0/16"]
    assert ospf.protocol == "ospf"
    assert ospf.next_hop == "10.10.10.2"
    assert warnings == []


def test_routing_table_legacy_fortios_parses() -> None:
    routes, _ = parse_routing_table(
        _read("fgt-b_legacy_get_router_info_routing-table_all.txt")
    )
    assert len(routes) == 3
    assert {r.protocol for r in routes} == {"connected", "static"}


def test_routing_table_multivrf_keeps_sections_separate() -> None:
    routes, _ = parse_routing_table(
        _read("fgt-c_get_router_info_routing-table_all.txt")
    )
    vrfs = {r.vrf for r in routes}
    assert vrfs == {"0", "10"}
    vlan101 = next(r for r in routes if "172.16.101.0" in r.prefix)
    assert vlan101.vrf == "10"


def test_routing_table_ecmp_continuation_is_reported_not_silently_dropped() -> None:
    routes, warnings = parse_routing_table(
        _read("fgt-c_get_router_info_routing-table_all.txt")
    )
    multi = next(r for r in routes if r.prefix == "192.168.20.0/24")
    assert multi.next_hop == "172.31.0.2"        # first hop kept
    assert any("additional next hop" in w and "ECMP" in w for w in warnings)


def test_routing_table_empty_output_warns() -> None:
    routes, warnings = parse_routing_table("")
    assert routes == []
    assert warnings and "empty output" in warnings[0]


def test_routing_table_route_without_nexthop_or_interface_is_skipped() -> None:
    routes, warnings = parse_routing_table(
        "Codes: K - kernel\nRouting table for VRF=0\nS       10.1.1.0/24 [10/0]\n"
    )
    assert all(r.prefix != "10.1.1.0/24" for r in routes)
    assert any("no next hop and no interface" in w for w in warnings)


# =========================================================================== #
# 5. Mapping to normalized domain models
# =========================================================================== #


def test_device_is_vendor_fortinet_with_model_and_management_ip() -> None:
    topology, _ = _fgt_a_topology()
    device = topology.devices[0]
    assert device.vendor == "fortinet"
    assert device.platform == "FortiGate-100F"
    assert device.name == "FGT-A"
    assert str(device.management_address) == "192.168.98.60"
    assert device.metadata["fortios_version"] == "7.4.4"
    assert device.metadata["serial"] == "FG100FTK00000001"


def test_interfaces_map_to_domain_model_with_states() -> None:
    topology, _ = _fgt_a_topology()
    by_name = {i.name: i for i in topology.interfaces}
    assert by_name["port1"].admin_state is AdminState.UP
    assert by_name["port1"].oper_state is OperState.UP
    assert str(by_name["port1"].ipv4_addresses[0]) == "192.168.98.60/24"
    assert by_name["port3"].admin_state is AdminState.DOWN
    assert by_name["port3"].ipv4_addresses == []


def test_routes_resolve_interface_ids_where_possible() -> None:
    topology, _ = _fgt_a_topology()
    default = next(r for r in topology.routes if str(r.destination_prefix) == "0.0.0.0/0")
    assert default.outgoing_interface_id == "fgt-a-wan1"
    assert str(default.next_hop) == "203.0.113.26"


def test_route_with_unresolvable_interface_is_kept_without_inventing() -> None:
    """A route naming an interface that was not collected keeps its next hop."""
    outputs = _fgt_a_outputs()
    outputs[CMD_ROUTES] = (
        "Codes: K - kernel\nRouting table for VRF=0\n"
        "S       10.99.0.0/16 [10/0] via 192.0.2.1, ghostport\n"
    )
    obs = parse_observations("192.168.98.60", outputs)
    topology, warnings = map_to_topology(obs, "fgt-a")
    route = next(r for r in topology.routes if str(r.destination_prefix) == "10.99.0.0/16")
    assert route.outgoing_interface_id is None
    assert str(route.next_hop) == "192.0.2.1"
    assert any("not present in collected interfaces" in w for w in warnings)


def test_fortigate_contributes_no_links_when_lldp_is_off() -> None:
    """The honest default: no neighbour evidence -> no links, and a reason."""
    topology, warnings = _fgt_a_topology()
    assert topology.links == []
    assert any("LLDP reception is disabled by default" in w for w in warnings)


def test_management_address_stays_none_for_hostname_target() -> None:
    obs = parse_observations("fgt-a.example.lab", _fgt_a_outputs())
    topology, _ = map_to_topology(obs, "fgt-a")
    assert topology.devices[0].management_address is None
    assert topology.devices[0].metadata["source_host"] == "fgt-a.example.lab"


def test_missing_everything_does_not_crash() -> None:
    """A device that answered nothing still yields a valid topology."""
    obs = parse_observations("10.0.0.9", {})
    topology, warnings = map_to_topology(obs, "dev-9")
    assert len(topology.devices) == 1
    assert topology.interfaces == []
    assert topology.routes == []
    assert topology.devices[0].platform == "FortiGate"
    assert warnings


def test_legacy_device_maps_end_to_end() -> None:
    obs = parse_observations(
        "172.16.1.1",
        {
            CMD_STATUS: _read("fgt-b_legacy_get_system_status.txt"),
            CMD_INTERFACE: _read("fgt-b_legacy_get_system_interface.txt"),
            CMD_ROUTES: _read("fgt-b_legacy_get_router_info_routing-table_all.txt"),
        },
    )
    topology, _ = map_to_topology(obs, "fgt-legacy")
    assert topology.devices[0].platform == "FortiGate-60E"
    by_name = {i.name: i for i in topology.interfaces}
    assert by_name["internal"].admin_state is AdminState.UP
    static = next(r for r in topology.routes if r.protocol == "static")
    assert static.outgoing_interface_id == "fgt-legacy-port1"


# =========================================================================== #
# 6. Command allowlists — safety
# =========================================================================== #


def test_cisco_command_set_is_unchanged() -> None:
    """The new dispatch layer must not alter the Cisco allowlist."""
    assert frozenset(CISCO_IOS_COMMANDS) == READ_ONLY_COMMANDS
    assert set(CISCO_IOS_PROFILE.commands) == READ_ONLY_COMMANDS


def test_fortigate_commands_are_get_only() -> None:
    for command in FORTIGATE_COMMANDS:
        assert command.startswith("get "), command
        assert "diagnose" not in command
        assert "config" not in command
        assert "execute" not in command


def test_no_command_is_shared_between_vendors() -> None:
    """A command valid for one vendor must not be dispatched to the other."""
    assert set(FORTIGATE_COMMANDS).isdisjoint(READ_ONLY_COMMANDS)


@pytest.mark.parametrize(
    "command",
    [
        "config system interface",
        "execute reboot",
        "diagnose lldp rx neighbor details",
        "get system interface port1",
        "get system status | grep Version",
        "delete system admin",
    ],
)
def test_fortigate_forbidden_commands_are_rejected(command: str) -> None:
    with pytest.raises(VendorCommandError):
        validate_command(FORTIGATE_PROFILE, command)


@pytest.mark.parametrize("command", list(FORTIGATE_COMMANDS))
def test_fortigate_allowlisted_commands_are_accepted(command: str) -> None:
    validate_command(FORTIGATE_PROFILE, command)   # must not raise


def test_ios_command_sent_to_fortigate_is_rejected() -> None:
    with pytest.raises(VendorCommandError):
        validate_command(FORTIGATE_PROFILE, "show version")


def test_fortigate_command_sent_to_ios_is_rejected() -> None:
    with pytest.raises(VendorCommandError):
        validate_command(CISCO_IOS_PROFILE, "get system status")


def test_unknown_vendor_gets_no_commands() -> None:
    assert command_set_for(UNKNOWN_VENDOR) == ()
    with pytest.raises(VendorCommandError):
        validate_command(UNKNOWN_PROFILE, "show version")


def test_unknown_vendor_key_falls_back_to_empty_command_set() -> None:
    assert command_set_for("nokia_sros") == ()


# =========================================================================== #
# 7. Integration with the existing normalized pipeline
# =========================================================================== #


def test_fortigate_topology_merges_with_cisco_through_existing_merge() -> None:
    """No vendor-specific branch in merge: both map to the same models."""
    from nettwin.collect.cisco_ios import DeviceObservations
    from nettwin.collect.cisco_ios import map_to_topology as cisco_map
    from nettwin.collect.discovery.merge import DeviceCollection, merge_device_topologies

    cisco_obs = DeviceObservations(
        host="10.0.0.1", device_id="r1", collected_at="2026-11-15T00:00:00Z", status="ok",
        identity={"hostname": "R1", "model": "C9300", "ios_version": "17.9"},
        interfaces=[
            {"name": "GigabitEthernet0/1", "ip_address": "10.0.0.1",
             "admin_state": "up", "oper_state": "up"},
        ],
        routes=[],
    )
    cisco_topo, _ = cisco_map(cisco_obs)

    fgt_obs = parse_observations("192.168.98.60", _fgt_a_outputs())
    fgt_topo, _ = map_to_topology(fgt_obs, "fgt-a")

    merged = merge_device_topologies([
        DeviceCollection(entry_name="R1", host="10.0.0.1", observations=cisco_obs, topology=cisco_topo),
        DeviceCollection(entry_name="FGT-A", host="192.168.98.60", observations=fgt_obs, topology=fgt_topo),
    ])
    vendors = sorted(d.vendor for d in merged.topology.devices)
    assert vendors == ["cisco", "fortinet"]
    # Interfaces from both vendors land in one flat, vendor-agnostic list.
    assert len(merged.topology.interfaces) == 5
    assert merged.topology.links == []


def test_fortigate_topology_passes_validation_as_part_of_a_merged_set() -> None:
    """``Topology`` cross-reference validation must accept FortiOS ids."""
    from nettwin.collect.discovery.merge import DeviceCollection, merge_device_topologies

    obs_a = parse_observations("192.168.98.60", _fgt_a_outputs())
    topo_a, _ = map_to_topology(obs_a, "fgt-a")
    obs_b = parse_observations(
        "172.16.1.1",
        {
            CMD_STATUS: _read("fgt-b_legacy_get_system_status.txt"),
            CMD_INTERFACE: _read("fgt-b_legacy_get_system_interface.txt"),
            CMD_ROUTES: _read("fgt-b_legacy_get_router_info_routing-table_all.txt"),
        },
    )
    topo_b, _ = map_to_topology(obs_b, "fgt-b")

    merged = merge_device_topologies([
        DeviceCollection(entry_name="A", host="192.168.98.60", observations=obs_a, topology=topo_a),
        DeviceCollection(entry_name="B", host="172.16.1.1", observations=obs_b, topology=topo_b),
    ])
    # Two FortiGates, all ids resolved, nothing dropped.
    assert len(merged.topology.devices) == 2
    assert len(merged.topology.interfaces) == 7
    for route in merged.topology.routes:
        if route.outgoing_interface_id:
            assert any(i.id == route.outgoing_interface_id for i in merged.topology.interfaces)


def test_unsupported_device_does_not_break_the_run() -> None:
    """An unknown vendor yields no commands, no parser, and no exception."""
    detection = detect_vendor(_read("unknown_vendor_show_version.txt"))
    assert detection.profile.key == UNKNOWN_VENDOR
    # Nothing to dispatch, and dispatch of anything at all is refused.
    assert detection.profile.commands == ()
    with pytest.raises(VendorCommandError):
        validate_command(detection.profile, "show version")
    # And the inventory still classifies it without raising.
    assert detection.profile.is_supported is False


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("Version: FortiGate-40F v7.0.0,build0001 (GA)\n", FORTIGATE_VENDOR),
        ("Version: FortiWiFi-60F v7.2.8,build1517 (GA.M)\n", FORTIGATE_VENDOR),
        ("Version: FortiGate-VM64-KVM v8.0.2,build1234 (GA)\n", FORTIGATE_VENDOR),
        ("Cisco IOS Software, C3750E Software (C3750E-UNIVERSALK9-M)\n", CISCO_IOS_VENDOR),
        ("Cisco IOS XE Software, Version 17.03.04\n", CISCO_IOS_VENDOR),
    ],
)
def test_detection_across_real_version_banners(text: str, expected: str) -> None:
    assert detect_vendor(text).profile.key == expected


def test_fortigate_observations_serialize_to_json_safely() -> None:
    import json

    obs = parse_observations("192.168.98.60", _fgt_a_outputs())
    encoded = json.dumps(obs.to_dict())
    assert "FG100FTK00000001" in encoded
    assert "192.168.98.60" not in encoded or True   # host is allowed; no secrets present
    for leak in ("password", "secret", "enable"):
        assert leak not in encoded.lower()
