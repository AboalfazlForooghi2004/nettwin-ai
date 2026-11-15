"""Phase-2 Cisco SSH collector tests — **OFFLINE, MOCKED SSH ONLY**.

Scope and honesty labels (see PHASE2_COLLECTOR_REPORT.md):

* Every test here runs against sanitized representative IOS 15.2 outputs in
  ``tests/data/ios152/`` plus injected mock sessions — **no socket is ever
  opened**, no device is contacted, and no SSH library (netmiko/paramiko/
  …) is required or imported.
* These tests do NOT prove live SSH works; live validation is executed by
  the operator from Ubuntu against R2-1 only (UBUNTU_LIVE_TEST_GUIDE.md).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from nettwin.collect import ios_parsers
from nettwin.collect.cisco_ios import (
    DEFAULT_COMMANDS,
    READ_ONLY_COMMANDS,
    AllowlistViolation,
    CiscoIOSCollector,
    CollectorConfigError,
    CollectorConnectionError,
    CollectorError,
    DeviceObservations,
    map_to_topology,
)

DATA_DIR = Path(__file__).parent / "data" / "ios152"

ENV_USER = "nettwin-ro"
ENV_PASS = "unit-test-only-fake-pw"  # placeholder secret for sanitization tests


def _read(name: str) -> str:
    return (DATA_DIR / name).read_text(encoding="utf-8")


@pytest.fixture
def full_outputs() -> dict[str, str]:
    return {
        "show version": _read("show_version.txt"),
        "show ip interface brief": _read("show_ip_interface_brief.txt"),
        "show ip route": _read("show_ip_route.txt"),
        "show ip ospf neighbor": _read("show_ip_ospf_neighbor.txt"),
        "show cdp neighbors": _read("show_cdp_neighbors.txt"),
    }


@pytest.fixture(autouse=True)
def _device_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    """Environment credentials for every test (values are fake, never real)."""
    monkeypatch.setenv("NETTWIN_DEVICE_USERNAME", ENV_USER)
    monkeypatch.setenv("NETTWIN_DEVICE_PASSWORD", ENV_PASS)


class MockSession:
    """netmiko-compatible mock: records dispatched commands, no network."""

    def __init__(
        self,
        outputs: dict[str, str],
        failures: dict[str, Exception] | None = None,
    ) -> None:
        self.outputs = outputs
        self.failures = failures or {}
        self.sent: list[str] = []
        self.read_timeouts: list[float | None] = []
        self.disconnected = False

    def send_command(self, command: str, read_timeout: float | None = None) -> str:
        self.sent.append(command)
        self.read_timeouts.append(read_timeout)
        if command in self.failures:
            raise self.failures[command]
        return self.outputs[command]

    def disconnect(self) -> None:
        self.disconnected = True


class RecordingFactory:
    """Session factory that records its call kwargs (or raises)."""

    def __init__(self, session: MockSession | None = None, error: Exception | None = None):
        self.session = session
        self.error = error
        self.calls: list[dict] = []

    def __call__(self, **kwargs):  # noqa: ANN003 - mirrors SessionFactory
        self.calls.append(kwargs)
        if self.error is not None:
            raise self.error
        assert self.session is not None
        return self.session


def _collector(outputs: dict[str, str], **kwargs) -> tuple[CiscoIOSCollector, MockSession, RecordingFactory]:
    session = MockSession(outputs, failures=kwargs.pop("failures", None))
    factory = RecordingFactory(session=session, **kwargs.pop("factory_kwargs", {}))
    collector = CiscoIOSCollector("192.168.98.34", connect_factory=factory, **kwargs)
    return collector, session, factory


# =========================================================================== #
# 1. Allowlist — reject BEFORE connecting; config mode can never be invoked
# =========================================================================== #

def test_readonly_allowlist_is_the_exact_five_commands() -> None:
    assert READ_ONLY_COMMANDS == frozenset(
        {
            "show version",
            "show ip interface brief",
            "show ip route",
            "show ip ospf neighbor",
            "show cdp neighbors",
        }
    )
    assert set(DEFAULT_COMMANDS) == set(READ_ONLY_COMMANDS)


@pytest.mark.parametrize(
    "bad_command",
    [
        "show running-config",
        "show startup-config",
        "configure terminal",
        "conf t",
        "write memory",
        "copy running-config tftp://x",
        "reload",
        "clear ip ospf neighbor",
        "enable",
        "debug ip ospf packet",
        "send log",
        "setup",
        "erase startup-config",
        "show ip ospf neighbor | pipe",  # not in allowlist, even if read-only-ish
        "SHOW VERSION extra-arg",  # allowlist is exact, not prefix-based
    ],
)
def test_non_allowlisted_command_rejected_before_connect(bad_command: str) -> None:
    factory = RecordingFactory(session=MockSession({}))
    collector = CiscoIOSCollector("192.168.98.34", connect_factory=factory)
    with pytest.raises(AllowlistViolation):
        collector.collect(commands=[bad_command])
    assert factory.calls == [], "connection must not be attempted for a rejected command"


def test_empty_command_list_rejected_before_connect() -> None:
    factory = RecordingFactory(session=MockSession({}))
    collector = CiscoIOSCollector("192.168.98.34", connect_factory=factory)
    with pytest.raises(AllowlistViolation):
        collector.collect(commands=[])
    assert factory.calls == []


def test_default_dispatch_is_exactly_allowlist_and_never_config(full_outputs: dict[str, str]) -> None:
    collector, session, _ = _collector(full_outputs)
    collector.collect()
    assert session.sent == list(DEFAULT_COMMANDS)
    for dispatched in session.sent:
        assert dispatched in READ_ONLY_COMMANDS
        lowered = dispatched.lower()
        assert "configure" not in lowered
        assert "conf t" not in lowered
        assert "write" not in lowered
        assert "reload" not in lowered


# =========================================================================== #
# 2. Session lifecycle & credentials
# =========================================================================== #

def test_session_disconnected_after_successful_collection(full_outputs: dict[str, str]) -> None:
    collector, session, factory = _collector(full_outputs)
    observations = collector.collect()
    assert session.disconnected is True
    assert observations.status == "ok"
    assert len(observations.commands) == 5
    assert all(c.status == "ok" for c in observations.commands)


def test_session_disconnected_even_when_a_command_fails(full_outputs: dict[str, str]) -> None:
    collector, session, _ = _collector(
        full_outputs, failures={"show ip route": RuntimeError("read timeout while paging")}
    )
    observations = collector.collect()
    assert session.disconnected is True
    assert observations.status == "partial"
    by_cmd = {c.command: c for c in observations.commands}
    assert by_cmd["show ip route"].status == "error"
    assert by_cmd["show version"].status == "ok"
    # uncollected section is marked unavailable, never faked
    assert observations.routes == []
    assert any("show ip route: not collected" in w for w in observations.warnings)


def test_credentials_come_from_environment(full_outputs: dict[str, str]) -> None:
    collector, _, factory = _collector(full_outputs)
    collector.collect()
    assert factory.calls[0]["username"] == ENV_USER
    assert factory.calls[0]["password"] == ENV_PASS
    assert factory.calls[0]["host"] == "192.168.98.34"
    assert factory.calls[0]["port"] == 22


def test_missing_environment_credentials_is_config_error() -> None:
    import os

    os.environ.pop("NETTWIN_DEVICE_USERNAME", None)
    os.environ.pop("NETTWIN_DEVICE_PASSWORD", None)
    factory = RecordingFactory(session=MockSession({}))
    collector = CiscoIOSCollector("192.168.98.34", connect_factory=factory)
    with pytest.raises(CollectorConfigError):
        collector.collect()
    assert factory.calls == [], "no connection attempt without configured credentials"


# =========================================================================== #
# 3. Connection failure classes: auth / timeout / unreachable
# =========================================================================== #


class AuthenticationException(Exception):  # mimics netmiko's exception naming
    pass


class NetmikoTimeoutException(Exception):
    pass


def test_auth_failure_mapped_to_auth_kind_and_password_sanitized() -> None:
    factory = RecordingFactory(
        error=AuthenticationException(f"Authentication failure: password {ENV_PASS} rejected")
    )
    collector = CiscoIOSCollector("192.168.98.34", connect_factory=factory)
    with pytest.raises(CollectorConnectionError) as excinfo:
        collector.collect()
    assert excinfo.value.kind == "auth"
    assert ENV_PASS not in str(excinfo.value)
    assert "***" in str(excinfo.value)


def test_timeout_failure_mapped_to_timeout_kind() -> None:
    factory = RecordingFactory(error=NetmikoTimeoutException("timed out waiting for SSH banner"))
    collector = CiscoIOSCollector("192.168.98.34", connect_factory=factory)
    with pytest.raises(CollectorConnectionError) as excinfo:
        collector.collect()
    assert excinfo.value.kind == "timeout"


def test_connection_refused_mapped_to_unreachable_kind() -> None:
    factory = RecordingFactory(error=ConnectionRefusedError("refused"))
    collector = CiscoIOSCollector("192.168.98.34", connect_factory=factory)
    with pytest.raises(CollectorConnectionError) as excinfo:
        collector.collect()
    assert excinfo.value.kind == "unreachable"


def test_per_command_timeout_recorded_and_session_closed(full_outputs: dict[str, str]) -> None:
    collector, session, _ = _collector(
        full_outputs, failures={"show ip ospf neighbor": TimeoutError("command read timeout")}
    )
    observations = collector.collect()
    assert session.disconnected is True
    by_cmd = {c.command: c for c in observations.commands}
    assert by_cmd["show ip ospf neighbor"].status == "timeout"
    assert by_cmd["show ip ospf neighbor"].error is not None
    assert ENV_PASS not in (by_cmd["show ip ospf neighbor"].error or "")
    assert observations.status == "partial"
    # parser marks the missing section unavailable instead of inventing rows
    assert observations.ospf_neighbors == []
    assert any("show ip ospf neighbor: not collected" in w for w in observations.warnings)


def test_command_timeout_read_timeout_argument_is_passed(full_outputs: dict[str, str]) -> None:
    collector, session, _ = _collector(full_outputs, command_timeout=42)
    collector.collect()
    assert all(t == 42 for t in session.read_timeouts)


# =========================================================================== #
# 4. IOS 15.2 parsers — from sanitized representative outputs
# =========================================================================== #


def test_parse_show_version_representative() -> None:
    parsed, warnings = ios_parsers.parse_show_version(_read("show_version.txt"))
    assert warnings == []
    assert parsed.hostname == "R2-1"
    assert parsed.ios_version == "15.2(4)M5"
    assert parsed.model == "IOL"


def test_parse_interface_brief_representative() -> None:
    rows, warnings = ios_parsers.parse_show_ip_interface_brief(
        _read("show_ip_interface_brief.txt")
    )
    assert warnings == []
    assert len(rows) == 7
    by_name = {r.name: r for r in rows}
    e02 = by_name["Ethernet0/2"]
    assert e02.ip_address == "192.168.98.34"
    assert e02.admin_state == "up" and e02.oper_state == "up"
    gi1 = by_name["GigabitEthernet0/1"]
    assert gi1.admin_state == "down" and gi1.oper_state == "down"
    assert gi1.status == "administratively down"
    lo0 = by_name["Loopback0"]
    assert lo0.ip_address == "10.255.255.1"
    vlan = by_name["Vlan50"]
    assert vlan.ip_address is None and vlan.oper_state == "down"


def test_parse_route_table_representative() -> None:
    routes, warnings = ios_parsers.parse_show_ip_route(_read("show_ip_route.txt"))
    assert warnings == []
    by_prefix = {r.prefix: r for r in routes}
    # candidate default
    default = by_prefix["0.0.0.0/0"]
    assert default.candidate_default is True
    assert default.protocol == "static"
    assert default.ad == 1 and default.metric == 0
    assert default.next_hops == [
        {"next_hop": "192.168.98.62", "outgoing_interface": "Ethernet0/2"}
    ]
    # connected / local
    connected = by_prefix["192.168.98.32/27"]
    assert connected.protocol == "connected"
    assert connected.next_hops == [{"next_hop": None, "outgoing_interface": "Ethernet0/2"}]
    local = by_prefix["192.168.98.34/32"]
    assert local.protocol == "local"
    # OSPF
    ospf = by_prefix["10.0.12.4/30"]
    assert ospf.protocol == "ospf"
    assert ospf.protocol_code == "O"
    assert ospf.ad == 110 and ospf.metric == 10
    e2 = by_prefix["172.16.0.0/16"]
    assert e2.protocol_code == "O E2"
    # no fabricated entries
    assert len(routes) == 48


def test_parse_route_ecmp_preserves_all_next_hops() -> None:
    routes, _ = ios_parsers.parse_show_ip_route(_read("show_ip_route.txt"))
    by_prefix = {r.prefix: r for r in routes}
    ecmp2 = by_prefix["10.50.0.0/24"]
    assert ecmp2.next_hops == [
        {"next_hop": "10.0.21.2", "outgoing_interface": "Ethernet0/0"},
        {"next_hop": "10.0.22.2", "outgoing_interface": "Ethernet0/1"},
    ]
    ecmp3 = by_prefix["10.100.1.0/24"]
    assert len(ecmp3.next_hops) == 3
    assert ecmp3.next_hops[2] == {
        "next_hop": "192.168.98.62",
        "outgoing_interface": "Ethernet0/2",
    }


def test_parse_ospf_neighbors_representative() -> None:
    rows, warnings = ios_parsers.parse_show_ip_ospf_neighbor(_read("show_ip_ospf_neighbor.txt"))
    assert warnings == []
    assert len(rows) == 3
    assert {r.neighbor_id for r in rows} == {
        "10.255.255.31",
        "10.255.255.2",
        "10.255.255.1",
    }
    assert rows[0].state == "FULL/DR"


def test_parse_cdp_neighbors_representative() -> None:
    rows, warnings = ios_parsers.parse_show_cdp_neighbors(_read("show_cdp_neighbors.txt"))
    assert warnings == []
    assert len(rows) == 4
    assert rows[0].device_id == "R2-3"
    assert rows[0].local_interface == "Ethernet0/0"
    assert rows[0].port_id == "Ethernet0/0"
    assert rows[1].device_id == "R2-1"
    assert {r.device_id for r in rows} == {"R2-1", "R2-2", "R2-3"}


def test_all_parsers_are_deterministic(full_outputs: dict[str, str]) -> None:
    pairs = [
        (ios_parsers.parse_show_version, full_outputs["show version"]),
        (ios_parsers.parse_show_ip_interface_brief, full_outputs["show ip interface brief"]),
        (ios_parsers.parse_show_ip_route, full_outputs["show ip route"]),
        (ios_parsers.parse_show_ip_ospf_neighbor, full_outputs["show ip ospf neighbor"]),
        (ios_parsers.parse_show_cdp_neighbors, full_outputs["show cdp neighbors"]),
    ]
    for parser, text in pairs:
        first = parser(text)
        second = parser(text)
        assert first == second, f"{parser.__name__} is not deterministic"


def test_malformed_route_line_is_marked_not_invented() -> None:
    text = "O 10.9.9.0/24 [110/2] via not-an-ip, garbage\n"
    routes, warnings = ios_parsers.parse_show_ip_route(text)
    assert routes == [] or all(r.next_hops for r in routes)
    assert warnings, "malformed content must produce a warning"


def test_malformed_brief_row_is_skipped_with_warning() -> None:
    text = "Interface IP-Address OK? Method Status Protocol\nthis row is broken\n"
    rows, warnings = ios_parsers.parse_show_ip_interface_brief(text)
    assert rows == []
    assert any("skipped unparseable row" in w for w in warnings)


# =========================================================================== #
# 5. Domain mapping — existing model only, no parallel structures
# =========================================================================== #


def test_map_to_topology_full_collection(full_outputs: dict[str, str]) -> None:
    collector, _, _ = _collector(full_outputs)
    observations = collector.collect()
    topology, warnings = map_to_topology(observations)

    # identity: evidence-based, deterministic
    assert len(topology.devices) == 1
    device = topology.devices[0]
    assert device.id == "r2-1"
    assert device.name == "r2-1"
    assert device.vendor == "cisco"
    assert device.platform == "IOL"
    assert device.metadata["ios_version"] == "15.2(4)M5"

    # interfaces: states + IPs with prefix lengths from connected routes
    assert len(topology.interfaces) == 7
    by_name = {i.name: i for i in topology.interfaces}
    e02 = by_name["Ethernet0/2"]
    assert [str(a) for a in e02.ipv4_addresses] == ["192.168.98.34/27"]
    lo0 = by_name["Loopback0"]
    assert [str(a) for a in lo0.ipv4_addresses] == ["10.255.255.1/32"]
    assert by_name["GigabitEthernet0/1"].admin_state == "down"

    # routes: all mapped, all VRF-scoped, active, on the collected device
    assert len(topology.routes) == len(observations.routes) == 48
    assert all(r.vrf_id == "GLOBAL" for r in topology.routes)
    assert all(r.device_id == "r2-1" for r in topology.routes)
    assert all(r.active is True for r in topology.routes)
    default = next(r for r in topology.routes if str(r.destination_prefix) == "0.0.0.0/0")
    assert str(default.next_hop) == "192.168.98.62"
    assert default.outgoing_interface_id == "r2-1-ethernet0/2"

    # single VRF; no links/endpoints/services fabricated
    assert len(topology.vrfs) == 1 and topology.vrfs[0].id == "GLOBAL"
    assert topology.links == []
    assert topology.endpoints == []
    assert topology.services == []

    # honest warnings
    joined = "\n".join(warnings)
    assert "ECMP" in joined and "10.100.1.0/24" in joined
    assert "adjacency NEVER inferred" in joined
    assert "CDP neighbor row(s) observed" in joined
    assert "AD/metric" in joined


def test_map_preserves_all_ecmp_next_hops_in_observations(full_outputs: dict[str, str]) -> None:
    collector, _, _ = _collector(full_outputs)
    observations = collector.collect()
    topology, warnings = map_to_topology(observations)

    by_prefix = {r["prefix"]: r for r in observations.routes}
    assert len(by_prefix["10.100.1.0/24"]["next_hops"]) == 3
    assert len(by_prefix["10.50.0.0/24"]["next_hops"]) == 2

    ecmp_routes = [
        r
        for r in warnings
        if "ECMP" in r and "ALL preserved in observations" in r
    ]
    assert len(ecmp_routes) == 2
    # model keeps first next-hop only — and says so
    mapped = next(
        r for r in topology.routes if str(r.destination_prefix) == "10.100.1.0/24"
    )
    assert str(mapped.next_hop) == "10.0.21.2"


def test_map_missing_hostname_raises_instead_of_inventing_identity() -> None:
    observations = DeviceObservations(
        host="192.168.98.34",
        device_id=None,
        collected_at="2026-11-14T00:00:00+00:00",
        status="partial",
        warnings=["show version: hostname/uptime line not found (unavailable)"],
    )
    with pytest.raises(CollectorError, match="hostname unavailable"):
        map_to_topology(observations)


def test_interface_ip_without_connected_prefix_marked_unavailable() -> None:
    observations = DeviceObservations(
        host="192.168.98.34",
        device_id="r2-1",
        collected_at="2026-11-14T00:00:00+00:00",
        status="ok",
        identity={"hostname": "R2-1", "ios_version": "15.2(4)M5", "model": "IOL"},
        interfaces=[
            {
                "name": "Ethernet0/5",
                "ip_address": "10.99.9.5",
                "status": "up",
                "protocol": "up",
                "admin_state": "up",
                "oper_state": "up",
            }
        ],
        routes=[],
    )
    topology, warnings = map_to_topology(observations)
    iface = topology.interfaces[0]
    assert iface.ipv4_addresses == [], "IP without known prefix must not be invented"
    assert any("not found in collected routes" in w for w in warnings)


def test_uncollected_sections_never_become_empty_truths(full_outputs: dict[str, str]) -> None:
    """A failed command yields an unavailable section + warning, not 'no data'."""
    collector, _, _ = _collector(
        full_outputs, failures={"show cdp neighbors": RuntimeError("session died")}
    )
    observations = collector.collect()
    topology, _map_warnings = map_to_topology(observations)
    assert observations.cdp_neighbors == []
    assert any("show cdp neighbors: not collected" in w for w in observations.warnings)
    # mapping still succeeds; absence of CDP rows is recorded as uncollected,
    # not as a claim that "the device has no neighbors"
    assert topology.devices[0].id == "r2-1"


# =========================================================================== #
# 6. Secrets never reach observations, logs or errors
# =========================================================================== #


def test_secrets_never_appear_in_observations_or_warnings(full_outputs: dict[str, str]) -> None:
    collector, _, _ = _collector(full_outputs)
    observations = collector.collect()
    serialized = json.dumps(observations.to_dict())
    assert ENV_PASS not in serialized
    assert ENV_USER not in serialized  # username is never stored either
    assert ENV_PASS not in "\n".join(observations.warnings)


def test_secret_in_command_error_is_sanitized(full_outputs: dict[str, str]) -> None:
    collector, _, _ = _collector(
        full_outputs,
        failures={"show version": RuntimeError(f"channel closed after auth {ENV_PASS}")},
    )
    observations = collector.collect()
    error_text = next(c.error or "" for c in observations.commands if c.command == "show version")
    assert ENV_PASS not in error_text
    assert "***" in error_text
