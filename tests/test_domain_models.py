"""Domain model validation tests (TASK-002)."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from nettwin.domain.models import (
    VRF,
    AdminState,
    Device,
    DiagnosticFinding,
    DiagnosticStatus,
    Endpoint,
    EvidenceItem,
    FindingCode,
    FindingSeverity,
    Interface,
    Link,
    LinkState,
    OperState,
    Route,
    Service,
)


def _interface_kwargs(**overrides) -> dict:
    kwargs = {
        "id": "leaf-a1:eth0",
        "device_id": "leaf-a1",
        "name": "eth0",
        "vrf_id": "TENANT_A",
        "ipv4_addresses": ["10.10.10.1/24"],
        "admin_state": "up",
        "oper_state": "up",
    }
    kwargs.update(overrides)
    return kwargs


def _route_kwargs(**overrides) -> dict:
    kwargs = {
        "id": "r1",
        "device_id": "leaf-a1",
        "vrf_id": "TENANT_A",
        "destination_prefix": "10.100.1.0/24",
        "next_hop": "10.100.10.2",
        "protocol": "static",
        "active": True,
    }
    kwargs.update(overrides)
    return kwargs


# --- Device ---


def test_valid_device() -> None:
    device = Device(id="d1", name="Edge", vendor="acme", platform="ios")
    assert device.id == "d1"
    assert device.management_address is None
    assert device.metadata == {}


def test_device_rejects_invalid_management_address() -> None:
    with pytest.raises(ValidationError, match="management_address"):
        Device(
            id="d1",
            name="Edge",
            vendor="acme",
            platform="ios",
            management_address="999.999.1.1",
        )


def test_device_rejects_unknown_fields() -> None:
    with pytest.raises(ValidationError, match="Extra inputs"):
        Device(id="d1", name="Edge", vendor="acme", platform="ios", typo_field="x")


# --- Interface ---


def test_valid_interface_parses_ip_prefixes() -> None:
    iface = Interface(**_interface_kwargs())
    assert iface.admin_state is AdminState.UP
    assert iface.oper_state is OperState.UP
    assert str(iface.ipv4_addresses[0]) == "10.10.10.1/24"
    assert iface.is_up is True


def test_interface_rejects_invalid_ip_address() -> None:
    with pytest.raises(ValidationError, match="ipv4_addresses"):
        Interface(**_interface_kwargs(ipv4_addresses=["999.1.1.1/24"]))


def test_interface_rejects_invalid_admin_state() -> None:
    with pytest.raises(ValidationError, match="admin_state"):
        Interface(**_interface_kwargs(admin_state="enabled"))


def test_interface_reports_down_when_oper_down() -> None:
    iface = Interface(**_interface_kwargs(oper_state="down"))
    assert iface.is_up is False


# --- VRF / Link ---


def test_valid_vrf() -> None:
    vrf = VRF(id="TENANT_A", name="TENANT_A", tenant_id="tenant-a")
    assert vrf.tenant_id == "tenant-a"


def test_link_requires_valid_state() -> None:
    link = Link(
        id="l1",
        source_interface_id="a:eth0",
        destination_interface_id="b:eth0",
        state="up",
    )
    assert link.state is LinkState.UP
    with pytest.raises(ValidationError, match="state"):
        Link(
            id="l2",
            source_interface_id="a:eth0",
            destination_interface_id="b:eth0",
            state="flappy",
        )


# --- Route ---


def test_valid_route() -> None:
    route = Route(**_route_kwargs())
    assert str(route.destination_prefix) == "10.100.1.0/24"
    assert route.active is True


def test_route_rejects_invalid_destination_prefix() -> None:
    with pytest.raises(ValidationError, match="destination_prefix"):
        Route(**_route_kwargs(destination_prefix="not-a-prefix"))


def test_route_rejects_invalid_next_hop() -> None:
    with pytest.raises(ValidationError, match="next_hop"):
        Route(**_route_kwargs(next_hop="10.0.0.999"))


def test_route_requires_forwarding_reference() -> None:
    with pytest.raises(ValidationError, match="next_hop and/or outgoing_interface_id"):
        Route(**_route_kwargs(next_hop=None, outgoing_interface_id=None))


def test_route_allows_connected_without_next_hop() -> None:
    route = Route(
        id="conn",
        device_id="leaf-a1",
        vrf_id="TENANT_A",
        destination_prefix="10.10.10.0/24",
        outgoing_interface_id="leaf-a1:eth0",
        protocol="connected",
        active=True,
    )
    assert route.next_hop is None


# --- Endpoint / Service ---


def test_valid_endpoint() -> None:
    endpoint = Endpoint(
        id="ep-a-app", name="App", ip_address="10.10.10.10", vrf_id="TENANT_A"
    )
    assert str(endpoint.ip_address) == "10.10.10.10"
    assert endpoint.device_id is None


def test_endpoint_rejects_invalid_ip() -> None:
    with pytest.raises(ValidationError, match="ip_address"):
        Endpoint(
            id="ep", name="App", ip_address="10.10.10.999", vrf_id="TENANT_A"
        )


def test_two_endpoints_may_share_ip_across_vrfs() -> None:
    a = Endpoint(id="ep-a", name="A", ip_address="10.10.10.10", vrf_id="TENANT_A")
    b = Endpoint(id="ep-b", name="B", ip_address="10.10.10.10", vrf_id="TENANT_B")
    assert a.ip_address == b.ip_address
    assert a.id != b.id
    assert a.vrf_id != b.vrf_id


def test_service_port_range_and_protocol_normalization() -> None:
    service = Service(
        id="svc",
        name="PostgreSQL",
        endpoint_id="ep-pg",
        protocol="TCP",
        port=5432,
        allowed_vrfs=["TENANT_A"],
    )
    assert service.protocol == "tcp"
    with pytest.raises(ValidationError, match="port"):
        Service(
            id="svc2",
            name="Bad",
            endpoint_id="ep-pg",
            protocol="tcp",
            port=70000,
        )


# --- DiagnosticFinding / Evidence ---


def test_diagnostic_finding_valid() -> None:
    finding = DiagnosticFinding(
        id="f1",
        code=FindingCode.MISSING_ROUTE,
        severity=FindingSeverity.HIGH,
        title="Missing route",
        description="No active route covers 10.100.1.20",
        vrf_id="TENANT_A",
        evidence=[
            EvidenceItem(
                type="route_lookup",
                device_id="leaf-a1",
                vrf_id="TENANT_A",
                destination="10.100.1.20",
                matched_route=None,
                result="no_matching_route",
            )
        ],
        recommendations=["Add a static route"],
        status=DiagnosticStatus.UNREACHABLE,
    )
    assert finding.code is FindingCode.MISSING_ROUTE
    dumped = finding.evidence[0].model_dump()
    assert dumped["type"] == "route_lookup"
    assert dumped["result"] == "no_matching_route"
    assert dumped["matched_route"] is None


def test_diagnostic_finding_rejects_invalid_severity() -> None:
    with pytest.raises(ValidationError, match="severity"):
        DiagnosticFinding(
            id="f1",
            code=FindingCode.INSUFFICIENT_DATA,
            severity="urgent",
            title="t",
            description="d",
            status=DiagnosticStatus.UNKNOWN,
        )


def test_diagnostic_finding_rejects_unknown_status() -> None:
    with pytest.raises(ValidationError, match="status"):
        DiagnosticFinding(
            id="f1",
            code=FindingCode.INSUFFICIENT_DATA,
            severity=FindingSeverity.LOW,
            title="t",
            description="d",
            status="maybe",
        )
