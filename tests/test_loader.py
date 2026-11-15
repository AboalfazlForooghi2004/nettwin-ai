"""YAML loader and topology validation tests (TASK-002)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from nettwin.data.loader import load_topology, load_topology_dict
from nettwin.errors import TopologyValidationError

BASE_TOPOLOGY: dict[str, Any] = {
    "devices": [
        {"id": "leaf-a1", "name": "Leaf A1", "vendor": "acme", "platform": "vxlan"},
        {"id": "leaf-b1", "name": "Leaf B1", "vendor": "acme", "platform": "vxlan"},
    ],
    "vrfs": [
        {"id": "TENANT_A", "name": "TENANT_A", "tenant_id": "tenant-a"},
        {"id": "TENANT_B", "name": "TENANT_B", "tenant_id": "tenant-b"},
    ],
    "interfaces": [
        {
            "id": "leaf-a1:eth0",
            "device_id": "leaf-a1",
            "name": "eth0",
            "vrf_id": "TENANT_A",
            "ipv4_addresses": ["10.10.10.1/24"],
            "admin_state": "up",
            "oper_state": "up",
        },
        {
            "id": "leaf-b1:eth0",
            "device_id": "leaf-b1",
            "name": "eth0",
            "vrf_id": "TENANT_B",
            "ipv4_addresses": ["10.10.10.1/24"],
            "admin_state": "up",
            "oper_state": "up",
        },
    ],
    "links": [],
    "routes": [
        {
            "id": "leaf-a1-conn",
            "device_id": "leaf-a1",
            "vrf_id": "TENANT_A",
            "destination_prefix": "10.10.10.0/24",
            "outgoing_interface_id": "leaf-a1:eth0",
            "protocol": "connected",
            "active": True,
        }
    ],
    "endpoints": [
        {
            "id": "ep-a-app",
            "name": "App A",
            "ip_address": "10.10.10.10",
            "vrf_id": "TENANT_A",
            "device_id": "leaf-a1",
        },
        {
            "id": "ep-b-app",
            "name": "App B",
            "ip_address": "10.10.10.10",
            "vrf_id": "TENANT_B",
            "device_id": "leaf-b1",
        },
    ],
    "services": [],
}


def _clone() -> dict[str, Any]:
    import copy

    return copy.deepcopy(BASE_TOPOLOGY)


# --- Happy path ---


def test_valid_topology_loads() -> None:
    topology = load_topology_dict(_clone())
    assert len(topology.devices) == 2
    assert len(topology.vrfs) == 2
    assert len(topology.endpoints) == 2


def test_overlapping_prefixes_across_vrfs_are_allowed() -> None:
    topology = load_topology_dict(_clone())
    # Both tenant interfaces use 10.10.10.1/24 in different VRFs.
    address_sets = {
        iface.vrf_id: [str(a) for a in iface.ipv4_addresses]
        for iface in topology.interfaces
    }
    assert address_sets["TENANT_A"] == ["10.10.10.1/24"]
    assert address_sets["TENANT_B"] == ["10.10.10.1/24"]
    # Same endpoint IP in both VRFs — distinct logical endpoints.
    ips = {(e.id, e.vrf_id, str(e.ip_address)) for e in topology.endpoints}
    assert ips == {
        ("ep-a-app", "TENANT_A", "10.10.10.10"),
        ("ep-b-app", "TENANT_B", "10.10.10.10"),
    }


# --- Structural errors ---


def test_root_must_be_mapping() -> None:
    with pytest.raises(TopologyValidationError, match="must be a mapping"):
        load_topology_dict(["not", "a", "mapping"])


def test_duplicate_device_ids_rejected() -> None:
    data = _clone()
    data["devices"].append(dict(data["devices"][0]))
    with pytest.raises(TopologyValidationError, match=r"duplicate devices id.*leaf-a1"):
        load_topology_dict(data)


def test_duplicate_ids_rejected_across_each_collection() -> None:
    data = _clone()
    data["endpoints"].append(dict(data["endpoints"][0]))
    with pytest.raises(TopologyValidationError, match="duplicate endpoints id"):
        load_topology_dict(data)


def test_unknown_vrf_reference_rejected() -> None:
    data = _clone()
    data["interfaces"][0]["vrf_id"] = "NO_SUCH_VRF"
    with pytest.raises(
        TopologyValidationError,
        match=r"interface 'leaf-a1:eth0' references unknown VRF 'NO_SUCH_VRF'",
    ):
        load_topology_dict(data)


def test_unknown_device_reference_rejected() -> None:
    data = _clone()
    data["interfaces"][0]["device_id"] = "ghost-device"
    with pytest.raises(
        TopologyValidationError,
        match=r"interface 'leaf-a1:eth0' references unknown device 'ghost-device'",
    ):
        load_topology_dict(data)


def test_invalid_link_interface_reference_rejected() -> None:
    data = _clone()
    data["links"].append(
        {
            "id": "bad-link",
            "source_interface_id": "leaf-a1:eth0",
            "destination_interface_id": "missing:eth9",
            "state": "up",
        }
    )
    with pytest.raises(
        TopologyValidationError,
        match=r"link 'bad-link' references unknown interface 'missing:eth9'",
    ):
        load_topology_dict(data)


def test_self_link_rejected() -> None:
    data = _clone()
    data["links"].append(
        {
            "id": "loop-link",
            "source_interface_id": "leaf-a1:eth0",
            "destination_interface_id": "leaf-a1:eth0",
            "state": "up",
        }
    )
    with pytest.raises(TopologyValidationError, match="to itself"):
        load_topology_dict(data)


def test_invalid_route_references_rejected() -> None:
    data = _clone()
    data["routes"][0]["device_id"] = "ghost"
    data["routes"][0]["vrf_id"] = "GHOST_VRF"
    data["routes"][0]["outgoing_interface_id"] = "ghost:eth0"
    with pytest.raises(TopologyValidationError) as exc_info:
        load_topology_dict(data)
    message = str(exc_info.value)
    assert "route 'leaf-a1-conn' references unknown device 'ghost'" in message
    assert "route 'leaf-a1-conn' references unknown VRF 'GHOST_VRF'" in message
    assert "route 'leaf-a1-conn' references unknown interface 'ghost:eth0'" in message


def test_route_outgoing_interface_must_belong_to_route_device() -> None:
    data = _clone()
    # leaf-b1's interface cannot be the outgoing interface of a leaf-a1 route.
    data["routes"][0]["outgoing_interface_id"] = "leaf-b1:eth0"
    with pytest.raises(
        TopologyValidationError,
        match=(
            r"route 'leaf-a1-conn' outgoing interface 'leaf-b1:eth0' "
            r"belongs to device 'leaf-b1', not 'leaf-a1'"
        ),
    ):
        load_topology_dict(data)


def test_unknown_endpoint_vrf_and_device_rejected() -> None:
    data = _clone()
    data["endpoints"][0]["vrf_id"] = "NOPE"
    data["endpoints"][0]["device_id"] = "NOPE_DEV"
    with pytest.raises(TopologyValidationError) as exc_info:
        load_topology_dict(data)
    message = str(exc_info.value)
    assert "endpoint 'ep-a-app' references unknown VRF 'NOPE'" in message
    assert "endpoint 'ep-a-app' references unknown device 'NOPE_DEV'" in message


def test_unknown_service_references_rejected() -> None:
    data = _clone()
    data["services"].append(
        {
            "id": "svc-x",
            "name": "X",
            "endpoint_id": "ghost-ep",
            "protocol": "tcp",
            "port": 443,
            "allowed_vrfs": ["TENANT_A", "GHOST_VRF"],
        }
    )
    with pytest.raises(TopologyValidationError) as exc_info:
        load_topology_dict(data)
    message = str(exc_info.value)
    assert "service 'svc-x' references unknown endpoint 'ghost-ep'" in message
    assert "service 'svc-x' references unknown VRF 'GHOST_VRF'" in message


def test_invalid_ip_in_yaml_content_rejected() -> None:
    data = _clone()
    data["interfaces"][0]["ipv4_addresses"] = ["999.1.1.1/24"]
    with pytest.raises(TopologyValidationError, match="ipv4_addresses"):
        load_topology_dict(data)


def test_validation_error_lists_every_problem() -> None:
    data = _clone()
    data["interfaces"][0]["vrf_id"] = "NOPE"
    data["endpoints"][0]["device_id"] = "GHOST"
    with pytest.raises(TopologyValidationError) as exc_info:
        load_topology_dict(data)
    message = str(exc_info.value)
    assert "unknown VRF 'NOPE'" in message
    assert "unknown device 'GHOST'" in message


# --- File loading ---


def test_load_topology_from_yaml_file(tmp_path: Path) -> None:
    yaml_text = """
devices:
  - id: d1
    name: Device One
    vendor: acme
    platform: ios
"""
    path = tmp_path / "topology.yaml"
    path.write_text(yaml_text, encoding="utf-8")
    topology = load_topology(path)
    assert topology.devices[0].id == "d1"


def test_missing_file_rejected(tmp_path: Path) -> None:
    with pytest.raises(TopologyValidationError, match="topology file not found"):
        load_topology(tmp_path / "does-not-exist.yaml")


def test_unsupported_extension_rejected(tmp_path: Path) -> None:
    path = tmp_path / "topology.json"
    path.write_text("{}", encoding="utf-8")
    with pytest.raises(TopologyValidationError, match="unsupported topology file type"):
        load_topology(path)


def test_malformed_yaml_rejected(tmp_path: Path) -> None:
    path = tmp_path / "broken.yaml"
    path.write_text("devices: [unclosed\n  - id:", encoding="utf-8")
    with pytest.raises(TopologyValidationError, match="invalid YAML"):
        load_topology(path)


def test_file_error_message_includes_path(tmp_path: Path) -> None:
    path = tmp_path / "bad.yaml"
    path.write_text("devices:\n  - id: d1\n    name: n\n", encoding="utf-8")
    with pytest.raises(TopologyValidationError, match="bad.yaml"):
        load_topology(path)
