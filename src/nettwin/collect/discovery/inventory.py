"""Multi-device inventory (Phase 2.2, Task 1).

The inventory describes *where* devices are — never *how to log in*. There is
no field for a username, password, key, or enable secret, and an inventory
containing such a field is rejected instead of quietly ignored: a credential
committed to a YAML file is exactly the failure mode this rule prevents.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from nettwin.errors import NetTwinError

#: Field names that must never appear anywhere in an inventory document.
FORBIDDEN_CREDENTIAL_KEYS: frozenset[str] = frozenset(
    {
        "username",
        "user",
        "password",
        "passwd",
        "secret",
        "enable",
        "enable_secret",
        "ssh_key",
        "private_key",
        "key",
        "token",
        "community",  # SNMP community — out of scope for 2.2 but must stay out
    }
)

SUPPORTED_PLATFORMS: frozenset[str] = frozenset({"cisco_ios"})


class InventoryError(NetTwinError):
    """The inventory file is missing, malformed, or contains forbidden fields."""


@dataclass(frozen=True)
class DeviceEntry:
    """One device to collect from."""

    name: str
    host: str
    platform: str = "cisco_ios"
    port: int = 22


@dataclass
class Inventory:
    """A validated inventory: an ordered, duplicate-free list of devices."""

    devices: list[DeviceEntry] = field(default_factory=list)
    source: str | None = None

    def __len__(self) -> int:
        return len(self.devices)

    def __iter__(self):
        return iter(self.devices)

    def by_name(self, name: str) -> DeviceEntry | None:
        for entry in self.devices:
            if entry.name == name:
                return entry
        return None


def _find_forbidden_keys(node: Any, path: str = "inventory") -> list[str]:
    """Walk the parsed YAML and collect any credential-looking key."""
    found: list[str] = []
    if isinstance(node, dict):
        for key, value in node.items():
            key_text = str(key).strip().lower()
            if key_text in FORBIDDEN_CREDENTIAL_KEYS:
                found.append(f"{path}.{key}")
            found.extend(_find_forbidden_keys(value, f"{path}.{key}"))
    elif isinstance(node, list):
        for index, item in enumerate(node):
            found.extend(_find_forbidden_keys(item, f"{path}[{index}]"))
    return found


def load_inventory(source: str | Path | dict[str, Any]) -> Inventory:
    """Load and validate an inventory from a YAML path or an already-parsed dict.

    Args:
        source: Path to a ``.yaml``/``.yml`` inventory, or a mapping with a
            top-level ``devices`` list.

    Returns:
        A validated :class:`Inventory` preserving the file order.

    Raises:
        InventoryError: On a missing file, invalid YAML, forbidden credential
            fields, missing/invalid device fields, an unsupported platform, or
            two devices sharing a name or a host.
    """
    if isinstance(source, (str, Path)):
        path = Path(source)
        if not path.exists():
            raise InventoryError(f"inventory file not found: {path}")
        if path.suffix.lower() not in {".yaml", ".yml"}:
            raise InventoryError(
                f"unsupported inventory file type {path.suffix!r} "
                f"(expected .yaml or .yml) for {path}"
            )
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            raise InventoryError(f"invalid YAML in {path}: {exc}") from exc
        origin = str(path)
    else:
        data = source
        origin = None

    forbidden = _find_forbidden_keys(data)
    if forbidden:
        raise InventoryError(
            "inventory must not contain credentials — found "
            f"{', '.join(forbidden)}. Credentials come from "
            "NETTWIN_DEVICE_USERNAME / NETTWIN_DEVICE_PASSWORD only."
        )

    if not isinstance(data, dict):
        raise InventoryError(
            f"inventory root must be a mapping with a 'devices' list, "
            f"got {type(data).__name__}"
        )
    raw_devices = data.get("devices")
    if not isinstance(raw_devices, list) or not raw_devices:
        raise InventoryError("inventory must contain a non-empty 'devices' list")

    devices: list[DeviceEntry] = []
    seen_names: dict[str, int] = {}
    seen_hosts: dict[str, int] = {}
    for index, raw in enumerate(raw_devices):
        location = f"devices[{index}]"
        if not isinstance(raw, dict):
            raise InventoryError(f"{location} must be a mapping")
        unknown = set(raw) - {"name", "host", "platform", "port"}
        if unknown:
            raise InventoryError(
                f"{location} has unsupported field(s) {', '.join(sorted(unknown))} "
                "(allowed: name, host, platform, port)"
            )
        name = str(raw.get("name", "")).strip()
        host = str(raw.get("host", "")).strip()
        platform = str(raw.get("platform", "cisco_ios")).strip()
        port = raw.get("port", 22)
        if not name:
            raise InventoryError(f"{location} is missing 'name'")
        if not host:
            raise InventoryError(f"{location} ({name}) is missing 'host'")
        if platform not in SUPPORTED_PLATFORMS:
            raise InventoryError(
                f"{location} ({name}) has unsupported platform {platform!r} "
                f"(supported: {', '.join(sorted(SUPPORTED_PLATFORMS))})"
            )
        if not isinstance(port, int) or not (1 <= port <= 65535):
            raise InventoryError(f"{location} ({name}) has invalid port {port!r}")
        if name in seen_names:
            raise InventoryError(
                f"{location} duplicates device name {name!r} "
                f"(already used by devices[{seen_names[name]}])"
            )
        if host in seen_hosts:
            raise InventoryError(
                f"{location} ({name}) duplicates host {host!r} "
                f"(already used by devices[{seen_hosts[host]}])"
            )
        seen_names[name] = index
        seen_hosts[host] = index
        devices.append(DeviceEntry(name=name, host=host, platform=platform, port=port))

    return Inventory(devices=devices, source=origin)
