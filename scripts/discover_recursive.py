#!/usr/bin/env python3
"""Recursive multi-hop discovery CLI (Phase 2.3).

Only the seed device is required. Everything else is discovered through CDP
and reached over the IOS CLI's own nested ``ssh`` — the tested lab path::

    Ubuntu -> R2-1 -> R2-2 -> R2-4

Credentials come from the same environment variables as every earlier phase
(never argv, never a file):

    export NETTWIN_DEVICE_USERNAME='nettwin-ro'
    export NETTWIN_DEVICE_PASSWORD='...'

Usage:
    # validate the plan without connecting
    python scripts/discover_recursive.py --seed 192.168.98.34 --dry-run

    # real recursive discovery
    python scripts/discover_recursive.py --seed 192.168.98.34 \\
        --output-dir collected/recursive

    # bounded walk
    python scripts/discover_recursive.py --seed 192.168.98.34 \\
        --max-depth 2 --max-devices 5

Only the read-only allowlist is ever dispatched (the Phase-2 five plus
``show cdp neighbors detail``). Nothing on the devices is configured.

Exit codes: 0 = ok, 1 = config/setup error, 2 = partial (some devices
unreachable), 3 = the seed itself could not be collected.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

import yaml  # noqa: E402

from nettwin.collect.cisco_ios import READ_ONLY_COMMANDS  # noqa: E402
from nettwin.collect.nested.discovery import (  # noqa: E402
    DISCOVERY_COMMANDS,
    DeviceStatus,
    RecursiveDiscovery,
)
from nettwin.collect.nested.netmiko_transport import (  # noqa: E402
    netmiko_nested_transport,
    netmiko_root_session,
)
from nettwin.collect.nested.session import SessionLimits  # noqa: E402

USERNAME_ENV = "NETTWIN_DEVICE_USERNAME"
PASSWORD_ENV = "NETTWIN_DEVICE_PASSWORD"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Recursive Cisco IOS topology discovery: collect the seed, then "
            "follow CDP with nested SSH (read-only, allowlisted commands only)."
        )
    )
    parser.add_argument("--seed", required=True, help="seed device IP or hostname")
    parser.add_argument("--port", type=int, default=22, help="SSH port for the seed (default 22)")
    parser.add_argument(
        "--output-dir",
        default=None,
        help="output directory (default: collected/recursive next to the repo root)",
    )
    parser.add_argument("--max-depth", type=int, default=4, help="maximum SSH nesting depth")
    parser.add_argument("--max-devices", type=int, default=16, help="maximum devices to collect")
    parser.add_argument("--connect-timeout", type=float, default=20.0, help="seconds per handshake")
    parser.add_argument("--command-timeout", type=float, default=30.0, help="seconds per command")
    parser.add_argument(
        "--max-attempts", type=int, default=2, help="maximum SSH attempts per device"
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="print the plan and exit (no connection)"
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    import os

    username = os.environ.get(USERNAME_ENV)
    password = os.environ.get(PASSWORD_ENV)

    print(f"seed       : {args.seed}:{args.port}")
    print(f"limits     : depth<={args.max_depth}, devices<={args.max_devices}, "
          f"attempts<={args.max_attempts}")
    print(f"allowlist  : {len(READ_ONLY_COMMANDS)} read-only commands "
          f"({len(DISCOVERY_COMMANDS)} used for discovery)")
    print("path       : workstation -> seed -> neighbour (nested ssh on the IOS CLI)")

    if args.dry_run:
        print("dry-run    : no connection attempted")
        return 0

    if not username or not password:
        print(
            f"CONFIG ERROR: set {USERNAME_ENV} and {PASSWORD_ENV} "
            "in the environment (values are never logged)",
            file=sys.stderr,
        )
        return 1

    limits = SessionLimits(
        connect_timeout=args.connect_timeout,
        command_timeout=args.command_timeout,
        max_devices=args.max_devices,
        max_depth=args.max_depth,
        max_attempts_per_device=args.max_attempts,
    )

    discovery = RecursiveDiscovery(
        seed_host=args.seed,
        username=username,
        password=password,
        limits=limits,
        root_factory=lambda host, pw: netmiko_root_session(
            host, pw, username=username, port=args.port, limits=limits
        ),
        nested_factory=netmiko_nested_transport,
    )

    try:
        result = discovery.run()
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130

    # ---- reporting ---------------------------------------------------------
    print("\ndiscovered :")
    for node in sorted(result.nodes, key=lambda n: (n.depth, n.identity)):
        marker = "OK " if node.collected else "-- "
        reason = f"  ({node.error})" if node.error else ""
        print(f"  {marker}{node.identity:<24} depth={node.depth} "
              f"path={' -> '.join(node.path)}{reason}")

    if result.edges:
        print("cdp edges  :")
        for edge in result.edges:
            print(f"  * {edge.source} [{edge.local_interface}] <-> "
                  f"{edge.target} [{edge.remote_interface}]"
                  + (f"  via {edge.target_ip}" if edge.target_ip else ""))

    output_dir = (
        Path(args.output_dir) if args.output_dir else REPO_ROOT / "collected" / "recursive"
    )
    output_dir.mkdir(parents=True, exist_ok=True)

    if result.topology is not None:
        topology_path = output_dir / "topology.yaml"
        topology_path.write_text(
            yaml.safe_dump(
                result.topology.model_dump(mode="json"), sort_keys=False, allow_unicode=True
            ),
            encoding="utf-8",
        )
        print(f"\nmerged     : {len(result.topology.devices)} devices, "
              f"{len(result.topology.interfaces)} interfaces, "
              f"{len(result.topology.routes)} routes -> {topology_path}")
    else:
        print("\nmerged     : nothing collected")

    report = {
        "seed": args.seed,
        "limits": {
            "max_depth": args.max_depth,
            "max_devices": args.max_devices,
            "max_attempts": args.max_attempts,
            "connect_timeout": args.connect_timeout,
            "command_timeout": args.command_timeout,
        },
        "nodes": [
            {
                "identity": n.identity,
                "display_name": n.display_name,
                "status": str(n.status),
                "depth": n.depth,
                "path": n.path,
                "parent": n.parent,
                "interfaces": n.interfaces,
                "error": n.error,
            }
            for n in result.nodes
        ],
        "edges": [
            {
                "source": e.source,
                "target": e.target,
                "local_interface": e.local_interface,
                "remote_interface": e.remote_interface,
                "target_ip": e.target_ip,
            }
            for e in result.edges
        ],
        "stats": {"visits": result.visits, "ssh_attempts": result.ssh_attempts},
        "warnings": result.warnings,
    }
    discovery_path = output_dir / "discovery.yaml"
    discovery_path.write_text(
        yaml.safe_dump(report, sort_keys=False, allow_unicode=True), encoding="utf-8"
    )

    print(f"discovery  : {discovery_path}")
    print(f"stats      : {result.visits} visit(s), {result.ssh_attempts} nested ssh attempt(s)")
    print(f"warnings   : {len(result.warnings)}")
    for warning in result.warnings:
        print(f"  ! {warning}")

    seed_node = next((n for n in result.nodes if n.depth == 0), None)
    if seed_node is None or not seed_node.collected:
        return 3
    if any(n.status is not DeviceStatus.COLLECTED for n in result.nodes):
        return 2
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        raise SystemExit(130) from None
