#!/usr/bin/env python3
"""Read-only Cisco IOS collection CLI (Phase 2 MVP).

Runs on the OPERATOR machine (Ubuntu), never in the sandbox. Reads
credentials from environment variables only (never argv — process listings
would leak them):

    export NETTWIN_DEVICE_USERNAME='...'
    export NETTWIN_DEVICE_PASSWORD='...'

Usage:
    python scripts/collect_cisco.py --host 192.168.98.34
    python scripts/collect_cisco.py --host 192.168.98.34 --raw-dir collected/raw
    python scripts/collect_cisco.py --host 192.168.98.34 --command "show version"

Only the five allowlisted read-only commands can be dispatched; anything
else is rejected before a connection is attempted. Requires the optional
extra: pip install -e ".[collect]"

Exit codes: 0 = ok, 1 = config/connection/allowlist error, 2 = partial.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

import yaml  # noqa: E402

from nettwin.collect.cisco_ios import (  # noqa: E402
    READ_ONLY_COMMANDS,
    AllowlistViolation,
    CiscoIOSCollector,
    CollectorConfigError,
    CollectorConnectionError,
    CollectorError,
    map_to_topology,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Read-only Cisco IOS collector (allowlisted commands only)."
    )
    parser.add_argument("--host", required=True, help="device IP or hostname (e.g. 192.168.98.34)")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default 22)")
    parser.add_argument(
        "--out",
        default=None,
        help="output directory (default: collected/ next to this script's repo root)",
    )
    parser.add_argument(
        "--raw-dir",
        default=None,
        help="optional directory to also dump raw per-command outputs (evidence)",
    )
    parser.add_argument(
        "--command",
        action="append",
        default=None,
        help="run a subset of the allowlist (repeatable); must be exact allowlist entries",
    )
    parser.add_argument("--connect-timeout", type=int, default=15, help="SSH connect timeout (s)")
    parser.add_argument("--command-timeout", type=int, default=30, help="per-command timeout (s)")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    out_dir = Path(args.out) if args.out else REPO_ROOT / "collected"
    out_dir.mkdir(parents=True, exist_ok=True)

    collector = CiscoIOSCollector(
        args.host,
        port=args.port,
        connect_timeout=args.connect_timeout,
        command_timeout=args.command_timeout,
    )

    try:
        observations = collector.collect(commands=args.command)
    except AllowlistViolation as exc:
        print(f"REJECTED (pre-connection): {exc}", file=sys.stderr)
        return 1
    except CollectorConfigError as exc:
        print(f"CONFIG ERROR: {exc}", file=sys.stderr)
        return 1
    except CollectorConnectionError as exc:
        print(f"CONNECTION ERROR [{exc.kind}]: {exc}", file=sys.stderr)
        hints = {
            "auth": "check NETTWIN_DEVICE_USERNAME/PASSWORD and the IOS 'secret' "
                    "for the dedicated read-only account",
            "timeout": "check TCP/22 reachability (nc -vz <host> 22) and that SSH "
                       "is enabled on the device",
            "unreachable": "check routing from this host: ip route get <host>; "
                           "ping -c3 -W2 <host>",
        }
        print(f"  hint: {hints.get(exc.kind, '')}", file=sys.stderr)
        return 1
    except CollectorError as exc:
        print(f"COLLECTOR ERROR: {exc}", file=sys.stderr)
        return 1

    # Persist evidence + model output ------------------------------------- #
    stamp = observations.collected_at.replace(":", "").replace("-", "")
    topology_path = out_dir / f"{args.host}.topology.yaml"
    observations_path = out_dir / f"{args.host}.observations.yaml"
    try:
        topology, map_warnings = map_to_topology(observations)
        topology_path.write_text(
            yaml.safe_dump(topology.model_dump(mode="json"), sort_keys=False, allow_unicode=True),
            encoding="utf-8",
        )
        map_failure = None
    except CollectorError as exc:
        topology, map_warnings, map_failure = None, [], str(exc)

    observations_path.write_text(
        yaml.safe_dump(observations.to_dict(), sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )

    if args.raw_dir:
        raw_dir = Path(args.raw_dir)
        raw_dir.mkdir(parents=True, exist_ok=True)
        for result in observations.commands:
            if result.status == "ok":
                safe_name = result.command.replace(" ", "_")
                (raw_dir / f"{args.host}.{safe_name}.{stamp}.txt").write_text(
                    result.output, encoding="utf-8"
                )

    # Summary (no raw outputs, no credentials) ----------------------------- #
    print(f"device     : {observations.device_id or '<unavailable>'} ({observations.host})")
    print(f"collected  : {observations.collected_at}")
    print(f"status     : {observations.status}")
    for result in observations.commands:
        line = f"  - {result.command:<26} {result.status:<8} {result.duration_s:.2f}s"
        if result.error:
            line += f"  error={result.error}"
        print(line)
    if topology is not None:
        print(
            f"model      : {len(topology.devices)} device, "
            f"{len(topology.interfaces)} interfaces, {len(topology.routes)} routes "
            f"-> {topology_path}"
        )
    else:
        print(f"model      : NOT MAPPED — {map_failure}")
    print(f"evidence   : {observations_path}")
    print(f"warnings   : {len(observations.warnings) + len(map_warnings)}")
    for warning in [*observations.warnings, *map_warnings]:
        print(f"  ! {warning}")
    print(
        f"allowlist  : {len(READ_ONLY_COMMANDS)} read-only commands; "
        "no configuration was or can be sent by this tool"
    )

    if map_failure is not None:
        return 1
    return 0 if observations.status == "ok" else 2


if __name__ == "__main__":
    raise SystemExit(main())
