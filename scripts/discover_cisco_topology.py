#!/usr/bin/env python3
"""Multi-device Cisco IOS topology discovery CLI (Phase 2.2).

Runs on the OPERATOR machine (Ubuntu). Credentials are never passed on the
command line — they come from the same environment variables as Phase 2.1:

    export NETTWIN_DEVICE_USERNAME='...'
    export NETTWIN_DEVICE_PASSWORD='...'

Usage:
    python scripts/discover_cisco_topology.py --inventory fixtures/pnetlab_inventory.yaml
    python scripts/discover_cisco_topology.py \
        --inventory fixtures/pnetlab_inventory.yaml --output-dir collected/multi
    python scripts/discover_cisco_topology.py --inventory inv.yaml --no-links
    python scripts/discover_cisco_topology.py --inventory inv.yaml --dry-run

Only the five allowlisted read-only commands are ever dispatched (unchanged
from Phase 2.1). Links are created **only** from mutually consistent CDP
evidence from both ends; one-sided CDP never becomes a link.

Exit codes: 0 = all devices collected, 1 = config/inventory/allowlist error,
2 = partial (at least one device failed), 3 = no device collected.
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
    CollectorConfigError,
    CollectorConnectionError,
)
from nettwin.collect.discovery import (  # noqa: E402
    InventoryError,
    load_inventory,
)
from nettwin.collect.discovery.merge import MergeError  # noqa: E402
from nettwin.collect.discovery.pipeline import discover_topology  # noqa: E402


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Read-only multi-device Cisco IOS discovery: collect an inventory, "
            "merge the devices into one topology, and build links only from "
            "two-sided CDP evidence."
        )
    )
    parser.add_argument(
        "--inventory",
        required=True,
        help="inventory YAML (devices: name/host/platform — no credentials)",
    )
    parser.add_argument(
        "--output-dir",
        default=None,
        help="directory for per-device observations and the merged topology "
        "(default: collected/multi next to the repo root)",
    )
    parser.add_argument(
        "--no-links",
        action="store_true",
        help="merge devices but do not derive links from CDP",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="validate the inventory and print the plan; no SSH connection is made",
    )
    parser.add_argument(
        "--no-raw",
        action="store_true",
        help="do not write per-command raw outputs (evidence) next to observations",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        inventory = load_inventory(args.inventory)
    except InventoryError as exc:
        print(f"INVENTORY ERROR: {exc}", file=sys.stderr)
        return 1

    print(f"inventory  : {args.inventory} ({len(inventory)} device(s))")
    for entry in inventory:
        print(f"  - {entry.name:<10} {entry.host:<16} platform={entry.platform} port={entry.port}")

    if args.dry_run:
        print("plan       : sequential collection, then CDP two-sided link discovery")
        print(
            f"allowlist  : {len(READ_ONLY_COMMANDS)} read-only commands "
            "(unchanged from Phase 2.1)"
        )
        print("dry-run    : no connection attempted")
        return 0

    output_dir = Path(args.output_dir) if args.output_dir else REPO_ROOT / "collected" / "multi"
    output_dir.mkdir(parents=True, exist_ok=True)

    try:
        report = discover_topology(inventory, collect_links=not args.no_links)
    except (CollectorConfigError, AllowlistViolation) as exc:
        print(f"CONFIG ERROR: {exc}", file=sys.stderr)
        return 1
    except MergeError as exc:
        print(f"MERGE ERROR: {exc}", file=sys.stderr)
        return 1

    # ---- per-device evidence ------------------------------------------------
    per_device_dir = output_dir / "devices"
    per_device_dir.mkdir(parents=True, exist_ok=True)
    for collection in report.collections:
        name = _safe_name(collection.entry_name)
        if collection.observations is not None:
            (per_device_dir / f"{name}.observations.yaml").write_text(
                yaml.safe_dump(
                    collection.observations.to_dict(), sort_keys=False, allow_unicode=True
                ),
                encoding="utf-8",
            )
            if not args.no_raw:
                raw_dir = per_device_dir / f"{name}.raw"
                raw_dir.mkdir(exist_ok=True)
                for result in collection.observations.commands:
                    if result.status == "ok":
                        command_file = result.command.replace(" ", "_")
                        (raw_dir / f"{command_file}.txt").write_text(
                            result.output, encoding="utf-8"
                        )
        if collection.topology is not None:
            (per_device_dir / f"{name}.topology.yaml").write_text(
                yaml.safe_dump(
                    collection.topology.model_dump(mode="json"),
                    sort_keys=False,
                    allow_unicode=True,
                ),
                encoding="utf-8",
            )

    # ---- merged topology + provenance --------------------------------------
    if report.topology is None:
        print("\nRESULT: no device collected — nothing merged", file=sys.stderr)
        for name, error in sorted(report.failures.items()):
            print(f"  ! {name}: {error}", file=sys.stderr)
        return 3

    merged_path = output_dir / "topology.yaml"
    merged_path.write_text(
        yaml.safe_dump(
            report.topology.model_dump(mode="json"), sort_keys=False, allow_unicode=True
        ),
        encoding="utf-8",
    )

    provenance = {
        "collected_at": report.collected_at,
        "inventory": str(args.inventory),
        "devices": report.device_ids,
        "links": {
            link.id: {
                "source_interface_id": link.source_interface_id,
                "destination_interface_id": link.destination_interface_id,
                "state": str(link.state),
                "evidence": report.link_provenance.get(link.id, []),
            }
            for link in report.topology.links
        },
        "failures": report.failures,
    }
    provenance_path = output_dir / "discovery.evidence.yaml"
    provenance_path.write_text(
        yaml.safe_dump(provenance, sort_keys=False, allow_unicode=True), encoding="utf-8"
    )

    # ---- summary (no credentials, no raw command output) -------------------
    print("\ncollected  : " + report.collected_at)
    for collection in report.collections:
        state = "ok" if collection.succeeded else f"FAILED ({collection.error})"
        device_id = collection.device_id or "-"
        print(f"  - {collection.entry_name:<10} -> {device_id:<12} {state}")
    print(
        f"merged     : {len(report.topology.devices)} devices, "
        f"{len(report.topology.interfaces)} interfaces, "
        f"{len(report.topology.routes)} routes, "
        f"{len(report.topology.links)} links -> {merged_path}"
    )
    if report.topology.links:
        print("links      :")
        for link in report.topology.links:
            print(
                f"  * {link.id}  "
                f"({link.source_interface_id} <-> {link.destination_interface_id}) "
                f"state={link.state}"
            )
    else:
        print("links      : none (no two-sided CDP evidence)")
    print(f"evidence   : {provenance_path}")
    print(f"warnings   : {len(report.warnings)}")
    for warning in report.warnings:
        print(f"  ! {warning}")
    print(
        f"allowlist  : {len(READ_ONLY_COMMANDS)} read-only commands; "
        "no configuration was or can be sent by this tool"
    )

    if report.failures:
        return 2
    return 0


def _safe_name(name: str) -> str:
    return "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in name)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        raise SystemExit(130) from None
    except CollectorConnectionError as exc:
        # Reaches here only if a collector escapes the per-device handler.
        print(f"CONNECTION ERROR [{exc.kind}]: {exc}", file=sys.stderr)
        raise SystemExit(1) from None
