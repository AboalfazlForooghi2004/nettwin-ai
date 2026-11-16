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
import time
from pathlib import Path


def _ospf_audit(ospf) -> dict:  # noqa: ANN001 - OspfTopology | None
    """The evidence trail behind the OSPF view, kept separate from ``links``.

    Deliberately does *not* feed ``topology.links``: this records what OSPF
    claimed and how well it was evidenced, so a reader can see that a transit
    network was reconstructed without that ever becoming a cable.
    """
    if ospf is None:
        return {
            "collected": False,
            "note": "no OSPF evidence was collected during this walk",
        }
    return {
        "collected": True,
        "routers": [
            {
                "router_id": r.router_id,
                "device_id": r.device_id,
                "process_ids": r.process_ids,
                "areas": r.areas,
            }
            for r in ospf.routers
        ],
        "transit_networks": [
            {
                "id": t.id,
                "area": t.area,
                "prefix": t.prefix,
                "dr_address": t.dr_address,
                "advertising_router": t.advertising_router,
                "member_router_ids": t.member_router_ids,
                "member_interface_addresses": t.member_interface_addresses,
                "state": str(t.state),
                "evidence": t.evidence,
                "source_lsas": [
                    {
                        "area": ref.area,
                        "lsa_type": ref.lsa_type,
                        "link_state_id": ref.link_state_id,
                        "advertising_router": ref.advertising_router,
                        "sequence": ref.sequence,
                        "checksum": ref.checksum,
                    }
                    for ref in t.source_lsas
                ],
            }
            for t in ospf.transit_networks
        ],
        "stub_networks": [
            {"prefix": s.prefix, "area": s.area,
             "advertising_router": s.advertising_router, "metric": s.metric}
            for s in ospf.stub_networks
        ],
        "router_lsas": [
            {
                "area": lsa.area,
                "link_state_id": lsa.link_state_id,
                "advertising_router": lsa.advertising_router,
                "sequence": lsa.sequence,
                "checksum": lsa.checksum,
                "observed_by": lsa.observed_by,
            }
            for lsa in ospf.router_lsas
        ],
        "network_lsas": [
            {
                "area": lsa.area,
                "link_state_id": lsa.link_state_id,
                "advertising_router": lsa.advertising_router,
                "prefix": lsa.prefix,
                "attached_routers": lsa.attached_routers,
                "observed_by": lsa.observed_by,
            }
            for lsa in ospf.network_lsas
        ],
        "logical_edges": [
            {
                "source_router_id": e.source_router_id,
                "destination_router_id": e.destination_router_id,
                "prefix": e.prefix,
                "area": e.area,
                "state": str(e.state),
            }
            for e in ospf.logical_edges
        ],
        "neighbors": [
            {
                "device_id": n.device_id,
                "local_interface": n.local_interface,
                "neighbor_router_id": n.neighbor_router_id,
                "neighbor_address": n.neighbor_address,
                "state": n.state,
            }
            for n in ospf.neighbors
        ],
        "routes": {
            "learned": len(ospf.learned_routes()),
            "connected": len(ospf.connected_routes()),
            "note": "routing evidence; never used to create a topology link",
        },
        "lsa_counts": ospf.lsa_counts(),
        "state_counts": ospf.state_counts(),
        "warnings": ospf.warnings,
    }


def _link_audit(result) -> dict:  # noqa: ANN001 - RecursiveDiscoveryResult
    """The evidence trail behind ``topology.links`` (and behind its absence)."""
    link_result = getattr(result, "link_result", None)
    if link_result is None:
        return {"confirmed": 0, "candidates": [], "rules": {}, "note": "link stage did not run"}
    rules: dict[str, int] = {}
    for candidate in link_result.candidates:
        reason = str(getattr(candidate, "rule", "") or "unknown")
        rules[reason] = rules.get(reason, 0) + 1
    return {
        "confirmed": len(link_result.links),
        "candidates": [
            {"rule": str(c.rule), "detail": c.detail}
            for c in link_result.candidates
            if c.link is None
        ],
        "rules": rules,
        "matched_rows": link_result.matched_rows,
        "note": (
            "links are built only from two-sided CDP evidence; "
            "one-sided or ambiguous rows stay candidates"
        ),
    }


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
from nettwin.collect.nested.progress import (  # noqa: E402
    NullProgress,
    RichProgress,
    SummaryTable,
)
from nettwin.collect.nested.session import SessionLimits  # noqa: E402
from nettwin.render import (  # noqa: E402
    render_html,
    render_ospf_html,
    render_ospf_svg,
    render_svg,
)

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
    parser.add_argument(
        "--no-progress",
        action="store_true",
        help=(
            "disable the live progress view (also automatic when stderr is not a "
            "TTY, as in CI); the final summary is still printed"
        ),
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

    # The live view writes to stderr so stdout stays the machine-readable
    # report, and it is skipped entirely when stderr is not a TTY (CI, pipes)
    # unless the operator asked for it. Discovery never reads back from it.
    progress_enabled = not args.no_progress and sys.stderr.isatty()
    observer = RichProgress() if progress_enabled else NullProgress()
    discovery._observer = observer  # noqa: SLF001 - the documented seam

    started = time.monotonic()
    if progress_enabled:
        observer._begin()  # noqa: SLF001 - start the spinner before the walk
    try:
        result = discovery.run()
    except KeyboardInterrupt:
        observer.discovery_finished()
        print("\ninterrupted", file=sys.stderr)
        return 130
    elapsed = time.monotonic() - started
    observer.discovery_finished()

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
        # The physical topology document keeps its exact Phase 2.5 shape. OSPF
        # is added as a *sibling* key, never inside `Topology`: an OSPF
        # adjacency must never appear in the list of links that a physical
        # evidence rule confirmed. A consumer that ignores the new key sees the
        # file it always saw.
        topology_document = result.topology.model_dump(mode="json")
        if getattr(result, "ospf_topology", None) is not None:
            topology_document["ospf"] = result.ospf_topology.model_dump(mode="json")
        topology_path.write_text(
            yaml.safe_dump(
                topology_document, sort_keys=False, allow_unicode=True
            ),
            encoding="utf-8",
        )
        print(f"\nmerged     : {len(result.topology.devices)} devices, "
              f"{len(result.topology.interfaces)} interfaces, "
              f"{len(result.topology.links)} links, "
              f"{len(result.topology.routes)} routes -> {topology_path}")

        ospf = getattr(result, "ospf_topology", None)
        if ospf is not None:
            states = ospf.state_counts()
            state_word = ", ".join(f"{k} {v}" for k, v in sorted(states.items())) or "none"
            print(
                f"ospf       : {len(ospf.routers)} router(s), "
                f"{len(ospf.router_lsas)} unique Router LSA(s), "
                f"{len(ospf.network_lsas)} unique Network LSA(s), "
                f"{len(ospf.transit_networks)} transit network(s), "
                f"{len(ospf.stub_networks)} stub prefix(es), "
                f"{len(ospf.learned_routes())} learned route(s) — {state_word}"
            )
            counts = ospf.lsa_counts()
            if counts["observers"] > 1:
                print(
                    f"             {counts['observers']} observers shared these LSAs: "
                    f"{counts['router_lsa_observations']} Router LSA + "
                    f"{counts['network_lsa_observations']} Network LSA observations "
                    "collapsed to one canonical copy each"
                )

        # Visualizations are rendered from the normalized topology only, so a
        # drawing can never show more than the collected evidence supports.
        title = f"NetTwin discovery — {args.seed}"
        svg_path = output_dir / "topology.svg"
        html_path = output_dir / "topology.html"
        try:
            svg_path.write_text(
                render_svg(result.topology, title=title), encoding="utf-8"
            )
            html_path.write_text(
                render_html(result.topology, title=title, run_id=str(output_dir.name)),
                encoding="utf-8",
            )
            print(f"visualize  : {html_path}")
            print(f"             {svg_path}")
        except Exception as exc:  # noqa: BLE001 - rendering must never fail discovery
            print(f"visualize  : FAILED — {exc} (yaml/discovery output is intact)",
                  file=sys.stderr)

        if ospf is not None:
            ospf_title = f"{title} — OSPF logical view"
            ospf_svg_path = output_dir / "ospf.svg"
            ospf_html_path = output_dir / "ospf.html"
            try:
                ospf_svg_path.write_text(
                    render_ospf_svg(ospf, title=ospf_title, physical=result.topology),
                    encoding="utf-8",
                )
                ospf_html_path.write_text(
                    render_ospf_html(
                        ospf,
                        title=ospf_title,
                        run_id=str(output_dir.name),
                        physical=result.topology,
                    ),
                    encoding="utf-8",
                )
                print(f"ospf view  : {ospf_html_path}")
                print(f"             {ospf_svg_path}")
            except Exception as exc:  # noqa: BLE001 - never fail discovery
                print(f"ospf view  : FAILED — {exc} (yaml/discovery output is intact)",
                      file=sys.stderr)
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
        "links": _link_audit(result),
        "ospf": _ospf_audit(getattr(result, "ospf_topology", None)),
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

    collected_count = sum(1 for n in result.nodes if n.collected)
    print(
        SummaryTable.render(
            devices=len(result.topology.devices) if result.topology else 0,
            interfaces=len(result.topology.interfaces) if result.topology else 0,
            routes=len(result.topology.routes) if result.topology else 0,
            links=len(result.topology.links) if result.topology else 0,
            warnings=len(result.warnings),
            elapsed=elapsed,
            collected=collected_count,
            discovered=len(result.nodes),
        )
    )

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
