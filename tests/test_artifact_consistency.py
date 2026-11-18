"""Live-run artifact consistency. **OFFLINE ONLY.**

Regression tests for three defects found by inspecting the artifacts of
``collected/recursive/live-ospf-20261118-115512``:

1. ``topology.yaml`` carried Network LSA sequence/checksum while
   ``discovery.yaml`` dropped them, so the two artifacts disagreed about the
   same LSAs. That was an oversight in the audit projection, not a deliberate
   narrowing.
2. ``raw_commands`` was retained on ``DeviceObservations`` but never written,
   so the evidence existed only in memory and died with the process.
3. The route summary was three keys of counts while ``topology.yaml`` held the
   full list, which read as a contradiction (48 records vs "3").

These tests drive the **real** projection and the **real** serialized output.
Earlier tests mirrored the writer by hand, which is exactly how a field could
go missing from both the writer and its test at the same time.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]


def _writer():  # noqa: ANN202 - module
    """Load ``scripts/discover_recursive.py`` as a module."""
    spec = importlib.util.spec_from_file_location(
        "_discover_recursive_under_test", REPO_ROOT / "scripts" / "discover_recursive.py"
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def writer():  # noqa: ANN201 - module
    return _writer()


# --------------------------------------------------------------------------- #
# A minimal OspfTopology carrying Network LSAs with real sequence/checksum
# --------------------------------------------------------------------------- #


def _ospf_topology():  # noqa: ANN202 - OspfTopology
    from nettwin.domain.ospf_models import (
        OspfNetworkLsa,
        OspfRoute,
        OspfRouterLsa,
        OspfRouteType,
        OspfTopology,
    )

    network = OspfNetworkLsa(
        area="0",
        link_state_id="10.0.23.1",
        advertising_router="10.255.255.2",
        network_mask="255.255.255.252",
        attached_routers=["10.255.255.2", "10.255.255.3"],
        sequence="80000078",
        checksum="0xAECE",
        age=120,
        device_id="r2-1",
        observed_by=["r2", "r2-1", "r2-2", "r2-3", "r2-4"],
    )
    router = OspfRouterLsa(
        area="0",
        link_state_id="10.255.255.2",
        advertising_router="10.255.255.2",
        sequence="8000007D",
        checksum="0x8B65",
        age=120,
        device_id="r2-1",
        number_of_links=0,
        observed_by=["r2", "r2-1", "r2-2", "r2-3", "r2-4"],
    )
    routes = [
        OspfRoute(device_id="r2-1", prefix="10.0.12.0/30", route_type=OspfRouteType.CONNECTED, learned=False),
        OspfRoute(device_id="r2-1", prefix="10.0.34.0/30", route_type=OspfRouteType.INTRA_AREA),
        OspfRoute(device_id="r2-2", prefix="10.0.34.0/30", route_type=OspfRouteType.INTRA_AREA),
    ]
    return OspfTopology(network_lsas=[network], router_lsas=[router], routes=routes)


# --------------------------------------------------------------------------- #
# Finding 2 — both artifacts must agree on LSA identity fields
# --------------------------------------------------------------------------- #


def test_network_lsa_sequence_and_checksum_survive_the_discovery_projection(writer) -> None:
    """The confirmed defect: ``discovery.yaml`` had sequence/checksum as None."""
    audit = writer._ospf_audit(_ospf_topology())
    assert len(audit["network_lsas"]) == 1
    lsa = audit["network_lsas"][0]
    assert lsa["sequence"] == "80000078"
    assert lsa["checksum"] == "0xAECE"
    assert lsa["age"] == 120


def test_router_and_network_lsa_projections_agree_on_identity_fields(writer) -> None:
    """Both LSA kinds must expose the same identity fields."""
    audit = writer._ospf_audit(_ospf_topology())
    shared = {"area", "link_state_id", "advertising_router", "sequence", "checksum", "observed_by"}
    assert shared <= set(audit["router_lsas"][0])
    assert shared <= set(audit["network_lsas"][0])


def test_both_artifacts_agree_on_every_network_lsa_field(writer, tmp_path: Path) -> None:
    """End to end: serialize both documents and compare the same LSA."""
    ospf = _ospf_topology()
    topology_doc = {"ospf": ospf.model_dump(mode="json")}
    discovery_doc = {"ospf": writer._ospf_audit(ospf)}

    top_path = tmp_path / "topology.yaml"
    disc_path = tmp_path / "discovery.yaml"
    top_path.write_text(yaml.safe_dump(topology_doc, sort_keys=False), encoding="utf-8")
    disc_path.write_text(yaml.safe_dump(discovery_doc, sort_keys=False), encoding="utf-8")

    top_lsa = yaml.safe_load(top_path.read_text(encoding="utf-8"))["ospf"]["network_lsas"][0]
    disc_lsa = yaml.safe_load(disc_path.read_text(encoding="utf-8"))["ospf"]["network_lsas"][0]

    for field in ("area", "link_state_id", "advertising_router", "sequence", "checksum", "age"):
        assert disc_lsa[field] == top_lsa[field], field
    assert disc_lsa["observed_by"] == top_lsa["observed_by"]


# --------------------------------------------------------------------------- #
# Finding 3 — raw evidence must reach a real artifact
# --------------------------------------------------------------------------- #


class _Node:
    def __init__(self, identity: str, observations) -> None:  # noqa: ANN001
        self.identity = identity
        self.observations = observations


class _Result:
    def __init__(self, nodes) -> None:  # noqa: ANN001
        self.nodes = nodes


def _observations(device_id: str, commands: dict[str, str]):  # noqa: ANN202
    from nettwin.collect.cisco_ios import DeviceObservations

    observations = DeviceObservations(host="10.0.0.1", device_id=device_id, collected_at="", status="ok")
    observations.raw_commands = commands
    return observations


def test_raw_evidence_reaches_a_serialized_artifact(writer, tmp_path: Path) -> None:
    """The defect: retained in memory, absent from every artifact."""
    from nettwin.collect.cisco_ios import OSPF_RAW_COMMANDS

    retained = {cmd: f"output of {cmd}\n" for cmd in sorted(OSPF_RAW_COMMANDS)}
    result = _Result([_Node("r2-1", _observations("r2-1", retained))])

    evidence = writer._raw_evidence_audit(result)
    path = tmp_path / "raw_evidence.yaml"
    path.write_text(yaml.safe_dump(evidence, sort_keys=False), encoding="utf-8")

    written = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert written["device_count"] == 1
    assert written["block_count"] == len(OSPF_RAW_COMMANDS)
    assert set(written["commands_retained"]) == set(OSPF_RAW_COMMANDS)

    device = written["devices"][0]
    assert device["device_id"] == "r2-1"
    assert set(device["commands"]) == set(OSPF_RAW_COMMANDS)
    assert device["commands"]["show ip ospf database router"]["output"].startswith("output of")


def test_raw_evidence_preserves_device_and_command_attribution(writer) -> None:
    result = _Result(
        [
            _Node("r2-1", _observations("r2-1", {"show ip ospf database router": "A"})),
            _Node("r3-1", _observations("r3-1", {"show ip ospf database router": "B"})),
        ]
    )
    evidence = writer._raw_evidence_audit(result)
    assert evidence["device_count"] == 2
    by_device = {d["device_id"]: d["commands"]["show ip ospf database router"]["output"] for d in evidence["devices"]}
    assert by_device == {"r2-1": "A", "r3-1": "B"}


def test_raw_evidence_never_contains_credential_bearing_commands(writer) -> None:
    """Even if a caller populated it wrongly, the allowlist is the contract."""
    from nettwin.collect.cisco_ios import OSPF_RAW_COMMANDS, READ_ONLY_COMMANDS

    assert "show ip ospf interface" not in OSPF_RAW_COMMANDS
    assert "show ip ospf interface" not in READ_ONLY_COMMANDS
    assert OSPF_RAW_COMMANDS <= READ_ONLY_COMMANDS

    evidence = writer._raw_evidence_audit(
        _Result([_Node("r1", _observations("r1", dict.fromkeys(sorted(OSPF_RAW_COMMANDS), "x")))])
    )
    for device in evidence["devices"]:
        for command in device["commands"]:
            assert command in OSPF_RAW_COMMANDS
            assert "password" not in command and "secret" not in command


def test_evidence_block_records_size_and_is_plain_text(writer) -> None:
    evidence = writer._raw_evidence_audit(
        _Result([_Node("r1", _observations("r1", {"show ip ospf route": "a\nb\nc"}))])
    )
    block = evidence["devices"][0]["commands"]["show ip ospf route"]
    assert block["lines"] == 3
    assert block["bytes"] == len("a\nb\nc")
    assert isinstance(block["output"], str)


def test_a_run_without_ospf_evidence_still_produces_the_key(writer) -> None:
    """Absence must be explicit, not a missing file to interpret."""
    evidence = writer._raw_evidence_audit(_Result([_Node("r1", _observations("r1", {}))]))
    assert evidence["device_count"] == 0
    assert evidence["devices"] == []
    assert evidence["block_count"] == 0


# --------------------------------------------------------------------------- #
# Route reconciliation — the "3 keys vs 48 records" puzzle
# --------------------------------------------------------------------------- #


def test_route_summary_states_the_total_so_it_reconciles(writer) -> None:
    ospf = _ospf_topology()
    audit = writer._ospf_audit(ospf)["routes"]
    assert audit["total"] == len(ospf.routes) == 3
    assert audit["learned"] == 2
    assert audit["connected"] == 1
    assert audit["learned"] + audit["connected"] == audit["total"]


def test_route_breakdown_is_deterministic_and_complete(writer) -> None:
    audit = writer._ospf_audit(_ospf_topology())["routes"]
    assert audit["by_device"] == {"r2-1": 2, "r2-2": 1}
    assert audit["by_type"] == {"connected": 1, "intra-area": 2}
    assert sum(audit["by_device"].values()) == audit["total"]
    assert sum(audit["by_type"].values()) == audit["total"]


def test_route_summary_states_it_excludes_show_ip_route(writer) -> None:
    note = writer._ospf_audit(_ospf_topology())["routes"]["note"]
    assert "show ip ospf route" in note
    assert "show ip route" in note


# --------------------------------------------------------------------------- #
# Finding 4 — the eighth stub prefix
#
# The live LSDB advertised 10.255.255.1/32 as a stub link on R2-1's Router LSA
# for 10.255.255.1, in addition to 192.168.98.32/27. That is exactly what IOS
# emits for a loopback placed in OSPF, and the reconstruction reproduces it
# faithfully. The count is therefore a property of the LSDB, not a constant:
# the previous expectation of 7 described a different LSDB.
# --------------------------------------------------------------------------- #


def test_stub_count_follows_the_lsdb_rather_than_a_constant() -> None:
    """Adding a loopback stub link raises the count; nothing filters it."""
    from pathlib import Path

    from nettwin.collect.ospf_parsers import parse_show_ip_ospf_database_router
    from nettwin.collect.ospf_topology import advertised_stub_links, reconstruct_stub_networks

    text = Path(__file__).parent.joinpath(
        "data", "ospf", "r2_show_ip_ospf_database_router.txt"
    ).read_text(encoding="utf-8")

    baseline_lsas, _ = parse_show_ip_ospf_database_router(text, "r2")
    assert len(advertised_stub_links(baseline_lsas)) == 7

    # Give the seed router's LSA the loopback stub the live run advertised.
    live = text.replace(
        "  Number of Links: 3", "  Number of Links: 4", 1
    ).replace(
        """     (Link Data) Network Mask: 255.255.255.224
      Number of MTID metrics: 0
       TOS 0 Metrics: 1""",
        """     (Link Data) Network Mask: 255.255.255.224
      Number of MTID metrics: 0
       TOS 0 Metrics: 1

    Link connected to: a Stub Network
     (Link ID) Network/subnet number: 10.255.255.1
     (Link Data) Network Mask: 255.255.255.255
      Number of MTID metrics: 0
       TOS 0 Metrics: 1""",
        1,
    )
    live_lsas, warnings = parse_show_ip_ospf_database_router(live, "r2")
    assert warnings == []

    advertised = advertised_stub_links(live_lsas)
    reconstructed = {
        (s.area, s.advertising_router, s.prefix) for s in reconstruct_stub_networks(live_lsas)
    }
    assert len(advertised) == 8
    assert advertised == reconstructed
    assert ("0", "10.255.255.1", "10.255.255.1/32") in advertised


def test_a_loopback_stub_is_not_silently_excluded() -> None:
    """A /32 host stub is real evidence and must survive reconstruction."""
    from nettwin.domain.ospf_models import (
        OspfLinkType,
        OspfLsaLink,
        OspfRouterLsa,
    )

    lsa = OspfRouterLsa(
        area="0",
        link_state_id="10.255.255.1",
        advertising_router="10.255.255.1",
        sequence="80000080",
        checksum="0x92FB",
        age=120,
        device_id="r2-1",
        number_of_links=1,
        links=[
            OspfLsaLink(
                link_type=OspfLinkType.STUB,
                link_id="10.255.255.1",
                link_data="255.255.255.255",
                network_mask="255.255.255.255",
                metric=1,
            )
        ],
        observed_by=["r2", "r2-1", "r2-2", "r2-3", "r2-4"],
    )
    from nettwin.collect.ospf_topology import reconstruct_stub_networks

    stubs = reconstruct_stub_networks([lsa])
    assert [s.prefix for s in stubs] == ["10.255.255.1/32"]


def test_single_observer_lsa_keeps_its_provenance_and_is_not_withheld() -> None:
    """Finding 1: a one-observer LSA is legitimate, not a canonicalisation gap.

    The live run showed 10.255.255.5 observed only by ``r2-1``. Canonicalisation
    must keep it with exactly that provenance — never pad it to five observers,
    and never drop it for being a minority of one.
    """
    from nettwin.collect.ospf_topology import OspfDeviceData, build_ospf_topology
    from nettwin.domain.ospf_models import OspfRouterLsa

    def router(dev: str, lsid: str) -> OspfRouterLsa:
        return OspfRouterLsa(
            area="0",
            link_state_id=lsid,
            advertising_router=lsid,
            sequence="80000080",
            checksum="0x1111",
            age=100,
            device_id=dev,
            number_of_links=0,
            links=[],
        )

    observers = ["r2", "r2-1", "r2-2", "r2-3", "r2-4"]
    devices = []
    for observer in observers:
        lsas = [router(observer, f"10.255.255.{i}") for i in range(1, 5)]
        if observer == "r2-1":
            lsas.append(router(observer, "10.255.255.5"))
        devices.append(OspfDeviceData(device_id=observer, router_lsas=lsas))

    topology = build_ospf_topology(devices)
    assert len(topology.router_lsas) == 5
    by_lsid = {lsa.link_state_id: lsa for lsa in topology.router_lsas}
    assert by_lsid["10.255.255.5"].observed_by == ["r2-1"]
    assert sum(len(lsa.observed_by) for lsa in topology.router_lsas) == 21

    # No *LSA conflict* is reported. (Unrelated warnings about this minimal
    # fixture having no Network LSAs or neighbours are expected and not the
    # subject of this test.)
    assert not [w for w in topology.warnings if "conflict" in w.lower() or "unresolved" in w.lower()]


# --------------------------------------------------------------------------- #
# Finding 1 (live-ospf-20261118-124403) — the five-observer Router LSA
#
# The raw evidence held 10.255.255.5 / 80000081 / 0x90FC in all five devices'
# output, yet the canonical record showed observed_by=['r2-1']. These fixtures
# reproduce the reported raw shape exactly, including the whitespace-only line
# preceding the block in the four non-seed captures.
# --------------------------------------------------------------------------- #

LIVE_DIR = Path(__file__).parent / "data" / "ospf" / "live"
LIVE_OBSERVERS = ["r2", "r2-1", "r2-2", "r2-3", "r2-4"]


def _parse_live(device: str):  # noqa: ANN202
    from nettwin.collect.ospf_parsers import parse_show_ip_ospf_database_router

    text = (LIVE_DIR / f"router_lsa_{device}.txt").read_text(encoding="utf-8")
    return parse_show_ip_ospf_database_router(text, device)


@pytest.mark.parametrize("device", LIVE_OBSERVERS)
def test_live_raw_capture_parses_on_every_observer(device: str) -> None:
    """Each of the five raw blocks must yield the LSA, before any aggregation."""
    lsas, warnings = _parse_live(device)
    assert len(lsas) == 1, f"{device}: {warnings}"
    lsa = lsas[0]
    assert lsa.link_state_id == "10.255.255.5"
    assert lsa.advertising_router == "10.255.255.5"
    assert lsa.sequence == "80000081"
    assert lsa.checksum == "0x90FC"
    assert len(lsa.links) == 3
    # Observer identity is the collecting device, never the originator.
    assert lsa.device_id == device


@pytest.mark.parametrize("device", ["r2", "r2-2", "r2-3", "r2-4"])
def test_leading_whitespace_line_does_not_swallow_the_block(device: str) -> None:
    """The reported format clue: a whitespace-only line before the header."""
    raw = (LIVE_DIR / f"router_lsa_{device}.txt").read_text(encoding="utf-8")
    assert "\n        \n" in raw, "fixture must preserve the reported shape"
    lsas, _ = _parse_live(device)
    assert len(lsas) == 1


def test_five_live_observers_canonicalise_to_one_router_lsa() -> None:
    """Acceptance: one canonical LSA, 80000081/0x90FC, all five observers."""
    from nettwin.collect.cisco_ios import DeviceObservations
    from nettwin.collect.nested.discovery import ospf_device_data
    from nettwin.collect.ospf_topology import build_ospf_topology

    devices = []
    for device in LIVE_OBSERVERS:
        lsas, _ = _parse_live(device)
        observations = DeviceObservations(
            host="h", device_id=device, collected_at="", status="ok"
        )
        observations.ospf_router_lsas = [lsa.model_dump() for lsa in lsas]
        devices.append(ospf_device_data(observations, device))

    topology = build_ospf_topology(devices)
    router_lsas = [
        item for item in topology.router_lsas if item.link_state_id == "10.255.255.5"
    ]
    assert len(router_lsas) == 1
    canonical = router_lsas[0]
    assert canonical.sequence == "80000081"
    assert canonical.checksum == "0x90FC"
    assert canonical.observed_by == sorted(LIVE_OBSERVERS)
    assert canonical.advertising_router == "10.255.255.5"
    # No observation invented, none duplicated.
    assert len(canonical.observed_by) == len(set(canonical.observed_by)) == 5


def test_a_truncated_capture_is_reported_not_silently_lost() -> None:
    """The observable symptom: an LSA present in the CLI but absent from results.

    A capture cut short leaves fewer links than the LSA declares, so the object
    is internally inconsistent and is withheld. That is correct — but it must
    say so, or a dropped observation is indistinguishable from one that never
    existed.
    """
    from nettwin.collect.ospf_parsers import parse_show_ip_ospf_database_router

    full = (LIVE_DIR / "router_lsa_r2-2.txt").read_text(encoding="utf-8")
    truncated = full.split("    Link connected to: a Transit Network")[0]

    lsas, warnings = parse_show_ip_ospf_database_router(truncated, "r2-2")
    assert lsas == []
    assert any("LSA dropped" in w for w in warnings)
    assert any("truncated" in w for w in warnings), warnings
    assert any("observer=r2-2" in w for w in warnings)


def test_parse_warnings_are_persisted_in_the_evidence_artifact(writer) -> None:
    """A dropped LSA must be visible in the artifact, not only in memory."""
    from nettwin.collect.cisco_ios import DeviceObservations

    observations = DeviceObservations(host="h", device_id="r2-2", collected_at="", status="ok")
    observations.raw_commands = {"show ip ospf database router": "text"}
    observations.warnings = [
        "show ip ospf database router [observer=r2-2]: LSA 10.255.255.5 declares 3 "
        "link(s) but 1 were parsed — LSA dropped (truncated)"
    ]
    evidence = writer._raw_evidence_audit(_Result([_Node("r2-2", observations)]))
    device = evidence["devices"][0]
    assert device["parse_warnings"]
    assert any("LSA dropped" in w for w in device["parse_warnings"])
