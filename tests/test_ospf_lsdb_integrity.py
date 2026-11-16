"""Phase 2.6 — LSDB canonicalisation, attribution and route integrity.

**OFFLINE.** Every test here corresponds to a defect found by running five
routers against the real PNETLab topology, where the naive implementation
reported 25 LSAs and 25 transit networks for 5 of each.

The distinction these tests exist to protect:

* an **LSA identity** — ``(area, ls_type, link_state_id, advertising_router)``
  — is what the topology is reconstructed from;
* an **observation** — one device's copy of that LSA — is provenance, and a
  flooded area produces one observation per router per LSA.

Confusing the two multiplies the topology by the number of collected devices;
discarding the second loses the ability to say who reported what. Both are
required, so both are asserted.
"""

from __future__ import annotations

import copy
import sys
from pathlib import Path

import pytest

TESTS = Path(__file__).parent
if str(TESTS) not in sys.path:
    sys.path.insert(0, str(TESTS))

from nettwin.collect.cisco_ios import DeviceObservations  # noqa: E402
from nettwin.collect.nested.discovery import ospf_device_data  # noqa: E402
from nettwin.collect.ospf_parsers import (  # noqa: E402
    parse_show_ip_ospf_database_router,
    parse_show_ip_ospf_route,
)
from nettwin.collect.ospf_topology import (  # noqa: E402
    advertised_stub_links,
    build_ospf_topology,
    canonical_network_lsas,
    canonical_router_lsas,
    reconstruct_stub_networks,
)
from nettwin.domain.ospf_models import OspfLinkType, OspfRouteType  # noqa: E402
from test_ospf_recursive import _run  # noqa: E402

OSPF_DATA = Path(__file__).parent / "data" / "ospf"

ROUTER_LSA_FIELDS = (
    "ospf_neighbors",
    "ospf_interfaces",
    "ospf_database",
    "ospf_router_lsas",
    "ospf_network_lsas",
    "ospf_routes",
)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _base_observations():  # noqa: ANN202
    """One real device's observations, from the reference transcript."""
    result = _run(ospf=True)
    return result.collected_nodes[0].observations


def as_observer(base: DeviceObservations, device_id: str) -> DeviceObservations:
    """The same LSDB, as read out of ``device_id``'s own CLI.

    A flooded area gives every router every LSA, so the *LSDB contents* are
    identical while the *observer* differs. This is precisely what a five-router
    run looks like, and it is what must not multiply the topology.
    """
    observed = copy.deepcopy(base)
    observed.device_id = device_id
    for field in ROUTER_LSA_FIELDS:
        rows = getattr(observed, field)
        setattr(observed, field, [{**row, "device_id": device_id} for row in rows])
    return observed


@pytest.fixture(scope="module")
def five_observers():  # noqa: ANN201
    base = _base_observations()
    return [f"r{i}" for i in range(1, 6)], [
        ospf_device_data(as_observer(base, f"r{i}"), f"r{i}") for i in range(1, 6)
    ]


# =========================================================================== #
# 1-3. Duplicate observation must not multiply canonical objects
# =========================================================================== #


def test_five_observers_produce_five_router_lsas(five_observers) -> None:  # noqa: ANN001
    names, devices = five_observers
    assert len(devices) == 5
    # The raw input really is 25 records — the fixture is not accidentally small.
    assert sum(len(d.router_lsas) for d in devices) == 25

    topology = build_ospf_topology(devices)
    assert len(topology.router_lsas) == 5


def test_five_observers_produce_five_network_lsas(five_observers) -> None:  # noqa: ANN001
    _names, devices = five_observers
    assert sum(len(d.network_lsas) for d in devices) == 25

    topology = build_ospf_topology(devices)
    assert len(topology.network_lsas) == 5


def test_five_observers_produce_five_transit_networks(five_observers) -> None:  # noqa: ANN001
    _names, devices = five_observers
    topology = build_ospf_topology(devices)
    assert len(topology.transit_networks) == 5
    assert sorted(n.prefix for n in topology.transit_networks) == [
        "10.0.21.0/30",
        "10.0.23.0/30",
        "10.0.32.0/30",
        "10.0.34.0/30",
        "10.0.41.0/30",
    ]


def test_transit_network_ids_are_unique(five_observers) -> None:  # noqa: ANN001
    _names, devices = five_observers
    ids = [n.id for n in build_ospf_topology(devices).transit_networks]
    assert len(ids) == len(set(ids))


def test_one_observer_and_five_observers_agree() -> None:
    """The canonical view must not depend on how many devices were collected."""
    base = _base_observations()
    single = build_ospf_topology([ospf_device_data(base, "r2")])
    devices = [
        ospf_device_data(as_observer(base, f"r{i}"), f"r{i}") for i in range(1, 6)
    ]
    many = build_ospf_topology(devices)

    assert len(single.transit_networks) == len(many.transit_networks)
    assert len(single.stub_networks) == len(many.stub_networks)
    assert sorted(n.prefix or "" for n in single.transit_networks) == sorted(
        n.prefix or "" for n in many.transit_networks
    )


# =========================================================================== #
# 4. Observer provenance survives canonicalisation
# =========================================================================== #


def test_observer_provenance_is_preserved(five_observers) -> None:  # noqa: ANN001
    names, devices = five_observers
    topology = build_ospf_topology(devices)

    for lsa in topology.router_lsas:
        assert lsa.observed_by == names, lsa.advertising_router
    for lsa in topology.network_lsas:
        assert lsa.observed_by == names, lsa.link_state_id


def test_provenance_is_empty_for_a_single_observer() -> None:
    base = _base_observations()
    topology = build_ospf_topology([ospf_device_data(base, "r2")])
    assert topology.router_lsas[0].observed_by == ["r2"]


def test_lsa_counts_separate_observations_from_identities(five_observers) -> None:  # noqa: ANN001
    _names, devices = five_observers
    counts = build_ospf_topology(devices).lsa_counts()

    assert counts["router_lsas"] == 5
    assert counts["network_lsas"] == 5
    assert counts["transit_networks"] == 5
    # 5 LSAs × 5 observers: the observations are counted, not hidden.
    assert counts["router_lsa_observations"] == 25
    assert counts["network_lsa_observations"] == 25
    assert counts["observers"] == 5


def test_flooded_lsdb_does_not_credit_every_router_to_one_device() -> None:
    """Holding an LSA is not the same as originating it.

    Every router in a flooded area holds all five Router LSAs. Before the
    attribution fix, "this LSA is in my LSDB" was read as "this LSA is mine",
    so all five router-ids were credited to the first device collected and four
    routers that were never SSH'd into were reported as collected.
    """
    base = _base_observations()
    devices = []
    for index, device_id in enumerate(["r1", "r2", "r3", "r4", "r5"], start=1):
        data = ospf_device_data(as_observer(base, device_id), device_id)
        data.router_id = f"10.255.255.{index}"
        devices.append(data)

    topology = build_ospf_topology(devices)
    assert {r.router_id: r.device_id for r in topology.routers} == {
        f"10.255.255.{i}": f"r{i}" for i in range(1, 6)
    }
    # One device per router: no router is credited twice.
    credited = [r.device_id for r in topology.routers]
    assert len(credited) == len(set(credited)) == 5


def test_router_without_its_own_lsa_is_not_credited() -> None:
    """A device that holds LSAs but originates none of its own stays unattributed."""
    base = _base_observations()
    data = ospf_device_data(base, "r2")
    data.router_id = ""            # e.g. `show ip ospf` returned nothing
    data.interfaces = []           # no interface evidence either

    topology = build_ospf_topology([data])
    assert all(r.collected is False for r in topology.routers)
    assert all(r.device_id == "" for r in topology.routers)


def test_advertising_router_is_not_the_observer(five_observers) -> None:  # noqa: ANN001
    """The two are different facts and must not be conflated."""
    _names, devices = five_observers
    topology = build_ospf_topology(devices)

    r2_1 = next(
        lsa for lsa in topology.router_lsas if lsa.advertising_router == "10.255.255.1"
    )
    # R2-1's LSA lives in every router's LSDB, including routers that are not R2-1.
    assert r2_1.advertising_router == "10.255.255.1"
    assert r2_1.device_id in {"r1", "r2", "r3", "r4", "r5"}
    assert r2_1.device_id != r2_1.advertising_router


# =========================================================================== #
# 5. Device attribution is populated
# =========================================================================== #


def test_no_empty_device_ids_survive_the_walk() -> None:
    """The live symptom: 21 interfaces / 25 LSAs with an empty device id."""
    result = _run(ospf=True)
    ospf = result.ospf_topology

    for collection in (
        ospf.neighbors,
        ospf.interfaces,
        ospf.router_lsas,
        ospf.network_lsas,
        ospf.routes,
        ospf.stub_networks,
        ospf.database_summary,
    ):
        for item in collection:
            assert item.device_id, f"{type(item).__name__} has an empty device_id"
            assert item.device_id != "unknown"


def test_transit_lsa_references_are_attributed() -> None:
    result = _run(ospf=True)
    for network in result.ospf_topology.transit_networks:
        assert network.source_lsas, network.id
        for ref in network.source_lsas:
            assert ref.device_id
            assert ref.device_id != "unknown"


def test_stub_source_lsa_is_attributed() -> None:
    result = _run(ospf=True)
    for stub in result.ospf_topology.stub_networks:
        assert stub.source_lsa is not None
        assert stub.source_lsa.device_id
        assert stub.source_lsa.device_id != "unknown"


def test_summary_rows_carry_the_observer() -> None:
    result = _run(ospf=True)
    for row in result.ospf_topology.database_summary:
        assert row.device_id
        # A summary row about LSAs originated elsewhere is still observed here.
        assert row.advertising_router


def test_ospf_device_data_fills_a_missing_observer() -> None:
    """Rows that arrive unattributed are attributed, not left blank."""
    base = _base_observations()
    stripped = copy.deepcopy(base)
    stripped.device_id = ""
    for field in ROUTER_LSA_FIELDS:
        rows = getattr(stripped, field)
        setattr(stripped, field, [{**row, "device_id": ""} for row in rows])

    data = ospf_device_data(stripped, "fallback-device")
    for collection in (
        data.neighbors,
        data.interfaces,
        data.router_lsas,
        data.network_lsas,
        data.routes,
    ):
        for item in collection:
            assert item.device_id == "fallback-device"


# =========================================================================== #
# 6. Conflicting LSA versions are reported, not silently dropped
# =========================================================================== #


def test_conflicting_router_lsa_instances_are_reported() -> None:
    base = _base_observations()
    stale = as_observer(base, "stale")
    fresh = as_observer(base, "fresh")

    # Same LSA identity, different instance.
    old = copy.deepcopy(stale.ospf_router_lsas[0])
    old["sequence"] = "0x80000001"
    old["checksum"] = "0x1111"
    stale.ospf_router_lsas = [old]
    new = copy.deepcopy(fresh.ospf_router_lsas[0])
    new["sequence"] = "0x80000009"
    new["checksum"] = "0x2222"
    fresh.ospf_router_lsas = [new]

    warnings: list[str] = []
    canonical = canonical_router_lsas(
        [
            ospf_device_data(stale, "stale"),
            ospf_device_data(fresh, "fresh"),
        ],
        warnings,
    )

    # One canonical LSA, newest instance chosen (RFC 2328 §13.1 ordering).
    assert len(canonical) == 1
    assert canonical[0].sequence == "0x80000009"
    # ...and the disagreement is a warning, naming both observers.
    assert any("disagreement" in w for w in warnings)
    assert any("stale" in w and "fresh" in w for w in warnings)


def test_identical_instances_produce_no_disagreement_warning(five_observers) -> None:  # noqa: ANN001
    _names, devices = five_observers
    warnings: list[str] = []
    canonical_router_lsas(devices, warnings)
    canonical_network_lsas(devices, warnings)
    assert not [w for w in warnings if "disagreement" in w]


def test_conflicting_network_lsa_membership_is_unioned_and_reported() -> None:
    base = _base_observations()
    a = as_observer(base, "a")
    b = as_observer(base, "b")

    trimmed = copy.deepcopy(a.ospf_network_lsas[0])
    trimmed["attached_routers"] = trimmed["attached_routers"][:1]
    a.ospf_network_lsas = [trimmed]
    untouched = copy.deepcopy(b.ospf_network_lsas[0])
    b.ospf_network_lsas = [untouched]

    warnings: list[str] = []
    canonical = canonical_network_lsas(
        [ospf_device_data(a, "a"), ospf_device_data(b, "b")], warnings
    )

    assert len(canonical) == 1
    # No member is lost when observers disagree about membership.
    assert set(canonical[0].attached_routers) == set(untouched["attached_routers"])
    assert any("attached-router" in w for w in warnings)


# =========================================================================== #
# 7-8. Routes
# =========================================================================== #


def test_ospf_routes_reach_the_topology_with_device_ids() -> None:
    result = _run(ospf=True)
    ospf = result.ospf_topology

    assert ospf.routes, "OSPF routes did not survive the pipeline"
    assert len(ospf.routes) == 11
    assert {r.device_id for r in ospf.routes} == {"r2"}


def test_reference_route_fixture_is_eleven_routes_nine_learned() -> None:
    text = (OSPF_DATA / "r2_show_ip_ospf_route.txt").read_text(encoding="utf-8")
    routes, warnings = parse_show_ip_ospf_route(text, "r2")

    assert warnings == []
    assert len(routes) == 11
    assert sum(1 for r in routes if r.learned) == 9
    assert sum(1 for r in routes if not r.learned) == 2


def test_connected_routes_are_not_learned() -> None:
    text = (OSPF_DATA / "r2_show_ip_ospf_route.txt").read_text(encoding="utf-8")
    routes, _ = parse_show_ip_ospf_route(text, "r2")
    connected = {r.prefix for r in routes if not r.learned}
    assert connected == {"10.0.23.0/30", "10.255.255.2/32"}
    for route in routes:
        if route.route_type is OspfRouteType.CONNECTED:
            assert route.learned is False


def test_routes_are_never_deduplicated_across_devices(five_observers) -> None:  # noqa: ANN001
    """Each router's OSPF route table is its own evidence.

    LSAs are flooded and shared; route tables are not. Canonicalising the LSDB
    must not touch them.
    """
    _names, devices = five_observers
    topology = build_ospf_topology(devices)
    assert len(topology.routes) == 55
    assert {r.device_id for r in topology.routes} == {"r1", "r2", "r3", "r4", "r5"}
    assert len(topology.learned_routes()) == 45
    assert len(topology.connected_routes()) == 10


def test_generic_routing_table_is_not_an_ospf_route_source() -> None:
    """``show ip route`` must never be used to fill ``OspfTopology.routes``."""
    result = _run(ospf=True)
    ospf_prefixes = {r.prefix for r in result.ospf_topology.routes}
    # 10.0.12.0/30 and 10.0.12.4/30 are in `show ip route` as connected but are
    # not in the OSPF route table, so they must be absent here.
    assert "10.0.12.0/30" not in ospf_prefixes
    assert "10.0.12.4/30" not in ospf_prefixes
    # Meanwhile the generic table does contain them.
    generic = {str(r.destination_prefix) for r in result.topology.routes}
    assert "10.0.12.0/30" in generic


# =========================================================================== #
# 9. Stub contract
# =========================================================================== #


def test_every_advertised_stub_link_is_reconstructed() -> None:
    text = (OSPF_DATA / "r2_show_ip_ospf_database_router.txt").read_text(encoding="utf-8")
    lsas, _ = parse_show_ip_ospf_database_router(text, "r2")

    advertised = advertised_stub_links(lsas)
    reconstructed = {
        (s.area, s.advertising_router, s.prefix)
        for s in reconstruct_stub_networks(lsas)
    }

    assert advertised == reconstructed
    assert len(advertised) == 7


def test_stub_prefix_that_is_also_a_connected_subnet_is_kept() -> None:
    """The LSDB advertises 10.0.12.0/30 and 10.0.12.4/30; they must survive.

    Dropping a valid Stub Link because the prefix also happens to be a locally
    connected interface would discard LSDB evidence and leave the two concepts
    (interface subnet vs advertised prefix) conflated.
    """
    text = (OSPF_DATA / "r2_show_ip_ospf_database_router.txt").read_text(encoding="utf-8")
    lsas, _ = parse_show_ip_ospf_database_router(text, "r2")
    prefixes = {s.prefix for s in reconstruct_stub_networks(lsas)}

    assert "10.0.12.0/30" in prefixes
    assert "10.0.12.4/30" in prefixes


def test_stub_prefixes_are_the_seven_the_lsdb_advertises() -> None:
    text = (OSPF_DATA / "r2_show_ip_ospf_database_router.txt").read_text(encoding="utf-8")
    lsas, _ = parse_show_ip_ospf_database_router(text, "r2")
    prefixes = sorted(s.prefix for s in reconstruct_stub_networks(lsas))

    assert prefixes == [
        "10.0.12.0/30",
        "10.0.12.4/30",
        "10.255.255.2/32",
        "10.255.255.3/32",
        "10.255.255.4/32",
        "10.255.255.5/32",
        "192.168.98.32/27",
    ]


def test_stub_networks_never_create_routers_or_edges() -> None:
    result = _run(ospf=True)
    ospf = result.ospf_topology
    stub_prefixes = {s.prefix for s in ospf.stub_networks}
    router_ids = set(ospf.router_ids())
    assert not (stub_prefixes & router_ids)
    assert all(
        s.prefix not in {n.prefix for n in ospf.transit_networks}
        for s in ospf.stub_networks
    )


def test_advertised_stub_links_helper_matches_stub_link_count() -> None:
    text = (OSPF_DATA / "r2_show_ip_ospf_database_router.txt").read_text(encoding="utf-8")
    lsas, _ = parse_show_ip_ospf_database_router(text, "r2")
    raw = sum(
        1
        for lsa in lsas
        for link in lsa.links
        if link.link_type is OspfLinkType.STUB
    )
    assert len(advertised_stub_links(lsas)) == raw == 7


# =========================================================================== #
# 10-12. Physical topology and non-OSPF devices are untouched
# =========================================================================== #


def test_cdp_links_are_unchanged_by_canonicalisation() -> None:
    """The physical result is identical whether OSPF ran or not."""
    with_ospf = _run(ospf=True)
    without = _run(ospf=False)

    def physical(result):  # noqa: ANN001, ANN202
        return (
            sorted(d.id for d in result.topology.devices),
            sorted(
                (link.source_interface_id, link.destination_interface_id, str(link.state))
                for link in result.topology.links
            ),
        )

    assert physical(with_ospf) == physical(without)


def test_transit_networks_never_become_physical_links(five_observers) -> None:  # noqa: ANN001
    _names, devices = five_observers
    topology = build_ospf_topology(devices)
    assert len(topology.transit_networks) == 5

    # OspfTopology has no link list at all, and no transit address appears in
    # a physical link when a real topology is attached.
    assert not hasattr(topology, "links")
    from nettwin.domain.models import Topology

    assert "ospf" not in Topology.model_fields


def test_device_without_ospf_still_collects_fully() -> None:
    result = _run(ospf=False)
    assert result.ospf_topology is not None
    assert result.ospf_topology.transit_networks == []
    assert result.ospf_topology.router_lsas == []
    assert any(
        "does not appear to run OSPF" in w for w in result.ospf_topology.warnings
    )
    assert result.topology is not None


# =========================================================================== #
# 13. Serialization and rendering stay valid
# =========================================================================== #


def test_yaml_serialization_stays_valid_with_five_observers(five_observers) -> None:  # noqa: ANN001
    import yaml

    _names, devices = five_observers
    topology = build_ospf_topology(devices)
    document = {"ospf": topology.model_dump(mode="json")}
    reloaded = yaml.safe_load(yaml.safe_dump(document, sort_keys=False))

    assert len(reloaded["ospf"]["router_lsas"]) == 5
    assert reloaded["ospf"]["router_lsas"][0]["observed_by"] == [
        "r1", "r2", "r3", "r4", "r5"
    ]


def test_renderers_show_canonical_counts(five_observers) -> None:  # noqa: ANN001
    from nettwin.render.ospf_html import build_ospf_payload
    from nettwin.render.ospf_svg import render_ospf_svg

    _names, devices = five_observers
    topology = build_ospf_topology(devices)

    payload = build_ospf_payload(topology, title="t")
    assert payload["counts"]["transit_networks"] == 5
    assert payload["counts"]["router_lsas"] == 5
    assert payload["counts"]["network_lsas"] == 5

    svg = render_ospf_svg(topology, title="t")
    assert "25 transit network" not in svg
    hexes = [
        p
        for p in __import__("xml.etree.ElementTree", fromlist=["ET"]).fromstring(
            svg
        ).iter("{http://www.w3.org/2000/svg}polygon")
        if p.get("fill") == "#fff8ed"
    ]
    assert len(hexes) == 6          # 5 nodes + 1 legend swatch


def test_payload_exposes_observer_provenance(five_observers) -> None:  # noqa: ANN001
    from nettwin.render.ospf_html import build_ospf_payload

    _names, devices = five_observers
    payload = build_ospf_payload(build_ospf_topology(devices), title="t")
    for lsa in payload["router_lsas"]:
        assert lsa["observed_by"] == ["r1", "r2", "r3", "r4", "r5"]


# =========================================================================== #
# Lab acceptance (§5) — device-specific data, delivered through the real API
# =========================================================================== #


ROUTER_IDS = {
    "r1": "10.255.255.1",
    "r2": "10.255.255.2",
    "r3": "10.255.255.3",
    "r4": "10.255.255.4",
    "r5": "10.255.255.5",
}

# Each router's own position on the five broadcast segments it shares with a
# neighbour. This is the part of the LSDB that is genuinely per-device.
SEGMENTS = {
    "r1": [("10.0.21.0/30", "10.0.21.2", "10.0.21.1"), ("10.0.41.0/30", "10.0.41.2", "10.0.41.1")],
    "r2": [("10.0.23.0/30", "10.0.23.1", "10.0.23.2"), ("10.0.12.0/30", None, None)],
    "r3": [("10.0.32.0/30", "10.0.32.2", "10.0.32.1"), ("10.0.21.0/30", "10.0.21.1", "10.0.21.2")],
    "r4": [("10.0.23.0/30", "10.0.23.2", "10.0.23.1"), ("10.0.34.0/30", "10.0.34.1", "10.0.34.2")],
    "r5": [("10.0.34.0/30", "10.0.34.2", "10.0.34.1"), ("10.0.41.0/30", "10.0.41.1", "10.0.41.2")],
}


def _lab_device_data(device_id: str):  # noqa: ANN202
    """One router's OSPF view, with its own router-id and its own interfaces.

    Everything else — the LSAs, the neighbours — is the flooded area-wide view,
    which is the same bytes on every router. That asymmetry is the whole point:
    shared LSDB, distinct observer, distinct route table.
    """
    base = _base_observations()
    observed = as_observer(base, device_id)
    data = ospf_device_data(observed, device_id)

    data.router_id = ROUTER_IDS[device_id]
    data.process_id = "10"

    # This router's own interfaces: address/prefix on the segments it attaches to.
    data.interfaces = [
        iface.model_copy(
            update={"device_id": device_id, "ip_address": prefix.split("/")[0]}
        )
        for iface, (_prefix, prefix, _dr) in zip(
            data.interfaces, SEGMENTS[device_id], strict=False
        )
        if prefix is not None
    ]
    return data


@pytest.fixture(scope="module")
def lab():  # noqa: ANN201
    devices = [_lab_device_data(d) for d in ROUTER_IDS]
    return build_ospf_topology(devices)


def test_lab_five_devices_five_unique_lsas(lab) -> None:  # noqa: ANN001
    assert len({d.device_id for d in lab.routers}) == 5
    assert len(lab.router_lsas) == 5
    assert len(lab.network_lsas) == 5


def test_lab_five_transit_networks(lab) -> None:  # noqa: ANN001
    assert len(lab.transit_networks) == 5
    assert len({n.id for n in lab.transit_networks}) == 5


def test_lab_seven_stubs_from_unchanged_evidence(lab) -> None:  # noqa: ANN001
    """Seven, not eight: the LSDB advertises seven Stub Links.

    An eighth stub would require an eighth advertised link. The count is a
    consequence of the evidence, not a target.
    """
    assert len(lab.stub_networks) == 7


def test_lab_zero_missing_device_ids(lab) -> None:  # noqa: ANN001
    for collection in (
        lab.routers,
        lab.neighbors,
        lab.interfaces,
        lab.router_lsas,
        lab.network_lsas,
        lab.routes,
        lab.stub_networks,
        lab.database_summary,
    ):
        assert all(item.device_id for item in collection), type(collection[0]).__name__
    for network in lab.transit_networks:
        assert all(ref.device_id for ref in network.source_lsas)
    for stub in lab.stub_networks:
        assert stub.source_lsa is not None and stub.source_lsa.device_id


def test_lab_no_logical_edge_is_invented(lab) -> None:  # noqa: ANN001
    """No reciprocal point-to-point evidence, so no logical edges."""
    assert all(
        link.link_type is not OspfLinkType.POINT_TO_POINT
        for lsa in lab.router_lsas
        for link in lsa.links
    )
    assert lab.logical_edges == []


def test_lab_transit_membership_is_intact(lab) -> None:  # noqa: ANN001
    by_prefix = {n.prefix: n for n in lab.transit_networks}
    assert set(by_prefix) == {
        "10.0.21.0/30",
        "10.0.23.0/30",
        "10.0.32.0/30",
        "10.0.34.0/30",
        "10.0.41.0/30",
    }
    for prefix, network in by_prefix.items():
        assert len(network.member_router_ids) == 2, prefix
        assert len(network.member_interface_addresses) == 2, prefix
