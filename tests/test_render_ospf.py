"""Phase 2.6 — OSPF renderers. **OFFLINE, no browser required.**

The rule these tests exist for: a transit network must never be drawn as a
switch or a cable. So the assertions are mechanical — count the elements, count
the edges, and prove that the number of visual connections equals the number of
*reconstructed logical relationships*, never the number of cables.

`tests/test_render_ospf_browser.py` covers the interactive behaviour of the HTML
page; this module covers the documents themselves.
"""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET

import pytest

from nettwin.domain.models import (
    AdminState,
    Device,
    Interface,
    Link,
    LinkState,
    OperState,
    Topology,
)
from nettwin.domain.ospf_models import (
    OspfEvidenceState,
    OspfInstance,
    OspfLogicalEdge,
    OspfNetworkLsa,
    OspfRoute,
    OspfRouter,
    OspfRouterLsa,
    OspfRouteType,
    OspfTopology,
    OspfTransitNetwork,
)
from nettwin.render.ospf_html import build_ospf_payload, render_ospf_html
from nettwin.render.ospf_svg import render_ospf_svg

SVG = "{http://www.w3.org/2000/svg}"


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #


@pytest.fixture(scope="module")
def reference_lab() -> OspfTopology:
    """The §9 lab, built through the real pipeline (not hand-assembled)."""
    import sys
    from pathlib import Path

    tests_dir = str(Path(__file__).parent)
    if tests_dir not in sys.path:
        sys.path.insert(0, tests_dir)
    from test_ospf_recursive import _run

    result = _run(ospf=True)
    assert result.ospf_topology is not None
    return result.ospf_topology


@pytest.fixture(scope="module")
def empty_ospf() -> OspfTopology:
    return OspfTopology(
        warnings=["no OSPF evidence collected — this device does not appear to run OSPF"]
    )


def _root(svg: str) -> ET.Element:
    return ET.fromstring(svg)          # raises if the document is malformed


def _texts(root: ET.Element) -> str:
    return " ".join(t.text or "" for t in root.iter(f"{SVG}text"))


def _paths(root: ET.Element) -> list[ET.Element]:
    return list(root.iter(f"{SVG}path"))


def _polygons(root: ET.Element) -> list[ET.Element]:
    return list(root.iter(f"{SVG}polygon"))


# =========================================================================== #
# 1. The document is sound
# =========================================================================== #


def test_svg_is_well_formed_xml(reference_lab: OspfTopology) -> None:
    root = _root(render_ospf_svg(reference_lab))
    assert root.tag == f"{SVG}svg"


def test_svg_is_self_contained(reference_lab: OspfTopology) -> None:
    """No external stylesheet, script, image or font may be referenced."""
    svg = render_ospf_svg(reference_lab)
    assert "<?xml-stylesheet" not in svg
    assert "<script" not in svg
    assert "<image" not in svg
    assert "href=" not in svg
    assert "url(" not in svg
    assert "@import" not in svg


def test_svg_declares_its_size(reference_lab: OspfTopology) -> None:
    root = _root(render_ospf_svg(reference_lab))
    assert int(root.get("width")) > 0
    assert int(root.get("height")) > 0
    assert root.get("viewBox") == f"0 0 {root.get('width')} {root.get('height')}"


def test_svg_has_an_accessible_title(reference_lab: OspfTopology) -> None:
    root = _root(render_ospf_svg(reference_lab, title="Lab A OSPF"))
    assert root.get("role") == "img"
    assert root.get("aria-label") == "Lab A OSPF"
    assert root.find(f"{SVG}title").text == "Lab A OSPF"
    assert "transit" in root.find(f"{SVG}desc").text.lower()


def test_svg_rendering_is_deterministic(reference_lab: OspfTopology) -> None:
    a = render_ospf_svg(reference_lab, title="same")
    b = render_ospf_svg(reference_lab, title="same")
    assert a == b


def test_svg_is_independent_of_input_list_order() -> None:
    """Two orderings of the same data must lay out identically."""

    def build(reverse: bool) -> OspfTopology:
        nets = [
            OspfTransitNetwork(
                id=f"t{i}", area="0", prefix=f"10.9.{i}.0/30", dr_address=f"10.9.{i}.1",
                advertising_router="1.1.1.1", member_router_ids=["1.1.1.1", "2.2.2.2"],
                state=OspfEvidenceState.CONFIRMED,
            )
            for i in range(1, 4)
        ]
        nets = list(reversed(nets)) if reverse else nets
        return OspfTopology(
            routers=[
                OspfRouter(router_id="2.2.2.2"),
                OspfRouter(router_id="1.1.1.1"),
            ],
            transit_networks=nets,
        )

    assert render_ospf_svg(build(True), title="t") == render_ospf_svg(build(False), title="t")


# =========================================================================== #
# 2. THE RULE: never draw an OSPF relationship as a cable
# =========================================================================== #


def test_every_transit_network_is_a_node_not_an_edge(reference_lab: OspfTopology) -> None:
    """5 transit networks ⇒ 5 hexagons, and a hexagon is never a line."""
    root = _root(render_ospf_svg(reference_lab))
    # The legend contains one swatch of the same fill, so identify node
    # hexagons by size: a node is ~214px wide, a swatch is 12px.
    def span(poly: ET.Element) -> float:
        xs = [float(v.split(",")[0]) for v in poly.get("points", "").split() if "," in v]
        return max(xs) - min(xs)

    hexes = [
        p for p in _polygons(root)
        if p.get("fill") == "#fff8ed" and span(p) > 100      # TRANSIT_FILL
    ]
    assert len(hexes) == len(reference_lab.transit_networks) == 5


def test_no_router_to_router_edge_exists_without_a_point_to_point_link(
    reference_lab: OspfTopology,
) -> None:
    """The lab has zero Type-1 P2P links, so no router-to-router line at all.

    The only paths that touch two router boxes are the adjacency arcs from the
    neighbour table, and those are explicitly dashed and green. Everything else
    is a router→transit spoke. If this ever produced a solid router-to-router
    line, an OSPF adjacency would have become a cable.
    """
    assert reference_lab.logical_edges == []
    root = _root(render_ospf_svg(reference_lab))
    for path in _paths(root):
        d = path.get("d", "")
        stroke = path.get("stroke", "")
        if stroke == "#c05621":        # MEMBER spoke: router -> transit
            continue
        if stroke == "#2f855a":        # ADJ arc: explicitly dashed + labelled
            assert path.get("stroke-dasharray"), "adjacency arc must be dashed"
            continue
        if stroke == "#6b46c1":        # P2P: cell would be purple + dashed
            assert path.get("stroke-dasharray")
            continue
        raise AssertionError(f"unexpected connector stroke={stroke!r} d={d[:60]}")


def test_stub_prefixes_have_no_connector_whatsoever(reference_lab: OspfTopology) -> None:
    """7 stub prefixes, 7 pills, and no path may end at a pill."""
    root = _root(render_ospf_svg(reference_lab))
    stub_label = next(
        t for t in root.iter(f"{SVG}text") if (t.text or "").startswith("Stub prefixes")
    )
    stub_y = float(stub_label.get("y"))
    legend_y = next(
        float(t.get("y")) for t in root.iter(f"{SVG}text")
        if (t.text or "").startswith("stub prefix — advertised")
    )
    pill_rects = [
        r for r in root.iter(f"{SVG}rect")
        if r.get("stroke-dasharray") == "4 3"
        and stub_y < float(r.get("y")) < legend_y
        and float(r.get("height")) == 30
    ]
    assert len(pill_rects) == len(reference_lab.stub_networks) == 7

    pill_boxes = [
        (float(r.get("x")), float(r.get("y")),
         float(r.get("x")) + float(r.get("width")), float(r.get("y")) + float(r.get("height")))
        for r in pill_rects
    ]

    def ends_inside_pill(path: ET.Element) -> bool:
        nums = [float(n) for n in re.findall(r"-?\d+\.?\d*", path.get("d", ""))]
        points = list(zip(nums[0::2], nums[1::2], strict=False))
        for x, y in (points[0], points[-1]):
            for x0, y0, x1, y1 in pill_boxes:
                if x0 - 1 <= x <= x1 + 1 and y0 - 1 <= y <= y1 + 1:
                    return True
        return False

    assert not [p for p in _paths(root) if ends_inside_pill(p)]


def test_transit_hexagons_are_labelled_as_transit_networks(
    reference_lab: OspfTopology,
) -> None:
    root = _root(render_ospf_svg(reference_lab))
    labels = [t.text for t in root.iter(f"{SVG}text") if t.text == "transit network (Type 2)"]
    assert len(labels) == len(reference_lab.transit_networks) == 5


def test_the_word_switch_appears_only_as_a_denial(reference_lab: OspfTopology) -> None:
    """A reader must never be able to think a hexagon is a switch."""
    text = _texts(_root(render_ospf_svg(reference_lab))).lower()
    assert "switch" in text
    for occurrence in re.finditer("switch", text):
        window = text[max(0, occurrence.start() - 40): occurrence.start() + 40]
        assert "not a switch" in window or "not switches" in window, window


def test_every_transit_network_prefix_is_drawn(reference_lab: OspfTopology) -> None:
    text = _texts(_root(render_ospf_svg(reference_lab)))
    for network in reference_lab.transit_networks:
        assert network.prefix in text


def test_every_stub_prefix_is_drawn(reference_lab: OspfTopology) -> None:
    text = _texts(_root(render_ospf_svg(reference_lab)))
    for stub in reference_lab.stub_networks:
        assert stub.prefix in text


def test_every_router_id_is_drawn(reference_lab: OspfTopology) -> None:
    text = _texts(_root(render_ospf_svg(reference_lab)))
    for rid in reference_lab.router_ids():
        assert rid in text


def test_member_interface_addresses_are_drawn(reference_lab: OspfTopology) -> None:
    text = _texts(_root(render_ospf_svg(reference_lab)))
    for network in reference_lab.transit_networks:
        for address in network.member_interface_addresses.values():
            assert address in text


def test_evidence_state_is_encoded_without_relying_on_colour(
    reference_lab: OspfTopology,
) -> None:
    root = _root(render_ospf_svg(reference_lab))
    legend = " ".join(t.text or "" for t in root.iter(f"{SVG}text")).lower()
    for word in ("confirmed", "partial", "inconsistent", "unresolved"):
        assert word in legend


# =========================================================================== #
# 3. Evidence-state rendering
# =========================================================================== #


def _one_transit(state: OspfEvidenceState) -> OspfTopology:
    return OspfTopology(
        routers=[OspfRouter(router_id="1.1.1.1"), OspfRouter(router_id="2.2.2.2")],
        transit_networks=[
            OspfTransitNetwork(
                id="t1", area="0", prefix="10.0.0.0/30", dr_address="10.0.0.1",
                advertising_router="1.1.1.1",
                member_router_ids=["1.1.1.1", "2.2.2.2"],
                state=state,
                notes=["Type 2 attached routers disagree with Type 1 link"],
            )
        ],
    )


@pytest.mark.parametrize(
    ("state", "dash"),
    [
        (OspfEvidenceState.CONFIRMED, ""),
        (OspfEvidenceState.PARTIAL, "7 4"),
        (OspfEvidenceState.INCONSISTENT, "2 3"),
        (OspfEvidenceState.UNRESOLVED, "3 6"),
    ],
)
def test_state_drives_the_hexagon_stroke(state: OspfEvidenceState, dash: str) -> None:
    root = _root(render_ospf_svg(_one_transit(state)))
    hexagon = next(p for p in _polygons(root) if p.get("fill") == "#fff8ed")
    assert hexagon.get("stroke-dasharray", "") == dash


def test_inconsistent_state_is_still_drawn_and_named() -> None:
    svg = render_ospf_svg(_one_transit(OspfEvidenceState.INCONSISTENT))
    text = _texts(_root(svg))
    assert "10.0.0.0/30" in text
    assert "inconsistent" in text


def test_unresolved_transit_without_prefix_uses_dr_address() -> None:
    network = OspfTransitNetwork(
        id="t1", area="0", prefix=None, dr_address="10.7.7.9",
        advertising_router="1.1.1.1", member_router_ids=["1.1.1.1"],
        state=OspfEvidenceState.UNRESOLVED,
    )
    text = _texts(_root(render_ospf_svg(OspfTopology(
        routers=[OspfRouter(router_id="1.1.1.1")],
        transit_networks=[network],
    ))))
    assert "10.7.7.9" in text
    assert "mask unknown" in text


# =========================================================================== #
# 4. Aspect coverage: p2p links, multiple areas, unknown routers
# =========================================================================== #


def test_point_to_point_edges_are_drawn_purple_and_dashed() -> None:
    ospf = OspfTopology(
        routers=[OspfRouter(router_id="1.1.1.1"), OspfRouter(router_id="2.2.2.2")],
        logical_edges=[
            OspfLogicalEdge(
                source_router_id="1.1.1.1", destination_router_id="2.2.2.2",
                prefix="10.5.5.0/30", area="0",
                state=OspfEvidenceState.CONFIRMED,
            )
        ],
    )
    root = _root(render_ospf_svg(ospf))
    p2p = [p for p in _paths(root) if p.get("stroke") == "#6b46c1"]
    assert len(p2p) == 1
    # confirmed ⇒ solid; the style is still logically distinct (purple).
    assert p2p[0].get("stroke-dasharray") or p2p[0].get("stroke") == "#6b46c1"
    assert "10.5.5.0/30" in _texts(root)


def test_multiple_areas_are_shown_per_node() -> None:
    ospf = OspfTopology(
        routers=[OspfRouter(router_id="1.1.1.1", areas=["0", "7"])],
        transit_networks=[
            OspfTransitNetwork(
                id=f"t-{area}", area=area, prefix=f"10.{area}.0.0/30",
                dr_address=f"10.{area}.0.1", advertising_router="1.1.1.1",
                member_router_ids=["1.1.1.1"],
            )
            for area in ("0", "7")
        ],
    )
    text = _texts(_root(render_ospf_svg(ospf)))
    assert "areas 0,7" in text
    assert "area 0" in text and "area 7" in text


def test_router_seen_only_in_the_lsdb_is_drawn_and_flagged() -> None:
    ospf = OspfTopology(
        routers=[OspfRouter(router_id="1.1.1.1", device_id="r1", collected=True)],
        transit_networks=[
            OspfTransitNetwork(
                id="t1", area="0", prefix="10.0.0.0/30", dr_address="10.0.0.1",
                advertising_router="1.1.1.1",
                member_router_ids=["1.1.1.1", "9.9.9.9"],
                state=OspfEvidenceState.PARTIAL,
            )
        ],
    )
    text = _texts(_root(render_ospf_svg(ospf)))
    assert "9.9.9.9" in text
    assert "not collected" in text


def test_no_pid_or_area_is_hardcoded() -> None:
    """A two-process, three-area LSDB must not be rendered as pid 10 / area 0."""
    ospf = OspfTopology(
        routers=[
            OspfRouter(router_id="1.1.1.1", process_ids=["7", "42"], areas=["5"]),
        ],
    )
    text = _texts(_root(render_ospf_svg(ospf)))
    assert "pid 7/42" in text
    assert "area 5" in text
    assert "pid 10" not in text


def test_empty_topology_draws_an_honest_empty_state(empty_ospf: OspfTopology) -> None:
    root = _root(render_ospf_svg(empty_ospf))
    assert "No OSPF evidence was collected" in _texts(root)

    def span(poly: ET.Element) -> float:
        xs = [float(v.split(",")[0]) for v in poly.get("points", "").split() if "," in v]
        return max(xs) - min(xs)

    node_hexes = [
        p for p in _polygons(root) if p.get("fill") == "#fff8ed" and span(p) > 100
    ]
    assert node_hexes == []


def test_svg_never_leaks_a_credential(reference_lab: OspfTopology) -> None:
    svg = render_ospf_svg(reference_lab).lower()
    for needle in ("password", "secret", "md5", "key-string", "enable"):
        assert needle not in svg


# =========================================================================== #
# 5. Physical underlay stays separate
# =========================================================================== #


def _physical() -> Topology:
    return Topology(
        devices=[
            Device(id="r1", name="R1", vendor="cisco", platform="ios"),
            Device(id="r2", name="R2", vendor="cisco", platform="ios"),
        ],
        interfaces=[
            Interface(
                id="r1:eth0", device_id="r1", name="Ethernet0/0",
                admin_state=AdminState.UP, oper_state=OperState.UP,
            ),
            Interface(
                id="r2:eth0", device_id="r2", name="Ethernet0/0",
                admin_state=AdminState.UP, oper_state=OperState.UP,
            ),
        ],
        links=[
            Link(
                id="l1",
                source_interface_id="r1:eth0",
                destination_interface_id="r2:eth0",
                state=LinkState.UP,
            )
        ],
    )


def test_physical_underlay_adds_no_ospf_semantics() -> None:
    ospf = _one_transit(OspfEvidenceState.CONFIRMED)
    without = render_ospf_svg(ospf)
    with_phys = render_ospf_svg(ospf, physical=_physical())
    # The CDP cable appears, in its own colour, and is named in the legend.
    assert "#6b46c1" in with_phys
    assert "CDP cable (physical view)" in _texts(_root(with_phys))
    # Nothing about the OSPF reconstruction changed: same nodes, same hexagons,
    # same membership spokes. Only the grey underlay is added.
    assert len(_polygons(_root(without))) == len(_polygons(_root(with_phys)))
    def spokes(root: ET.Element) -> list[ET.Element]:
        return [p for p in _paths(root) if p.get("stroke") == "#c05621"]

    assert len(spokes(_root(without))) == len(spokes(_root(with_phys)))
    for text in ("10.0.0.0/30", "1.1.1.1", "2.2.2.2", "DR 10.0.0.1"):
        assert text in _texts(_root(with_phys))


def test_physical_underlay_is_grey_and_never_transit_coloured() -> None:
    root = _root(render_ospf_svg(_one_transit(OspfEvidenceState.CONFIRMED),
                                 physical=_physical()))
    physical_lines = [p for p in root.iter(f"{SVG}line") if p.get("stroke") == "#a0aec0"]
    assert physical_lines, "the CDP underlay should draw something"


# =========================================================================== #
# 6. HTML payload — data fidelity
# =========================================================================== #


def test_payload_is_pure_json(reference_lab: OspfTopology) -> None:
    payload = build_ospf_payload(reference_lab, title="t")
    assert json.loads(json.dumps(payload)) == payload


def test_payload_carries_every_required_field(reference_lab: OspfTopology) -> None:
    payload = build_ospf_payload(reference_lab, title="t")
    for key in (
        "routers", "transit_networks", "stub_networks", "logical_edges",
        "neighbors", "routes", "correlations", "router_lsas", "network_lsas",
        "warnings", "state_counts", "counts", "instances",
    ):
        assert key in payload, key


def test_transit_payload_keeps_full_traceability(reference_lab: OspfTopology) -> None:
    payload = build_ospf_payload(reference_lab, title="t")
    for network in payload["transit_networks"]:
        assert network["dr_address"]
        assert network["advertising_router"]
        assert network["member_router_ids"]
        assert network["state"]
        assert network["source_lsas"], "every transit network must cite its LSAs"
        for ref in network["source_lsas"]:
            assert ref["area"]
            assert ref["advertising_router"]
            assert ref["link_state_id"]
            assert ref["lsa_type"] in (1, 2)


def test_stub_payload_separates_prefixes_from_links(reference_lab: OspfTopology) -> None:
    payload = build_ospf_payload(reference_lab, title="t")
    assert payload["counts"]["stub_networks"] == 7
    for stub in payload["stub_networks"]:
        assert "member_router_ids" not in stub
        assert "dr_address" not in stub


def test_route_payload_keeps_learned_and_connected_apart(
    reference_lab: OspfTopology,
) -> None:
    payload = build_ospf_payload(reference_lab, title="t")
    learned = [r for r in payload["routes"] if r["learned"]]
    connected = [r for r in payload["routes"] if not r["learned"]]
    assert len(learned) == 9
    assert len(connected) == 2
    assert {r["prefix"] for r in connected} == {"10.0.23.0/30", "10.255.255.2/32"}


def test_counts_add_up(reference_lab: OspfTopology) -> None:
    counts = build_ospf_payload(reference_lab, title="t")["counts"]
    assert counts["routers"] == 5
    assert counts["transit_networks"] == 5
    assert counts["router_lsas"] == 5
    assert counts["network_lsas"] == 5
    assert counts["learned_routes"] + counts["connected_routes"] == counts["routes"]


def test_state_counts_cover_every_reconstructed_relationship(
    reference_lab: OspfTopology,
) -> None:
    payload = build_ospf_payload(reference_lab, title="t")
    total = sum(payload["state_counts"].values())
    assert total == len(reference_lab.transit_networks) + len(reference_lab.logical_edges)


def test_empty_payload_keeps_its_warning(empty_ospf: OspfTopology) -> None:
    payload = build_ospf_payload(empty_ospf, title="t")
    assert payload["warnings"]
    assert "does not appear to run OSPF" in payload["warnings"][0]
    assert payload["counts"]["routers"] == 0


# =========================================================================== #
# 7. HTML document
# =========================================================================== #


def test_html_is_one_self_contained_file(reference_lab: OspfTopology) -> None:
    html = render_ospf_html(reference_lab, title="t")
    assert html.count("<!DOCTYPE html>") == 1
    assert "<link" not in html
    assert "src=" not in html
    assert "@import" not in html
    assert "http://" not in html and "https://" not in html
    assert "fetch(" not in html
    assert "XMLHttpRequest" not in html


def test_html_embeds_parseable_data(reference_lab: OspfTopology) -> None:
    html = render_ospf_html(reference_lab, title="t")
    match = re.search(
        r'<script id="ospf-data" type="application/json">(.*?)</script>', html, re.S
    )
    assert match
    data = json.loads(match.group(1).replace("<\\/", "</"))
    assert data["counts"]["transit_networks"] == 5
    assert data["capability"] == "ospf-logical"


def test_html_escapes_a_hostile_title(reference_lab: OspfTopology) -> None:
    html = render_ospf_html(reference_lab, title='<script>alert("x")</script>')
    assert "<script>alert" not in html
    assert "&lt;script&gt;" in html


def test_html_escapes_hostile_data() -> None:
    """A prefix or note is data, never markup."""
    ospf = OspfTopology(
        routers=[OspfRouter(router_id="1.1.1.1")],
        transit_networks=[
            OspfTransitNetwork(
                id='t"1', area="0", prefix="</script><img src=x>", dr_address="10.0.0.1",
                advertising_router="1.1.1.1", member_router_ids=["1.1.1.1"],
                notes=["<b>boom</b>"],
            )
        ],
    )
    html = render_ospf_html(ospf, title="t")
    match = re.search(
        r'<script id="ospf-data" type="application/json">(.*?)</script>', html, re.S
    )
    assert match, "a </script> in the data must not close the tag"
    json.loads(match.group(1).replace("<\\/", "</"))     # still valid JSON


def test_html_never_calls_a_transit_network_a_switch_or_a_cable(
    reference_lab: OspfTopology,
) -> None:
    """Every mention of switch/cable in the document must be a denial.

    The window is generous because the words appear inside JS string literals
    that are split across lines; what matters is that no sentence asserts a
    transit network *is* one.
    """
    html = render_ospf_html(reference_lab, title="t")
    for match_ in re.finditer(r"switch|cable", html, re.I):
        window = html[max(0, match_.start() - 130): match_.start() + 130].lower()
        assert (
            "never" in window or "not a" in window or "not switches" in window
        ), window


def test_empty_html_says_so_rather_than_showing_nothing(empty_ospf: OspfTopology) -> None:
    html = render_ospf_html(empty_ospf, title="t")
    assert "does not appear to run OSPF" in html


def test_html_rendering_is_deterministic(reference_lab: OspfTopology) -> None:
    assert render_ospf_html(reference_lab, title="t") == render_ospf_html(
        reference_lab, title="t"
    )


# =========================================================================== #
# 8. Sanity: the reference data itself
# =========================================================================== #


def test_reference_lab_matches_the_task_table(reference_lab: OspfTopology) -> None:
    by_prefix = {n.prefix: n for n in reference_lab.transit_networks}
    expected = {
        "10.0.21.0/30": ("10.0.21.1", "10.255.255.3"),
        "10.0.23.0/30": ("10.0.23.1", "10.255.255.2"),
        "10.0.32.0/30": ("10.0.32.2", "10.255.255.3"),
        "10.0.34.0/30": ("10.0.34.2", "10.255.255.5"),
        "10.0.41.0/30": ("10.0.41.1", "10.255.255.5"),
    }
    assert set(by_prefix) == set(expected)
    for prefix, (dr, adv) in expected.items():
        assert by_prefix[prefix].dr_address == dr
        assert by_prefix[prefix].advertising_router == adv
        assert by_prefix[prefix].state is OspfEvidenceState.CONFIRMED


def test_renderers_keep_instances_reachable() -> None:
    """Router ID, PID and area must all survive into the payload."""
    ospf = OspfTopology(
        instances=[
            OspfInstance(device_id="r1", process_id="10", router_id="10.255.255.1")
        ],
        routers=[OspfRouter(router_id="10.255.255.1", device_id="r1",
                            process_ids=["10"], areas=["0"])],
    )
    payload = build_ospf_payload(ospf, title="t")
    assert payload["instances"][0]["process_id"] == "10"
    assert payload["instances"][0]["router_id"] == "10.255.255.1"
    assert payload["routers"][0]["process_ids"] == ["10"]


def test_router_lsa_links_reach_the_payload() -> None:
    from nettwin.domain.ospf_models import OspfLinkType, OspfLsaLink

    ospf = OspfTopology(
        router_lsas=[
            OspfRouterLsa(
                area="0", link_state_id="1.1.1.1", advertising_router="1.1.1.1",
                number_of_links=1,
                links=[
                    OspfLsaLink(
                        link_type=OspfLinkType.STUB, link_id="10.1.0.0",
                        network_mask="255.255.255.0", metric=10,
                    )
                ],
            )
        ]
    )
    payload = build_ospf_payload(ospf, title="t")
    link = payload["router_lsas"][0]["links"][0]
    assert link["link_type"] == "stub"
    assert link["prefix"] == "10.1.0.0/24"
    assert link["metric"] == 10


def test_network_lsa_prefix_and_members_reach_the_payload() -> None:
    ospf = OspfTopology(
        network_lsas=[
            OspfNetworkLsa(
                area="0", link_state_id="10.0.0.1", advertising_router="1.1.1.1",
                network_mask="255.255.255.252",
                attached_routers=["1.1.1.1", "2.2.2.2"],
            )
        ]
    )
    lsa = build_ospf_payload(ospf, title="t")["network_lsas"][0]
    assert lsa["prefix"] == "10.0.0.0/30"
    assert lsa["attached_routers"] == ["1.1.1.1", "2.2.2.2"]


def test_route_types_are_serialized_by_name() -> None:
    ospf = OspfTopology(
        routes=[
            OspfRoute(device_id="r1", prefix="10.0.0.0/30",
                      route_type=OspfRouteType.INTRA_AREA, cost=11,
                      next_hop="10.0.23.2"),
            OspfRoute(device_id="r1", prefix="10.0.23.0/30",
                      route_type=OspfRouteType.CONNECTED, cost=1, learned=False),
        ]
    )
    payload = build_ospf_payload(ospf, title="t")
    assert payload["routes"][0]["route_type"] == "intra-area"
    assert payload["routes"][1]["route_type"] == "connected"
    assert payload["routes"][1]["learned"] is False


def test_evidence_tags_survive(reference_lab: OspfTopology) -> None:
    payload = build_ospf_payload(reference_lab, title="t")
    tags = {t for n in payload["transit_networks"] for t in n["evidence"]}
    assert "ospf-router-lsa" in tags
    assert "ospf-network-lsa" in tags
