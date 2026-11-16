"""Phase 2.5 — topology renderers (SVG + HTML). **OFFLINE ONLY.**

Every case builds a ``Topology`` from the domain models directly; nothing here
reads CLI output or touches a device. The renderers must be *honest*: what they
draw has to be backed by the model, and empty/incomplete topologies must
degrade instead of failing.
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
from nettwin.render import build_payload, render_html, render_svg
from nettwin.render.topology_html import _CSS, _JS


def _dev(
    device_id: str,
    name: str,
    *,
    vendor: str = "cisco",
    platform: str = "C9300",
    mgmt: str | None = "10.0.0.1",
) -> Device:
    return Device(
        id=device_id, name=name, vendor=vendor, platform=platform,
        management_address=mgmt,
    )


def _iface(
    iface_id: str,
    device_id: str,
    name: str,
    *,
    addresses: list[str] | None = None,
    admin: AdminState = AdminState.UP,
    oper: OperState = OperState.UP,
) -> Interface:
    return Interface(
        id=iface_id, device_id=device_id, name=name, vrf_id=None,
        ipv4_addresses=addresses or [], admin_state=admin, oper_state=oper,
    )


def _two_device_topology(state: LinkState = LinkState.UP) -> Topology:
    return Topology(
        devices=[_dev("r1", "R1"), _dev("r2", "R2", mgmt="10.0.0.2")],
        interfaces=[
            _iface("r1-g0/1", "r1", "GigabitEthernet0/1", addresses=["10.1.0.1/30"]),
            _iface("r2-g0/2", "r2", "GigabitEthernet0/2", addresses=["10.1.0.2/30"]),
        ],
        links=[Link(
            id="r1-g0/1--r2-g0/2",
            source_interface_id="r1-g0/1",
            destination_interface_id="r2-g0/2",
            state=state,
        )],
    )


# =========================================================================== #
# SVG
# =========================================================================== #


def test_svg_is_wellformed_xml() -> None:
    svg = render_svg(_two_device_topology())
    root = ET.fromstring(svg)     # raises on malformed XML
    assert root.tag == "{http://www.w3.org/2000/svg}svg"


def test_svg_contains_every_device_name() -> None:
    svg = render_svg(_two_device_topology())
    assert "R1" in svg and "R2" in svg


def test_svg_shows_both_endpoint_interface_names() -> None:
    svg = render_svg(_two_device_topology())
    assert "GigabitEthernet0/1" in svg
    assert "GigabitEthernet0/2" in svg


def test_svg_shows_interface_ips_when_available() -> None:
    svg = render_svg(_two_device_topology())
    assert "10.1.0.1/30" in svg
    assert "10.1.0.2/30" in svg


def test_svg_shows_management_addresses() -> None:
    svg = render_svg(_two_device_topology())
    assert "10.0.0.1" in svg and "10.0.0.2" in svg


def _edge_line(svg: str) -> str:
    """The drawn edge itself, not the legend swatch."""
    for line in svg.splitlines():
        if line.startswith("<line") and "x1=\"155\"" in line:
            return line
    raise AssertionError("edge line not found")


def test_svg_link_state_is_distinguishable() -> None:
    up = render_svg(_two_device_topology(LinkState.UP))
    down = render_svg(_two_device_topology(LinkState.DOWN))
    assert "stroke-dasharray" not in _edge_line(up)
    assert "stroke-dasharray" in _edge_line(down)
    assert "2f855a" in _edge_line(up)      # green
    assert "c53030" in _edge_line(down)    # red


def test_svg_empty_topology_renders_a_message_not_an_error() -> None:
    svg = render_svg(Topology())
    ET.fromstring(svg)
    assert "No devices were collected" in svg


def test_svg_device_without_links_still_renders() -> None:
    topology = Topology(
        devices=[_dev("r1", "R1")],
        interfaces=[_iface("r1-g0/1", "r1", "GigabitEthernet0/1")],
    )
    svg = render_svg(topology)
    ET.fromstring(svg)
    assert "R1" in svg
    assert "0 confirmed link(s)" in svg


def test_svg_marks_unknown_platform_honestly() -> None:
    topology = Topology(devices=[_dev("x", "X", vendor="unknown", platform="unknown", mgmt=None)])
    svg = render_svg(topology)
    assert "vendor not evidenced" in svg
    assert "management address not evidenced" in svg


def test_svg_is_deterministic() -> None:
    topology = _two_device_topology()
    assert render_svg(topology) == render_svg(topology)


def test_svg_escapes_html_in_names() -> None:
    topology = Topology(devices=[_dev("x", "R1<script>&")])
    svg = render_svg(topology)
    ET.fromstring(svg)                      # still valid XML
    assert "<script>" not in svg
    assert "&lt;script&gt;" in svg


# =========================================================================== #
# HTML
# =========================================================================== #


def test_html_is_self_contained_no_external_resources() -> None:
    """No CDN, no fetch, no external stylesheet: it must open from disk."""
    html = render_html(_two_device_topology())
    assert not re.search(r'src\s*=\s*["\']https?://', html)
    assert not re.search(r'href\s*=\s*["\']https?://', html)
    assert "@import" not in html
    assert "fetch(" not in html
    assert "XMLHttpRequest" not in html


def test_html_inlines_css_and_js() -> None:
    html = render_html(_two_device_topology())
    assert "<style>" in html and "</style>" in html
    assert "<script>" in html
    assert _CSS.strip().splitlines()[0] in html


def test_html_embeds_topology_as_json() -> None:
    html = render_html(_two_device_topology())
    match = re.search(
        r'<script id="topology-data" type="application/json">(.*?)</script>',
        html,
        re.DOTALL,
    )
    assert match is not None
    payload = json.loads(match.group(1).replace("<\\/", "</"))
    assert payload["counts"] == {
        "devices": 2, "interfaces": 2, "links": 1, "routes": 0,
    }
    assert {d["name"] for d in payload["devices"]} == {"R1", "R2"}


def test_html_payload_carries_device_identity_fields() -> None:
    payload = build_payload(_two_device_topology(), title="t")
    r1 = next(d for d in payload["devices"] if d["name"] == "R1")
    assert r1["vendor"] == "cisco"
    assert r1["platform"] == "C9300"
    assert r1["management_address"] == "10.0.0.1"


def test_html_payload_carries_both_link_endpoints() -> None:
    payload = build_payload(_two_device_topology(), title="t")
    link = payload["links"][0]
    assert link["source"]["interface_name"] == "GigabitEthernet0/1"
    assert link["destination"]["interface_name"] == "GigabitEthernet0/2"
    assert link["source"]["addresses"] == ["10.1.0.1/30"]
    assert link["destination"]["addresses"] == ["10.1.0.2/30"]


def test_html_empty_topology_renders() -> None:
    html = render_html(Topology())
    payload_match = re.search(
        r'<script id="topology-data" type="application/json">(.*?)</script>',
        html, re.DOTALL,
    )
    assert payload_match is not None
    payload = json.loads(payload_match.group(1))
    assert payload["devices"] == []
    assert payload["links"] == []


def test_html_devices_without_links_render() -> None:
    topology = Topology(devices=[_dev("r1", "R1")], interfaces=[])
    payload = build_payload(topology, title="t")
    assert len(payload["devices"]) == 1
    assert payload["links"] == []


def test_domain_model_refuses_a_link_with_an_unknown_endpoint() -> None:
    """Structural honesty: a dangling link cannot even be constructed.

    This is why the renderer has no "invented endpoint" branch to get wrong —
    the invariant is enforced upstream, so every link the renderer sees has two
    real interfaces. The ``state_evidenced`` flag is the belt to that braces.
    """
    with pytest.raises(Exception, match="references unknown interface"):
        Topology(
            devices=[_dev("r1", "R1"), _dev("r2", "R2")],
            interfaces=[_iface("r1-g0/1", "r1", "GigabitEthernet0/1")],
            links=[Link(
                id="l1",
                source_interface_id="r1-g0/1",
                destination_interface_id="r2-missing",
                state=LinkState.DOWN,
            )],
        )


def test_html_marks_every_rendered_endpoint_as_evidenced() -> None:
    """Every endpoint in a valid topology resolves, so nothing claims otherwise."""
    payload = build_payload(_two_device_topology(), title="t")
    for link in payload["links"]:
        assert link["source"]["state_evidenced"] is True
        assert link["destination"]["state_evidenced"] is True
        assert link["source"]["interface_name"]
        assert link["destination"]["interface_name"]


def test_html_interface_state_reflects_model() -> None:
    topology = Topology(
        devices=[_dev("r1", "R1")],
        interfaces=[
            _iface("a", "r1", "Gi0/1"),
            _iface("b", "r1", "Gi0/2", admin=AdminState.DOWN, oper=OperState.DOWN),
            _iface("c", "r1", "Gi0/3", admin=AdminState.UP, oper=OperState.DOWN),
        ],
    )
    payload = build_payload(topology, title="t")
    by_name = {i["name"]: i for i in payload["interfaces"]}
    assert by_name["Gi0/1"]["is_up"] is True
    assert by_name["Gi0/2"]["is_up"] is False
    assert by_name["Gi0/3"]["is_up"] is False       # admin up, oper down


def test_html_escapes_script_tag_in_data() -> None:
    """A device name containing </script> must not break out of the data block."""
    topology = Topology(devices=[_dev("x", "evil</script><b>x")])
    html = render_html(topology)
    body_between = html.split('<script id="topology-data" type="application/json">')[1]
    data_block = body_between.split("</script>")[0]
    assert "</script>" not in data_block


def test_html_allowed_to_be_large_but_single_file(tmp_path) -> None:
    topology = _two_device_topology()
    out = tmp_path / "topology.html"
    out.write_text(render_html(topology, title="t"), encoding="utf-8")
    text = out.read_text(encoding="utf-8")
    assert text.startswith("<!DOCTYPE html>")
    assert text.count("<script") == 2        # data block + behaviour


@pytest.mark.parametrize("title", ["plain", "with <angles>", "with \"quotes\"", "با فارسی"])
def test_titles_are_escaped(title: str) -> None:
    html = render_html(_two_device_topology(), title=title)
    assert "<title>" in html
    # the raw title must never appear unescaped inside a tag
    if "<" in title:
        assert title not in html.split("<title>")[1].split("</title>")[0]


# =========================================================================== #
# Regression guards for interaction bugs found by driving a real browser
# =========================================================================== #


def test_html_pan_only_starts_on_empty_background() -> None:
    """Pointer capture on the whole canvas swallowed node/link clicks."""
    assert "function isBackground(target){" in _JS
    assert "if(!isBackground(e.target)) return;" in _JS


def test_html_link_hit_area_is_not_stroke_transparent() -> None:
    """``stroke: transparent`` was not reliably hit-testable."""
    assert 'stroke:"transparent"' not in _JS
    assert '"stroke-opacity":"0.001"' in _JS


def test_html_background_click_does_not_clear_a_selection() -> None:
    """Clicking a node used to bubble to the stage handler and reset the panel."""
    assert "if(e.target===svg || e.target===stage) resetPanel();" in _JS
    assert 'addEventListener("click",function(){ resetPanel(); })' not in _JS


def test_html_node_click_shows_details_not_just_selection() -> None:
    assert "showDevice(d)" in _JS
    assert "showLink(link)" in _JS


def test_svg_packs_isolated_devices_in_a_grid_not_a_column() -> None:
    """A run with no confirmed links used to stack every device vertically."""
    devices = [
        _dev(f"d{i}", f"D{i}", mgmt=f"10.0.0.{i}") for i in range(1, 7)
    ]
    topology = Topology(devices=devices)
    svg = render_svg(topology)
    xs = {line.split('x="')[1].split('"')[0] for line in svg.splitlines() if "<rect" in line and 'height="84"' in line}
    # six isolated devices must occupy at least two distinct columns
    assert len(xs) >= 2
    ET.fromstring(svg)


def test_svg_canvas_is_wide_enough_for_the_legend() -> None:
    from nettwin.render.topology_svg import LEGEND_MIN_WIDTH

    svg = render_svg(Topology(devices=[_dev("a", "A")]))
    width = int(svg.split('width="')[1].split('"')[0])
    assert width >= LEGEND_MIN_WIDTH
