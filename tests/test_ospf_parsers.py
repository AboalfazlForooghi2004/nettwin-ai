"""Phase 2.6 — OSPF CLI parsers. **OFFLINE, fixture-driven.**

Every fixture under ``tests/data/ospf/`` is built from the real PNETLab capture
described in the task (process 10, area 0, routers .1–.5, five transit
networks). Malformed, partial and empty variants are generated inline so the
parsers are exercised on the failure side too.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from nettwin.collect import ospf_parsers as P
from nettwin.domain.ospf_models import OspfLinkType, OspfRouteType

DATA = Path(__file__).parent / "data" / "ospf"


def _read(name: str) -> str:
    return (DATA / name).read_text(encoding="utf-8")


# =========================================================================== #
# 1. show ip ospf neighbor
# =========================================================================== #


def test_parse_ospf_neighbors_real_lab() -> None:
    neighbors, warnings = P.parse_show_ip_ospf_neighbor(
        _read("r2_show_ip_ospf_neighbor.txt")
    )
    assert warnings == []
    assert len(neighbors) == 2
    first = neighbors[0]
    assert first.neighbor_id == "10.255.255.4"
    assert first.state == "FULL/BDR"
    assert first.address == "10.0.23.2"
    assert first.interface == "Ethernet0/0"
    assert first.priority == "1"
    assert first.dead_time == "00:00:36"


def test_neighbor_state_and_role_split() -> None:
    from nettwin.domain.ospf_models import OspfNeighbor

    neighbor = OspfNeighbor(
        device_id="r2", local_interface="Et0/0", neighbor_router_id="10.0.0.1",
        neighbor_address="10.0.0.2", state="FULL/DR",
    )
    assert neighbor.adjacency_state == "FULL"
    assert neighbor.role == "DR"


def test_neighbor_without_role() -> None:
    from nettwin.domain.ospf_models import OspfNeighbor

    neighbor = OspfNeighbor(
        device_id="r2", local_interface="Et0/0", neighbor_router_id="10.0.0.1",
        neighbor_address="10.0.0.2", state="2WAY",
    )
    assert neighbor.adjacency_state == "2WAY"
    assert neighbor.role == ""


@pytest.mark.parametrize("state", ["FULL/DR", "FULL/BDR", "2WAY/DROTHER",
                                   "EXSTART/DROTHER", "INIT/DROTHER", "LOADING/DROTHER"])
def test_neighbor_parses_every_adjacency_state(state: str) -> None:
    text = (
        "Neighbor ID     Pri State           Dead Time   Address         Interface\n"
        f"10.255.255.9      1 {state:<15} 00:00:33    10.0.99.2       Ethernet0/3\n"
    )
    neighbors, warnings = P.parse_show_ip_ospf_neighbor(text)
    assert warnings == []
    assert neighbors[0].state == state


def test_neighbor_empty_output() -> None:
    neighbors, warnings = P.parse_show_ip_ospf_neighbor("")
    assert neighbors == []
    assert warnings == ["show ip ospf neighbor: empty output"]


def test_neighbor_malformed_rows_are_reported_not_dropped_silently() -> None:
    text = (
        "Neighbor ID     Pri State           Dead Time   Address         Interface\n"
        "10.255.255.9      1 FULL/DR\n"                      # short row
        "not-an-ip         1 FULL/DR        00:00:33    10.0.99.2    Et0/0\n"
    )
    neighbors, warnings = P.parse_show_ip_ospf_neighbor(text)
    assert neighbors == []
    assert len(warnings) == 3          # short row + non-IP line + "no rows"


def test_neighbor_ospf_not_enabled_message() -> None:
    _, warnings = P.parse_show_ip_ospf_neighbor("% OSPF not enabled\n")
    assert any("skipped non-neighbor line" in w for w in warnings)


# =========================================================================== #
# 2. show ip ospf interface brief
# =========================================================================== #


def test_parse_ospf_interfaces_real_lab() -> None:
    interfaces, warnings = P.parse_show_ip_ospf_interface_brief(
        _read("r2_show_ip_ospf_interface_brief.txt"), "r2"
    )
    assert warnings == []
    by_name = {i.name: i for i in interfaces}
    assert set(by_name) == {"Et0/0", "Et0/1", "Lo0"}

    et0 = by_name["Et0/0"]
    assert et0.process_id == "10"
    assert et0.area == "0"
    assert et0.ip_address == "10.0.23.1"
    assert et0.mask == "255.255.255.252"
    assert et0.cost == 10
    assert et0.state == "DR"
    assert (et0.neighbors_full, et0.neighbors_total) == (2, 2)


def test_interface_prefix_computed_from_address_and_mask() -> None:
    interfaces, _ = P.parse_show_ip_ospf_interface_brief(
        _read("r2_show_ip_ospf_interface_brief.txt"), "r2"
    )
    by_name = {i.name: i for i in interfaces}
    assert by_name["Et0/0"].prefix == "10.0.23.0/30"
    assert by_name["Lo0"].prefix == "10.255.255.2/32"


def test_interface_multiple_area_and_process_not_hardcoded() -> None:
    """Areas and processes come from the row — none is assumed."""
    text = (
        "Interface    PID   Area            IP Address/Mask    Cost  State Nbrs F/C\n"
        "Et0/0        1     0               10.1.0.1/30        10    BDR   1/1\n"
        "Et0/1        2     0.0.0.7         10.2.0.1/30        20    DR    2/2\n"
        "Et0/2        7     192.168.5.1     10.3.0.1/24        5     P2P   1/1\n"
    )
    interfaces, warnings = P.parse_show_ip_ospf_interface_brief(text, "dev")
    assert warnings == []
    assert [(i.process_id, i.area) for i in interfaces] == [
        ("1", "0"), ("2", "0.0.0.7"), ("7", "192.168.5.1"),
    ]


def test_interface_empty_output() -> None:
    interfaces, warnings = P.parse_show_ip_ospf_interface_brief("")
    assert interfaces == []
    assert warnings == ["show ip ospf interface brief: empty output"]


def test_interface_malformed_row_warns() -> None:
    interfaces, warnings = P.parse_show_ip_ospf_interface_brief(
        "Interface    PID   Area            IP Address/Mask    Cost  State Nbrs F/C\n"
        "Et0/0        X     0               garbage\n"
    )
    assert interfaces == []
    assert any("unparseable row" in w for w in warnings)


# =========================================================================== #
# 3. show ip ospf database (summary)
# =========================================================================== #


def test_parse_database_summary_real_lab() -> None:
    summary, warnings = P.parse_show_ip_ospf_database(
        _read("r2_show_ip_ospf_database.txt")
    )
    assert warnings == []
    router_rows = [s for s in summary if s.lsa_type == 1]
    net_rows = [s for s in summary if s.lsa_type == 2]
    assert len(router_rows) == 5
    assert len(net_rows) == 5
    assert {s.area for s in summary} == {"0"}
    assert router_rows[1].link_count == 4
    assert net_rows[0].link_count is None      # Net rows carry no link count


def test_database_summary_multiple_areas() -> None:
    text = (
        "\t\tRouter Link States (Area 0)\n"
        "Link ID         ADV Router      Age         Seq#       Checksum Link count\n"
        "10.0.0.1        10.0.0.1        10          0x80000001 0x1111 2\n"
        "\n\t\tNet Link States (Area 0)\n"
        "Link ID         ADV Router      Age         Seq#       Checksum\n"
        "10.1.0.1        10.0.0.1        10          0x80000001 0x2222\n"
        "\n\t\tRouter Link States (Area 1)\n"
        "Link ID         ADV Router      Age         Seq#       Checksum Link count\n"
        "10.0.0.2        10.0.0.2        20          0x80000002 0x3333 3\n"
    )
    summary, warnings = P.parse_show_ip_ospf_database(text)
    assert warnings == []
    assert [(s.area, s.lsa_type, s.advertising_router) for s in summary] == [
        ("0", 1, "10.0.0.1"),
        ("0", 2, "10.0.0.1"),
        ("1", 1, "10.0.0.2"),
    ]


def test_database_summary_empty_output() -> None:
    summary, warnings = P.parse_show_ip_ospf_database("")
    assert summary == []
    assert warnings == ["show ip ospf database: empty output"]


# =========================================================================== #
# 4. Router LSA (Type 1)
# =========================================================================== #


def test_parse_router_lsas_real_lab() -> None:
    lsas, warnings = P.parse_show_ip_ospf_database_router(
        _read("r2_show_ip_ospf_database_router.txt"), "r2"
    )
    assert warnings == []
    assert len(lsas) == 5
    by_router = {lsa.advertising_router: lsa for lsa in lsas}
    assert set(by_router) == {
        "10.255.255.1", "10.255.255.2", "10.255.255.3",
        "10.255.255.4", "10.255.255.5",
    }
    # Declared link counts agree with what was actually parsed.
    for lsa in lsas:
        assert lsa.number_of_links == len(lsa.links)


def test_router_lsa_link_types_separated() -> None:
    lsas, _ = P.parse_show_ip_ospf_database_router(
        _read("r2_show_ip_ospf_database_router.txt"), "r2"
    )
    r2 = next(lsa for lsa in lsas if lsa.advertising_router == "10.255.255.2")
    transit = [link for link in r2.links if link.link_type is OspfLinkType.TRANSIT]
    stub = [link for link in r2.links if link.link_type is OspfLinkType.STUB]
    assert len(transit) == 1
    assert len(stub) == 3
    assert transit[0].link_id == "10.0.23.1"
    assert transit[0].link_data == "10.0.23.1"
    assert transit[0].metric == 10


def test_router_lsa_stub_link_mask_becomes_prefix() -> None:
    """`(Link Data) Network Mask:` carries the mask — it must become the prefix."""
    lsas, _ = P.parse_show_ip_ospf_database_router(
        _read("r2_show_ip_ospf_database_router.txt"), "r2"
    )
    r2_1 = next(lsa for lsa in lsas if lsa.advertising_router == "10.255.255.1")
    stub = next(link for link in r2_1.links if link.link_type is OspfLinkType.STUB)
    assert stub.link_id == "192.168.98.32"
    assert stub.network_mask == "255.255.255.224"
    assert stub.prefix == "192.168.98.32/27"


def test_router_lsa_point_to_point_and_virtual_links() -> None:
    text = """
		Router Link States (Area 0)

  LS age: 100
  LS Type: Router Links
  Link State ID: 10.0.0.1
  Advertising Router: 10.0.0.1
  LS Seq Number: 80000001
  Checksum: 0xABCD
  Number of Links: 2

    Link connected to: another Router (point-to-point)
     (Link ID) Neighboring Router ID: 10.0.0.2
     (Link Data) Router Interface address: 10.9.9.1
      Number of MTID metrics: 0
       TOS 0 Metrics: 10

    Link connected to: a Virtual Link
     (Link ID) Neighboring Router ID: 10.0.0.3
     (Link Data) Router Interface address: 10.9.9.2
      Number of MTID metrics: 0
       TOS 0 Metrics: 20
"""
    lsas, warnings = P.parse_show_ip_ospf_database_router(text, "r1")
    assert warnings == []
    kinds = [link.link_type for link in lsas[0].links]
    assert kinds == [OspfLinkType.POINT_TO_POINT, OspfLinkType.VIRTUAL]


def test_router_lsa_unrecognized_link_type_kept_as_unknown() -> None:
    text = """
		Router Link States (Area 0)

  LS age: 100
  LS Type: Router Links
  Link State ID: 10.0.0.1
  Advertising Router: 10.0.0.1
  Number of Links: 1

    Link connected to: a Someday Invented Network
     (Link ID) Designated Router address: 10.0.0.9
"""
    lsas, warnings = P.parse_show_ip_ospf_database_router(text, "r1")
    assert lsas[0].links[0].link_type is OspfLinkType.UNKNOWN
    assert any("unrecognized link type" in w for w in warnings)


def test_router_lsa_empty_output() -> None:
    lsas, warnings = P.parse_show_ip_ospf_database_router("")
    assert lsas == []
    # The warning must admit that no observer identity was available rather
    # than inventing one.
    assert warnings == ["show ip ospf database router [observer unidentified]: empty output"]

    _, attributed = P.parse_show_ip_ospf_database_router("", "r4")
    assert attributed == ["show ip ospf database router [observer=r4]: empty output"]


def test_router_lsa_declared_link_count_mismatch_warns() -> None:
    text = """
		Router Link States (Area 0)

  LS age: 100
  LS Type: Router Links
  Link State ID: 10.0.0.1
  Advertising Router: 10.0.0.1
  Number of Links: 5

    Link connected to: a Stub Network
     (Link ID) Network/subnet number: 10.5.5.0
     (Link Data) Network Mask: 255.255.255.0
      TOS 0 Metrics: 1
"""
    lsas, warnings = P.parse_show_ip_ospf_database_router(text, "r1")
    # Reported...
    assert any("declares 5 link(s) but 1 were parsed" in w for w in warnings)
    # ...and withheld: an LSA whose own count contradicts its body is not
    # evidence, so it must not travel onward as if it were.
    assert lsas == []
    assert any("LSA dropped" in w for w in warnings)


def test_router_lsa_missing_advertising_router_warns() -> None:
    text = """
		Router Link States (Area 0)

  LS age: 100
  LS Type: Router Links
  Link State ID: 10.0.0.1
  Number of Links: 0
"""
    _, warnings = P.parse_show_ip_ospf_database_router(text, "r1")
    assert any("no Advertising Router" in w for w in warnings)


# =========================================================================== #
# 5. Network LSA (Type 2)
# =========================================================================== #


def test_parse_network_lsas_real_lab() -> None:
    lsas, warnings = P.parse_show_ip_ospf_database_network(
        _read("r2_show_ip_ospf_database_network.txt"), "r2"
    )
    assert warnings == []
    assert len(lsas) == 5
    by_dr = {lsa.link_state_id: lsa for lsa in lsas}
    assert set(by_dr) == {
        "10.0.21.1", "10.0.23.1", "10.0.32.2", "10.0.34.2", "10.0.41.1"
    }


def test_network_lsa_prefix_from_dr_address_and_mask() -> None:
    lsas, _ = P.parse_show_ip_ospf_database_network(
        _read("r2_show_ip_ospf_database_network.txt"), "r2"
    )
    by_dr = {lsa.link_state_id: lsa for lsa in lsas}
    assert by_dr["10.0.21.1"].prefix == "10.0.21.0/30"
    assert by_dr["10.0.41.1"].prefix == "10.0.41.0/30"


def test_network_lsa_attached_routers_real_lab() -> None:
    lsas, _ = P.parse_show_ip_ospf_database_network(
        _read("r2_show_ip_ospf_database_network.txt"), "r2"
    )
    by_dr = {lsa.link_state_id: lsa for lsa in lsas}
    assert by_dr["10.0.21.1"].attached_routers == ["10.255.255.3", "10.255.255.1"]
    assert by_dr["10.0.23.1"].attached_routers == ["10.255.255.2", "10.255.255.4"]
    assert by_dr["10.0.32.2"].attached_routers == ["10.255.255.3", "10.255.255.4"]
    assert by_dr["10.0.34.2"].attached_routers == ["10.255.255.5", "10.255.255.4"]
    assert by_dr["10.0.41.1"].attached_routers == ["10.255.255.5", "10.255.255.1"]


def test_network_lsa_multiple_attached_routers_multi_access() -> None:
    """A five-router segment must keep all five members — that is the point."""
    attached = "".join(
        f"\tAttached Router: 10.255.255.{i}\n" for i in range(1, 6)
    )
    text = (
        "\t\tNet Link States (Area 0)\n"
        "  LS age: 100\n"
        "  LS Type: Network Links\n"
        "  Link State ID: 10.9.9.1 (address of Designated Router)\n"
        "  Advertising Router: 10.255.255.1\n"
        "  Network Mask: /24\n"
        + attached
    )
    lsas, warnings = P.parse_show_ip_ospf_database_network(text, "r1")
    assert warnings == []
    assert len(lsas[0].attached_routers) == 5
    assert lsas[0].prefix == "10.9.9.0/24"


def test_network_lsa_dotted_mask_is_accepted() -> None:
    text = (
        "\t\tNet Link States (Area 0)\n"
        "  LS age: 100\n"
        "  Link State ID: 10.9.9.1 (address of Designated Router)\n"
        "  Advertising Router: 10.255.255.1\n"
        "  Network Mask: 255.255.255.252\n"
        "\tAttached Router: 10.255.255.1\n"
        "\tAttached Router: 10.255.255.2\n"
    )
    lsas, _ = P.parse_show_ip_ospf_database_network(text, "r1")
    assert lsas[0].network_mask == "255.255.255.252"
    assert lsas[0].prefix == "10.9.9.0/30"


def test_network_lsa_missing_mask_warns_and_prefix_is_none() -> None:
    text = (
        "\t\tNet Link States (Area 0)\n"
        "  LS age: 100\n"
        "  Link State ID: 10.9.9.1 (address of Designated Router)\n"
        "  Advertising Router: 10.255.255.1\n"
        "\tAttached Router: 10.255.255.1\n"
    )
    lsas, warnings = P.parse_show_ip_ospf_database_network(text, "r1")
    assert lsas[0].prefix is None
    assert any("no Network Mask" in w for w in warnings)


def test_network_lsa_empty_output() -> None:
    lsas, warnings = P.parse_show_ip_ospf_database_network("")
    assert lsas == []
    assert warnings == ["show ip ospf database network [observer unidentified]: empty output"]

    _, attributed = P.parse_show_ip_ospf_database_network("", "r5")
    assert attributed == ["show ip ospf database network [observer=r5]: empty output"]


# =========================================================================== #
# 6. show ip ospf route
# =========================================================================== #


def test_parse_ospf_routes_real_lab() -> None:
    routes, warnings = P.parse_show_ip_ospf_route(
        _read("r2_show_ip_ospf_route.txt"), "r2"
    )
    assert warnings == []
    assert len(routes) == 11
    by_prefix = {r.prefix: r for r in routes}
    assert set(by_prefix) == {
        "10.0.23.0/30", "10.0.34.0/30", "10.0.32.0/30", "10.0.21.0/30",
        "10.0.41.0/30", "192.168.98.32/27", "10.255.255.1/32",
        "10.255.255.2/32", "10.255.255.3/32", "10.255.255.4/32",
        "10.255.255.5/32",
    }


@pytest.mark.parametrize(
    ("prefix", "route_type", "cost", "next_hop"),
    [
        # Real IOS prints a via line for Connected rows too — the local address
        # and interface are real device output, so they are kept rather than
        # suppressed. ``learned`` is what distinguishes them, not a null hop.
        ("10.0.23.0/30", OspfRouteType.CONNECTED, 1, "10.0.23.1"),
        ("10.0.34.0/30", OspfRouteType.INTRA_AREA, 11, "10.0.23.2"),
        ("10.0.32.0/30", OspfRouteType.INTRA_AREA, 11, "10.0.23.2"),
        ("10.0.21.0/30", OspfRouteType.INTRA_AREA, 21, "10.0.23.2"),
        ("10.0.41.0/30", OspfRouteType.INTRA_AREA, 21, "10.0.23.2"),
        ("192.168.98.32/27", OspfRouteType.INTRA_AREA, 31, "10.0.23.2"),
        ("10.255.255.1/32", OspfRouteType.INTRA_AREA, 22, "10.0.23.2"),
        ("10.255.255.2/32", OspfRouteType.CONNECTED, 1, "10.255.255.2"),
        ("10.255.255.3/32", OspfRouteType.INTRA_AREA, 12, "10.0.23.2"),
        ("10.255.255.4/32", OspfRouteType.INTRA_AREA, 2, "10.0.23.2"),
        ("10.255.255.5/32", OspfRouteType.INTRA_AREA, 12, "10.0.23.2"),
    ],
)
def test_ospf_route_matches_the_task_table(
    prefix: str, route_type: OspfRouteType, cost: int, next_hop: str | None
) -> None:
    """Every row of the reference ``show ip ospf route`` table."""
    routes, _ = P.parse_show_ip_ospf_route(_read("r2_show_ip_ospf_route.txt"), "r2")
    route = next(r for r in routes if r.prefix == prefix)
    assert route.route_type is route_type
    assert route.cost == cost
    assert route.next_hop == next_hop


def test_connected_routes_are_marked_not_learned() -> None:
    routes, _ = P.parse_show_ip_ospf_route(_read("r2_show_ip_ospf_route.txt"), "r2")
    connected = [r for r in routes if r.route_type is OspfRouteType.CONNECTED]
    learned = [r for r in routes if r.learned]
    assert {r.prefix for r in connected} == {"10.0.23.0/30", "10.255.255.2/32"}
    assert all(not r.learned for r in connected)
    assert len(learned) == 9


def test_directly_connected_non_ospf_networks_are_not_ospf_routes() -> None:
    """10.0.12.0/30 and 10.0.12.4/30 are interface subnets, not OSPF routes."""
    routes, _ = P.parse_show_ip_ospf_route(_read("r2_show_ip_ospf_route.txt"), "r2")
    prefixes = {r.prefix for r in routes}
    assert "10.0.12.0/30" not in prefixes
    assert "10.0.12.4/30" not in prefixes


def test_route_type_aliases() -> None:
    text = (
        "Area 0\n"
        "Prefix               Metric  Type       Next Hop         Interface\n"
        "10.1.0.0/24          20      Inter      via 10.0.1.1     Et0/0\n"
        "10.2.0.0/24          30      E1         via 10.0.1.1     Et0/0\n"
        "10.3.0.0/24          40      E2         via 10.0.1.1     Et0/0\n"
        "10.4.0.0/24          50      N1         via 10.0.1.1     Et0/0\n"
        "10.5.0.0/24          60      N2         via 10.0.1.1     Et0/0\n"
    )
    routes, warnings = P.parse_show_ip_ospf_route(text, "r")
    assert warnings == []
    assert [r.route_type for r in routes] == [
        OspfRouteType.INTER_AREA, OspfRouteType.EXTERNAL_1,
        OspfRouteType.EXTERNAL_2, OspfRouteType.NSSA_1, OspfRouteType.NSSA_2,
    ]


def test_route_empty_output() -> None:
    routes, warnings = P.parse_show_ip_ospf_route("")
    assert routes == []
    assert warnings == ["show ip ospf route: empty output"]


def test_route_ecmp_extra_hop_is_reported() -> None:
    text = (
        "Area 0\n"
        "10.1.0.0/24          20      Intra      via 10.0.1.1     Et0/0\n"
        "via 10.0.2.1\n"
    )
    routes, warnings = P.parse_show_ip_ospf_route(text, "r")
    assert routes[0].next_hop == "10.0.1.1"
    assert any("equal-cost next hop" in w for w in warnings)


# =========================================================================== #
# 7. Process / router-id context
# =========================================================================== #


def test_process_context_from_header() -> None:
    process, router_id = P.process_context(
        "            OSPF Router with ID (10.255.255.2) (Process ID 10)\n"
    )
    assert (process, router_id) == ("10", "10.255.255.2")


def test_process_context_absent() -> None:
    assert P.process_context("nothing useful here") == ("", "")


# =========================================================================== #
# 8. Robustness — every parser survives junk
# =========================================================================== #


@pytest.mark.parametrize(
    "parser",
    [
        P.parse_show_ip_ospf_neighbor,
        P.parse_show_ip_ospf_database,
        P.parse_show_ip_ospf_database_network,
        P.parse_show_ip_ospf_database_router,
        P.parse_show_ip_ospf_route,
    ],
)
@pytest.mark.parametrize(
    "payload",
    [
        "",
        "   \n\n  ",
        "% OSPF not enabled\n",
        "\x00\x01binary junk\n",
        "LS age: notanumber\n",
        "\t\tRouter Link States (Area 0)\n" * 3,
    ],
)
def test_parsers_never_raise(parser, payload: str) -> None:
    result, warnings = parser(payload)
    assert isinstance(result, list)
    assert isinstance(warnings, list)


@pytest.mark.parametrize(
    "payload",
    ["", "% OSPF not enabled\n", "garbage\n"],
)
def test_interface_parser_never_raises(payload: str) -> None:
    result, warnings = P.parse_show_ip_ospf_interface_brief(payload, "d")
    assert isinstance(result, list)
    assert isinstance(warnings, list)


def test_no_parser_emits_secret_material() -> None:
    """No collected OSPF command can carry a key, so no fixture may leak one."""
    for path in DATA.glob("*.txt"):
        text = path.read_text(encoding="utf-8").lower()
        for needle in ("password", "secret", "md5", "key-chain", "key-string"):
            assert needle not in text, f"{path.name} contains {needle!r}"


# =========================================================================== #
# 9. Fixture-integrity: summary LSDB and detail LSDB must agree
# =========================================================================== #


def test_summary_link_counts_match_router_lsa_detail() -> None:
    """A hand-written summary that disagrees with the detail dump is drift.

    Caught once already (R2 claimed 5 links, its Type 1 carried 4).  The two
    fixtures narrate the same LSDB, so a mismatch means one of them lies.
    """
    summary, _ = P.parse_show_ip_ospf_database(_read("r2_show_ip_ospf_database.txt"))
    lsas, _ = P.parse_show_ip_ospf_database_router(
        _read("r2_show_ip_ospf_database_router.txt"), "r2"
    )
    detail = {lsa.advertising_router: lsa for lsa in lsas}
    compared = 0
    for row in summary:
        if row.lsa_type != 1 or row.link_count is None:
            continue
        assert row.advertising_router in detail
        assert row.link_count == detail[row.advertising_router].number_of_links, (
            f"{row.advertising_router}: summary says {row.link_count}, "
            f"detail says {detail[row.advertising_router].number_of_links}"
        )
        compared += 1
    assert compared == 5


def test_network_lsa_dr_addresses_match_summary_lsdb() -> None:
    summary, _ = P.parse_show_ip_ospf_database(_read("r2_show_ip_ospf_database.txt"))
    networks, _ = P.parse_show_ip_ospf_database_network(
        _read("r2_show_ip_ospf_database_network.txt"), "r2"
    )
    summary_net = {
        (r.link_state_id, r.advertising_router) for r in summary if r.lsa_type == 2
    }
    detail_net = {(n.link_state_id, n.advertising_router) for n in networks}
    assert summary_net == detail_net


# =========================================================================== #
# Regression: IOS prints LSA header fields in several layouts
#
# Live run live-ospf-20261118-092140: four of five routers reported no LS
# checksum for the same LSA while the fifth reported 0x8B65. The cause was the
# parser, not the devices: a generic greedy key/value match both swallowed a
# second field on the same line and lost a value wrapped onto the next line.
# =========================================================================== #

_ROUTER_HEADER_TEMPLATE = """Router Link States (Area 0)

  LS age: 100
  LS Type: Router Links
  Link State ID: 10.255.255.2
  Advertising Router: 10.255.255.2
{header}
  Number of Links: 0
"""

_NETWORK_HEADER_TEMPLATE = """Net Link States (Area 0)

  LS age: 100
  LS Type: Network Links
  Link State ID: 10.0.23.1
  Advertising Router: 10.255.255.2
{header}
  Network Mask: /30
        Attached Router: 10.255.255.2
        Attached Router: 10.255.255.3
"""


@pytest.mark.parametrize(
    ("label", "header"),
    [
        ("separate lines", "  LS Seq Number: 8000007D\n  Checksum: 0x8B65"),
        ("both on one line", "  LS Seq Number: 8000007D        Checksum: 0x8B65"),
        ("value wrapped", "  LS Seq Number: 8000007D\n  Checksum:\n  0x8B65"),
        ("extra padding", "  LS Seq Number:   8000007D\n  Checksum:   0x8B65"),
    ],
    ids=["separate", "same-line", "wrapped", "padded"],
)
def test_router_lsa_header_layouts_all_yield_sequence_and_checksum(
    label: str, header: str
) -> None:
    """Every layout IOS uses must yield *both* fields — never a corrupt value."""
    lsas, _ = P.parse_show_ip_ospf_database_router(
        _ROUTER_HEADER_TEMPLATE.replace("{header}", header), "r3-1"
    )
    assert len(lsas) == 1
    lsa = lsas[0]
    assert lsa.sequence == "8000007D", label
    assert lsa.checksum == "0x8B65", label


@pytest.mark.parametrize(
    ("label", "header"),
    [
        ("separate lines", "  LS Seq Number: 80000078\n  Checksum: 0xAECE"),
        ("both on one line", "  LS Seq Number: 80000078        Checksum: 0xAECE"),
        ("value wrapped", "  LS Seq Number: 80000078\n  Checksum:\n  0xAECE"),
    ],
    ids=["separate", "same-line", "wrapped"],
)
def test_network_lsa_header_layouts_all_yield_sequence_and_checksum(
    label: str, header: str
) -> None:
    lsas, _ = P.parse_show_ip_ospf_database_network(
        _NETWORK_HEADER_TEMPLATE.replace("{header}", header), "r3-1"
    )
    assert len(lsas) == 1
    lsa = lsas[0]
    assert lsa.sequence == "80000078", label
    assert lsa.checksum == "0xAECE", label


def test_sequence_is_never_contaminated_by_the_next_field() -> None:
    """The corruption bug: the value used to absorb the rest of the line."""
    text = _ROUTER_HEADER_TEMPLATE.replace(
        "{header}", "  LS Seq Number: 8000007D        Checksum: 0x8B65"
    )
    lsas, _ = P.parse_show_ip_ospf_database_router(text, "r3-1")
    sequence = lsas[0].sequence
    assert sequence == "8000007D"
    assert "Checksum" not in sequence
    assert " " not in sequence


def test_genuinely_absent_checksum_stays_absent() -> None:
    """The fix must not fabricate: a missing field stays missing."""
    text = _ROUTER_HEADER_TEMPLATE.replace("{header}", "  LS Seq Number: 8000007D")
    lsas, _ = P.parse_show_ip_ospf_database_router(text, "r3-1")
    assert lsas[0].sequence == "8000007D"
    assert lsas[0].checksum == ""


def test_wrapped_value_does_not_swallow_a_real_header_line() -> None:
    """A following header line must never be mistaken for a wrapped value."""
    text = _ROUTER_HEADER_TEMPLATE.replace(
        "{header}", "  LS Seq Number: 8000007D\n  Checksum:\n  Number of Links: 0"
    )
    lsas, _ = P.parse_show_ip_ospf_database_router(text, "r3-1")
    assert lsas[0].checksum == ""
    assert lsas[0].sequence == "8000007D"


# =========================================================================== #
# Malformed header values must degrade to "absent", never to "truncated"
#
# A truncated value is worse than a missing one: the caller can detect absence,
# but cannot distinguish 8000007D (valid) from the first eight digits of
# 8000007DAA (invalid). Encoding a prefix of a malformed value would let an
# invalid observation decide RFC 2328 §13.1 ordering.
# =========================================================================== #


@pytest.mark.parametrize(
    ("label", "header", "expected_seq", "expected_cksum"),
    [
        ("valid-same-line", "  LS Seq Number: 8000007D   Checksum: 0x8B65", "8000007D", "0x8B65"),
        ("valid-separate", "  LS Seq Number: 8000007D\n  Checksum: 0x8B65", "8000007D", "0x8B65"),
        ("valid-wrapped", "  LS Seq Number: 8000007D\n  Checksum:\n  0x8B65", "8000007D", "0x8B65"),
        ("checksum-16bit", "  LS Seq Number: 8000007D\n  Checksum: 0xFFFF", "8000007D", "0xFFFF"),
        ("checksum-no-0x", "  LS Seq Number: 8000007D\n  Checksum: 8B65", "8000007D", "8B65"),
        ("seq-10-hex-digits", "  LS Seq Number: 8000007DAA\n  Checksum: 0x8B65", "", "0x8B65"),
        ("cksum-5-hex-digits", "  LS Seq Number: 8000007D\n  Checksum: 0x8B651", "8000007D", ""),
        ("cksum-0x-zzzz", "  LS Seq Number: ZZZZ\n  Checksum: 0xZZZZ", "", ""),
        ("cksum-bare-0x", "  LS Seq Number: 8000007D\n  Checksum: 0x", "8000007D", ""),
        ("seq-absent", "  Checksum: 0x8B65", "", "0x8B65"),
        ("cksum-absent", "  LS Seq Number: 8000007D", "8000007D", ""),
        ("continuation-is-field", "  LS Seq Number: 8000007D\n  Checksum:\n  Number of Links: 0", "8000007D", ""),
    ],
    ids=lambda v: v if isinstance(v, str) and " " not in v else "",
)
def test_header_values_are_never_truncated(
    label: str, header: str, expected_seq: str, expected_cksum: str
) -> None:
    lsas, _ = P.parse_show_ip_ospf_database_router(
        _ROUTER_HEADER_TEMPLATE.replace("{header}", header), "r9-1"
    )
    lsa = lsas[0]
    assert lsa.sequence == expected_seq, label
    assert lsa.checksum == expected_cksum, label


def test_truncated_sequence_is_not_a_usable_sequence() -> None:
    """End to end: the malformed value cannot decide an instance ordering."""
    from nettwin.collect.ospf_topology import parse_ls_sequence

    lsas, _ = P.parse_show_ip_ospf_database_router(
        _ROUTER_HEADER_TEMPLATE.replace("{header}", "  LS Seq Number: 8000007DAA"), "r9-1"
    )
    assert parse_ls_sequence(lsas[0].sequence) is None


def test_malformed_checksum_cannot_become_a_valid_checksum() -> None:
    from nettwin.collect.ospf_topology import parse_ls_checksum

    lsas, _ = P.parse_show_ip_ospf_database_router(
        _ROUTER_HEADER_TEMPLATE.replace("{header}", "  LS Seq Number: 8000007D\n  Checksum: 0x8B651"),
        "r9-1",
    )
    assert parse_ls_checksum(lsas[0].checksum) is None
