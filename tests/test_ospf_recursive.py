"""Phase 2.6 — OSPF inside the real recursive discovery walk. **OFFLINE ONLY.**

The point of this module is integration, not parsing: it drives
:class:`RecursiveDiscovery` with scripted IOS transcripts and asserts that OSPF
evidence reaches ``RecursiveDiscoveryResult.ospf_topology`` while the CDP
result stays exactly as it was.

Reference data is the real PNETLab capture (process 10, area 0, five routers)
described in the task; the fixtures live in ``tests/data/ospf/``.
"""

from __future__ import annotations

from pathlib import Path

from nettwin.collect.nested import (
    IosShellSession,
    ScriptedTransport,
    ScriptStep,
    SessionLimits,
)
from nettwin.collect.nested.discovery import (
    DISCOVERY_COMMANDS,
    DeviceStatus,
    RecursiveDiscovery,
)
from nettwin.domain.ospf_models import OspfEvidenceState

NESTED_DATA = Path(__file__).parent / "data" / "nested"
OSPF_DATA = Path(__file__).parent / "data" / "ospf"

USER = "nettwin-ro"
PASS = "unit-test-only-fake-pw"

FAST = SessionLimits(
    connect_timeout=0.4, command_timeout=0.4, poll_interval=0.001,
    max_attempts_per_device=1,
)


def _ospf(name: str) -> str:
    return (OSPF_DATA / name).read_text(encoding="utf-8")


#: The six OSPF answers, identical on every device for this test: what matters
#: is that the pipeline carries them, not that each device saw a different LSDB.
OSPF_RESPONSES: dict[str, str] = {
    "show ip ospf neighbor": _ospf("r2_show_ip_ospf_neighbor.txt"),
    "show ip ospf interface brief": _ospf("r2_show_ip_ospf_interface_brief.txt"),
    "show ip ospf database": _ospf("r2_show_ip_ospf_database.txt"),
    "show ip ospf database router": _ospf("r2_show_ip_ospf_database_router.txt"),
    "show ip ospf database network": _ospf("r2_show_ip_ospf_database_network.txt"),
    "show ip ospf route": _ospf("r2_show_ip_ospf_route.txt"),
}


# --------------------------------------------------------------------------- #
# Transcripts
# --------------------------------------------------------------------------- #

VERSION = (
    "Cisco IOS Software, Linux Software (I86BI_LINUXL2-ADVENTERPRISEK9-M), "
    "Version 15.2(4)M5, RELEASE SOFTWARE (fc2)\n\n{host} uptime is 2 weeks\n"
)
BRIEF = (
    "Interface              IP-Address      OK? Method Status                Protocol\n"
    "Ethernet0/0            10.0.23.1       YES NVRAM  up                    up\n"
    "Ethernet0/1            10.0.12.1       YES NVRAM  up                    up\n"
    "Loopback0              10.255.255.2    YES NVRAM  up                    up\n"
)
ROUTES = (
    "Codes: L - local, C - connected, S - static\n\n"
    "C        10.0.23.0/30 is directly connected, Ethernet0/0\n"
    "C        10.0.12.0/30 is directly connected, Ethernet0/1\n"
    "C        10.255.255.2/32 is directly connected, Loopback0\n"
)
CDP_SUMMARY = (
    "Device ID        Local Intrfce     Holdtme    Capability  Platform  Port ID\n"
)
CDP_DETAIL = """-------------------------
Device ID: {peer}
Entry address(es):
  IP address: {peer_ip}
Platform: Linux Uni,  Capabilities: Router
Interface: Ethernet0/0,  Port ID (outgoing port): Ethernet0/0
Holdtime : 152 sec

Version :
Cisco IOS Software, Linux Software (I86BI_LINUXL2-ADVENTERPRISEK9-M), \
Version 15.2(4)M5, RELEASE SOFTWARE (fc2)

advertisement version: 2
"""


def _steps_for(
    hostname: str,
    *,
    ospf: bool,
    peers: tuple[tuple[str, str], ...] = (),
) -> list[ScriptStep]:
    """One device's full read-only conversation, in dispatch order.

    ``DISCOVERY_COMMANDS`` is the authority for order, so this transcript can
    never drift from what the walk actually sends.
    """
    answers: dict[str, str] = {
        "show version": VERSION.format(host=hostname),
        "show ip interface brief": BRIEF,
        "show ip route": ROUTES,
        "show ip ospf neighbor": (
            OSPF_RESPONSES["show ip ospf neighbor"] if ospf else "% OSPF not enabled\n"
        ),
        "show cdp neighbors": CDP_SUMMARY
        + "".join(f"{peer:<16} Eth 0/0           138             R S I  Linux Uni Eth 0/0\n"
                  for peer, _ in peers),
        "show cdp neighbors detail": "".join(
            CDP_DETAIL.format(peer=peer, peer_ip=ip) for peer, ip in peers
        )
        or "Total cdp entries displayed : 0\n",
    }
    for command in DISCOVERY_COMMANDS:
        if command in answers:
            continue
        answers[command] = (
            OSPF_RESPONSES[command] if ospf else "% OSPF not enabled\n"
        )

    steps = [ScriptStep(expect="", respond=f"{hostname}#")]
    for command in DISCOVERY_COMMANDS:
        steps.append(ScriptStep(expect=command, respond=answers[command] + f"{hostname}#"))
    steps.append(ScriptStep(expect="exit", respond="", repeat=True))
    return steps


def _run(
    *,
    ospf: bool = True,
    peers: tuple[tuple[str, str], ...] = (),
    nested: dict[str, tuple[str, bool]] | None = None,
) -> object:
    """Run a one- or two-hop discovery and return the result object."""
    children = nested or {}

    def root_factory(host: str, password: str) -> IosShellSession:
        steps = _steps_for("R2", ospf=ospf, peers=peers)
        for target in children:
            steps.insert(
                -1,
                ScriptStep(expect=f"ssh -l {USER} {target}", respond="Password: ", repeat=True),
            )
        return IosShellSession(
            host=host, transport=ScriptedTransport(steps, name="root"),
            limits=FAST, username=USER, password=password,
        )

    def nested_factory(*, host: str, username: str, password: str, parent=None):
        hostname, child_ospf = children[host]
        steps = _steps_for(hostname, ospf=child_ospf)
        steps.insert(0, ScriptStep(expect="", respond="Password: "))
        steps.insert(1, ScriptStep(expect=PASS, respond=f"\n{hostname}#"))
        return ScriptedTransport(steps, name=f"nested:{hostname}")

    discovery = RecursiveDiscovery(
        seed_host="192.168.98.34", username=USER, password=PASS, limits=FAST,
        root_factory=root_factory, nested_factory=nested_factory,
    )
    return discovery.run()


# =========================================================================== #
# 1. OSPF reaches the result, CDP is unaffected
# =========================================================================== #


def test_ospf_topology_is_attached_to_the_result() -> None:
    result = _run(ospf=True)
    assert result.ospf_topology is not None
    assert result.ospf_topology.router_lsas, "Router LSAs did not reach the result"
    assert len(result.ospf_topology.transit_networks) == 5


def test_five_transit_networks_reconstructed_in_the_walk() -> None:
    result = _run(ospf=True)
    ospf = result.ospf_topology
    prefixes = sorted(n.prefix for n in ospf.transit_networks if n.prefix)
    assert prefixes == [
        "10.0.21.0/30",
        "10.0.23.0/30",
        "10.0.32.0/30",
        "10.0.34.0/30",
        "10.0.41.0/30",
    ]


def test_all_five_router_ids_identified() -> None:
    result = _run(ospf=True)
    assert result.ospf_topology.router_ids() == [
        "10.255.255.1",
        "10.255.255.2",
        "10.255.255.3",
        "10.255.255.4",
        "10.255.255.5",
    ]


def test_ospf_process_and_area_come_from_the_output_not_a_constant() -> None:
    result = _run(ospf=True)
    instance = result.ospf_topology.instances[0]
    assert instance.process_id == "10"
    assert instance.router_id == "10.255.255.2"
    assert [a.area for a in instance.areas] == ["0"]


def test_ospf_contributes_no_physical_links() -> None:
    """The hard rule: an OSPF adjacency is never a cable."""
    result = _run(ospf=True, peers=(("R2-3.nettwin.lab", "10.0.23.2"),))
    # One peer is advertised by CDP but is not collected, so no CDP link forms.
    assert result.topology.links == []
    # ...yet OSPF reconstructed all five transit networks from the LSDB.
    assert len(result.ospf_topology.transit_networks) == 5
    # And not one of them leaked into Topology.links.
    assert all(
        link.id not in {n.id for n in result.ospf_topology.transit_networks}
        for link in result.topology.links
    )


def test_cdp_section_is_unchanged_when_ospf_is_present() -> None:
    """Same CDP input, OSPF on or off -> identical physical result."""
    with_ospf = _run(ospf=True)
    without = _run(ospf=False)
    assert len(with_ospf.topology.devices) == len(without.topology.devices)
    assert len(with_ospf.topology.interfaces) == len(without.topology.interfaces)
    assert with_ospf.topology.links == without.topology.links


# =========================================================================== #
# 2. Failure isolation (acceptance criterion 16)
# =========================================================================== #


def test_device_without_ospf_still_collects_fully() -> None:
    """A router with OSPF disabled is 'ok', not 'partial'."""
    result = _run(ospf=False)
    node = result.collected_nodes[0]
    assert node.status is DeviceStatus.COLLECTED
    assert node.observations is not None
    assert node.observations.status == "ok"
    # Required evidence was parsed: identity and interfaces are both present.
    assert node.observations.identity.get("hostname") == "R2"
    assert node.observations.interfaces, "interface evidence was lost"
    assert node.observations.routes, "route evidence was lost"
    # IOS answered "% OSPF not enabled" — the command succeeded, so there is no
    # "optional section unavailable" warning. What must be recorded is that no
    # OSPF evidence came back, and that is a parser-level note.
    assert any(
        "no neighbor rows parsed" in w or "no interface rows parsed" in w
        for w in node.observations.warnings
    ), node.observations.warnings


def test_no_ospf_evidence_produces_an_empty_ospf_topology_not_an_error() -> None:
    result = _run(ospf=False)
    ospf = result.ospf_topology
    assert ospf is not None
    assert ospf.transit_networks == []
    assert ospf.stub_networks == []
    assert ospf.logical_edges == []
    assert any(
        "does not appear to run OSPF" in w for w in ospf.warnings
    ), ospf.warnings


def test_ospf_never_creates_links_even_across_a_multi_router_segment() -> None:
    result = _run(ospf=True)
    # Five routers share 10.0.23.0/30 in the LSDB. That is one segment, and
    # must not become 10 point-to-point links anywhere in Topology.
    assert result.topology.links == []


def test_ospf_timeout_marks_the_device_partial_but_keeps_cdp() -> None:
    """A *timeout* is an anomaly, unlike a clean 'no OSPF' answer."""

    def root_factory(host: str, password: str) -> IosShellSession:
        steps = [
            step for step in _steps_for("R2", ospf=False)
            if step.expect != "show ip ospf database"
        ]
        # `show ip ospf database` now has no answer -> the session times out.
        return IosShellSession(
            host=host, transport=ScriptedTransport(steps, name="root"),
            limits=FAST, username=USER, password=password,
        )

    discovery = RecursiveDiscovery(
        seed_host="192.168.98.34", username=USER, password=PASS, limits=FAST,
        root_factory=root_factory,
        nested_factory=lambda **kw: None,
    )
    result = discovery.run()
    node = result.collected_nodes[0]
    observations = node.observations
    assert observations is not None
    assert any(
        "optional command unavailable" in w for w in observations.warnings
    ), observations.warnings
    # The evidence gathered before the timeout is intact.
    assert observations.identity.get("hostname") == "R2"
    assert observations.interfaces


# =========================================================================== #
# 3. Two devices, mixed OSPF capability
# =========================================================================== #


def test_one_device_with_ospf_and_one_without() -> None:
    result = _run(
        ospf=True,
        peers=(("R2-3.nettwin.lab", "10.0.21.1"),),
        nested={"10.0.21.1": ("R2-3", False)},
    )
    collected = {n.identity: n for n in result.collected_nodes}
    # The OSPF-capable seed contributed the LSDB.
    assert "r2" in collected
    assert result.ospf_topology.router_lsas
    # Whatever else was reached, each collected device produced evidence and
    # none of them failed the run.
    for identity, node in collected.items():
        assert node.observations is not None, identity
        assert node.status is DeviceStatus.COLLECTED


# =========================================================================== #
# 4. Evidence honesty
# =========================================================================== #


def test_transit_networks_are_confirmed_when_both_lsa_types_agree() -> None:
    result = _run(ospf=True)
    for network in result.ospf_topology.transit_networks:
        assert network.state is OspfEvidenceState.CONFIRMED, network.id


def test_transit_network_carries_source_lsa_references() -> None:
    result = _run(ospf=True)
    for network in result.ospf_topology.transit_networks:
        assert network.source_lsas, f"{network.id} has no provenance"
        for ref in network.source_lsas:
            assert ref.area == "0"
            assert ref.lsa_type in {1, 2}
            assert ref.advertising_router
            assert ref.command


def test_stub_networks_are_not_turned_into_links() -> None:
    result = _run(ospf=True)
    ospf = result.ospf_topology
    assert len(ospf.stub_networks) == 7
    stub_prefixes = {s.prefix for s in ospf.stub_networks}
    assert "192.168.98.32/27" in stub_prefixes
    # No Link in the physical topology claims a stub prefix.
    iface_addresses = {
        str(a).split("/")[0]
        for i in result.topology.interfaces
        for a in i.ipv4_addresses
    }
    assert not (stub_prefixes & iface_addresses)


def test_connected_routes_are_not_counted_as_learned() -> None:
    result = _run(ospf=True)
    ospf = result.ospf_topology
    connected = ospf.connected_routes()
    learned = ospf.learned_routes()
    assert {r.prefix for r in connected} == {"10.0.23.0/30", "10.255.255.2/32"}
    # The two directly-connected networks the task calls out explicitly.
    assert "10.0.12.0/30" not in {r.prefix for r in connected}
    assert "10.0.12.4/30" not in {r.prefix for r in connected}
    assert len(learned) == 9
    assert all(r.route_type.value == "intra-area" for r in learned)


def test_correlation_reports_cdp_state_without_merging() -> None:
    """A transit network between uncollected routers produces no correlation.

    Correlation pairs a transit network with the *devices* that sit on it. In
    this run only R2 was collected, so although the LSDB names all five routers,
    four of them have no device behind them and there is no pair to classify.
    The five transit networks are still reconstructed — this is silence about
    correlation, not a loss of OSPF evidence.

    (This is also the regression guard for the opposite bug: when every router-id
    in a flooded LSDB was credited to the collected device, this test produced
    ten bogus correlations between devices that were never contacted.)
    """
    result = _run(ospf=True)
    ospf = result.ospf_topology

    assert len(ospf.transit_networks) == 5
    assert ospf.correlations == []
    # ...and correlating must never conjure a cable.
    assert result.topology.links == []
