"""Phase 2.5 — link normalization on the recursive discovery path. **OFFLINE ONLY.**

Before this phase ``_assemble_topology`` stopped at ``merge_device_topologies``
and every recursive run wrote ``links: []``. These tests pin the behaviour of
the newly wired stage: links come from two-sided CDP evidence only, reciprocal
records collapse to one link, one-sided rows stay candidates, and nothing is
ever inferred from addressing.

Fixture provenance: ``tests/data/nested/recip_*.txt`` are **SYNTHETIC**, written
to mirror what three routers would each report about the other two, so that a
fully reciprocal triple can be exercised. The pre-existing ``r2-*_detail.txt``
fixtures are deliberately non-reciprocal and are used here to prove that
one-sided evidence does *not* become a link.
"""

from __future__ import annotations

from pathlib import Path

from nettwin.collect.nested.discovery import (
    RecursiveDiscovery,
    RecursiveDiscoveryResult,
)

NESTED_DATA = Path(__file__).parent / "data" / "nested"

USER = "nettwin-ro"
PASS = "unit-test-only-fake-pw"

#: Reciprocal ``show cdp neighbors`` summaries for the recip_* detail fixtures.
RECIP_SUMMARIES: dict[str, str] = {
    "R2-1": (
        "Device ID        Local Intrfce     Holdtme    Capability  Platform  Port ID\n"
        "R2-2.recip.lab   Eth 0/0           138             R S I  Linux Uni Eth 0/1\n"
        "R2-4.recip.lab   Eth 0/1           138             R S I  Linux Uni Eth 0/1\n"
    ),
    "R2-2": (
        "Device ID        Local Intrfce     Holdtme    Capability  Platform  Port ID\n"
        "R2-1.recip.lab   Eth 0/1           138             R S I  Linux Uni Eth 0/0\n"
        "R2-4.recip.lab   Eth 0/2           138             R S I  Linux Uni Eth 0/2\n"
    ),
    "R2-4": (
        "Device ID        Local Intrfce     Holdtme    Capability  Platform  Port ID\n"
        "R2-1.recip.lab   Eth 0/1           138             R S I  Linux Uni Eth 0/1\n"
        "R2-2.recip.lab   Eth 0/2           138             R S I  Linux Uni Eth 0/2\n"
    ),
}

#: Interface set consistent with the linked interfaces in each fixture.
RECIP_INTERFACES: dict[str, list[tuple[str, str, str]]] = {
    "R2-1": [
        ("Ethernet0/0", "10.0.21.2", "up"),
        ("Ethernet0/1", "10.0.41.2", "up"),
    ],
    "R2-2": [
        ("Ethernet0/1", "10.0.21.1", "up"),
        ("Ethernet0/2", "10.0.22.1", "up"),
    ],
    "R2-4": [
        ("Ethernet0/1", "10.0.41.1", "up"),
        ("Ethernet0/2", "10.0.22.2", "up"),
    ],
}


# --------------------------------------------------------------------------- #
# Harness
# --------------------------------------------------------------------------- #


def _version(hostname: str) -> str:
    return (
        "Cisco IOS Software, Linux Software (I86BI_LINUXL2-ADVENTERPRISEK9-M), "
        f"Version 15.2(4)M5, RELEASE SOFTWARE (fc2)\n\n{hostname} uptime is 2 weeks\n"
    )


def _brief(hostname: str) -> str:
    lines = ["Interface              IP-Address      OK? Method Status                Protocol"]
    for name, address, status in RECIP_INTERFACES[hostname]:
        lines.append(f"{name:<22} {address:<15} YES NVRAM  {status:<21} up")
    return "\n".join(lines) + "\n"


def _routes(hostname: str) -> str:
    lines = ["Codes: L - local, C - connected, S - static", ""]
    for name, address, _ in RECIP_INTERFACES[hostname]:
        octets = address.split(".")
        lines.append(f"C        {octets[0]}.{octets[1]}.{octets[2]}.0/24 is directly connected, {name}")
    return "\n".join(lines) + "\n"


OSPF_TEXT = (
    "Neighbor ID     Pri State           Dead Time   Address         Interface\n"
    "10.255.255.2      1 FULL/BDR        00:00:35    10.0.21.1       Ethernet0/0\n"
)


def _device_steps(hostname: str, detail_file: str) -> list:
    """The read-only conversation for one device with reciprocal CDP rows."""
    from nettwin.collect.nested import ScriptStep

    host_prompt = f"{hostname}#"
    detail = (NESTED_DATA / detail_file).read_text(encoding="utf-8")
    return [
        ScriptStep(expect="show ip interface brief", respond=_brief(hostname) + host_prompt),
        ScriptStep(expect="show ip route", respond=_routes(hostname) + host_prompt),
        ScriptStep(expect="show ip ospf neighbor", respond=OSPF_TEXT + host_prompt),
        ScriptStep(
            expect="show cdp neighbors\n",
            respond=RECIP_SUMMARIES[hostname] + host_prompt,
        ),
        ScriptStep(expect="show cdp neighbors detail", respond=detail + host_prompt),
        ScriptStep(expect="show version", respond=_version(hostname) + host_prompt),
        ScriptStep(expect="exit", respond="", repeat=True),
    ]


def _make_discovery(*, nested: dict[str, tuple[str, str]]) -> RecursiveDiscovery:
    from nettwin.collect.nested import IosShellSession, ScriptedTransport, SessionLimits

    limits = SessionLimits(
        connect_timeout=0.4, command_timeout=0.4, poll_interval=0.001,
        max_attempts_per_device=1,
    )

    def root_factory(host: str, password: str) -> IosShellSession:
        steps = _device_steps("R2-1", "recip_r2-1_detail.txt")
        steps.insert(0, ScriptStepFactory.initial("R2-1#"))
        for target in nested:
            steps.append(ScriptStepFactory.ssh(target))
        return IosShellSession(
            host=host, transport=ScriptedTransport(steps, name="root:R2-1"),
            limits=limits, username=USER, password=password,
        )

    def nested_factory(*, host: str, username: str, password: str, parent=None):
        from nettwin.collect.nested import ScriptStep

        hostname, detail = nested[host]
        steps = _device_steps(hostname, detail)
        steps.insert(0, ScriptStep(expect="", respond="Password: "))
        steps.insert(1, ScriptStep(expect=PASS, respond=f"\n{hostname}#"))
        return ScriptedTransport(steps, name=f"nested:{hostname}")

    return RecursiveDiscovery(
        seed_host="192.168.98.34", username=USER, password=PASS, limits=limits,
        root_factory=root_factory, nested_factory=nested_factory,
    )


class ScriptStepFactory:
    """Small helpers so the step list reads clearly."""

    @staticmethod
    def initial(prompt: str):
        from nettwin.collect.nested import ScriptStep
        return ScriptStep(expect="", respond=prompt)

    @staticmethod
    def ssh(target: str):
        from nettwin.collect.nested import ScriptStep
        return ScriptStep(expect=f"ssh -l {USER} {target}", respond="Password: ", repeat=True)


def _run_reciprocal() -> RecursiveDiscoveryResult:
    return _make_discovery(
        nested={
            "10.0.21.1": ("R2-2", "recip_r2-2_detail.txt"),
            "10.0.41.1": ("R2-4", "recip_r2-4_detail.txt"),
        }
    ).run()


# =========================================================================== #
# 1. The regression this phase fixes
# =========================================================================== #


def test_recursive_run_produces_links_from_two_sided_evidence() -> None:
    """The bug: recursive runs used to end at merge and write ``links: []``."""
    result = _run_reciprocal()
    assert result.topology is not None
    # Three cables, each reported by both of its endpoints:
    #   R2-1 Ethernet0/0 <-> R2-2 Ethernet0/1
    #   R2-1 Ethernet0/1 <-> R2-4 Ethernet0/1
    #   R2-2 Ethernet0/2 <-> R2-4 Ethernet0/2
    assert len(result.topology.links) == 3
    assert result.link_result is not None
    assert result.link_result.links == result.topology.links
    assert not any("links left to Phase 2.2" in w for w in result.warnings)


def test_link_endpoints_name_real_devices_and_interfaces() -> None:
    topology = _run_reciprocal().topology
    assert topology is not None
    interface_ids = {i.id for i in topology.interfaces}
    device_ids = {d.id for d in topology.devices}
    interfaces = {i.id: i for i in topology.interfaces}
    for link in topology.links:
        assert link.source_interface_id in interface_ids
        assert link.destination_interface_id in interface_ids
        assert interfaces[link.source_interface_id].device_id in device_ids
        assert interfaces[link.destination_interface_id].device_id in device_ids
        assert (
            interfaces[link.source_interface_id].device_id
            != interfaces[link.destination_interface_id].device_id
        )


def test_link_ids_are_unique_no_duplicate_physical_links() -> None:
    topology = _run_reciprocal().topology
    assert topology is not None
    ids = [link.id for link in topology.links]
    assert len(ids) == len(set(ids))
    # Reciprocal records of the same cable must not yield two links.
    pairs = {
        frozenset({link.source_interface_id, link.destination_interface_id})
        for link in topology.links
    }
    assert len(pairs) == len(topology.links)


def test_reciprocal_records_collapse_to_one_link_per_cable() -> None:
    """R2-1 and R2-2 each report the cable; it is one cable."""
    topology = _run_reciprocal().topology
    assert topology is not None
    cable = [
        link for link in topology.links
        if {link.source_interface_id, link.destination_interface_id}
        == {"r2-1-ethernet0/0", "r2-2-ethernet0/1"}
    ]
    assert len(cable) == 1


def test_both_interface_names_are_preserved_on_the_link() -> None:
    topology = _run_reciprocal().topology
    assert topology is not None
    link = next(link for link in topology.links if link.source_interface_id == "r2-1-ethernet0/0")
    assert link.destination_interface_id == "r2-2-ethernet0/1"


# =========================================================================== #
# 2. Refusals — nothing invented
# =========================================================================== #


def test_one_sided_evidence_never_becomes_a_link() -> None:
    """The non-reciprocal fixtures: every row is one-sided, so zero links."""
    from nettwin.collect.nested import IosShellSession, ScriptedTransport, ScriptStep, SessionLimits

    def _steps(hostname: str, detail_file: str) -> list:
        host_prompt = f"{hostname}#"
        return [
            ScriptStep(expect="show ip interface brief", respond=_brief(hostname) + host_prompt),
            ScriptStep(expect="show ip route", respond=_routes(hostname) + host_prompt),
            ScriptStep(expect="show ip ospf neighbor", respond=OSPF_TEXT + host_prompt),
            # The legacy summary only ever advertises R2-2, from every device.
            ScriptStep(
                expect="show cdp neighbors\n",
                respond=(
                    "Device ID        Local Intrfce     Holdtme    Capability  Platform  Port ID\n"
                    "R2-2.nettwin.lab Eth 0/0           138             R S I  Linux Uni Eth 0/1\n"
                ) + host_prompt,
            ),
            ScriptStep(
                expect="show cdp neighbors detail",
                respond=(NESTED_DATA / detail_file).read_text(encoding="utf-8") + host_prompt,
            ),
            ScriptStep(expect="show version", respond=_version(hostname) + host_prompt),
            ScriptStep(expect="exit", respond="", repeat=True),
        ]

    limits = SessionLimits(
        connect_timeout=0.4, command_timeout=0.4, poll_interval=0.001,
        max_attempts_per_device=1,
    )

    def root_factory(host: str, password: str) -> IosShellSession:
        steps = _steps("R2-1", "r2-1_detail.txt")
        steps.insert(0, ScriptStep(expect="", respond="R2-1#"))
        for target in ("10.0.21.1", "10.0.41.1"):
            steps.append(
                ScriptStep(expect=f"ssh -l {USER} {target}", respond="Password: ", repeat=True)
            )
        return IosShellSession(
            host=host, transport=ScriptedTransport(steps, name="root"),
            limits=limits, username=USER, password=password,
        )

    def nested_factory(*, host: str, username: str, password: str, parent=None):
        hostname, detail = {
            "10.0.21.1": ("R2-2", "r2-2_detail.txt"),
            "10.0.41.1": ("R2-4", "r2-4_detail.txt"),
        }[host]
        steps = _steps(hostname, detail)
        steps.insert(0, ScriptStep(expect="", respond="Password: "))
        steps.insert(1, ScriptStep(expect=PASS, respond=f"\n{hostname}#"))
        return ScriptedTransport(steps, name=f"nested:{hostname}")

    result = RecursiveDiscovery(
        seed_host="192.168.98.34", username=USER, password=PASS, limits=limits,
        root_factory=root_factory, nested_factory=nested_factory,
    ).run()

    assert result.topology is not None
    assert result.topology.links == []
    # and the reason is reported, not swallowed
    assert any("one-sided evidence is not a link" in w for w in result.warnings)


def test_no_link_is_inferred_from_shared_subnets() -> None:
    """R2-1 and R2-2 sit on 10.0.21.0/24 — addressing alone is not a link."""
    topology = _run_reciprocal().topology
    assert topology is not None
    # The R2-2 <-> R2-4 cable has full evidence in the fixtures and resolves.
    # Build the counterfactual: devices that share addressing but report no
    # neighbours must produce no link.
    from nettwin.collect.discovery.links import collect_evidence, discover_links
    from nettwin.domain.models import (
        AdminState,
        Device,
        Interface,
        OperState,
        Topology,
    )

    topology = Topology(
        devices=[
            Device(id="a", name="A", vendor="cisco", platform="x"),
            Device(id="b", name="B", vendor="cisco", platform="x"),
        ],
        interfaces=[
            Interface(id="a-g0/1", device_id="a", name="GigabitEthernet0/1", vrf_id=None,
                      ipv4_addresses=["10.0.21.1/24"], admin_state=AdminState.UP,
                      oper_state=OperState.UP),
            Interface(id="b-g0/1", device_id="b", name="GigabitEthernet0/1", vrf_id=None,
                      ipv4_addresses=["10.0.21.2/24"], admin_state=AdminState.UP,
                      oper_state=OperState.UP),
        ],
    )
    result = discover_links(topology, collect_evidence({}))
    assert result.links == []


def test_run_with_no_neighbour_evidence_says_so() -> None:
    """A device that reports no neighbours must produce a stated reason."""
    from nettwin.collect.nested import IosShellSession, ScriptedTransport, ScriptStep, SessionLimits

    limits = SessionLimits(
        connect_timeout=0.4, command_timeout=0.4, poll_interval=0.001,
        max_attempts_per_device=1,
    )
    steps = [
        ScriptStep(expect="show ip interface brief", respond=_brief("R2-1") + "R2-1#"),
        ScriptStep(expect="show ip route", respond=_routes("R2-1") + "R2-1#"),
        ScriptStep(expect="show ip ospf neighbor", respond=OSPF_TEXT + "R2-1#"),
        # An isolated router: CDP is up, nothing is plugged in.
        ScriptStep(
            expect="show cdp neighbors\n",
            respond=(
                "Device ID        Local Intrfce     Holdtme    Capability  Platform  Port ID\n"
                "\nTotal cdp entries displayed : 0\n"
            ) + "R2-1#",
        ),
        ScriptStep(
            expect="show cdp neighbors detail",
            respond="Total cdp entries displayed : 0\n" + "R2-1#",
        ),
        ScriptStep(expect="show version", respond=_version("R2-1") + "R2-1#"),
        ScriptStep(expect="", respond="R2-1#"),
        ScriptStep(expect="exit", respond="", repeat=True),
    ]

    def root_factory(host: str, password: str) -> IosShellSession:
        return IosShellSession(
            host=host, transport=ScriptedTransport(steps, name="root"),
            limits=limits, username=USER, password=password,
        )

    result = RecursiveDiscovery(
        seed_host="192.168.98.34", username=USER, password=PASS, limits=limits,
        root_factory=root_factory,
        nested_factory=lambda **kw: (_ for _ in ()).throw(AssertionError("no nesting expected")),
    ).run()
    assert result.topology is not None
    assert result.topology.links == []
    assert any(
        "no CDP neighbour rows were collected" in w for w in result.warnings
    )


def test_link_states_only_up_when_both_endpoints_are_up() -> None:
    topology = _run_reciprocal().topology
    assert topology is not None
    interfaces = {i.id: i for i in topology.interfaces}
    for link in topology.links:
        expected_up = (
            interfaces[link.source_interface_id].is_up
            and interfaces[link.destination_interface_id].is_up
        )
        assert (str(link.state) == "up") is expected_up
