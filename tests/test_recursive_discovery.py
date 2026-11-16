"""Phase 2.3 — recursive multi-hop discovery tests. **OFFLINE ONLY.**

No socket is opened and no SSH library is imported. Every device is a
:class:`ScriptedTransport` playing a fixed IOS transcript, so the orchestration
(queues, limits, backtracking, duplicates, cycles) is exercised deterministically.

Fixture provenance:
* ``tests/data/nested/*_detail.txt`` — the real PNETLab CDP structure (same
  column/block format as ``tests/data/live2026``), with the neighbour IPs the
  lab actually uses. R2-2 and R2-4 rows are **synthetic mirrors** because
  those devices have not been collected live yet.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from nettwin.collect import ios_parsers
from nettwin.collect.nested import (
    IosShellSession,
    PromptKind,
    ReplayTransport,
    ScriptedTransport,
    ScriptStep,
    SessionLimits,
    SessionTimeoutError,
    classify_prompt,
    looks_like_failure,
)
from nettwin.collect.nested.discovery import (
    DISCOVERY_COMMANDS,
    DeviceStatus,
    IpAliases,
    RecursiveDiscovery,
)
from nettwin.collect.nested.prompts import failure_reason
from nettwin.collect.nested.session import NestedConnectError, SessionAuthError

NESTED_DATA = Path(__file__).parent / "data" / "nested"

USER = "nettwin-ro"
PASS = "unit-test-only-fake-pw"


# =========================================================================== #
# Transcript builder — one device's full read-only conversation
# =========================================================================== #


def _version(hostname: str) -> str:
    return (
        "Cisco IOS Software, Linux Software (I86BI_LINUXL2-ADVENTERPRISEK9-M), "
        f"Version 15.2(4)M5, RELEASE SOFTWARE (fc2)\n\n{hostname} uptime is 2 weeks\n"
    )


def _brief(hostname: str) -> str:
    return (
        "Interface              IP-Address      OK? Method Status                Protocol\n"
        f"Ethernet0/0            10.0.21.{'1' if hostname == 'R2-2' else '2'}       "
        "YES NVRAM  up                    up\n"
        "Ethernet0/1            10.0.41.1       YES NVRAM  up                    up\n"
        "Loopback0              10.255.255.1    YES NVRAM  up                    up\n"
    )


ROUTE_TEXT = (
    "Codes: L - local, C - connected, S - static\n\n"
    "C        10.0.21.0/30 is directly connected, Ethernet0/0\n"
    "C        10.0.41.0/30 is directly connected, Ethernet0/1\n"
    "C        10.255.255.1/32 is directly connected, Loopback0\n"
)

OSPF_TEXT = (
    "Neighbor ID     Pri State           Dead Time   Address         Interface\n"
    "10.255.255.2      1 FULL/BDR        00:00:35    10.0.21.1       Ethernet0/0\n"
)

CDP_SUMMARY = (
    "Device ID        Local Intrfce     Holdtme    Capability  Platform  Port ID\n"
    "R2-2.nettwin.lab Eth 0/0           138             R S I  Linux Uni Eth 0/1\n"
)


def device_steps(
    hostname: str,
    detail_file: str,
    *,
    cdp_summary: str = CDP_SUMMARY,
    prompt_sig: str = "#",
) -> list[ScriptStep]:
    """The read-only conversation for one device, in dispatch order."""
    host_prompt = f"{hostname}{prompt_sig}"
    detail = (NESTED_DATA / detail_file).read_text(encoding="utf-8")
    steps: list[ScriptStep] = [
        ScriptStep(
            expect="show ip interface brief",
            respond=_brief(hostname) + host_prompt,
        ),
        ScriptStep(expect="show ip route", respond=ROUTE_TEXT + host_prompt),
        ScriptStep(expect="show ip ospf neighbor", respond=OSPF_TEXT + host_prompt),
        ScriptStep(expect="show cdp neighbors\n", respond=cdp_summary + host_prompt),
        ScriptStep(expect="show cdp neighbors detail", respond=detail + host_prompt),
        ScriptStep(expect="show version", respond=_version(hostname) + host_prompt),
        ScriptStep(expect="exit", respond="", repeat=True),
    ]
    return steps


def root_transport(
    hostname: str = "R2-1",
    detail_file: str = "r2-1_detail.txt",
    *,
    prompt_sig: str = "#",
    ssh_targets: tuple[str, ...] = (),
) -> ScriptedTransport:
    """Transport for the seed: already authenticated, and able to answer ``ssh``.

    On a real IOS parent, typing ``ssh -l user <ip>`` prints the password
    prompt for the *neighbour*; the neighbour's own transport (supplied by the
    nested factory) then carries the rest of that conversation. ``ssh_targets``
    lists the IPs this parent will be asked to dial.
    """
    steps = device_steps(hostname, detail_file, prompt_sig=prompt_sig)
    steps.insert(0, ScriptStep(expect="", respond=f"{hostname}{prompt_sig}"))
    for target in ssh_targets:
        steps.append(
            ScriptStep(
                expect=f"ssh -l nettwin-ro {target}", respond="Password: ", repeat=True
            )
        )
    return ScriptedTransport(steps, name=f"root:{hostname}")


def nested_transport(hostname: str, detail_file: str) -> ScriptedTransport:
    """Transport for a session opened by ``ssh``: password prompt first."""
    steps = device_steps(hostname, detail_file)
    steps.insert(0, ScriptStep(expect="", respond="Password: "))
    steps.insert(1, ScriptStep(expect=PASS, respond=f"\n{hostname}#"))
    return ScriptedTransport(steps, name=f"nested:{hostname}")



def _node(result, name: str):
    """Find a discovered node by short name or FQDN (both are one device)."""
    from nettwin.collect.discovery.identity import normalize_device_key

    key = normalize_device_key(name)
    for candidate in (name, key.split(".")[0]):
        found = result.node(candidate)
        if found is not None:
            return found
    short = key.split(".")[0]
    for node in result.nodes:
        if node.identity.split(".")[0] == short:
            return node
    return None


# =========================================================================== #
# Prompt classification
# =========================================================================== #


@pytest.mark.parametrize(
    ("buffer", "kind"),
    [
        ("R2-1#", PromptKind.PRIVILEGED),
        ("R2-1>", PromptKind.READY),
        ("R2-1.nettwin.lab#", PromptKind.PRIVILEGED),
        ("R2-1(config)#", PromptKind.PRIVILEGED),
        ("Password: ", PromptKind.PASSWORD),
        ("Username: ", PromptKind.USERNAME),
        ("Are you sure you want to continue connecting (yes/no)? ", PromptKind.HOSTKEY),
        ("--More--", PromptKind.MORE),
        ("% Connection refused by remote host", PromptKind.ERROR),
        ("", PromptKind.UNKNOWN),
        ("garbage without prompt", PromptKind.UNKNOWN),
    ],
)
def test_prompt_classification(buffer: str, kind: PromptKind) -> None:
    assert classify_prompt(buffer).kind is kind


def test_unknown_prompt_is_never_ready() -> None:
    """A caller must not send commands into an unrecognised buffer."""
    assert not classify_prompt("something we do not understand").is_ready


def test_failure_detection_covers_lab_messages() -> None:
    for text in (
        "Connection refused by remote host",
        "Connection timed out",
        "% Authentication failed",
        "Host key verification failed",
        "No route to host",
    ):
        assert looks_like_failure(text), text
        assert failure_reason(text)


# =========================================================================== #
# Session layer
# =========================================================================== #


def test_session_opens_and_runs_a_command() -> None:
    transport = root_transport("R2-1")
    session = IosShellSession(host="192.168.98.34", transport=transport, limits=FAST)
    session.open()
    assert session.hostname == "R2-1"
    assert session.privilege == 15
    output = session.run_command("show version")
    assert "Version 15.2(4)M5" in output
    session.close()
    assert transport.closed


def test_session_authenticates_with_password_prompt() -> None:
    transport = nested_transport("R2-2", "r2-2_detail.txt")
    session = IosShellSession(
        host="10.0.21.1",
        transport=transport,
        limits=FAST,
        username=USER,
        password=PASS,
    )
    session.open()
    assert session.hostname == "R2-2"
    assert PASS in transport.written
    session.close()


def test_session_missing_username_is_auth_error() -> None:
    transport = ScriptedTransport([ScriptStep(expect="", respond="Username: ")])
    session = IosShellSession(host="10.0.21.1", transport=transport, limits=FAST)
    with pytest.raises(SessionAuthError, match="asked for a username"):
        session.open()


def test_session_timeout_is_explicit() -> None:
    transport = ScriptedTransport([])  # never replies
    session = IosShellSession(
        host="10.0.21.1", transport=transport, limits=SessionLimits(connect_timeout=0.2, poll_interval=0.001)
    )
    with pytest.raises(SessionTimeoutError, match="timeout waiting"):
        session.open()


def test_password_never_appears_in_error_messages() -> None:
    transport = ScriptedTransport([])
    session = IosShellSession(
        host="10.0.21.1",
        transport=transport,
        limits=SessionLimits(connect_timeout=0.2, poll_interval=0.001),
        password=PASS,
    )
    with pytest.raises(SessionTimeoutError) as excinfo:
        session.open()
    assert PASS not in str(excinfo.value)


def test_nested_ssh_refused_raises_nested_connect_error() -> None:
    steps = [
        ScriptStep(expect="", respond="R2-1#"),
        ScriptStep(
            expect="ssh -l",
            respond="% Connection refused by remote host\nR2-1#",
        ),
    ]
    parent = IosShellSession(
        host="192.168.98.34",
        transport=ScriptedTransport(steps),
        limits=FAST,
        username=USER,
        password=PASS,
    )
    parent.open()
    with pytest.raises(NestedConnectError) as excinfo:
        parent.open_nested(
            neighbour_ip="10.0.21.1",
            username=USER,
            password=PASS,
            transport_factory=lambda **_: ScriptedTransport([]),
        )
    assert excinfo.value.kind == "refused"


def test_nested_ssh_auth_failure_is_classified() -> None:
    """The neighbour rejects the password: the parent prints the password
    prompt, the *child* channel carries the rejection."""
    parent_steps = [
        ScriptStep(expect="", respond="R2-1#"),
        ScriptStep(expect="ssh -l", respond="Password: "),
    ]
    child_steps = [ScriptStep(expect=PASS, respond="\n% Authentication failed\nR2-1#")]
    parent = IosShellSession(
        host="192.168.98.34",
        transport=ScriptedTransport(parent_steps),
        limits=FAST,
        username=USER,
        password=PASS,
    )
    parent.open()
    with pytest.raises(NestedConnectError) as excinfo:
        parent.open_nested(
            neighbour_ip="10.0.21.1",
            username=USER,
            password=PASS,
            transport_factory=lambda **_: ScriptedTransport(child_steps),
        )
    assert excinfo.value.kind == "auth"
    assert PASS not in str(excinfo.value)


def test_replay_transport_reads_a_recorded_file(tmp_path: Path) -> None:
    """A recorded transcript replays command output verbatim."""
    transcript = tmp_path / "session.txt"
    transcript.write_text(
        ">>> \nR2-1#\n"
        ">>> show version\nCisco IOS Software, Version 15.2(4)M5\nR2-1#\n",
        encoding="utf-8",
    )
    transport = ReplayTransport(transcript)
    session = IosShellSession(host="r", transport=transport, limits=FAST)
    session.open()
    assert "Version 15.2(4)M5" in session.run_command("show version")


# =========================================================================== #
# Recursive orchestration — the required scenario table (Task 6)
# =========================================================================== #


FAST = SessionLimits(
    connect_timeout=0.4, command_timeout=0.4, poll_interval=0.001, max_attempts_per_device=1
)


def _make_discovery(
    *,
    root_name: str = "R2-1",
    root_detail: str = "r2-1_detail.txt",
    nested: dict[str, tuple[str, str]],
    limits: SessionLimits | None = None,
    failing: dict[str, Exception] | None = None,
) -> RecursiveDiscovery:
    """Wire a discovery whose devices are scripted transcripts.

    ``nested`` maps neighbour IP -> (hostname, detail fixture).
    ``failing`` maps neighbour IP -> exception the nested factory should raise.
    """
    failures = failing or {}

    # Every IP the root will be asked to dial — including ones whose nested
    # factory will deliberately fail (that is what we are testing).
    ssh_targets = tuple(nested) + tuple(failures)

    def root_factory(host: str, password: str) -> IosShellSession:
        return IosShellSession(
            host=host,
            transport=root_transport(
                root_name, root_detail, ssh_targets=ssh_targets
            ),
            limits=limits or FAST,
            username=USER,
            password=password,
        )

    def nested_factory(*, host: str, username: str, password: str, parent=None):
        if host in failures:
            raise failures[host]
        hostname, detail = nested[host]
        return nested_transport(hostname, detail)

    return RecursiveDiscovery(
        seed_host="192.168.98.34",
        username=USER,
        password=PASS,
        limits=limits or FAST,
        root_factory=root_factory,
        nested_factory=nested_factory,
    )


def test_1_seed_device_discovery() -> None:
    """The seed is collected and both advertised neighbours are recorded."""
    discovery = _make_discovery(nested={})
    result = discovery.run()
    seed = next(n for n in result.nodes if n.identity == "r2-1")
    assert seed.status is DeviceStatus.COLLECTED
    assert seed.depth == 0
    assert seed.path == ["192.168.98.34"]
    assert seed.interfaces, "seed interfaces were not parsed"
    # Both neighbours appear as edges and as retained nodes (never dropped),
    # and neither was reachable on this run.
    assert {e.target for e in result.edges} == {"r2-2.nettwin.lab", "r2-4.nettwin.lab"}
    assert len(result.nodes) == 3
    for identity in ("r2-2.nettwin.lab", "r2-4.nettwin.lab"):
        node = result.node(identity)
        assert node is not None and not node.collected
        assert node.error, "an unreachable neighbour must carry a reason"


def test_2_r2_1_to_r2_2_nested_ssh() -> None:
    discovery = _make_discovery(
        nested={"10.0.21.1": ("R2-2", "r2-2_detail.txt")},
    )
    result = discovery.run()
    r2_2 = _node(result, "r2-2")
    assert r2_2 is not None
    assert r2_2.status is DeviceStatus.COLLECTED
    assert r2_2.depth == 1
    assert r2_2.path == ["192.168.98.34", "10.0.21.1"]
    assert r2_2.parent == "r2-1"


def test_3_r2_2_to_r2_4_nested_ssh() -> None:
    discovery = _make_discovery(
        nested={
            "10.0.21.1": ("R2-2", "r2-2_detail.txt"),
            "10.0.41.1": ("R2-4", "r2-4_detail.txt"),
        },
    )
    result = discovery.run()
    r2_4 = _node(result, "r2-4")
    assert r2_4 is not None
    assert r2_4.status is DeviceStatus.COLLECTED
    assert r2_4.depth >= 1


def test_4_recursive_discovery_across_multiple_hops() -> None:
    """R2-1 -> R2-2 -> R2-4 with the full path recorded."""
    discovery = _make_discovery(
        nested={
            "10.0.21.1": ("R2-2", "r2-2_detail.txt"),
            "10.0.41.1": ("R2-4", "r2-4_detail.txt"),
        },
    )
    result = discovery.run()
    assert {n.identity for n in result.collected_nodes} == {"r2-1", "r2-2", "r2-4"}
    r2_4 = _node(result, "r2-4")
    assert r2_4 is not None
    assert r2_4.path[0] == "192.168.98.34"
    assert len(r2_4.path) >= 2
    assert result.topology is not None
    assert len(result.topology.devices) == 3


def test_5_duplicate_device_id_with_different_ips() -> None:
    """One identity, two advertised addresses -> one node, both IPs tracked."""
    aliases = IpAliases()
    aliases.add("r2-2.nettwin.lab", "10.0.21.1")
    aliases.add("r2-2.nettwin.lab", "192.168.98.36")
    assert aliases.of("r2-2.nettwin.lab") == ["10.0.21.1", "192.168.98.36"]
    assert aliases.identity_of_ip("192.168.98.36") == "r2-2.nettwin.lab"
    assert len(aliases.of("r2-2.nettwin.lab")) == 2

    # Parsing keeps every advertised address (never collapsed to one).
    rows, _ = ios_parsers.parse_show_cdp_neighbors_detail(
        "-------------------------\n"
        "Device ID: R2-2.nettwin.lab\n"
        "Entry address(es):\n"
        "  IP address: 10.0.21.1\n"
        "  IP address: 192.168.98.36\n"
        "Platform: Linux Uni,  Capabilities: Router\n"
        "Interface: Ethernet0/0,  Port ID (outgoing port): Ethernet0/1\n"
    )
    assert rows[0].ip_addresses == ["10.0.21.1", "192.168.98.36"]


def test_6_cycle_prevention() -> None:
    """R2-2 advertises R2-1 back; R2-1 must not be visited twice."""
    discovery = _make_discovery(
        nested={"10.0.21.1": ("R2-2", "r2-2_detail.txt")},
    )
    result = discovery.run()
    identities = [n.identity for n in result.nodes]
    assert len(identities) == len(set(identities)), "duplicate node created"
    # The seed is collected exactly once even though R2-2 advertises it back.
    seed_nodes = [n for n in result.nodes if n.identity == "r2-1"]
    assert len(seed_nodes) == 1
    assert seed_nodes[0].status is DeviceStatus.COLLECTED
    # R2-1's own advert (r2-1.nettwin.lab from R2-2) must not become a new node.
    assert not any(n.identity.startswith("r2-1.") for n in result.nodes)
    assert result.visits <= len(result.nodes)


def test_7_failed_ssh_authentication() -> None:
    discovery = _make_discovery(
        nested={},
        failing={"10.0.21.1": NestedConnectError("auth failed", "auth")},
    )
    result = discovery.run()
    r2_2 = _node(result, "r2-2")
    assert r2_2 is not None
    assert r2_2.status is DeviceStatus.AUTH_FAILED
    assert r2_2.error is not None
    assert not r2_2.collected
    # the other neighbour must not be lost
    assert _node(result, "r2-4") is not None


def test_8_unreachable_neighbour_is_kept_with_reason() -> None:
    discovery = _make_discovery(
        nested={},
        failing={"10.0.21.1": NestedConnectError("no route", "unreachable")},
    )
    result = discovery.run()
    r2_2 = _node(result, "r2-2")
    assert r2_2 is not None
    assert r2_2.status is DeviceStatus.UNREACHABLE
    assert "no route" in (r2_2.error or "")
    assert any("nested ssh failed" in w for w in result.warnings)


def test_9_timeout_handling() -> None:
    discovery = _make_discovery(
        nested={},
        failing={"10.0.21.1": NestedConnectError("timed out", "timeout")},
        limits=SessionLimits(connect_timeout=0.2, command_timeout=0.2, poll_interval=0.001),
    )
    result = discovery.run()
    r2_2 = _node(result, "r2-2")
    assert r2_2 is not None
    assert r2_2.status is DeviceStatus.TIMEOUT


def test_10a_maximum_depth_limit() -> None:
    """max_depth=0 collects the seed only and says so."""
    discovery = _make_discovery(
        nested={"10.0.21.1": ("R2-2", "r2-2_detail.txt")},
        limits=SessionLimits(max_depth=0),
    )
    result = discovery.run()
    assert [n.identity for n in result.collected_nodes] == ["r2-1"]
    assert any("depth limit reached" in w for w in result.warnings)


def test_10b_maximum_device_limit() -> None:
    discovery = _make_discovery(
        nested={
            "10.0.21.1": ("R2-2", "r2-2_detail.txt"),
            "10.0.41.1": ("R2-4", "r2-4_detail.txt"),
        },
        limits=SessionLimits(max_devices=1),
    )
    result = discovery.run()
    assert len(result.collected_nodes) <= 1
    assert any("device limit reached" in w for w in result.warnings)


def test_11_backtracking_closes_parent_sessions() -> None:
    """Every nested session is closed; the parent chain is torn down."""
    opened: list[ScriptedTransport] = []

    def root_factory(host: str, password: str) -> IosShellSession:
        transport = root_transport("R2-1")
        opened.append(transport)
        return IosShellSession(
            host=host, transport=transport, limits=FAST,
            username=USER, password=password,
        )

    def nested_factory(*, host: str, username: str, password: str, parent=None):
        hostname, detail = {
            "10.0.21.1": ("R2-2", "r2-2_detail.txt"),
            "10.0.41.1": ("R2-4", "r2-4_detail.txt"),
        }[host]
        transport = nested_transport(hostname, detail)
        opened.append(transport)
        return transport

    discovery = RecursiveDiscovery(
        seed_host="192.168.98.34",
        username=USER,
        password=PASS,
        limits=FAST,
        root_factory=root_factory,
        nested_factory=nested_factory,
    )
    result = discovery.run()
    assert result.collected_nodes
    assert opened, "no session was opened"
    # close_all() must have closed every session that is still registered.
    assert all(t.closed for t in opened), (
        f"{sum(1 for t in opened if not t.closed)} of {len(opened)} session(s) "
        "left open (backtracking failed)"
    )
    # every collected device typed 'exit' at least once
    assert all("exit" in t.written for t in opened)


def test_12_no_device_created_from_a_neighbour_without_ip() -> None:
    detail_without_ip = (
        "-------------------------\n"
        "Device ID: R2-9.nettwin.lab\n"
        "Platform: Linux Uni,  Capabilities: Router\n"
        "Interface: Ethernet0/5,  Port ID (outgoing port): Ethernet0/9\n"
    )
    steps = device_steps("R2-1", "r2-1_detail.txt")
    for step in steps:
        if step.expect == "show cdp neighbors detail":
            step.respond = detail_without_ip + "R2-1#"
            break
    transport = ScriptedTransport(
        [ScriptStep(expect="", respond="R2-1#"), *steps], name="root:R2-1"
    )
    discovery = RecursiveDiscovery(
        seed_host="192.168.98.34",
        username=USER,
        password=PASS,
        limits=FAST,
        root_factory=lambda h, p: IosShellSession(
            host=h, transport=transport, limits=FAST,
            username=USER, password=p,
        ),
        nested_factory=lambda **_: ScriptedTransport([]),
    )
    # The neighbour advertises no IP, so the walk must never dial it.
    result = discovery.run()
    r2_9 = _node(result, "r2-9.nettwin.lab")
    assert r2_9 is not None
    assert r2_9.status is DeviceStatus.UNREACHABLE
    assert "no IP" in (r2_9.error or "")
    assert len(result.topology.devices) == 1  # only the seed — nothing invented


# =========================================================================== #
# Safety invariants
# =========================================================================== #


def test_discovery_commands_are_all_allowlisted() -> None:
    from nettwin.collect.cisco_ios import READ_ONLY_COMMANDS

    assert DISCOVERY_COMMANDS
    for command in DISCOVERY_COMMANDS:
        assert command in READ_ONLY_COMMANDS, command


def test_discovery_refuses_non_allowlisted_command() -> None:
    with pytest.raises(ValueError, match="refusing non-allowlisted"):
        RecursiveDiscovery(
            seed_host="192.168.98.34",
            username=USER,
            password=PASS,
            root_factory=lambda h, p: None,  # type: ignore[arg-type,return-value]
            nested_factory=lambda **_: None,  # type: ignore[arg-type,return-value]
            commands=("configure terminal",),
        )


def test_discovery_requires_explicit_factories() -> None:
    with pytest.raises(ValueError, match="explicit session factories"):
        RecursiveDiscovery(seed_host="1.1.1.1", username=USER, password=PASS)


def test_session_limits_validate_boundaries() -> None:
    with pytest.raises(ValueError):
        SessionLimits(max_devices=0)
    with pytest.raises(ValueError):
        SessionLimits(max_depth=-1)
    with pytest.raises(ValueError):
        SessionLimits(max_attempts_per_device=0)
    with pytest.raises(ValueError):
        SessionLimits(connect_timeout=0)


def test_no_secret_in_any_discovery_warning() -> None:
    discovery = _make_discovery(
        nested={}, failing={"10.0.21.1": NestedConnectError("refused", "refused")}
    )
    result = discovery.run()
    joined = "\n".join(result.warnings + [n.error or "" for n in result.nodes])
    assert PASS not in joined


# --------------------------------------------------------------------------- #
# Live regression: R2-3 advertises an address from two different neighbours.
# --------------------------------------------------------------------------- #


def test_13_r2_3_reaches_discovery_from_both_parents_as_one_device() -> None:
    """R2-3 is ONE device, even though two parents advertise two addresses.

    Live evidence from the PNETLab lab:

      * from R2-2, R2-3's Entry address is 10.0.32.1
      * from R2-4, R2-3's only advertised address is 10.0.34.1
        (under Management address(es))

    R2-4 is collected first here so the R2-4 path is the one that dials R2-3;
    that is exactly the path that used to yield "<no-ip>". Requirement 3: two
    advertised IPs must not become two devices.
    """
    discovery = _make_discovery(
        root_name="R2-4",
        root_detail="r2-4_with_r2-3_management_only.txt",
        nested={
            "10.0.21.1": ("R2-2", "r2-2_with_r2-3_detail.txt"),
            "10.0.34.1": ("R2-3", "r2-3_detail.txt"),
        },
    )
    result = discovery.run()

    r2_3_nodes = [node for node in result.nodes if "r2-3" in node.identity]
    assert len(r2_3_nodes) == 1, (
        f"R2-3 became {len(r2_3_nodes)} nodes: {[n.identity for n in r2_3_nodes]}"
    )
    node = r2_3_nodes[0]
    assert "<no-ip>" not in node.path, f"R2-3 was left unreachable: {node.path}"
    assert node.path[-1] == "10.0.34.1", (
        f"the management-only address was not used to reach R2-3: {node.path}"
    )

    # Both addresses seen for R2-3 are recorded, against the same identity.
    edge_ips: set[str] = set()
    for edge in result.edges:
        if "r2-3" in edge.target:
            edge_ips.update(edge.target_ips)
    assert edge_ips == {"10.0.32.1", "10.0.34.1"}, (
        f"expected both advertised addresses on the edges, got {edge_ips}"
    )


def test_14_management_only_address_produces_a_dialable_edge() -> None:
    """An edge to a neighbour whose address is only in Management address(es)
    still carries a concrete, non-invented address."""
    discovery = _make_discovery(
        root_name="R2-4",
        root_detail="r2-4_with_r2-3_management_only.txt",
        nested={"10.0.34.1": ("R2-3", "r2-3_detail.txt")},
    )
    result = discovery.run()
    edges = [edge for edge in result.edges if "r2-3" in edge.target]
    assert edges, "no edge to R2-3 was produced"
    assert {edge.target_ip for edge in edges} == {"10.0.34.1"}
