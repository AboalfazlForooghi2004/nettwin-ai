"""Terminal cursor rendering for CLI parsing.

Live run live-ospf-20261118-173241 proved the root cause of the missing Router
LSA observations: on r2, r2-2, r2-3 and r2-4 the third ``Link connected to:``
marker arrived preceded by terminal backspaces::

    \\x08\\x08\\x08\\x08\\x08\\x08\\x08\\x08\\x08        \\x08\\x08\\x08\\x08\\x08\\x08\\x08\\x08\\x08    Link connected to: a Transit Network

Only two links were recognised, so the LSA contradicted its declared count, was
withheld, and that observer's copy vanished from the canonical record.

The rendering model matters. A backspace **moves the cursor**; it does not
delete. The character survives until overwritten. Stripping the bytes keeps
text the terminal erased and destroys text the terminal kept, so the normaliser
replays a character buffer with a cursor instead.

Test groups below are deliberately separated:

* rendered terminal semantics — synthetic cases, checked against a real
  terminal model;
* the exact captured PNETLab bytes — real fixtures from the live artifact;
* aggregation and preserved validation.

No live PNETLab run has confirmed the end-to-end result.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from nettwin.collect.cli_text import (
    TAB_WIDTH,
    normalise_cli_text,
    render_terminal_line,
)

BS = "\x08"
CR = "\r"
HT = "\t"
LIVE_DIR = Path(__file__).parent / "data" / "ospf" / "live"

#: The exact prefix reported in the live artifacts.
LIVE_PREFIX = f"{BS * 9}        {BS * 9}    "


# =========================================================================== #
# Group 1 — rendered terminal semantics (synthetic cases)
# =========================================================================== #


@pytest.mark.parametrize(
    ("raw", "rendered"),
    [
        # A backspace only moves the cursor; the cell stays until overwritten.
        ("abc\b\bX", "aXc"),
        ("abc\b", "abc"),
        ("abc\bX", "abX"),
        # CR returns to column zero without clearing the line.
        ("abc\rX", "Xbc"),
        # Overwrite shorter than the existing content leaves the tail intact.
        ("abcdef\rXY", "XYcdef"),
        # Overwrite longer than the existing content extends it.
        ("abc\rLONGTEXT", "LONGTEXT"),
        # Backspace at column zero is bounded and destructive to nothing.
        (BS * 3 + "abc", "abc"),
        (BS, ""),
    ],
)
def test_cursor_rendering_matches_a_terminal(raw: str, rendered: str) -> None:
    assert render_terminal_line(raw) == rendered


def test_backspace_does_not_delete_the_character() -> None:
    """The regression this round corrects.

    A pop-based implementation returns ``"ab"`` for ``"abc\\b"`` — it deletes a
    character a terminal only moved away from.
    """
    assert render_terminal_line("abc" + BS) == "abc"
    assert render_terminal_line("abc" + BS) != "ab"


def test_carriage_return_does_not_clear_the_line() -> None:
    """A clear-based implementation returns ``"X"`` for ``"abc\\rX"``."""
    assert render_terminal_line("abc" + CR + "X") == "Xbc"
    assert render_terminal_line("abc" + CR + "X") != "X"


def test_cursor_position_is_not_the_end_of_the_buffer() -> None:
    """Overwrites land at the cursor, not at the end of the string."""
    assert render_terminal_line("abc" + BS * 2 + "XY") == "aXY"
    assert render_terminal_line("abcdef" + BS * 3 + "Z") == "abcZef"


def test_tabs_advance_to_terminal_tab_stops() -> None:
    """Tabs are handled, not dropped, so column alignment survives."""
    assert render_terminal_line("A" + HT + "B") == "A" + " " * (TAB_WIDTH - 1) + "B"
    assert render_terminal_line(HT + "X") == " " * TAB_WIDTH + "X"
    # A tab stop is measured from column zero, not from the string start.
    assert render_terminal_line("  A" + HT + "B") == "  A" + " " * (TAB_WIDTH - 3) + "B"
    assert len(render_terminal_line("A" + HT + "B")) == TAB_WIDTH + 1


def test_indentation_is_preserved_verbatim() -> None:
    """Indentation is structural in IOS output; nothing may trim it."""
    for line in (
        "    Link connected to: a Transit Network",
        "      Number of MTID metrics: 0",
        "       TOS 0 Metrics: 10",
        "  LS age: 1163",
    ):
        assert render_terminal_line(line) == line
        assert normalise_cli_text(line) == line


def test_clean_text_is_returned_unchanged() -> None:
    for text in (
        "",
        "  LS age: 100\n  Checksum: 0x90FC",
        "Codes: L - local, C - connected\n\nO  10.0.0.0/8 [110/2] via 10.0.0.1",
    ):
        assert normalise_cli_text(text) == text


def test_crlf_is_a_line_ending_not_a_redraw() -> None:
    """``\\r\\n`` must not be read as CR then LF; that would fuse lines."""
    assert normalise_cli_text("  LS age: 100\r\n  Checksum: 0x90FC") == (
        "  LS age: 100\n  Checksum: 0x90FC"
    )
    # A bare CR inside a line is a real redraw: the new text overwrites from
    # column zero, and here it is longer, so none of "junk" survives.
    assert normalise_cli_text("junk\r  LS age: 100") == "  LS age: 100"
    # When the new text is shorter, the tail of the old line survives — the
    # visible signature of a redraw rather than a clear.
    assert normalise_cli_text("0123456789\rABC") == "ABC3456789"


def test_cursor_state_does_not_leak_across_lines() -> None:
    """One line's trailing backspaces must not move the next line's cursor."""
    assert normalise_cli_text("abc" + BS + BS + "\n  LS age: 100") == "abc\n  LS age: 100"


def test_recognised_ansi_sequences_are_removed_by_pattern() -> None:
    """Colour and cursor escapes are instructions, not content."""
    assert normalise_cli_text("\x1b[32mLink\x1b[0m connected") == "Link connected"
    assert normalise_cli_text("\x1b[2JLink connected") == "Link connected"
    assert normalise_cli_text("\x1b]0;r2\x07Link connected") == "Link connected"


def test_zero_width_noise_is_removed() -> None:
    assert normalise_cli_text("Link\x00 connected\x07 to: a Stub Network") == (
        "Link connected to: a Stub Network"
    )


def test_stray_control_bytes_do_not_split_tokens() -> None:
    assert normalise_cli_text("Link\x01 connected\x0b to: a Stub Network") == (
        "Link connected to: a Stub Network"
    )


def test_renderer_never_raises_on_any_byte() -> None:
    """No input may throw; a parser must degrade, not crash."""
    for code in range(0x20):
        normalise_cli_text(f"Link {chr(code)} connected")
        normalise_cli_text(chr(code))
    assert render_terminal_line("") == ""


# =========================================================================== #
# Group 2 — the exact captured PNETLab bytes
# =========================================================================== #


def test_the_exact_live_prefix_renders_to_the_marker() -> None:
    line = LIVE_PREFIX + "Link connected to: a Transit Network"
    assert normalise_cli_text(line) == "    Link connected to: a Transit Network"


def test_the_live_prefix_keeps_four_leading_spaces_not_twelve() -> None:
    """Byte-stripping would leave twelve columns and still fail to match."""
    rendered = normalise_cli_text(LIVE_PREFIX + "Link")
    assert rendered == "    Link"
    assert not rendered.startswith("     ")


def test_a_non_space_under_the_live_cursor_run_is_not_lost() -> None:
    """The live case only passed because every overwritten cell was a space.

    Put real text where the cursor lands and a pop/clear implementation
    destroys it while this renderer overwrites it correctly.
    """
    line = f"{BS * 9}        {BS * 9}    Link connected to: a Transit Network"
    assert normalise_cli_text(line) == "    Link connected to: a Transit Network"
    # Same geometry, but the cursor lands mid-word.
    assert render_terminal_line("X" * 9 + BS * 9 + "TYPEDTEXT") == "TYPEDTEXT"


def test_captured_fixtures_contain_the_real_control_bytes() -> None:
    """The fixtures must carry the live bytes, not a cleaned paraphrase."""
    assert BS in (LIVE_DIR / "backspace_r2-2.txt").read_text(encoding="utf-8")
    assert BS in (LIVE_DIR / "backspace_r2.txt").read_text(encoding="utf-8")
    assert BS not in (LIVE_DIR / "backspace_r2-1.txt").read_text(encoding="utf-8")


# =========================================================================== #
# Group 3 — parser effect on the captured bytes
# =========================================================================== #


def _parse(device: str):  # noqa: ANN202
    from nettwin.collect.ospf_parsers import parse_show_ip_ospf_database_router

    text = (LIVE_DIR / f"backspace_{device}.txt").read_text(encoding="utf-8")
    return parse_show_ip_ospf_database_router(text, device)


@pytest.mark.parametrize("device", ["r2-1", "r2", "r2-2", "r2-3", "r2-4"])
def test_all_three_links_are_recognised_on_every_device(device: str) -> None:
    """Acceptance: three links, 8000008A / 0x7E06, on all five captures."""
    lsas, warnings = _parse(device)
    assert warnings == [], f"{device}: {warnings}"
    assert len(lsas) == 1
    lsa = lsas[0]
    assert lsa.sequence == "8000008A"
    assert lsa.checksum == "0x7E06"
    assert lsa.number_of_links == 3
    assert len(lsa.links) == 3, f"{device}: only {len(lsa.links)} link(s) parsed"
    assert [link.link_id for link in lsa.links] == ["10.0.21.1", "10.0.45.2", "10.255.255.5"]


def test_the_affected_captures_match_the_clean_one() -> None:
    clean, _ = _parse("r2-1")
    for device in ("r2", "r2-2", "r2-3", "r2-4"):
        noisy, _ = _parse(device)
        assert noisy[0].links == clean[0].links, device
        assert noisy[0].sequence == clean[0].sequence
        assert noisy[0].checksum == clean[0].checksum


def test_five_observers_with_backspaces_canonicalise_to_one_lsa() -> None:
    """The live acceptance criterion, end to end."""
    from nettwin.collect.cisco_ios import DeviceObservations
    from nettwin.collect.nested.discovery import ospf_device_data
    from nettwin.collect.ospf_topology import build_ospf_topology

    devices = []
    for device in ("r2", "r2-1", "r2-2", "r2-3", "r2-4"):
        lsas, _ = _parse(device)
        observations = DeviceObservations(
            host="h", device_id=device, collected_at="", status="ok"
        )
        observations.ospf_router_lsas = [lsa.model_dump() for lsa in lsas]
        devices.append(ospf_device_data(observations, device))

    topology = build_ospf_topology(devices)
    matches = [
        lsa for lsa in topology.router_lsas if lsa.link_state_id == "10.255.255.5"
    ]
    assert len(matches) == 1
    canonical = matches[0]
    assert canonical.sequence == "8000008A"
    assert canonical.checksum == "0x7E06"
    assert len(canonical.links) == 3
    assert canonical.observed_by == ["r2", "r2-1", "r2-2", "r2-3", "r2-4"]
    assert len(canonical.observed_by) == len(set(canonical.observed_by))


# =========================================================================== #
# Group 3b — every parser that consumes raw transport text
# =========================================================================== #

#: The exact live control run, injected before a data row.
NOISY = LIVE_PREFIX


@pytest.mark.parametrize(
    ("parser_name", "clean", "target", "pick"),
    [
        (
            "parse_show_version",
            "Cisco IOS Software, 3725 Software\nRouter uptime is 3 days\n"
            "cisco 3725 (R7000) processor\n",
            "Cisco IOS Software",
            lambda result: (result.hostname, result.model),
        ),
        (
            "parse_show_ip_interface_brief",
            "Interface    IP-Address  OK? Method Status  Protocol\n"
            "Ethernet0/0  10.0.0.1    YES NVRAM  up      up\n",
            "Ethernet0/0",
            lambda result: [(row.name, row.ip_address) for row in result],
        ),
        (
            "parse_show_ip_route",
            "Codes: O - OSPF\n\nO  10.0.34.0/30 [110/20] via 10.0.23.2, "
            "00:01:02, Ethernet0/0\n",
            "O  10.0.34.0",
            lambda result: [(row.prefix, row.protocol_code) for row in result],
        ),
        (
            "parse_show_ip_ospf_neighbor",
            "Neighbor ID   Pri  State    Dead Time  Address   Interface\n"
            "10.255.255.4  1    FULL/DR  00:00:38   10.0.34.6  Ethernet0/0\n",
            "10.255.255.4",
            lambda result: [(row.neighbor_id, row.state) for row in result],
        ),
        (
            "parse_show_cdp_neighbors_detail",
            "-------------------------\nDevice ID: R2-2\n"
            "Interface: Ethernet0/0,  Port ID (outgoing port): Ethernet0/1\n"
            "\nPlatform: cisco 3725\n",
            "Device ID: R2-2",
            lambda result: [(row.device_id, row.local_interface) for row in result],
        ),
    ],
)
def test_live_control_run_does_not_change_parser_output(
    parser_name: str, clean: str, target: str, pick
) -> None:
    """Inject the exact captured bytes; the parse result must be identical.

    This is the cross-parser guarantee: one shared renderer, and no parser
    behaves differently because the transport redrew a line.
    """
    from nettwin.collect import ios_parsers

    parser = getattr(ios_parsers, parser_name)
    noisy = clean.replace(target, NOISY + target, 1)
    assert noisy != clean

    expected, expected_warnings = parser(clean)
    actual, actual_warnings = parser(noisy)
    # Same rows *and* same diagnostics: a redrawn line must not change the
    # parse, and must not manufacture or suppress a warning either.
    assert pick(actual) == pick(expected), parser_name
    assert actual_warnings == expected_warnings, f"{parser_name}: {actual_warnings}"


def test_cdp_table_parsing_is_unaffected_by_a_clean_capture() -> None:
    """CDP regression guard: normalisation must not alter a clean table."""
    from nettwin.collect.ios_parsers import parse_show_cdp_neighbors

    table = (
        "Device ID        Local Intrfce     Holdtme    Capability  Platform  Port ID\n"
        "R2-2             Eth0/0            170          R S I     3725      Eth0/1\n"
    )
    rows, warnings = parse_show_cdp_neighbors(table)
    assert warnings == []
    assert [(row.device_id, row.local_interface) for row in rows] == [
        ("R2-2", "Ethernet0/0")
    ]


def test_indented_cdp_tables_are_a_pre_existing_limitation() -> None:
    """Documented, not introduced here.

    ``parse_show_cdp_neighbors`` slices at absolute column offsets taken from
    the header row. A table indented with *plain spaces* already fails before
    any control character is involved, so this is old behaviour that the
    renderer neither causes nor may silently change — it is out of scope for
    this fix and is recorded so a future change is a deliberate one.
    """
    from nettwin.collect.ios_parsers import parse_show_cdp_neighbors

    table = (
        "Device ID        Local Intrfce     Holdtme    Capability  Platform  Port ID\n"
        "R2-2             Eth0/0            170          R S I     3725      Eth0/1\n"
    )
    indented = "\n".join("    " + line if line else line for line in table.split("\n"))
    assert parse_show_cdp_neighbors(indented)[0] == []          # pre-existing
    assert parse_show_cdp_neighbors(table)[0] != []             # unindented works


# =========================================================================== #
# Group 4 — raw evidence unchanged, validation not weakened
# =========================================================================== #


def test_parsing_does_not_mutate_the_raw_input() -> None:
    from nettwin.collect.ospf_parsers import parse_show_ip_ospf_database_router

    raw = (LIVE_DIR / "backspace_r2-2.txt").read_text(encoding="utf-8")
    before = raw
    parse_show_ip_ospf_database_router(raw, "r2-2")
    assert raw == before


def test_raw_evidence_remains_byte_for_byte_unchanged() -> None:
    """raw_evidence.yaml records what the device sent, control bytes included."""
    import importlib.util

    from nettwin.collect.cisco_ios import DeviceObservations

    spec = importlib.util.spec_from_file_location(
        "_dr_under_test", Path(__file__).resolve().parents[1] / "scripts" / "discover_recursive.py"
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)

    raw = (LIVE_DIR / "backspace_r2-2.txt").read_text(encoding="utf-8")
    observations = DeviceObservations(host="h", device_id="r2-2", collected_at="", status="ok")
    observations.raw_commands = {"show ip ospf database router": raw}

    class _Node:
        identity = "r2-2"

    _Node.observations = observations

    class _Result:
        nodes = [_Node()]

    evidence = module._raw_evidence_audit(_Result())
    stored = evidence["devices"][0]["commands"]["show ip ospf database router"]["output"]
    assert stored == raw
    assert stored.encode("utf-8") == raw.encode("utf-8")
    assert BS in stored


@pytest.mark.parametrize(
    ("declared", "kept", "marker"),
    [(3, 0, "declares 3 link(s) but 0 were parsed"), (2, 1, "declares 2 link(s) but 1 were parsed")],
)
def test_a_genuinely_truncated_lsa_is_still_rejected(
    declared: int, kept: int, marker: str
) -> None:
    """The fix must not turn a short body into a valid LSA."""
    from nettwin.collect.ospf_parsers import parse_show_ip_ospf_database_router

    raw = (LIVE_DIR / "backspace_r2-2.txt").read_text(encoding="utf-8")
    body = raw.replace("  Number of Links: 3", f"  Number of Links: {declared}", 1)
    # Keep the header and exactly `kept` link blocks.
    parts = body.split("    Link connected to:")
    truncated = "    Link connected to:".join(parts[: kept + 1])

    lsas, warnings = parse_show_ip_ospf_database_router(truncated, "r2-2")
    assert lsas == []
    assert any(marker in w for w in warnings), warnings
    assert any("LSA dropped" in w for w in warnings)


def test_rendering_cannot_invent_links() -> None:
    """A body with one link and one declared stays contradictory."""
    from nettwin.collect.ospf_parsers import parse_show_ip_ospf_database_router

    raw = (LIVE_DIR / "backspace_r2-1.txt").read_text(encoding="utf-8")
    body = raw.replace("  Number of Links: 3", "  Number of Links: 2", 1)
    one = body.split("    Link connected to:")[0] + (
        "    Link connected to: a Stub Network\n"
        "     (Link ID) Network/subnet number: 10.255.255.5\n"
        "     (Link Data) Network Mask: 255.255.255.255\n"
        "      Number of MTID metrics: 0\n"
        "       TOS 0 Metrics: 1\n"
    )
    lsas, warnings = parse_show_ip_ospf_database_router(one, "r2-1")
    assert lsas == []
    assert any("declares 2 link(s) but 1 were parsed" in w for w in warnings)
