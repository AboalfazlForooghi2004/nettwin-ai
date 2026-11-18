"""Terminal control-character normalisation for CLI parsing.

Live run live-ospf-20261118-173241 proved the root cause of the missing Router
LSA observations: on four of five devices the third ``Link connected to:``
marker arrived preceded by terminal backspaces::

    \\x08\\x08\\x08\\x08\\x08\\x08\\x08\\x08\\x08        \\x08\\x08\\x08\\x08\\x08\\x08\\x08\\x08\\x08    Link connected to: a Transit Network

Only two links were recognised, so the LSA contradicted its own declared count,
was withheld, and that observer's copy vanished from the canonical record.

The fix is a *text* concern, not an OSPF one, so it lives in
``nettwin.collect.cli_text`` and is applied by every parser that consumes raw
transport text.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from nettwin.collect.cli_text import collapse_terminal_overstrike, normalise_cli_text

BS = "\x08"
LIVE_DIR = Path(__file__).parent / "data" / "ospf" / "live"

#: The exact prefix reported in the live artifacts.
LIVE_PREFIX = f"{BS * 9}        {BS * 9}    "


# --------------------------------------------------------------------------- #
# Cursor semantics
# --------------------------------------------------------------------------- #


def test_backspace_erases_the_preceding_character() -> None:
    """``0x08`` is cursor motion, not a printable character.

    Naive ``str.replace`` would leave the erased characters behind: on the
    live prefix it yields twelve spaces instead of four, which is how a link
    marker stopped matching. The collapse replays the cursor instead.
    """
    # Classic overstrike: print "k", backspace, print "k" again — one glyph.
    assert normalise_cli_text("k" + BS + "k") == "k"
    assert normalise_cli_text("ab" + BS + "c") == "ac"
    # Erasing cannot go before column zero.
    assert normalise_cli_text(BS * 3 + "Link") == "Link"


def test_the_exact_live_prefix_collapses_to_the_marker() -> None:
    line = LIVE_PREFIX + "Link connected to: a Transit Network"
    assert normalise_cli_text(line) == "    Link connected to: a Transit Network"


def test_backspaces_at_column_zero_are_dropped() -> None:
    """A terminal cannot erase before column zero; nothing is corrupted."""
    assert normalise_cli_text(BS * 9 + "Link") == "Link"


def test_adjacent_meaningful_text_is_not_corrupted() -> None:
    """Erasing must stop exactly where the character stops."""
    assert normalise_cli_text("abc" + BS * 3 + "def") == "def"
    assert normalise_cli_text("abc" + BS + "X") == "abX"


def test_carriage_return_redraws_the_line() -> None:
    """CR returns to column zero, so the later text overwrites the earlier."""
    assert collapse_terminal_overstrike("  junk junk\r  Link") == "  Link"
    assert collapse_terminal_overstrike("  junk\rreal") == "real"
    # A CRLF pair is a line ending, not a redraw.
    assert normalise_cli_text("a\r\nb") == "a\nb"


def test_zero_width_noise_is_removed_not_interpreted() -> None:
    assert normalise_cli_text("Link\x00 connected\x07 to: a Stub Network") == (
        "Link connected to: a Stub Network"
    )


def test_clean_text_is_returned_unchanged() -> None:
    for text in (
        "",
        "    Link connected to: a Transit Network",
        "  LS age: 100\n  Checksum: 0x90FC",
    ):
        assert normalise_cli_text(text) == text


def test_indentation_after_the_control_run_is_preserved() -> None:
    """Indentation is structural in IOS output; only the erase is replayed."""
    line = LIVE_PREFIX + "Link connected to: a Transit Network"
    normalised = normalise_cli_text(line)
    assert normalised.startswith("    ")
    assert not normalised.startswith("     ")          # exactly four, not twelve
    assert normalised == "    Link connected to: a Transit Network"


# --------------------------------------------------------------------------- #
# Effect on the OSPF parser — the live failure
# --------------------------------------------------------------------------- #


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


def test_the_affected_captures_exactly_match_the_clean_one() -> None:
    """Normalisation must make the noisy captures equal to the clean capture."""
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


# --------------------------------------------------------------------------- #
# Raw evidence is untouched; validation is not weakened
# --------------------------------------------------------------------------- #


def test_raw_evidence_keeps_the_control_characters() -> None:
    """Parsing normalises a copy. The artifact must stay forensically true."""
    raw = (LIVE_DIR / "backspace_r2-2.txt").read_text(encoding="utf-8")
    assert BS in raw, "fixture must contain the live control characters"

    from nettwin.collect.ospf_parsers import parse_show_ip_ospf_database_router

    before = raw
    parse_show_ip_ospf_database_router(raw, "r2-2")
    assert raw == before, "the parser must not mutate its input"


def test_retained_raw_evidence_still_contains_backspaces() -> None:
    """raw_evidence.yaml records what the device sent, verbatim."""
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
    assert BS in stored
    assert stored == raw


def test_a_genuinely_truncated_lsa_is_still_rejected() -> None:
    """The fix must not turn a short body into a valid LSA."""
    from nettwin.collect.ospf_parsers import parse_show_ip_ospf_database_router

    raw = (LIVE_DIR / "backspace_r2-2.txt").read_text(encoding="utf-8")
    truncated = raw.split("    Link connected to: a Transit Network")[0]

    lsas, warnings = parse_show_ip_ospf_database_router(truncated, "r2-2")
    assert lsas == []
    assert any("declares 3 link(s) but 0 were parsed" in w for w in warnings)
    assert any("LSA dropped" in w for w in warnings)


def test_normalisation_does_not_invent_links() -> None:
    """A two-link LSA that declares two links stays two links."""
    from nettwin.collect.ospf_parsers import parse_show_ip_ospf_database_router

    raw = (LIVE_DIR / "backspace_r2-1.txt").read_text(encoding="utf-8")
    two = raw.replace("  Number of Links: 3", "  Number of Links: 2", 1)
    two = two.split("    Link connected to: a Transit Network")[0] + (
        "    Link connected to: a Stub Network\n"
        "     (Link ID) Network/subnet number: 10.255.255.5\n"
        "     (Link Data) Network Mask: 255.255.255.255\n"
        "      Number of MTID metrics: 0\n"
        "       TOS 0 Metrics: 1\n"
    )
    # One link present against two declared is a genuine contradiction, so the
    # LSA is still withheld. Normalisation must never pad the count to match.
    lsas, warnings = parse_show_ip_ospf_database_router(two, "r2-1")
    assert lsas == []
    assert any("declares 2 link(s) but 1 were parsed" in w for w in warnings)
