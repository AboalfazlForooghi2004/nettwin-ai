"""Regression: a neighbour whose address appears only in
``Management address(es)`` was dropped to ``<no-ip>``.

Live evidence (PNETLab, IOS 15.2 on IOL)
----------------------------------------
R2-3 advertises its address in CDP detail, and it is visible from two
neighbours on two different links::

    (from R2-2)  R2-3.nettwin.lab   Entry address(es) -> IP address: 10.0.32.1
    (from R2-4)  R2-3.nettwin.lab   Entry address(es) -> IP address: 10.0.34.1
                                     Management address(es) also carries it

NetTwin nevertheless reported ``r2-3.nettwin.lab ... <no-ip>``.

Root cause
----------
``parse_show_cdp_neighbors_detail`` tracked a ``pending_version`` flag that was
set by ``Version :`` and cleared only by a block separator. A real IOS block
puts the version body *before* the address sections::

    Version :
    Cisco IOS Software, ...            <- collected
    advertisement version: 2           <- let through (prefix check)
    Management address(es):            <- swallowed
      IP address: 10.0.34.1            <- swallowed

Every line after ``Version :`` that did not start with ``advertisement`` or
``Capability codes`` was appended to the version body and ``continue``d, so the
``Management address(es)`` header and its IP were never matched. A neighbour
whose only address lived there produced ``ip_addresses == []``, the parser
warned "advertises no IP address", and discovery created the node with
``path=[..., "<no-ip>"]`` and status ``unreachable``.

The fix stops the version body at the next section header and records each
address in the section it appeared under.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from nettwin.collect.ios_parsers import parse_show_cdp_neighbors_detail

DATA = Path(__file__).parent / "data" / "nested"


def _neighbour(records, name: str):
    for record in records:
        if name in record.device_id:
            return record
    raise AssertionError(f"{name} not parsed; got {[r.device_id for r in records]}")


# --------------------------------------------------------------------------- #
# The exact real outputs, as fixtures
# --------------------------------------------------------------------------- #


def test_r2_2_reports_r2_3_entry_address() -> None:
    """From R2-2, R2-3's address is a plain Entry address (10.0.32.1)."""
    text = (DATA / "r2-2_with_r2-3_detail.txt").read_text(encoding="utf-8")
    records, warnings = parse_show_cdp_neighbors_detail(text)
    neighbour = _neighbour(records, "R2-3")
    assert neighbour.ip_addresses == ["10.0.32.1"]
    assert neighbour.entry_addresses == ["10.0.32.1"]
    assert warnings == []


def test_r2_4_reports_r2_3_management_address() -> None:
    """From R2-4 the address is only under Management address(es) — the bug.

    Before the fix this returned ``ip_addresses == []`` and the warning
    "advertises no IP address", which is what produced ``<no-ip>``.
    """
    text = (DATA / "r2-4_with_r2-3_management_only.txt").read_text(encoding="utf-8")
    records, warnings = parse_show_cdp_neighbors_detail(text)
    neighbour = _neighbour(records, "R2-3")
    assert neighbour.ip_addresses == ["10.0.34.1"], "management address must not be lost"
    assert neighbour.entry_addresses == []
    assert neighbour.management_addresses == ["10.0.34.1"]
    assert warnings == [], "no 'advertises no IP' warning may be emitted"


def test_version_body_does_not_swallow_the_management_section() -> None:
    """The version body must stop at the next section header."""
    text = (DATA / "r2-4_with_r2-3_management_only.txt").read_text(encoding="utf-8")
    records, _ = parse_show_cdp_neighbors_detail(text)
    neighbour = _neighbour(records, "R2-3")
    assert neighbour.software_version.startswith("Cisco IOS Software")
    assert "Management address" not in neighbour.software_version
    assert "10.0.34.1" not in neighbour.software_version


# --------------------------------------------------------------------------- #
# Both sections, generally
# --------------------------------------------------------------------------- #


def test_same_address_in_both_sections_is_not_duplicated() -> None:
    text = """-------------------------
Device ID: R2-3.nettwin.lab
Entry address(es):
  IP address: 10.0.32.1
Platform: Linux Uni,  Capabilities: Router
Interface: Ethernet0/0,  Port ID (outgoing port): Ethernet0/1
Holdtime : 148 sec
Version :
Cisco IOS Software, Version 15.2(4)M5
advertisement version: 2
Management address(es):
  IP address: 10.0.32.1
"""
    records, _ = parse_show_cdp_neighbors_detail(text)
    assert records[0].ip_addresses == ["10.0.32.1"]
    assert records[0].entry_addresses == ["10.0.32.1"]
    assert records[0].management_addresses == ["10.0.32.1"]


def test_two_distinct_addresses_are_both_preserved() -> None:
    """A neighbour seen on two links advertises two addresses; keep both."""
    text = """-------------------------
Device ID: R2-3.nettwin.lab
Entry address(es):
  IP address: 10.0.32.1
Platform: Linux Uni,  Capabilities: Router
Interface: Ethernet0/0,  Port ID (outgoing port): Ethernet0/1
Holdtime : 148 sec
Version :
Cisco IOS Software, Version 15.2(4)M5
advertisement version: 2
Management address(es):
  IP address: 10.0.34.1
"""
    records, warnings = parse_show_cdp_neighbors_detail(text)
    record = records[0]
    assert record.ip_addresses == ["10.0.32.1", "10.0.34.1"]
    assert record.entry_addresses == ["10.0.32.1"]
    assert record.management_addresses == ["10.0.34.1"]
    assert warnings == []


def test_management_section_is_reset_between_blocks() -> None:
    """A management address in block 1 must not leak into block 2."""
    text = """-------------------------
Device ID: R2-3.nettwin.lab
Entry address(es):
Platform: Linux Uni,  Capabilities: Router
Interface: Ethernet0/0,  Port ID (outgoing port): Ethernet0/1
Holdtime : 148 sec
advertisement version: 2
Management address(es):
  IP address: 10.0.34.1

-------------------------
Device ID: R2-9.nettwin.lab
Entry address(es):
  IP address: 10.0.99.1
Platform: Linux Uni,  Capabilities: Router
Interface: Ethernet0/0,  Port ID (outgoing port): Ethernet0/2
Holdtime : 120 sec
"""
    records, _ = parse_show_cdp_neighbors_detail(text)
    assert _neighbour(records, "R2-3").management_addresses == ["10.0.34.1"]
    second = _neighbour(records, "R2-9")
    assert second.entry_addresses == ["10.0.99.1"]
    assert second.management_addresses == [], "section leaked across blocks"


def test_neighbour_with_no_address_at_all_still_warns() -> None:
    """Safety: a genuinely address-less neighbour must still be flagged.

    The fix must not turn "no address" into a silent guess.
    """
    text = """-------------------------
Device ID: R2-7.nettwin.lab
Entry address(es):
Platform: Linux Uni,  Capabilities: Router
Interface: Ethernet0/0,  Port ID (outgoing port): Ethernet0/1
Holdtime : 148 sec
"""
    records, warnings = parse_show_cdp_neighbors_detail(text)
    assert records[0].ip_addresses == []
    assert any("no IP address" in warning for warning in warnings)


@pytest.mark.parametrize(
    ("text", "expected_ip"),
    [
        ("  IP address: 10.0.32.1\n", "10.0.32.1"),
        ("  IP address: 10.0.34.1\n", "10.0.34.1"),
    ],
)
def test_entry_and_management_forms_are_extracted(text: str, expected_ip: str) -> None:
    """Requirement 2: extraction works from both sections."""
    block = (
        "Device ID: R2-3.nettwin.lab\n"
        "Entry address(es):\n"
        "Platform: Linux Uni,  Capabilities: Router\n"
        "Version :\n"
        "Cisco IOS Software, Version 15.2(4)M5\n"
        "advertisement version: 2\n"
        "Management address(es):\n" + text
    )
    records, _ = parse_show_cdp_neighbors_detail(block)
    assert records[0].ip_addresses == [expected_ip]
