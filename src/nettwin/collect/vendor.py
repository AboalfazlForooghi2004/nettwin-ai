"""Vendor detection and the read-only command set per vendor (Phase 2.5).

The recursive walk reaches a device knowing only that it speaks SSH. This
module answers two questions from evidence that is already in hand:

1. **Who is this?** — ``detect_vendor`` reads the *identity* command output and
   returns a ``VendorProfile``. Detection is positive-evidence only: a device is
   a Cisco because IOS says so, a FortiGate because FortiOS says so. Anything
   else is ``unknown`` and stays ``unknown``.
2. **What may we read?** — each profile carries its own frozen command tuple,
   so the FortiOS command set can never be dispatched to an IOS box (or the
   reverse), and unknown vendors get nothing at all.

Safety rules enforced here:

* the Cisco allowlist in :mod:`nettwin.collect.cisco_ios` is untouched;
* every FortiOS command is a ``get`` (never ``config``/``execute``/``diagnose``);
* a command that appears in neither profile is rejected before connecting;
* an unrecognised vendor raises nothing and breaks nothing — it simply yields
  no commands, and discovery continues with the other devices.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

CISCO_IOS_VENDOR = "cisco_ios"
FORTIGATE_VENDOR = "fortigate_fortios"
UNKNOWN_VENDOR = "unknown"

# --------------------------------------------------------------------------- #
# Cisco IOS
# --------------------------------------------------------------------------- #

#: Verbatim copy of the phase-2 IOS allowlist, re-exported so callers can work
#: through one interface. ``cisco_ios.READ_ONLY_COMMANDS`` remains the source of
#: truth and a test asserts the two stay identical.
CISCO_IOS_COMMANDS: tuple[str, ...] = (
    "show version",
    "show ip interface brief",
    "show ip route",
    "show ip ospf neighbor",
    "show cdp neighbors",
    "show cdp neighbors detail",
)

# --------------------------------------------------------------------------- #
# FortiGate / FortiOS — every entry verified against Fortinet documentation
# --------------------------------------------------------------------------- #

#: Read-only ``get`` commands only. ``diagnose`` is deliberately absent: it is
#: a diagnostic subsystem, not part of this project's read-only contract, and
#: FortiGate LLDP would need it (see docs/PHASE2_5_DESIGN_NOTES.md).
FORTIGATE_COMMANDS: tuple[str, ...] = (
    "get system status",
    "get system interface",
    "get router info routing-table all",
    "get system lldp neighbors",
)

#: ``get system lldp neighbors`` returns nothing unless the operator enabled
#: LLDP reception. Its emptiness is evidence about the device, never a failure.
FORTIGATE_OPTIONAL_COMMANDS: frozenset[str] = frozenset({"get system lldp neighbors"})

_FORTIGATE_FORBIDDEN_FRAGMENTS: tuple[str, ...] = (
    "config ",
    "conf ",
    "edit ",
    "set ",
    "unset ",
    "next",
    "end",
    "execute",
    "diagnose",
    "restore",
    "backup",
    "purge",
    "delete",
    "rename",
    "append",
    "clear",
    "reset",
    "shutdown",
    "reboot",
    "factoryreset",
    "exec ",
    "show full-configuration",
    "show system password",
)


@dataclass(frozen=True)
class VendorProfile:
    """What one vendor is, and what we are willing to ask it."""

    key: str
    label: str
    commands: tuple[str, ...]
    identity_command: str
    optional_commands: frozenset[str] = frozenset()

    @property
    def is_supported(self) -> bool:
        """True when this vendor has a parser and a command set."""
        return self.key in {CISCO_IOS_VENDOR, FORTIGATE_VENDOR}


CISCO_IOS_PROFILE = VendorProfile(
    key=CISCO_IOS_VENDOR,
    label="Cisco IOS / IOS-XE",
    commands=CISCO_IOS_COMMANDS,
    identity_command="show version",
)

FORTIGATE_PROFILE = VendorProfile(
    key=FORTIGATE_VENDOR,
    label="Fortinet FortiGate / FortiOS",
    commands=FORTIGATE_COMMANDS,
    identity_command="get system status",
    optional_commands=FORTIGATE_OPTIONAL_COMMANDS,
)

#: An unsupported vendor: identified, reported, asked for nothing.
UNKNOWN_PROFILE = VendorProfile(
    key=UNKNOWN_VENDOR,
    label="unknown / unsupported",
    commands=(),
    identity_command="",
)

PROFILES: dict[str, VendorProfile] = {
    CISCO_IOS_VENDOR: CISCO_IOS_PROFILE,
    FORTIGATE_VENDOR: FORTIGATE_PROFILE,
    UNKNOWN_VENDOR: UNKNOWN_PROFILE,
}


# --------------------------------------------------------------------------- #
# Detection
# --------------------------------------------------------------------------- #

_CISCO_MARKERS = (
    re.compile(r"Cisco IOS(?:[- ]XE)? Software", re.IGNORECASE),
    re.compile(r"^Cisco IOS XE Software", re.IGNORECASE | re.MULTILINE),
    re.compile(r"Cisco Internetwork Operating System", re.IGNORECASE),
    re.compile(r"^cisco\s+\S+\s+\(.*\)\s+processor", re.IGNORECASE | re.MULTILINE),
)

#: ``Version: FortiGate-100F v7.4.4,build2662,240514 (GA)`` and friends.
_FORTIOS_MARKER = re.compile(
    r"^Version:\s*Forti(?:Gate|WiFi|Switch|AP|Mail|Web|Proxy|Manager|Analyzer|SIEM)"
    r"(?:[\w\-]*)\s+v\d",
    re.IGNORECASE | re.MULTILINE,
)
_FORTIOS_WEAK_MARKER = re.compile(
    r"^(?:Serial-Number|Current virtual domain|Operation Mode):",
    re.IGNORECASE | re.MULTILINE,
)


@dataclass
class DetectionResult:
    """Outcome of looking at one device's identity output."""

    profile: VendorProfile
    evidence: str
    """The line that decided it, kept for the run report."""
    ambiguous: bool = False
    """True when more than one vendor's markers matched."""


def detect_vendor(identity_output: str) -> DetectionResult:
    """Identify a device from its identity-command output.

    Order matters: a positive FortiOS ``Version:`` line wins, because on some
    platforms a banner can echo vendor strings. Ties are reported as
    ``ambiguous`` and downgraded to ``unknown`` rather than guessed.
    """
    text = identity_output or ""
    if not text.strip():
        return DetectionResult(
            profile=UNKNOWN_PROFILE,
            evidence="identity output empty — vendor not established",
        )

    fortios_match = _FORTIOS_MARKER.search(text)
    cisco_match = None
    for pattern in _CISCO_MARKERS:
        cisco_match = pattern.search(text)
        if cisco_match:
            break

    if fortios_match and cisco_match:
        return DetectionResult(
            profile=UNKNOWN_PROFILE,
            evidence=(
                "both FortiOS and IOS markers present "
                f"({fortios_match.group(0).strip()!r} / {cisco_match.group(0).strip()!r}) "
                "— not guessing"
            ),
            ambiguous=True,
        )

    if fortios_match:
        return DetectionResult(
            profile=FORTIGATE_PROFILE,
            evidence=fortios_match.group(0).strip(),
        )

    if cisco_match:
        return DetectionResult(
            profile=CISCO_IOS_PROFILE,
            evidence=cisco_match.group(0).strip(),
        )

    if _FORTIOS_WEAK_MARKER.search(text):
        return DetectionResult(
            profile=FORTIGATE_PROFILE,
            evidence="FortiOS key/value markers present, no Version line",
        )

    return DetectionResult(
        profile=UNKNOWN_PROFILE,
        evidence="no recognized vendor marker in identity output",
    )


# --------------------------------------------------------------------------- #
# Validation
# --------------------------------------------------------------------------- #

class VendorCommandError(ValueError):
    """A command was dispatched to the wrong vendor, or is not read-only."""


def validate_command(profile: VendorProfile, command: str) -> None:
    """Reject anything that is not in *this* vendor's read-only set.

    Called before any command is sent. Raises :class:`VendorCommandError`.
    """
    normalized = " ".join(command.strip().lower().split())
    allowed = {" ".join(c.strip().lower().split()) for c in profile.commands}
    if normalized not in allowed:
        raise VendorCommandError(
            f"command {command!r} is not in the read-only {profile.key} allowlist "
            "(rejected before dispatch)"
        )
    if profile.key == FORTIGATE_VENDOR:
        for fragment in _FORTIGATE_FORBIDDEN_FRAGMENTS:
            if normalized.startswith(fragment) or f" {fragment}" in normalized:
                raise VendorCommandError(
                    f"command {command!r} contains forbidden fragment {fragment!r} "
                    "(rejected before dispatch)"
                )
        if not normalized.startswith("get "):
            raise VendorCommandError(
                f"FortiOS commands must be read-only 'get' commands: {command!r}"
            )


def command_set_for(vendor_key: str) -> tuple[str, ...]:
    """The ordered read-only command tuple for a vendor key."""
    return PROFILES.get(vendor_key, UNKNOWN_PROFILE).commands
