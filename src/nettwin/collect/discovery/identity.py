"""Device and interface name normalization (Phase 2.2, Tasks 4 and 5).

Both normalizers are **lossless and exact**: they fold case and whitespace and
expand a fixed table of IOS interface abbreviations, but they never do
substring or fuzzy matching. Every normalization that could be read two ways
is surfaced as an ambiguity by the indexes at the bottom of this module, not
resolved silently.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# --------------------------------------------------------------------------- #
# Interface names (Task 5)
# --------------------------------------------------------------------------- #

#: IOS abbreviations -> canonical long form. Only *documented* IOS
#: abbreviations appear here; anything else is left alone rather than guessed.
_INTERFACE_ABBREVIATIONS: dict[str, str] = {
    "eth": "ethernet",
    "ethernet": "ethernet",
    "et": "ethernet",
    "fa": "fastethernet",
    "fast": "fastethernet",
    "fastethernet": "fastethernet",
    "gi": "gigabitethernet",
    "gig": "gigabitethernet",
    "gige": "gigabitethernet",
    "gigabitethernet": "gigabitethernet",
    "te": "tengigabitethernet",
    "ten": "tengigabitethernet",
    "tengig": "tengigabitethernet",
    "tengigabitethernet": "tengigabitethernet",
    "fo": "fortygigabitethernet",
    "forty": "fortygigabitethernet",
    "fortygigabitethernet": "fortygigabitethernet",
    "hu": "hundredgigeethernet",
    "hundredgigeethernet": "hundredgigeethernet",
    "lo": "loopback",
    "loopback": "loopback",
    "vl": "vlan",
    "vlan": "vlan",
    "se": "serial",
    "serial": "serial",
    "po": "port-channel",
    "port-channel": "port-channel",
    "portchannel": "port-channel",
    "mgmt": "management",
    "management": "management",
    "tu": "tunnel",
    "tunnel": "tunnel",
}

#: Long forms with their canonical display casing.
_CANONICAL_DISPLAY: dict[str, str] = {
    "ethernet": "Ethernet",
    "fastethernet": "FastEthernet",
    "gigabitethernet": "GigabitEthernet",
    "tengigabitethernet": "TenGigabitEthernet",
    "fortygigabitethernet": "FortyGigabitEthernet",
    "hundredgigeethernet": "HundredGigE",
    "loopback": "Loopback",
    "vlan": "Vlan",
    "serial": "Serial",
    "port-channel": "Port-Channel",
    "management": "Management",
    "tunnel": "Tunnel",
}


def split_interface_name(raw: str) -> tuple[str, str]:
    """Split ``"Eth 0/0"`` / ``"Ethernet0/0"`` into ``("eth", "0/0")``.

    The numeric part is everything from the first digit onwards, including
    sub-interfaces (``0/0.100``), channel groups (``0/0/1``), and optional
    suffixes (``0/0a``). The type part keeps its original characters, case
    folded, tokens joined without spaces.
    """
    text = " ".join(raw.split())
    for index, char in enumerate(text):
        if char.isdigit():
            return text[:index].strip().lower().replace(" ", ""), text[index:].strip()
    return text.lower().replace(" ", ""), ""


def normalize_interface_key(raw: str) -> str:
    """Return a canonical comparison key for an IOS interface name.

    ``"Eth 0/0"``, ``"eth0/0"``, ``"Ethernet 0/0"`` and ``"Ethernet0/0"`` all
    map to ``"ethernet0/0"``. An unknown type is preserved verbatim (lower
    cased) instead of being coerced into a known one — the interface then
    simply will not match anything, which is the honest outcome.

    >>> normalize_interface_key("Eth 0/0")
    'ethernet0/0'
    >>> normalize_interface_key("Gi0/1")
    'gigabitethernet0/1'
    """
    type_part, number = split_interface_name(raw)
    canonical = _INTERFACE_ABBREVIATIONS.get(type_part)
    if canonical is None:
        # Unknown prefix: fall back to the compacted original so that two
        # identical strings still match each other.
        return f"{type_part}{number}".replace(" ", "").lower()
    return f"{canonical}{number}"


def canonical_interface_display(raw: str) -> str:
    """Display form matching the domain model's existing interface names.

    ``"Eth 0/0"`` -> ``"Ethernet0/0"``. Unknown prefixes are returned compacted
    and unchanged in case, never renamed.
    """
    type_part, number = split_interface_name(raw)
    canonical = _INTERFACE_ABBREVIATIONS.get(type_part)
    if canonical is None:
        return f"{raw.strip().replace(' ', '')}"
    return f"{_CANONICAL_DISPLAY.get(canonical, canonical)}{number}"


def interface_is_subinterface(raw: str) -> bool:
    """True when the numeric part contains a dot (IOS sub-interface)."""
    _, number = split_interface_name(raw)
    return "." in number


def interface_parent_key(raw: str) -> str:
    """Parent interface key for a sub-interface (``0/0.100`` -> ``0/0``)."""
    type_part, number = split_interface_name(raw)
    parent = number.split(".", 1)[0]
    return normalize_interface_key(f"{type_part}{parent}")


# --------------------------------------------------------------------------- #
# Device names (Task 4)
# --------------------------------------------------------------------------- #


def normalize_device_key(raw: str) -> str:
    """Canonical, case-insensitive comparison key for a device name.

    Folds surrounding/interior whitespace and case **only**. The domain suffix
    (``.nettwin.lab``) is deliberately *kept*: stripping it is a second,
    separate normalization step (:func:`device_match_keys`) that is only
    applied when the short form is unique in the collected set.

    >>> normalize_device_key("  R2-2.Nettwin.LAB ")
    'r2-2.nettwin.lab'
    """
    return "".join(raw.split()).lower()


def device_match_keys(raw: str) -> tuple[list[str], str | None]:
    """Return ``(keys_in_priority_order, short_key_or_None)``.

    The first key is the full normalized name; the second (when the name has a
    domain suffix) is the short hostname. Callers must try the full key first
    and fall back to the short key **only** if it identifies exactly one
    collected device.

    >>> device_match_keys("R2-2.nettwin.lab")
    (['r2-2.nettwin.lab', 'r2-2'], 'r2-2')
    >>> device_match_keys("R2-2")
    (['r2-2'], None)
    """
    full = normalize_device_key(raw)
    if "." not in full:
        return [full], None
    short = full.split(".", 1)[0]
    if not short:
        return [full], None
    return [full, short], short


# --------------------------------------------------------------------------- #
# Ambiguity-aware indexes
# --------------------------------------------------------------------------- #


@dataclass
class DeviceNameIndex:
    """Map normalized device names to collected device ids, tracking ambiguity.

    A name that would resolve to more than one collected device is *ambiguous*
    and never resolves to an arbitrary member.
    """

    full: dict[str, set[str]] = field(default_factory=dict)
    short: dict[str, set[str]] = field(default_factory=dict)

    def add(self, device_id: str, *names: str) -> None:
        """Register ``device_id`` under every given name (hostname, FQDN, …).

        Both indexes are always populated: a bare hostname registers its only
        key as *both* the full key and the short key, so an incoming FQDN can
        still find it by hostname. The short index is what makes ambiguity
        detectable — two devices sharing ``r2-2`` under different domains fill
        the same short bucket and neither can win.
        """
        for name in names:
            if not name:
                continue
            keys, short = device_match_keys(name)
            self.full.setdefault(keys[0], set()).add(device_id)
            if short:
                self.short.setdefault(short, set()).add(device_id)
            else:
                # Bare name: it also serves as the short (hostname-only) key.
                self.short.setdefault(keys[0], set()).add(device_id)

    def resolve(self, name: str) -> tuple[str | None, str]:
        """Resolve ``name`` to a collected device id.

        Returns ``(device_id, note)``. ``device_id`` is ``None`` when the name
        matches nothing or matches more than one device; ``note`` always
        explains which case applied.
        """
        keys, short = device_match_keys(name)
        full_hits = self.full.get(keys[0], set())
        if len(full_hits) == 1:
            return next(iter(full_hits)), f"{name!r} matched collected device by full name"
        if len(full_hits) > 1:
            return None, (
                f"{name!r} is ambiguous: full-name key {keys[0]!r} matches "
                f"{len(full_hits)} collected devices ({', '.join(sorted(full_hits))})"
            )
        # A bare query ("R2-2") has no suffix of its own, but collected devices
        # may be registered under FQDNs: consult the short index as well so two
        # devices sharing that hostname are reported instead of missed.
        short_key = short if short is not None else keys[0]
        short_hits = self.short.get(short_key, set())
        if len(short_hits) == 1:
            return next(iter(short_hits)), (
                f"{name!r} matched collected device by hostname without domain suffix"
            )
        if len(short_hits) > 1:
            return None, (
                f"{name!r} is ambiguous: hostname {short_key!r} matches "
                f"{len(short_hits)} collected devices ({', '.join(sorted(short_hits))})"
            )
        return None, f"{name!r} does not match any collected device (no suffix guessing)"


@dataclass
class InterfaceNameIndex:
    """Map normalized interface keys to interface ids **within one device**."""

    keys: dict[str, set[str]] = field(default_factory=dict)
    names: dict[str, str] = field(default_factory=dict)  # interface_id -> real name

    @classmethod
    def from_interfaces(cls, items: list[tuple[str, str]]) -> InterfaceNameIndex:
        """Build from ``(interface_id, interface_name)`` pairs of one device."""
        index = cls()
        for interface_id, name in items:
            index.add(interface_id, name)
        return index

    def add(self, interface_id: str, name: str) -> None:
        self.keys.setdefault(normalize_interface_key(name), set()).add(interface_id)
        self.names[interface_id] = name

    def resolve(self, raw_name: str) -> tuple[str | None, str]:
        """Resolve a CDP interface name to exactly one interface id, or ``None``."""
        key = normalize_interface_key(raw_name)
        hits = self.keys.get(key, set())
        if len(hits) == 1:
            return next(iter(hits)), f"{raw_name!r} -> interface {next(iter(hits))!r}"
        if len(hits) > 1:
            return None, (
                f"{raw_name!r} is ambiguous: key {key!r} matches "
                f"{len(hits)} interfaces ({', '.join(sorted(hits))})"
            )
        return None, f"{raw_name!r} matches no collected interface (key {key!r})"
