"""OSPF LSDB → logical topology reconstruction (Phase 2.6).

Takes the parsed LSDB of one or more devices and reconstructs:

* OSPF routers (by Router ID),
* **transit networks as first-class nodes** with their membership,
* stub networks as prefixes owned by a router,
* point-to-point logical edges, only where genuinely reciprocal.

The central rule, stated once: **a transit network is a node, not an edge.** A
multi-access segment with five routers produces one ``OspfTransitNetwork`` with
five members. It never produces ten router-to-router edges, and it never
produces a :class:`nettwin.domain.models.Link` — that type is reserved for
layer-2 adjacency confirmed by CDP.

Every derived object carries ``source_lsas`` and an explicit
:class:`OspfEvidenceState`, and conflicting evidence is reported rather than
resolved silently.
"""

from __future__ import annotations

import ipaddress
from collections import defaultdict
from dataclasses import dataclass, field

from nettwin.domain.models import Topology
from nettwin.domain.ospf_models import (
    OspfCdpRelation,
    OspfCorrelation,
    OspfEvidenceState,
    OspfInstance,
    OspfInterface,
    OspfLinkType,
    OspfLogicalEdge,
    OspfLsaRef,
    OspfLsaSummary,
    OspfNeighbor,
    OspfNetworkLsa,
    OspfRoute,
    OspfRouter,
    OspfRouterLsa,
    OspfStubNetwork,
    OspfTopology,
    OspfTransitNetwork,
)

#: Command names used as evidence tags, matching what was actually dispatched.
EV_ROUTER_LSA = "ospf-router-lsa"
EV_NETWORK_LSA = "ospf-network-lsa"
EV_NEIGHBOR = "ospf-neighbor"
EV_ROUTE = "ospf-route"


@dataclass
class OspfDeviceData:
    """Everything one device contributed, before cross-device reconstruction."""

    device_id: str
    process_id: str = ""
    router_id: str = ""
    neighbors: list[OspfNeighbor] = field(default_factory=list)
    interfaces: list[OspfInterface] = field(default_factory=list)
    database_summary: list[OspfLsaSummary] = field(default_factory=list)
    router_lsas: list[OspfRouterLsa] = field(default_factory=list)
    network_lsas: list[OspfNetworkLsa] = field(default_factory=list)
    routes: list[OspfRoute] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def _prefix_or_none(address: str, mask: str) -> str | None:
    try:
        return str(ipaddress.ip_network(f"{address}/{mask}", strict=False))
    except ValueError:
        return None


def _contains(prefix: str | None, address: str) -> bool:
    if not prefix or not address:
        return False
    try:
        return ipaddress.ip_address(address) in ipaddress.ip_network(prefix, strict=False)
    except ValueError:
        return False


def _lsa_ref(lsa: OspfRouterLsa | OspfNetworkLsa, lsa_type: int) -> OspfLsaRef:
    return OspfLsaRef(
        device_id=lsa.device_id or "unknown",
        area=lsa.area,
        lsa_type=lsa_type,
        link_state_id=lsa.link_state_id or "unknown",
        advertising_router=lsa.advertising_router or "unknown",
        sequence=lsa.sequence,
        checksum=lsa.checksum,
        age=lsa.age,
        command=lsa.command,
    )


# --------------------------------------------------------------------------- #
# Type 3: transit network correlation
# --------------------------------------------------------------------------- #


# --------------------------------------------------------------------------- #
# Canonical LSDB
# --------------------------------------------------------------------------- #
#
# An OSPF area is flooded, so every router in it holds every LSA. Five collected
# routers therefore hand us five *copies* of each of the five Router LSAs and
# five copies of each Network LSA — 25 records for 5 real LSAs. Treating a
# record as an LSA multiplies the topology by the number of observers.
#
# The fix is a canonicalisation layer: an LSA's *identity* is
# ``(area, ls_type, link_state_id, advertising_router)`` — exactly the OSPF LSA
# identity — and the devices that reported it are a separate axis of the model,
# kept in ``observed_by``. Nothing is thrown away; the copies collapse, the
# provenance does not.


@dataclass(frozen=True)
class LsaIdentity:
    """The identity of an LSA within its area (its "name" in the LSDB)."""

    area: str
    lsa_type: int
    link_state_id: str
    advertising_router: str

    def describe(self) -> str:
        return (
            f"Type {self.lsa_type} LSID {self.link_state_id} "
            f"adv {self.advertising_router} area {self.area}"
        )


# --------------------------------------------------------------------------- #
# OSPF protocol constants (RFC 2328)
# --------------------------------------------------------------------------- #

LS_SEQUENCE_INITIAL = 0x80000001
"""RFC 2328 §12.1.6: sequence numbers start here and the space is *signed*."""

LS_SEQUENCE_MAX = 0x7FFFFFFF
"""The largest valid LS sequence number (``0x7FFFFFFF``)."""

LS_SEQUENCE_RESERVED = 0x80000000
"""Reserved (``0x80000000``) — never a valid sequence number."""

LS_AGE_MAX = 3600
"""MaxAge in seconds (RFC 2328 §12.1.1 / §A.3)."""

MAX_AGE_DIFF = 900
"""MaxAgeDiff in seconds (RFC 2328 §12.1.1)."""


def parse_ls_sequence(sequence: str) -> int | None:
    """Parse an LS sequence number as the **signed** 32-bit value of RFC 2328 §12.1.6.

    Sequence numbers live in the signed space that begins at ``0x80000001`` and
    runs up through ``0x7FFFFFFF``. Interpreted as unsigned, the ordering is
    wrong across the boundary that wraps through the reserved value
    ``0x80000000``:

    * ``0x80000001`` → ``-2147483647`` (the *oldest* valid sequence)
    * ``0x80000009`` → ``-2147483639``
    * ``0x7FFFFFFF`` → ``2147483647`` (the *newest* valid sequence)

    so ``0x7FFFFFFF`` must compare as newer than ``0x80000001``, which the
    unsigned form gets backwards.

    IOS prints the sequence **without** an ``0x`` prefix (``LS Seq Number:
    80000002``) while checksums carry one, so both spellings are accepted, in
    either case. ``None`` is returned for anything that is not a usable
    sequence: empty, malformed, or out of the signed 32-bit range.
    """
    text = (sequence or "").strip()
    if text.lower().startswith("0x"):
        text = text[2:]
    if not text or len(text) > 8:
        return None
    try:
        unsigned = int(text, 16)
    except ValueError:
        return None
    if not 0 <= unsigned <= 0xFFFFFFFF:
        return None
    # Two's complement, signed 32-bit: the representation RFC 2328 §12.1.6 uses.
    return unsigned - (1 << 32) if unsigned & 0x80000000 else unsigned


def is_valid_ls_sequence(value: int | None) -> bool:
    """Is ``value`` a sequence number an LSA may legitimately carry?

    ``0x80000000`` is reserved, so ``-2147483648`` is not a valid instance.
    """
    return value is not None and value != -(1 << 31) and -2147483647 <= value <= 2147483647


def parse_ls_checksum(checksum: str) -> int | None:
    """Parse an LS checksum as an **unsigned 16-bit** integer.

    IOS reports checksums as ``0x5E6F``. They are compared numerically, never
    as strings: ``"0x0E6F"`` is numerically smaller than ``"0x1A2B"``, but
    lexicographically *larger*, so string comparison silently picks the wrong
    instance.
    """
    text = (checksum or "").strip()
    if text.lower().startswith("0x"):
        text = text[2:]
    if not text or len(text) > 4:
        return None
    try:
        value = int(text, 16)
    except ValueError:
        return None
    return value if 0 < value <= 0xFFFF else None


def is_valid_ls_checksum(value: int | None) -> bool:
    """Is ``value`` a usable LS checksum?

    RFC 2328 §§12.1.7 and 13.1: the checksum is an unsigned 16-bit field
    computed with the Fletcher algorithm over the LSA. **Zero is not a
    checksum** — a Fletcher checksum of a real LSA cannot be 0, so ``0x0000``
    means the field was absent, mistranscribed or the LSA is corrupt. Accepting
    it would let malformed metadata act as the tie-break that decides which
    instance is canonical.
    """
    return isinstance(value, int) and not isinstance(value, bool) and 0 < value <= 0xFFFF


def same_lsa_version(
    first: OspfRouterLsa | OspfNetworkLsa,
    second: OspfRouterLsa | OspfNetworkLsa,
) -> bool:
    """Do two copies claim to be the *same instance* of an LSA?

    Compared on parsed values, not on the reported strings: IOS prints the
    sequence without an ``0x`` prefix and the checksum with one, and observers
    may disagree about case or padding. ``"0x80000002"``/``"0x5E6F"`` and
    ``"80000002"``/``"5e6f"`` are the same version; a raw string comparison
    would call them a conflict.

    Two unusable metadata pairs are *not* assumed identical — nothing
    establishes that they match.
    """
    sequence_a = parse_ls_sequence(first.sequence)
    sequence_b = parse_ls_sequence(second.sequence)
    if sequence_a is None or sequence_b is None:
        return False
    if sequence_a != sequence_b:
        return False
    checksum_a = parse_ls_checksum(first.checksum)
    checksum_b = parse_ls_checksum(second.checksum)
    if checksum_a is None or checksum_b is None:
        return False
    return checksum_a == checksum_b


def parse_ls_age(age: object) -> int | None:
    """Validate an LS age, returning ``None`` when it is not usable evidence.

    RFC 2328 §12.1.1 defines LS age as a 16-bit *unsigned* seconds counter that
    saturates at ``MaxAge`` (3600); a value outside ``0..3600`` cannot have come
    from a conforming LSDB.

    Validation is deliberately strict, because every lenient behaviour here
    would narrow to "a number appeared, so the instances must agree":

    * ``bool`` is **rejected** even though it is an ``int`` subclass — ``True``
      would otherwise silently become age 1, which is a real, young age;
    * ``float`` is **rejected** rather than truncated — ``1418.7`` is not an
      age, and rounding it invents precision the device never reported;
    * numeric *strings* are **rejected** rather than coerced — the parser has
      already converted the transcript, so a string here means a caller bypassed
      it and the value's provenance is unknown;
    * ``None`` and anything else non-integer is rejected.

    Nothing is clamped. ``5000`` is not "MaxAge-ish", it is malformed, and
    clamping it to 3600 would manufacture a MaxAge claim the LSA never made.
    """
    if isinstance(age, bool) or not isinstance(age, int):
        return None
    if age < 0 or age > LS_AGE_MAX:
        return None
    return age


def is_valid_ls_age(age: object) -> bool:
    """Is ``age`` a usable LS age (0..MaxAge, a genuine integer)?"""
    return parse_ls_age(age) is not None


@dataclass(frozen=True)
class LsaInstanceComparison:
    """The outcome of comparing two instances of one LSA identity.

    ``winner`` is ``None`` when the available metadata cannot establish a
    protocol-correct winner. That happens when the sequence numbers are
    unusable: RFC 2328 §13.1 decides between instances *first* on the sequence
    number, so with no trustworthy sequence number there is no defensible
    answer, and an arbitrary pick would be a guess dressed up as evidence.
    """

    winner: OspfRouterLsa | OspfNetworkLsa | None
    reason: str
    """Why the winner won, in protocol terms — carried into the warning text."""

    undecided: bool = False
    """True when no protocol-correct winner could be established."""


def _identical(
    first: OspfRouterLsa | OspfNetworkLsa,
    second: OspfRouterLsa | OspfNetworkLsa,
    age_a: int,
    age_b: int,
) -> LsaInstanceComparison:
    """The two copies are the same instance, and that was *verified*.

    Takes both validated ages as arguments so "identical" can only be claimed
    by a caller that actually established it. The previous signature accepted a
    free-text reason and no age at all, which let unusable metadata fall
    through to a confident "the sequence, checksum and age agree".
    """
    spread = abs(age_a - age_b)
    return LsaInstanceComparison(
        winner=first,
        reason=(
            f"identical instance (sequence and checksum match; ages {age_a} and "
            f"{age_b} are within MaxAgeDiff {MAX_AGE_DIFF}, spread {spread}s)"
        ),
    )


def compare_lsa_instances(
    first: OspfRouterLsa | OspfNetworkLsa,
    second: OspfRouterLsa | OspfNetworkLsa,
) -> LsaInstanceComparison:
    """Compare two instances of the same LSA by RFC 2328 §13.1, in order.

    The order is **not** negotiable, and in particular checksum precedes age:

    1. **Higher signed LS sequence number wins** (§12.1.6 signed space).
    2. Sequence equal → **higher LS checksum wins**, as an unsigned 16-bit
       integer. A checksum difference always means a different instance, so
       age is never consulted next.
    3. Sequence and checksum equal → an instance with ``LS age == MaxAge``
       wins. MaxAge means "being flushed"; the MaxAge copy is the authoritative
       statement that the LSA is going away.
    4. Otherwise, if ``abs(age1 - age2) > MaxAgeDiff``, the **younger** (lower
       age) instance wins — aging is the only remaining discriminator.
    5. Otherwise they are the same instance.

    ``first`` is returned as the winner of a tie, so the result is stable
    across observers.
    """
    sequence_a = parse_ls_sequence(first.sequence)
    sequence_b = parse_ls_sequence(second.sequence)

    if not is_valid_ls_sequence(sequence_a) or not is_valid_ls_sequence(sequence_b):
        # No defensible ordering exists without a usable sequence number.
        return LsaInstanceComparison(
            winner=None,
            reason=(
                "unresolved: a usable LS sequence number is missing or invalid "
                f"(observers report {first.sequence or 'absent'!r} and "
                f"{second.sequence or 'absent'!r}); RFC 2328 §13.1 orders "
                "instances on the sequence number first, so no protocol-correct "
                "newest instance can be established"
            ),
            undecided=True,
        )

    assert sequence_a is not None and sequence_b is not None  # narrowed above
    if sequence_a != sequence_b:
        if sequence_a > sequence_b:
            return LsaInstanceComparison(
                winner=first, reason=f"higher LS sequence number ({sequence_a})"
            )
        return LsaInstanceComparison(
            winner=second, reason=f"higher LS sequence number ({sequence_b})"
        )

    checksum_a = parse_ls_checksum(first.checksum)
    checksum_b = parse_ls_checksum(second.checksum)

    if not is_valid_ls_checksum(checksum_a) or not is_valid_ls_checksum(checksum_b):
        return LsaInstanceComparison(
            winner=None,
            reason=(
                "unresolved: the LS sequence numbers match but an LS checksum is "
                f"missing or malformed (observers report {first.checksum or 'absent'!r} "
                f"and {second.checksum or 'absent'!r}); RFC 2328 §13.1 orders equal "
                "sequences on the checksum, so no protocol-correct newest instance "
                "can be established"
            ),
            undecided=True,
        )

    assert checksum_a is not None and checksum_b is not None
    if checksum_a != checksum_b:
        if checksum_a > checksum_b:
            return LsaInstanceComparison(
                winner=first,
                reason=f"same sequence, higher checksum (0x{checksum_a:04X})",
            )
        return LsaInstanceComparison(
            winner=second,
            reason=f"same sequence, higher checksum (0x{checksum_b:04X})",
        )

    # Sequence and checksum agree: the same LSA body, differing only in age.
    # Both ages must now be *validated* before age can decide anything.
    age_a = parse_ls_age(first.age)
    age_b = parse_ls_age(second.age)

    if age_a is None or age_b is None:
        return LsaInstanceComparison(
            winner=None,
            reason=(
                "unresolved: the LS sequence numbers and checksums match, so only "
                "LS Age can distinguish these copies, but an age is missing or "
                "invalid (observers report "
                f"{first.age!r} and {second.age!r}; a valid age is an integer in "
                f"0..{LS_AGE_MAX})"
            ),
            undecided=True,
        )

    # MaxAge is authoritative: it states the LSA is being flushed. It may only
    # be compared against a *known* age, which the check above guarantees.
    if age_a == LS_AGE_MAX and age_b != LS_AGE_MAX:
        return LsaInstanceComparison(winner=first, reason="MaxAge instance wins")
    if age_b == LS_AGE_MAX and age_a != LS_AGE_MAX:
        return LsaInstanceComparison(winner=second, reason="MaxAge instance wins")

    if age_a != age_b and abs(age_a - age_b) > MAX_AGE_DIFF:
        if age_a < age_b:
            return LsaInstanceComparison(
                winner=first,
                reason=f"younger instance (age {age_a} vs {age_b}, exceeds MaxAgeDiff)",
            )
        return LsaInstanceComparison(
            winner=second,
            reason=f"younger instance (age {age_b} vs {age_a}, exceeds MaxAgeDiff)",
        )

    return _identical(first, second, age_a, age_b)


def _single_version(copies: list[OspfRouterLsa] | list[OspfNetworkLsa]) -> bool:
    """Do all copies agree that they are the same instance version?

    Used to decide whether observers are reporting *different versions* of an
    LSA or *the same version* with different content. Comparison is on parsed
    sequence/checksum, so formatting differences are not mistaken for conflicts.
    """
    if len(copies) < 2:
        return True
    reference = copies[0]
    return all(same_lsa_version(reference, other) for other in copies[1:])


def _normalised_options(options: str) -> str:
    """Canonical, **order-independent** form of an LSA Options field.

    RFC 2328 §12.1.2 defines the Options field as a set of bits. IOS renders
    those bits as prose, and the rendering varies in ways that do not change the
    bitmask:

    * decoration — ``(No TOS-capability, DC)`` and ``No TOS-capability, DC``
      both appear in the reference transcript;
    * **order** — ``(DC, E-bit)`` and ``(E-bit, DC)`` are the same bits;
    * case and spacing.

    Comparing the rendered text verbatim would therefore report a content
    difference where the LSA content is identical, which is exactly the false
    conflict the fingerprint exists to avoid. So the comparison form lowercases,
    splits on commas, strips decoration and whitespace, and **sorts what is
    left** — a set, not a sequence *and not a multiset*.

    Deduplication is part of that, not a detail: ``(DC, DC)`` and ``(DC)``
    describe the same bit. Sorting alone would keep both copies and report a
    false content difference, so tokens are folded into a **set** (case-
    insensitively, since ``DC`` and ``dc`` are the same bit) before sorting.
    Empty tokens — a trailing comma, ``()``, a blank field — carry no bit at all
    and are dropped.

    Unknown tokens are *kept*: this function normalises rendering, it does not
    whitelist vocabulary. A bit it has never seen still distinguishes one LSA
    from another, so discarding it would merge genuinely different instances.

    Only the comparison form is normalised: the model stores the field exactly
    as reported, so nothing is lost from the evidence. An empty value stays
    empty, which is what a transcript without an ``Options:`` line yields.

    Known limit, stated rather than hidden: two *different* bit combinations
    that render to the same words would compare equal. IOS emits distinct
    phrases for distinct bits (``DC``, ``E-bit``, ``No TOS-capability``, ``TOS``),
    so this does not arise in practice, but the bitmask itself is not parsed.
    """
    text = " ".join((options or "").split())
    if text.startswith("(") and text.endswith(")"):
        text = text[1:-1].strip()
    tokens = {token.strip().lower() for token in text.split(",")}
    tokens.discard("")
    return ",".join(sorted(tokens))


def lsa_content_fingerprint(
    lsa: OspfRouterLsa | OspfNetworkLsa,
) -> tuple[object, ...]:
    """A comparable fingerprint of an LSA's **body**, excluding LS Age.

    RFC 2328 §13.2 lists what makes two LSAs different instances: a change in
    Options, a change in the LS type, a change in LSA length, or a change in the
    LSA body. Everything the type can carry is therefore included:

    * **Router LSA** — Options, ``Length``, the advertised link count, and every
      link's type, Link ID, Link Data, mask, metric and MTID.
    * **Network LSA** — Options, ``Length``, the network mask and the complete
      attached-router list.

    Two fields are deliberately **excluded**:

    * **LS Age** — ageing is a transport property; two copies of one instance
      legitimately differ only in how long each router has held them. Treating
      age as content would make every flooded copy a conflict.
    * **Observer metadata** — ``device_id``, ``command``, ``observed_by`` and
      ``observed_instances`` describe *who looked*, not *what was seen*.

    ``number_of_links`` is included even though it is redundant with ``links``:
    it is the LSA's own claim about its size, and a transcript whose declared
    count disagrees with its printed links is a real inconsistency worth
    surfacing rather than silently reconciling.
    """
    if isinstance(lsa, OspfNetworkLsa):
        return (
            "network",
            _normalised_options(lsa.options),
            lsa.ls_length,
            lsa.network_mask,
            tuple(sorted(lsa.attached_routers)),
        )
    return (
        "router",
        _normalised_options(lsa.options),
        lsa.ls_length,
        lsa.number_of_links,
        tuple(
            sorted(
                (
                    str(link.link_type),
                    link.link_id,
                    link.link_data,
                    link.network_mask,
                    link.metric,
                    link.mtid,
                )
                for link in lsa.links
            )
        ),
    )


def select_lsa_instance(
    copies: list[OspfRouterLsa] | list[OspfNetworkLsa],
) -> LsaInstanceComparison:
    """Pick the winning instance from **all** observations, order-independently.

    The previous implementation folded pairwise comparisons sequentially. That
    is unsound here: RFC 2328 §13.1's age rule is ``abs(a-b) <= MaxAgeDiff =>
    same instance``, which is **not transitive**. With ages 100/800/1700 (every
    pair within 900), folding left-to-right kept 100, but starting at 800 kept
    800 — the canonical LSA depended on which device happened to be collected
    first. A relation that is not an order cannot be folded.

    So this aggregates over the whole set instead, applying §13.1's precedence
    to the set rather than to a running pair:

    1. **Sequence** — highest signed sequence number. Copies whose sequence
       cannot be parsed make the whole selection unresolved.
    2. **Checksum** — among copies at the winning sequence, highest valid
       unsigned 16-bit checksum.
    3. **MaxAge** — if any surviving copy is exactly MaxAge, those copies win.
    4. **Age spread** — if ``max(age) - min(age) > MaxAgeDiff`` the youngest
       copies win; if the spread is within MaxAgeDiff every copy is the same
       instance as far as the protocol is concerned, and the representative is
       chosen deterministically below.
    5. **Content** — a tie may only be resolved if the surviving copies agree
       about the LSA body (see :func:`lsa_content_fingerprint`). Disagreement is
       reported as an unresolved inconsistency, never silently resolved.

    Observer provenance is never discarded: ``observed_by`` is built by the
    caller from the same set, so a deterministic pick cannot erase an observer.
    """
    if not copies:
        return LsaInstanceComparison(winner=None, reason="no copies", undecided=True)

    # --- 1. sequence ------------------------------------------------------- #
    sequenced: list[tuple[int, OspfRouterLsa | OspfNetworkLsa]] = []
    for copy in copies:
        value = parse_ls_sequence(copy.sequence)
        if not is_valid_ls_sequence(value):
            return LsaInstanceComparison(
                winner=None,
                reason=(
                    "unresolved: an observer reports a missing or invalid LS "
                    f"sequence number ({copy.sequence or 'absent'!r} from "
                    f"{copy.device_id or '?'}); RFC 2328 §13.1 orders instances on "
                    "the sequence number first"
                ),
                undecided=True,
            )
        assert value is not None
        sequenced.append((value, copy))

    best_sequence = max(value for value, _ in sequenced)
    candidates = [c for value, c in sequenced if value == best_sequence]

    # --- 2. checksum ------------------------------------------------------- #
    checked: list[tuple[int, OspfRouterLsa | OspfNetworkLsa]] = []
    for copy in candidates:
        value = parse_ls_checksum(copy.checksum)
        if not is_valid_ls_checksum(value):
            return LsaInstanceComparison(
                winner=None,
                reason=(
                    "unresolved: copies agree on LS sequence "
                    f"{best_sequence} but an LS checksum is missing, malformed or "
                    f"zero ({copy.checksum or 'absent'!r} from "
                    f"{copy.device_id or '?'}); RFC 2328 §13.1 orders equal "
                    "sequences on the checksum"
                ),
                undecided=True,
            )
        assert value is not None
        checked.append((value, copy))

    best_checksum = max(value for value, _ in checked)
    candidates = [c for value, c in checked if value == best_checksum]

    sequence_reason = f"sequence {best_sequence}, checksum 0x{best_checksum:04X}"
    if len(candidates) == 1:
        return LsaInstanceComparison(
            winner=candidates[0], reason=f"highest {sequence_reason}"
        )

    # --- 3. MaxAge --------------------------------------------------------- #
    aged: list[tuple[int, OspfRouterLsa | OspfNetworkLsa]] = []
    for copy in candidates:
        age = parse_ls_age(copy.age)
        if age is None:
            return LsaInstanceComparison(
                winner=None,
                reason=(
                    f"unresolved: copies agree on {sequence_reason}, so only LS Age "
                    "can distinguish them, but an age is missing or invalid "
                    f"({copy.age!r} from {copy.device_id or '?'}; a valid age is an "
                    f"integer in 0..{LS_AGE_MAX})"
                ),
                undecided=True,
            )
        aged.append((age, copy))

    max_age_copies = [c for age, c in aged if age == LS_AGE_MAX]
    if max_age_copies and len(max_age_copies) < len(candidates):
        reason = f"{sequence_reason}; MaxAge instance wins"
        candidates = max_age_copies
        if len(candidates) == 1:
            return LsaInstanceComparison(winner=candidates[0], reason=reason)
    else:
        reason = sequence_reason

    # --- 4. age spread ----------------------------------------------------- #
    ages = [age for age, _ in aged]
    youngest = min(ages)
    oldest = max(ages)
    if oldest - youngest > MAX_AGE_DIFF:
        contenders = [c for age, c in aged if age == youngest]
        reason = (
            f"{reason}; age spread {oldest - youngest}s exceeds MaxAgeDiff "
            f"{MAX_AGE_DIFF}, youngest instance (age {youngest}) wins"
        )
        if len(contenders) == 1:
            return LsaInstanceComparison(winner=contenders[0], reason=reason)
        candidates = contenders
    else:
        reason = (
            f"{reason}; ages {sorted(set(ages))} span {oldest - youngest}s, within "
            f"MaxAgeDiff {MAX_AGE_DIFF}, so every copy is the same instance"
        )

    # --- 5. content -------------------------------------------------------- #
    fingerprints = {lsa_content_fingerprint(c) for c in candidates}
    if len(fingerprints) > 1:
        return LsaInstanceComparison(
            winner=None,
            reason=(
                f"unresolved: copies agree on {sequence_reason} and are within "
                f"MaxAgeDiff of each other, but their LSA content differs — "
                f"{len(fingerprints)} distinct bodies are reported for one instance "
                "(observers: "
                + ", ".join(sorted(c.device_id or "?" for c in candidates))
                + "). Choosing one body would silently discard the others"
            ),
            undecided=True,
        )

    # Same instance, same body: pick deterministically so the result cannot
    # depend on input order.
    chosen = min(
        candidates, key=lambda c: (parse_ls_age(c.age), c.device_id or "", c.command)
    )
    return LsaInstanceComparison(
        winner=chosen,
        reason=(
            f"{reason}; content is identical across observers, youngest copy "
            f"(age {parse_ls_age(chosen.age)}) chosen as representative"
        ),
    )


def canonical_router_lsas(
    devices: list[OspfDeviceData], warnings: list[str]
) -> list[OspfRouterLsa]:
    """Collapse every observer's copy of a Router LSA into one canonical record.

    Selection when observers disagree about sequence/checksum: the highest
    sequence number wins (RFC 2328 §13.1 instance ordering), then the lowest
    age, then a stable ordering by checksum. The disagreement itself is a
    warning — a stale LSDB on one router is real operational information and is
    never silently dropped.
    """
    grouped: dict[LsaIdentity, list[OspfRouterLsa]] = defaultdict(list)
    for device in devices:
        for lsa in device.router_lsas:
            # An LSA whose declared link count contradicts its own body is not
            # evidence: the two halves of the object disagree. The parser drops
            # these, but a copy can arrive by another route (a hand-built
            # DeviceObservations, a fixture, a future collector), so the check
            # is repeated where the object is consumed.
            mismatch = lsa.link_count_mismatch()
            if mismatch is not None:
                warnings.append(
                    f"{device.device_id}: {mismatch} — excluded from "
                    "canonicalisation because the copy is internally inconsistent"
                )
                continue
            identity = LsaIdentity(
                area=lsa.area,
                lsa_type=1,
                link_state_id=lsa.link_state_id,
                advertising_router=lsa.advertising_router,
            )
            # The observer is the device whose LSDB produced this copy. Fall
            # back to the enclosing device so provenance is never empty.
            if not lsa.device_id:
                lsa.device_id = device.device_id
            grouped[identity].append(lsa)

    canonical: list[OspfRouterLsa] = []
    for identity in sorted(
        grouped, key=lambda i: (i.area, i.advertising_router, i.link_state_id)
    ):
        copies = grouped[identity]
        observers = sorted({c.device_id for c in copies if c.device_id})

        selection = select_lsa_instance(copies)
        chosen = selection.winner
        if chosen is None:
            # No protocol-correct winner exists. Keep every observation, claim
            # nothing about which is current, and say exactly why.
            warnings.append(
                f"OSPF LSDB conflict on {identity.describe()} could not be resolved: "
                f"{selection.reason}. No instance was chosen; the LSA is left out "
                "of reconstruction until the LSDB agrees or is re-collected."
            )
            warnings.extend(
                f"OSPF LSDB unresolved {identity.describe()}: observer "
                f"{c.device_id or '?'} reports seq {c.sequence or 'absent'} "
                f"checksum {c.checksum or 'absent'} age {c.age}"
                for c in sorted(copies, key=lambda c: c.device_id)
            )
            continue

        per_observer: list[dict[str, str]] = []
        if not _single_version(copies):
            detail = ", ".join(
                f"{c.device_id or '?'}={c.sequence or '?'}/{c.checksum or '?'}"
                for c in sorted(copies, key=lambda c: c.device_id)
            )
            warnings.append(
                f"OSPF LSDB disagreement on {identity.describe()}: observers report "
                f"different instances ({detail}); {selection.reason} was used and the "
                "conflict is preserved here rather than resolved silently"
            )
            per_observer = [
                {
                    "observer": c.device_id or "?",
                    "sequence": c.sequence,
                    "checksum": c.checksum,
                    "age": "" if c.age is None else str(c.age),
                }
                for c in sorted(copies, key=lambda c: c.device_id)
            ]

        # Re-emit the chosen instance as the canonical record, carrying the full
        # observer set. A copy built from one device is not mutated in place:
        # the original objects stay owned by their observer.
        canonical.append(
            chosen.model_copy(
                update={
                    "observed_by": observers,
                    "device_id": chosen.device_id,
                    "observed_instances": per_observer,
                }
            )
        )
    return canonical


def canonical_network_lsas(
    devices: list[OspfDeviceData], warnings: list[str]
) -> list[OspfNetworkLsa]:
    """Collapse every observer's copy of a Network LSA into one canonical record.

    The winning instance is chosen with :func:`select_lsa_instance` (RFC 2328
    §13.1) and its attached-router list is the canonical list — **only** the
    winner's. Membership is never unioned across instances: a Network LSA names
    the routers the DR currently has on the segment, so merging a stale copy's
    list would resurrect a router that has since left and manufacture a segment
    member the LSDB does not claim.

    Differing observations are still preserved, in
    :attr:`OspfNetworkLsa.observed_membership` and in a warning, so the
    disagreement remains auditable after the winner has been selected.
    """
    grouped: dict[LsaIdentity, list[OspfNetworkLsa]] = defaultdict(list)
    for device in devices:
        for lsa in device.network_lsas:
            identity = LsaIdentity(
                area=lsa.area,
                lsa_type=2,
                link_state_id=lsa.link_state_id,
                advertising_router=lsa.advertising_router,
            )
            if not lsa.device_id:
                lsa.device_id = device.device_id
            grouped[identity].append(lsa)

    canonical: list[OspfNetworkLsa] = []
    for identity in sorted(
        grouped, key=lambda i: (i.area, i.link_state_id, i.advertising_router)
    ):
        copies = grouped[identity]
        observers = sorted({c.device_id for c in copies if c.device_id})

        selection = select_lsa_instance(copies)
        chosen = selection.winner
        if chosen is None:
            warnings.append(
                f"OSPF LSDB conflict on {identity.describe()} could not be resolved: "
                f"{selection.reason}. No instance was chosen; the transit network is "
                "left out of reconstruction until the LSDB agrees or is re-collected."
            )
            # When the copies agree on sequence and checksum but not on
            # membership, say so in membership terms: "content differs" is
            # accurate but not diagnosable for a Network LSA.
            variants: dict[frozenset[str], list[str]] = defaultdict(list)
            for copy in sorted(copies, key=lambda c: c.device_id):
                variants[frozenset(copy.attached_routers)].append(copy.device_id or "?")
            if _single_version(copies) and len(variants) > 1:
                reports = "; ".join(
                    f"{', '.join(devices)} report {sorted(members)}"
                    for members, devices in sorted(
                        variants.items(), key=lambda kv: (len(kv[0]), sorted(kv[1]))
                    )
                )
                warnings.append(
                    f"OSPF Network LSA membership disagreement on "
                    f"{identity.describe()}: {reports}. All observers report the "
                    "same sequence and checksum, so this is an inconsistent "
                    "observation of a single instance rather than differing "
                    "versions; no membership list was chosen."
                )
            warnings.extend(
                f"OSPF LSDB unresolved {identity.describe()}: observer "
                f"{c.device_id or '?'} reports seq {c.sequence or 'absent'} "
                f"checksum {c.checksum or 'absent'} age {c.age} "
                f"members {sorted(c.attached_routers)}"
                for c in sorted(copies, key=lambda c: c.device_id)
            )
            continue

        if not _single_version(copies):
            detail = ", ".join(
                f"{c.device_id or '?'}={c.sequence or '?'}/{c.checksum or '?'}"
                for c in sorted(copies, key=lambda c: c.device_id)
            )
            warnings.append(
                f"OSPF LSDB disagreement on {identity.describe()}: observers report "
                f"different instances ({detail}); {selection.reason} was used and the "
                "conflict is preserved here rather than resolved silently"
            )

        # Membership comes from the **winning instance only**. A Network LSA
        # states which routers the DR currently has on the segment; unioning
        # stale copies would resurrect a router that has since been removed,
        # inventing a segment member the current LSDB does not claim.
        attached = sorted(chosen.attached_routers)

        # Differing reports are still preserved as evidence — just not merged.
        variants: dict[frozenset[str], list[str]] = defaultdict(list)
        for copy in sorted(copies, key=lambda c: c.device_id):
            variants[frozenset(copy.attached_routers)].append(copy.device_id or "?")
        if len(variants) > 1:
            reports = "; ".join(
                f"{', '.join(devices)} report {sorted(members)}"
                for members, devices in sorted(
                    variants.items(), key=lambda kv: (len(kv[0]), sorted(kv[1]))
                )
            )
            warning = (
                f"OSPF Network LSA membership disagreement on {identity.describe()}: "
                f"{reports}. The canonical list is the winner's "
                f"({sorted(chosen.attached_routers)}) from {chosen.device_id or '?'}; "
                "members from other instances are not merged in."
            )
            if _single_version(copies):
                # Same instance, different content: not a stale copy, a corrupt
                # or mistranscribed observation.
                warning += (
                    " All observers report the same sequence and checksum, so this "
                    "is an inconsistent observation of a single instance rather "
                    "than differing versions."
                )
            warnings.append(warning)

        canonical.append(
            chosen.model_copy(
                update={
                    "attached_routers": attached,
                    "observed_by": observers,
                    "device_id": chosen.device_id,
                    "observed_membership": [
                        {
                            "observer": c.device_id or "?",
                            "attached_routers": sorted(c.attached_routers),
                            "sequence": c.sequence,
                            "checksum": c.checksum,
                        }
                        for c in sorted(copies, key=lambda c: c.device_id)
                    ],
                }
            )
        )
    return canonical


def _transit_key(area: str, dr_address: str) -> tuple[str, str]:
    """The join key between a Type-1 transit link and a Type-2 LSA."""
    return (area, dr_address)


def reconstruct_transit_networks(
    router_lsas: list[OspfRouterLsa],
    network_lsas: list[OspfNetworkLsa],
    warnings: list[str],
) -> list[OspfTransitNetwork]:
    """Correlate Router LSA transit records with Network LSAs.

    For each Network LSA the DR address is the join key. Every router whose own
    Router LSA contains a transit link pointing at that DR is a candidate
    member; the member's interface address comes from that same link's
    ``Link Data``.

    Evidence states:

    * ``confirmed``  — the Type-1 members and the Type-2 attached list agree.
    * ``partial``    — only one side is present in the LSDB.
    * ``inconsistent`` — both present and they disagree.
    * ``unresolved`` — the DR address cannot be tied to a prefix at all.
    """
    # (area, dr) -> {router_id: interface_address}
    transit_members: dict[tuple[str, str], dict[str, str]] = defaultdict(dict)
    for lsa in router_lsas:
        for link in lsa.links:
            if link.link_type is not OspfLinkType.TRANSIT:
                continue
            key = _transit_key(lsa.area, link.link_id)
            transit_members[key][lsa.advertising_router] = link.link_data

    networks: list[OspfTransitNetwork] = []
    consumed_keys: set[tuple[str, str]] = set()

    for lsa in network_lsas:
        key = _transit_key(lsa.area, lsa.link_state_id)
        consumed_keys.add(key)
        prefix = lsa.prefix
        type1_members = dict(transit_members.get(key, {}))
        type2_members = list(lsa.attached_routers)

        notes: list[str] = []
        sources = [_lsa_ref(lsa, 2)]
        evidence = [EV_NETWORK_LSA]

        if type1_members:
            sources.append(
                _lsa_ref(
                    next(
                        r
                        for r in router_lsas
                        if r.area == lsa.area
                        and r.advertising_router in type1_members
                    ),
                    1,
                )
            )
            evidence.append(EV_ROUTER_LSA)

        # Membership union, so a router that only appears on one side is kept
        # visible instead of vanishing — with the disagreement recorded.
        members = sorted(set(type2_members) | set(type1_members))

        if type1_members and type2_members:
            only_1 = sorted(set(type1_members) - set(type2_members))
            only_2 = sorted(set(type2_members) - set(type1_members))
            if only_1 or only_2:
                state = OspfEvidenceState.INCONSISTENT
                if only_1:
                    notes.append(
                        "router(s) claim membership in their Router LSA but are absent "
                        f"from the Network LSA attached list: {', '.join(only_1)}"
                    )
                if only_2:
                    notes.append(
                        "Network LSA lists router(s) whose Router LSA does not reference "
                        f"this DR: {', '.join(only_2)}"
                    )
                warnings.append(
                    f"OSPF transit network {prefix or lsa.link_state_id}: "
                    f"Type 1 and Type 2 disagree ({'; '.join(notes)})"
                )
            else:
                state = OspfEvidenceState.CONFIRMED
        elif type2_members or type1_members:
            state = OspfEvidenceState.PARTIAL
            if not type1_members:
                notes.append(
                    "no Router LSA in the collected LSDB references this DR — "
                    "membership rests on the Network LSA alone"
                )
            if not type2_members:
                notes.append(
                    "no Network LSA for this DR — membership rests on Router LSAs alone"
                )
        else:
            state = OspfEvidenceState.UNRESOLVED
            notes.append("no member information from either LSA type")

        if prefix is None:
            state = OspfEvidenceState.UNRESOLVED
            notes.append("Network Mask missing — the segment prefix cannot be computed")
            warnings.append(
                f"OSPF transit network at DR {lsa.link_state_id}: prefix unresolved "
                "(no usable Network Mask)"
            )

        # Validate each member's interface address against the segment prefix.
        interface_addresses: dict[str, str] = {}
        for router_id, address in type1_members.items():
            if not address:
                continue
            interface_addresses[router_id] = address
            if prefix and not _contains(prefix, address):
                notes.append(
                    f"router {router_id} reports interface address {address} which is "
                    f"not inside {prefix}"
                )
                if state is OspfEvidenceState.CONFIRMED:
                    state = OspfEvidenceState.INCONSISTENT
                    warnings.append(
                        f"OSPF transit network {prefix}: router {router_id} interface "
                        f"{address} is outside the advertised prefix"
                    )

        networks.append(
            OspfTransitNetwork(
                id=f"ospf-transit-{lsa.area}-{lsa.link_state_id}",
                area=lsa.area,
                prefix=prefix,
                dr_address=lsa.link_state_id,
                advertising_router=lsa.advertising_router,
                member_router_ids=members,
                member_interface_addresses=interface_addresses,
                source_lsas=sources,
                evidence=sorted(set(evidence)),
                state=state,
                notes=notes,
            )
        )

    # A transit segment known ONLY from Router LSAs (no Network LSA collected).
    for key, members in sorted(transit_members.items()):
        if key in consumed_keys:
            continue
        area, dr = key
        warnings.append(
            f"OSPF transit network at DR {dr} (area {area}) is referenced by "
            f"{len(members)} Router LSA(s) but no Network LSA was collected — "
            "membership is partial"
        )
        networks.append(
            OspfTransitNetwork(
                id=f"ospf-transit-{area}-{dr}",
                area=area,
                prefix=None,
                dr_address=dr,
                advertising_router="",
                member_router_ids=sorted(members),
                member_interface_addresses=dict(members),
                source_lsas=[],
                evidence=[EV_ROUTER_LSA],
                state=OspfEvidenceState.PARTIAL,
                notes=[
                    "Network LSA (Type 2) not present in the collected LSDB; the "
                    "segment prefix and the DR's own view are unknown"
                ],
            )
        )

    return networks


# --------------------------------------------------------------------------- #
# Type 4/5: point-to-point edges and stub networks
# --------------------------------------------------------------------------- #


def reconstruct_point_to_point_edges(
    router_lsas: list[OspfRouterLsa], warnings: list[str]
) -> list[OspfLogicalEdge]:
    """Build P2P logical edges only where *both* sides provide Type-1 evidence.

    A Type-1 point-to-point link names the peer Router ID in ``Link ID``. The
    edge is emitted only when the peer's own Router LSA independently contains a
    point-to-point link back to the first router on the same subnet. One-sided
    P2P evidence stays a warning, never an edge.
    """
    # (area, adv_router) -> list of p2p (peer_id, local_address, metric)
    p2p: dict[tuple[str, str], list[tuple[str, str, int | None]]] = defaultdict(list)
    for lsa in router_lsas:
        for link in lsa.links:
            if link.link_type is not OspfLinkType.POINT_TO_POINT:
                continue
            p2p[(lsa.area, lsa.advertising_router)].append(
                (link.link_id, link.link_data, link.metric)
            )

    edges: list[OspfLogicalEdge] = []
    seen: set[tuple[str, str, str]] = set()
    for (area, router), peers in sorted(p2p.items()):
        for peer_id, local_address, metric in peers:
            reverse = p2p.get((area, peer_id), [])
            reciprocal = any(reverse_peer == router for reverse_peer, _, _ in reverse)
            key = (area, *sorted((router, peer_id)))
            if key in seen:
                continue
            if not reciprocal:
                warnings.append(
                    f"OSPF point-to-point link {router} -> {peer_id} (area {area}) has "
                    "no reciprocal Router LSA — kept as one-sided, not an edge"
                )
                continue
            seen.add(key)
            peer_addresses = [a for p, a, _ in reverse if p == router]
            prefix = None
            if local_address and peer_addresses:
                for plen in range(31, 23, -1):
                    candidate = _prefix_or_none(local_address, str(
                        ipaddress.IPv4Network(f"0.0.0.0/{plen}").netmask
                    ))
                    if candidate and _contains(candidate, peer_addresses[0]):
                        prefix = candidate
                        break
            source_lsas = [
                _lsa_ref(lsa, 1)
                for lsa in router_lsas
                if lsa.area == area and lsa.advertising_router in {router, peer_id}
            ]
            edges.append(
                OspfLogicalEdge(
                    source_router_id=router,
                    destination_router_id=peer_id,
                    prefix=prefix,
                    area=area,
                    destination_interface="",
                    source_lsas=source_lsas,
                    state=OspfEvidenceState.CONFIRMED,
                    notes=[
                        "reciprocal Type 1 point-to-point evidence on both routers",
                        f"metric {metric}" if metric is not None else "metric not reported",
                    ],
                )
            )
    return edges


def reconstruct_stub_networks(
    router_lsas: list[OspfRouterLsa],
) -> list[OspfStubNetwork]:
    """Every Stub Link in every Router LSA becomes one advertised prefix.

    **The contract, stated once.** A Stub Network is ``(prefix, advertising
    router, area, metric)`` exactly as the Type-1 LSA advertises it. It is the
    LSDB's statement that *this router owns this prefix on-link*.

    This is a different fact from "the prefix is a locally connected subnet",
    and the two must not be conflated in either direction:

    * a prefix that is both (e.g. ``10.0.12.0/30`` on R2) appears **once** here,
      because the LSA advertises it — the fact that it is also an interface
      subnet changes nothing and must not suppress it;
    * a prefix that is an interface subnet but that the router does **not**
      advertise as a stub link is absent, because the LSDB does not claim it.

    Stub links never create routers or edges — they are prefix-ownership
    statements, nothing more, and ``OspfStubNetwork`` deliberately has no
    member/DR fields so it cannot be mistaken for a segment.
    """
    stubs: list[OspfStubNetwork] = []
    seen: set[tuple[str, str, str]] = set()
    for lsa in router_lsas:
        for link in lsa.links:
            if link.link_type is not OspfLinkType.STUB:
                continue
            prefix = link.prefix
            if not prefix:
                continue
            key = (lsa.area, lsa.advertising_router, prefix)
            if key in seen:
                continue
            seen.add(key)
            stubs.append(
                OspfStubNetwork(
                    prefix=prefix,
                    advertising_router=lsa.advertising_router,
                    area=lsa.area,
                    metric=link.metric,
                    source_lsa=_lsa_ref(lsa, 1),
                    device_id=lsa.device_id,
                )
            )
    return stubs


def _originator_is_self(device: OspfDeviceData, lsa: OspfRouterLsa) -> bool:
    """Did ``device`` originate ``lsa``, or merely hold a copy of it?

    Attribution rule, stated once so it cannot drift:

    * if the device reported its own router-id (``show ip ospf``), only the LSA
      whose Advertising Router equals that id is its own;
    * if it did not, fall back to interface evidence: a router advertises its
      attached networks as links in its own LSA, so an LSA whose stub links
      match an interface address of this device is very likely its own. This is
      inference, and inference is named as such in the docs — the primary path
      is the explicit router-id.

    Everything else in the LSDB belongs to some other router.
    """
    if device.router_id:
        return lsa.advertising_router == device.router_id
    own_addresses = {
        iface.ip_address for iface in device.interfaces if iface.device_id == device.device_id
    }
    if not own_addresses:
        return False
    for link in lsa.links:
        if link.link_data in own_addresses:
            return True
    return False


def advertised_stub_links(router_lsas: list[OspfRouterLsa]) -> set[tuple[str, str, str]]:
    """Every ``(area, advertising_router, prefix)`` a Router LSA advertises as a stub.

    The ground truth for the stub contract: whatever appears here must also
    appear in :func:`reconstruct_stub_networks`, and nothing else may.
    """
    advertised: set[tuple[str, str, str]] = set()
    for lsa in router_lsas:
        for link in lsa.links:
            if link.link_type is not OspfLinkType.STUB:
                continue
            if link.prefix:
                advertised.add((lsa.area, lsa.advertising_router, link.prefix))
    return advertised


# --------------------------------------------------------------------------- #
# Assembly
# --------------------------------------------------------------------------- #


def build_ospf_topology(
    devices: list[OspfDeviceData],
    *,
    physical: Topology | None = None,
) -> OspfTopology:
    """Assemble the whole OSPF view from every collected device.

    ``physical`` is optional and used only for CDP correlation at the end —
    OSPF reconstruction itself never reads it.
    """
    topology = OspfTopology()
    warnings: list[str] = []

    router_lsas: list[OspfRouterLsa] = []
    network_lsas: list[OspfNetworkLsa] = []

    for device in devices:
        warnings.extend(f"{device.device_id}: {w}" for w in device.warnings)
        topology.neighbors.extend(device.neighbors)
        topology.interfaces.extend(device.interfaces)
        topology.database_summary.extend(device.database_summary)
        topology.routes.extend(device.routes)

        if device.process_id or device.router_id:
            areas = sorted({i.area for i in device.interfaces if i.area})
            topology.instances.append(
                OspfInstance(
                    device_id=device.device_id,
                    process_id=device.process_id or "unknown",
                    router_id=device.router_id,
                    areas=[],
                )
            )
            # Record which interfaces sit in which area, per device.
            by_area: dict[str, list[str]] = defaultdict(list)
            for iface in device.interfaces:
                if iface.area:
                    by_area[iface.area].append(iface.name)
            if topology.instances:
                from nettwin.domain.ospf_models import OspfArea

                topology.instances[-1].areas = [
                    OspfArea(area=area, interfaces=sorted(by_area[area]))
                    for area in sorted(by_area) or areas
                ]

    # --- canonical LSAs ---------------------------------------------------- #
    # An area's LSDB is flooded: every observer holds the same LSAs. Collapse
    # the copies to one canonical record per LSA identity *before* anything is
    # reconstructed from them, otherwise the topology is multiplied by the
    # number of devices that happened to be collected. Observer provenance is
    # carried on the canonical record's ``observed_by``.
    router_lsas = canonical_router_lsas(devices, warnings)
    network_lsas = canonical_network_lsas(devices, warnings)
    topology.router_lsas = router_lsas
    topology.network_lsas = network_lsas

    # --- routers ---------------------------------------------------------- #
    router_ids: dict[str, set[str]] = defaultdict(set)     # router_id -> devices
    process_ids: dict[str, set[str]] = defaultdict(set)
    areas_by_router: dict[str, set[str]] = defaultdict(set)

    # A device's own router-id is the one *it* reports about itself:
    #   * the router-id line of its own `show ip ospf` output, and
    #   * the Router LSA it *originated* in its own LSDB.
    #
    # It is emphatically NOT every Router LSA in its LSDB: an area is flooded,
    # so every router holds all five LSAs. Treating "I can see it" as "I am it"
    # credited all five router-ids to the first device collected and marked
    # four uncollected routers as collected.
    for device in devices:
        originated = {
            lsa.advertising_router
            for lsa in device.router_lsas
            # Observer == originator only for the device's *own* LSA.
            if lsa.device_id == device.device_id
            and _originator_is_self(device, lsa)
        }
        candidates = {device.router_id, *originated} - {""}
        for router_id in candidates:
            router_ids[router_id].add(device.device_id)
            if device.process_id:
                process_ids[router_id].add(device.process_id)

    for lsa in router_lsas:
        areas_by_router[lsa.advertising_router].add(lsa.area)
    for lsa in network_lsas:
        for attached in lsa.attached_routers:
            areas_by_router[attached].add(lsa.area)

    for router_id in sorted(set(router_ids) | set(areas_by_router)):
        owning = sorted(router_ids.get(router_id, set()))
        topology.routers.append(
            OspfRouter(
                router_id=router_id,
                device_id=owning[0] if owning else "",
                process_ids=sorted(process_ids.get(router_id, set())),
                areas=sorted(areas_by_router.get(router_id, set())),
                collected=bool(owning),
            )
        )

    # --- reconstructed relationships -------------------------------------- #
    topology.transit_networks = reconstruct_transit_networks(
        router_lsas, network_lsas, warnings
    )
    topology.logical_edges = reconstruct_point_to_point_edges(router_lsas, warnings)
    topology.stub_networks = reconstruct_stub_networks(router_lsas)

    # --- honesty notes ----------------------------------------------------- #
    # Computed once, before it is needed: the previous version assigned this
    # inside the ``if not router_lsas`` branch and then read it further down,
    # which raised UnboundLocalError on every run that did have Router LSAs.
    any_ospf_signal = bool(
        topology.neighbors
        or topology.interfaces
        or topology.database_summary
        or topology.network_lsas
        or topology.router_lsas
        or topology.routes
    )
    if not router_lsas:
        # Two very different situations, both reported precisely:
        #   * nothing OSPF-shaped arrived at all -> the device does not run OSPF
        #   * OSPF answered but the LSDB had no Router LSAs -> evidence gap
        if not any_ospf_signal:
            warnings.append(
                "no OSPF evidence collected — this device does not appear to run OSPF, "
                "so no logical topology was reconstructed (nothing invented)"
            )
        else:
            warnings.append(
                "no Router LSA (Type 1) collected — OSPF logical topology cannot be "
                "reconstructed from the evidence available (nothing invented)"
            )
    if not network_lsas and router_lsas:
        warnings.append(
            "no Network LSA (Type 2) collected — transit membership has only "
            "Router LSA evidence"
        )
    if not topology.neighbors and devices and any_ospf_signal:
        warnings.append(
            "no OSPF neighbor rows collected — operational adjacency state unknown"
        )

    topology.warnings = warnings

    if physical is not None:
        topology.correlations = correlate_with_cdp(topology, physical)

    return topology


# --------------------------------------------------------------------------- #
# CDP correlation
# --------------------------------------------------------------------------- #


def correlate_with_cdp(ospf: OspfTopology, physical: Topology) -> list[OspfCorrelation]:
    """Compare OSPF-derived relationships with CDP-derived links — never merge.

    Correlation is per-pair, and it reports rather than resolves:

    * ``cdp_confirmed`` — CDP links the same two devices and the OSPF transit
      prefix contains one of that link's interface addresses.
    * ``cdp_missing``   — OSPF shows the relationship, CDP saw nothing between
      them. Normal when the segment runs through an unmanaged switch.
    * ``cdp_disagrees`` — CDP links the two devices but no OSPF transit prefix
      covers either interface address.
    * ``no_cdp_data``   — no CDP links exist for either device at all.
    """
    iface_by_id = {i.id: i for i in physical.interfaces}
    device_by_id = {d.id: d for d in physical.devices}

    # device_id -> set of CDP-linked device ids
    cdp_pairs: dict[tuple[str, str], list[str]] = {}
    for link in physical.links:
        src = iface_by_id.get(link.source_interface_id)
        dst = iface_by_id.get(link.destination_interface_id)
        if not src or not dst:
            continue
        key = tuple(sorted((src.device_id, dst.device_id)))
        addresses = [str(a).split("/")[0] for a in src.ipv4_addresses]
        addresses += [str(a).split("/")[0] for a in dst.ipv4_addresses]
        cdp_pairs.setdefault(key, []).extend(addresses)  # type: ignore[arg-type]

    devices_with_cdp = {d for pair in cdp_pairs for d in pair}
    router_to_device = {
        r.router_id: r.device_id for r in ospf.routers if r.device_id
    }

    correlations: list[OspfCorrelation] = []
    for network in ospf.transit_networks:
        for member in network.member_router_ids:
            member_device = router_to_device.get(member)
            if not member_device:
                continue
            for other in network.member_router_ids:
                if other == member:
                    continue
                other_device = router_to_device.get(other)
                if not other_device:
                    continue
                key = tuple(sorted((member_device, other_device)))
                addresses = cdp_pairs.get(key)  # type: ignore[arg-type]
                relation_id = f"{network.id}:{member}-{other}"

                if addresses is None:
                    state = (
                        OspfCdpRelation.NO_CDP_DATA
                        if member_device not in devices_with_cdp
                        and other_device not in devices_with_cdp
                        else OspfCdpRelation.CDP_MISSING
                    )
                    detail = (
                        "no CDP link exists between "
                        f"{device_by_id.get(member_device, member_device)} and "
                        f"{device_by_id.get(other_device, other_device)}"
                    )
                elif any(_contains(network.prefix, a) for a in addresses):
                    state = OspfCdpRelation.CDP_CONFIRMED
                    detail = (
                        f"CDP links these devices and the OSPF prefix "
                        f"{network.prefix} covers the link addressing"
                    )
                else:
                    state = OspfCdpRelation.CDP_DISAGREES
                    detail = (
                        f"CDP links these devices but no address on that link "
                        f"({', '.join(addresses) or 'none collected'}) falls inside "
                        f"the OSPF prefix {network.prefix}"
                    )
                correlations.append(
                    OspfCorrelation(
                        relation_id=relation_id, cdp_state=state, detail=detail
                    )
                )
    return correlations
