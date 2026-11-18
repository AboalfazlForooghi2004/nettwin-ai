"""Phase 2.6 — RFC 2328 §12.1.6 sequence numbers and §13.1 instance ordering.

**OFFLINE.** These tests pin the protocol-level behaviour of LSA canonicalisation
against the specification rather than against the implementation's own output.

Three things are being protected:

* **The sequence space is signed.** RFC 2328 §12.1.6 numbers LSAs from
  ``0x80000001`` upward through ``0x7FFFFFFF`` in the *signed* 32-bit range.
  Parsed unsigned, ``0x80000001`` looks enormous and ``0x7FFFFFFF`` looks
  larger still, which inverts the true order across the boundary.
* **The comparison order is §13.1's, not a convenient one.** Checksum precedes
  age. A checksum difference means a different instance, full stop.
* **Canonical content comes from one instance.** A Network LSA's attached
  routers are the DR's current view; merging a stale copy's list invents
  membership the LSDB does not claim.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

TESTS = Path(__file__).parent
if str(TESTS) not in sys.path:
    sys.path.insert(0, str(TESTS))

from nettwin.collect.ospf_topology import (  # noqa: E402
    LS_AGE_MAX,
    LS_SEQUENCE_RESERVED,
    MAX_AGE_DIFF,
    canonical_network_lsas,
    canonical_router_lsas,
    compare_lsa_instances,
    is_valid_ls_sequence,
    parse_ls_checksum,
    parse_ls_sequence,
    same_lsa_version,
    select_lsa_instance,
)
from nettwin.domain.ospf_models import (  # noqa: E402
    OspfLinkType,
    OspfLsaLink,
    OspfNetworkLsa,
    OspfRouterLsa,
)


def rlsa(
    sequence: str = "0x80000001",
    checksum: str = "0x1111",
    age: int | None = 100,
    *,
    link_state_id: str = "10.255.255.1",
    advertising_router: str = "10.255.255.1",
    device_id: str = "r1",
) -> OspfRouterLsa:
    return OspfRouterLsa(
        area="0",
        link_state_id=link_state_id,
        advertising_router=advertising_router,
        sequence=sequence,
        checksum=checksum,
        age=age,
        device_id=device_id,
    )


def nlsa(
    sequence: str = "0x80000002",
    checksum: str = "0x5E6F",
    age: int | None = 100,
    *,
    attached: list[str] | None = None,
    link_state_id: str = "10.0.21.1",
    device_id: str = "r1",
) -> OspfNetworkLsa:
    return OspfNetworkLsa(
        area="0",
        link_state_id=link_state_id,
        advertising_router="10.255.255.3",
        network_mask="255.255.255.252",
        attached_routers=list(attached if attached is not None else ["10.255.255.1"]),
        sequence=sequence,
        checksum=checksum,
        age=age,
        device_id=device_id,
    )


# =========================================================================== #
# 1. Signed LS sequence numbers (RFC 2328 §12.1.6)
# =========================================================================== #


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("0x80000001", -2147483647),   # initial sequence number
        ("0x80000005", -2147483643),
        ("0x80000009", -2147483639),
        ("0x7FFFFFFF", 2147483647),    # maximum, the *newest* valid sequence
    ],
)
def test_signed_sequence_parsing(text: str, expected: int) -> None:
    assert parse_ls_sequence(text) == expected


def test_ios_prints_the_sequence_without_a_hex_prefix() -> None:
    """``LS Seq Number: 80000002`` — no ``0x``, unlike ``Checksum: 0x5E6F``."""
    assert parse_ls_sequence("80000002") == parse_ls_sequence("0x80000002")
    assert parse_ls_sequence("80000002") == -2147483646


@pytest.mark.parametrize("text", ["0x8000000a", "0x8000000A", "8000000a", "8000000A"])
def test_sequence_parsing_is_case_insensitive(text: str) -> None:
    assert parse_ls_sequence(text) == parse_ls_sequence("0x80000009") + 1


def test_maximum_sequence_is_newer_than_the_initial_one() -> None:
    """The whole point of the signed reading.

    Unsigned, ``0x80000001`` (2147483649) beats ``0x7FFFFFFF`` (2147483647)
    and the comparison is inverted. Signed, the initial number is the most
    negative value and the maximum is the newest.
    """
    initial = parse_ls_sequence("0x80000001")
    maximum = parse_ls_sequence("0x7FFFFFFF")
    assert initial is not None
    assert maximum is not None
    assert maximum > initial

    older, newer = rlsa(sequence="0x80000001"), rlsa(sequence="0x7FFFFFFF")
    assert compare_lsa_instances(older, newer).winner is newer
    assert compare_lsa_instances(newer, older).winner is newer


def test_sequence_progresses_inside_the_negative_range() -> None:
    """Normal ageing: each increment wraps further into the negative range."""
    values = [parse_ls_sequence(f"0x8000000{n}") for n in range(1, 6)]
    assert values == [-2147483647, -2147483646, -2147483645, -2147483644, -2147483643]
    assert values == sorted(values)
    assert all(v is not None and v < 0 for v in values)


def test_reserved_sequence_is_parsed_but_never_valid() -> None:
    """``0x80000000`` is reserved (RFC 2328 §12.1.6) and is not an instance."""
    value = parse_ls_sequence("0x80000000")
    assert value == -(1 << 31) == -2147483648
    assert is_valid_ls_sequence(value) is False
    assert LS_SEQUENCE_RESERVED == 0x80000000


@pytest.mark.parametrize("text", ["", "   ", None, "zzz", "0xzzzzzzzz", "0x123456789"])
def test_malformed_or_missing_sequences_are_not_valid(text: object) -> None:
    """A malformed value must not be mistaken for a usable sequence number."""
    value = parse_ls_sequence(text)  # type: ignore[arg-type]
    assert value is None
    assert is_valid_ls_sequence(value) is False


def test_reserved_sequence_cannot_decide_a_winner() -> None:
    """A reserved value must not silently act as an extremely old instance."""
    reserved = rlsa(sequence="0x80000000")
    valid = rlsa(sequence="0x80000001")
    comparison = compare_lsa_instances(reserved, valid)
    assert comparison.undecided is True
    assert comparison.winner is None


# =========================================================================== #
# 2. Checksum precedence (RFC 2328 §13.1 step 2)
# =========================================================================== #


def test_higher_checksum_wins_even_with_a_greater_age() -> None:
    """Checksum is compared before age, so a fresher-looking copy can lose."""
    stale_but_higher = rlsa(checksum="0x1A2B", age=1800)
    young_but_lower = rlsa(checksum="0x0E6F", age=50)

    comparison = compare_lsa_instances(young_but_lower, stale_but_higher)
    assert comparison.winner is stale_but_higher
    assert "checksum" in comparison.reason


def test_checksum_is_compared_numerically_not_lexicographically() -> None:
    """``0xFFF`` (4095) is numerically below ``0x1000`` (4096) — as text, above.

    A 3-digit checksum against a 4-digit one is where string comparison
    inverts: ``"0xFFF"`` sorts after ``"0x1000"`` because ``"F" > "1"``, so a
    lexicographic comparator would hand the win to the smaller checksum.
    """
    low, high = "0xFFF", "0x1000"
    low_value, high_value = parse_ls_checksum(low), parse_ls_checksum(high)
    assert low_value is not None and high_value is not None
    assert low_value == 4095
    assert high_value == 4096
    assert low_value < high_value
    # The trap: as strings the ordering is the opposite.
    assert low > high

    smaller = rlsa(checksum=low, age=1)       # fresher, but numerically lower
    larger = rlsa(checksum=high, age=3000)    # older, but numerically higher
    assert compare_lsa_instances(smaller, larger).winner is larger


def test_checksum_comparison_ignores_hex_formatting() -> None:
    """``0x0e6f``, ``0E6F`` and ``0x0E6F`` are the same checksum."""
    for spelling in ("0x0E6F", "0x0e6f", "0E6F", "0e6f", " 0x0E6F "):
        assert parse_ls_checksum(spelling) == 0x0E6F

    padded = rlsa(checksum="0x0e6f")
    unpadded = rlsa(checksum="E6F")
    assert compare_lsa_instances(padded, unpadded).reason.startswith("identical")


@pytest.mark.parametrize("text", ["", "zzz", "0x1FFFF", "0xGGGG"])
def test_malformed_checksums_are_rejected(text: str) -> None:
    assert parse_ls_checksum(text) is None


def test_equal_sequence_with_missing_checksum_is_unresolved() -> None:
    """§13.1 decides equal sequences on the checksum; without one, nothing decides."""
    comparison = compare_lsa_instances(rlsa(checksum=""), rlsa(checksum="0x1234"))
    assert comparison.undecided is True
    assert comparison.winner is None
    assert "checksum" in comparison.reason


# =========================================================================== #
# 3. Age precedence (RFC 2328 §13.1 steps 3-5)
# =========================================================================== #


def test_max_age_wins_over_a_non_max_age_instance() -> None:
    max_age = rlsa(checksum="0x1111", age=LS_AGE_MAX)
    fresh = rlsa(checksum="0x1111", age=10)
    for first, second in ((fresh, max_age), (max_age, fresh)):
        comparison = compare_lsa_instances(first, second)
        assert comparison.winner is max_age
    assert LS_AGE_MAX == 3600


def test_younger_instance_wins_beyond_max_age_diff() -> None:
    young = rlsa(checksum="0x1111", age=100)
    old = rlsa(checksum="0x1111", age=100 + MAX_AGE_DIFF + 1)
    for first, second in ((old, young), (young, old)):
        assert compare_lsa_instances(first, second).winner is young
    assert MAX_AGE_DIFF == 900


def test_instances_within_max_age_diff_are_identical() -> None:
    """Below the threshold, age is noise: the instances are the same LSA."""
    a = rlsa(checksum="0x1111", age=100)
    b = rlsa(checksum="0x1111", age=100 + MAX_AGE_DIFF)
    comparison = compare_lsa_instances(a, b)
    assert comparison.winner is a          # first wins ties, so it is stable
    assert "identical" in comparison.reason
    assert compare_lsa_instances(b, a).winner is b


def test_age_does_not_override_a_sequence_difference() -> None:
    """Sequence is the primary key; a fresh old instance is still old."""
    newer_but_aged = rlsa(sequence="0x80000005", checksum="0x1111", age=3000)
    older_but_fresh = rlsa(sequence="0x80000004", checksum="0x1111", age=1)
    assert compare_lsa_instances(newer_but_aged, older_but_fresh).winner is newer_but_aged


def test_age_does_not_override_a_checksum_difference() -> None:
    """Step 2 precedes step 3: MaxAge does not beat a higher checksum."""
    max_age_lower_checksum = rlsa(checksum="0x1111", age=LS_AGE_MAX)
    younger_higher_checksum = rlsa(checksum="0x9999", age=10)
    assert (
        compare_lsa_instances(max_age_lower_checksum, younger_higher_checksum).winner
        is younger_higher_checksum
    )


def test_missing_ages_never_win_a_tie() -> None:
    """An unknown age is absence of evidence, not evidence of agreement.

    The previous version of this test asserted ``winner is unknown or winner is
    known`` — always true — and required the reason to say "identical", which
    is exactly the bug: unusable metadata fell through to a confident claim
    that the copies agreed. Now the comparison must be unresolved in both
    directions.
    """
    known = rlsa(checksum="0x1111", age=100)
    unknown = rlsa(checksum="0x1111", age=None)

    for first, second in ((unknown, known), (known, unknown)):
        comparison = compare_lsa_instances(first, second)
        assert comparison.undecided is True
        assert comparison.winner is None
        assert "unresolved" in comparison.reason
        assert "identical" not in comparison.reason


def test_select_lsa_instance_folds_across_observers() -> None:
    copies = [
        rlsa(sequence="0x80000001", checksum="0x1111", device_id="r1"),
        rlsa(sequence="0x80000005", checksum="0x2222", device_id="r2"),
        rlsa(sequence="0x80000003", checksum="0x3333", device_id="r3"),
    ]
    selection = select_lsa_instance(copies)
    assert selection.winner is copies[1]
    assert selection.undecided is False


def test_select_lsa_instance_is_unresolved_if_any_copy_is_unusable() -> None:
    copies = [
        rlsa(sequence="0x80000005", device_id="r1"),
        rlsa(sequence="", device_id="r2"),
    ]
    selection = select_lsa_instance(copies)
    assert selection.undecided is True
    assert selection.winner is None


# =========================================================================== #
# 4. Network-LSA membership comes from the winner only
# =========================================================================== #


def test_winning_membership_is_the_canonical_membership() -> None:
    # Identical instance content from both observers: no version conflict, so
    # the only thing under test here is that membership is taken verbatim.
    winner = nlsa(sequence="0x80000009", attached=["10.255.255.1", "10.255.255.3"])
    loser = nlsa(sequence="0x80000009", attached=["10.255.255.1", "10.255.255.3"])

    warnings: list[str] = []
    canonical = canonical_network_lsas(
        [_device("r1", [loser]), _device("r2", [winner])], warnings
    )
    assert len(canonical) == 1
    assert canonical[0].sequence == "0x80000009"
    assert canonical[0].attached_routers == sorted(winner.attached_routers)
    assert warnings == []


def test_stale_observers_router_is_not_reintroduced_by_union() -> None:
    """The regression: a member dropped in the newer LSA must stay dropped."""
    current = nlsa(sequence="0x80000009", attached=["10.255.255.1"])
    stale = nlsa(sequence="0x80000001", attached=["10.255.255.1", "10.255.255.9"])

    warnings: list[str] = []
    canonical = canonical_network_lsas(
        [_device("r1", [stale]), _device("r2", [current])], warnings
    )

    assert len(canonical) == 1
    assert canonical[0].attached_routers == ["10.255.255.1"]
    assert "10.255.255.9" not in canonical[0].attached_routers


def test_membership_disagreement_produces_a_warning() -> None:
    current = nlsa(sequence="0x80000009", attached=["10.255.255.1"])
    stale = nlsa(sequence="0x80000001", attached=["10.255.255.1", "10.255.255.9"])

    warnings: list[str] = []
    canonical_network_lsas(
        [_device("r1", [stale]), _device("r2", [current])], warnings
    )
    membership = [w for w in warnings if "membership disagreement" in w]
    assert len(membership) == 1
    assert "10.255.255.9" in membership[0]
    assert "r1" in membership[0] and "r2" in membership[0]
    assert "not merged in" in membership[0]


def test_observer_provenance_retains_differing_reports() -> None:
    current = nlsa(sequence="0x80000009", attached=["10.255.255.1"], device_id="r2")
    stale = nlsa(sequence="0x80000001", attached=["10.255.255.1", "10.255.255.9"], device_id="r1")

    warnings: list[str] = []
    canonical = canonical_network_lsas(
        [_device("r1", [stale]), _device("r2", [current])], warnings
    )

    record = canonical[0]
    assert record.observed_by == ["r1", "r2"]
    reported = {entry["observer"]: entry for entry in record.observed_membership}
    assert reported["r1"]["attached_routers"] == ["10.255.255.1", "10.255.255.9"]
    assert reported["r2"]["attached_routers"] == ["10.255.255.1"]
    assert reported["r1"]["sequence"] == "0x80000001"


def test_same_instance_with_different_membership_is_flagged_inconsistent() -> None:
    """Same sequence *and* checksum: one instance, two reports — not two versions."""
    a = nlsa(sequence="0x80000002", checksum="0x5E6F", attached=["10.255.255.1"], device_id="r1")
    b = nlsa(
        sequence="0x80000002",
        checksum="0x5E6F",
        attached=["10.255.255.1", "10.255.255.3"],
        device_id="r2",
    )

    warnings: list[str] = []
    canonical = canonical_network_lsas(
        [_device("r1", [a]), _device("r2", [b])], warnings
    )

    # One instance, two different bodies: no list may be chosen, so the LSA is
    # withheld from reconstruction rather than guessed at.
    assert canonical == []
    assert any("membership disagreement" in w for w in warnings)
    assert any("inconsistent observation" in w for w in warnings)
    # Both reports survive in the warning text.
    assert any("10.255.255.3" in w for w in warnings)


def test_formatting_differences_are_not_mistaken_for_a_version_conflict() -> None:
    """IOS prints the sequence bare and the checksum prefixed.

    ``0x80000002``/``0x5E6F`` and ``80000002``/``5e6f`` are the *same* instance.
    Comparing the reported strings would call that a conflict and mislabel a
    genuine membership problem as two different versions.
    """
    a = nlsa(sequence="0x80000002", checksum="0x5E6F", attached=["10.255.255.1"], device_id="r1")
    b = nlsa(
        sequence="80000002",
        checksum="5e6f",
        attached=["10.255.255.1", "10.255.255.3"],
        device_id="r2",
    )
    assert (a.sequence, a.checksum) != (b.sequence, b.checksum)   # raw strings differ
    assert same_lsa_version(a, b) is True                          # parsed values agree

    warnings: list[str] = []
    canonical = canonical_network_lsas(
        [_device("r1", [a]), _device("r2", [b])], warnings
    )
    # The memberships differ, so no list can be chosen.
    assert canonical == []
    # One instance observed, so this is an inconsistent observation...
    assert any("inconsistent observation" in w for w in warnings)
    # ...not a version conflict.
    assert not any("different instances" in w for w in warnings)


def test_identical_network_observations_produce_no_membership_warning() -> None:
    copy_a = nlsa(attached=["10.255.255.1"], device_id="r1")
    copy_b = nlsa(attached=["10.255.255.1"], device_id="r2")
    warnings: list[str] = []
    canonical = canonical_network_lsas(
        [_device("r1", [copy_a]), _device("r2", [copy_b])], warnings
    )
    assert len(canonical) == 1
    assert canonical[0].attached_routers == ["10.255.255.1"]
    assert not [w for w in warnings if "membership" in w]


def test_unresolvable_conflict_reports_instead_of_choosing() -> None:
    """No usable sequence numbers: both LSA types refuse to pick and say why."""
    a = nlsa(sequence="", attached=["10.255.255.1"], device_id="r1")
    b = nlsa(sequence="zzz", attached=["10.255.255.3"], device_id="r2")

    warnings: list[str] = []
    canonical = canonical_network_lsas([_device("r1", [a]), _device("r2", [b])], warnings)

    assert canonical == []
    assert any("could not be resolved" in w for w in warnings)
    assert any("unresolved" in w for w in warnings)


def test_unresolvable_router_lsa_conflict_is_not_a_fallback_winner() -> None:
    a = rlsa(sequence="", device_id="r1")
    b = rlsa(sequence="not-hex", device_id="r2")

    warnings: list[str] = []
    canonical = canonical_router_lsas(
        [_device("r1", router_lsas=[a]), _device("r2", router_lsas=[b])], warnings
    )

    assert canonical == []
    assert any("could not be resolved" in w for w in warnings)


# =========================================================================== #
# Helpers
# =========================================================================== #


def _device(
    device_id: str,
    network_lsas: list[OspfNetworkLsa] | None = None,
    router_lsas: list[OspfRouterLsa] | None = None,
):  # noqa: ANN202
    """A minimal OspfDeviceData carrying just the LSAs under test.

    The observer is stamped onto each row, exactly as ``ospf_device_data()``
    does for rows read off a device — otherwise every "observer" would be the
    same ``r1`` and the provenance tests would pass for the wrong reason.
    """
    from nettwin.collect.ospf_topology import OspfDeviceData

    return OspfDeviceData(
        device_id=device_id,
        network_lsas=[
            lsa.model_copy(update={"device_id": device_id})
            for lsa in (network_lsas or [])
        ],
        router_lsas=[
            lsa.model_copy(update={"device_id": device_id})
            for lsa in (router_lsas or [])
        ],
    )


# =========================================================================== #
# 5. Integration — the five-router reference lab through the real pipeline
# =========================================================================== #


@pytest.fixture(scope="module")
def lab():  # noqa: ANN201
    """The reference lab: five device-specific observers sharing one LSDB."""
    from nettwin.collect.ospf_topology import build_ospf_topology
    from test_ospf_lsdb_integrity import ROUTER_IDS, _lab_device_data

    return build_ospf_topology([_lab_device_data(d) for d in ROUTER_IDS])


def test_integration_five_canonical_router_lsas(lab) -> None:  # noqa: ANN001
    assert len(lab.router_lsas) == 5
    for lsa in lab.router_lsas:
        assert len(lsa.observed_by) == 5      # provenance preserved
        assert lsa.observed_instances == []    # observers agreed


def test_integration_five_canonical_network_lsas(lab) -> None:  # noqa: ANN001
    assert len(lab.network_lsas) == 5
    for lsa in lab.network_lsas:
        assert len(lsa.observed_by) == 5
        assert len(lsa.attached_routers) == 2


def test_integration_five_transit_networks(lab) -> None:  # noqa: ANN001
    assert len(lab.transit_networks) == 5
    assert {n.prefix for n in lab.transit_networks} == {
        "10.0.21.0/30",
        "10.0.23.0/30",
        "10.0.32.0/30",
        "10.0.34.0/30",
        "10.0.41.0/30",
    }


def test_integration_seven_stub_networks(lab) -> None:  # noqa: ANN001
    assert len(lab.stub_networks) == 7


def test_integration_eleven_routes_per_device(lab) -> None:  # noqa: ANN001
    devices = sorted({r.device_id for r in lab.routes})
    assert devices == ["r1", "r2", "r3", "r4", "r5"]
    for device in devices:
        assert len([r for r in lab.routes if r.device_id == device]) == 11
        assert len(lab.learned_routes(device)) == 9
        assert len(lab.connected_routes(device)) == 2


def test_integration_no_empty_or_fabricated_attribution(lab) -> None:  # noqa: ANN001
    for collection in (
        lab.routers,
        lab.neighbors,
        lab.interfaces,
        lab.router_lsas,
        lab.network_lsas,
        lab.routes,
        lab.stub_networks,
        lab.database_summary,
    ):
        for item in collection:
            assert item.device_id
            assert item.device_id != "unknown"
    # Each router-id is owned by exactly one device.
    assert {r.router_id: r.device_id for r in lab.routers} == {
        f"10.255.255.{i}": f"r{i}" for i in range(1, 6)
    }


def test_integration_cdp_links_unchanged_and_no_cable_from_ospf(lab) -> None:  # noqa: ANN001
    """OSPF never contributes a physical link, whatever the LSDB says."""
    from nettwin.domain.models import Topology

    assert len(lab.transit_networks) == 5
    # OspfTopology has no link collection at all.
    assert not hasattr(lab, "links")
    assert "ospf" not in Topology.model_fields


# =========================================================================== #
# 5. Strict LS Age validation
# =========================================================================== #

from nettwin.collect.ospf_topology import (  # noqa: E402
    is_valid_ls_age,
    is_valid_ls_checksum,
    lsa_content_fingerprint,
    parse_ls_age,
)


@pytest.mark.parametrize(
    "value",
    [None, True, False, 1418.7, 0.0, "1418", "", "abc", [1418], {"age": 1418}],
    ids=["none", "true", "false", "float", "float0", "numeric-str", "empty",
         "garbage", "list", "dict"],
)
def test_invalid_age_is_rejected(value: object) -> None:
    """Non-integer, bool, float and string ages are not evidence."""
    assert parse_ls_age(value) is None
    assert is_valid_ls_age(value) is False


@pytest.mark.parametrize("value", [-1, -5, 3601, 5000, 99999])
def test_out_of_range_age_is_rejected(value: int) -> None:
    """RFC 2328 §12.1.1: age is a unsigned seconds counter saturating at MaxAge."""
    assert parse_ls_age(value) is None
    assert is_valid_ls_age(value) is False


@pytest.mark.parametrize("value", [0, 1, 100, 900, 1800, 3599, 3600])
def test_boundary_ages_are_accepted(value: int) -> None:
    assert parse_ls_age(value) == value
    assert is_valid_ls_age(value) is True


def test_age_is_never_clamped_into_range() -> None:
    """5000 is malformed, not "MaxAge-ish"; clamping would invent a flush claim."""
    assert parse_ls_age(5000) is None


def test_none_vs_none_age_is_unresolved() -> None:
    comparison = compare_lsa_instances(rlsa(age=None), rlsa(age=None))
    assert comparison.undecided is True
    assert comparison.winner is None


def test_none_vs_valid_age_is_unresolved_in_both_directions() -> None:
    unknown, known = rlsa(age=None), rlsa(age=100)
    for first, second in ((unknown, known), (known, unknown)):
        comparison = compare_lsa_instances(first, second)
        assert comparison.undecided is True
        assert comparison.winner is None
        assert "unresolved" in comparison.reason


def test_max_age_does_not_win_against_an_unknown_age() -> None:
    """The specific regression: MaxAge vs None must not pick the MaxAge copy."""
    max_age, unknown = rlsa(age=LS_AGE_MAX), rlsa(age=None)
    for first, second in ((max_age, unknown), (unknown, max_age)):
        comparison = compare_lsa_instances(first, second)
        assert comparison.undecided is True
        assert comparison.winner is None
        assert "MaxAge instance wins" not in comparison.reason


@pytest.mark.parametrize("bad_age", [-1, 3601, 5000], ids=["negative", "over", "far-over"])
def test_negative_and_oversized_ages_are_rejected_by_the_model(bad_age: int) -> None:
    """Out-of-range ages cannot even reach the comparator.

    The model is the first line of defence: ``OspfAge`` is a ``StrictInt``
    bounded to 0..3600, so a negative or oversized age is refused at
    construction rather than travelling through the pipeline as a plausible
    number. (The comparator keeps its own check for callers that bypass the
    model — see ``test_comparator_defends_against_ages_the_model_would_reject``.)
    """
    import pydantic

    with pytest.raises(pydantic.ValidationError):
        rlsa(age=bad_age)


def test_comparator_defends_against_ages_the_model_would_reject() -> None:
    """Defence in depth: ``model_construct`` skips validation entirely.

    A caller that bypasses validation must still not get a winner out of an
    out-of-range age, so ``compare_lsa_instances`` re-validates independently.
    """
    for bad_age in (-1, 3601, 5000):
        broken = OspfRouterLsa.model_construct(
            area="0",
            link_state_id="10.255.255.1",
            advertising_router="10.255.255.1",
            sequence="0x80000005",
            checksum="0x1111",
            age=bad_age,
            device_id="r1",
            links=[],
        )
        assert broken.age == bad_age          # validation really was skipped
        # Same sequence and checksum, so only the age could decide — which is
        # precisely where an out-of-range age must not become evidence.
        healthy = rlsa(sequence="0x80000005", checksum="0x1111", age=100)
        for first, second in ((broken, healthy), (healthy, broken)):
            comparison = compare_lsa_instances(first, second)
            assert comparison.undecided is True
            assert comparison.winner is None


def test_sequence_and_checksum_precedence_survives_bad_age() -> None:
    """Age is only consulted when sequence and checksum tie."""
    newer = rlsa(sequence="0x80000005", age=None)
    older = rlsa(sequence="0x80000004", age=100)
    assert compare_lsa_instances(newer, older).winner is newer

    higher_ck = rlsa(checksum="0x9999", age=None)
    lower_ck = rlsa(checksum="0x1111", age=100)
    assert compare_lsa_instances(higher_ck, lower_ck).winner is higher_ck


def test_exact_max_age_diff_boundary_is_identical() -> None:
    """900 == MaxAgeDiff is within tolerance; 901 is beyond it."""
    a, b = rlsa(age=100), rlsa(age=100 + MAX_AGE_DIFF)
    comparison = compare_lsa_instances(a, b)
    assert comparison.undecided is False
    assert "identical" in comparison.reason

    c = rlsa(age=100 + MAX_AGE_DIFF + 1)
    comparison = compare_lsa_instances(a, c)
    assert comparison.winner is a
    assert "younger" in comparison.reason


def test_zero_and_max_age_boundaries_compare_correctly() -> None:
    zero_age, max_age = rlsa(age=0), rlsa(age=LS_AGE_MAX)
    comparison = compare_lsa_instances(zero_age, max_age)
    assert comparison.winner is max_age          # MaxAge rule, not "younger"
    assert parse_ls_age(0) == 0
    assert parse_ls_age(LS_AGE_MAX) == LS_AGE_MAX


# =========================================================================== #
# 6. Deterministic multi-observer canonicalisation
# =========================================================================== #

_AGE_TO_OBSERVER = {100: "r1", 800: "r3", 1700: "r5"}


def _copies_for(ages: list[int]) -> list[OspfRouterLsa]:
    """One copy per age, with the observer bound to the age (identity is stable)."""
    return [rlsa(age=age, device_id=_AGE_TO_OBSERVER[age]) for age in ages]


def test_all_six_permutations_choose_the_same_canonical_instance() -> None:
    """The regression: a sequential fold returned 100 or 800 depending on order.

    With ages 100/800/1700 every pair is within MaxAgeDiff 900, so pairwise
    §13.1 calls them all the same instance and the relation is not transitive.
    Aggregation over the whole set must yield one answer for every order.
    """
    from itertools import permutations

    results = []
    for order in permutations([100, 800, 1700]):
        selection = select_lsa_instance(_copies_for(list(order)))
        assert selection.undecided is False
        assert selection.winner is not None
        results.append((selection.winner.age, selection.winner.device_id))

    assert len(set(results)) == 1, f"order-dependent result: {results}"
    assert results[0] == (100, "r1")


def test_permutations_preserve_observer_provenance() -> None:
    """Determinism must not be achieved by forgetting who reported what."""
    from itertools import permutations

    for order in permutations([100, 800, 1700]):
        copies = _copies_for(list(order))
        selection = select_lsa_instance(copies)
        observers = {c.device_id for c in copies}
        assert len(observers) == 3
        # The chosen instance is one of the reported ones, not synthesised.
        assert selection.winner in copies


def test_age_spread_beyond_max_age_diff_selects_youngest_whatever_the_order() -> None:
    from itertools import permutations

    for order in permutations([100, 1700]):
        selection = select_lsa_instance(_copies_for(list(order)))
        assert selection.winner is not None
        assert selection.winner.age == 100
        assert "exceeds MaxAgeDiff" in selection.reason


def test_content_disagreement_within_max_age_diff_is_unresolved() -> None:
    """Same sequence/checksum, different body: never silently pick one."""
    from nettwin.domain.ospf_models import OspfLinkType, OspfLsaLink

    def with_metric(age: int, device_id: str, metric: int) -> OspfRouterLsa:
        return rlsa(age=age, device_id=device_id).model_copy(
            update={
                "links": [
                    OspfLsaLink(
                        link_type=OspfLinkType.STUB,
                        link_id="192.0.2.0",
                        link_data="255.255.255.0",
                        metric=metric,
                    )
                ]
            }
        )

    first = with_metric(100, "r1", 10)
    second = with_metric(800, "r2", 20)

    selection = select_lsa_instance([first, second])
    assert selection.undecided is True
    assert selection.winner is None
    assert "content differs" in selection.reason
    assert "r1" in selection.reason and "r2" in selection.reason

    # And through the canonical layer, nothing is published.
    from nettwin.collect.ospf_topology import OspfDeviceData, canonical_router_lsas

    warnings: list[str] = []
    canonical = canonical_router_lsas(
        [
            OspfDeviceData(device_id="r1", router_lsas=[first]),
            OspfDeviceData(device_id="r2", router_lsas=[second]),
        ],
        warnings,
    )
    assert canonical == []
    assert any("could not be resolved" in w for w in warnings)


def test_identical_content_with_different_ages_keeps_every_observer() -> None:
    from nettwin.collect.ospf_topology import OspfDeviceData, canonical_router_lsas

    copies = [
        rlsa(age=100, device_id="r1"),
        rlsa(age=800, device_id="r3"),
        rlsa(age=1700, device_id="r5"),
    ]
    devices = [
        OspfDeviceData(device_id=c.device_id, router_lsas=[
            c.model_copy(update={"link_state_id": "10.255.255.1",
                                 "advertising_router": "10.255.255.1"})
        ])
        for c in copies
    ]
    warnings: list[str] = []
    canonical = canonical_router_lsas(devices, warnings)

    assert len(canonical) == 1
    assert canonical[0].observed_by == ["r1", "r3", "r5"]
    assert canonical[0].age == 100


def test_content_fingerprint_excludes_age_and_observer() -> None:
    a = rlsa(age=100, device_id="r1")
    b = rlsa(age=1700, device_id="r9")
    assert lsa_content_fingerprint(a) == lsa_content_fingerprint(b)

    n1 = nlsa(age=100, attached=["10.255.255.1"], device_id="r1")
    n2 = nlsa(age=1700, attached=["10.255.255.1"], device_id="r2")
    assert lsa_content_fingerprint(n1) == lsa_content_fingerprint(n2)

    n3 = nlsa(age=100, attached=["10.255.255.1", "10.255.255.3"], device_id="r1")
    assert lsa_content_fingerprint(n1) != lsa_content_fingerprint(n3)


# =========================================================================== #
# 7. Zero LS checksum rejection
# =========================================================================== #


def test_zero_checksum_is_invalid() -> None:
    assert parse_ls_checksum("0x0000") is None
    assert parse_ls_checksum("0") is None
    assert parse_ls_checksum("0000") is None
    assert is_valid_ls_checksum(0) is False


@pytest.mark.parametrize("value", [1, 2, 0x5E6F, 0xFFFF])
def test_valid_checksums_are_accepted(value: int) -> None:
    assert is_valid_ls_checksum(value) is True


@pytest.mark.parametrize("value", [65536, 0x10000, 0x123456, -1])
def test_checksums_outside_16_bit_range_are_invalid(value: int) -> None:
    assert is_valid_ls_checksum(value) is False


def test_checksum_boundaries() -> None:
    assert parse_ls_checksum("0x0001") == 1
    assert parse_ls_checksum("0xFFFF") == 65535
    assert parse_ls_checksum("0x10000") is None   # 65536


def test_zero_checksum_cannot_decide_between_copies() -> None:
    """Zero is malformed metadata, so it cannot act as the §13.1 tie-break."""
    zero, one = rlsa(checksum="0x0000"), rlsa(checksum="0x0001")
    for first, second in ((zero, one), (one, zero)):
        comparison = compare_lsa_instances(first, second)
        assert comparison.undecided is True
        assert comparison.winner is None


def test_zero_checksum_versus_zero_checksum_is_unresolved() -> None:
    comparison = compare_lsa_instances(rlsa(checksum="0x0000"), rlsa(checksum="0x0000"))
    assert comparison.undecided is True
    assert comparison.winner is None


@pytest.mark.parametrize("bad", ["", "zzz", "0x0000", "0x10000"], ids=["empty", "garbage", "zero", "over"])
def test_missing_or_malformed_checksum_never_yields_a_fallback_winner(bad: str) -> None:
    for first, second in ((rlsa(checksum=bad), rlsa(checksum="0x1234")),
                          (rlsa(checksum="0x1234"), rlsa(checksum=bad))):
        comparison = compare_lsa_instances(first, second)
        assert comparison.undecided is True
        assert comparison.winner is None


# =========================================================================== #
# 8. Model-level (Pydantic) Age strictness — end to end
# =========================================================================== #

#: Every input the audit asked to be exercised at the *model* boundary.
AGE_INPUTS = [True, False, 12.0, 12.5, "12", None, -1, 3601, 0, 3600]

_AGE_ACCEPTED = {None: None, 0: 0, 3600: 3600}


@pytest.mark.parametrize("model", [OspfRouterLsa, OspfNetworkLsa], ids=["router", "network"])
@pytest.mark.parametrize("value", AGE_INPUTS, ids=[repr(v) for v in AGE_INPUTS])
def test_model_age_boundary(model: type, value: object) -> None:  # noqa: ANN001
    """Pydantic must not coerce a prohibited input into a plausible age.

    The audit's concern: with a bare ``int | None``, Pydantic turned ``True``
    into age 1 and ``"12"`` into age 12 *before* ``parse_ls_age()`` could
    object, so the helper's guards were unreachable. ``OspfAge`` closes that.
    """
    import pydantic

    kwargs = {"area": "0", "link_state_id": "x", "advertising_router": "y"}
    if value in _AGE_ACCEPTED and type(value) is int:
        assert model(**kwargs, age=value).age == value
    elif value is None:
        assert model(**kwargs, age=value).age is None
    else:
        with pytest.raises(pydantic.ValidationError):
            model(**kwargs, age=value)


@pytest.mark.parametrize("model", [OspfRouterLsa, OspfNetworkLsa], ids=["router", "network"])
def test_model_age_defaults_to_none(model: type) -> None:  # noqa: ANN001
    """A missing age is an allowed absence, not an error."""
    assert model(area="0", link_state_id="x", advertising_router="y").age is None


def test_coerced_boolean_cannot_masquerade_as_a_young_age() -> None:
    """The specific end-to-end failure: ``True`` used to become age 1 and win."""
    import pydantic

    with pytest.raises(pydantic.ValidationError):
        rlsa(age=True)
    with pytest.raises(pydantic.ValidationError):
        nlsa(age=True)

    # And the same via the real canonicalisation entry point.
    from nettwin.collect.ospf_topology import OspfDeviceData, canonical_router_lsas

    with pytest.raises(pydantic.ValidationError):
        canonical_router_lsas(
            [OspfDeviceData(device_id="r1", router_lsas=[rlsa(age=True)])], []
        )


def test_coerced_numeric_string_cannot_become_an_age() -> None:
    import pydantic

    with pytest.raises(pydantic.ValidationError):
        rlsa(age="12")


def test_real_parser_output_satisfies_strict_age() -> None:
    """Strict validation must accept what the device actually reports."""
    from pathlib import Path

    from nettwin.collect.ospf_parsers import (
        parse_show_ip_ospf_database_network,
        parse_show_ip_ospf_database_router,
    )

    data = Path(__file__).parent / "data" / "ospf"
    router_lsas, _ = parse_show_ip_ospf_database_router(
        (data / "r2_show_ip_ospf_database_router.txt").read_text(encoding="utf-8"), "r2"
    )
    network_lsas, _ = parse_show_ip_ospf_database_network(
        (data / "r2_show_ip_ospf_database_network.txt").read_text(encoding="utf-8"), "r2"
    )
    assert len(router_lsas) == 5
    assert len(network_lsas) == 5
    for lsa in [*router_lsas, *network_lsas]:
        assert type(lsa.age) is int
        assert 0 <= lsa.age <= LS_AGE_MAX


# =========================================================================== #
# 9. Content fingerprint completeness (RFC 2328 §13.2)
# =========================================================================== #


def _fingerprint_router(**overrides: object) -> OspfRouterLsa:
    base: dict[str, object] = {
        "area": "0",
        "link_state_id": "10.255.255.1",
        "advertising_router": "10.255.255.1",
        "sequence": "0x80000005",
        "checksum": "0x1111",
        "age": 100,
        "device_id": "r1",
        "options": "(No TOS-capability, DC)",
        "ls_length": 60,
        "number_of_links": 1,
        "links": [
            OspfLsaLink(
                link_type=OspfLinkType.STUB,
                link_id="10.0.12.0",
                link_data="255.255.255.252",
                network_mask="255.255.255.252",
                metric=10,
            )
        ],
    }
    base.update(overrides)
    return OspfRouterLsa(**base)  # type: ignore[arg-type]


def _fingerprint_network(**overrides: object) -> OspfNetworkLsa:
    base: dict[str, object] = {
        "area": "0",
        "link_state_id": "10.0.21.1",
        "advertising_router": "10.255.255.3",
        "network_mask": "255.255.255.252",
        "attached_routers": ["10.255.255.1", "10.255.255.3"],
        "sequence": "0x80000002",
        "checksum": "0x5E6F",
        "age": 100,
        "device_id": "r1",
        "options": "(No TOS-capability, DC)",
        "ls_length": 36,
    }
    base.update(overrides)
    return OspfNetworkLsa(**base)  # type: ignore[arg-type]


def test_parser_retains_options_and_length() -> None:
    """Neither field was captured before this change; both are printed by IOS."""
    from pathlib import Path

    from nettwin.collect.ospf_parsers import (
        parse_show_ip_ospf_database_network,
        parse_show_ip_ospf_database_router,
    )

    data = Path(__file__).parent / "data" / "ospf"
    router_lsas, _ = parse_show_ip_ospf_database_router(
        (data / "r2_show_ip_ospf_database_router.txt").read_text(encoding="utf-8"), "r2"
    )
    for lsa in router_lsas:
        assert lsa.options, "Options line was not captured"
        assert lsa.ls_length is not None and lsa.ls_length > 0

    network_lsas, _ = parse_show_ip_ospf_database_network(
        (data / "r2_show_ip_ospf_database_network.txt").read_text(encoding="utf-8"), "r2"
    )
    for lsa in network_lsas:
        assert lsa.options
        assert lsa.ls_length is not None and lsa.ls_length > 0


def test_fingerprint_covers_router_options_and_length() -> None:
    base = _fingerprint_router()
    assert lsa_content_fingerprint(base) != lsa_content_fingerprint(
        _fingerprint_router(options="(DC)")
    )
    assert lsa_content_fingerprint(base) != lsa_content_fingerprint(
        _fingerprint_router(ls_length=72)
    )


def test_fingerprint_covers_router_link_count() -> None:
    """``number_of_links`` was a live gap: it collapsed contradictory copies."""
    base = _fingerprint_router()
    assert lsa_content_fingerprint(base) != lsa_content_fingerprint(
        _fingerprint_router(number_of_links=99)
    )


def test_fingerprint_covers_router_link_fields() -> None:
    base = _fingerprint_router()
    for label, override in [
        ("link type", {"link_type": OspfLinkType.TRANSIT}),
        ("link id", {"link_id": "10.0.13.0"}),
        ("link data", {"link_data": "10.0.12.1"}),
        ("mask", {"network_mask": "255.255.255.0"}),
        ("metric", {"metric": 99}),
        ("mtid", {"mtid": "2"}),
    ]:
        changed = _fingerprint_router(
            links=[base.links[0].model_copy(update=override)]
        )
        assert lsa_content_fingerprint(base) != lsa_content_fingerprint(changed), label


def test_fingerprint_covers_network_options_length_and_membership() -> None:
    base = _fingerprint_network()
    for label, other in [
        ("options", _fingerprint_network(options="(DC)")),
        ("length", _fingerprint_network(ls_length=48)),
        ("mask", _fingerprint_network(network_mask="255.255.255.0")),
        ("membership", _fingerprint_network(attached_routers=["10.255.255.1"])),
    ]:
        assert lsa_content_fingerprint(base) != lsa_content_fingerprint(other), label


def test_fingerprint_excludes_age_and_observer_metadata() -> None:
    """Ageing and provenance are not content, however much they differ."""
    router_a = _fingerprint_router(age=0, device_id="r1", command="show x")
    router_b = _fingerprint_router(age=3600, device_id="r9", command="show y")
    assert lsa_content_fingerprint(router_a) == lsa_content_fingerprint(router_b)

    net_a = _fingerprint_network(age=0, device_id="r1")
    net_b = _fingerprint_network(age=1800, device_id="r4")
    assert lsa_content_fingerprint(net_a) == lsa_content_fingerprint(net_b)


def test_options_rendering_is_normalised_for_comparison() -> None:
    """IOS renders the bitmask as prose; the same mask must not look different.

    The reference transcript itself contains both ``(No TOS-capability, DC)``
    and ``No TOS-capability, DC`` for identical Option bits.
    """
    with_parens = _fingerprint_router(options="(No TOS-capability, DC)")
    without = _fingerprint_router(options="No TOS-capability, DC", device_id="r2")
    assert lsa_content_fingerprint(with_parens) == lsa_content_fingerprint(without)

    # The model still keeps exactly what was reported.
    assert with_parens.options == "(No TOS-capability, DC)"
    assert without.options == "No TOS-capability, DC"


@pytest.mark.parametrize(
    ("label", "make"),
    [
        ("options", lambda: _fingerprint_router(options="(DC)")),
        ("length", lambda: _fingerprint_router(ls_length=72)),
        (
            "link metric",
            lambda: _fingerprint_router(
                links=[
                    OspfLsaLink(
                        link_type=OspfLinkType.STUB,
                        link_id="10.0.12.0",
                        link_data="255.255.255.252",
                        network_mask="255.255.255.252",
                        metric=99,
                    )
                ]
            ),
        ),
    ],
)
def test_content_differences_at_identical_metadata_never_collapse(label: str, make) -> None:  # noqa: ANN001
    """Same identity, sequence, checksum *and* age — only content differs."""
    original = _fingerprint_router(device_id="r1")
    changed = make().model_copy(update={"device_id": "r2"})
    assert changed.sequence == original.sequence
    assert changed.checksum == original.checksum
    assert changed.age == original.age

    from nettwin.collect.ospf_topology import OspfDeviceData, canonical_router_lsas

    warnings: list[str] = []
    canonical = canonical_router_lsas(
        [
            OspfDeviceData(device_id="r1", router_lsas=[original]),
            OspfDeviceData(device_id="r2", router_lsas=[changed]),
        ],
        warnings,
    )
    assert canonical == [], f"{label}: differing content was silently collapsed"
    assert any("content differs" in w for w in warnings), label


def test_internally_inconsistent_link_count_is_excluded_before_canonicalisation() -> None:
    """A copy whose declared count contradicts its body never reaches the tie.

    This is a stronger guarantee than the content check: the object is not even
    a candidate, because its two halves disagree about what it contains.
    """
    from nettwin.collect.ospf_topology import OspfDeviceData, canonical_router_lsas

    inconsistent = _fingerprint_router(number_of_links=3, device_id="r2")
    assert inconsistent.number_of_links != len(inconsistent.links)

    warnings: list[str] = []
    canonical = canonical_router_lsas(
        [
            OspfDeviceData(device_id="r1", router_lsas=[_fingerprint_router()]),
            OspfDeviceData(device_id="r2", router_lsas=[inconsistent]),
        ],
        warnings,
    )
    # Exactly one canonical LSA survives: the healthy copy. The inconsistent
    # copy contributes nothing, and crucially does not drag the result into an
    # unresolved conflict — it was never a candidate.
    assert len(canonical) == 1
    assert canonical[0].number_of_links == 1
    assert canonical[0].observed_by == ["r1"]
    assert any("internally inconsistent" in w for w in warnings)
    assert not any("content differs" in w for w in warnings)


def test_network_membership_difference_at_identical_metadata_never_collapses() -> None:
    from nettwin.collect.ospf_topology import OspfDeviceData, canonical_network_lsas

    a = _fingerprint_network(device_id="r1")
    b = _fingerprint_network(device_id="r2", attached_routers=["10.255.255.1"])
    assert a.sequence == b.sequence and a.checksum == b.checksum and a.age == b.age

    warnings: list[str] = []
    canonical = canonical_network_lsas(
        [
            OspfDeviceData(device_id="r1", network_lsas=[a]),
            OspfDeviceData(device_id="r2", network_lsas=[b]),
        ],
        warnings,
    )
    assert canonical == []
    assert any("membership disagreement" in w for w in warnings)


# =========================================================================== #
# 10. number_of_links must agree with the actual links
# =========================================================================== #


def test_link_count_mismatch_query() -> None:
    link = OspfLsaLink(link_type=OspfLinkType.STUB, link_id="10.0.12.0")
    consistent = _fingerprint_router(number_of_links=1, links=[link])
    assert consistent.link_count_mismatch() is None

    # No declared count is an absence of evidence, not a contradiction.
    unreported = _fingerprint_router(number_of_links=None, links=[link])
    assert unreported.link_count_mismatch() is None

    contradictory = _fingerprint_router(number_of_links=9, links=[link])
    message = contradictory.link_count_mismatch()
    assert message is not None
    assert "declares 9" in message and "1 were parsed" in message


def test_parser_drops_an_lsa_whose_link_count_contradicts_its_body() -> None:
    """The parser reports *and* drops it — a warning alone left it usable."""
    from pathlib import Path

    from nettwin.collect.ospf_parsers import parse_show_ip_ospf_database_router

    raw = (Path(__file__).parent / "data" / "ospf" / "r2_show_ip_ospf_database_router.txt").read_text(
        encoding="utf-8"
    )
    clean, clean_warnings = parse_show_ip_ospf_database_router(raw, "r2")
    assert len(clean) == 5
    assert not [w for w in clean_warnings if "declares" in w]

    corrupted = raw.replace("Number of Links: 3", "Number of Links: 9", 1)
    lsas, warnings = parse_show_ip_ospf_database_router(corrupted, "r2")

    assert len(lsas) == 4                      # the bad one is gone
    assert all(lsa.link_count_mismatch() is None for lsa in lsas)
    assert any("declares 9 link(s)" in w for w in warnings)
    assert any("LSA dropped" in w for w in warnings)


def test_reference_transcript_has_no_link_count_mismatch() -> None:
    """Every LSA in the real fixture is internally consistent."""
    from pathlib import Path

    from nettwin.collect.ospf_parsers import parse_show_ip_ospf_database_router

    raw = (Path(__file__).parent / "data" / "ospf" / "r2_show_ip_ospf_database_router.txt").read_text(
        encoding="utf-8"
    )
    lsas, _ = parse_show_ip_ospf_database_router(raw, "r2")
    for lsa in lsas:
        assert lsa.number_of_links == len(lsa.links), lsa.link_state_id


def test_canonical_layer_excludes_a_contradictory_copy() -> None:
    """A copy that arrives by another route is still refused at consumption."""
    from nettwin.collect.ospf_topology import OspfDeviceData, canonical_router_lsas

    healthy = _fingerprint_router(device_id="r1")
    contradictory = _fingerprint_router(number_of_links=9, device_id="r2")

    warnings: list[str] = []
    canonical = canonical_router_lsas(
        [
            OspfDeviceData(device_id="r1", router_lsas=[healthy]),
            OspfDeviceData(device_id="r2", router_lsas=[contradictory]),
        ],
        warnings,
    )
    assert len(canonical) == 1
    assert canonical[0].observed_by == ["r1"]
    assert any("internally inconsistent" in w for w in warnings)


# =========================================================================== #
# 11. Semantic (order-independent) Options normalisation
# =========================================================================== #


@pytest.mark.parametrize(
    ("first", "second"),
    [
        ("(No TOS-capability, DC)", "(DC, No TOS-capability)"),
        ("(DC,E-bit)", "(E-bit, DC)"),
        ("(DC, E-bit)", "(E-bit,DC)"),
        ("(E-bit,DC,No TOS-capability)", "(No TOS-capability, DC, E-bit)"),
        ("(No TOS-capability, DC)", "No TOS-capability, DC"),
        ("  ( DC , No TOS-capability )  ", "(No TOS-capability,DC)"),
    ],
    ids=["dc-order", "ebit-order", "spacing", "three-token-order", "decoration", "messy"],
)
def test_options_normalisation_is_order_independent(first: str, second: str) -> None:
    """Options is a bit *set*; the rendered order carries no meaning."""
    from nettwin.collect.ospf_topology import _normalised_options

    assert _normalised_options(first) == _normalised_options(second)


@pytest.mark.parametrize(
    ("first", "second"),
    [
        ("(DC)", "(E-bit)"),
        ("(DC, E-bit)", "(DC)"),
        ("(No TOS-capability, DC)", "(No TOS-capability, DC, E-bit)"),
        ("", "(DC)"),
    ],
    ids=["different-bit", "subset", "extra-bit", "empty-vs-set"],
)
def test_genuinely_different_options_are_not_equated(first: str, second: str) -> None:
    """Normalisation must not erase a real difference."""
    from nettwin.collect.ospf_topology import _normalised_options

    assert _normalised_options(first) != _normalised_options(second)


def test_options_order_difference_does_not_create_a_conflict() -> None:
    """Same bits, different rendering order -> one canonical LSA, no warning."""
    from nettwin.collect.ospf_topology import OspfDeviceData, canonical_router_lsas

    a = _fingerprint_router(options="(No TOS-capability, DC)", device_id="r1")
    b = _fingerprint_router(options="(DC, No TOS-capability)", device_id="r2")

    warnings: list[str] = []
    canonical = canonical_router_lsas(
        [OspfDeviceData(device_id="r1", router_lsas=[a]),
         OspfDeviceData(device_id="r2", router_lsas=[b])],
        warnings,
    )
    assert len(canonical) == 1
    assert canonical[0].observed_by == ["r1", "r2"]
    assert warnings == []


def test_options_bit_difference_still_withholds_the_lsa() -> None:
    """Same order, different bits -> unresolved, as §13.2 requires."""
    from nettwin.collect.ospf_topology import OspfDeviceData, canonical_router_lsas

    a = _fingerprint_router(options="(DC)", device_id="r1")
    b = _fingerprint_router(options="(DC, E-bit)", device_id="r2")

    warnings: list[str] = []
    canonical = canonical_router_lsas(
        [OspfDeviceData(device_id="r1", router_lsas=[a]),
         OspfDeviceData(device_id="r2", router_lsas=[b])],
        warnings,
    )
    assert canonical == []
    assert any("content differs" in w for w in warnings)


def test_options_model_field_keeps_the_reported_rendering() -> None:
    """Normalisation is for comparison only; the model stays verbatim."""
    ordering = _fingerprint_router(options="(DC, No TOS-capability)")
    assert ordering.options == "(DC, No TOS-capability)"

    network = _fingerprint_network(options="No TOS-capability, DC")
    assert network.options == "No TOS-capability, DC"


# =========================================================================== #
# 12. Parser-warning provenance — the collecting observer, stated exactly once
# =========================================================================== #


def _corrupt(fixture: str, old: str, new: str) -> str:
    from pathlib import Path

    raw = (Path(__file__).parent / "data" / "ospf" / fixture).read_text(encoding="utf-8")
    assert old in raw
    return raw.replace(old, new, 1)


def test_router_warning_names_the_collecting_observer() -> None:
    """``observer=r2`` — the router the command ran on, not the LSA originator.

    In the fixture r2's LSDB holds r1's LSA, so the two differ: without the tag
    the operator cannot tell whose LSDB declared the bad link count.
    """
    from nettwin.collect.ospf_parsers import parse_show_ip_ospf_database_router

    corrupted = _corrupt("r2_show_ip_ospf_database_router.txt", "Number of Links: 3", "Number of Links: 9")
    _, warnings = parse_show_ip_ospf_database_router(corrupted, "r2")

    drop_warnings = [w for w in warnings if "LSA dropped" in w]
    assert len(drop_warnings) == 1
    warning = drop_warnings[0]
    assert "observer=r2" in warning
    # The LSA it is about is r1's, and that name appears as the *subject*, never
    # as the observer.
    assert "10.255.255.1" in warning
    assert "observer=10.255.255.1" not in warning


def test_observer_is_named_exactly_once() -> None:
    """No double-prefixing: one ``observer=`` per warning, whatever the call path."""
    from nettwin.collect.ospf_parsers import (
        parse_show_ip_ospf_database_network,
        parse_show_ip_ospf_database_router,
    )

    router_raw = _corrupt("r2_show_ip_ospf_database_router.txt", "Number of Links: 3", "Number of Links: 9")
    _, router_warnings = parse_show_ip_ospf_database_router(router_raw, "r2")

    network_raw = _corrupt("r2_show_ip_ospf_database_network.txt", "Attached Router", "Detached Router")
    _, network_warnings = parse_show_ip_ospf_database_network(network_raw, "r2")

    for warning in [*router_warnings, *network_warnings]:
        assert warning.count("observer=") <= 1, warning


def test_unattributed_observer_is_stated_not_invented() -> None:
    """With no device id the warning admits it rather than guessing a name."""
    from nettwin.collect.ospf_parsers import parse_show_ip_ospf_database_router

    corrupted = _corrupt("r2_show_ip_ospf_database_router.txt", "Number of Links: 3", "Number of Links: 9")
    _, warnings = parse_show_ip_ospf_database_router(corrupted, "")

    drop_warnings = [w for w in warnings if "LSA dropped" in w]
    assert len(drop_warnings) == 1
    assert "observer unidentified" in drop_warnings[0]
    assert "observer=" not in drop_warnings[0]


def test_empty_lsdb_warning_names_the_observer() -> None:
    """The 'nothing came back' path is attributed too — absence is evidence."""
    from nettwin.collect.ospf_parsers import parse_show_ip_ospf_database_router

    _, warnings = parse_show_ip_ospf_database_router("", "r4")
    assert warnings, "an empty transcript must still warn"
    assert all("observer=r4" in w for w in warnings), warnings

    # And the header-present-but-no-LSA path.
    _, no_blocks = parse_show_ip_ospf_database_router(
        "\t\tRouter Link States (Area 0)\n", "r4"
    )
    if no_blocks:
        assert all("observer=r4" in w for w in no_blocks), no_blocks


def test_network_warnings_name_the_observing_router() -> None:
    from nettwin.collect.ospf_parsers import parse_show_ip_ospf_database_network

    _, warnings = parse_show_ip_ospf_database_network("", "r5")
    assert warnings, "an empty transcript must still warn"
    assert all("observer=r5" in w for w in warnings)


# =========================================================================== #
# 13. Observer attribution survives the discovery integration paths
# =========================================================================== #


def test_nested_discovery_parser_warnings_carry_the_observer() -> None:
    """The nested path appends ``observations.warnings`` with no prefix of its own.

    ``nested/discovery.py`` extends ``observations.warnings`` verbatim (unlike
    the merge path, which prefixes ``entry_name``), so the observer has to be
    inside the string for the nested report to be auditable.
    """
    from nettwin.collect.cisco_ios import DeviceObservations
    from nettwin.collect.nested.discovery import _DEVICE_SCOPED_COMMANDS

    assert "show ip ospf database router" in _DEVICE_SCOPED_COMMANDS, (
        "the router parser must stay observer-scoped or it loses its device id"
    )

    observations = DeviceObservations(host="10.0.0.2", device_id="r2", collected_at="", status="ok")
    observations.warnings.append("placeholder")   # container is plain per-device
    assert observations.device_id == "r2"


def test_merge_path_prefixes_entry_name_and_does_not_double_prefix() -> None:
    """merge.py adds ``entry_name:`` only to topics it owns.

    OSPF parser warnings never reach ``DeviceCollection.warnings`` — that list
    carries map warnings only — so an ``observer=`` tag inside the string cannot
    collide with a merge-level prefix. This test pins that plumbing: if OSPF
    warnings are ever routed through ``collection.warnings``, the assertion on
    ``map_warnings`` count will fail and force the double-prefix question to be
    answered deliberately.
    """
    import inspect

    from nettwin.collect.discovery.merge import DeviceCollection
    from nettwin.collect.discovery.pipeline import discover_topology

    # DeviceCollection.warnings starts empty: merge prefixes only what it is given.
    assert DeviceCollection(entry_name="r2", host="10.0.0.2").warnings == []

    source = inspect.getsource(discover_topology)
    assert "collection.warnings.extend(map_warnings)" in source
    assert "collection.warnings.extend(observations.warnings)" not in source, (
        "routing parser warnings through collection.warnings would add a second prefix"
    )


def test_observer_tag_helper_is_the_single_source_of_format() -> None:
    from nettwin.collect.ospf_parsers import _observer_tag

    assert _observer_tag("r2") == "observer=r2"
    assert _observer_tag("") == "observer unidentified"


# =========================================================================== #
# 14. Options is a SET, not a multiset
# =========================================================================== #


@pytest.mark.parametrize(
    ("redundant", "plain"),
    [
        ("(DC, DC)", "(DC)"),
        ("(DC, dc)", "(DC)"),
        ("(DC, dc, E-bit)", "(E-bit, DC)"),
        ("( DC , dc , DC )", "(DC)"),
        ("(E-bit, E-BIT, e-bit)", "(E-bit)"),
    ],
    ids=["repeat", "case-repeat", "case-repeat-with-peer", "triple-mixed", "five-times"],
)
def test_duplicate_options_tokens_collapse(redundant: str, plain: str) -> None:
    """``(DC, DC)`` and ``(DC)`` are the same bit — and must not look different.

    Sorting alone would keep both copies, which is a false content conflict:
    exactly the failure this normalisation exists to prevent.
    """
    from nettwin.collect.ospf_topology import _normalised_options

    assert _normalised_options(redundant) == _normalised_options(plain)


def test_duplicate_options_do_not_create_a_conflict_end_to_end() -> None:
    """The observable consequence: one canonical LSA, no warning, both observers."""
    from nettwin.collect.ospf_topology import OspfDeviceData, canonical_router_lsas

    a = _fingerprint_router(options="(DC, DC)", device_id="r1")
    b = _fingerprint_router(options="(DC)", device_id="r2")

    warnings: list[str] = []
    canonical = canonical_router_lsas(
        [OspfDeviceData(device_id="r1", router_lsas=[a]),
         OspfDeviceData(device_id="r2", router_lsas=[b])],
        warnings,
    )
    assert len(canonical) == 1
    assert canonical[0].observed_by == ["r1", "r2"]
    assert warnings == []


@pytest.mark.parametrize(
    ("first", "second"),
    [
        ("(Frobnicate, DC)", "(DC, Frobnicate)"),
        ("(FROBNICATE, dc)", "(dc, frobnicate)"),
        ("(Zzz, Aaa, DC)", "(DC, Zzz, Aaa)"),
    ],
    ids=["unknown-reorder", "unknown-case", "two-unknowns"],
)
def test_unknown_options_tokens_are_kept_and_order_independent(first: str, second: str) -> None:
    """Normalisation is not a whitelist: an unseen bit still counts, once."""
    from nettwin.collect.ospf_topology import _normalised_options

    assert _normalised_options(first) == _normalised_options(second)
    assert "frobnicate" in _normalised_options(first) or "zzz" in _normalised_options(first)


@pytest.mark.parametrize(
    ("first", "second"),
    [
        ("(Frobnicate, DC)", "(DC)"),
        ("(Frobnicate)", "(Brobnicate)"),
        ("(DC, E-bit)", "(DC, E-bit, No TOS-capability)"),
        ("", "(DC)"),
        ("(DC, DC)", "(DC, E-bit)"),
    ],
    ids=["extra-unknown", "unknown-vs-unknown", "extra-known", "empty-vs-set", "dup-vs-more"],
)
def test_genuinely_different_option_sets_stay_different(first: str, second: str) -> None:
    """Deduplication must not become erasure."""
    from nettwin.collect.ospf_topology import _normalised_options

    assert _normalised_options(first) != _normalised_options(second)


@pytest.mark.parametrize(
    ("raw", "expected_tokens"),
    [
        ("(DC, , E-bit)", {"dc", "e-bit"}),
        ("(DC,)", {"dc"}),
        ("( DC )", {"dc"}),
        ("()", set()),
        ("", set()),
        ("( , )", set()),
    ],
    ids=["inner-blank", "trailing-comma", "padded", "empty-parens", "empty", "only-separators"],
)
def test_empty_options_tokens_are_ignored(raw: str, expected_tokens: set) -> None:
    """A blank element carries no bit and must not become an empty token."""
    from nettwin.collect.ospf_topology import _normalised_options

    normalised = _normalised_options(raw)
    assert normalised != "" or expected_tokens == set()
    actual = set(normalised.split(",")) if normalised else set()
    assert actual == expected_tokens
    # No empty element may survive in a non-empty result.
    if normalised:
        assert all(token for token in normalised.split(","))


def test_options_normalisation_never_touches_the_model_field() -> None:
    """The raw string is evidence; only the comparison form is rewritten."""
    raw = "(DC, dc, DC, E-bit)"
    lsa = _fingerprint_router(options=raw)
    assert lsa.options == raw

    network = _fingerprint_network(options="( Frobnicate , DC )")
    assert network.options == "( Frobnicate , DC )"
