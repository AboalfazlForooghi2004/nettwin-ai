"""Phase 2.6 — the OSPF view as it lands on disk. **OFFLINE.**

Phase 2.5 proved the physical `topology.yaml` / `topology.svg` / `topology.html`
trio. This module extends that contract to OSPF and pins the two things that
matter most to a consumer of these files:

1. **backward compatibility** — the physical `topology.yaml` keeps its exact
   Phase 2.5 shape, with OSPF attached as a *sibling* key. A reader written
   against the old schema still works.
2. **separation** — no OSPF relationship ever appears in `links`, and the OSPF
   payload never contains a link object.

These assertions run against the real objects the discovery walk produces.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
import yaml

TESTS = Path(__file__).parent
if str(TESTS) not in sys.path:
    sys.path.insert(0, str(TESTS))

from nettwin.render import render_ospf_html, render_ospf_svg  # noqa: E402
from test_ospf_recursive import _run  # noqa: E402


@pytest.fixture(scope="module")
def result():  # noqa: ANN201 - RecursiveDiscoveryResult
    return _run(ospf=True)


@pytest.fixture(scope="module")
def topology_document(result):  # noqa: ANN001, ANN201
    """Exactly what ``discover_recursive.py`` writes to ``topology.yaml``."""
    document = result.topology.model_dump(mode="json")
    if getattr(result, "ospf_topology", None) is not None:
        document["ospf"] = result.ospf_topology.model_dump(mode="json")
    return document


# =========================================================================== #
# 1. Backward compatibility of topology.yaml
# =========================================================================== #


def test_physical_document_keeps_its_phase_2_5_shape(result, topology_document) -> None:
    """Every Phase 2.5 key is still present, with the same type."""
    for key in ("devices", "interfaces", "links", "routes"):
        assert key in topology_document
    assert isinstance(topology_document["devices"], list)
    assert isinstance(topology_document["interfaces"], list)
    assert isinstance(topology_document["links"], list)
    assert len(topology_document["devices"]) == len(result.topology.devices)


def test_ospf_is_a_sibling_key_not_a_field_of_topology(result, topology_document) -> None:
    """`Topology` itself is untouched — it forbids unknown fields by design."""
    from nettwin.domain.models import Topology

    assert "ospf" not in Topology.model_fields
    assert "ospf" in topology_document
    # ... and the OSPF key does not leak into the model round-trip.
    stripped = {k: v for k, v in topology_document.items() if k != "ospf"}
    assert Topology.model_validate(stripped).links == result.topology.links


def test_document_survives_a_yaml_round_trip(topology_document) -> None:
    text = yaml.safe_dump(topology_document, sort_keys=False, allow_unicode=True)
    reloaded = yaml.safe_load(text)
    assert reloaded["ospf"]["routers"]
    assert len(reloaded["ospf"]["transit_networks"]) == 5
    # Nothing exotic was serialized (no Python objects, no sets).
    assert all(isinstance(v, (str, int, float, bool, list, dict, type(None)))
               for v in yaml.safe_load(yaml.safe_dump(topology_document)).keys())


# =========================================================================== #
# 2. Separation: OSPF never becomes a link
# =========================================================================== #


def test_ospf_contributes_zero_links(result, topology_document) -> None:
    """The walk has no CDP peers, so links must be empty with OSPF on."""
    assert topology_document["links"] == []
    assert result.topology.links == []


def test_ospf_document_contains_no_link_objects(topology_document) -> None:
    blob = yaml.safe_dump(topology_document["ospf"], default_flow_style=False)
    for forbidden in ("source_interface_id", "destination_interface_id"):
        assert forbidden not in blob


def test_transit_networks_are_not_in_the_physical_links(result, topology_document) -> None:
    link_blob = yaml.safe_dump(topology_document["links"])
    for network in result.ospf_topology.transit_networks:
        assert network.dr_address not in link_blob


# =========================================================================== #
# 3. What the OSPF section must contain
# =========================================================================== #


def test_transit_networks_are_serialized_with_full_provenance(topology_document) -> None:
    networks = topology_document["ospf"]["transit_networks"]
    assert len(networks) == 5
    for network in networks:
        for key in (
            "id", "area", "prefix", "dr_address", "advertising_router",
            "member_router_ids", "member_interface_addresses", "state",
            "evidence", "source_lsas",
        ):
            assert key in network, key
        assert network["state"] == "confirmed"
        assert network["source_lsas"]
        assert network["member_interface_addresses"]


def test_router_lsas_and_network_lsas_are_both_present(topology_document) -> None:
    ospf = topology_document["ospf"]
    assert len(ospf["router_lsas"]) == 5
    assert len(ospf["network_lsas"]) == 5


def test_stub_prefixes_are_kept_apart_from_links(topology_document) -> None:
    stubs = topology_document["ospf"]["stub_networks"]
    assert len(stubs) == 7
    for stub in stubs:
        # A stub is a prefix with provenance — never a set of attachments.
        assert {"prefix", "area", "metric", "advertising_router"} <= set(stub)
        assert "member_router_ids" not in stub
        assert "member_interface_addresses" not in stub
        assert "dr_address" not in stub
        assert stub["source_lsa"], "a stub must cite the Router LSA it came from"


def test_routes_are_kept_apart_from_topology_evidence(topology_document) -> None:
    routes = topology_document["ospf"]["routes"]
    assert len(routes) == 11
    connected = [r for r in routes if not r["learned"]]
    assert {r["prefix"] for r in connected} == {"10.0.23.0/30", "10.255.255.2/32"}


def test_11_2_networks_are_not_ospf_learned(topology_document) -> None:
    prefixes = {r["prefix"] for r in topology_document["ospf"]["routes"]}
    assert "10.0.12.0/30" not in prefixes
    assert "10.0.12.4/30" not in prefixes


def test_no_credentials_anywhere_in_the_document(topology_document) -> None:
    blob = yaml.safe_dump(topology_document).lower()
    for needle in ("password", "secret", "md5", "key-string", "username", "enable"):
        assert needle not in blob, needle


# =========================================================================== #
# 4. discovery.yaml-style audit
# =========================================================================== #


def test_ospf_audit_helper_records_states_and_lsa_refs(result) -> None:
    sys.path.insert(0, str(TESTS.parent / "scripts"))
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "discover_recursive", TESTS.parent / "scripts" / "discover_recursive.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    audit = module._ospf_audit(result.ospf_topology)
    assert audit["collected"] is True
    assert len(audit["transit_networks"]) == 5
    assert audit["state_counts"] == {"confirmed": 5}
    assert audit["routes"]["learned"] == 9
    assert audit["routes"]["connected"] == 2
    for network in audit["transit_networks"]:
        assert network["source_lsas"]
        assert network["member_interface_addresses"]

    # and the no-OSPF branch is honest rather than empty
    absent = module._ospf_audit(None)
    assert absent["collected"] is False
    assert "no OSPF evidence" in absent["note"]


def test_link_audit_is_untouched_by_ospf(result) -> None:
    sys.path.insert(0, str(TESTS.parent / "scripts"))
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "discover_recursive_links", TESTS.parent / "scripts" / "discover_recursive.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    audit = module._link_audit(result)
    assert audit["confirmed"] == 0


# =========================================================================== #
# 5. The rendered files
# =========================================================================== #


def test_rendered_ospf_files_are_written_and_reloadable(result, tmp_path) -> None:
    svg = tmp_path / "ospf.svg"
    html = tmp_path / "ospf.html"
    svg.write_text(
        render_ospf_svg(result.ospf_topology, title="lab", physical=result.topology),
        encoding="utf-8",
    )
    html.write_text(
        render_ospf_html(result.ospf_topology, title="lab"), encoding="utf-8"
    )
    assert svg.read_text(encoding="utf-8").startswith("<svg")
    assert html.read_text(encoding="utf-8").startswith("<!DOCTYPE html>")
    assert svg.stat().st_size > 1000
    assert html.stat().st_size > 10000


def test_ospf_view_without_physical_evidence_still_renders(result) -> None:
    """A consumer with only the OSPF section (no Topology) can still draw it."""
    svg = render_ospf_svg(result.ospf_topology, title="lab")
    assert "CDP cable" not in svg
    assert "transit network (Type 2)" in svg
