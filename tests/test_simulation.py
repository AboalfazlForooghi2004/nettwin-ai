"""What-if simulation engine tests (TASK-005): impact + immutability."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from nettwin.data.loader import load_topology
from nettwin.domain.models import (
    DiagnosticFinding,
    DiagnosticStatus,
    FindingCode,
    FindingSeverity,
    LinkState,
    Topology,
)
from nettwin.errors import EndpointNotFoundError, ObjectNotFoundError
from nettwin.simulation import (
    ChangeType,
    SimulationReport,
    WhatIfEngine,
    compare_findings,
)
from nettwin.simulation import engine as simulation_module

ROUTE_ID = "leaf-a1-svc-10-100-1"
LINK_ID = "link-a-uplink"


@pytest.fixture
def healthy_topology(fixtures_dir: Path) -> Topology:
    return load_topology(fixtures_dir / "healthy.yaml")


@pytest.fixture
def whatif(healthy_topology: Topology) -> WhatIfEngine:
    return WhatIfEngine(healthy_topology)


# ----------------------------------------------------------------------
# Route removal simulation (Demo Case D)
# ----------------------------------------------------------------------


def test_route_removal_simulation_report(whatif: WhatIfEngine) -> None:
    report = whatif.simulate_route_removal(ROUTE_ID, "ep-a-app", "ep-pg")

    assert isinstance(report, SimulationReport)
    assert report.simulation_id
    assert report.change.type is ChangeType.REMOVE_ROUTE
    assert report.change.target_id == ROUTE_ID
    assert report.change.description.startswith("remove route leaf-a1-svc")
    assert "10.100.1.0/24" in report.change.description

    # Baseline healthy → simulated failure.
    assert report.baseline_status is DiagnosticStatus.REACHABLE
    assert report.simulated_status is DiagnosticStatus.UNREACHABLE

    # New finding: the missing route; nothing resolved/unchanged.
    assert [f.code for f in report.new_findings] == [FindingCode.MISSING_ROUTE]
    assert report.resolved_findings == []
    assert report.unchanged_findings == []
    assert report.affected_endpoints == ["ep-a-app", "ep-pg"]
    assert report.limitations  # simulation + model limitations documented

    # The original topology stays healthy (re-analyze on the baseline).
    from nettwin.diagnostics import DiagnosticEngine
    from nettwin.graph import NetworkGraph

    recheck = DiagnosticEngine(NetworkGraph(whatif.topology)).analyze(
        "ep-a-app", "ep-pg"
    )
    assert recheck.status is DiagnosticStatus.REACHABLE


def test_route_removal_keeps_original_route(whatif: WhatIfEngine) -> None:
    before_ids = {route.id for route in whatif.topology.routes}
    whatif.simulate_route_removal(ROUTE_ID, "ep-a-app", "ep-pg")
    after_ids = {route.id for route in whatif.topology.routes}
    assert after_ids == before_ids
    assert ROUTE_ID in after_ids
    route = next(r for r in whatif.topology.routes if r.id == ROUTE_ID)
    assert route.active is True
    assert str(route.destination_prefix) == "10.100.1.0/24"


# ----------------------------------------------------------------------
# Link failure simulation
# ----------------------------------------------------------------------


def test_link_failure_simulation_report(whatif: WhatIfEngine) -> None:
    report = whatif.simulate_link_failure(LINK_ID, "ep-a-app", "ep-pg")

    assert report.change.type is ChangeType.DISABLE_LINK
    assert report.change.target_id == LINK_ID
    assert "link-a-uplink" in report.change.description
    assert report.baseline_status is DiagnosticStatus.REACHABLE
    assert report.simulated_status is DiagnosticStatus.UNREACHABLE
    assert [f.code for f in report.new_findings] == [FindingCode.LINK_DOWN]
    assert report.affected_endpoints == ["ep-a-app", "ep-pg"]

    link = next(link for link in whatif.topology.links if link.id == LINK_ID)
    assert link.state is LinkState.UP  # original unchanged


def test_link_failure_does_not_affect_other_path(
    whatif: WhatIfEngine,
) -> None:
    # Tenant B's uplink is irrelevant to Tenant A -> PostgreSQL.
    report = whatif.simulate_link_failure(
        "link-b-uplink", "ep-a-app", "ep-pg"
    )
    assert report.baseline_status is DiagnosticStatus.REACHABLE
    assert report.simulated_status is DiagnosticStatus.REACHABLE
    assert report.new_findings == []
    assert report.resolved_findings == []
    assert report.affected_endpoints == []
    link = next(
        link for link in whatif.topology.links if link.id == "link-b-uplink"
    )
    assert link.state is LinkState.UP


def test_irrelevant_route_removal_keeps_status(whatif: WhatIfEngine) -> None:
    # Removing Tenant B's service route does not affect Tenant A's path.
    report = whatif.simulate_route_removal(
        "leaf-b1-svc-10-100-1", "ep-a-app", "ep-pg"
    )
    assert report.baseline_status is DiagnosticStatus.REACHABLE
    assert report.simulated_status is DiagnosticStatus.REACHABLE
    assert report.new_findings == []
    assert report.unchanged_findings == []
    assert report.affected_endpoints == []


# ----------------------------------------------------------------------
# Comparison against an already-broken baseline
# ----------------------------------------------------------------------


def test_unchanged_findings_on_broken_baseline(fixtures_dir: Path) -> None:
    topology = load_topology(fixtures_dir / "missing_route.yaml")
    whatif = WhatIfEngine(topology)
    # Disabling Tenant B's uplink cannot change Tenant A's earlier failure.
    report = whatif.simulate_link_failure(
        "link-b-uplink", "ep-a-app", "ep-pg"
    )

    assert report.baseline_status is DiagnosticStatus.UNREACHABLE
    assert report.simulated_status is DiagnosticStatus.UNREACHABLE
    assert [f.code for f in report.unchanged_findings] == [
        FindingCode.MISSING_ROUTE
    ]
    assert report.new_findings == []
    assert report.resolved_findings == []
    assert report.affected_endpoints == []


def test_resolved_findings_when_failure_moves_earlier(
    fixtures_dir: Path,
) -> None:
    """Baseline fails at the service link; the simulation fails earlier."""
    topology = load_topology(fixtures_dir / "healthy.yaml")
    link = next(link for link in topology.links if link.id == "link-svc")
    link.state = LinkState.DOWN  # baseline model is broken at the last hop
    whatif = WhatIfEngine(topology)

    report = whatif.simulate_route_removal(ROUTE_ID, "ep-a-app", "ep-pg")

    assert report.baseline_status is DiagnosticStatus.UNREACHABLE
    assert report.simulated_status is DiagnosticStatus.UNREACHABLE
    # The old LINK_DOWN is resolved (never reached) and MISSING_ROUTE appears.
    assert [f.code for f in report.new_findings] == [FindingCode.MISSING_ROUTE]
    assert [f.code for f in report.resolved_findings] == [FindingCode.LINK_DOWN]
    assert report.unchanged_findings == []
    assert report.affected_endpoints == ["ep-a-app", "ep-pg"]
    # Original baseline model still has the down link and the route.
    assert link.state is LinkState.DOWN
    assert ROUTE_ID in {r.id for r in topology.routes}


# ----------------------------------------------------------------------
# Immutability / independence / reproducibility
# ----------------------------------------------------------------------


def test_repeated_simulations_are_independent(whatif: WhatIfEngine) -> None:
    first = whatif.simulate_route_removal(ROUTE_ID, "ep-a-app", "ep-pg")
    second = whatif.simulate_link_failure(LINK_ID, "ep-a-app", "ep-pg")
    third = whatif.simulate_route_removal(ROUTE_ID, "ep-a-app", "ep-pg")

    assert len({first.simulation_id, second.simulation_id, third.simulation_id}) == 3
    for report in (first, third):
        assert report.baseline_status is DiagnosticStatus.REACHABLE
        assert report.simulated_status is DiagnosticStatus.UNREACHABLE
        assert [f.code for f in report.new_findings] == [
            FindingCode.MISSING_ROUTE
        ]
    assert [f.code for f in second.new_findings] == [FindingCode.LINK_DOWN]

    # Original model untouched after all runs.
    assert ROUTE_ID in {r.id for r in whatif.topology.routes}
    assert all(link.state is LinkState.UP for link in whatif.topology.links)


def test_baseline_results_are_reproducible(whatif: WhatIfEngine) -> None:
    first = whatif.simulate_route_removal(ROUTE_ID, "ep-a-app", "ep-pg")
    second = whatif.simulate_route_removal(ROUTE_ID, "ep-a-app", "ep-pg")
    assert first.baseline_status == second.baseline_status
    assert [f.id for f in first.baseline_findings] == [
        f.id for f in second.baseline_findings
    ]
    assert [f.id for f in first.simulated_findings] == [
        f.id for f in second.simulated_findings
    ]
    # Each run is its own simulation.
    assert first.simulation_id != second.simulation_id


def test_simulation_deep_copies_not_shares_objects(
    healthy_topology: Topology,
) -> None:
    whatif = WhatIfEngine(healthy_topology)
    original_route = next(r for r in healthy_topology.routes if r.id == ROUTE_ID)
    whatif.simulate_route_removal(ROUTE_ID, "ep-a-app", "ep-pg")
    # Original route object still present and identical in value.
    assert original_route in healthy_topology.routes
    assert original_route.active is True


# ----------------------------------------------------------------------
# Errors
# ----------------------------------------------------------------------


def test_unknown_route_id_raises(whatif: WhatIfEngine) -> None:
    with pytest.raises(ObjectNotFoundError, match="route not found: 'ghost'"):
        whatif.simulate_route_removal("ghost", "ep-a-app", "ep-pg")


def test_unknown_link_id_raises(whatif: WhatIfEngine) -> None:
    with pytest.raises(ObjectNotFoundError, match="link not found: 'ghost'"):
        whatif.simulate_link_failure("ghost", "ep-a-app", "ep-pg")


def test_unknown_endpoint_raises(whatif: WhatIfEngine) -> None:
    with pytest.raises(EndpointNotFoundError):
        whatif.simulate_route_removal(ROUTE_ID, "ghost", "ep-pg")


def test_invalid_target_checked_before_analysis(whatif: WhatIfEngine) -> None:
    # Invalid target fails fast — no analysis side effects needed.
    with pytest.raises(ObjectNotFoundError):
        whatif.simulate_route_removal("ghost", "ghost-src", "ghost-dst")


# ----------------------------------------------------------------------
# Finding comparison helper
# ----------------------------------------------------------------------


def _finding(finding_id: str, code: FindingCode = FindingCode.MISSING_ROUTE):
    return DiagnosticFinding(
        id=finding_id,
        code=code,
        severity=FindingSeverity.HIGH,
        title=f"t-{finding_id}",
        description="d",
        evidence=[],
        recommendations=[],
        status=DiagnosticStatus.UNREACHABLE,
    )


def test_compare_findings_partitions_by_id() -> None:
    baseline = [_finding("A"), _finding("B")]
    simulated = [_finding("B"), _finding("C"), _finding("D")]
    new, resolved, unchanged = compare_findings(baseline, simulated)
    assert [f.id for f in new] == ["C", "D"]
    assert [f.id for f in resolved] == ["A"]
    assert [f.id for f in unchanged] == ["B"]


def test_compare_findings_identical_inputs_all_unchanged() -> None:
    findings = [_finding("A"), _finding("B")]
    new, resolved, unchanged = compare_findings(findings, list(findings))
    assert new == [] and resolved == []
    assert [f.id for f in unchanged] == ["A", "B"]


# ----------------------------------------------------------------------
# Report serialization + safety
# ----------------------------------------------------------------------


def test_report_is_json_serializable(whatif: WhatIfEngine) -> None:
    report = whatif.simulate_route_removal(ROUTE_ID, "ep-a-app", "ep-pg")
    payload = report.model_dump(mode="json")
    assert payload["baseline_status"] == "reachable"
    assert payload["simulated_status"] == "unreachable"
    assert payload["change"]["type"] == "remove_route"
    assert isinstance(payload["new_findings"], list)
    assert payload["new_findings"][0]["code"] == "MISSING_ROUTE"
    assert payload["new_findings"][0]["evidence"]


def test_simulation_module_imports_no_execution_capability() -> None:
    """The simulation layer must not gain shell/SSH/network-write abilities."""
    source = simulation_module.__file__
    assert source is not None
    tree = ast.parse(Path(source).read_text(encoding="utf-8"))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    forbidden = {"subprocess", "paramiko", "socket", "requests", "http", "os"}
    assert imported.isdisjoint(forbidden), sorted(imported & forbidden)
