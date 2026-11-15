"""Safe what-if simulation engine (TASK-005).

Simulates hypothetical changes — removing a route or disabling a link — on a
deep copy of the network model, then compares baseline vs simulated
diagnostics into a structured impact report.

Safety rules
------------
- The original topology is NEVER modified: every simulation starts from
  ``copy.deepcopy`` of the baseline model.
- No real devices are contacted; no shell commands; no configuration
  deployment. Read-only analysis of modeled state.
"""

from __future__ import annotations

import copy
import logging
import uuid
from collections.abc import Callable
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from nettwin.diagnostics import BASE_LIMITATIONS, DiagnosticEngine
from nettwin.domain.models import (
    DiagnosticFinding,
    DiagnosticResult,
    DiagnosticStatus,
    LinkState,
    Topology,
)
from nettwin.errors import ObjectNotFoundError
from nettwin.graph import NetworkGraph

logger = logging.getLogger("nettwin.simulation")

SIMULATION_LIMITATIONS: list[str] = [
    "Simulation runs on a deep copy of the topology; the original model is "
    "unchanged.",
    "Only the analyzed source/destination pair is re-evaluated; other "
    "endpoints may also be impacted by this change.",
    "No live devices are contacted; results reflect modeled state only.",
]


class ChangeType(StrEnum):
    """Supported hypothetical change types (MVP)."""

    REMOVE_ROUTE = "remove_route"
    DISABLE_LINK = "disable_link"


class SimulationChange(BaseModel):
    """Description of the hypothetical change that was simulated."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    type: ChangeType
    target_id: str = Field(min_length=1)
    description: str = Field(min_length=1)


class SimulationReport(BaseModel):
    """Structured baseline-vs-simulated impact report."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    simulation_id: str = Field(min_length=1)
    change: SimulationChange
    source_id: str
    destination_id: str
    baseline_status: DiagnosticStatus
    simulated_status: DiagnosticStatus
    baseline_findings: list[DiagnosticFinding] = Field(default_factory=list)
    simulated_findings: list[DiagnosticFinding] = Field(default_factory=list)
    new_findings: list[DiagnosticFinding] = Field(default_factory=list)
    resolved_findings: list[DiagnosticFinding] = Field(default_factory=list)
    unchanged_findings: list[DiagnosticFinding] = Field(default_factory=list)
    affected_endpoints: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


def compare_findings(
    baseline: list[DiagnosticFinding],
    simulated: list[DiagnosticFinding],
) -> tuple[list[DiagnosticFinding], list[DiagnosticFinding], list[DiagnosticFinding]]:
    """Split findings into (new, resolved, unchanged).

    Findings are matched by their deterministic ids (``code:subject``), so
    the same modeled problem compares equal across two analyses.
    """
    baseline_ids = {finding.id for finding in baseline}
    simulated_ids = {finding.id for finding in simulated}
    new = [finding for finding in simulated if finding.id not in baseline_ids]
    resolved = [finding for finding in baseline if finding.id not in simulated_ids]
    unchanged = [finding for finding in simulated if finding.id in baseline_ids]
    return new, resolved, unchanged


def _dedupe(items: list[str]) -> list[str]:
    return list(dict.fromkeys(items))


class WhatIfEngine:
    """Evaluates hypothetical changes against a baseline topology."""

    def __init__(self, topology: Topology) -> None:
        self._topology = topology

    @property
    def topology(self) -> Topology:
        """The baseline topology (never modified by simulations)."""
        return self._topology

    # ------------------------------------------------------------------
    # Public operations
    # ------------------------------------------------------------------

    def simulate_route_removal(
        self, route_id: str, source_id: str, destination_id: str
    ) -> SimulationReport:
        """Simulate removing a route, without touching the original model.

        Raises:
            ObjectNotFoundError: If ``route_id`` is not in the topology.
            EndpointNotFoundError: If either endpoint id is unknown.
        """
        route = next(
            (r for r in self._topology.routes if r.id == route_id), None
        )
        if route is None:
            raise ObjectNotFoundError("route", route_id)
        description = (
            f"remove route {route.id} ({route.destination_prefix} on "
            f"{route.device_id} in VRF {route.vrf_id})"
        )
        return self._simulate(
            ChangeType.REMOVE_ROUTE,
            route_id,
            description,
            source_id,
            destination_id,
            _apply_route_removal,
        )

    def simulate_link_failure(
        self, link_id: str, source_id: str, destination_id: str
    ) -> SimulationReport:
        """Simulate disabling a link, without touching the original model.

        Raises:
            ObjectNotFoundError: If ``link_id`` is not in the topology.
            EndpointNotFoundError: If either endpoint id is unknown.
        """
        link = next(
            (link for link in self._topology.links if link.id == link_id), None
        )
        if link is None:
            raise ObjectNotFoundError("link", link_id)
        description = (
            f"disable link {link.id} "
            f"({link.source_interface_id} <-> {link.destination_interface_id})"
        )
        return self._simulate(
            ChangeType.DISABLE_LINK,
            link_id,
            description,
            source_id,
            destination_id,
            _apply_link_failure,
        )

    # ------------------------------------------------------------------
    # Workflow
    # ------------------------------------------------------------------

    def _simulate(
        self,
        change_type: ChangeType,
        target_id: str,
        description: str,
        source_id: str,
        destination_id: str,
        apply_change: Callable[[Topology, str], None],
    ) -> SimulationReport:
        # 1-2. Baseline diagnostics on the ORIGINAL topology.
        baseline = _analyze(self._topology, source_id, destination_id)

        # 3-4. Independent copy + hypothetical change.
        simulated_topology = copy.deepcopy(self._topology)
        apply_change(simulated_topology, target_id)

        # 5. Diagnostics against the simulated model.
        simulated = _analyze(simulated_topology, source_id, destination_id)

        # 6. Comparison.
        new_findings, resolved_findings, unchanged_findings = compare_findings(
            baseline.findings, simulated.findings
        )

        affected: set[str] = set()
        if baseline.status != simulated.status:
            affected.update({source_id, destination_id})
        for finding in new_findings + resolved_findings:
            if finding.source_id:
                affected.add(finding.source_id)
            if finding.destination_id:
                affected.add(finding.destination_id)

        # 7. Structured impact report.
        report = SimulationReport(
            simulation_id=uuid.uuid4().hex[:16],
            change=SimulationChange(
                type=change_type, target_id=target_id, description=description
            ),
            source_id=source_id,
            destination_id=destination_id,
            baseline_status=baseline.status,
            simulated_status=simulated.status,
            baseline_findings=baseline.findings,
            simulated_findings=simulated.findings,
            new_findings=new_findings,
            resolved_findings=resolved_findings,
            unchanged_findings=unchanged_findings,
            affected_endpoints=sorted(affected),
            limitations=_dedupe(
                SIMULATION_LIMITATIONS
                + list(baseline.limitations)
                + list(simulated.limitations)
            ),
        )
        logger.info(
            "simulation %s: %s -> baseline=%s simulated=%s",
            report.simulation_id,
            description,
            report.baseline_status.value,
            report.simulated_status.value,
        )
        return report


def _analyze(topology: Topology, source_id: str, destination_id: str) -> DiagnosticResult:
    """Fresh graph + diagnostic engine over the given topology snapshot."""
    return DiagnosticEngine(NetworkGraph(topology)).analyze(
        source_id, destination_id
    )


def _apply_route_removal(topology: Topology, route_id: str) -> None:
    topology.routes = [route for route in topology.routes if route.id != route_id]


def _apply_link_failure(topology: Topology, link_id: str) -> None:
    link = next(link for link in topology.links if link.id == link_id)
    link.state = LinkState.DOWN


__all__ = [
    "BASE_LIMITATIONS",
    "ChangeType",
    "SimulationChange",
    "SimulationReport",
    "SIMULATION_LIMITATIONS",
    "WhatIfEngine",
    "compare_findings",
]
