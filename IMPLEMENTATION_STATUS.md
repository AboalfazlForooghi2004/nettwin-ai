# NetTwin AI — Implementation Status

## Current Project Status

Status: MVP COMPLETE + LAB EXTENSION READY (HQ lab scenario + LLM eval loop)

Current phase: LAB VALIDATION (run `scripts/lab_demo.py` on the machine
that can reach the LLM gateway)

## Task Tracking

| Task | Description | Status |
|---|---|---|
| TASK-001 | Project Bootstrap | COMPLETED |
| TASK-002 | Domain Models | COMPLETED |
| TASK-003 | Network Graph | COMPLETED |
| TASK-004 | Diagnostics | COMPLETED |
| TASK-005 | What-if Analysis | COMPLETED |
| TASK-006 | MCP Integration | COMPLETED |

## Status Definitions

- NOT STARTED
- IN PROGRESS
- BLOCKED
- COMPLETED

## Development Log

### TASK-001

Status: COMPLETED

Implementation notes:

- Inspected repository: empty (no existing files, no git repo).
- Python 3.13.18 available (satisfies 3.12+ requirement).
- Created `pyproject.toml` with runtime deps (pydantic, PyYAML, networkx, mcp),
  dev deps (pytest, pytest-cov, ruff), setuptools src-layout, pytest config,
  and Ruff config (line length 100, target py312, E/W/F/I/UP/B rules).
- Created package `src/nettwin/` with subpackages `domain/`, `data/`, `graph/`,
  `diagnostics/`, `simulation/`, `mcp_server/` (placeholders for later tasks).
- Created `src/nettwin/main.py` entry point (logs startup, prints version).
- Created `README.md` with quick start and layout.
- Created `tests/test_bootstrap.py`.
- Installed project editable with `pip install -e ".[dev]"`.

Files created:

- `pyproject.toml`
- `README.md`
- `src/nettwin/__init__.py`
- `src/nettwin/main.py`
- `src/nettwin/{domain,data,graph,diagnostics,simulation,mcp_server}/__init__.py`
- `tests/test_bootstrap.py`

Dependencies selected:

- Runtime: pydantic 2.14.3, PyYAML 6.0.3, networkx 3.7, mcp (latest)
- Dev: pytest 9.0.3, pytest-cov, ruff 0.17.5

Commands used:

```bash
pip install -e ".[dev]"
pytest
ruff check .
python -m nettwin.main
```

Tests: 2 passed (bootstrap import + entry point).

Known limitations:

- Entry point is a stub; no diagnostic or MCP functionality yet.
- No network logic implemented (per task restrictions).

### TASK-002

Status: COMPLETED

Implementation notes:

- `src/nettwin/errors.py`: explicit exception types (`NetTwinError`,
  `TopologyValidationError`, `EndpointNotFoundError`, `ObjectNotFoundError`).
- `src/nettwin/domain/models.py`: Pydantic v2 models — Device, Interface, VRF,
  Link, Route, Endpoint, Service, EvidenceItem, DiagnosticFinding,
  DiagnosticResult, Topology; enums AdminState/OperState/LinkState,
  FindingSeverity, DiagnosticStatus, FindingCode.
  - `extra="forbid"` on all structural models (typo'd YAML keys rejected).
  - Interface addresses use `IPvAnyInterface`, endpoints/next-hops
    `IPvAnyAddress`, route prefixes `IPvAnyNetwork`.
  - `Topology` model validator rejects duplicate ids per collection and all
    invalid cross-references (device/VRF/interface/endpoint), aggregating
    every problem into one error message.
  - Route requires `next_hop` and/or `outgoing_interface_id` (connected routes
    legitimately have no next hop — documented deviation from the field list).
  - Service protocol normalized to lowercase; port constrained to 1..65535.
  - `EvidenceItem` is a flat typed object (`type` + extra fields), matching
    the evidence example in 04_DATA_MODEL_AND_DIAGNOSTIC_RULES.md.
- `src/nettwin/data/loader.py`: `load_topology(path)` / `load_topology_dict`
  — YAML safe-load, structure check, Pydantic validation, explicit
  `TopologyValidationError` messages including file path and field locations.
- Fixtures:
  - `fixtures/healthy.yaml`: 4 devices, 3 VRFs (TENANT_A/TENANT_B/SERVICE),
    overlapping 10.10.10.0/24 in both tenants, shared PostgreSQL service
    (10.100.1.20, tcp/5432) with `allowed_vrfs: [TENANT_A, TENANT_B]`,
    explicit service-handoff routes on edge-a1, no implicit leaking.
  - `fixtures/missing_route.yaml`: identical except route
    `leaf-a1-svc-10-100-1` removed (Tenant A → PostgreSQL fails).
  - `fixtures/tenant_isolation.yaml`: two tenants, overlapping prefixes,
    shared edge device, no services, no cross-VRF routes or links.

Tests:

- `tests/test_domain_models.py` (19 tests): type/IP/enum validation, route
  forwarding-reference rule, endpoint IP overlap across VRFs, finding
  severity/status/evidence shape.
- `tests/test_loader.py` (17 tests): valid load, non-mapping root, duplicate
  ids, unknown VRF/device/interface/endpoint/service references, invalid IPs,
  aggregated error messages, missing file, bad extension, malformed YAML.
- `tests/test_fixtures.py` (9 tests): all three fixtures load; healthy has
  PostgreSQL service with both tenants allowed; missing_route differs from
  healthy by exactly one route id; isolation fixture has zero cross-VRF
  forwarding (routes and links stay within one VRF); healthy fixture's only
  cross-VRF routes are explicit permitted SERVICE handoffs.
- Total: 50 passed. Ruff: all checks passed.

Known limitations:

- No graph engine yet — VRF isolation is enforced structurally by fixtures
  and validation, not yet by graph queries (TASK-003).
- `DiagnosticResult` model defined but unused until TASK-004.
- No SQLite persistence (optional, deferred).

### TASK-003

Status: COMPLETED

Implementation notes:

- `src/nettwin/graph/network_graph.py`: `NetworkGraph` wraps a validated
  `Topology` in an `nx.MultiGraph` with typed nodes/edges:
  - nodes: device, interface, vrf, endpoint, service (attributes include
    interface `vrf_id`, addresses, states);
  - edges: `has_interface`, `member_of` (VRF membership), `link`, `in_vrf`,
    `attached_to`, `exposes`, `allows` (service → allowed VRF).
- Indexes: interfaces-by-device, links-by-interface, service-by-endpoint.
- Queries: getters for every object (explicit `ObjectNotFoundError` /
  `EndpointNotFoundError`), `list_devices/vrfs/endpoints/services`,
  `get_device_interfaces`, `get_vrf_interfaces`, `get_vrf_devices`,
  `get_neighbors` (optional `require_link_up`), `get_interface_neighbors`,
  `connected_components` (structural device-level),
  `get_vrf_components` (intra-VRF links only — never crosses a VRF),
  `find_endpoints_by_ip` (returns ALL VRF matches; never implies
  connectivity), `get_service_allowed_vrfs`, `find_service_for_endpoint`.
- Tenant boundaries: `check_tenant_boundary(src_vrf, dst_vrf, service=)`
  returns an explicit `TenantBoundaryResult` (`allowed_same_vrf` /
  `allowed_explicit_service` / `denied_cross_tenant` /
  `denied_no_explicit_relationship`); `find_tenant_boundary_violations()`
  flags links that implicitly join two tenants' VRFs.

Tests:

- `tests/test_graph.py` (24 tests): node/edge structure, VRF-context node
  attributes, getters + explicit errors, device/VRF/interface/neighbor
  queries, link-state-aware queries, components, service queries,
  overlapping-IP lookup returning both VRFs, VRF components never mixing
  tenants, cross-tenant denial, explicit service permission, isolation
  fixture with no implicit path, synthetic cross-tenant link flagged.
- Total: 74 passed. Ruff: all checks passed.

Known limitations:

- Graph components are structural only (no routing-aware reachability —
  that belongs to the diagnostic engine in TASK-004).
- `find_tenant_boundary_violations` checks links only; VRF handoff routes
  are validated against service permissions by the diagnostics layer.
- No route lookup in the graph layer (routes indexed by diagnostics).

### TASK-004

Status: COMPLETED

Implementation notes:

- `src/nettwin/diagnostics/engine.py`: `DiagnosticEngine(graph).analyze(
  source_id, destination_id, source_vrf_id=None)` → `DiagnosticResult`.
  - Deterministic pipeline: endpoint validation (IP addresses are rejected as
    identifiers — `EndpointNotFoundError`) → requested-VRF context check →
    endpoint attachment completeness → tenant-boundary check via
    `NetworkGraph.check_tenant_boundary` → iterative forwarding walk with
    longest-prefix route lookup per (device, VRF) table.
  - Walk steps emit structured evidence: `endpoint_resolution`,
    `tenant_boundary`, `route_lookup`, `interface_state`,
    `next_hop_resolution`, `link_traversal`, `vrf_handoff`, `arrival`,
    `route_loop`.
  - Findings: all six required codes (MISSING_ROUTE, INTERFACE_DOWN,
    LINK_DOWN, VRF_MISMATCH, TENANT_ISOLATION, INSUFFICIENT_DATA) plus two
    justified additions (ROUTE_LOOP terminates the walk on modeled loops;
    NEXT_HOP_UNRESOLVED distinguishes an unresolvable next hop from a
    missing route). Deterministic severities (tenant isolation = critical,
    routing/forwarding failures = high, missing data = medium).
  - Status semantics: `reachable` on arrival; `unreachable` for confirmed
    failures (missing/inactive route, down interface/link, denied boundary,
    bad next hop, loop); `incomplete` when required request data is missing
    (unattached endpoint, VRF context mismatch); `unknown` when the model
    lacks mid-walk data (no modeled link, on-link claim without local
    delivery). Unknown/incomplete are never reported as confirmed results.
  - Limitations are always included in the result (model-vs-live note,
    simplified routing assumptions, explicit-service handoff rule, inactive
    route notes).
- `FindingCode` extended with ROUTE_LOOP and NEXT_HOP_UNRESOLVED (justified
  in the enum docstring).
- Domain models now use `validate_assignment=True` everywhere (assigning
  raw strings during simulations/tests is coerced+validated); Service
  protocol normalization moved to a `field_validator` to avoid recursion.
- Topology validation strengthened: a route's outgoing interface must belong
  to the route's device.

Tests:

- `tests/test_diagnostics.py` (31 tests): Case A reachable (both tenants,
  same-endpoint, evidence chain incl. permitted handoff), IP-as-identifier
  rejected; Case B MISSING_ROUTE (severity/evidence/recommendations/context)
  while Tenant B stays reachable, inactive-route variant with
  `no_active_route` evidence + limitation; Case C TENANT_ISOLATION
  (fixture + service-denied + walk-time cross-tenant handoff);
  INTERFACE_DOWN (oper + admin + peer side), LINK_DOWN; VRF_MISMATCH
  (context mismatch = incomplete, same-tenant cross-VRF = unreachable,
  walk-time wrong-VRF handoff); INSUFFICIENT_DATA as incomplete (unattached
  endpoint) and as unknown (removed link) — both never `unreachable`;
  NEXT_HOP_UNRESOLVED, ROUTE_LOOP, recursive next-hop-only resolution;
  evidence traceability to real route/link/vrf ids; deterministic repeat
  runs; no AI-layer dependency.
- Loader test for route outgoing-interface ownership.
- Total: 103 passed. Ruff: all checks passed.

Known limitations:

- Simplified routing: LPM in the current VRF table only; no ECMP, no
  recursive FIB fallback (an unresolvable LPM next hop fails the analysis
  rather than trying a less-specific route), no policy routing.
- On-link/connected routes that match away from the destination device
  produce `unknown` (model gap) rather than guessing L2 delivery.
- Diagnostic findings are per-analysis; finding ids are deterministic within
  a topology so baseline/simulated results can be compared (TASK-005).

### TASK-005

Status: COMPLETED

Implementation notes:

- `src/nettwin/simulation/engine.py`:
  - `WhatIfEngine(topology)` with `simulate_route_removal(route_id, src, dst)`
    and `simulate_link_failure(link_id, src, dst)`.
  - Workflow per spec: baseline diagnostics on the ORIGINAL topology →
    `copy.deepcopy` → apply change to the copy only → re-run diagnostics →
    compare → structured `SimulationReport`.
  - `SimulationReport` (Pydantic, JSON-serializable): `simulation_id`,
    `change` (type/target/description), `baseline_status`,
    `simulated_status`, `baseline_findings`, `simulated_findings`,
    `new_findings`, `resolved_findings`, `unchanged_findings`,
    `affected_endpoints`, `limitations`.
  - `compare_findings()` partitions by deterministic finding id
    (`code:subject`) → new / resolved / unchanged.
  - `affected_endpoints`: analyzed pair when status changes, plus endpoints
    named by new/resolved findings.
  - Limitations always include: deep-copy-only mutation, single-pair scope,
    no live devices, plus the diagnostic engine's limitations.
  - Unknown route/link ids raise explicit `ObjectNotFoundError` BEFORE any
    analysis; unknown endpoints raise `EndpointNotFoundError`.
- Models use `validate_assignment=True`, so mutations on copies
  (`link.state = LinkState.DOWN`, `topology.routes = [...]`) are validated.

Tests:

- `tests/test_simulation.py` (16 tests): Demo Case D route-removal report
  (baseline reachable → simulated unreachable, MISSING_ROUTE new, affected
  endpoints); original route/link state proven unchanged after simulations;
  irrelevant change → no findings, no affected endpoints; unchanged
  findings on a broken baseline; resolved-findings case (failure moves
  earlier in the walk); repeated simulations independent (3 distinct ids,
  original intact); baseline reproducible; deep-copy object independence;
  unknown route/link/endpoint errors + fail-fast ordering;
  `compare_findings` unit tests; JSON serialization of the report; AST check
  that the simulation module imports no shell/SSH/socket capability.
- Total: 121 passed. Ruff: all checks passed. Coverage: 98% of `src/nettwin`.

Known limitations:

- `affected_endpoints` covers the analyzed pair and endpoints named by
  changed findings; other endpoint pairs are not re-analyzed.
- Resolved findings require the simulated failure to occur *earlier* in the
  walk than the baseline failure (removal/disable cannot fix a path).
- Simulations recompute the baseline on every call (slight overhead,
  guarantees freshness).

### TASK-006

Status: COMPLETED

Implementation notes:

- `src/nettwin/mcp_server/server.py`: built on the official MCP Python SDK
  (v2.3.0, `MCPServer`; FastMCP was renamed in SDK v2).
  - `create_server(topology)` registers exactly eight read-only tools; the
    factory wires tools to application services only
    (`NetworkGraph`, `DiagnosticEngine`, `WhatIfEngine`) — no network logic
    in handlers.
  - Uniform Pydantic response envelopes: `ToolResponse` (ok, summary,
    status, error, devices, vrfs, topology, endpoint_details, source/
    destination/vrf ids, findings, evidence, recommendations,
    finding_codes, limitations) and `SimulationResponse` (adds
    simulation_id, change, baseline/simulated status+findings,
    new/resolved/unchanged findings, affected endpoints). Pydantic return
    types give clients real `structuredContent` + output schemas.
  - Errors are structured (`ok=false` + `error.code`/`message`):
    `endpoint_not_found`, `route_not_found`, `link_not_found`,
    `vrf_not_found`, `topology_validation_error`.
  - Malformed arguments (missing field, wrong type) are rejected by the SDK
    schema validation as `ToolError`.
  - `nettwin-mcp` console script + `python -m nettwin.mcp_server` +
    `NETTWIN_TOPOLOGY` env (default `fixtures/healthy.yaml`); clean
    exit code 1 with a clear message on topology load failure.
- Read-only guarantee: no shell/SSH/write tools exist; the registered tool
  set is asserted by tests against `READ_ONLY_TOOLS`.

Tests:

- `tests/test_mcp_server.py` (26 tests): all 8 required tools registered
  with descriptions; no write-capable names; unknown tool rejected;
  list/summary/endpoint happy paths and unknown-id envelopes;
  check/diagnose healthy + missing-route + tenant-isolation cases with
  evidence; both simulations with full impact reports and proven original
  topology immutability (model dump equality); structured error envelopes;
  missing/wrong-type/empty arguments raise `ToolError`; running every tool
  leaves the model byte-identical; **real stdio subprocess** test
  (initialize → list 8 tools → call check_connectivity);
  entry-point failure paths return exit code 1.
- `scripts/demo_mcp.py`: acceptance demonstration (six example calls).

Total: 147 passed. Ruff: all checks passed.

Example MCP calls and outputs (abbreviated; run `python scripts/demo_mcp.py`
for full JSON):

```text
> list_devices
{"ok": true, "summary": "4 devices modeled",
 "devices": [{"device": {"id": "leaf-a1", ...}, "interface_count": 2}, ...]}

> list_vrfs
{"ok": true, "summary": "3 VRFs modeled",
 "vrfs": [{"vrf": {"id": "TENANT_A", "tenant_id": "tenant-a",
           "interface_count": 3, "endpoint_count": 1, "route_count": 3}, ...}]}

> check_connectivity {source_id: "ep-a-app", destination_id: "ep-pg"}
{"ok": true, "status": "reachable",
 "summary": "ep-a-app -> ep-pg (VRF TENANT_A): reachable — modeled path found",
 "finding_codes": [], "limitations": [ ...3 documented limitations... ]}

> diagnose_connectivity on fixtures/missing_route.yaml
{"ok": true, "status": "unreachable",
 "summary": "... unreachable — confirmed failure (MISSING_ROUTE)",
 "findings": [{"code": "MISSING_ROUTE", "severity": "high",
   "evidence": [{"type": "route_lookup", "device_id": "leaf-a1",
     "vrf_id": "TENANT_A", "destination": "10.100.1.20",
     "matched_route": null, "result": "no_matching_route"}],
   "recommendations": ["Add a route to 10.100.1.20 on leaf-a1 ..."]}]}

> simulate_route_removal {route_id: "leaf-a1-svc-10-100-1", ...}
{"ok": true,
 "summary": "Baseline reachable -> simulated unreachable: remove route ...",
 "baseline_status": "reachable", "simulated_status": "unreachable",
 "new_findings": [{"code": "MISSING_ROUTE", ...}],
 "resolved_findings": [], "affected_endpoints": ["ep-a-app", "ep-pg"],
 "limitations": ["Simulation runs on a deep copy ...", ...]}

> after simulation: original topology unchanged
{"original_topology_unchanged": true, "routes_present": 7,
 "links_up": true, "recheck_status": "reachable"}
```

Known limitations:

- MCP v2 SDK (`MCPServer`) instead of v1 `FastMCP` — same protocol, newer
  API (migration required if pinning `mcp<2`).
- Tool envelopes include `null` for fields unused by that tool (one shared
  schema keeps responses predictable).
- `affected_endpoints` covers the analyzed pair + endpoints named by changed
  findings (documented in the report's limitations).
- Optional SQLite persistence and HTTP API remain out of MVP scope.

## Acceptance Criteria Checklist (MVP)

| # | Criterion | Status |
|---|---|---|
| 1 | Application starts successfully | PASS (`python -m nettwin.main`) |
| 2 | YAML topology files load correctly | PASS |
| 3 | Invalid topology references rejected | PASS |
| 4 | Overlapping prefixes in separate VRFs supported | PASS |
| 5 | Cross-tenant connectivity not inferred | PASS |
| 6 | Connectivity diagnostics return structured results | PASS |
| 7 | Missing routes identified | PASS |
| 8 | Findings include evidence | PASS |
| 9 | What-if can remove a route / disable a link | PASS |
| 10 | What-if does not mutate original topology | PASS |
| 11 | MCP tools expose diagnostics | PASS (8 read-only tools) |
| 12 | Automated tests pass | PASS (147 passed) |
| 13 | Ruff reports no relevant errors | PASS (all checks passed) |

### POST-MVP: HQ Lab Extension + LLM Setup (2026-11-14)

Status: COMPLETED (pending live LLM validation from the user's machine)

Implementation notes:

- LLM gateway configuration stored in `.env`
  (`https://llm-net.partcorp.ir/v1`, 4 Qwen models, default
  `qwen-27b-instruct`).
- `scripts/llm_check.py`: stdlib-only OpenAI-compatible client
  (`--list`, `--ask`, ping-all) — verified offline against a mock gateway
  (all 4 models incl. reasoning-content extraction).
- Gateway reachability from THIS sandbox: DNS OK, TCP accepted, but
  HTTP/TLS payload blocked by path filtering → live LLM calls must run on
  the user's own machine (user confirmed gateway is local-only).
- `fixtures/lab_hq.yaml`: 6-device HQ lab — 4 switches
  (`sw-blue-1`, `sw-green-1`, `sw-core-1`, `sw-dmz-1`) + 2 firewalls
  (`fw-edge-1`, `fw-branch-1`), exact IPs, 5 VRFs (BLUE/GREEN/DMZ/BRANCH/
  MGMT), overlapping 10.10.1.0/24 in BLUE+GREEN, WAN tunnel modeled as a
  BRANCH VRF extension (documented simplification), shared Web Portal
  `10.100.0.10:443` allowed from BLUE/GREEN/BRANCH, MGMT out-of-band.
- `fixtures/lab_hq_missing_route.yaml`: identical minus `r-blue-to-dmz`.
- `scripts/lab_demo.py`: full scenario runner — connectivity matrix (6
  cases through MCP handlers), evidence chain dump, both what-if sims with
  byte-identical fixture proof, then an LLM evaluation loop: three
  DiagnosticResults (reachable / missing-route / tenant-isolation) sent to
  every configured model with a strict `VERDICT: <status>` contract,
  accuracy table vs engine ground truth; graceful skip when the gateway is
  unreachable.

Tests:

- `tests/test_lab_fixtures.py` (10 tests): structure (6 devices / 21
  interfaces / 19 routes / 5 VRFs / mgmt addresses), fixture diff,
  overlap + boundary-violation checks, connectivity matrix, BLUE evidence
  chain (3 route lookups + permitted handoff + arrival), branch path
  across both firewalls, tenant isolation, missing-route matrix, both
  what-if simulations with immutability.
- Totals: 157 passed. Ruff: all checks passed. Lab demo: deterministic
  PASS, LLM loop skipped gracefully in-sandbox (exit 0).

Known limitations:

- Live LLM evaluation not yet executed (sandbox egress blocked; run
  `python scripts/lab_demo.py` on the user's machine).
- WAN tunnel modeled as single-BRANCH-VRF extension (no IPsec/VRF-lite
  details).
- MGMT VRF is inert (no routes/endpoints) by design.
- No live device collection: lab testing is model-based read-only, per the
  project safety rules.

## Important Rule

Only mark a task COMPLETED when all acceptance criteria pass.
Do not mark tasks complete based on code generation alone.
