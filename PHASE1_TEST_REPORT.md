# PHASE1_TEST_REPORT.md — PNETLab Fixture-Based Testing

> Date: 2026-11-15 · Stage: Phase 1 (Mode 1 fixture integration) ·
> Baseline commit: `46678b0` (unchanged — **no commits, no pushes**) ·
> Live integration: NOT authorized (G0 pending).

## 1. Created and modified files

| File | Action |
|---|---|
| `fixtures/pnetlab_topology.yaml` | **Created** — the approved proposal promoted from `proposed/pnetlab_topology.yaml` (file moved; `proposed/` removed). Header status updated to "Phase 1 approved"; provenance/assumptions/data unchanged. |
| `tests/test_pnetlab_fixture.py` | **Created** — 10 new tests (below). |
| `PHASE1_TEST_REPORT.md` | **Created** — this report. |
| Production code (`src/**`), schema, existing tests, dependencies | **UNCHANGED** (verified: `git diff --stat` = 0; HEAD still `46678b0`). |

## 2. Fixture integration

Followed the repository's established conventions: the fixture lives in
`fixtures/` so the shared `fixtures_dir` pytest fixture (tests/conftest.py)
serves it exactly like `healthy.yaml` / `lab_hq.yaml`; the test module
mirrors `test_lab_fixtures.py` style (`_engine()` helper, enum-based
assertions, WhatIfEngine immutability checks). No new abstractions,
frameworks, or dependencies were introduced.

## 3. New test cases and their purposes

| Test | Purpose |
|---|---|
| `test_pnetlab_structure_counts` | Reported characteristics == actual file: 7/21/7/1/56/7/0, device-id set, single GLOBAL VRF on every interface/endpoint, protocol split 20 connected / 35 ospf / 1 static |
| `test_pnetlab_addressing_and_default_route` | Key IPs (external `192.168.98.34/27`, SVI core `10.0.23.x`, FortiGate `10.0.12.x`), loopback /32 anchors, static default via `192.168.98.62` out `r21-e02` |
| `test_pnetlab_single_component_no_violations` | 1 connected component == all 7 devices; zero tenant-boundary violations; all links UP |
| `test_pnetlab_diagnostic_matrix` | The full 12-case matrix: 9 loopback pairs must be **reachable with an `arrival` evidence chain**; 3 FortiGate probes must match their expected status/codes |
| `test_fgt_missing_route_explained_by_modeled_table` | Explains `ep-fgt-p2 → ep-lo-r2-1`: FortiGate's modeled table is exactly `{10.0.12.0/30}` + **no default route (documented gap)** → lookup evidence `no_matching_route`, `covering_routes=[]` |
| `test_fgt_to_fgt1_prefix_not_covered` | Explains `ep-fgt-p2 → ep-fgt1-p2`: `10.0.12.6 ∉ 10.0.12.0/30` (proven with `ipaddress` against the modeled prefix) → no covering route |
| `test_onlink_delivery_reports_unknown_not_success` | Explains `ep-lo-r2 → ep-fgt-p2`: honest `unknown`/`INSUFFICIENT_DATA` with `onlink_without_local_delivery` evidence; **explicitly asserts status is not REACHABLE** (unknown ≠ live success) |
| `test_what_if_route_removal_asymmetric_impact` | What-if on `r22-o-10-255-255-4`: forward pair reachable→unreachable `[MISSING_ROUTE]`, reverse pair unaffected; original model byte-equal after both runs |
| `test_what_if_link_failure` | What-if on `lnk-r23-r22`: reachable→unreachable `[LINK_DOWN]`; original link still UP |
| `test_mcp_summary_and_connectivity` | MCP surface on the real fixture: exact counts envelope, single component, no violations, `check_connectivity` reachable with empty `finding_codes` |

## 4. Fixture validation results

```text
LOAD OK — devices=7 interfaces=21 links=7 vrfs=1 routes=56 endpoints=7 services=0
protocol split: {connected: 20, ospf: 35, static: 1}
components = 1  (r2, r2-1..r2-4, fortigate, fortigate-1)
tenant_boundary_violations = []
all 7 links UP · every interface/endpoint in VRF GLOBAL
```

All reported characteristics from the approval match the file and runtime.

## 5. Diagnostic matrix results (12/12)

| # | Pair | Expected | Result | Notes |
|---|---|---|---|---|
| 1 | ep-lo-r2-1 → ep-lo-r2-3 | reachable | ✅ | evidence chain via R2-2 (representative ECMP path [ASSUMP]) |
| 2 | ep-lo-r2-1 → ep-lo-r2-4 | reachable | ✅ | direct via R2-4 |
| 3 | ep-lo-r2-1 → ep-lo-r2 | reachable | ✅ | via R2-2 → R2-3 → core |
| 4 | ep-lo-r2 → ep-lo-r2-4 | reachable | ✅ | |
| 5 | ep-lo-r2-3 → ep-lo-r2-1 | reachable | ✅ | |
| 6 | ep-lo-r2-4 → ep-lo-r2-2 | reachable | ✅ | via R2-3 |
| 7 | ep-lo-r2-2 → ep-lo-r2 | reachable | ✅ | |
| 8 | ep-lo-r2 → ep-lo-r2-2 | reachable | ✅ | |
| 9 | ep-lo-r2-4 → ep-lo-r2-3 | reachable | ✅ | adjacent |
| 10 | ep-lo-r2 → ep-fgt-p2 | **unknown** `[INSUFFICIENT_DATA]` | ✅ | on-link final delivery has no next hop; no L2/ARP model. **Not a live result** — asserted `status is not REACHABLE` |
| 11 | ep-fgt-p2 → ep-lo-r2-1 | **unreachable** `[MISSING_ROUTE]` | ✅ | FortiGate table = one connected /30, no default (gap) → nothing covers `10.255.255.1`; evidence `no_matching_route` |
| 12 | ep-fgt-p2 → ep-fgt1-p2 | **unreachable** `[MISSING_ROUTE]` | ✅ | `10.0.12.6` is outside modeled `10.0.12.0/30`; FGT has no route to `10.0.12.4/30` |

No finding was suppressed or modified to obtain these results; the three
FortiGate-related outcomes are asserted *together with* the modeled-routing
facts that produce them (tests 5–7 in the table above).

## 6. Full regression results

| Run | Result |
|---|---|
| New PNETLab fixture tests | **10 passed** (1.07s) |
| Complete suite | **167 passed** (4.98s) = 157 baseline + 10 new · 0 failed / 0 skipped / 0 errors / 0 warnings |
| Baseline preservation | 157 previous tests untouched and still green |

## 7. Ruff, demo, MCP

| Check | Result |
|---|---|
| `ruff check .` | **All checks passed** |
| `python scripts/lab_demo.py --no-llm` | exit 0 · **9/9 PASS** · `deterministic: PASS` |
| Independent MCP harness | **16/16 PASS** (11 in-process + 5 stdio: registration, schemas, execution, error envelopes, topology-unchanged) |

**Environmental vs application failures:** none of either — all runs green.
(Environment note: the sandbox system-site `mcp`/`ruff` packages had been
lost by a sandbox reset earlier; they were reinstalled with the same
declared versions (`mcp>=1.0` → 2.3.0, `ruff>=0.4` → 0.17.5) before these
runs. This is an environment restoration, not an application change.)

## 8. Newly discovered discrepancies / limitations

1. **ECMP representativeness [ASSUMP → G4]** — 5 OSPF routes carry a
   representative next hop where the real FIB may install equal-cost
   multiple paths (engine documents "no ECMP" in `BASE_LIMITATIONS`).
   G4 diffs must classify "alternate equal-cost" as acceptable.
2. **FortiGate default routes still absent [GAP]** — next-hops were never
   supplied; FGT→outside reachability is unmodeled (tests now pin this
   behavior so a future fixture update is a visible, reviewed change).
3. **On-link final delivery = `unknown` (engine design limitation, not a
   bug)** — no L2/neighbor model. Smallest future correction if ever
   needed: an optional modeled "on-link adjacency" fact per link; **not
   implemented** (production code untouched, no correction proposed for
   this stage).
4. **Single-VRF lab** — tenant-isolation scenarios (S8) cannot be
   exercised on this fixture; they remain covered by synthetic fixtures.
5. **OSPF area/adjacencies not representable** (schema gap, documented in
   Phase-0 report) — neighbor tables stay as device evidence outside the
   model.
6. **`unknown` semantics reinforced** — test 10 encodes the rule that an
   intentionally unknown result must never be read as a successful live
   connectivity test.

## 9. Confirmation: production code unchanged

- `git diff --stat` → **0 tracked files modified**; HEAD still `46678b0`;
  **no commits and no pushes** performed.
- `src/nettwin/**` (engine, domain model, schema, MCP server, loaders):
  byte-identical. No dependency changes. No existing test modified.
- Only additions: the fixture, one new test module, and reports.

## 10. Recommendation for the next stage

**Next: Gate G0 (read-only Ubuntu↔PNETLab connectivity + duplicate-IP
check for `192.168.98.34`)** — it remains the sole blocker for Mode 2.
After G0 passes and with explicit approval, the following stage would be
"B3: G1 collector MVP" (SSH `show ip interface brief` + `show ip route`
on two IOL routers → raw JSON → existing loader), still read-only, with
parser golden-file tests and no device configuration changes. Until G0 is
independently verified and approved, stay in Mode 1: the fixture-based
baseline established here (167 tests) is the reference for all future
comparison work.
