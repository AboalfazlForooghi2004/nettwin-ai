# Phase-2 Deliverable — Cisco SSH Collector MVP (read-only)

**Branch:** `pnetlab/cisco-collector-mvp` (from `pnetlab/phase1-fixture-validation` @ `ad725c3`)
**Scope:** smallest useful read-only IOS collector; live validation target R2-1 only, executed by the operator from Ubuntu.
**Evidence labels:** `[REPO]` = verified against source/tests in this workspace · `[DEVICE]` = captured device output (pending live run) · `[USER]` = operator-executed · `[PENDING]` = not yet done · `[ASSUMP]` = stated assumption.

---

## 1. Architecture and implementation summary `[REPO]`

```
operator (Ubuntu)                          device (IOS 15.2)
┌──────────────────────────────┐          ┌──────────────────┐
│ scripts/collect_cisco.py     │  SSH     │ R2-1             │
│   └─ CiscoIOSCollector ──────┼─────────►│  (5 allowlisted  │
│        │ allowlist check     │          │   show commands) │
│        │ env credentials     │          └──────────────────┘
│        │ session lifecycle   │
│        ▼                     │
│   DeviceObservations         │  raw outputs + parsed records + warnings
│        │ ios_parsers (pure)  │
│        ▼                     │
│   map_to_topology ───────────┼──► Topology (EXISTING domain model)
│        │ + honest warnings   │    Device/Interface/Route/VRF only
│        ▼                     │
│   collected/<host>.{topology,observations}.yaml
└──────────────────────────────┘
```

* **Transport:** `netmiko` via lazy import inside `default_connect()` — the
  package imports and the whole test suite run with **no SSH library
  installed** (mock session factories).
* **Allowlist first:** `collect()` validates every requested command against
  `READ_ONLY_COMMANDS` (exact five) **and** a forbidden-fragment list
  (`configure`, `conf t`, `write`, `copy`, `reload`, `clear`, `enable`, …)
  *before* credentials are resolved and *before* any connection attempt.
* **Layered read-only guarantees:** (1) only allowlisted commands can be
  dispatched; (2) forbidden fragments hard-rejected even if the allowlist
  were edited; (3) no code path exists that enters enable/config mode;
  (4) session closed in `finally`.
* **Observations → model:** `map_to_topology()` maps onto the existing
  classes (`Topology`, `Device`, `Interface`, `VRF`, `Route`) — no parallel
  model. Gaps (ECMP, OSPF adjacency, CDP, AD/metric) are reported as
  warnings, never silently dropped and never invented.
* **Errors:** `CollectorError ⊂ NetTwinError`; kinds `auth` / `timeout` /
  `unreachable` for connection failures; per-command `ok|error|timeout`;
  all messages sanitized against the password before escaping.

## 2. Files created and modified `[REPO]`

| File | Action | Purpose |
|---|---|---|
| `pyproject.toml` | modified | optional extra `collect = ["netmiko>=4.3"]` (see §3) |
| `src/nettwin/collect/__init__.py` | created | public API of the collector package |
| `src/nettwin/collect/ios_parsers.py` | created | pure deterministic parsers for the five IOS outputs |
| `src/nettwin/collect/cisco_ios.py` | created | allowlist, session lifecycle, observations, domain mapping |
| `scripts/collect_cisco.py` | created | operator CLI (env credentials, YAML + evidence output) |
| `tests/test_cisco_collector.py` | created | 43 offline tests (mocked SSH, no sockets) |
| `tests/data/ios152/*.txt` (5 files) | created | sanitized representative IOS 15.2 outputs (parser fixtures) |
| `docs/IOS_SSH_PROPOSED_CONFIG.md` | created | proposed IOS account/SSH config — manual review only |
| `docs/UBUNTU_LIVE_TEST_GUIDE.md` | created | operator live-test procedure for R2-1 |
| `docs/PHASE2_COLLECTOR_REPORT.md` | created | this report |

**Untouched (verified):** `src/nettwin/domain/`, `src/nettwin/diagnostics/`,
`src/nettwin/simulation/`, `src/nettwin/mcp_server/`, `src/nettwin/data/`,
all existing tests, all fixtures, `main.py`. **Production engine/model/schema
changes: zero.** Mode-1/MCP behaviour preserved (regression §6).

## 3. Dependency changes and rationale `[REPO]`

* **Added (optional extra only): `netmiko>=4.3`** under
  `[project.optional-dependencies] collect`.
  * Rationale: Python's stdlib has no SSH client. netmiko is the de-facto
    standard library family for network device CLIs, ships a dedicated
    `cisco_ios` driver (prompt detection, paging, IOS 15.2 compatible) and
    centralizes connection/auth/timeout exception taxonomy.
  * Alternatives considered: **paramiko** (raw SSH: would require
    reimplementing IOS prompt/paging handling — more code, more risk);
    **asyncssh/scrapli** (equal capability, larger async surface than an MVP
    needs; scrapli community driver split). netmiko is the smallest correct
    layer.
  * Core install, `lab_demo`, MCP server and the entire test suite work
    **without** it (lazy import + mocks). Install: `pip install -e ".[collect]"`.
* **No other dependency added or version-changed.** pytest / ruff / mcp /
  pydantic / PyYAML / networkx untouched.

## 4. API and usage example `[REPO]`

```python
from nettwin.collect import CiscoIOSCollector, map_to_topology

collector = CiscoIOSCollector("192.168.98.34")   # env: NETTWIN_DEVICE_USERNAME/PASSWORD
observations = collector.collect()               # 5 allowlisted commands, session closed
topology, warnings = map_to_topology(observations)   # existing domain model

observations.status            # "ok" | "partial" | "failed"
observations.commands[i].status  # "ok" | "error" | "timeout" (+ duration, error text)
topology.routes[0].destination_prefix, .next_hop, .outgoing_interface_id, .vrf_id
```

CLI:

```bash
export NETTWIN_DEVICE_USERNAME=... NETTWIN_DEVICE_PASSWORD=...
python scripts/collect_cisco.py --host 192.168.98.34 --raw-dir collected/raw
# exit 0 = ok, 1 = config/connection/allowlist, 2 = partial
```

Rejecting unsafe input (tested):

```python
collector.collect(commands=["show running-config"])
# AllowlistViolation: ... (rejected before connect)  — factory never called
```

## 5. Parser evidence `[REPO]` / `[PENDING device capture]`

Fixtures in `tests/data/ios152/` are **sanitized, representative IOS 15.2
outputs constructed to the real CLI formats** — they are *not* yet captures
from R2-1 (`[PENDING]`: first real capture happens during the Ubuntu live
run via `--raw-dir`; file any format gap as a parser issue).

| Fixture | Proves |
|---|---|
| `show_version.txt` | hostname (`R2-1`), `Version 15.2(4)M5`, platform `IOL` extraction |
| `show_ip_interface_brief.txt` | fixed columns incl. `administratively down`, `unassigned`, space-containing status |
| `show_ip_route.txt` | codes legend, `subnetted` headers, `S*` candidate default, C/L/O/E2 codes (digits!), AD/metric, uptime variants (`01:22:33`, `3w2d`), **ECMP: 2-hop and 3-hop entries**, directly-connected with no next hop |
| `show_ip_ospf_neighbor.txt` | header + `FULL/DR`/`FULL/BDR`/`FULL/DROTHER` states |
| `show_cdp_neighbors.txt` | capability legend, header row, `Eth 0/0` → `Ethernet0/0` normalization, footer |

Determinism: every parser is a pure function of its text — asserted by
`test_all_parsers_are_deterministic`. Unparseable rows → warning + skip
(never invented); missing sections after a failed command → warning
`not collected — section unavailable` (uncollected ≠ absent).

## 6. Unit and regression results `[REPO]` (sandbox — offline only)

Run on Ariana.ia — **no network, no SSH library, no device contact:**

| Check | Baseline (Phase 1) | After Phase 2 | Verdict |
|---|---|---|---|
| `python3 -m pytest` | 167 passed | **210 passed in 5.10s** (167 + 43 new) | ✅ no regression |
| `python3 -m ruff check .` | clean | **clean** | ✅ |
| `python3 scripts/lab_demo.py --no-llm` | 9/9 (known `llm loop: PASS` label bug) | **PASS, bug unchanged (unfixed — needs separate approval)** | ✅ no regression |
| MCP checks (healthy.yaml) | 16/16 (11 in-process + 5 stdio) | **16/16** (+ initialize handshake) | ✅ no regression |

New test file `tests/test_cisco_collector.py` — **43 tests**, covering:
exact allowlist & pre-connection rejection (15 malicious/blocked commands),
empty-list rejection, dispatch = allowlist and config-never-invoked,
session lifecycle incl. disconnect-on-failure, env-credential wiring,
missing-credential config error, auth/timeout/unreachable classification
with password sanitization, per-command timeout/error recording, five IOS
parsers from representative outputs, parser determinism, malformed-row
honesty, full domain mapping (identity/interfaces/routes/VRF), ECMP
preservation (2- and 3-next-hop), missing-hostname refusal, IP-without-
prefix marked unavailable, uncollected-section honesty, secrets-never-in-
observations.

**Honesty statement:** these tests exercise mocked sessions only. They do
**not** prove live SSH works. `[PENDING — operator, Ubuntu, R2-1 only]`

## 7. Read-only security analysis `[REPO]`

| Vector | Control | Residual risk |
|---|---|---|
| Accidental config change | exact 5-command allowlist + forbidden-fragment layer + no config/enable code path + tests assert dispatch contents | none demonstrated; app-side only (see next row) |
| Malicious/buggy client | *device-side* privilege-1 account + VTY ACL (proposal §2) — **app allowlist is NOT claimed as device authorization** | until operator applies device config, only client-side controls exist |
| Credential leak | env vars only (never argv/files/git); password sanitized out of every error message; never stored in observations; test greps serialized output | operator shell history if they inline secrets — guide says export only |
| Command output leak | outputs stored as evidence files in `collected/` (operator-controlled); summary prints statuses not outputs | device configs are not collected (`show running-config` blocked); generic `show` output may still reveal topology — treat files as sensitive |
| Session left open | `finally: disconnect()` + tests on failure paths | — |
| Host-key surprises | netmiko/paramiko default = system known_hosts policy | first-connection TOFU on lab device — operator reviews the prompt |
| DoS/lockout | per-command timeouts (default 30 s), connect timeout 15 s, single-threaded, no retry storms | 5 commands/run; IOS `login block` if enabled — guide troubleshooting covers it |

## 8. Proposed IOS SSH configuration `[PENDING operator review]`

`docs/IOS_SSH_PROPOSED_CONFIG.md` — dedicated `privilege 1` account, no
enable secret, SSH v2 + timeouts, VTY ACL example, and verification
commands (`show privilege`, denied `configure terminal` / `show
running-config`). **Manual review document only — never applied remotely,
by design.**

## 9. Ubuntu live-test instructions `[PENDING operator]`

`docs/UBUNTU_LIVE_TEST_GUIDE.md` — deps (`pip install -e ".[dev,collect]"`),
env vars, TCP/22 + SSH pre-flight, restricted-account verification, run
against R2-1, output validation vs manual SSH, troubleshooting matrix
(auth / negotiation / timeout / privilege), safety rules.

## 10. Reachability status: R2-1 / R2-3

* **R2-1 (`192.168.98.34`): G0 VERIFIED `[USER]`** — Ubuntu 172.30.201.18
  ↔ R2-1 bidirectional (3/3 + 3/3 + reverse 5/5, 2026-11-15). **Live SSH
  collection: PENDING** (this phase's live step, operator-run).
  Outstanding *optional* check: duplicate-IP vs gateway ARP (not a
  demonstrated fault).
* **R2-3 (preferred `10.255.255.4`): UNVERIFIED** — no reachability evidence
  exists. Required before any use: `ip route get 10.255.255.4` and
  `ping -c3 -W2 10.255.255.4` from Ubuntu. If it fails → report blocker,
  **change no routes**. Code supports R2-3; live validation does not include
  it in this phase.

## 11. Known limitations (incl. ECMP)

1. **ECMP — exact limitation:** the existing `Route` model holds a **single**
   `next_hop`. The collector preserves **all** observed next hops in
   `observations.routes[].next_hops` and emits a per-route warning
   (`… ALL preserved in observations; model Route keeps the first next-hop
   only`). The mapped topology's route carries the first next hop.
   **Proposed smallest compatible model change (NOT made — requires separate
   approval):** add optional `Route.alternate_next_hops: list[...]` (or
   `next_hops: list[RouteHop]` with `next_hop` kept for compatibility) +
   diagnostics awareness; engine/model/schema untouched in this phase.
2. **No OSPF adjacency / CDP objects in the schema** — rows are preserved in
   observations with an explicit warning; adjacency is **never inferred**
   from IPs (standing rule).
3. **No AD/metric fields on `Route`** — preserved in observations; one
   aggregate warning.
4. **Standalone topology output** — mapping produces a new `Topology`; it is
   *not* merged into `fixtures/pnetlab_topology.yaml` (merge would be a
   separate, approved step).
5. **App allowlist ≠ device authorization** (§7) — device-side account
   hardening is a proposal until applied manually.
6. **Representative parser fixtures** are format-faithful but not yet real
   captures; IOS output variants may surface during the live run (captured
   via `--raw-dir` for follow-up).
7. **`netmiko` optional** — live runs need `pip install -e ".[collect]"`.
8. Unmapped protocol codes map to `protocol: "unknown"` **with a warning**
   (never silently relabeled).
9. Hostname → `device_id` is lowercased (`R2-1` → `r2-1`); unusual hostnames
   are not slugified further (IOS hostnames are `[A-Za-z0-9-]` in practice).

## 12. Patch / branch delivery

* **Branch:** `pnetlab/cisco-collector-mvp` — created from
  `pnetlab/phase1-fixture-validation` @ `ad725c3`.
* **Commit:** single phase-2 commit on that branch (hash in the delivery
  message / `git log`). `main` untouched; **no push and no merge without
  explicit approval.**
* **Patch file:** `cisco-collector-mvp.patch` (diff `ad725c3..HEAD`,
  Phase-2 changes only) — delivered alongside this report.

---

### Acceptance traceability (proposal §CISCOLLECTOR-ACCEPT-001..010)

| # | Criterion | Status |
|---|---|---|
| 1 | five allowlisted read-only commands, reject pre-connect | ✅ tests |
| 2 | session lifecycle incl. disconnect-on-failure | ✅ tests |
| 3 | auth/timeout/connection error handling, sanitized | ✅ tests |
| 4 | IOS 15.2 parsers from representative outputs | ✅ tests (+ live capture pending) |
| 5 | domain mapping incl. ECMP multi-next-hop preservation | ✅ tests + warnings |
| 6 | config-never-invoked & secrets-never-in-logs tests | ✅ tests |
| 7 | netmiko as justified optional extra | ✅ §3 |
| 8 | live validation only R2-1, only operator-Executed | ⏳ guide ready |
| 9 | full regression + ruff + demo + MCP, no regression | ✅ §6 |
| 10 | deliverables 1–12 complete, patch/branch, no push without approval | ✅ this report |
