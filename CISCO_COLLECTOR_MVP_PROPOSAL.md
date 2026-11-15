# CISCO_COLLECTOR_MVP_PROPOSAL.md — Read-only Collector (NOT IMPLEMENTED)

> **STATUS UPDATE (Phase 2 executed):** gates cleared — G0 PASS was recorded
> and implementation was authorized. The collector now exists on branch
> `pnetlab/cisco-collector-mvp`; execution evidence and deliverables 1–12
> are in `docs/PHASE2_COLLECTOR_REPORT.md`. This document is preserved
> unchanged below as the original proposal/acceptance record.
>
> **Original gate status (historical): BLOCKED — implementation requires
> (1) G0 PASS with pasted evidence and (2) separate explicit authorization.**
> This document is a proposal only. No collector code exists; no device
> has been contacted; no credentials are requested here.

**MVP target:** exactly **two** Cisco IOL routers first —
`R2-1` and `R2-3` (one external-edge, one core-adjacent — together they
see the default route, the external interface, and the OSPF fabric).

---

## 1. SSH connection approach

- **Library:** `netmiko` (proposed single new dependency — justification:
  Python has no stdlib SSH client; shelling out to `ssh` would violate the
  no-shell-execution boundary and be untestable. `paramiko` alone would
  still require reimplementing IOS paging/prompt handling that netmiko
  already solves). **Dependency addition needs its own approval at
  implementation time.**
- **Platform driver:** `cisco_ios` (IOS 15.2 IOL [USER-confirmed]).
- **Session model:** one device per short-lived session (connect →
  N commands → disconnect). No persistent polling daemon in the MVP.
- **Hard read-only enforcement:**
  - Commands pass through an allow-list (`show …` only) — anything else
    raises before it is sent.
  - `check_config_mode()` asserted false; entering config mode is a
    test failure, not a retry.
  - No `configure`, `write`, `reload`, `copy`, `clear`, `debug`, or
    `terminal length` mutations beyond `terminal length 0` (paging
    disable — display-only, explicitly whitelisted).
- **Reachability precondition:** G0 PASS (management path to the loopback
  anchors `10.255.255.1` / `10.255.255.4` or an agreed management route).

## 2. Read-only command set (MVP)

| # | Command | Purpose |
|---|---|---|
| 1 | `show version` | platform/OS → `Device.platform`, `metadata.os` |
| 2 | `show ip interface brief` | interfaces, IPs, admin/oper → `Interface` |
| 3 | `show ip route` | routing table → `Route` |
| 4 | `show ip ospf neighbor` | adjacency evidence (kept as raw evidence; schema has no field) |
| 5 | `show cdp neighbors` | cabling cross-check vs fixture `Link`s |

Explicitly **excluded** from the MVP: `show running-config` (secrets
risk — revisit only with a concrete need and secure handling), any
`clear`/`debug`, any config-mode command.

## 3. Output parsing strategy

- **Stage 1 — raw capture:** each command's full output saved verbatim
  to `raw/<device>/<command>.txt` with a capture timestamp (audit trail;
  becomes the golden-file corpus).
- **Stage 2 — parsers:** one pure function per command
  (`parse_ip_iface_brief(text) -> list[dict]`, …) using strict line
  regexes tuned against **captured IOS 15.2 samples**; no live network in
  unit tests.
- **Stage 3 — normalizer:** `dict → Topology` fragments using the
  existing Pydantic models directly (no parallel schema). Interface
  names preserved verbatim (`Ethernet0/2`), prefixes normalized via
  `ipaddress`.
- **Ambiguity policy:** unparsable line → collected issue list, never a
  silent drop; issues become `limitations`/`INSUFFICIENT_DATA` context,
  never invented data.

## 4. Mapping into the existing domain model

| Parsed fact | Existing model field |
|---|---|
| hostname / model / IOS version | `Device{id, name, vendor:"cisco", platform, metadata}` |
| interface, ip/mask, up/down | `Interface{id, device_id, name, vrf_id, ipv4_addresses, admin_state, oper_state}` |
| route: prefix, proto, next-hop, iface, active | `Route{device_id, vrf_id, destination_prefix, next_hop, outgoing_interface_id, protocol, active}` |
| CDP adjacency (both ends known) | `Link{source_interface_id, destination_interface_id, state}` |
| OSPF neighbor state | raw evidence file + `Device.metadata` (schema gap — documented, not extended) |
| collection time | result `limitations` string (schema gap) |

VRF: the lab is single-table → everything maps to existing `GLOBAL`.
The mapper **reuses** `load_topology_dict()` validation as the final
gate: if the mapped dict fails validation, collection is reported failed
— the validator stays the source of truth.

## 5. Error handling and timeouts

| Condition | Behavior |
|---|---|
| TCP/SSH unreachable | per-device `unreachable` result with error class; pipeline continues with other devices |
| Auth failure | distinct `auth_failed` result; **no retries with different credentials**; never logs the password |
| Command timeout (default 15 s connect / 30 s per command) | abort device, keep whatever was already captured, mark `incomplete` |
| Partial output / parsing gap | device result `incomplete` + issue list (mirrors the app's `incomplete` status philosophy) |
| Never | crash the whole run on one device; retry loops that could look like scanning; any write attempt |

Output of a run: `collected/<timestamp>/<device>.yaml` + `manifest.json`
(status per device, durations, issue lists). **No scheduling/daemon in
the MVP** — one-shot CLI execution only.

## 6. Credential handling

- Env vars only: `NETTWIN_CISCO_USER`, `NETTWIN_CISCO_PASSWORD`
  (optionally `NETTWIN_CISCO_ENABLE_SECRET` if enable is ever required —
  not expected for read-only show commands).
- Loaded via the existing `.env` pattern (`llm_check.load_env` style),
  which is gitignored; **never** in YAML fixtures, never in git, never in
  logs (password objects redacted by netmiko; we additionally assert no
  secret substring appears in captured logs during tests).
- Same rule as FortiGate: placeholders in all documentation.

## 7. Tests (planned)

| Layer | Content | Network needed? |
|---|---|---|
| Unit — parsers | golden files for all 5 commands (captured from real IOL 15.2 once authorized) → exact structured output | no |
| Unit — allow-list | any non-`show` command raises before send; config-mode detection | no |
| Unit — mapper | parsed dicts → `Topology` passes `load_topology_dict`; counts/ids asserted against fixture expectations | no |
| Unit — errors | timeout/auth/partial fixtures → correct status classes, no secret leakage | no |
| Integration (opt-in) | skipped unless `NETTWIN_LIVE_COLLECT=1` **and** G0 evidence flag set; runs against the two routers read-only, emits YAML that must load + diff cleanly vs `pnetlab_topology.yaml` | yes (opt-in only) |
| Regression | full existing suite + ruff + demo remain green after any merge | no |

## 8. Acceptance criteria (for the implementation stage)

1. G0 PASS evidence is on file; separate authorization received.
2. Two routers (`R2-1`, `R2-3`) collected end-to-end, read-only.
3. Emitted YAML loads via existing `load_topology_dict` with zero
   validation errors.
4. Interface set and IP addresses match `fixtures/pnetlab_topology.yaml`
   (G4-style diff: only ECMP/known-gap differences allowed — anything
   else is a finding, not a silent update).
5. Routes: default `0.0.0.0/0 via 192.168.98.62` on R2-1 observed;
   connected prefixes match the fixture.
6. OSPF neighbor outputs for R2-1/R2-3 match the recorded [DEVICE]
   evidence (FULL ×2 / FULL ×3 respectively).
7. Automated tests for parsers/mapper/allow-list pass; full suite ≥
   current baseline (167) and ruff clean.
8. Proof of read-only: code review + runtime allow-list test; no config
   command appears in any captured session log.
9. No secrets in repo, logs, or reports (automated grep check).
10. One-shot CLI only; no daemon, no scheduling, no auto-push of
    collected data anywhere.

## 9. Explicitly out of scope (MVP)

FortiGate REST (separate proposal), all other three routers, topology
discovery, polling/monitoring loops, config generation of any kind,
integration of collected data into `main` without review.
