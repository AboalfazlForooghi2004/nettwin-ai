# Phase 2.5 — Design notes (written BEFORE implementation)

## Investigation results

### Why `links: []` — confirmed root cause

`src/nettwin/collect/nested/discovery.py::_assemble_topology` ends with:

```python
merge = merge_device_topologies(collections)
return merge.topology          # <- links never built
```

Its own docstring says *"links left to Phase 2.2"*. The code path that **does**
build links is `collect/discovery/pipeline.py`, which calls
`discover_links(topology, evidence)` — but `scripts/discover_recursive.py`
never imports `pipeline`. So every recursive run produces
`links: []` by construction, regardless of how much CDP evidence was
collected.

`discover_links` itself is already strict and correct:

* both device names must resolve to collected, distinct devices;
* both interface names must resolve on those devices;
* each side's *remote* interface claim must equal the other side's *local*
  interface;
* one-sided evidence, ambiguous names, self-references and sub-interfaces are
  rejected with a typed `EvidenceRule` reason.

Nothing about that logic needs changing. The fix is to **call it** from the
recursive path and surface its audit trail.

Evidence source: `observations.cdp_neighbors` (`show cdp neighbors`, the summary
table). That is the phase-2.2 evidence model and it carries
`local_interface`, `port_id`, `device_id` on both sides.

### Integration point for a second vendor

`map_to_topology(observations) -> (Topology, warnings)` in
`collect/cisco_ios.py` is the only place that turns one device's parsed
observations into normalized objects (`Device`, `Interface`, `VRF`, `Route`).
`merge_device_topologies` then just concatenates those topologies and reads
`vendor`/`platform` off the per-device `Device`. So a second vendor needs:

1. its own parsers (separate module),
2. its own `map_to_topology` producing the *same* normalized models,
3. a detector that picks the right parser set per device.

No change to `merge`, `identity`, `links`, the domain models, or the walk.

### Verified FortiOS command set

Checked against Fortinet documentation before implementing:

| Command | Verified content |
|---|---|
| `get system status` | `Version: FortiGate-100F v7.4.4,build2662,240514 (GA)`, `Serial-Number:`, `Hostname:`, `Current virtual domain:` |
| `get system interface` | Blocks `== [ port1 ]` with `name:`, `mode:`, `ip: <addr> <mask>`, `status: up/down`, `type:`, `role:` |
| `get router info routing-table all` | `Codes:` header then `S*  0.0.0.0/0 [10/0] via 172.20.120.2, wan1` / `C  10.31.101.0/24 is directly connected, internal` |

Notes that shaped the design:

* `get system interface` prints `status: enable` on older FortiOS and
  `status: up/down` on newer ones — **both must parse**.
* An interface with `ip: 0.0.0.0 0.0.0.0` has no address and must not be given
  a bogus one.
* Routes carry the interface *name*, not an id, so the mapper resolves it
  against the interfaces it just built and drops the route if the name does
  not resolve.
* `get router info routing-table all` prints one `Routing table for VRF=n`
  header per VRF; entry ids must stay unique across them.

### FortiGate neighbor discovery — the honest finding

FortiGate LLDP reception is **disabled by default**:

* `diagnose lldprx neighbor summary` (→ `diagnose lldp rx neighbor summary` in
  FortiOS 7.6.3+) is empty unless `lldp-reception` is enabled globally or per
  interface;
* those `diagnose` commands are diagnostics, not part of the read-only
  allowlist the project maintains;
* before FortiOS 7.0.4 the output reports a *numeric interface index* instead
  of the local interface name, which would need `diagnose netlink interface
  list` to translate — another `diagnose` command.

Decision: **do not** add `diagnose` commands. FortiGate is collected for
identity, interfaces and routes. Its neighbors are captured only from
`get system lldp neighbors` when the operator has enabled LLDP reception;
otherwise the device contributes no links, and the run says so explicitly
instead of inventing them.

## Planned changes

| Area | Change |
|---|---|
| `collect/fortios_parsers.py` | New. `get system status` / `get system interface` / `get router info routing-table all` / `get system lldp neighbors`. |
| `collect/fortios.py` | New. `map_to_topology` for FortiGate producing the existing domain models. |
| `collect/vendor.py` | New. Detection: `cisco_ios` / `fortigate_fortios` / `unknown`, from the collected text. |
| `collect/discovery/allowlist.py` | New. Per-vendor read-only command sets; the IOS set is unchanged. |
| `collect/nested/discovery.py` | `_assemble_topology` now builds links and returns them with provenance. |
| `collect/discovery/render/*` | New. `topology.html` + `topology.svg` from the normalized `Topology` only. |
| `scripts/discover_recursive.py` | Writes `topology.html`/`topology.svg` after discovery. |
| Tests | New fixtures + tests for parsers, detection, links in the recursive path, and both renderers. |

## Non-goals (explicitly not done)

* No rewrite of the walk, the session layer or the transports.
* No change to the domain schema (no new fields on `Device`/`Interface`/`Link`).
* No `diagnose` commands, no config-mode commands, no LLDP-enabling commands.
* No link inferred from IP subnets, OSPF adjacency or interface naming.
