# Phase 2.5 — Topology visualization + FortiGate discovery

Two features landed together because they share one seam: the moment a device's
raw output becomes a normalized `Topology`.

* **A. Automatic visualization** — every successful discovery run now writes
  `topology.html` and `topology.svg` next to `topology.yaml`.
* **B. FortiGate / FortiOS support** — devices are classified by vendor and
  FortiGate is collected and mapped into the *same* domain models as Cisco IOS.

---

## 1. The bug behind `links: []`

### Symptom

Every recursive discovery run wrote `topology.yaml` with `links: []`, even
though `show cdp neighbors` had clearly been collected on every device.

### Root cause (confirmed)

`src/nettwin/collect/nested/discovery.py::_assemble_topology` ended at:

```python
merge = merge_device_topologies(collections)
return merge.topology
```

Strictly speaking its own docstring said so — *"links left to Phase 2.2"* — and
it was accurate: the link stage was never wired into this path. The code that
*builds* links, `discover_links(topology, evidence)`, lived in
`collect/discovery/pipeline.py`, and `scripts/discover_recursive.py` never
imports `pipeline`. Grep confirmed exactly **one** production caller of
`discover_links` (`pipeline.py:160`) and everything else was tests.

So this was never a CDP parsing failure. The evidence was collected, parsed,
merged, and then thrown away at the last step.

### Fix

`_assemble_topology` now runs the existing `discover_links()` unchanged, feeding
it the `cdp_neighbors` rows each device's observations carry:

```python
evidence = collect_evidence(rows_by_device)
link_result = discover_links(topology, evidence)
connected = Topology(..., links=link_result.links, ...)
```

No new matching logic was written. The rules that already existed — and that
`tests/test_multidevice_discovery.py` already covered — now apply to the
recursive path:

| Rule | Behaviour |
|---|---|
| both device names resolve to collected, distinct devices | required |
| both interface names resolve on their own device | required |
| each side's remote-interface claim equals the other side's local interface | required |
| one-sided evidence | rejected (`ONE_SIDED_ONLY`) |
| ambiguous names, self-references | rejected |
| sub-interfaces | rejected |
| reciprocal duplicates | collapsed by `build_link_id` + `seen_pairs` |
| IP/subnet/OSPF adjacency | **never** used to infer a link |

The audit trail is preserved: `RecursiveDiscoveryResult.link_result` carries
every candidate and its `EvidenceRule`, and `discovery.yaml` now includes a
`links:` block with the confirmed count, the rejection histogram, and the
detail string for every non-link row.

---

## 2. Link normalization, concretely

Verified against a scripted three-router run (R2-1, R2-2, R2-4, each reporting
the other two):

```
LINKS (3):
  Ethernet0/0 [10.0.21.2/24] <-> Ethernet0/1 [10.0.21.1/24]   state=up
  Ethernet0/1 [10.0.41.2/24] <-> Ethernet0/1 [10.0.41.1/24]   state=up
  Ethernet0/2 [10.0.22.1/24] <-> Ethernet0/2 [10.0.22.2/24]   state=up
```

Both endpoints, both interface names and both interface addresses are preserved
on each link. Each of the six CDP rows was considered; the three reciprocal
mirrors were recognised as duplicates of already-built links rather than
becoming a second cable:

```
LINK AUDIT: { "both_sides_agree": 6 }
  - both_sides_agree | r2-2: Ethernet0/1 -> R2-1.recip.lab:Ethernet0/0 confirmed by
      r2-1: Ethernet0/0 -> R2-2.recip.lab:Ethernet0/1 (interfaces
      r2-1-ethernet0/0 <-> r2-2-ethernet0/1); duplicate of already-discovered link
      r2-1-ethernet0/0--r2-2-ethernet0/1
```

When evidence is incomplete the result is *no link*, plus the reason:

```
- links: no link from r2-1: Ethernet0/0 -> R2-2.nettwin.lab:Ethernet0/1:
    device 'r2-2' has no CDP row for local interface 'Ethernet0/1'
    (one-sided evidence is not a link)
- links: no CDP neighbour rows were collected on any device — no link can be
    confirmed (none invented)
```

---

## 3. Visualization

### Contract

| Artifact | Shape |
|---|---|
| `topology.html` | one self-contained file: CSS + JS + data all inline |
| `topology.svg` | standalone vector document, valid XML |

Both are pure functions of the normalized `Topology`:

```
topology.yaml --(Topology.model_validate)--> Topology --> render_svg / render_html
```

A test asserts exactly this — `render_svg(reloaded)` is byte-identical to the
SVG the run wrote — so the drawing cannot drift from the data.

### Why the HTML has no dependencies

The requirement is "no backend server or external service required to view".
That rules out a CDN import of d3/vis.js, and it also means the file has to work
when opened from disk with no network at all. So the viewer is ~13 KB of plain
ES2019: an SVG viewport with a `translate/scale` transform, and pointer-event
handlers for pan, zoom and node dragging. `build_payload()` flattens the
topology into JSON that is embedded in a
`<script type="application/json">` block.

`</` inside the JSON is escaped so a device name containing `</script>` cannot
break out of the data block.

### What it shows

* **Devices**: name, vendor, platform, management address, `n/m interfaces up`.
* **Links**: drawn as cables; green solid when up, red dashed when down. Each
  cable is labelled with *both* endpoint interface names near their own end.
* **Click a device** → side panel with identity, metadata (serial, FortiOS
  version, IOS version, VDOM, model), every interface with its addresses and
  state, and every link touching it.
* **Click a link** → both endpoints, both interface names, both interface
  addresses, and state.
* **Controls**: `+`/`−`/fit buttons, wheel-to-zoom at the pointer, drag
  background to pan, drag a device to reposition it.

### Honesty rules in the renderer

* A device whose vendor/platform is `unknown` is drawn as
  `vendor not evidenced`, never with a guessed vendor.
* A device with no management address is drawn as
  `management address not evidenced`.
* Link state is `up` only when both endpoint interfaces are up — inherited from
  `Link`'s own definition, not recomputed.
* Interface state is only shown because the model always carries both
  `admin_state` and `oper_state`; the payload flags each interface with
  `state_evidenced` so the UI never has to infer it.
* A link with a dangling endpoint id cannot even be constructed —
  `Topology.validate_references` rejects it — so the renderer has no
  "invented endpoint" path to get wrong.

### Determinism

Layout is a breadth-first sweep from the highest-degree node (ties broken by
id), so the same topology always renders the same file. Isolated devices are
grid-packed instead of stacked into one tall column.

---

## 4. FortiGate / FortiOS

### Verified command set

Every command was checked against Fortinet documentation before implementation
— no format was assumed.

| Command | Verified content | Read-only |
|---|---|---|
| `get system status` | `Version: FortiGate-100F v7.4.4,build2662,240514 (GA)`, `Serial-Number:`, `Hostname:`, `Current virtual domain:` | yes |
| `get system interface` | `== [ port1 ]` blocks with `name:`, `mode:`, `ip: <addr> <mask>`, `status:`, `type:`, `role:` | yes |
| `get router info routing-table all` | `Codes:` header, `Routing table for VRF=n`, `S*  0.0.0.0/0 [10/0] via 172.20.120.2, wan1`, `C  10.31.101.0/24 is directly connected, internal` | yes |
| `get system lldp neighbors` | neighbours **only if** the operator enabled LLDP reception | yes |

### Version differences absorbed, not hidden

| Difference | Handling |
|---|---|
| `status: enable` / `disable` (older) vs `status: up` / `down` (newer) | both normalized; an unrecognized word becomes `unknown` → recorded `down` with a warning, never assumed up |
| `ip: 0.0.0.0 0.0.0.0` on an unaddressed interface | no address is created; the interface simply has none |
| several `Routing table for VRF=n` sections | kept separate; route ids include the VRF so they stay unique |
| ECMP continuation lines (`      [10/0] via ...`) | first next hop used (the model holds one), the rest reported as a warning |
| route naming an interface that was not collected | route kept with no `outgoing_interface_id`, warning emitted |

### Neighbor discovery — the honest finding

**FortiGate does not receive LLDP by default.** Confirmed on Fortinet's own
documentation: `diagnose lldprx neighbor` is empty unless `lldp-reception` is
enabled globally or per interface, and before FortiOS 7.0.4 the output reports a
numeric interface *index* rather than a name (translatable only with
`diagnose netlink interface list`).

Decision: **`diagnose` commands are not used.** They are a diagnostic subsystem,
outside this project's read-only contract, and adding them to get around a
disabled-by-default feature would be the wrong trade. `get system lldp neighbors`
is in the allowlist but returns nothing on a default device, so a FortiGate
contributes identity, interfaces and routes — and **zero links** — with the run
say so:

```
get system lldp neighbors: empty output — LLDP reception is disabled by
default on FortiGate, so no neighbor evidence is available
(no links are inferred from this device)
```

If an operator *does* enable LLDP reception, the parser will pick the neighbours
up; they occupy the same normalized shape Cisco's CDP rows do, so
`discover_links()` treats them identically (still requiring both sides).

### Architecture

```
collect/vendor.py          detection + per-vendor read-only command sets
   ├── CISCO_IOS_PROFILE       (re-export of cisco_ios.READ_ONLY_COMMANDS, asserted equal)
   ├── FORTIGATE_PROFILE       (git-free, get-only, diagnose-free)
   └── UNKNOWN_PROFILE         (no commands at all)

collect/ios_parsers.py     ──┐
collect/fortios_parsers.py ──┼──> normalized device / interface / vrf / route
collect/cisco_ios.py       ──┤    (domain.models — unchanged schema)
collect/fortios.py         ──┘
                ↓
        discovery/merge.py        (vendor-agnostic: reads vendor off the Device)
                ↓
        discovery/links.py        (vendor-agnostic: CDP-shaped evidence)
```

* The **Cisco allowlist is untouched**; a test asserts
  `set(CISCO_IOS_COMMANDS) == READ_ONLY_COMMANDS`.
* The two command sets are **disjoint**, and dispatching either to the wrong
  vendor raises `VendorCommandError` before anything is sent.
* FortiOS commands must additionally start with `get ` and must not contain
  `config`, `execute`, `diagnose`, `edit`, `set`, `delete`, `reboot`, … .
* Detection is positive-evidence only. Both markers present → `unknown`, no
  guess. No marker → `unknown`, no commands, **no exception** — an unsupported
  device cannot break a run.

---

## 5. Files

**New**

| File | Lines | Purpose |
|---|---|---|
| `src/nettwin/collect/fortios_parsers.py` | 457 | `get system status` / `get system interface` / `get system routing-table` / LLDP parsing |
| `src/nettwin/collect/fortios.py` | 318 | FortiOS observations → normalized domain models |
| `src/nettwin/collect/vendor.py` | 264 | vendor detection, per-vendor allowlists, command validation |
| `src/nettwin/render/__init__.py` | 11 | renderer exports |
| `src/nettwin/render/topology_svg.py` | 345 | standalone SVG |
| `src/nettwin/render/topology_html.py` | 513 | self-contained interactive HTML |
| `tests/test_fortios.py` | 550 | 57 tests |
| `tests/test_topology_render.py` | 354 | 33 tests |
| `tests/test_recursive_links.py` | 402 | 9 tests |
| `tests/test_discovery_outputs.py` | 133 | 6 tests |
| `tests/data/fortios/*` | 9 files | realistic CLI fixtures (incl. legacy FortiOS, multi-VRF, unsupported vendor) |
| `tests/data/nested/recip_*.txt` | 3 files | reciprocal CDP detail fixtures |
| `docs/PHASE2_5_DESIGN_NOTES.md` | — | pre-implementation investigation record |
| `docs/PHASE2_5_TOPOLOGY_AND_FORTIGATE.md` | — | this document |

**Modified**

| File | Change |
|---|---|
| `src/nettwin/collect/nested/discovery.py` | `_assemble_topology` builds links; `link_result` field; warnings surfaced |
| `src/nettwin/collect/nested/progress.py` | `SummaryTable.render(links=...)` (defaulted, backward compatible) |
| `scripts/discover_recursive.py` | writes `topology.html`/`topology.svg`; `links:` block in `discovery.yaml`; link count in summary |

Nothing else in the discovery engine was touched: no change to the walk, the
queue, the session layer, the transports, the merge, the identity indexes, the
link matcher, or the domain schema.

---

## 6. Test results

```
$ .venv/bin/python -m pytest tests/ -q
475 passed in 13.07s

$ .venv/bin/python -m ruff check src/ scripts/ tests/
All checks passed!

$ .venv/bin/python scripts/discover_recursive.py --seed 192.168.98.34 --dry-run
dry-run exit=0
```

`475` total. Baseline before this phase was `370`, so **105 tests were added**
(57 FortiOS + 33 renderer + 9 recursive-link + 6 run-directory).

Coverage of the required cases:

| Required | Test |
|---|---|
| HTML+SVG from a valid topology | `test_html_is_self_contained_no_external_resources`, `test_svg_is_wellformed_xml` |
| empty topology | `test_svg_empty_topology_renders_a_message_not_an_error`, `test_html_empty_topology_renders` |
| devices without links | `test_svg_device_without_links_still_renders`, `test_html_devices_without_links_render` |
| incomplete link info | `test_domain_model_refuses_a_link_with_an_unknown_endpoint`, `test_html_marks_every_rendered_endpoint_as_evidenced` |
| dedupe reciprocal | `test_reciprocal_records_collapse_to_one_link_per_cable`, `test_link_ids_are_unique_no_duplicate_physical_links` |
| device/interface labels | `test_svg_shows_both_endpoint_interface_names`, `test_html_payload_carries_both_link_endpoints` |
| no invented links | `test_one_sided_evidence_never_becomes_a_link`, `test_no_link_is_inferred_from_shared_subnets` |
| identify from `get system status` | `test_identifies_fortigate_from_get_system_status` |
| model + version | `test_status_extracts_model_version_serial_hostname` |
| interface parse | `test_interfaces_parsed_with_addresses_and_states` |
| routing-table parse | `test_routing_table_parses_all_entry_kinds` |
| missing/incomplete fields | `test_status_missing_fields_warn_but_do_not_crash` |
| unsupported FortiOS safe | `test_status_empty_output_is_not_evidence`, `test_missing_everything_does_not_crash` |
| Cisco behavior unchanged | `test_cisco_command_set_is_unchanged`, `test_identifies_cisco_unchanged` |
| unsupported devices don't crash | `test_unsupported_device_does_not_break_the_run` |

### Browser verification

The HTML viewer was not only unit-tested: it was driven in headless Chromium
via Playwright. That found three real bugs the static tests missed, all fixed
and now guarded by regression tests:

1. **Clicking a device showed nothing** — the node's click bubbled to the stage
   handler, which immediately reset the panel. Fixed by only resetting when the
   click lands on the background itself.
2. **Link hit areas were unclickable** — `stroke: transparent` is not reliably
   hit-testable. Fixed with `stroke-opacity: 0.001`.
3. **Clicks on nodes and links were swallowed** — the pan handler called
   `setPointerCapture` on the whole SVG. Fixed by only starting a pan on the
   empty canvas.

Final browser state: 3 device nodes, 3 clickable cables, device panel and link
panel both populate correctly, wheel zoom changes the transform (1.0 → 1.79), no
console or page errors.

---

## 7. Known limitations

* **FortiGate contributes no links by default.** LLDP reception is off on
  FortiOS unless the operator enables it; this is a property of the device, not
  of the collector. No `diagnose` command was added to work around it. A mixed
  Fabvric where only Cisco devices speak CDP will show the FortiGate isolated.
* **FortiOS reports one state string,** not separate admin and link states. The
  mapper records it in both fields and warns; a link touching a FortiGate
  interface is only `up` when that string says `up`.
* **ECMP routes lose extra next hops** in the domain model (one `next_hop`
  field). They are preserved in the warning text, not silently dropped.
* **FortiGate neighbour evidence, when LLDP is enabled,** has a parser entry
  point but the concrete `get system lldp neighbors` block format was not
  exercised against a live device. `parse_lldp_neighbors` currently recognizes
  the `== [ name ]` block form; a different layout yields zero neighbours plus
  the existing warning rather than a wrong neighbour.
* **The HTML viewer has no persistence** — dragging nodes is per-session, by
  design (no backend).
* **The SVG is a static snapshot** of the deterministic layout; it does not
  reflect node positions changed interactively in the HTML.
* **No live FortiGate was used** for any test, per the task constraints. All
  fixtures are documentation-derived, and the FortiOS 6.x / 7.x / 8.x variants
  differ enough that a real device may still surface a format this parser does
  not recognize — in which case it yields a warning, not a wrong object.

---

## 8. Example generated output

A run directory from a scripted three-router discovery:

```
collected/<run>/
├── discovery.yaml       walk + link audit + warnings
├── topology.yaml        normalized topology
├── topology.html        interactive, offline
└── topology.svg         standalone vector
```

`topology.yaml` (abridged):

```yaml
devices:
- id: r2-1
  name: r2-1
  vendor: cisco
  platform: IOL
  management_address: 192.168.98.34
interfaces:
- id: r2-1-ethernet0/0
  device_id: r2-1
  name: Ethernet0/0
  ipv4_addresses: [10.0.21.2/24]
  admin_state: up
  oper_state: up
links:
- id: r2-1-ethernet0/0--r2-2-ethernet0/1
  source_interface_id: r2-1-ethernet0/0
  destination_interface_id: r2-2-ethernet0/1
  state: up
```

`discovery.yaml` link audit (abridged):

```yaml
links:
  confirmed: 3
  matched_rows: 6
  rules:
    both_sides_agree: 6
  candidates:
  - rule: both_sides_agree
    detail: "r2-2: Ethernet0/1 -> R2-1.recip.lab:Ethernet0/0 confirmed by
             r2-1: Ethernet0/0 -> R2-2.recip.lab:Ethernet0/1 (interfaces
             r2-1-ethernet0/0 <-> r2-2-ethernet0/1); duplicate of
             already-discovered link r2-1-ethernet0/0--r2-2-ethernet0/1"
  note: links are built only from two-sided CDP evidence; one-sided or
        ambiguous rows stay candidates
```

The same topology rendered as SVG: devices in columns by hop distance, each
cable labelled with both interface names and both addresses, green solid for up,
red dashed for down, with the footer note
*"drawn from confirmed two-sided evidence only"*.
