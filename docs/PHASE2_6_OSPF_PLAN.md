# Phase 2.6 — OSPF discovery & LSDB topology reconstruction

## Plan (written before implementation)

### Inspection findings — where OSPF plugs in

| Concern | Existing component | Reuse decision |
|---|---|---|
| read-only command allowlist | `cisco_ios.READ_ONLY_COMMANDS` (frozenset) + `_FORBIDDEN_FRAGMENTS` | **extend** with `show` commands only |
| command dispatch order | `cisco_ios.DEFAULT_COMMANDS` → `nested.discovery.DISCOVERY_COMMANDS` | **append** so phase-2 order is preserved |
| command → parser map | `nested.discovery._PARSERS` | **extend** |
| per-device parsed state | `cisco_ios.DeviceObservations` (dataclass) | **add fields**, defaults keep old callers working |
| CLI text parsing | `ios_parsers.py` (one module, one parser per command) | **new sibling module** `ospf_parsers.py` — OSPF output is a different shape and would bloat the IOS module |
| normalized device/interfaces/routes | `domain/models.py` | **reuse unchanged** for the IP-level objects |
| link building | `discovery/links.py` (`discover_links`, `CdpEvidence`) | **untouched** — OSPF must not create `Link` objects |
| merge | `discovery/merge.py` | **untouched** |
| topology assembly | `nested/discovery.py::_assemble_topology` | **extend**: after links, build the OSPF logical topology |
| output | `discovery.yaml` / `topology.yaml` / `topology.html` / `topology.svg` | **extend**, schema-compatible |
| rendering | `render/topology_svg.py`, `render/topology_html.py` | **extend** with a separate OSPF view, not a change to the CDP drawing |

Key architectural fact: `Link` in `domain/models.py` is a *physical/logical
interface-to-interface* object and `discover_links()` is the only thing that
creates links, from two-sided CDP evidence. OSPF transit networks are a
**many-to-many** relationship (a multi-access segment with N routers). Forcing
them into `Link` would either invent point-to-point cables or lose members. So:

> OSPF gets its own normalized model (`ospf_models.py`) and its own topology
> object (`OspfTopology`). `Topology.links` keeps meaning exactly "confirmed
> layer-2 adjacency". Nothing in the existing schema changes.

### New modules

| Module | Responsibility |
|---|---|
| `collect/ospf_parsers.py` | six `show ip ospf ...` parsers. Pure text → dataclasses. One small function per command, shared line-level helpers. |
| `domain/ospf_models.py` | pydantic models: `OspfInstance`, `OspfArea`, `OspfNeighbor`, `OspfRouterLsa`, `OspfLsaLink`, `OspfNetworkLsa`, `OspfTransitNetwork`, `OspfStubNetwork`, `OspfRoute`, `OspfTopology` |
| `collect/ospf_topology.py` | reconstruction: Router LSA → links, Network LSA → transit networks, Type-1/Type-2 correlation, stub extraction, evidence validation states, CDP correlation |
| `render/ospf_svg.py` | standalone OSPF logical-topology SVG (routers, transit networks as distinct node shape, stub prefixes) |
| `render/ospf_html.py` | interactive OSPF view, same offline/no-backend constraints |

### Commands collected (all `show`, all read-only)

```
show ip ospf neighbor
show ip ospf interface brief
show ip ospf database                 (summary)
show ip ospf database router          (Type 1 detail)
show ip ospf database network         (Type 2 detail)
show ip ospf route                    (SPF-derived routes)
```

`show ip ospf interface brief` is preferred over `show ip ospf interface`
because it carries PID/Area/IP-mask/cost/state/neighbour counts in one row
without authentication material. Authentication is therefore **never** parsed
and cannot leak. `show ip ospf interface` is intentionally not collected.

### Reconstruction algorithm

1. **Router LSA (Type 1)** → per link, classify `Point-to-Point | Transit |
   Stub | Virtual`. Keep Link ID, Link Data, mask, metric, MTID, and the LSA
   reference (area, adv router, LSID, seq, checksum, age).
2. **Network LSA (Type 2)** → Link State ID is the DR interface address;
   `Network Mask` gives the prefix; `Attached Router` lines give membership.
   Reference kept.
3. **Transit correlation** → join Type-1 transit links to Type-2 LSAs on
   `(area, DR address)`. For each member router, resolve that router's own
   interface address from its *own* Type-1 transit link whose Link ID equals the
   DR address. Validation states:
   * `confirmed` — Type-1 membership and Type-2 attached list agree, and the
     member's interface address falls inside the network prefix;
   * `partial` — only one side present (e.g. Type-2 seen but that router's
     Type-1 not in the LSDB);
   * `inconsistent` — both present but they disagree;
   * `unresolved` — DR address cannot be tied to a router or a prefix.
4. **Point-to-point** → a Type-1 P2P link may only become a logical edge when
   the peer's Router ID is derivable from the Link Data subnet *and* the peer
   Router LSA independently links back (`reciprocal`). One-sided P2P stays a
   hint, never an edge. No `Link` object is produced either way.
5. **Stub** → `(adv_router, prefix, mask, area, metric)`; never becomes a node
   or an edge.
6. **Routes** → `OspfRoute` list, kept separate. Classification distinguishes
   `Connected` (local interface, cost 1, "in <local ip>") from `Intra`/`Inter`/
   `External`. Connected entries are *never* labelled OSPF-learned.

### Evidence provenance

Every reconstructed relationship carries `source_lsas: list[OspfLsaRef]` and
`evidence: list[str]` naming the command that produced it
(`ospf-router-lsa`, `ospf-network-lsa`, `ospf-neighbor`, `ospf-route`).
OSPF evidence is never merged into `Link.source`/`Link.state`.

### CDP correlation

`correlate_with_cdp(ospf_topology, topology)` produces, per logical
relationship, one of:

* `cdp_confirmed` — a CDP link exists between the same two devices AND the OSPF
  prefix sits on one of that link's interfaces;
* `cdp_missing` — OSPF says adjacent, CDP saw nothing (physically normal
  through a switch — reported, not an error);
* `cdp_disagrees` — CDP links those devices but no common prefix, or OSPF does
  not see an adjacency on a CDP-linked pair that both run OSPF.
* `no_cdp_data` — CDP produced nothing for that device at all.

Discrepancies are reported. Neither source is silently preferred.

### Testing

Real fixture set built from the lab tables in the task (`tests/data/ospf/`),
covering 5 routers, 5 transit networks, 2 areas worth of stub data, plus
malformed / empty / partial / conflicting variants. Target: one test per
required case (17 listed) plus reconstruction and regression guards.

### Non-goals

* No OSPF configuration, no `show ip ospf interface` (auth strings).
* No change to `Link`, `discover_links`, `merge`, or the CDP drawing.
* No live device access; every test is offline.
* No claim of FortiGate OSPF support — FortiOS OSPF is not collected here.

---

## Delivered

Status: implemented, integrated, tested and linted. Everything above was written
before the code and is left in place as the record of that plan; the notes below
say what actually landed and where it deviates.

### What was built

| Module | Lines | What it does |
|---|---|---|
| `domain/ospf_models.py` | ~430 | 15 pydantic models. Separate namespace from `domain.models` on purpose. |
| `collect/ospf_parsers.py` | ~740 | 6 command parsers + `process_context`. Each returns `(items, warnings)`. |
| `collect/ospf_topology.py` | ~600 | `reconstruct_transit_networks`, `reconstruct_point_to_point_edges`, `reconstruct_stub_networks`, `build_ospf_topology`, `correlate_with_cdp`. |
| `render/ospf_svg.py` | ~560 | Static SVG. Lanes: routers → transit hexagons → stub pills. |
| `render/ospf_html.py` | ~700 | Interactive inspector, one self-contained file. |

Integration, all edit-in-place rather than parallel copies:

* `cisco_ios.py` — the 6 OSPF commands joined `READ_ONLY_COMMANDS` (11 total).
  A new `OPTIONAL_COMMANDS` frozenset marks them as *tolerable to fail*:
  a device with no OSPF answers `% OSPF not enabled` and returns an error, and
  that must not make the device `partial`. `_overall_status` is now
  optional-aware — **error** on an optional command ⇒ status stays `ok` with a
  warning; **timeout** ⇒ `partial`, because a device going silent mid-walk is a
  real anomaly even if the missing section was optional.
* `nested/discovery.py` — `_PARSERS` gained the 6 commands; the walk loop catches
  `SessionError`/`SessionTimeoutError` for optional commands only and records
  `optional command unavailable — …`; `_attach_ospf` normalizes parsed rows into
  `DeviceObservations`; `ospf_device_data()` (module-level) rebuilds typed objects;
  `RecursiveDiscoveryResult.ospf_topology` is populated by `_assemble_topology`.
* `discover_recursive.py` — writes `topology.yaml` with an `ospf:` **sibling**
  key, adds an `ospf:` section and an `_ospf_audit()` helper to `discovery.yaml`,
  and renders `ospf.svg` / `ospf.html` next to the Phase 2.5 pair.

### Deviations from the plan, and why

1. **`show ip ospf interface` is not collected at all.** The plan said "only
   where necessary". It became unnecessary: `show ip ospf interface brief`
   carries PID, area, address/mask, cost, state and neighbour counts in one row,
   and the detailed form is where `Message digest authentication enabled` and
   key ids appear. Dropping it removes the credential-exposure surface entirely
   rather than filtering it. A test asserts the command is absent and that no
   allowlisted OSPF command contains `key`/`password`/`auth`.
2. **`topology.yaml` gained a sibling `ospf:` key, not new `Topology` fields.**
   `Topology` is `extra="forbid"`, and more importantly a transit network must
   never become a `Link`. Serializing OSPF beside the physical document keeps a
   Phase 2.5 reader working unchanged.
3. **The SVG puts transit networks in their own lane** (hexagons under the
   router row, membership spokes going up), rather than treating them as edge
   labels. A segment with N members is a node with N spokes; drawing it as
   N×(N−1)/2 router-to-router lines would be exactly the false claim the task
   forbids. Stub prefixes are pills with **no** connector at all.
4. **Routers are ordered breadth-first over the transit-membership graph**, not
   alphabetically, so the two ends of each /30 sit next to each other. Still
   fully deterministic.

### Two real bugs found while testing

* **Duplicate dict key** in `nested/discovery.py`: `"show ip ospf neighbor"` was
   registered twice, the stale `ios_parsers` entry silently shadowed by the new
   one. Removed (caught by `ruff` F601).
* **JSON-in-HTML injection in *both* HTML renderers.** Escaping `</` was not
   enough: a device hostname of `<script>alert(1)</script>` arrived intact inside
   the embedded JSON and would execute for any consumer that inserts it into the
   DOM. Both `topology_html.py` (pre-existing, Phase 2.5) and `ospf_html.py` now
   use `_embed_json()`, which escapes `<`, `>`, `&` (and U+2028/9) as JSON
   `\uXXXX` escapes — valid JSON, decodes to the original string, no `<`
   survives to be read as markup. Hostnames are attacker-controlled data, so
   this was a genuine, reachable hole.

### Verification

* `pytest tests/` — **690 passed** (649 at the start of this fix round; +41 new
  integrity tests). See `docs/PHASE2_6_ROOT_CAUSES.md` for the six defects these
  tests exist to catch.
* `ruff check .` — clean.
* Reference lab reproduced exactly: 5 transit networks, 5 router IDs, 10/10
  member interface addresses, 7 stubs, 11 routes (9 learned + 2 connected),
  `10.0.12.0/30` and `10.0.12.4/30` correctly absent from the OSPF routes.
* SVG verified by rasterizing with cairosvg; the HTML verified in headless
  Chromium (no console errors, all panels reachable).

### Test modules added

| File | Tests | Covers |
|---|---|---|
| `tests/test_ospf_parsers.py` | 90 | every parser against the real fixtures, plus empty/malformed/hostile input; fixture-integrity guards |
| `tests/test_ospf_recursive.py` | 18 | OSPF inside the real `RecursiveDiscovery.run()` walk |
| `tests/test_render_ospf.py` | 51 | SVG/HTML structure, the never-a-cable rule, evidence states, XSS |
| `tests/test_ospf_outputs.py` | 16 | `topology.yaml` / `discovery.yaml` on disk, backward compatibility |
| `tests/test_ospf_lsdb_integrity.py` | 41 | canonical LSAs vs observations, observer provenance, observer≠Advertising Router, conflicting LSA instances, attribution completeness, route sources kept separate, the documented stub contract, lab acceptance |

### Known limits (stated, not hidden)

* Verified against **Cisco IOS fixtures only**. FortiOS OSPF is not collected and
  no claim is made about it. Nothing here has been run against physical hardware
  in this phase; the fixtures are the reference lab's real output.
* Only OSPFv2 for IPv4. OSPFv3, virtual-link transit reconstruction (classified
  and preserved, but not reconstructed into edges) and multi-process correlation
  are represented in the models but not reconstructed end to end.

---

## Phase 2.6 fix round — LSDB canonicalisation, attribution, route reconstruction

Three defects reported from a live five-router run, three more found while
fixing them. Full root causes and reasoning live in
`docs/PHASE2_6_ROOT_CAUSES.md`; this is the summary.

| # | Reported symptom | Root cause | Fix |
|---|---|---|---|
| A | 25 Router LSAs / 25 Network LSAs / 25 transit networks for 5 of each | nothing canonicalised: every device's copy was concatenated and one transit network emitted per Type-2 record. Stub reconstruction happened to dedupe, hiding half the symptom | canonical LSA layer run before reconstruction; identity = `(area, type, LSID, adv router)`; provenance kept in `observed_by` |
| A′ | *(found while fixing A)* all router-ids credited to one device; uncollected routers marked `collected`; ten bogus CDP correlations | "this LSA is in my LSDB" was read as "this LSA is mine" | `_originator_is_self()`: own LSA ⇔ Advertising Router ≡ the device's own reported router-id (interface evidence as a documented fallback) |
| B | 21 interfaces / 25 LSAs with empty `device_id`, transit refs `"unknown"` | dispatch called `parser(text)`; the observer never reached the parser | `show version` parsed first, device-scoped command set derived from parser signatures, `device_id` threaded through; `_attributed()` backfills |
| C | zero OSPF routes | the parser's table regex could not match real IOS comma-format output; the fixture had been written to fit the parser, so tests passed while the wire format failed — silently | parser accepts the real format; fixture replaced with genuine IOS output; `Connected` suffix overrides the type column |
| D | `UnboundLocalError` on any run with Router LSAs | `any_ospf_signal` assigned inside `if not router_lsas:` and read later | computed once before use |
| E | counters could say "25 transit networks" | observed records and canonical identities shared one number | `lsa_counts()` reports identities, observations and observer count separately; CLI and renderer payload both use it |

**Architectural decision.** LSA *identity* and *observation* are now different
objects. Identity is what the topology is reconstructed from; observation is
provenance and is preserved on `observed_by`. Conflicting instances are never
resolved silently: the RFC 2328 §13.1 ordering picks the winner *and* a warning
names every observer's sequence/checksum. Network-LSA membership is unioned, so
no observer can hide a member. Route tables are deliberately **not**
canonicalised — they are per-device evidence, not flooded state.

**Stub contract.** A Stub Network is what a Type-1 LSA advertises, not what is
configured on an interface. A prefix that is both appears once (the LSDB claims
it); a configured subnet the router does not advertise does not appear.
`advertised_stub_links()` is the ground truth and a test pins reconstruction to
it in both directions. The reference lab yields **7**, and an eighth would
reconstruct automatically if the evidence ever contained one.

### Fix-round verification

* `pytest tests/` — **690 passed**; `ruff check .` clean.
* Lab acceptance through the real pipeline with five device-specific observers:
  5 devices, 5 unique Router LSAs, 5 unique Network LSAs, 5 transit networks,
  7 stubs, 11 routes per device (9 learned / 2 Connected), 0 missing device IDs,
  `logical_edges = 0` (no reciprocal point-to-point evidence exists, so this is
  correct rather than a gap).
* Physical topology untouched: CDP results are byte-identical with and without
  OSPF, and a regression test asserts it.
