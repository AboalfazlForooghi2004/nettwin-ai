# Phase 2.2 — Multi-Device Topology Discovery

**Base:** `0e90c0a7e657fa7269e7794cd8da4c63baece3f8` (Phase 2.1)
**Branch:** `pnetlab/phase2.2-multi-device-topology`

## Result

| Check | Result |
|---|---|
| `python -m pytest` | **273 passed** (223 Phase 2.1 + 50 new) |
| `python -m ruff check .` | **All checks passed!** |
| `python scripts/lab_demo.py --no-llm` | **deterministic: PASS / llm loop: PASS** |
| Domain schema / engine / graph / simulation | **0 files changed** |
| SSH allowlist | **0 lines changed** (still the same five read-only commands) |
| `collected/` in git | **not present** (already ignored since 2.1) |

## Architecture

Four small layers, each testable without SSH, plus one orchestrator:

```
inventory.yaml
     │  load_inventory()            validates; rejects credential fields
     ▼
[DeviceEntry, ...]
     │  CiscoIOSCollector (unchanged from 2.1, sequential)
     ▼
DeviceObservations per device      (one failure never stops the others)
     │  map_to_topology()           unchanged from 2.1
     ▼
per-device Topology
     │  merge_device_topologies()   concatenation + id-collision guard
     ▼
merged Topology (no links yet)
     │  collect_evidence() + discover_links()   TWO-SIDED CDP only
     ▼
final Topology with Link objects
```

| Module | Responsibility |
|---|---|
| `nettwin/collect/discovery/inventory.py` | Inventory parsing/validation, credential-field rejection |
| `nettwin/collect/discovery/identity.py` | Device + interface name normalization, ambiguity-aware indexes |
| `nettwin/collect/discovery/merge.py` | Merge per-device topologies, refuse id collisions |
| `nettwin/collect/discovery/links.py` | CDP evidence model, two-sided matching, `Link` construction |
| `nettwin/collect/discovery/pipeline.py` | Orchestration + `DiscoveryReport` |
| `scripts/discover_cisco_topology.py` | Operator CLI |

### Multi-device collection

* **Sequential**, by design (parallel SSH is out of scope for 2.2).
* Reuses `CiscoIOSCollector` unchanged — same five allowlisted commands.
* Credentials come from `NETTWIN_DEVICE_USERNAME` / `NETTWIN_DEVICE_PASSWORD`
  only. The inventory schema has no credential field and an inventory that
  contains one (`username`, `password`, `secret`, `key`, `token`, …) is
  **rejected with an error**, not silently ignored.
* A failing device is recorded in `report.failures` and the run continues;
  the merged topology contains only what was actually collected.
* If **no** device can be collected, no topology is produced at all
  (rather than an empty one that could be misread as "the network is empty").
* The per-device CLI (`scripts/collect_cisco.py`) is untouched.

### CDP two-sided matching

A link is created only when all four conditions hold:

1. both device names resolve to **collected, distinct** devices;
2. both interface names resolve to interfaces that **exist** on those devices;
3. R2-1's claimed remote interface == R2-2's local interface;
4. R2-2's claimed remote interface == R2-1's local interface.

Worked example (real R2-1 row + synthetic mirror):

```
r2-1: Ethernet0/0  ->  R2-2.nettwin.lab:Ethernet0/1
r2-2: Ethernet0/1  ->  R2-1.nettwin.lab:Ethernet0/0
                   ▼
link r2-1-ethernet0/0--r2-2-ethernet0/1  (state up)
```

Every rejected row produces a `LinkCandidate` carrying an `EvidenceRule`
(`ONE_SIDED_ONLY`, `REMOTE_DEVICE_NOT_COLLECTED`, `AMBIGUOUS_DEVICE_NAME`,
`REMOTE_INTERFACE_UNKNOWN`, `AMBIGUOUS_INTERFACE_NAME`, `INCONSISTENT_SIDES`,
`SELF_REFERENCE`, `SUBINTERFACE`). The CLI writes the accepted evidence per
link to `discovery.evidence.yaml`, so provenance is traceable without
touching the `Link` schema.

### Name normalization

| Rule | Behaviour |
|---|---|
| Case / whitespace | folded (`"  R2-2.Nettwin.LAB "` → `r2-2.nettwin.lab`) |
| FQDN ↔ hostname | full name tried first; short name used **only** if it matches exactly one collected device |
| Ambiguity | two devices sharing `r2-2` under different domains → `ambiguous`, **never** resolved arbitrarily |
| Substring matching | **never** used (`R2` does not match `R2-1`) |
| Interfaces | `Eth`/`Ethernet`, `Gi`/`Gig`, `Fa`/`Fast`, `Te`/`TenGig`, `Lo`, `Vl`, `Se`, `Po` expand to one canonical key |
| Unknown interface family | left as-is (never coerced into a known family) |
| Sub-interfaces | never used as link endpoints (CDP reports physical ports) |

### Strict evidence rules (enforced in code, covered by tests)

* one-sided CDP is **not** enough for a link;
* OSPF adjacency alone never creates an L2 link;
* IP-subnet similarity is never consulted;
* unknown interfaces and unknown devices are never guessed or created;
* inconsistent two-sided CDP produces no link and an explicit warning;
* duplicate CDP rows produce exactly one link;
* two independent parallel links between the same pair of devices are both kept.

## Files added / changed

```
A  src/nettwin/collect/discovery/__init__.py
A  src/nettwin/collect/discovery/identity.py
A  src/nettwin/collect/discovery/inventory.py
A  src/nettwin/collect/discovery/links.py
A  src/nettwin/collect/discovery/merge.py
A  src/nettwin/collect/discovery/pipeline.py
A  scripts/discover_cisco_topology.py
A  fixtures/pnetlab_inventory.yaml
A  tests/test_multidevice_discovery.py            (50 tests)
A  tests/data/multidevice/r2-1.show_cdp_neighbors.txt   (real, copied)
A  tests/data/multidevice/r2-2.show_cdp_neighbors.txt   (SYNTHETIC)
A  tests/data/multidevice/r2-4.show_cdp_neighbors.txt   (SYNTHETIC)
A  docs/PHASE2_2_MULTIDEVICE_REPORT.md            (this file)
```

No existing file was modified. Phase 2.1 behaviour is untouched.

## Fixture provenance

| File | Origin |
|---|---|
| `tests/data/live2026/*` | **real** sanitized R2-1 output (Phase 2.1) |
| `tests/data/multidevice/r2-1.show_cdp_neighbors.txt` | byte copy of the real R2-1 CDP output |
| `tests/data/multidevice/r2-2.*`, `r2-4.*` | **SYNTHETIC** — written to mirror what R2-2/R2-4 *must* report for the real R2-1 rows |

The synthetic fixtures exist only because R2-2 and R2-4 have no management
address yet. They encode the expected answer, not measured data — a live run
is still required to confirm the real devices agree (see limitations).

## Sample inventory

`fixtures/pnetlab_inventory.yaml`:

```yaml
devices:
  - name: R2-1
    host: 192.168.98.34
    platform: cisco_ios
  - name: R2-2
    host: <R2-2-MANAGEMENT-IP>
    platform: cisco_ios
  - name: R2-4
    host: <R2-4-MANAGEMENT-IP>
    platform: cisco_ios
```

## Real run command

```bash
export NETTWIN_DEVICE_USERNAME='nettwin-ro'
export NETTWIN_DEVICE_PASSWORD='...'

# validate without connecting
python scripts/discover_cisco_topology.py \
  --inventory fixtures/pnetlab_inventory.yaml --dry-run

# real collection
python scripts/discover_cisco_topology.py \
  --inventory fixtures/pnetlab_inventory.yaml \
  --output-dir collected/multi
```

## Sample merged output

From the fixture-backed run (3 devices, 2 confirmed links):

```yaml
devices:
- {id: r2-1, name: r2-1, vendor: cisco, platform: IOL, ...}
- {id: r2-2, name: r2-2, vendor: cisco, platform: IOL, ...}
- {id: r2-4, name: r2-4, vendor: cisco, platform: IOL, ...}
vrfs:
- {id: GLOBAL, name: default}
links:
- id: r2-1-ethernet0/0--r2-2-ethernet0/1
  source_interface_id: r2-1-ethernet0/0
  destination_interface_id: r2-2-ethernet0/1
  state: up
- id: r2-1-ethernet0/1--r2-4-ethernet0/1
  source_interface_id: r2-1-ethernet0/1
  destination_interface_id: r2-4-ethernet0/1
  state: up
endpoints: []
services: []
```

`discovery.evidence.yaml` records, per link, the two CDP rows that produced it.

## CLI exit codes

| Code | Meaning |
|---|---|
| 0 | every device collected, topology written |
| 1 | inventory / config / allowlist / merge error |
| 2 | partial — at least one device failed |
| 3 | no device collected, nothing merged |

## Remaining limitations

1. **No live validation on R2-2 / R2-4.** Their addresses are not available;
   all multi-device tests are fixture-based. The synthetic mirrors encode the
   expected answer — the real devices must still confirm it.
2. **L2 only.** No LLDP, no SNMP, no NETCONF/RESTCONF/gNMI, no L3 topology,
   no route-based inference (explicitly out of scope for 2.2).
3. **Sequential collection.** Parallel SSH is out of scope; a slow device
   delays the run.
4. **ECMP** still keeps a single next hop in the domain `Route` (unchanged
   from 2.1); all next hops remain in observations.
5. **Device/interface identity is hostname-based**, not serial or chassis-id
   based. Two devices with the same hostname in different domains are reported
   as ambiguous rather than merged.
6. **Sub-interfaces** are never link endpoints; CDP only reports physical ports.
7. **Links are created only from CDP.** If CDP is disabled on a segment, that
   segment stays unlinked — by design, not by omission.
8. **`Link` schema has no provenance field.** Evidence is written to
   `discovery.evidence.yaml`; the schema was deliberately not extended.
