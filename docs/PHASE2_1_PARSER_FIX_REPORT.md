# Phase 2.1 — Live IOS 15.2 Parser Compatibility Fix

**Base commit:** `c54361a34e1426f3125427f779ec53e4d964e4bd`
**Scope:** parsers + mapping + optional dependency + `.gitignore` + regression tests.
**Not touched:** domain schema, diagnostic engine, allowlist, ECMP behaviour, any device.

## Result

| Check | Before | After |
|---|---|---|
| `python -m pytest` | 210 passed | **223 passed** |
| `python -m ruff check .` | All checks passed | **All checks passed** |
| `python scripts/lab_demo.py --no-llm` | PASS / PASS | **PASS / PASS** |
| CDP rows on live R2-1 output | 0 parsed, 2 warnings | **2 parsed, 0 warnings** |
| `0.0.0.0/0` in domain model | route skipped | **mapped, `Ethernet0/2`** |
| Platform on IOL `show version` | `None` / unknown | **`IOL`** |
| Clean `.[collect]` install | paramiko 5.1.0 (KEX fail) | **netmiko 4.8.0 + paramiko 4.0.0** |

## Files changed

| File | Change |
|---|---|
| `src/nettwin/collect/ios_parsers.py` | CDP column-offset parser; IOL signature recognition |
| `src/nettwin/collect/cisco_ios.py` | Next-hop → connected-prefix resolution; routes preserved without an interface |
| `pyproject.toml` | `collect = ["netmiko[par4]>=4.8,<5"]` |
| `.gitignore` | added `collected/` |
| `docs/UBUNTU_LIVE_TEST_GUIDE.md` | version pin + verification commands |
| `tests/test_cisco_collector.py` | 13 regression tests |
| `tests/data/live2026/*` | sanitized live-shaped fixtures (5 files) |

## Task 1 — CDP parser

The old regex required a single-token Platform (`\S+`) and rejected
`Linux Uni`. CDP is a **column-aligned** table, so parsing now slices each row
on the offsets of the header line from the *same* output:

```
Device ID        Local Intrfce     Holdtme    Capability  Platform  Port ID
R2-2.nettwin.lab Eth 0/0           138             R S I  Linux Uni Eth 0/1
Start:           18               36          47          58         68
```

Behaviour:

* Platform keeps spaces (`Linux Uni`); Capability keeps its codes (`R S I`).
* Rows shorter than the header are sliced to end-of-line — no valid row is
  dropped because of a short last column.
* `Eth 0/0` → `Ethernet0/0` via the existing `normalize_interface()`.
* Output without a header falls back to a regex anchored on the numeric
  Holdtme column (multi-word platform still recovered).
* Existing representative fixtures (single-token `IOL`) parse unchanged.

## Task 2 — Default route without an explicit interface

`S* 0.0.0.0/0 [1/0] via 192.168.98.62` has a next hop but no interface.
`map_to_topology()` used to skip it. Now:

1. The next hop is matched against **collected connected prefixes** — only
   those evidenced by `C … is directly connected, <iface>` rows.
2. Exactly one matching prefix → that interface is used
   (`192.168.98.62` ∈ `192.168.98.32/27` → `Ethernet0/2`) with a warning
   stating the interface was resolved, not read from the output.
3. Zero or multiple matches → the route is **kept** with
   `outgoing_interface_id=None` and an explicit warning. No interface is
   invented and no valid route is dropped.

Protocol, candidate-default flag, AD and metric are preserved in observations
as before (`AD/metric` warning still emitted).

## Task 3 — Cisco IOL platform

`Linux Software (I86BI_LINUXL2-ADVENTERPRISEK9-M)` was not recognised because
the model regex expects `cisco <X> (...)`. The documented image signature
`I86BI_LINUX` / `I86BI-LINUX` (case-insensitive) now yields platform `IOL`,
with a warning quoting the matched line. Without the signature the parsed
model is returned unchanged — unknown platforms stay unknown
(`WS-C2960-24TT-L` is not rewritten to `IOL`).

## Remaining limitations (unchanged, deliberate)

* **ECMP**: the domain `Route` holds one next hop. All next hops remain in
  `observations.routes`; the model keeps the first plus a warning.
* **OSPF adjacency / CDP neighbours**: recorded in observations only; no
  adjacency object exists in the schema and none is inferred.
* A single-device collection never produces links, endpoints or remote
  devices.
* Interface resolution uses only connected prefixes present in the same
  collection; a next hop reachable through a prefix that was not collected
  stays unresolved (warned, not guessed).
* Live SSH behaviour is not exercised by these tests — they are offline and
  mocked; live re-validation against R2-1 is the operator step.
