# Phase 2.6 — Root cause analysis (pre-implementation)

Written before any code change, per the task's execution workflow §7.2.

---

## A. Duplicate LSAs and transit networks (25 instead of 5)

**Symptom.** Five routers, each reporting the same five Type-2 LSAs, produce 25
Network LSAs and 25 Transit Networks.

**Root cause.** `build_ospf_topology()` concatenates every device's records into
flat lists and hands the concatenation to the reconstruction functions:

```python
topology.router_lsas.extend(device.router_lsas)     # 5 observers × 5 LSAs
topology.network_lsas.extend(device.network_lsas)
router_lsas.extend(device.router_lsas)
network_lsas.extend(device.network_lsas)
```

There is **no canonicalisation step anywhere**. Whether a consumer multiplies
depends on whether each *reconstruction* function happens to dedupe:

| Function | Dedupe? | Result with 5 observers |
|---|---|---|
| `reconstruct_stub_networks` | yes — `(area, adv_router, prefix)` | 7 ✅ |
| `reconstruct_transit_networks` | **no** — one object per Type-2 record | 25 ❌ |
| `reconstruct_point_to_point_edges` | no (but no P2P links here) | — |

So the bug is not "transit reconstruction is wrong"; it is that **the LSDB is a
set shared by many observers and the model has no notion of that**. The
per-function dedupe made one symptom invisible and the other visible.

**Fix.** Introduce an explicit canonical-LSA layer *before* reconstruction:

- An LSA's identity is `(area, lsa_type, link_state_id, advertising_router)` —
  exactly what the task specifies, and exactly the OSPF LSA identity
  (LS type, Link State ID, Advertising Router) scoped by area.
- Observer provenance is a separate axis: `observed_by` is the set of devices
  whose LSDB contained that LSA. Nothing is discarded.
- Sequence/checksum differences for the same identity are **not** collapsed
  silently: the canonical copy keeps the highest sequence number (RFC 2328
  §13.1 instance ordering) and a warning records that the observers disagreed,
  naming each observer's sequence.

## B. Missing device attribution

**Root cause, two independent defects.**

1. In `_observations_from()`, the dispatch loop calls every parser as
   `parser(text)`. The OSPF parsers take `(text, device_id)`, so `device_id`
   silently defaults to `""`. `parse_show_ip_ospf_interface_brief`,
   `…_database_router`, `…_database_network` and `…_route` all therefore
   produce rows with an empty `device_id`.

   The CDP and `show ip route` parsers keep working because they are
   single-argument parsers — which is why only OSPF was affected.

2. `_attach_ospf()` copies `item.model_dump()` straight onto observations, which
   faithfully preserves that empty id, and `ospf_device_data()` re-validates the
   rows without ever filling it in. `_lsa_ref()` then does
   `device_id=lsa.device_id or "unknown"`, which is how
   `device_id="unknown"` reached the transit LSA references.

**Note on identity.** The observing device and the LSA's *Advertising Router* are
different things and must not be conflated: R2's LSDB contains R2-1's Router LSA,
so `device_id="r2"` while `advertising_router="10.255.255.1"`. The fix attributes
the observer and leaves the advertising router alone.

**`OspfLsaSummary`.** `show ip ospf database` is a *summary of the LSDB*, so every
row is likewise something the device observed rather than originated. The model
has no observer field; it is extended with `device_id: str = ""`, which is
backward compatible (defaulted, and `extra="forbid"` means nothing else changes).

## C. OSPF routes missing from live output

**Root cause: the parser's row regex does not match real Cisco IOS output.**

`parse_show_ip_ospf_route()` expects a tabular row:

```
10.0.23.0/30         1       Connected  in 10.0.23.1     Et0/0
```

That shape is what the hand-written fixture contains, but it is **not** what
`show ip ospf route` prints. Real IOS prints comma-separated rows with the
next hop on its own line (Cisco IOS IP Routing: OSPF Command Reference):

```
    Intra-area Route List
*   192.168.20.0/30, Intra, cost 64, area 0, Connected
      via 192.168.20.1, Serial0/1
*>  192.168.10.64/26, Inter, cost 138, area 0
      via 192.168.20.2, Serial0/1
```

Against real output the regex matches nothing, the parser returns an empty list
with a warning, and the warning is swallowed into `observations.warnings` — so
`OspfTopology.routes` is empty on a live device while an offline fixture test
passes. The fixture was written to match the parser instead of the parser being
written to match the device, which is exactly how this class of bug hides.

Additional real-IOS shapes that must also work:

- `Codes: …` legend lines (already skipped)
- `Area BACKBONE(0)` and `Area 4` headers
- section headers: `Intra-area Route List`, `Inter-area Route List`,
  `External Route List`, `Intra-area Router Path List`
- `Intra-area Router Path List` rows (`i 1.1.1.1 [10] via …`) are **not** routes
- `via` lines, including several ECMP `via` lines per prefix
- `tag 0` on external routes
- `SPF Instance`/`Flags:`/`LSA:` continuation lines that are not routes

**Fix.** Rewrite the route parser to consume the comma form and keep the old
tabular form working (harmless, and it keeps older fixtures/transcripts valid).
The fixture itself is corrected to real IOS output so the tests exercise reality.

## D. Stub prefix count: 7 vs 8

**The fixture advertises 7 stub links, and the task's "8" appears to be an
off-by-one.** Verified by parsing, not by assumption:

| Advertising router | Stub links in its Router LSA |
|---|---|
| 10.255.255.1 | `192.168.98.32/27` (metric 1) |
| 10.255.255.2 | `10.255.255.2/32`, `10.0.12.0/30`, `10.0.12.4/30` |
| 10.255.255.3 | `10.255.255.3/32` |
| 10.255.255.4 | `10.255.255.4/32` |
| 10.255.255.5 | `10.255.255.5/32` |

That is seven, and **`10.255.255.1/32` is not among them**: R2-1's Router LSA
carries two transit links and one stub link (`192.168.98.32/27`), with no
loopback stub. The task's list of eight includes `10.255.255.1/32`, which the
fixture does not contain.

Two independent cross-checks confirm the fixture is self-consistent rather than
truncated:

- Routes to `10.255.255.2…5/32` are direct (`Connected`, cost 1); the route to
  `10.255.255.1/32` is *learned* at cost 22 via `10.0.23.2`, i.e. R2-1's loopback
  is reached across the topology, not advertised as a stub on-link.
- R2-1's `192.168.98.32/27` is the management segment R2 itself sits in.

**Action taken: none on the fixture.** Rewriting a captured-LSDB fixture to add
a stub link that the device did not advertise would fabricate LSDB evidence —
the one thing this phase must never do. The contract is documented and
**machine-enforced**: every Stub Link present in a Router LSA must appear in
`stub_networks`, and no stub may be dropped because its prefix is also a
connected interface (a new test asserts `10.0.12.0/30` and `10.0.12.4/30`,
which are also R2's own connected subnets, are still present).

If the real PNETLab LSDB does carry an eighth stub, it will be reconstructed
automatically — the code has no count constant anywhere.

## E. Latent bug found while reading: `any_ospf_signal` unbound

In `build_ospf_topology()`, `any_ospf_signal` is assigned only inside the
`if not router_lsas:` branch but read later by
`if not topology.neighbors and devices and any_ospf_signal:`. When Router LSAs
*are* present the name is unbound — `UnboundLocalError`, which would take out
the whole OSPF section. It has not fired only because every exercised path so
far had either no devices or no neighbours. Fixed as part of this work.

## F. Summary counters are ambiguous

`_assemble_topology` and the CLI report raw list lengths, so a 5-router run
prints "25 transit network(s)". Counters must distinguish *observed* (records,
including duplicates across observers) from *canonical* (unique LSAs) and
*reconstructed* (unique logical objects).

---

## Outcome — what was actually changed

All six defects were fixed in place; nothing was rewritten from scratch and no
physical-topology behaviour changed.

### A. Duplicated LSAs (25 → 5)

`build_ospf_topology()` concatenated every device's observations and
`reconstruct_transit_networks()` emitted one network per Type-2 record, so a
five-router flood produced 25 LSAs and 25 transit networks. `reconstruct_stub_networks()`
happened to dedupe on `(area, advertising_router, prefix)`, which is why the
stub count looked right while everything else was multiplied.

**Fix:** a canonical layer runs between collection and reconstruction.

* `LsaIdentity` = `(area, lsa_type, link_state_id, advertising_router)`.
* `canonical_router_lsas()` / `canonical_network_lsas()` collapse copies.
* The winner is chosen by the RFC 2328 §13.1 ordering — newest sequence
  instance, then lowest age, then checksum.
* Network-LSA attached routers are **unioned**, so no observer can hide a member.

`build_ospf_topology()` now assigns `topology.router_lsas` / `.network_lsas` from
the canonical lists, and reconstruction reads those. Route tables are **not**
canonicalised: each router's OSPF route table is its own evidence (5 routers ×
11 routes = 55 is correct, and `learned_routes()` = 45).

### A′. Attribution (found while fixing A — this was latent and worse)

`router_ids[router_id].add(device.device_id)` was fed by
`[lsa.advertising_router for lsa in device.router_lsas if lsa.device_id == device.device_id]`
— i.e. "every LSA in my LSDB is mine". In a flooded area that credited all five
router-ids to the first device collected and reported four routers that were
never SSH'd into as `collected=True`. It also produced ten bogus CDP
correlations between devices with no physical evidence.

**Fix:** `_originator_is_self()`. A device owns an LSA only if the LSA's
Advertising Router equals the router-id *that device reported about itself*;
failing that, interface-address evidence is used, and that fallback is named as
inference in the docstring. Holding a copy never counts as originating it.

### B. Empty device IDs

The dispatch loop called `parser(text)`, so every ``device_id`` defaulted to
`""`; `_lsa_ref()` then turned that into `"unknown"`.

**Fix:** `_observations_from()` parses `show version` first, derives the
device-scoped command set from the parser signatures with `inspect`, and passes
`device_id` into every parser that accepts it. `ospf_device_data()` backfills
through `_attributed()`. Verified: zero empty IDs, zero `"unknown"` across
neighbours, interfaces, both LSA types, routes, stubs, database summary and
transit source references.

### C. Zero OSPF routes

The parser's table regex could not match real IOS output, which uses the
resource-string/comma form (`*  192.168.20.0/30, Intra, cost 64, area 0, Connected`
with a `via …` continuation). The fixture had been hand-written to fit the
parser, so the tests passed while a real router produced nothing. The loss was
silent: a warning went into `observations.warnings` and `routes` came back empty.

**Fix:** the parser accepts the real format (legacy tabular retained), and the
fixture is now genuine IOS output. Connected networks print their type as
`Intra` and are distinguished **only** by the `Connected` suffix, so that
suffix overrides the type column — otherwise every connected network counts as
learned.

### Counters

`OspfTopology.lsa_counts()` reports identities and observations separately
(`router_lsas: 5`, `router_lsa_observations: 25`, `observers: 5`), and both the
CLI and the renderer payload use it. The CLI additionally prints a line naming
the multiplicity. A run can no longer say "25 transit networks" when there are
five.

### Stub contract (§2) — seven, and the distinction is the point

A **Stub Network** is `(prefix, advertising router, area, metric)` exactly as a
Type-1 LSA advertises it: the LSDB's statement that a router owns a prefix
on-link. It is *not* a statement about interface configuration. The two are kept
separate in both directions:

* `10.0.12.0/30` and `10.0.12.4/30` are advertised **and** configured on R2 — they
  appear, because the LSA advertises them. Being a connected subnet never
  suppresses a stub.
* `10.255.255.1/32` is an interface subnet somewhere but is **not** advertised as
  a stub, so it does not appear. R2 reaches it as a learned route at cost 22.

`advertised_stub_links()` exposes the ground truth, and a test asserts
`advertised_stub_links(lsas) == {(s.area, s.advertising_router, s.prefix) for s in reconstruct_stub_networks(lsas)}`
— so the reconstruction can never drift from the LSDB in either direction.
**The lab yields 7 stubs.** An eighth would need an eighth advertised link; the
code has no count constant, so one would reconstruct automatically.

### Latent bug

`any_ospf_signal` was assigned inside `if not router_lsas:` and read later,
raising `UnboundLocalError` on every run that *did* have Router LSAs. Now
computed once, before use.

## Verification

* `690 passed` (649 before + 41 new in `tests/test_ospf_lsdb_integrity.py`).
* `ruff check .` clean.
* Reference lab through the real pipeline: 5 router LSAs, 5 network LSAs,
  5 transit networks, 7 stubs, 11 routes on R2 (9 learned / 2 Connected),
  0 missing device IDs, `logical_edges=0` (no reciprocal P2P links exist).

---

## Correction round — RFC 2328 §12.1.6 and §13.1 conformance

A review of `1454096` found three protocol-level defects in the canonical layer:
the sequence space was parsed unsigned, the ordering was a generic sort key
rather than §13.1's, and Network-LSA membership was unioned across versions.

### 1. Signed LS sequence numbers (§12.1.6)

`_sequence_value()` did `int(text, 16)`, giving an unsigned value. RFC 2328
§12.1.6 defines the space as **signed 32-bit**, starting at `0x80000001`, so
unsigned parsing inverts the ordering across the boundary:

| text | unsigned (wrong) | signed (correct) |
|---|---|---|
| `0x80000001` | 2147483649 | **−2147483647** ← oldest |
| `0x80000009` | 2147483657 | **−2147483639** |
| `0x7FFFFFFF` | 2147483647 | **2147483647** ← newest |

Unsigned, `0x80000001` beats `0x7FFFFFFF` — the initial sequence number is
reported as newer than the maximum. `parse_ls_sequence()` now applies two's
complement. `0x80000000` is **reserved**: it parses but `is_valid_ls_sequence()`
rejects it, so it can never win a comparison. IOS prints the sequence *without*
an `0x` prefix while checksums carry one, so both spellings are accepted in
either case; anything empty, malformed or wider than 8 hex digits returns
`None` rather than a number that would silently sort somewhere plausible.

### 2. Instance comparison (§13.1)

The generic sort key `(-sequence, age, checksum)` was wrong in two ways: `age`
was compared **before** `checksum`, and the checksum was compared as a
**string**. `compare_lsa_instances()` now applies the specification's order
explicitly:

1. higher **signed** sequence number;
2. equal sequence → higher **unsigned 16-bit** checksum (never lexicographic:
   `"0xFFF" > "0x1000"` as text but `4095 < 4096` numerically);
3. equal sequence and checksum → `age == MaxAge` (3600) wins;
4. otherwise, if `|age₁ − age₂| > MaxAgeDiff` (900), the **younger** wins;
5. otherwise the instances are identical.

When the metadata cannot establish a winner — an unusable sequence number, or
equal sequences with a malformed checksum — the result is `undecided` with
`winner=None`. The LSA is then **left out of reconstruction** and reported as
unresolved, with each observer's report listed. Claiming an arbitrary copy is
the newest LSA would be a guess presented as evidence.

`same_lsa_version()` compares *parsed* values, so `0x80000002`/`0x5E6F` and
`80000002`/`5e6f` are recognised as one instance rather than a conflict.

### 3. Network-LSA membership is the winner's, not a union

Unioning `attached_routers` across copies resurrected routers that a newer
Network LSA had dropped — inventing segment membership the LSDB does not
claim. The canonical list is now **exactly the winning instance's**. Differing
reports are preserved in `OspfNetworkLsa.observed_membership`, and a warning
names every observer's list. When observers report the *same* sequence and
checksum with different membership, that is flagged as an **inconsistent
observation** of a single instance rather than differing versions.

Router LSAs carry the equivalent per-observer record in
`observed_instances`, populated only when observers actually disagreed.

### Result

* `741 passed` (690 before; +51 in `tests/test_ospf_lsa_ordering.py`), `ruff check .` clean.
* Reference lab unchanged: 5 Router LSAs, 5 Network LSAs, 5 transit networks,
  7 stubs, 11 routes per device (9 learned / 2 Connected), no empty device IDs,
  CDP untouched, no transit network rendered as a cable.

---

## Third correction round — LS Age strictness, determinism, zero checksum

The read-only audit of `e6b6b7a` confirmed three defects, all rooted in one
problem: **the code had no way to express "this field is unusable" for LS Age**,
so unusable metadata fell through to a confident claim of agreement.

### 1. Strict LS Age validation

`parse_ls_age()` accepts only genuine integers in `0..MaxAge (3600)`. It rejects
`bool` (otherwise `True` becomes age 1 — a real, young age), `float` (no
truncating `1418.7` into an age), numeric strings (the parser already converts;
a string means the caller bypassed it), `None`, and anything outside the range.
Values are never clamped: `5000` is malformed, and clamping it to 3600 would
manufacture a MaxAge flush claim the LSA never made.

`_identical()` now takes both **validated** ages as arguments, so "identical"
can only be claimed by a caller that established it. Previously it accepted a
free-text reason and no age at all. `compare_lsa_instances()` returns
`undecided` when sequence and checksum tie but an age is unusable — including
the specific case of **MaxAge versus an unknown age**, which used to return the
MaxAge copy.

### 2. Deterministic multi-observer canonicalisation

The old `select_lsa_instance()` folded `compare_lsa_instances()` pairwise.
That is unsound because §13.1's age rule (`abs(a-b) <= MaxAgeDiff => same
instance`) is **not transitive**. With ages 100/800/1700 every pair is within
900, and a left-to-right fold returned 100 while starting at 800 returned 800 —
the canonical LSA depended on collection order. Measured: identical LSDB,
canonical metric 10 or 20, silently, no warning.

A relation that is not an order cannot be folded, so selection now aggregates
over the whole set, applying the precedence to the set:

1. **Sequence** — highest signed number; an unparseable sequence makes the
   whole selection unresolved.
2. **Checksum** — highest valid unsigned 16-bit value at that sequence.
3. **MaxAge** — surviving MaxAge copies win.
4. **Age spread** — beyond MaxAgeDiff, the youngest copies win; within it, every
   copy is the same instance per the protocol.
5. **Content** — a tie may only be resolved when the surviving copies agree
   about the LSA body, compared by `lsa_content_fingerprint()`, which excludes
   age and observer metadata. Differing bodies make the result **unresolved**
   with a warning naming every observer; no body is silently preferred.

The representative is chosen by `(age, device_id, command)`, so the result is
invariant under all input permutations — verified across all six permutations of
100/800/1700 — while `observed_by` is still built from the full observation set,
so determinism costs no provenance.

### 3. Zero checksum rejected

RFC 2328 §§12.1.7 and 13.1: the checksum is an unsigned 16-bit Fletcher field,
and a real LSA's checksum cannot be zero. `0x0000` means absent, mistranscribed
or corrupt. `parse_ls_checksum()` now returns `None` for zero and
`is_valid_ls_checksum()` rejects it, so malformed metadata can no longer act as
the §13.1 tie-break. Values above 65535 were already rejected; 1 and 65535
remain valid.

### Test correction

`test_missing_ages_never_win_a_tie` previously asserted
`winner is unknown or winner is known` — a tautology — and required the reason
to contain "identical", which is precisely the bug. It now requires
`undecided is True`, `winner is None`, and no "identical" claim, in both
directions. Three further tests that expected a canonical record where the
stricter contract now withholds one were updated to the new contract, not
weakened: they assert *less* output and *more* evidence.

### Result

* `795 passed` (741 before; +54 in this round), `ruff check .` clean.
* Reference lab unchanged and warning-free: 5 Router LSAs, 5 Network LSAs,
  5 transit networks, 7 stubs, 11 routes per device (9 learned / 2 Connected),
  0 missing device IDs, correct per-router attribution, full `observed_by`
  provenance, `logical_edges=0`.
