# Phase 2.3 — Recursive Multi-Hop Discovery

**Base:** `06d40da` (Phase 2.2) · **Branch:** `pnetlab/phase2.2-multi-device-topology`

## Result

| Check | Result |
|---|---|
| `python -m pytest` | **313 passed** (274 + 39 new) |
| `python -m ruff check .` | **All checks passed!** |
| `python scripts/lab_demo.py --no-llm` | **deterministic: PASS / llm loop: PASS** |
| Domain schema / engine / graph / simulation | **0 files changed** |
| Allowlist | **6 commands** — the Phase-2 five + `show cdp neighbors detail` (read-only) |

> **Honest boundary:** every result above comes from automated tests with
> scripted IOS transcripts. **No live PNETLab validation has been performed**
> — the lab (`192.168.98.34`) is not reachable from the development
> environment. See *Acceptance status* at the end.

## How it works

```
workstation ──SSH(netmiko)──> R2-1
                                │  show cdp neighbors detail
                                │  -> neighbours + their management IPs
                                ▼
                             ssh -l user <ip>     (typed on the IOS CLI)
                                ▼
                              R2-2  ── same again ──> R2-4
```

Breadth-first, one nested session alive per level:

1. Collect the seed (6 allowlisted read-only commands).
2. Parse `show cdp neighbors detail` → neighbour name, IP(s), interfaces.
3. Resolve each neighbour name through the Phase-2.2 alias index, so
   `R2-2` and `R2-2.nettwin.lab` are one device.
4. Open the child with `ssh -l <user> <ip>` **from the live parent session**
   (the child's password prompt is answered on the child channel, not the
   parent's — see *Fixed during implementation*).
5. Repeat until the queue is empty or a limit is hit.
6. `close_all()` tears every session down, deepest first.

### Why not ProxyJump

Any local socket to R2-2 would need a route the workstation does not have.
The tested path is the IOS CLI's own `ssh`, so that is what the code drives.

## New modules

| File | Responsibility |
|---|---|
| `src/nettwin/collect/nested/prompts.py` | Classify IOS prompts (`>`, `#`, `Password:`, host-key, `--More--`, `%` errors); unknown is never "ready" |
| `src/nettwin/collect/nested/session.py` | `IosShellSession`: open / run_command / open_nested / close, with explicit error classes |
| `src/nettwin/collect/nested/transcript.py` | `ScriptedTransport`, `ReplayTransport` — deterministic fakes |
| `src/nettwin/collect/nested/discovery.py` | `RecursiveDiscovery`: BFS queue, limits, identity, cycles, `IpAliases` |
| `src/nettwin/collect/nested/netmiko_transport.py` | Production netmiko root session + forwarded nested transport |
| `scripts/discover_recursive.py` | CLI (seed only) |
| `tests/test_recursive_discovery.py` | 39 tests |
| `tests/data/nested/*_detail.txt` | CDP-detail fixtures |

### Changed files (4)

| File | Change |
|---|---|
| `src/nettwin/collect/ios_parsers.py` | **new** `parse_show_cdp_neighbors_detail` |
| `src/nettwin/collect/cisco_ios.py` | allowlist +1 read-only command; `DeviceObservations.cdp_neighbors_detail` |
| `tests/test_cisco_collector.py` | allowlist test now asserts *only* a read-only `show` command was added |
| `tests/data/{ios152,live2026}/show_cdp_neighbors_detail.txt` | fixtures |

## Safety and limits

`SessionLimits` (all validated in `__post_init__`):

| Field | Default | Meaning |
|---|---|---|
| `max_depth` | 8 | maximum SSH nesting |
| `max_devices` | 32 | maximum collected devices |
| `connect_timeout` | 20 s | per handshake |
| `command_timeout` | 30 s | per command |
| `max_attempts_per_device` | 2 | SSH attempts per device |
| `disable_paging` | **False** | opt-in `terminal length 0` |
| `escalate_privilege` | **False** | opt-in `enable` |

Every failure is explicit and local — one bad hop never stops the walk:

| Situation | Node status |
|---|---|
| successful collection | `collected` |
| `% Connection refused` / no route | `unreachable` |
| `% Authentication failed` | `auth_failed` |
| silence past timeout | `timeout` |
| `max_devices` hit | `limit_reached` |
| hostname already seen elsewhere | `identity_conflict` |

A neighbour that advertises **no IP** is retained as unreachable with the
reason "no IP in CDP detail" — it is never dialled with a guessed address.

## CLI

```bash
export NETTWIN_DEVICE_USERNAME='nettwin-ro'
export NETTWIN_DEVICE_PASSWORD='...'

# plan only
python scripts/discover_recursive.py --seed 192.168.98.34 --dry-run

# real recursive discovery
python scripts/discover_recursive.py --seed 192.168.98.34 \
    --output-dir collected/recursive --max-depth 4 --max-devices 16
```

Exit codes: `0` ok · `1` config error · `2` partial · `3` seed not collected.

Outputs: `collected/recursive/topology.yaml` (merged topology) and
`collected/recursive/discovery.yaml` (nodes, paths, statuses, CDP edges,
stats, warnings). Both live under the already-ignored `collected/`.

## Sample output (fixture-backed run)

```
discovered :
  OK r2-1                     depth=0 path=192.168.98.34
  OK r2-2                     depth=1 path=192.168.98.34 -> 10.0.21.1
  OK r2-4                     depth=1 path=192.168.98.34 -> 10.0.41.1
cdp edges  :
  * r2-1 [Ethernet0/0] <-> r2-2.nettwin.lab [Ethernet0/1]  via 10.0.21.1
  * r2-1 [Ethernet0/1] <-> r2-4.nettwin.lab [Ethernet0/1]  via 10.0.41.1
  * r2-2 [Ethernet0/1] <-> r2-1 [Ethernet0/0]              via 10.0.21.2
  * r2-2 [Ethernet0/2] <-> r2-4.nettwin.lab [Ethernet0/2]  via 10.0.41.1
  * r2-4 [Ethernet0/1] <-> r2-1 [Ethernet0/1]              via 10.0.21.2
merged     : 3 devices, 9 interfaces, 9 routes
stats      : 3 visit(s), 2 nested ssh attempt(s)
warnings   : 1
  ! cycle prevented: 'r2-4.nettwin.lab' already discovered via another path
```

## Fixed during implementation (real bugs, not test noise)

1. **Nested credential channel.** The password prompt is printed by the
   parent but answered by the neighbour. Writing it to the parent's channel
   loses it. The handshake now writes credentials to the child transport.
2. **Prompt without failure detection.** IOS prints
   `% Connection refused` and drops straight back to `R2-1#`. A prompt-only
   check reported success. The whole buffer is now scanned for failure text.
3. **Session left open on backtrack.** Parents consumed by a child were
   dropped from the registry and never closed. `_all_sessions` now guarantees
   teardown.
4. **FQDN vs hostname duplication.** `R2-1` and `R2-1.nettwin.lab` became two
   nodes. Identity now resolves through the Phase-2.2 alias index.

## Limitations

1. **No live lab validation.** The acceptance criterion
   (`Ubuntu → R2-1 → R2-2 → R2-4` on real hardware) has **not** been executed.
   All evidence here is fixture-based.
2. **R2-3 is not reached in the fixtures.** Its CDP rows were not captured; the
   algorithm would collect it if any collected device advertises it with an IP.
3. **One nested ssh per session.** Siblings require re-opening the parent
   chain, which costs an extra handshake per hop. That is IOS behaviour, not a
   shortcut.
4. **`ForwardedTransport` shares the parent's channel.** It is intentionally
   single-flight; the breadth-first walk never interleaves two children.
5. **Paging.** `terminal length 0` is opt-in and needs privileged mode; with
   it off, long outputs paginate and `--More--` is answered with a space.
6. **ECMP** still keeps one next hop in the domain model (unchanged since 2.1).
7. **Host keys.** `accept-new` semantics: a changed key on a known host is not
   automatically trusted; the operator sees the prompt in the transcript.

## Acceptance status

| Requirement | Status |
|---|---|
| Automated tests (39 new, 313 total) | ✅ complete |
| CLI requiring only the seed | ✅ complete |
| Duplicate prevention / cycle detection | ✅ tested |
| Limits + explicit failure statuses | ✅ tested |
| **Live `Ubuntu → R2-1 → R2-2 → R2-4`** | ❌ **not run — operator step** |

To close the acceptance gap, from the Ubuntu workstation:

```bash
cd ~/nettwin-ai && git pull
export NETTWIN_DEVICE_USERNAME='nettwin-ro'
export NETTWIN_DEVICE_PASSWORD='...'
python scripts/discover_recursive.py --seed 192.168.98.34 --output-dir collected/recursive
```

Send back `collected/recursive/discovery.yaml` and the real topology will be
compared against the fixture expectation above.
