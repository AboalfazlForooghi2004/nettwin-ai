# Phase 2.3 — Recursive Multi-Hop Discovery

**Base:** `06d40da` (Phase 2.2) · **Branch:** `pnetlab/phase2.2-multi-device-topology`

## Result

| Check | Result |
|---|---|
| `python -m pytest` | **356 passed** (274 + 44 recursive + 29 transport + 9 cdp-address) |
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

## Post-run fix: `SSHChannel` has no `settimeout` (live bug)

The first **real** run on the Ubuntu host died before the first command:

```
AttributeError: 'SSHChannel' object has no attribute 'settimeout'
```

**Cause.** `NetmikoChannelTransport` reached for `connection.channel`. That
attribute does not exist on `netmiko.BaseConnection` — checked against the
installed versions (netmiko **4.8.0**, paramiko **4.0.0**):

```python
assert not hasattr(netmiko.BaseConnection, "channel")   # passes
```

The SSH channel on a netmiko connection is `connection.remote_conn`
(`Union[None, Telnet, paramiko.Channel, serial.Serial]`). Where the attribute
lookup fell through to some other wrapper, `settimeout` was never there — and
because the failure happened while *opening* the transport, it surfaced before
the connection stage could even report success.

**Fix.** The transport no longer guesses. It probes, and picks one of two
explicit backends:

| Probe | `backend` | Read / write |
|---|---|---|
| `remote_conn` has `recv` + (`sendall` or `send`) + `settimeout` | `"raw"` | `settimeout(min(timeout, read_timeout))`, `recv()`, `send()` |
| connection has `read_channel` + `write_channel` | `"api"` | netmiko's own buffered API |
| neither | — | `TypeError` naming both options |

Timeout behaviour is preserved on both paths: `"raw"` applies the socket
timeout itself, `"api"` relies on netmiko's non-blocking buffered reads, and
in both cases `SessionLimits.connect_timeout` still bounds `ConnectHandler`
and `command_timeout` still bounds per-command polling.

**Regression coverage.** `tests/test_netmiko_transport.py` (29 tests) covers
the raw backend, the api backend, `remote_conn=None`, a wrapper that lacks
`settimeout`, credentials redaction, and an end-to-end session that must reach
`show cdp neighbors detail` output. One test asserts the original mistake
stays caught:

```python
assert not hasattr(BaseConnection, "channel")
```

Note that this assertion is necessary but not sufficient: `BaseConnection`
assigns `self.channel` **per instance** in `__init__` (as a
`netmiko.channel.SSHChannel`, a wrapper with no `settimeout`), which is how the
attribute existed at runtime while being absent from the class. That is why the
transport probes the *object* rather than trusting a `hasattr` on the type.

## Second live bug: the run would die *after* a successful login

Fixing `settimeout` exposed the next failure in the same code path, so it is
fixed here rather than shipped and discovered on the next operator run.

### `netmiko_root_session` re-waited for a prompt that had already appeared

`ConnectHandler()` does not return a bare socket. It runs
`session_preparation()` — login, `set_base_prompt()`, `set_terminal_width()`,
`disable_paging()` — and hands back a device **already sitting at its prompt**,
with nothing left to read. `netmiko_root_session` then built an
`IosShellSession` with `_already_open=False`, so `open()` waited for an initial
prompt that would never be printed again. The socket stayed idle for the full
`connect_timeout` and raised `timeout waiting for initial prompt` — blaming the
connection *after* the SSH login had already succeeded.

Measured on a simulated post-`ConnectHandler` device (`connect_timeout=1.5`):

| | result |
|---|---|
| before | `SessionTimeoutError` after **1.51 s**, no command ever sent |
| after | session ready in **< 0.01 s**, `show cdp neighbors detail` returns output |

The root factory now seeds identity from `connection.base_prompt`, records the
real privilege via `check_enable_mode()`, and marks the session as already open.

### Redaction was destroying the error text it was attached to

`_sanitize` did a bare `str.replace(secret, "***")`. Passwords are short and
full of common letters, so:

```
password="p"  ->  "timeout waiting for prompt"  ->  "time***out waiting for ***rom***t"
password="o"  ->  "cannot connect to host"      ->  "cann***t c***nnect t*** h***st"
```

The operator lost the diagnosis at exactly the moment they needed it. Substring
redaction is kept (a partial redaction is a leak), but it is now applied **only
to untrusted text** — device output and library exception messages. Our own
diagnostic wording is composed afterwards by `_session_error()`, so it can never
be shredded. `_sanitize` also has exactly one implementation, shared by the
session and the transport.

## Third bug: a wrong password looked like a network timeout

`netmiko_root_session` wrapped *every* `ConnectHandler` failure in
`SessionTimeoutError`, and `_walk` mapped every plain `SessionError` to
`DeviceStatus.TIMEOUT`. Consequences on the first real run:

- a rejected password would be reported as `timeout`, sending the operator to
  debug the network instead of the credentials;
- the warning always said `nested ssh failed`, even for the **seed**, which is
  reached directly and is not a nested hop.

Connect failures are now classified into the same vocabulary the nodes already
use (`auth` / `timeout` / `refused` / `hostkey` / `unreachable`) and raised as
`NestedConnectError(kind=...)`, so `R2-1` with bad credentials becomes
`auth_failed`, not `timeout`. The warning names the failing hop
(`connect` vs `nested ssh`). Eight cases are parametrised in the tests against
real netmiko exception classes.

## Fourth bug: `<no-ip>` for a device that plainly advertises an address

### Correction to the first analysis

The first write-up blamed the `Management address(es)` parsing order and called
that the cause of the live `<no-ip>`. **That was wrong**, and the operator was
right to challenge it: their captures show the R2-3 address in
`Entry address(es)` *before* `Version:`, so a management-only parse defect
cannot explain it. Checked directly against the old parser with the exact
blocks:

```
OLD parser, r2-2_exact.txt -> R2-3 ips=['10.0.32.1']    warnings=[]
OLD parser, r2-4_exact.txt -> R2-3 ips=['10.0.34.1']    warnings=[]
```

The parser was **not** the cause of `<no-ip>`. The real cause is below; the
parser defect is kept as a separate, independently verified fix.

### Confirmed root cause: one device, two CDP spellings, two nodes

Real captures on this lab prove both spellings occur for the same box:

```
show cdp neighbors         ->  Device ID "R2-3"                (ios152 capture)
show cdp neighbors detail  ->  Device ID "R2-3.nettwin.lab"
```

`_walk` keyed each queued child by the **raw CDP name**, so those two became
different keys (`r2-3` vs `r2-3.nettwin.lab`). Only the *first* sighting of a
device is dialled, and the enqueue loop then did:

```python
existing = nodes.get(child_identity)
if existing is not None:
    continue          # a later sighting can never improve anything
```

Two consequences, both producing exactly the reported symptom:

1. **Duplicate node.** A block without a usable address won the race, creating
   `path=[..., "<no-ip>"]`. The same device's other block *did* carry
   `10.0.32.1` but landed on a second key, so the address never reached the
   first node. Result: one reachable node and one `<no-ip>` node for one
   physical router — and the `<no-ip>` one is what gets reported.
2. **Placeholders were permanent.** Even for a single key, a node created
   without an address was never upgraded, because `existing is not None:
   continue` discarded every later, better sighting.

Reproduced end-to-end with a seed that advertises R2-3 under both spellings,
one block with the address and one without — on the old code:

```
identity=r2-3.nettwin.lab   unreachable   path=['192.168.98.34', '<no-ip>']   <- the reported symptom
identity=r2-3               timeout       path=['192.168.98.34', '10.0.32.1'] <- same device, has the IP
R2-3 node count: 2                                                            <- must be 1
```

### Fixes

| # | Fix | Effect |
|---|---|---|
| 1 | New child nodes are registered in the name index **at creation**, not only at the start of a parent's loop | a later block in the same response resolves to the node just created |
| 2 | Detail blocks are ordered address-bearing-first before enqueueing | the sighting that can actually be dialled is the one that creates the node |
| 3 | `_upgrade_placeholder` promotes an un-collected `<no-ip>` node when a later block advertises an address | placeholders are no longer permanent |
| 4 | A collected device is re-keyed to its real hostname and any stale `<no-ip>` duplicate is merged away, both spellings registered | one device can no longer survive as two nodes |

Nothing is guessed: every address used comes from the device's own output, and
a neighbour that genuinely advertises nothing is still flagged.

### Verified against the reported fixtures

Both parents collected in one run (`R2-4` seed sees R2-3 at `10.0.34.1`,
`R2-2` sees it at `10.0.32.1`):

```
r2-3   COLLECTED   path=['192.168.98.34', '10.0.34.1']
R2-3 node count          : 1
r2-4 -> r2-3.nettwin.lab : dialled=10.0.34.1  all=['10.0.34.1']
r2-2 -> r2-3.nettwin.lab : dialled=10.0.32.1  all=['10.0.32.1']
addresses preserved      : ['10.0.32.1', '10.0.34.1']
'<no-ip>' anywhere       : False
```

Regression tests `test_15`, `test_16`, `test_17` fail on the old code
(`['192.168.98.34', '<no-ip>']`) and pass now.

### Separately confirmed: the `Management address(es)` parser defect

Independent of the above, and worth fixing on its own merits: the
`pending_version` flag set by `Version :` was cleared only by a block separator,
so everything after it that did not start with `advertisement`/`Capability
codes` was appended to the version body — including `Management address(es)`
and its IP. A neighbour advertising an address **only** there parsed to
`ip_addresses == []`.

```
OLD -> ips=[]                    warning "advertises no IP address"
NEW -> ips=['10.0.34.1']         management_addresses=['10.0.34.1']
```

The version body now ends at the next section header, and addresses are
recorded per section (`entry_addresses` / `management_addresses`). This case
was **not** what the live run hit, since the live blocks carry the address in
`Entry address(es)`.

## Limitations## Limitations

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
| Automated tests (82 new, 356 total) | ✅ complete |
| CLI requiring only the seed | ✅ complete |
| Duplicate prevention / cycle detection | ✅ tested |
| Limits + explicit failure statuses | ✅ tested |
| Transport `settimeout` crash (live bug) | ✅ **fixed, mocked regression added** |
| Post-login prompt re-wait / redaction (live bugs) | ✅ **fixed, mocked regression added** |
| Auth failure reported as a timeout | ✅ **fixed, mocked regression added** |
| Neighbour with only `Management address(es)` → `<no-ip>` | ✅ **fixed, real-output fixtures** |
| One device under two CDP spellings → duplicate `<no-ip>` node | ✅ **confirmed cause, fixed + 3 regressions** |
| **Live `Ubuntu → R2-1 → R2-2 → R2-4`** | ❌ **not run — operator step** |

> The transport fix is verified against the **installed** netmiko/paramiko
> APIs and by 18 mocked tests, but that is still not a live run. Until the
> command below completes on the Ubuntu host, the connection stage and the
> first `show cdp neighbors detail` remain unproven on real devices. If it
> fails again, the exception is no longer swallowed: send the traceback and
> the transcript in `collected/recursive/`.

To close the acceptance gap, from the Ubuntu workstation:

```bash
cd ~/nettwin-ai && git pull
export NETTWIN_DEVICE_USERNAME='nettwin-ro'
export NETTWIN_DEVICE_PASSWORD='...'
python scripts/discover_recursive.py --seed 192.168.98.34 --output-dir collected/recursive
```

Send back `collected/recursive/discovery.yaml` and the real topology will be
compared against the fixture expectation above.
