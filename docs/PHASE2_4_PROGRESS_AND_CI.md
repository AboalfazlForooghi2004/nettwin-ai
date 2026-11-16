# Phase 2.4 — Live Progress and CI

**Branch:** `pnetlab/phase2.2-multi-device-topology`

## Task 1 — Live discovery progress

### What the operator sees

While `scripts/discover_recursive.py` runs, a live panel on **stderr** shows:

| Field | Meaning |
|---|---|
| `elapsed` | real wall-clock seconds since the walk started |
| `devices` | `N collected / M discovered`, plus `K failed` when any failed |
| `current` | the device currently being worked on, its depth, and its access path |
| `status` | what is happening right now (`connecting to seed`, `nested ssh`, `running command`, `re-opening parent chain`, `collected`, `timeout`, …) |
| `command` | the read-only command currently in flight |
| `limits` | the depth/device bounds for this run |

A spinner animates continuously, so a 40-second nested handshake looks like
work in progress rather than a hang.

### No fake percentages

Recursive discovery does **not** know how many devices exist until it has
walked them — that is the nature of the problem. So no percentage and no
progress bar with an invented total is ever shown. The counters reflect only
what has actually been discovered, and the elapsed clock is real time.

### Turning it off

```bash
python scripts/discover_recursive.py --seed 192.168.98.34 --no-progress
```

The live view is also disabled automatically whenever stderr is not a TTY
(CI, pipes, cron, `> file`). The final summary is still printed in both cases.
Tests that assert this:

- `test_progress_is_silent_on_a_non_tty_stream`
- `test_no_progress_flag_yields_a_null_observer`
- `test_cli_dry_run_makes_no_terminal_writes`
- `test_render_never_prints_a_fake_percentage`

### Final summary

Printed on stdout after the report, so it survives `--no-progress` and CI:

```
================ SUMMARY ================
  devices     : 3
  interfaces  : 9
  routes      : 9
  warnings    : 1
  collected   : 3/4 discovered
  elapsed     : 12.4s
=========================================
```

### It cannot affect discovery

The progress view is an **observer** passed to `RecursiveDiscovery`:

```python
RecursiveDiscovery(..., observer=...)
```

- Every hook is optional; the default is `NullProgress`, a no-op.
- Discovery never reads anything back from the observer.
- `progress.py` does not import the discovery package, so there is no cycle.
- `rich` is imported lazily: a core install without it still runs, falling back
  to a plain one-line-per-event writer.

`test_discovery_accepts_an_observer_without_changing_its_result` asserts that
node identities, statuses and edge counts are identical with and without an
observer.

### Install

`rich` is optional:

```bash
pip install -e ".[progress]"     # just the live view
pip install -e ".[collect,progress]"   # a full recursive run
pip install -e ".[cli]"          # both, via the aggregate extra
```

Without `rich` the CLI degrades to the plain writer — never crashes.

## Task 2 — GitHub Actions CI

`.github/workflows/ci.yml`

### Triggers

| Event | Scope |
|---|---|
| `push` | every branch **except `main`** (feature branches, all of them) |
| `pull_request` | anything targeting `main` |
| `workflow_dispatch` | manual re-run |

`main` pushes are not built directly: `main` only moves by a reviewed merge,
and that merge already ran these checks on the branch.

### Steps

1. Checkout
2. Set up Python — matrix **3.12** (the `requires-python` floor) and **3.13**
   (what the project is developed against)
3. Install `.[dev,collect,progress]` with pip caching keyed on `pyproject.toml`
4. `ruff check .` — fails the job on any lint error, no `--fix` in CI
5. Full `pytest`
6. Regression: CDP parser (`test_cdp_management_address.py`,
   `test_cisco_collector.py`)
7. Regression: recursive discovery (`test_recursive_discovery.py`,
   `test_netmiko_transport.py`, `test_progress.py`)
8. Deterministic demo (`scripts/lab_demo.py --no-llm`)
9. CLI smoke test with `--dry-run` (opens no socket)
10. A guard that fails if fewer than 300 tests were collected, so a suite that
    silently fails to load cannot pass as green

### Safety properties

| Requirement | How it is met |
|---|---|
| No credentials or secrets | The workflow references no secret and sets no env var with a value. Credentials are read by the CLI from the environment only, and CI never runs a live collection. |
| No live PNETLab on a hosted runner | Every test is mocked or fixture-driven; the CLI step uses `--dry-run`, which guarantees no connection. The live run remains a documented operator step. |
| LLM/API tests not required | The demo runs `--no-llm`; the suite itself makes no network calls. |
| Fails on any step failure | Each step is a failing command; there is no `continue-on-error`. |
| Caching | `actions/setup-python` with `cache: pip`. |
| All feature branches | `push: branches: ["**", "!main"]`. |
| Least privilege | `permissions: contents: read`. |
| No stale builds | `concurrency` cancels superseded runs on the same ref. |

## Local verification of every CI command

| Step | Result |
|---|---|
| `ruff check . --output-format=github` | clean |
| `pytest -q` | **370 passed** |
| CDP parser regressions | 66 passed |
| Recursive discovery regressions | 87 passed |
| `lab_demo.py --no-llm` | deterministic PASS |
| CLI `--dry-run` and `--dry-run --no-progress` | exit 0, no stderr |
| collect-only guard | 370 collected (> 300) |

## Limitations

1. **The live panel is cosmetic by design.** It reports real events, but it does
   not shorten any timeout or retry a device — behaviour is unchanged.
2. **`rich` is optional**, so a machine without it sees the plain writer. Both
   paths are tested.
3. **The CI matrix starts at 3.12.** Older interpreters are unsupported by
   `pyproject.toml` and are not tested.
4. **No live lab run in CI**, by instruction: GitHub-hosted runners cannot reach
   `192.168.98.34`, and running live discovery there would be both impossible
   and unsafe.
