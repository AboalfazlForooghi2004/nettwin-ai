# NetTwin AI

Evidence-driven network intelligence and troubleshooting platform.

NetTwin AI loads a modeled network topology, diagnoses connectivity problems
between endpoints, explains findings with structured evidence, and evaluates
hypothetical changes — all without touching real devices.

## Principles

- **The network model is the source of truth.** Deterministic code produces every
  finding; AI only explains results.
- **VRF context is mandatory.** Overlapping IP prefixes in different VRFs are
  distinct; connectivity is never inferred from IP equality alone.
- **Read-only MVP.** No device writes, no shell execution, no configuration
  deployment. What-if simulations run on copies of the model.
- **Evidence-based diagnostics.** Every finding carries traceable evidence and
  explicit status (`reachable`, `unreachable`, `unknown`, `incomplete`).

## Quick start

```bash
# Install (editable) with dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Lint
ruff check .

# Run the application entry point
python -m nettwin.main

# Run the read-only MCP server (stdio); topology from $NETTWIN_TOPOLOGY
# (default: fixtures/healthy.yaml)
nettwin-mcp            # or: python -m nettwin.mcp_server

# Reproduce the acceptance demonstration (six example MCP tool calls)
python scripts/demo_mcp.py
```

## MCP tools (read-only)

| Tool | Purpose |
|---|---|
| `list_devices` | Modeled devices + interface counts |
| `list_vrfs` | VRFs with interface/endpoint/route counts |
| `get_topology_summary` | Counts, components, boundary violations, services |
| `get_endpoint_details` | Endpoint by **id** (never IP alone) + VRF/device/service |
| `check_connectivity` | Explicit status + finding codes + limitations |
| `diagnose_connectivity` | Full findings with evidence + recommendations |
| `simulate_route_removal` | What-if route removal impact report |
| `simulate_link_failure` | What-if link failure impact report |

The server exposes **no** shell, SSH, Python execution, or write operations.
Simulations run on deep copies; the original topology is never modified.

## HQ lab scenario (switches + firewalls, exact IPs)

Fixtures model a 6-device lab — `sw-blue-1`, `sw-green-1`, `sw-core-1`,
`sw-dmz-1` (switches) and `fw-edge-1`, `fw-branch-1` (firewalls) — with
exact IPs across 5 VRFs (BLUE, GREEN, DMZ, BRANCH, MGMT), overlapping
`10.10.1.0/24` in BLUE/GREEN, and a shared Web Portal (`10.100.0.10:443`)
explicitly allowed from all three tenant VRFs.

| Fixture | Purpose |
|---|---|
| `fixtures/lab_hq.yaml` | Healthy lab |
| `fixtures/lab_hq_missing_route.yaml` | Same lab without `r-blue-to-dmz` |

## Running on your machine (with LLM gateway access)

```bash
# 1. Python 3.12+ then:
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# 1b. LLM config (the key is never committed):
cp env.example .env    # then edit .env and paste your LLM_API_KEY

# 2. Verify everything
pytest                     # 157 tests
ruff check .

# 3. Verify LLM gateway + all four Qwen models
python scripts/llm_check.py --list      # model ids
python scripts/llm_check.py            # ping all 4 models

# 4. Full lab demo: deterministic matrix + what-if + LLM evaluation loop
python scripts/lab_demo.py
#    (LLM part asks each model for VERDICT: <status> and prints an
#     accuracy table against the deterministic engine)

# 5. MCP server (topology from $NETTWIN_TOPOLOGY, default healthy fixture)
NETTWIN_TOPOLOGY=fixtures/lab_hq.yaml nettwin-mcp
```

LLM credentials/config live in `.env` (`LLM_BASE_URL`, `LLM_API_KEY`,
`LLM_MODELS`). No device is ever contacted: lab interaction is modeled-only,
read-only.

### Troubleshooting

- **`ModuleNotFoundError: No module named 'nettwin'` / `'mcp'`** — pytest is
  not running on the venv interpreter (or the editable install broke because
  the home path contains special characters like `@`). Fix:
  ```bash
  . .venv/bin/activate
  python -m pip install -e ".[dev]"
  python -m pytest            # always via `python -m`, never bare pytest
  ```
  Tests also run without any install (`pythonpath = ["src"]` in
  pyproject.toml). For the MCP server in that case:
  `PYTHONPATH=src python -m nettwin.mcp_server`.
- **LLM `HTTP 401`** — `.env` still has the placeholder key; rewrite it
  (see `env.example`) so `LLM_API_KEY` holds the real key, then verify with
  `python scripts/llm_check.py --list`.

## Project layout

```text
src/nettwin/
├── main.py          # application entry point
├── domain/          # Pydantic domain models
├── data/            # YAML loading and validation
├── graph/           # NetworkX VRF-aware topology graph
├── diagnostics/     # deterministic diagnostic engine
├── simulation/      # what-if analysis on model copies
└── mcp_server/      # read-only MCP tool interface
tests/               # pytest test suite
fixtures/            # synthetic YAML topologies
```

## MVP scope

The MVP demonstrates: topology loading, multi-tenant VRF modeling,
connectivity diagnostics with evidence, what-if route/link simulation, and
read-only MCP tools. See `IMPLEMENTATION_STATUS.md` for progress and known
limitations.
