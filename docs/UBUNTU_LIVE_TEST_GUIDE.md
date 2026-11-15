# Ubuntu Live-Test Guide — Cisco SSH Collector (Phase 2)

> **Executor: the operator, from the Ubuntu workstation (172.30.201.18).**
> The sandbox (Ariana.ia) must never reach lab devices — do not run any of
> these steps from there. All commands below are read-only with respect to
> device configuration; nothing here changes routes, firewall rules,
> PNETLab topology or IOS configuration.

## 0. Targets and reachability status (read first)

| Target | Address | Reachability status | Evidence |
|---|---|---|---|
| **R2-1** | `192.168.98.34` (IOS 15.2) | **VERIFIED for G0** (bidirectional ping, 2026-11-15: U→R2-1 3/3, R2-1→U 5/5) — **SSH validation still PENDING** (this guide) | `G0_CONNECTIVITY_CHECK.md`, recorded in Phase-2 brief |
| **R2-3** | preferred mgmt `10.255.255.4` (Loopback0) | **UNVERIFIED — DO NOT USE YET** | none |

R2-3 pre-checks (run only if you intend to add R2-3 later; **do not change
routing if these fail — report the blocker instead**):

```bash
ip route get 10.255.255.4        # which path/nh would be used?
ping -c3 -W2 10.255.255.4       # does it answer?
```

* If `ip route get` errors or `ping` fails → R2-3 stays out of scope; the
  code supports it, the live run does not.
* Duplicate-IP check for `192.168.98.34` (vs gateway ARP table) remains an
  outstanding *optional* verification — not required for this guide.

## 1. Dependencies (once)

```bash
cd ~/nettwin-ai            # or your clone path
git fetch
git checkout pnetlab/cisco-collector-mvp
git pull

python3 -m venv .venv      # if not already present
source .venv/bin/activate
python -m pip install -e ".[dev,collect]"     # adds netmiko (optional extra)
python -c "import netmiko, paramiko; print(netmiko.__version__, paramiko.__version__)"
```

Rationale for netmiko: Python's standard library has no SSH client;
`netmiko` is the de-facto standard driver family for Cisco IOS (supports
`cisco_ios` / IOS 15.2 prompt handling and paging). It is declared as an
optional extra in `pyproject.toml` so the core install and the whole test
suite remain dependency-free of SSH libraries.

**Version pin (Phase 2.1).** The extra is declared as
`netmiko[par4]>=4.8,<5`. The `par4` extra pins `paramiko<5` because IOS 15.2
on Cisco IOL only offers the legacy SHA-1 KEX algorithms that paramiko 5.x no
longer negotiates. A clean install must report **netmiko 4.8.x + paramiko
4.x**:

```bash
python -c "import paramiko; assert paramiko.__version__.startswith('4.'), paramiko.__version__"
```

If your venv already contains paramiko 5.x from an earlier install, force the
compatible combination explicitly:

```bash
python -m pip install --upgrade 'netmiko[par4]==4.8.0'
```

## 2. Credentials (environment only — never argv, never files in git)

```bash
export NETTWIN_DEVICE_USERNAME='nettwin-ro'      # dedicated read-only account
export NETTWIN_DEVICE_PASSWORD='...'             # its secret (never echo it)
```

Use the dedicated account from `docs/IOS_SSH_PROPOSED_CONFIG.md`
(privilege 1, no enable secret). Do **not** use an admin account.

## 3. Pre-flight network checks (read-only)

```bash
ip route get 192.168.98.34          # expect: via 172.30.201.254 dev enp2s0
nc -vz -w3 192.168.98.34 22         # TCP/22 open?
ssh -o BatchMode=yes -o ConnectTimeout=5 nettwin-ro@192.168.98.34 exit \
    && echo SSH_OK || echo SSH_FAIL # SSH negotiation + key auth path
```

If `nc` fails → routing/firewall problem (check Step 0 G0 evidence first).
If `ssh` fails but `nc` passes → SSH negotiation/account issue (Step 6).

## 4. Run the collector against R2-1

```bash
python scripts/collect_cisco.py --host 192.168.98.34 --raw-dir collected/raw
```

Exit codes: `0` all five commands ok · `1` config/connection/allowlist
error · `2` partial (some commands failed — inspect warnings).

Outputs:

* `collected/192.168.98.34.topology.yaml` — observations mapped onto the
  existing domain model (`Topology`)
* `collected/192.168.98.34.observations.yaml` — raw evidence: per-command
  status/duration/output, parsed records, warnings, timestamps
* `collected/raw/*` (with `--raw-dir`) — untouched command outputs

## 5. Validate the observations (against the device, not the model)

Manual SSH session in a second terminal (`ssh nettwin-ro@192.168.98.34`),
then compare **device output vs `observations.yaml`**:

```ios
show version            ! hostname R2-1, Version 15.2(x)
show ip interface brief ! same interface set + IPs + up/down states
show ip route           ! same prefixes; check an ECMP entry has the same
                        ! number of next hops as in observations.routes
show ip ospf neighbor   ! same neighbor IDs/states (recorded as observations
                        ! only — the schema has no adjacency object)
show cdp neighbors      ! same device IDs (observations only)
```

Expected signature for R2-1 (from G0/Phase-1 evidence — re-verify, do not
trust blindly):

* `device_id: r2-1`, platform from `show version`
* `Ethernet0/2` = `192.168.98.34/27`, `Loopback0` = `10.255.255.1/32`
* default route `0.0.0.0/0 → 192.168.98.62` (candidate default `S*`)
* at least one OSPF-learned route with **multiple next hops** → collector
  warning contains `ECMP` and `ALL preserved in observations`
* OSPF neighbor rows → warning `adjacency NEVER inferred`

Also confirm: no credentials appear anywhere in the YAML/summary output
(`grep -R "$NETTWIN_DEVICE_PASSWORD" collected/` must print nothing).

## 6. Troubleshooting

| Symptom | Exit | Likely cause | Action |
|---|---|---|---|
| `CONNECTION ERROR [auth]` | 1 | wrong user/secret; account locked; SSH ACL | verify env vars, `show users` on device, ACL on VTY |
| `CONNECTION ERROR [timeout]` | 1 | TCP/22 filtered or SSH disabled | re-run Step 3 `nc`/`ssh`; check `ip ssh` on device |
| `CONNECTION ERROR [unreachable]` | 1 | routing from this host | `ip route get 192.168.98.34`, compare with G0 |
| `CONFIG ERROR: credentials not configured` | 1 | env vars not exported in this shell | re-export (Step 2) |
| `netmiko is not installed` | 1 | extra missing | `python -m pip install -e ".[collect]"` |
| `REJECTED (pre-connection)` | 1 | command outside allowlist | only the five `show` commands are permitted |
| partial (`2`) with `parser failed` warnings | 2 | unexpected IOS output variant | keep `--raw-dir` output, file it as a parser-gap issue |
| privilege errors on individual commands | 2 | account not at privilege 1 / wrong account | see `docs/IOS_SSH_PROPOSED_CONFIG.md` §3 |

## 7. Safety rules during the live run

1. Read-only: the tool cannot send configuration, enable mode, `write`,
   `reload` or `clear` — if you see anything else attempted, stop and report.
2. One target only: **R2-1** in this phase. R2-3 requires its own
   reachability evidence first (Step 0).
3. No route/firewall/topology changes to make anything pass — a failure is
   a finding, not something to route around.
4. Never paste the password into shell history files, tickets or git; use
   the environment variables.
