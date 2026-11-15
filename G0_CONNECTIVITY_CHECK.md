# G0_CONNECTIVITY_CHECK.md — Ubuntu ↔ PNETLab Connectivity Gate

> **Status: NOT STARTED — must be executed by the user on the Ubuntu
> workstation. Nothing in this gate has been run or verified yet.**
> All commands are **read-only** (inspection, ping, ARP observation).
> Do not change any interface, route, firewall rule, or lab configuration.

| Parameter | Value |
|---|---|
| Ubuntu host | `172.30.201.18` |
| PNETLab external interface (R2-1 Ethernet0/2) | `192.168.98.34/27` |
| External gateway | `192.168.98.62` |
| External network | `192.168.98.32/27` (mask `255.255.255.224`) |
| Connection path | Ubuntu → (Cloud node) → external L2 → R2-1 E0/2 |

**Golden rule:** a successful ping to the gateway `192.168.98.62` proves
ONLY that the gateway answers. It does **not** prove host-to-lab
connectivity (`192.168.98.34`), and it does not prove the return path.

---

## 1. Identify interfaces and routes (Ubuntu)

```bash
# Interface inventory (find which interface faces the lab path)
ip -br addr show
ip -br link show

# Routing table + the specific route the kernel would use
ip route show
ip route get 192.168.98.34
ip route get 192.168.98.62

# DNS is irrelevant here (pure IPs) — recorded for completeness
resolvectl status 2>/dev/null | head -20
```

**Record:** the egress interface printed by `ip route get 192.168.98.34`
(e.g. `dev eth0`), the via/gateway used, and whether a route to
`192.168.98.32/27` exists at all.

### How to interpret

| Observation | Meaning |
|---|---|
| `ip route get` returns a route with `via 192.168.98.62 dev X` | Host expects the gateway to forward to the lab — proceed |
| `ip route get` returns `dev X` directly (on-link, no via) | Host believes the lab subnet is directly attached — verify the interface really faces that L2 |
| `Network is unreachable` / `enoent` | **Routing failure on the host** (§7-A) — no route toward `192.168.98.32/27` |
| Route points at a different interface than expected | Document it; do not change it yet |

---

## 2. Ubuntu → lab ping tests

```bash
# 2a. Gateway (control test — NECESSARY BUT NOT SUFFICIENT)
ping -c 3 -W 2 192.168.98.62

# 2b. THE actual gate target: R2-1 external interface
ping -c 3 -W 2 192.168.98.34

# 2c. Broader sweep of the external subnet (helps see who answers)
ping -c 2 -W 1 192.168.98.62
for i in 1 2 3 33 34 62; do
  ping -c 1 -W 1 192.168.98.$i >/dev/null 2>&1 \
    && echo "192.168.98.$i UP" || echo "192.168.98.$i no reply"
done

# 2d. Path observation while pinging (in a second terminal)
traceroute -n -q1 -w 2 192.168.98.34   # or: mtr -n -r -c3 192.168.98.34
```

**Record:** packet loss %, RTT, and the traceroute hop list.

---

## 3. Reverse ping: R2-1 → Ubuntu (source 192.168.98.34)

Run on **R2-1** (read-only ICMP):

```
R2-1# ping 172.30.201.18 source 192.168.98.34
```

Equivalent explicit form:

```
R2-1# ping ip 172.30.201.18 source Ethernet0/2
```

Also capture the forwarding decision:

```
R2-1# show ip route 172.30.201.18
R2-1# show ip arp 172.30.201.18
```

**Record:** success rate, which route was used (connected / default via
`192.168.98.62` / none), and the ARP entry (or its absence).

### Interpretation

| Result | Meaning |
|---|---|
| Forward ping OK (§2b) + reverse OK (§3) | **G0 PASS** candidate — record both outputs |
| Forward OK, reverse FAIL | Return path broken: R2-1 has no route to `172.30.201.18`, or the gateway/cloud does not route back (§7-B) |
| Forward FAIL, reverse OK | Asymmetric: inbound to lab works, host→lab filtered or host routing issue (§7-A/C) |
| Both FAIL | G0 FAIL — classify with §5–§7 before changing anything |

> Note: `172.30.201.18` is NOT inside `192.168.98.32/27`; R2-1 will reach
> it via its default route (`0.0.0.0/0 via 192.168.98.62`) — the gateway
> and Cloud node must know the return path. That is exactly what this
> test verifies.

---

## 4. Identify the actual route and egress interface

**Ubuntu side:**

```bash
ip route get 192.168.98.34          # -> "via <gw> dev <iface> src 172.30.201.18"
ip route get 172.30.201.18          # sanity: host's own address path
ip neigh show                       # ARP/ND cache (see §5)
```

**R2-1 side:**

```
R2-1# show ip route 192.168.98.32 255.255.255.224
R2-1# show ip route 172.30.201.18
R2-1# show ip interface Ethernet0/2
R2-1# show interfaces Ethernet0/2 | include hardware|address
```

**Record:** for each direction — egress interface, next hop, and whether
the route is `C` (connected), `S` (static), `S*` (default), or missing.

---

## 5. Duplicate-IP check for 192.168.98.34 (authoritative method)

A duplicate on the external L2 would make the gate flaky and misleading.
Use **MAC comparison** as the authority:

**Step 1 — R2-1's real MAC on E0/2:**

```
R2-1# show interfaces Ethernet0/2 | include address
! look for: "Hardware is ..., address is aabb.cc00.1111"  -> MAC_R2_1
R2-1# show ip arp 192.168.98.62
! gateway MAC as seen by R2-1                     -> MAC_GW_SEEN_BY_R21
```

**Step 2 — what the segment (via the Ubuntu host) resolves:**

```bash
# Clear only OUR host's cache entry (does not touch the network config)
ip neigh flush dev <egress_iface> 192.168.98.34 2>/dev/null

ping -c 2 192.168.98.34          # populates the neighbor table
ip neigh show 192.168.98.34      # -> MAC_HOST_SEES

# Independent ARP probe (repeat 5x; watch for MULTIPLE distinct MACs)
arping -c 5 -I <egress_iface> 192.168.98.34 2>&1 | tee /tmp/arping_g0.txt
grep -ioE "([0-9a-f]{2}:){5}[0-9a-f]{2}" /tmp/arping_g0.txt | sort -u
```

**Optional duplicate-detection mode:**

```bash
arping -D -c 3 -I <egress_iface> 192.168.98.34
```

**Step 3 — compare (the decision table):**

| Observation | Verdict |
|---|---|
| Exactly ONE MAC seen, **equal to MAC_R2_1** | No duplicate — PASS this check |
| ONE MAC seen, **≠ MAC_R2_1** | Wrong responder (mis-mapping, proxy ARP, or wrong segment) — **investigate, G0 blocked** |
| TWO OR MORE distinct MACs across pings/arping | **Duplicate IP confirmed — G0 BLOCKED** until resolved |
| No ARP reply at all | L2 path to the lab broken (Cloud node / bridging) — §7-A |

If you can read the gateway's ARP table as well, compare its entry for
`192.168.98.34` against `MAC_R2_1` — same rule (must match).

---

## 6. Expected results (what a PASS looks like)

1. `ip route get 192.168.98.34` → valid route via `192.168.98.62` (or
   on-link) with a concrete egress interface.
2. `ping -c3 192.168.98.62` → 100% (control).
3. `ping -c3 192.168.98.34` → **0% loss** (the actual gate).
4. `ping 172.30.201.18 source 192.168.98.34` on R2-1 → **success rate
   100%** (or ≥80% with 0% systematic loss).
5. Exactly one MAC for `192.168.98.34` on the segment, matching R2-1's
   E0/2 MAC.
6. `traceroute -n 192.168.98.34` shows ≤ 2 hops (gateway, then R2-1).

**Paste back:** every command with its raw output (redact unrelated
hosts if desired). G0 is assigned PASS/FAIL only from this evidence —
never assumed.

---

## 7. Failure classification (keep these separate)

### A. Routing failure (host → lab, forward path)
- **Signature:** `ip route get 192.168.98.34` → `Network is unreachable`;
  or ping fails instantly with no ARP entry ever appearing
  (`ip neigh show 192.168.98.34` → `FAILED`/`INCOMPLETE`).
- **Evidence:** §1 output + `ip neigh` state.
- **Meaning:** the Ubuntu host has no path toward `192.168.98.32/27`.
- **Action:** document only — fixing host routes requires separate
  approval (never change interfaces/routes without it).

### B. Missing return route (lab → host, reverse path)
- **Signature:** forward ping (§2b) works or ARPs succeed, but R2-1's
  reverse ping (§3) fails; `show ip route 172.30.201.18` on R2-1 shows
  only the default via `192.168.98.62`, and the gateway/Cloud does not
  carry `172.30.201.0/24` back.
- **Evidence:** §3 output + `show ip route 172.30.201.18`.
- **Meaning:** asymmetric reachability — not a host problem, not a
  duplicate problem.

### C. Firewall / filtering
- **Signature:** ARP resolves and traceroute reaches the gateway (or
  even R2-1) but ICMP replies vanish; or forward works, reverse blocked.
  Test discrimination:
  ```bash
  # Does ANY traffic get through? (read-only probes)
  traceroute -n -U -p 33434 192.168.98.34     # UDP traceroute
  timeout 3 bash -c '</dev/tcp/192.168.98.34/22' && echo "tcp/22 open-ish" || echo "tcp/22 no"
  ```
- **Evidence:** ARP OK + traceroute OK to hop N + ICMP blocked pattern.
- **Meaning:** a firewall (host `ufw`/`iptables`, gateway, or FortiGate
  policy) is dropping traffic — distinct from routing and duplicates.
- **Check host firewall state read-only:** `sudo ufw status verbose`,
  `sudo iptables -L -n | head -40` (do not modify).

### D. Duplicate IP (192.168.98.34 elsewhere)
- **Signature:** §5 finds ≥2 MACs, or MAC ≠ R2-1's E0/2; symptoms also
  include intermittent ping loss, ARP flapping, and console messages on
  R2-1 such as `%IP-4-DUPADDR: Duplicate address 192.168.98.34 on
  Ethernet0/2`.
- **Evidence:** §5 MAC comparison (authoritative) + R2-1 console/output.
- **Meaning:** two devices claim the same address — the gate cannot be
  trusted until resolved (resolving it = lab change → needs approval).

### Quick discriminator table

| Symptom | A: no fwd route | B: no return route | C: filtered | D: duplicate |
|---|---|---|---|---|
| `ip route get` fails | ✅ | | | |
| ARP never resolves | ✅ | | | |
| ARP resolves, ping 100% loss, traceroute stops at gateway | | | ✅ | |
| Forward OK, R2-1 reverse ping FAIL | | ✅ | possible | |
| Two MACs / wrong MAC for .34 | | | | ✅ |
| Intermittent loss + MAC changes between probes | | | | ✅ |

---

## Execution checklist (fill in and paste back)

```text
[ ] §1 ip -br addr / ip route get 192.168.98.34        -> egress: ________
[ ] §2a ping 192.168.98.62                             -> ____% loss
[ ] §2b ping 192.168.98.34                             -> ____% loss
[ ] §2d traceroute -n 192.168.98.34                    -> hops: ________
[ ] §3 R2-1: ping 172.30.201.18 source 192.168.98.34   -> ____% success
[ ] §3 R2-1: show ip route 172.30.201.18               -> ________
[ ] §4 reverse/forward route evidence captured         -> yes / no
[ ] §5 MAC_R2_1 = ______________  MAC_HOST_SEES = ______________
[ ] §5 arping distinct MACs: ____ (must be 1 and equal)
[ ] G0 RESULT: PASS / FAIL / BLOCKED (class A/B/C/D): ________
```
