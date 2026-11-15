#!/usr/bin/env python3
"""NetTwin AI — HQ lab demo: full scenario + optional LLM evaluation loop.

Runs entirely on YOUR machine (the LLM gateway only needs to be reachable
from where you run it). Deterministic part always runs; the LLM part is
skipped gracefully when the gateway is unreachable.

What it does:
  1. Loads fixtures/lab_hq.yaml (4 switches + 2 firewalls, exact IPs).
  2. Runs the connectivity matrix through the MCP tool handlers.
  3. Runs both what-if simulations and proves the original model is intact.
  4. If the LLM gateway is reachable: sends three DiagnosticResults
     (reachable / missing-route / tenant-isolation) to every configured
     Qwen model, asks for a machine-checkable `VERDICT:` line, and prints
     an accuracy table (engine status vs model verdict).

Usage:
    python scripts/lab_demo.py               # everything (LLM if reachable)
    python scripts/lab_demo.py --no-llm      # deterministic only
    python scripts/lab_demo.py --models qwen-27b-instruct,qwen-27b-reasoning
"""

from __future__ import annotations

import argparse
import asyncio
import json
import re
import sys
import urllib.error
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import llm_check  # noqa: E402

from nettwin.data.loader import load_topology  # noqa: E402
from nettwin.mcp_server import create_server  # noqa: E402

FIXTURES = REPO_ROOT / "fixtures"
VERDICT_RE = re.compile(
    r"VERDICT:\s*(reachable|unreachable|unknown|incomplete)", re.IGNORECASE
)

SYSTEM_PROMPT = (
    "تو لایهٔ توضیح NetTwin AI هستی. فقط و فقط از روی نتایج دیاگنوستیک قطعی "
    "زیر (JSON شامل status، findings، evidence، limitations) توضیح بنویس. "
    "ممنوعیت مطلق: اختراع توپولوژی، روت یا وضعیت؛ تغییر status؛ ادعای بررسی "
    "زنده. اگر داده‌ای وجود ندارد بگو نامشخص. پاسخ به فارسی و با این ساختار: "
    "۱) خلاصه ۲) دلیل اصلی با استناد به شواهد (evidence) ۳) پیشنهاد بررسی "
    "۴) آخرین خط باید دقیقاً به شکل زیر باشد:\n"
    "VERDICT: <reachable|unreachable|unknown|incomplete>"
)

# Deterministic acceptance matrix: (fixture, source, destination, expected)
MATRIX = [
    ("lab_hq.yaml", "pc-blue", "web-dmz", "reachable"),
    ("lab_hq.yaml", "pc-green", "web-dmz", "reachable"),
    ("lab_hq.yaml", "pc-branch", "web-dmz", "reachable"),
    ("lab_hq.yaml", "pc-blue", "pc-green", "unreachable"),
    ("lab_hq_missing_route.yaml", "pc-blue", "web-dmz", "unreachable"),
    ("lab_hq_missing_route.yaml", "pc-green", "web-dmz", "reachable"),
]

# (label, fixture, source, destination) cases sent to the LLMs.
LLM_CASES = [
    ("healthy", "lab_hq.yaml", "pc-blue", "web-dmz"),
    ("missing-route", "lab_hq_missing_route.yaml", "pc-blue", "web-dmz"),
    ("tenant-isolation", "lab_hq.yaml", "pc-blue", "pc-green"),
]


def call(server, name: str, arguments: dict) -> dict:
    async def _invoke():
        return await server.call_tool(name, arguments)

    result = asyncio.run(_invoke())
    return json.loads(result.content[0].text)


def banner(title: str) -> None:
    print(f"\n{'=' * 74}\n  {title}\n{'=' * 74}")


def run_deterministic() -> bool:
    """Run the matrix + what-if checks. Returns True when all pass."""
    servers = {}
    for fixture in {f for f, *_ in MATRIX}:
        servers[fixture] = create_server(load_topology(FIXTURES / fixture))

    banner("1) Connectivity matrix (via MCP tool handlers)")
    all_ok = True
    for fixture, source, destination, expected in MATRIX:
        body = call(
            servers[fixture],
            "check_connectivity",
            {"source_id": source, "destination_id": destination},
        )
        actual = body["status"]
        ok = body["ok"] and actual == expected
        all_ok &= ok
        mark = "PASS" if ok else "FAIL"
        print(f"  [{mark}] {fixture:30} {source:10} -> {destination:9} "
              f"= {actual:12} (expected {expected})")

    banner("2) Evidence example: pc-blue -> web-dmz (healthy)")
    diagnose = call(
        servers["lab_hq.yaml"],
        "diagnose_connectivity",
        {"source_id": "pc-blue", "destination_id": "web-dmz"},
    )
    print(f"  summary : {diagnose['summary']}")
    print(f"  evidence: {len(diagnose['evidence'])} items -> "
          + " > ".join(i["type"] for i in diagnose["evidence"]))

    banner("3) What-if simulations (original model must stay intact)")
    healthy_server = servers["lab_hq.yaml"]
    healthy_path = FIXTURES / "lab_hq.yaml"
    before = healthy_path.read_text(encoding="utf-8")

    route_sim = call(
        healthy_server,
        "simulate_route_removal",
        {"route_id": "r-blue-to-dmz", "source_id": "pc-blue",
         "destination_id": "web-dmz"},
    )
    ok = (route_sim["baseline_status"] == "reachable"
          and route_sim["simulated_status"] == "unreachable"
          and [f["code"] for f in route_sim["new_findings"]] == ["MISSING_ROUTE"])
    all_ok &= ok
    print(f"  [{'PASS' if ok else 'FAIL'}] remove r-blue-to-dmz: "
          f"{route_sim['baseline_status']} -> {route_sim['simulated_status']}, "
          f"new={[f['code'] for f in route_sim['new_findings']]}")

    link_sim = call(
        healthy_server,
        "simulate_link_failure",
        {"link_id": "lnk-wan-tunnel", "source_id": "pc-branch",
         "destination_id": "web-dmz"},
    )
    ok = (link_sim["baseline_status"] == "reachable"
          and link_sim["simulated_status"] == "unreachable"
          and [f["code"] for f in link_sim["new_findings"]] == ["LINK_DOWN"])
    all_ok &= ok
    print(f"  [{'PASS' if ok else 'FAIL'}] disable lnk-wan-tunnel: "
          f"{link_sim['baseline_status']} -> {link_sim['simulated_status']}, "
          f"new={[f['code'] for f in link_sim['new_findings']]}")

    intact = healthy_path.read_text(encoding="utf-8") == before
    all_ok &= intact
    print(f"  [{'PASS' if intact else 'FAIL'}] fixture file byte-identical "
          f"after both simulations")
    return all_ok


def run_llm_loop(models: list[str], timeout: float) -> tuple[bool, str]:
    """Evaluate models on three DiagnosticResults.

    Returns (all_verdicts_ok, skip_reason).
    """
    env = llm_check.load_env()
    base_url, api_key = env["LLM_BASE_URL"], env["LLM_API_KEY"]

    banner("4) LLM evaluation loop (ground truth = deterministic engine)")
    try:
        gateway_models = llm_check.list_models(base_url, api_key, timeout=10)
        print(f"  gateway reachable — {len(gateway_models)} models advertised")
    except urllib.error.HTTPError as exc:
        hint = " — check LLM_API_KEY in .env (cp env.example .env)" if exc.code in (
            401, 403) else ""
        print(f"  SKIPPED: gateway returned HTTP {exc.code}{hint}: {exc}")
        return True, f"gateway HTTP {exc.code}"
    except Exception as exc:  # noqa: BLE001 - report any connectivity issue
        print(f"  SKIPPED: gateway unreachable from here ({type(exc).__name__}: {exc})")
        print("           Run this on the machine that can reach "
              f"{base_url} — deterministic part already passed.")
        return True, "gateway unreachable"

    # Keep only models the gateway actually advertises; fall back to its list
    # when configured ids went stale (gateways rename models over time).
    advertised = set(gateway_models)
    usable = [m for m in models if m in advertised]
    stale = [m for m in models if m not in advertised]
    if stale:
        print(f"  note: configured ids not advertised: {', '.join(stale)}")
    if not usable:
        print("  falling back to the gateway's advertised model list")
        usable = list(gateway_models)
    models = usable

    # Ground truth from the engine (same MCP handlers).
    truth: dict[str, dict] = {}
    for label, fixture, source, destination in LLM_CASES:
        server = create_server(load_topology(FIXTURES / fixture))
        truth[label] = call(
            server,
            "diagnose_connectivity",
            {"source_id": source, "destination_id": destination},
        )

    rows = []
    all_ok = True
    for model in models:
        case_results = []
        for label, *_ in LLM_CASES:
            payload = truth[label]
            user_prompt = (
                "نتایج دیاگنوستیک قطعی (JSON):\n"
                + json.dumps(
                    {
                        "status": payload["status"],
                        "findings": payload["findings"],
                        "evidence": payload["evidence"],
                        "limitations": payload["limitations"],
                    },
                    ensure_ascii=False,
                    indent=2,
                )
            )
            try:
                content, reasoning, _ = llm_check.chat(
                    base_url, api_key, model, user_prompt,
                    system=SYSTEM_PROMPT, max_tokens=4096, timeout=timeout,
                )
            except Exception as exc:  # noqa: BLE001
                case_results.append((label, payload["status"], f"ERROR:{exc}", False))
                all_ok = False
                continue
            match = VERDICT_RE.search(content)
            verdict = match.group(1).lower() if match else "—"
            ok = verdict == payload["status"]
            all_ok &= ok
            case_results.append((label, payload["status"], verdict, ok))
            if reasoning:
                print(f"    ({model} / {label}: reasoning {len(reasoning)} chars)")
        rows.append((model, case_results))

    banner("5) Accuracy table — engine status vs model VERDICT")
    header_labels = [label for label, *_ in LLM_CASES]
    print(
        f"  {'model':<28} "
        + " ".join(f"{label:<18}" for label in header_labels)
    )
    for model, case_results in rows:
        cells = []
        for _, truth_status, verdict, ok in case_results:
            mark = "✓" if ok else "✗"
            cells.append(f"{truth_status}/{verdict}{mark}".ljust(18))
        print(f"  {model:<28} " + " ".join(cells))
    return all_ok, ""


def main() -> int:
    parser = argparse.ArgumentParser(description="NetTwin AI HQ lab demo")
    parser.add_argument("--no-llm", action="store_true",
                        help="skip the LLM evaluation loop")
    parser.add_argument("--models", help="comma-separated model ids to evaluate")
    parser.add_argument("--timeout", type=float, default=240,
                        help="per-call LLM timeout seconds")
    args = parser.parse_args()

    banner("NetTwin AI — HQ lab demo (4 switches + 2 firewalls)")
    deterministic_ok = run_deterministic()

    llm_ok = True
    llm_note = ""
    if not args.no_llm:
        env = llm_check.load_env()
        if args.models:
            models = [m.strip() for m in args.models.split(",") if m.strip()]
        else:
            models = [m.strip() for m in env.get("LLM_MODELS", "").split(",")
                      if m.strip()]
        llm_ok, llm_note = run_llm_loop(models, timeout=args.timeout)

    banner("RESULT")
    if not llm_ok:
        llm_label = "FAIL"
    elif llm_note:
        llm_label = f"SKIPPED ({llm_note})"
    else:
        llm_label = "PASS"
    print(f"  deterministic: {'PASS' if deterministic_ok else 'FAIL'}")
    print(f"  llm loop      : {llm_label}")
    return 0 if (deterministic_ok and llm_ok) else 1


if __name__ == "__main__":
    raise SystemExit(main())
