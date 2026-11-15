#!/usr/bin/env python3
"""LLM gateway helper for NetTwin AI (OpenAI-compatible /v1 API).

Reads configuration from the workspace ``.env`` (or real environment
variables, which take precedence). Standard library only — no extra deps.

Usage:
    python scripts/llm_check.py                      # ping every model
    python scripts/llm_check.py --list               # list gateway models
    python scripts/llm_check.py --model qwen-27b-instruct --ask "سلام"
    python scripts/llm_check.py --model ... --ask "..." --system "..."
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
ENV_KEYS = ("LLM_BASE_URL", "LLM_API_KEY", "LLM_MODELS", "LLM_DEFAULT_MODEL")


def load_env(path: Path | None = None) -> dict[str, str]:
    """Load LLM_* keys from .env; real environment variables win."""
    env: dict[str, str] = {}
    env_path = path or (REPO_ROOT / ".env")
    if env_path.exists():
        for line in env_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            env[key.strip()] = value.strip().strip('"').strip("'")
    for key in ENV_KEYS:
        if os.environ.get(key):
            env[key] = os.environ[key]
    return env


def _request(
    url: str,
    *,
    api_key: str,
    payload: dict | None = None,
    timeout: float = 180,
) -> dict:
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = urllib.request.Request(
        url,
        data=data,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        method="POST" if payload is not None else "GET",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def list_models(base_url: str, api_key: str, timeout: float = 30) -> list[str]:
    """Return model ids advertised by the gateway."""
    data = _request(f"{base_url}/models", api_key=api_key, timeout=timeout)
    return sorted(model["id"] for model in data.get("data", []))


def chat(
    base_url: str,
    api_key: str,
    model: str,
    prompt: str,
    *,
    system: str | None = None,
    max_tokens: int = 2048,
    temperature: float = 0.2,
    timeout: float = 240,
) -> tuple[str, str, dict]:
    """One chat completion.

    Returns:
        ``(content, reasoning, raw_response)`` — reasoning holds
        ``reasoning_content`` when the model is a reasoning variant.
    """
    messages: list[dict] = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})
    data = _request(
        f"{base_url}/chat/completions",
        api_key=api_key,
        payload={
            "model": model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        },
        timeout=timeout,
    )
    message = data["choices"][0].get("message", {})
    content = (message.get("content") or "").strip()
    reasoning = (
        message.get("reasoning_content") or message.get("reasoning") or ""
    ).strip()
    return content, reasoning, data


def ping_model(env: dict[str, str], model: str, timeout: float) -> dict:
    """Health-check one model with a tiny prompt."""
    started = time.monotonic()
    try:
        content, reasoning, _ = chat(
            env["LLM_BASE_URL"],
            env["LLM_API_KEY"],
            model,
            "پاسخ کوتاه و تک‌کلمه‌ای بده: آماده‌ای؟",
            max_tokens=2048,
            timeout=timeout,
        )
        elapsed = time.monotonic() - started
        return {
            "model": model,
            "ok": bool(content),
            "latency_s": round(elapsed, 2),
            "content": content[:200],
            "reasoning_chars": len(reasoning),
        }
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return {
            "model": model,
            "ok": False,
            "latency_s": round(time.monotonic() - started, 2),
            "error": f"{type(exc).__name__}: {exc}",
        }
    except (KeyError, IndexError, json.JSONDecodeError) as exc:
        return {
            "model": model,
            "ok": False,
            "latency_s": round(time.monotonic() - started, 2),
            "error": f"bad response: {type(exc).__name__}: {exc}",
        }


def main() -> int:
    parser = argparse.ArgumentParser(description="NetTwin AI LLM gateway helper")
    parser.add_argument("--list", action="store_true", help="list gateway models")
    parser.add_argument("--model", help="model id for --ask / single ping")
    parser.add_argument("--ask", help="send one prompt to --model")
    parser.add_argument("--system", help="optional system prompt for --ask")
    parser.add_argument("--max-tokens", type=int, default=2048)
    parser.add_argument("--timeout", type=float, default=240)
    args = parser.parse_args()

    env = load_env()
    for required in ("LLM_BASE_URL", "LLM_API_KEY"):
        if not env.get(required):
            print(f"error: {required} not configured (.env or env var)", file=sys.stderr)
            return 1
    base_url, api_key = env["LLM_BASE_URL"], env["LLM_API_KEY"]

    if args.list:
        try:
            for model_id in list_models(base_url, api_key, timeout=args.timeout):
                print(model_id)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
            return 2
        return 0

    if args.ask:
        model = args.model or env.get("LLM_DEFAULT_MODEL", "")
        if not model:
            print("error: --model required (no LLM_DEFAULT_MODEL set)", file=sys.stderr)
            return 1
        try:
            content, reasoning, _ = chat(
                base_url, api_key, model, args.ask,
                system=args.system,
                max_tokens=args.max_tokens,
                timeout=args.timeout,
            )
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
            return 2
        if reasoning:
            print(f"[reasoning:{len(reasoning)} chars] {reasoning[:500]}")
        print(content)
        return 0

    # Default: ping all configured models.
    models = [
        m.strip()
        for m in env.get("LLM_MODELS", "").split(",")
        if m.strip()
    ]
    if args.model:
        models = [args.model]
    if not models:
        print("error: no models configured (LLM_MODELS)", file=sys.stderr)
        return 1

    failures = 0
    for model in models:
        result = ping_model(env, model, timeout=args.timeout)
        if result["ok"]:
            print(
                f"OK   {model:<28} {result['latency_s']:>7}s  "
                f"reasoning_chars={result['reasoning_chars']}  "
                f"reply={result['content']!r}"
            )
        else:
            failures += 1
            print(f"FAIL {model:<28} {result['latency_s']:>7}s  {result['error']}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
