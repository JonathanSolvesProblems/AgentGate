"""Smoke test: Foundation-Sec via Ollama answers a security-domain prompt."""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

from dotenv import load_dotenv
from ollama import Client

REPO_ROOT = Path(__file__).resolve().parents[1]
load_dotenv(REPO_ROOT / ".env")


def main() -> int:
    host = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
    model = os.environ.get("OLLAMA_MODEL", "hf.co/gabriellarson/Foundation-Sec-8B-Instruct-GGUF:Q4_K_M")

    client = Client(host=host)

    prompt = (
        "You are a security reasoning assistant. In one short paragraph, "
        "explain why disabling a Splunk correlation search that maps to MITRE T1078 "
        "(Valid Accounts) could open a PCI DSS compliance gap. Be specific."
    )

    print(f"model: {model}")
    print(f"prompt: {prompt}\n---")
    t0 = time.perf_counter()
    resp = client.chat(
        model=model,
        messages=[{"role": "user", "content": prompt}],
        options={"temperature": 0.2, "num_predict": 220},
    )
    dt = time.perf_counter() - t0

    content = resp["message"]["content"].strip()
    print(content)
    print(f"\n---\nlatency: {dt:.1f}s  ({resp.get('eval_count', '?')} tokens)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
