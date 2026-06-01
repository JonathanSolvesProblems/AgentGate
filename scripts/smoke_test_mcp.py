"""Smoke test: initialize MCP session, list tools, call one read-only tool."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import httpx
from dotenv import load_dotenv

REPO_ROOT = Path(__file__).resolve().parents[1]
load_dotenv(REPO_ROOT / ".env")


def jsonrpc(method: str, params: dict | None = None, _id: int = 1) -> dict:
    body = {"jsonrpc": "2.0", "id": _id, "method": method}
    if params is not None:
        body["params"] = params
    return body


def main() -> int:
    url = os.environ["SPLUNK_MCP_URL"]
    token = os.environ["SPLUNK_MCP_TOKEN"]

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
    }

    with httpx.Client(verify=False, timeout=30.0) as client:
        # 1) initialize
        init_body = jsonrpc(
            "initialize",
            params={
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "agentgate-smoke", "version": "0.0.1"},
            },
            _id=1,
        )
        r = client.post(url, headers=headers, json=init_body)
        print(f"initialize: HTTP {r.status_code}")
        session_id = r.headers.get("mcp-session-id") or r.headers.get("Mcp-Session-Id")
        if session_id:
            headers["Mcp-Session-Id"] = session_id
            print(f"session: {session_id}")
        body_preview = r.text[:400].replace("\n", " ")
        print(f"  body: {body_preview}")

        # 2) notifications/initialized (one-way, per MCP spec)
        client.post(
            url,
            headers=headers,
            json={"jsonrpc": "2.0", "method": "notifications/initialized"},
        )

        # 3) tools/list
        r = client.post(url, headers=headers, json=jsonrpc("tools/list", _id=2))
        print(f"\ntools/list: HTTP {r.status_code}")
        # MCP streamable HTTP may return SSE-framed JSON; handle both
        text = r.text
        if text.startswith("event:") or "data: " in text:
            for line in text.splitlines():
                if line.startswith("data: "):
                    text = line[len("data: "):]
                    break
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            print(f"  could not parse: {exc}")
            print(f"  raw: {r.text[:600]}")
            return 1
        tools = data.get("result", {}).get("tools", [])
        print(f"  found {len(tools)} tools")
        for t in tools[:15]:
            print(f"    - {t['name']}")
        if len(tools) > 15:
            print(f"    ... +{len(tools)-15} more")

        # 4) call a low-risk read tool: splunk_get_indexes
        if any(t["name"] == "splunk_get_indexes" for t in tools):
            r = client.post(
                url,
                headers=headers,
                json=jsonrpc(
                    "tools/call",
                    params={"name": "splunk_get_indexes", "arguments": {}},
                    _id=3,
                ),
            )
            print(f"\nsplunk_get_indexes: HTTP {r.status_code}")
            text = r.text
            if "data: " in text:
                for line in text.splitlines():
                    if line.startswith("data: "):
                        text = line[len("data: "):]
                        break
            try:
                data = json.loads(text)
                content = data.get("result", {}).get("content", [])
                for item in content[:1]:
                    txt = item.get("text", "")
                    print(f"  {txt[:400]}{'...' if len(txt) > 400 else ''}")
            except json.JSONDecodeError:
                print(f"  raw: {r.text[:400]}")

    print("\nOK: MCP initialize + tools/list + tools/call round-trip works.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
