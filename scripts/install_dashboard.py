"""Install the AgentGate Audit dashboard into Splunk's `search` app via REST.

Reads splunk_app/agentgate/default/data/ui/views/agentgate_audit.xml and POSTs
it to /servicesNS/admin/search/data/ui/views. Idempotent: PUTs if it already
exists. Visible at: Splunk Web → search app → Dashboards → "AgentGate Audit".
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from rich.console import Console  # noqa: E402

from agentgate.splunk_client import rest  # noqa: E402

console = Console()

VIEW_NAME = "agentgate_audit"
XML_PATH = REPO_ROOT / "splunk_app" / "agentgate" / "default" / "data" / "ui" / "views" / "agentgate_audit.xml"


def main() -> int:
    if not XML_PATH.exists():
        console.print(f"[red]dashboard XML not found at {XML_PATH}[/red]")
        return 2
    xml = XML_PATH.read_text(encoding="utf-8")

    base = "/servicesNS/admin/search/data/ui/views"
    existing = rest("GET", f"{base}/{VIEW_NAME}")
    if existing.status_code == 200:
        r = rest("POST", f"{base}/{VIEW_NAME}", data={"eai:data": xml})
        action = "updated"
    else:
        r = rest("POST", base, data={"name": VIEW_NAME, "eai:data": xml})
        action = "created"

    if r.status_code in (200, 201):
        console.print(f"[green]{action} dashboard {VIEW_NAME!r}[/green]")
        web_port = 8000
        console.print(f"  visit: http://localhost:{web_port}/en-US/app/search/{VIEW_NAME}")
        return 0
    console.print(f"[red]failed: HTTP {r.status_code}: {r.text[:400]}[/red]")
    return 1


if __name__ == "__main__":
    sys.exit(main())
