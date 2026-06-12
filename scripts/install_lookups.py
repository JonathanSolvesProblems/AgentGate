"""Register the agentgate_findings KV-store as a lookup transform so SPL can
read it via `| inputlookup agentgate_findings`.

The seed script creates the KV collection via the SDK (which lives in the
nobody/system namespace). Splunk's lookup commands need a separate transform
definition registered in transforms.conf — or, equivalently, POSTed to the
admin/search REST endpoint. This script does the latter so the install is
fully idempotent without copying files into $SPLUNK_HOME/etc/apps/.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def _bootstrap_into_venv() -> None:
    import os
    venv_python = REPO_ROOT / ".venv" / "Scripts" / "python.exe"
    if not venv_python.exists():
        venv_python = REPO_ROOT / ".venv" / "bin" / "python"
        if not venv_python.exists():
            return
    if Path(sys.executable).resolve() == venv_python.resolve():
        return
    print(f"[bootstrap] re-exec under {venv_python}", flush=True)
    os.execv(str(venv_python), [str(venv_python), *sys.argv])


_bootstrap_into_venv()
sys.path.insert(0, str(REPO_ROOT))

from rich.console import Console  # noqa: E402

from agentgate.splunk_client import rest  # noqa: E402

console = Console()

LOOKUPS = {
    "agentgate_findings": {
        "external_type": "kvstore",
        "collection": "agentgate_findings",
        "fields_list": "_key, finding_id, created_at, agent_id, tool_name, arguments, decision, severity, summary, status, matched_policies, stages_json",
    },
    "agentgate_assets": {
        "external_type": "kvstore",
        "collection": "agentgate_assets",
        "fields_list": "_key, asset_id, asset_type, compliance_tags, criticality, owner",
    },
}


def main() -> int:
    base = "/servicesNS/admin/search/data/transforms/lookups"
    for name, spec in LOOKUPS.items():
        existing = rest("GET", f"{base}/{name}")
        if existing.status_code == 200:
            r = rest("POST", f"{base}/{name}", data=spec)
            action = "updated"
        else:
            payload = {"name": name, **spec}
            r = rest("POST", base, data=payload)
            action = "created"
        if r.status_code in (200, 201):
            console.print(f"[green]{action} lookup {name!r}[/green]")
        else:
            console.print(f"[red]failed {name!r}: HTTP {r.status_code}: {r.text[:300]}[/red]")
            return 1
    console.print("\n[bold green]Lookups registered. Reload the dashboard.[/bold green]")
    return 0


if __name__ == "__main__":
    sys.exit(main())
