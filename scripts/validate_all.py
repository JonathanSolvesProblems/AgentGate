"""Pre-record readiness check.

Probes every surface AgentGate touches and prints a green/red status table.
Run this before every recording attempt. Exits 0 if everything is ready, 1
otherwise. The script never modifies state — it is read-only.

Auto-bootstraps into the project venv if run with a different Python (e.g.
plain `python scripts/validate_all.py` on Windows picks up system Python,
which doesn't have splunklib / pytest installed).
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

REPO_ROOT = Path(__file__).resolve().parents[1]


def _bootstrap_into_venv() -> None:
    """If a project .venv exists and we're not already running with its Python,
    re-exec ourselves with the venv interpreter. Idempotent."""
    venv_python = REPO_ROOT / ".venv" / "Scripts" / "python.exe"
    if not venv_python.exists():
        venv_python = REPO_ROOT / ".venv" / "bin" / "python"  # POSIX fallback
        if not venv_python.exists():
            return
    current = Path(sys.executable).resolve()
    target = venv_python.resolve()
    if current == target:
        return
    print(f"[bootstrap] re-exec under {target}", flush=True)
    os.execv(str(target), [str(target), *sys.argv])


_bootstrap_into_venv()
sys.path.insert(0, str(REPO_ROOT))

import httpx  # noqa: E402
from dotenv import load_dotenv  # noqa: E402
from rich.console import Console  # noqa: E402
from rich.table import Table  # noqa: E402

load_dotenv(REPO_ROOT / ".env")
console = Console()


@dataclass
class CheckResult:
    name: str
    ok: bool
    detail: str
    fix: str = ""


def _splunk_rest(path: str, *, params: dict | None = None) -> httpx.Response:
    host = os.environ.get("SPLUNK_HOST", "localhost")
    port = os.environ.get("SPLUNK_MGMT_PORT", "8089")
    token = os.environ["SPLUNK_TOKEN"]
    params = params or {}
    params.setdefault("output_mode", "json")
    return httpx.get(
        f"https://{host}:{port}{path}",
        headers={"Authorization": f"Bearer {token}"},
        params=params,
        verify=False,
        timeout=10.0,
    )


# --- Checks ----------------------------------------------------------------


def c_splunk_reachable() -> CheckResult:
    try:
        r = _splunk_rest("/services/server/info")
        if r.status_code != 200:
            return CheckResult("Splunk Enterprise reachable + auth", False,
                               f"HTTP {r.status_code}",
                               "is splunkd running? curl https://localhost:8089/services/server/info")
        entry = r.json()["entry"][0]["content"]
        return CheckResult("Splunk Enterprise reachable + auth", True,
                           f"version={entry['version']} license={entry['licenseState']}")
    except Exception as exc:
        return CheckResult("Splunk Enterprise reachable + auth", False, str(exc)[:120],
                           "start Splunk service from Services.msc or Splunk Web tray")


def c_indexes() -> CheckResult:
    try:
        r = _splunk_rest("/services/data/indexes", params={"count": "0"})
        names = [e["name"] for e in r.json().get("entry", [])]
        required = {"agentgate_demo_data", "agentgate_audit"}
        missing = required - set(names)
        if missing:
            return CheckResult("Indexes exist", False, f"missing: {missing}",
                               "python scripts/seed_splunk.py")
        return CheckResult("Indexes exist", True, "agentgate_demo_data + agentgate_audit OK")
    except Exception as exc:
        return CheckResult("Indexes exist", False, str(exc)[:120], "python scripts/seed_splunk.py")


def c_saved_searches() -> CheckResult:
    try:
        r = _splunk_rest("/services/saved/searches", params={"count": "0"})
        ag = [e["name"] for e in r.json().get("entry", []) if e["name"].startswith("AG:")]
        if len(ag) < 12:
            return CheckResult("Saved searches (AG: portfolio)", False,
                               f"only {len(ag)}/12 AG: searches found",
                               "python scripts/seed_splunk.py")
        return CheckResult("Saved searches (AG: portfolio)", True, f"{len(ag)} AG: searches OK")
    except Exception as exc:
        return CheckResult("Saved searches (AG: portfolio)", False, str(exc)[:120], "")


def _kv_rows(name: str) -> tuple[bool, int, str]:
    """Use the SDK so namespace (nobody/system vs admin/search) stops mattering."""
    from agentgate.splunk_client import get_service
    svc = get_service()
    for c in svc.kvstore:
        if c.name == name:
            rows = list(c.data.query())
            return True, len(rows), ""
    return False, 0, "collection not found"


def c_kv_assets() -> CheckResult:
    try:
        found, n, err = _kv_rows("agentgate_assets")
        if not found:
            return CheckResult("KV: agentgate_assets", False, err, "python scripts/seed_splunk.py")
        if n == 0:
            return CheckResult("KV: agentgate_assets", False, "0 rows",
                               "python scripts/seed_splunk.py")
        return CheckResult("KV: agentgate_assets", True, f"{n} assets OK")
    except Exception as exc:
        return CheckResult("KV: agentgate_assets", False, str(exc)[:120], "")


def c_kv_findings() -> CheckResult:
    try:
        found, n, err = _kv_rows("agentgate_findings")
        if not found:
            return CheckResult("KV: agentgate_findings", False, err,
                               "python scripts/demo.py (creates collection on first non-ALLOW)")
        return CheckResult("KV: agentgate_findings", True,
                           f"{n} historical findings (0 OK on a fresh run)")
    except Exception as exc:
        return CheckResult("KV: agentgate_findings", False, str(exc)[:120], "")


def c_hec_enabled() -> CheckResult:
    try:
        r = _splunk_rest("/servicesNS/nobody/splunk_httpinput/data/inputs/http/http")
        if r.status_code != 200:
            return CheckResult("HEC global", False, f"HTTP {r.status_code}", "python scripts/seed_splunk.py")
        content = r.json()["entry"][0]["content"]
        if content.get("disabled") in (1, "1", True):
            return CheckResult("HEC global", False, "HEC is disabled",
                               "Settings → Data Inputs → HTTP Event Collector → enable")
        return CheckResult("HEC global", True, f"port={content.get('port', '8088')}")
    except Exception as exc:
        return CheckResult("HEC global", False, str(exc)[:120], "")


def c_hec_audit_token() -> CheckResult:
    token = os.environ.get("AGENTGATE_HEC_TOKEN", "")
    if not token:
        return CheckResult("HEC audit token in .env", False, "AGENTGATE_HEC_TOKEN empty",
                           "python scripts/seed_splunk.py (rewrites .env)")
    return CheckResult("HEC audit token in .env", True, f"{token[:8]}…")


def c_mcp_server() -> CheckResult:
    url = os.environ.get("SPLUNK_MCP_URL", "")
    token = os.environ.get("SPLUNK_MCP_TOKEN", "")
    if not url or not token:
        return CheckResult("MCP Server endpoint", False, "URL or TOKEN missing in .env",
                           "Splunk Web → Splunk MCP Server → Create MCP Encrypted Token")
    try:
        body = {
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "agentgate-validate", "version": "0.0.1"},
            },
        }
        r = httpx.post(
            url,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/json, text/event-stream",
                "Content-Type": "application/json",
            },
            json=body, verify=False, timeout=10.0,
        )
        if r.status_code != 200:
            return CheckResult("MCP Server endpoint", False, f"HTTP {r.status_code}",
                               "verify token + Splunk MCP Server app is enabled")
        return CheckResult("MCP Server endpoint", True, "initialize OK")
    except Exception as exc:
        return CheckResult("MCP Server endpoint", False, str(exc)[:120], "")


def c_dashboard_installed() -> CheckResult:
    try:
        r = _splunk_rest("/servicesNS/admin/search/data/ui/views/agentgate_audit")
        if r.status_code == 200:
            return CheckResult("Dashboard installed", True,
                               "http://localhost:8000/en-US/app/search/agentgate_audit")
        return CheckResult("Dashboard installed", False, f"HTTP {r.status_code}",
                           "python scripts/install_dashboard.py")
    except Exception as exc:
        return CheckResult("Dashboard installed", False, str(exc)[:120], "")


def c_audit_events_flowing() -> CheckResult:
    """Look back 30 days so historical demo runs still register; the recording
    pass will write fresh events the moment scripts/demo.py runs."""
    try:
        body = {"search": "search index=agentgate_audit earliest=-30d | stats count",
                "output_mode": "json", "exec_mode": "oneshot"}
        host = os.environ.get("SPLUNK_HOST", "localhost")
        port = os.environ.get("SPLUNK_MGMT_PORT", "8089")
        token = os.environ["SPLUNK_TOKEN"]
        r = httpx.post(
            f"https://{host}:{port}/services/search/jobs",
            headers={"Authorization": f"Bearer {token}"},
            data=body, verify=False, timeout=15.0,
        )
        data = r.json()
        n = int(data.get("results", [{}])[0].get("count", "0")) if data.get("results") else 0
        if n == 0:
            return CheckResult("Audit index has events (30d)", False, "0 events in last 30d",
                               "python scripts/demo.py")
        return CheckResult("Audit index has events (30d)", True, f"{n} events in last 30d")
    except Exception as exc:
        return CheckResult("Audit index has events (30d)", False, str(exc)[:120], "")


def c_ollama() -> CheckResult:
    host = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
    model = os.environ.get("OLLAMA_MODEL", "")
    try:
        r = httpx.get(f"{host}/api/tags", timeout=5.0)
        names = [m["name"] for m in r.json().get("models", [])]
        if model and model not in names:
            return CheckResult("Ollama + Foundation-Sec", False,
                               f"model {model!r} not loaded; available: {names[:3]}",
                               f"ollama pull {model}")
        return CheckResult("Ollama + Foundation-Sec", True,
                           f"loaded={len(names)} model={model.split('/')[-1] if model else '?'}")
    except Exception as exc:
        return CheckResult("Ollama + Foundation-Sec", False, str(exc)[:120],
                           "start the Ollama tray app")


def c_ollama_hot() -> CheckResult:
    """Check if the demo model is currently resident in VRAM (avoids the 158s cold-load)."""
    host = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
    model = os.environ.get("OLLAMA_MODEL", "")
    try:
        r = httpx.get(f"{host}/api/ps", timeout=5.0)
        loaded = [m["name"] for m in r.json().get("models", [])]
        if model and model in loaded:
            return CheckResult("Foundation-Sec hot in VRAM", True, "resident")
        return CheckResult("Foundation-Sec hot in VRAM", False,
                           "model is cold (first scenario will take ~150s)",
                           "pre-warm: ollama run " + model + " 'ok' (then ctrl-d)")
    except Exception as exc:
        return CheckResult("Foundation-Sec hot in VRAM", False, str(exc)[:120], "")


def c_pytest_fast() -> CheckResult:
    try:
        t0 = time.perf_counter()
        result = subprocess.run(
            [sys.executable, "-m", "pytest", "tests/test_injection.py", "-q", "--no-header"],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=60,
        )
        dt = time.perf_counter() - t0
        if result.returncode != 0:
            return CheckResult("pytest tests/test_injection.py", False,
                               result.stdout.splitlines()[-1] if result.stdout else "failed",
                               "pytest tests/test_injection.py -v")
        last = result.stdout.strip().splitlines()[-1]
        return CheckResult("pytest tests/test_injection.py", True, f"{last} ({dt:.1f}s)")
    except Exception as exc:
        return CheckResult("pytest tests/test_injection.py", False, str(exc)[:120], "")


def c_repo_files() -> CheckResult:
    required = ["LICENSE", "README.md", "architecture_diagram.md", ".env", "requirements.txt"]
    missing = [f for f in required if not (REPO_ROOT / f).exists()]
    if missing:
        return CheckResult("Repo files present", False, f"missing: {missing}", "")
    return CheckResult("Repo files present", True, "LICENSE + README + architecture_diagram + .env + requirements")


def c_submission_artifacts() -> CheckResult:
    """submission.md + demo_script.md are private artifacts the user needs at recording time."""
    missing = [f for f in ("submission.md", "demo_script.md") if not (REPO_ROOT / f).exists()]
    if missing:
        return CheckResult("Private submission artifacts", False, f"missing: {missing}", "")
    return CheckResult("Private submission artifacts", True, "submission.md + demo_script.md (gitignored)")


CHECKS: list[Callable[[], CheckResult]] = [
    c_splunk_reachable,
    c_indexes,
    c_saved_searches,
    c_kv_assets,
    c_kv_findings,
    c_hec_enabled,
    c_hec_audit_token,
    c_mcp_server,
    c_dashboard_installed,
    c_audit_events_flowing,
    c_ollama,
    c_ollama_hot,
    c_pytest_fast,
    c_repo_files,
    c_submission_artifacts,
]


def main() -> int:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    console.rule("[bold cyan]AgentGate readiness check[/bold cyan]")
    results: list[CheckResult] = []
    for check in CHECKS:
        try:
            results.append(check())
        except Exception as exc:  # never crash the validator
            results.append(CheckResult(check.__name__, False, f"validator raised: {exc}", ""))

    table = Table(show_header=True, header_style="bold")
    table.add_column("check", style="bold", no_wrap=True)
    table.add_column("status", justify="center")
    table.add_column("detail")
    table.add_column("fix if red", style="dim")
    for r in results:
        status = "[green]OK[/green]" if r.ok else "[red]FAIL[/red]"
        table.add_row(r.name, status, r.detail, r.fix if not r.ok else "")
    console.print(table)

    failed = [r for r in results if not r.ok]
    if not failed:
        console.print("\n[bold green]All checks passed — ready to record.[/bold green]\n")
        return 0
    console.print(f"\n[bold red]{len(failed)} check(s) failed.[/bold red] Address them then re-run.\n")
    return 1


if __name__ == "__main__":
    sys.exit(main())
