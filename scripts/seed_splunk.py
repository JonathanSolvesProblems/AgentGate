"""Seed the local Splunk with realistic SOC content for AgentGate to operate on.

Idempotent: re-running updates in place rather than duplicating. Creates:
- indexes: agentgate_demo_data, agentgate_audit
- HEC global config + per-token entries (audit + demo)
- 12 saved searches annotated with MITRE techniques and compliance tags
- KV store collection 'agentgate_assets' populated with criticality + compliance metadata
- Sample synthetic events so the searches return non-empty results
"""

from __future__ import annotations

import json
import random
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from faker import Faker
from rich.console import Console

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from agentgate.splunk_client import get_service, rest  # noqa: E402

console = Console()
fake = Faker()
Faker.seed(42)
random.seed(42)


DEMO_INDEX = "agentgate_demo_data"
AUDIT_INDEX = "agentgate_audit"
DEMO_APP = "search"
KV_COLLECTION = "agentgate_assets"


SAVED_SEARCHES: list[dict[str, Any]] = [
    {
        "name": "AG: Brute Force Windows Logon",
        "search": (
            f"search index={DEMO_INDEX} sourcetype=windows:security EventCode=4625 "
            "| bucket _time span=5m | stats count by user, src_ip | where count >= 5"
        ),
        "cron_schedule": "*/5 * * * *",
        "description": "[MITRE: T1110.001] [Compliance: PCI, SOX] Five or more failed Windows logon attempts within five minutes from a single source.",
        "dispatch.earliest_time": "-15m",
        "dispatch.latest_time": "now",
    },
    {
        "name": "AG: Anomalous Geo Login",
        "search": (
            f"search index={DEMO_INDEX} sourcetype=windows:security EventCode=4624 LogonType=10 "
            "| iplocation src_ip | search Country!=US Country!=*"
        ),
        "cron_schedule": "*/10 * * * *",
        "description": "[MITRE: T1078] [Compliance: PCI, SOX] Interactive logon from non-US geo to a corporate host.",
        "dispatch.earliest_time": "-1h",
    },
    {
        "name": "AG: SQL Injection on Payment App",
        "search": (
            f"search index={DEMO_INDEX} sourcetype=web:access host=paymentapp01 "
            "| regex uri=\"(?i)(union\\s+select|--|;\\s*drop|or\\s+1=1)\" | stats count by clientip, uri"
        ),
        "cron_schedule": "*/5 * * * *",
        "description": "[MITRE: T1190] [Compliance: PCI] SQL injection patterns against the payment application.",
        "dispatch.earliest_time": "-15m",
    },
    {
        "name": "AG: Suspicious PowerShell EncodedCommand",
        "search": (
            f"search index={DEMO_INDEX} sourcetype=windows:security EventCode=4104 "
            "| regex ScriptBlockText=\"(?i)(invoke-expression|downloadstring|encodedcommand|frombase64string)\""
        ),
        "cron_schedule": "*/10 * * * *",
        "description": "[MITRE: T1059.001] [Compliance: SOX, PCI] PowerShell script block with offensive primitives.",
        "dispatch.earliest_time": "-30m",
    },
    {
        "name": "AG: New Privileged Account Creation",
        "search": (
            f"search index={DEMO_INDEX} sourcetype=windows:security EventCode=4720 "
            "| join user [search EventCode=4732 GroupName=Administrators]"
        ),
        "cron_schedule": "*/15 * * * *",
        "description": "[MITRE: T1136.001] [Compliance: SOX, HIPAA] New account created and added to Administrators in close succession.",
        "dispatch.earliest_time": "-1h",
    },
    {
        "name": "AG: DNS Tunneling Indicator",
        "search": (
            f"search index={DEMO_INDEX} sourcetype=dns:query "
            "| eval qlen=len(query) | where qlen > 50 | stats count by src_ip"
        ),
        "cron_schedule": "*/10 * * * *",
        "description": "[MITRE: T1572] [Compliance: PCI] DNS queries longer than 50 chars (tunneling indicator).",
        "dispatch.earliest_time": "-30m",
    },
    {
        "name": "AG: Large Outbound Data Transfer",
        "search": (
            f"search index={DEMO_INDEX} sourcetype=firewall:netscreen action=allow "
            "| stats sum(bytes_out) as total by src_ip, dst_ip | where total > 100000000"
        ),
        "cron_schedule": "*/15 * * * *",
        "description": "[MITRE: T1041] [Compliance: PCI, HIPAA] >100MB outbound from a single src/dst pair in window.",
        "dispatch.earliest_time": "-1h",
    },
    {
        "name": "AG: RDP from External IP",
        "search": (
            f"search index={DEMO_INDEX} sourcetype=windows:security EventCode=4624 LogonType=10 "
            "| search NOT (src_ip=10.* OR src_ip=192.168.* OR src_ip=172.16.*)"
        ),
        "cron_schedule": "*/5 * * * *",
        "description": "[MITRE: T1021.001] [Compliance: PCI, HIPAA] RDP interactive logon from a non-RFC1918 source.",
        "dispatch.earliest_time": "-15m",
    },
    {
        "name": "AG: LSASS Memory Access",
        "search": (
            f"search index={DEMO_INDEX} sourcetype=windows:security EventCode=4688 "
            "| search New_Process_Name=*lsass* OR Process_Command_Line=*lsass*"
        ),
        "cron_schedule": "*/10 * * * *",
        "description": "[MITRE: T1003.001] [Compliance: PCI] Process spawn referencing LSASS (credential dumping).",
        "dispatch.earliest_time": "-30m",
    },
    {
        "name": "AG: Mass File Rename Encryption",
        "search": (
            f"search index={DEMO_INDEX} sourcetype=windows:security EventCode=4663 "
            "| regex ObjectName=\"\\.(encrypted|locked|crypt)$\" | stats dc(ObjectName) as files by user | where files > 50"
        ),
        "cron_schedule": "*/5 * * * *",
        "description": "[MITRE: T1486] [Compliance: HIPAA, PCI] Single user touching 50+ files with ransomware-style extensions.",
        "dispatch.earliest_time": "-15m",
    },
    {
        "name": "AG: Account Lockout Surge",
        "search": (
            f"search index={DEMO_INDEX} sourcetype=windows:security EventCode=4740 "
            "| bin _time span=10m | stats count by _time | where count > 20"
        ),
        "cron_schedule": "*/10 * * * *",
        "description": "[MITRE: T1110] [Compliance: SOX] Account lockouts exceeding 20 per 10-minute window.",
        "dispatch.earliest_time": "-30m",
    },
    {
        "name": "AG: Service Account Interactive Login",
        "search": (
            f"search index={DEMO_INDEX} sourcetype=windows:security EventCode=4624 LogonType=2 "
            '| search user="svc_*"'
        ),
        "cron_schedule": "*/15 * * * *",
        "description": "[MITRE: T1078.002] [Compliance: SOX, PCI] Service account logged in interactively (policy violation).",
        "dispatch.earliest_time": "-1h",
    },
]


ASSETS: list[dict[str, Any]] = [
    {"asset_id": f"index:{DEMO_INDEX}", "asset_type": "index", "compliance_tags": ["PCI", "SOX", "HIPAA"], "criticality": "high", "owner": "soc"},
    {"asset_id": "host:dc01", "asset_type": "host", "compliance_tags": ["SOX"], "criticality": "critical", "owner": "identity"},
    {"asset_id": "host:paymentapp01", "asset_type": "host", "compliance_tags": ["PCI"], "criticality": "critical", "owner": "payments"},
    {"asset_id": "host:patientportal01", "asset_type": "host", "compliance_tags": ["HIPAA"], "criticality": "critical", "owner": "clinical"},
    {"asset_id": "host:fileserver01", "asset_type": "host", "compliance_tags": ["HIPAA", "SOX"], "criticality": "high", "owner": "storage"},
    {"asset_id": "host:webfront01", "asset_type": "host", "compliance_tags": ["PCI"], "criticality": "high", "owner": "frontend"},
    {"asset_id": "user:svc_payment", "asset_type": "user", "compliance_tags": ["PCI"], "criticality": "high", "owner": "payments"},
    {"asset_id": "user:svc_hl7", "asset_type": "user", "compliance_tags": ["HIPAA"], "criticality": "high", "owner": "clinical"},
    {"asset_id": "sourcetype:windows:security", "asset_type": "sourcetype", "compliance_tags": ["SOX", "PCI"], "criticality": "high", "owner": "soc"},
]


def ensure_index(service: Any, name: str) -> None:
    if name in service.indexes:
        console.print(f"  index {name!r} already exists")
        return
    service.indexes.create(name)
    console.print(f"  [green]created index {name!r}[/green]")


def ensure_hec_enabled() -> None:
    r = rest("POST", "/servicesNS/nobody/splunk_httpinput/data/inputs/http/http",
            data={"disabled": "0", "enableSSL": "1", "port": "8088"})
    if r.status_code in (200, 201):
        console.print("  HEC globally enabled on :8088")
    else:
        console.print(f"  HEC global enable returned HTTP {r.status_code} (likely already enabled): {r.text[:120]}")


def ensure_hec_token(name: str, index: str) -> str:
    r = rest("GET", f"/servicesNS/nobody/splunk_httpinput/data/inputs/http/{name}")
    if r.status_code == 200:
        entry = r.json()["entry"][0]["content"]
        console.print(f"  HEC token {name!r} already exists")
        return entry["token"]

    r = rest("POST", "/servicesNS/nobody/splunk_httpinput/data/inputs/http",
            data={"name": name, "index": index, "indexes": index, "disabled": "0",
                  "useACK": "0", "sourcetype": "agentgate:event"})
    if r.status_code not in (200, 201):
        raise RuntimeError(f"HEC token creation failed: {r.status_code} {r.text[:300]}")
    token = r.json()["entry"][0]["content"]["token"]
    console.print(f"  [green]created HEC token {name!r}[/green]")
    return token


def upsert_saved_search(service: Any, spec: dict[str, Any]) -> None:
    name = spec["name"]
    payload = {k: v for k, v in spec.items() if k != "name"}
    if name in service.saved_searches:
        ss = service.saved_searches[name]
        ss.update(**payload).refresh()
        console.print(f"  updated saved search {name!r}")
        return
    service.saved_searches.create(name, search=payload.pop("search"), **payload)
    console.print(f"  [green]created saved search {name!r}[/green]")


def ensure_kv_collection(service: Any) -> None:
    collections = service.kvstore
    if KV_COLLECTION in collections:
        console.print(f"  KV collection {KV_COLLECTION!r} already exists")
        return
    collections.create(KV_COLLECTION, **{
        "field.asset_id": "string",
        "field.asset_type": "string",
        "field.compliance_tags": "string",
        "field.criticality": "string",
        "field.owner": "string",
    })
    console.print(f"  [green]created KV collection {KV_COLLECTION!r}[/green]")


def populate_assets(service: Any) -> None:
    coll = service.kvstore[KV_COLLECTION].data
    existing = {row.get("asset_id"): row.get("_key") for row in coll.query()}
    for asset in ASSETS:
        body = dict(asset)
        body["compliance_tags"] = ",".join(asset["compliance_tags"])
        if asset["asset_id"] in existing:
            coll.update(existing[asset["asset_id"]], json.dumps(body))
        else:
            coll.insert(json.dumps(body))
    console.print(f"  [green]populated {len(ASSETS)} assets in KV[/green]")


def submit_events(service: Any) -> int:
    """Inject ~300 mixed events covering the sourcetypes our detections query."""
    idx = service.indexes[DEMO_INDEX]
    now = datetime.now(timezone.utc)
    count = 0

    # 100 windows:security events: 70 noise, 20 failed logons (T1110.001), 10 4624 type 10
    for _ in range(70):
        t = now - timedelta(seconds=random.randint(60, 86400))
        evt = (
            f"{t:%Y-%m-%d %H:%M:%S} host=dc01 EventCode=4624 LogonType=3 "
            f"user={fake.user_name()} src_ip={fake.ipv4_private()} Workstation={fake.hostname()}"
        )
        idx.submit(evt, sourcetype="windows:security", host="dc01")
        count += 1
    for _ in range(20):
        t = now - timedelta(seconds=random.randint(60, 3600))
        ip = "10.0.0.45"  # concentrated so brute-force detection fires
        user = "finance_clerk"
        evt = (
            f"{t:%Y-%m-%d %H:%M:%S} host=dc01 EventCode=4625 LogonType=3 "
            f"user={user} src_ip={ip} FailureReason=BadPassword"
        )
        idx.submit(evt, sourcetype="windows:security", host="dc01")
        count += 1
    for _ in range(10):
        t = now - timedelta(seconds=random.randint(60, 7200))
        evt = (
            f"{t:%Y-%m-%d %H:%M:%S} host=paymentapp01 EventCode=4624 LogonType=10 "
            f"user={fake.user_name()} src_ip={fake.ipv4_public()}"
        )
        idx.submit(evt, sourcetype="windows:security", host="paymentapp01")
        count += 1

    # 50 web:access on paymentapp01: 45 benign, 5 with SQLi
    for _ in range(45):
        t = now - timedelta(seconds=random.randint(60, 7200))
        evt = (
            f"{t:%Y-%m-%d %H:%M:%S} clientip={fake.ipv4_public()} "
            f'method=GET uri=/checkout/order/{random.randint(1000,9999)} status=200 useragent="Mozilla/5.0"'
        )
        idx.submit(evt, sourcetype="web:access", host="paymentapp01")
        count += 1
    for _ in range(5):
        t = now - timedelta(seconds=random.randint(60, 1800))
        evt = (
            f"{t:%Y-%m-%d %H:%M:%S} clientip={fake.ipv4_public()} "
            f"method=GET uri=/login?user=admin'%20OR%201=1--&pw=x status=500"
        )
        idx.submit(evt, sourcetype="web:access", host="paymentapp01")
        count += 1

    # 30 firewall:netscreen: 25 small, 5 big exfil
    for _ in range(25):
        t = now - timedelta(seconds=random.randint(60, 86400))
        evt = (
            f"{t:%Y-%m-%d %H:%M:%S} src_ip={fake.ipv4_private()} dst_ip={fake.ipv4_public()} "
            f"dst_port={random.choice([80,443,53])} action=allow bytes_out={random.randint(200,20000)}"
        )
        idx.submit(evt, sourcetype="firewall:netscreen", host="fw01")
        count += 1
    for _ in range(5):
        t = now - timedelta(seconds=random.randint(60, 3600))
        evt = (
            f"{t:%Y-%m-%d %H:%M:%S} src_ip=10.10.5.21 dst_ip={fake.ipv4_public()} "
            f"dst_port=443 action=allow bytes_out={random.randint(110_000_000, 800_000_000)}"
        )
        idx.submit(evt, sourcetype="firewall:netscreen", host="fw01")
        count += 1

    # 20 dns:query: 15 normal, 5 long (tunneling)
    for _ in range(15):
        t = now - timedelta(seconds=random.randint(60, 86400))
        evt = (
            f"{t:%Y-%m-%d %H:%M:%S} src_ip={fake.ipv4_private()} query={fake.domain_name()} "
            f"query_type=A answer={fake.ipv4_public()}"
        )
        idx.submit(evt, sourcetype="dns:query", host="resolver01")
        count += 1
    for _ in range(5):
        t = now - timedelta(seconds=random.randint(60, 3600))
        evt = (
            f"{t:%Y-%m-%d %H:%M:%S} src_ip=10.10.7.99 "
            f"query={fake.lexify('?'*70)}.attacker.net query_type=TXT answer="
        )
        idx.submit(evt, sourcetype="dns:query", host="resolver01")
        count += 1

    return count


def main() -> int:
    console.rule("[bold cyan]AgentGate Splunk seed[/bold cyan]")
    service = get_service()

    console.print("\n[bold]1. Indexes[/bold]")
    ensure_index(service, DEMO_INDEX)
    ensure_index(service, AUDIT_INDEX)

    console.print("\n[bold]2. HEC[/bold]")
    ensure_hec_enabled()
    audit_token = ensure_hec_token("agentgate_audit", AUDIT_INDEX)
    demo_token = ensure_hec_token("agentgate_demo", DEMO_INDEX)

    # update .env with the audit HEC token if blank
    env_path = REPO_ROOT / ".env"
    if env_path.exists():
        env_text = env_path.read_text()
        if "AGENTGATE_HEC_TOKEN=\n" in env_text or "AGENTGATE_HEC_TOKEN=$" in env_text or "AGENTGATE_HEC_TOKEN=" in env_text and "AGENTGATE_HEC_TOKEN=\n" in (env_text + "\n"):
            pass
        if "\nAGENTGATE_HEC_TOKEN=\n" in (env_text + "\n") or env_text.rstrip().endswith("AGENTGATE_HEC_TOKEN="):
            env_text = env_text.replace("AGENTGATE_HEC_TOKEN=", f"AGENTGATE_HEC_TOKEN={audit_token}")
            env_path.write_text(env_text)
            console.print("  [green]wrote AGENTGATE_HEC_TOKEN to .env[/green]")

    console.print("\n[bold]3. Saved searches[/bold]")
    for spec in SAVED_SEARCHES:
        upsert_saved_search(service, spec)

    console.print("\n[bold]4. KV store assets[/bold]")
    ensure_kv_collection(service)
    populate_assets(service)

    console.print("\n[bold]5. Sample events[/bold]")
    t0 = time.perf_counter()
    n = submit_events(service)
    console.print(f"  injected {n} events in {time.perf_counter()-t0:.1f}s")

    console.print("\n[bold green]Seed complete.[/bold green]")
    console.print(f"  demo HEC token (events):  {demo_token}")
    console.print(f"  audit HEC token (writes): {audit_token}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
