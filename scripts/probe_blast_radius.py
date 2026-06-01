"""Probe blast-radius for a handful of seeded saved searches."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agentgate.graph import blast_radius, build_graph

artifact = build_graph()
targets = [
    "AG: SQL Injection on Payment App",
    "AG: New Privileged Account Creation",
    "AG: Mass File Rename Encryption",
    "AG: Anomalous Geo Login",
    "AG: RDP from External IP",
    "AG: LSASS Memory Access",
]
for name in targets:
    r = blast_radius(artifact, name)
    print(f"\n=== {name} ===")
    print(f"  severity:        {r.severity}")
    print(f"  techniques_lost: {r.techniques_lost}")
    print(f"  compliance_lost: {r.compliance_lost}")
    print(f"  assets affected: {len(r.assets_affected)}")
    for a in r.assets_affected:
        print(f"    - {a['asset_id']:<40s} crit={a['criticality']:<8s} "
              f"redund={a['redundancy']:>2d}  tags={a['compliance_tags']}")
