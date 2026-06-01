AgentGate
=========

Splunk-native pre-action governance and blast-radius layer for AI agents.
Repository: https://github.com/JonathanSolvesProblems/AgentGate

This app ships:
- 12 saved searches (default/savedsearches.conf) tagged with MITRE techniques
  and compliance bands (PCI, SOX, HIPAA).
- KV-store collections:
    agentgate_assets    — criticality + compliance tags per asset
    agentgate_findings  — pending approval records (mock of ES 8 Findings)
- Audit dashboard at: Search & Reporting > Dashboards > "AgentGate Audit"

The Python pipeline that performs interception, blast-radius analysis,
prompt-injection detection, and Foundation-Sec reasoning lives in the parent
repository at /agentgate/. Run it with:

    py -3.12 -m venv .venv
    .venv\Scripts\activate
    pip install -r requirements.txt
    python scripts\demo.py

See the parent README for the deterministic-vs-generative thesis, measured
metrics, and standards mapping.

License: Apache 2.0.
