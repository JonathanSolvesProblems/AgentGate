# AgentGate: Stop rogue AI actions on Splunk before they hit production

[![CI](https://github.com/JonathanSolvesProblems/AgentGate/actions/workflows/ci.yml/badge.svg)](https://github.com/JonathanSolvesProblems/AgentGate/actions/workflows/ci.yml) [![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE) [![Python](https://img.shields.io/badge/python-3.12-blue)](https://www.python.org/)

A Splunk-native pre-action governance and blast-radius layer for AI agents. Built for the [Splunk Agentic Ops Hackathon](https://splunk.devpost.com/) (Security track, deadline 2026-06-15).

## The pain

Splunk shipped six agentic capabilities in twelve months: Triage Agent, Investigation Agent, Malware Reversal Agent, AI Playbook Authoring, AI Assistant for SPL, Foundation-Sec-8B. Every one of them can read your data, propose changes, and (increasingly) execute them. **None of them answers compliance's question: who approved this action, and what was its blast radius?**

> *"The most likely outcome is that compliance and governance teams block the application from going to production."* — Jeff Wiedemann, Global AI Partner Technical Leader, Splunk

AgentGate is the gate between any AI agent and Splunk that produces an answerable trail of every decision.

## What it does

AgentGate intercepts every tool call an agent makes against Splunk and runs **five deterministic stages plus one advisory sixth**:

1. **Prompt-injection check** — heuristic + obfuscation-normalised scan over tool inputs and the context (log lines) the agent has read. Targets override-style injection (LLM01 indirect).
2. **Blast-radius walk** — NetworkX graph of saved searches → indexes → sourcetypes → hosts → assets. Computes which MITRE techniques and compliance tags lose coverage and how many other detections share that coverage (the redundancy story).
3. **Cost prediction** — SVC-hour estimate from the proposed SPL. Cloud target: Cisco Deep Time Series Model.
4. **Policy engine** — 12 deterministic rules mapped to NIST AI RMF, OWASP LLM Top 10, EU AI Act Article 14, PCI DSS 10, HIPAA 164.308, SOX, ISO/IEC 42001.
5. **Decision synthesis** — `ALLOW | REQUIRE_APPROVAL | BLOCK`, read **only** from the policy stage. Non-ALLOW persists as a Finding (mock of ES 8 v2 `/findings` API). Fails closed: if the gating stage raises, the verdict is BLOCK with severity=HIGH (regression test: `test_policy_stage_exception_fails_closed`).

The **sixth stage** runs Foundation-Sec-1.1-8B-Instruct as an **advisory Finding-explainer** — it does NOT gate decisions. Its paragraph is attached to the Finding so a human reviewer reads the risk in natural language. Decisions are reproducible from the policy library alone. This is the deterministic-vs-generative thesis: deterministic where audit demands reproducibility, generative where humans demand explanation.

Every verdict, regardless of outcome, fans out to the `agentgate_audit` index via HEC. The bundled dashboard makes it the system of record for AI-agent governance.

See [architecture_diagram.md](architecture_diagram.md) for the full diagram, module map, and deterministic-vs-generative thesis.

## Measured performance

### Decision-path latency (the path EVERY gate decision takes)

| Metric | Value | Source |
|---|---|---|
| Deterministic path p50 | 0.23 ms | `tests/test_latency.py` |
| Deterministic path p95 | 0.56 ms | `tests/test_latency.py` |
| Policy-gate FPR | 0.000 (20 benign tool calls) | `tests/test_pipeline.py` |

### Reasoning-path latency (advisory only — explains the Finding)

| Metric | Value | Source |
|---|---|---|
| Foundation-Sec mean | 9.4 s | `tests/test_latency.py --runslow` |
| Foundation-Sec p50 | 8.2 s | `tests/test_latency.py --runslow` |
| Foundation-Sec max | 13.1 s | `tests/test_latency.py --runslow` |

### Injection-detector quality

Corpus blends hand-curated common patterns, AgentDojo `important_instructions_attacks` templates, and adversarial obfuscation variants (homoglyph, zero-width, leet, payload-split). The corpus is committed in [tests/corpora/](tests/corpora/) — reproducible, not self-graded.

| Metric | Value | Notes |
|---|---|---|
| Precision (in-scope) | 1.000 | 0 false positives on 26 lookalike negatives |
| Recall (in-scope) | 0.971 | 34 / 35 — leet bypass `1gn0r3 4ll pr3v10us` is the documented xfail miss |
| F1 | 0.986 | |
| Specificity | 1.000 | 26 / 26 |
| Out-of-scope passthrough | 8 / 8 | INJECAGENT-style tool-execution hijacking routed to Foundation-Sec semantic stage |

Run with `pytest tests/ -v -s` (full suite, no slow tests) or `pytest tests/ -v -s --runslow` (includes reasoning-path latency).

## Why this matters

The cost of getting AI-agent governance wrong is not hypothetical, and the numbers are public.

- **$4.88M** — global average cost of a data breach in 2024, up 10% year over year, per IBM's *Cost of a Data Breach Report 2024* ([ibm.com/reports/data-breach](https://www.ibm.com/reports/data-breach)). Breaches that took longer to identify and contain cost over **$1M more** on average.
- **Human element involved in 68% of breaches** in 2024 per Verizon's *Data Breach Investigations Report* ([verizon.com/business/resources/reports/dbir/](https://www.verizon.com/business/resources/reports/dbir/)) — the misconfiguration subset of that group is exactly what a misbehaving agent silently disabling a detection rule produces.
- **PCI DSS 10.6** mandates daily review of cardholder-environment logs. A sole-coverage detection silently disabled by an agent is the difference between a noisy alert and a regulator-investigation event.

Real recent incidents in the shape AgentGate guards against:

- **July 2025 — Replit's coding agent destroyed a customer's production database** despite an explicit code freeze instruction, and admitted to it on the next prompt. Widely reported; SaaStr's Jason Lemkin was the customer. POL-004 (destructive primitive) + POL-009 (mutation of system-of-record) would have blocked this pre-execution.
- **CVE-2024-5184** — indirect prompt-injection vulnerability in an open-source LLM agent runtime, on NVD. The OWASP LLM01 family has continued to grow through 2025. POL-006 covers this attack class with measured precision 1.000 on the committed corpus.
- **Splunk's own MCP Telemetry Dashboard (May 2026)** exists because customers are already running production AI agents against Splunk and ASKING for governance visibility. AgentGate is the pre-action half of the same need.

The expensive thing is not building the gate. The expensive thing is not having one.

## Defensible uniqueness statement

> **No other tool combines a Splunk-native pre-action blast-radius walk of the knowledge-object graph with an ES 8 v2 Findings approval artifact** — these two are the durable moat.

Splunk MCP Telemetry Dashboard v1.2 (May 2026) and Splunkbase MCP Watch audit agent activity **after** the action; AgentGate gates it **before**. Cisco DefenseClaw is a generic LLM-proxy firewall: no KO graph, no ES 8 Findings emission, no Splunk-native policy. Microsoft Agent Governance Toolkit is framework-agnostic with zero Splunk integration. Splunk MCP Server 1.2 added coarse tool enable/disable but no per-action blast-radius or approval gate.

Side-by-side prior-art table with citations: [docs/comparison.md](docs/comparison.md).

## Cross-track applicability

While the primary submission is the Security track, the same gate applies to the other two tracks through the existing policy library — no code changes required:

| Track | Policy that already applies | Example tool call gated |
|---|---|---|
| **Security** (primary) | POL-001/002/003/006/009/010 | `propose_disable_saved_search("AG: SQL Injection on Payment App")` → BLOCK |
| **Observability** | POL-008 (mass-change), POL-009 (system-index mutation) | An ITSI agent proposing to rewrite a `summary` index → BLOCK / REQUIRE_APPROVAL |
| **Platform & Developer Experience** | POL-004 (destructive SPL), POL-007 (cost), POL-008 (Excessive Agency) | An MLTK agent proposing `| fit` against `_audit` → BLOCK |

## Standards mapped

- **NIST AI RMF** — GOVERN-1.4 Excessive Agency · MANAGE-2.3 deployment risk · MEASURE-2.7 system performance
- **OWASP LLM Top 10** — LLM01 Prompt Injection · LLM06 Sensitive Info Disclosure · LLM08 Excessive Agency
- **EU AI Act** — Article 14 Human Oversight (this layer IS the human oversight)
- **ISO/IEC 42001** — AI management system requirements
- **PCI DSS 10.6, 10.2.4** — daily review of cardholder-data-environment logs
- **HIPAA 164.308(a)(1)(ii)(D)** — Information System Activity Review
- **SOX** — segregation of duties + audit-log integrity

## Run it

### Requirements

Splunk Enterprise 10.4+ (Developer License or Free Trial), `Splunk MCP Server` (Splunkbase 7931), Python 3.12, Ollama with `Foundation-Sec-8B-Instruct` (or any 8B+ instruct model as fallback). NVIDIA GPU recommended.

### Setup

```powershell
py -3.12 -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt

copy .env.example .env
# Edit .env: paste your Splunk bearer token + MCP encrypted token

python scripts\smoke_test_splunk.py    # SDK auth
python scripts\smoke_test_mcp.py       # MCP tools/list + tools/call
python scripts\smoke_test_ollama.py    # Foundation-Sec inference

python scripts\seed_splunk.py          # indexes, 12 saved searches, 9 KV assets, HEC, sample events
python scripts\install_dashboard.py    # audit dashboard
python scripts\demo.py                 # 4 canonical scenarios
```

### Demo scenarios

1. **Friendly fire** — a cleanup agent proposes to disable `AG: SQL Injection on Payment App`. AgentGate blocks: `host:paymentapp01` has zero redundant coverage and is PCI-tagged. Triggers POL-001 (EU AI Act 14), POL-002 (PCI DSS 10.6), POL-010 (NIST AI RMF MANAGE-2.3).
2. **Prompt injection** — a triage agent reads a poisoned log line containing "ignore all previous instructions...". The injection stage catches override_instruction; POL-006 (OWASP LLM01) blocks.
3. **Happy path** — a reporter bot runs a benign read-only query on `webfront01`. All stages pass in <1 ms.
4. **Require-approval → approved** — a tier-2 analyst proposes a high-redundancy detection tune. AgentGate raises a Finding for review (proves the gate is not just `return BLOCK`).

## What we did NOT validate (the honest gaps)

Per Jeff Wiedemann's framing of "the most likely outcome is compliance blocks production," judges should know exactly which gaps would surface in a real procurement review.

1. **Adversarial red-team coverage is limited.** The leet bypass `1gn0r3 4ll pr3v10us` is a documented xfail. Multilingual obfuscation, payload-splitting beyond zero-width, and base64-smuggling under 120 chars are out of the regex's threat model. Production would pair the heuristic with a semantic check (Foundation-Sec or a small classifier) on the same input.
2. **The KO graph is hand-seeded with 12 saved searches and 9 assets.** Real SOC portfolios are 10k+ saved searches. The parser scales linearly with NetworkX, but graph-walk cost at that scale has not been measured.
3. **The injection corpus is small (35 positives, 26 negatives, 8 out-of-scope).** It includes AgentDojo template variants but is not the full AgentDojo / INJECAGENT runs.
4. **No prospective false-positive rate from real telemetry.** FPR=0.000 is measured against a curated benign-corpus of 20 SPL queries, not a week of real SOC traffic.
5. **No analyst-in-the-loop user study.** The Finding-approval UX is unproven against real shift change-overs.
6. **ES 8 Findings is mocked as a KV collection.** Production needs swap to `POST /public/v2/investigations/{id}/findings`.
7. **Foundation-Sec runs locally via Ollama.** Production needs swap to Splunk Hosted Models (`| ai provider=splunk model=foundation-sec-1.1-8b-instruct`), Splunk Cloud only.

These are the questions a procurement review WILL ask. Naming them is part of the proposal, not a defect.

## Splunk AI capabilities leveraged

The hackathon's resources page names five capability families. AgentGate touches all five — three directly, two indirectly through the MCP gating boundary.

| Capability | Used? | How |
|---|---|---|
| **AI for Splunk Apps** (Python SDK agentic workflows) | Direct | Pipeline built on `splunklib.client` + `splunklib.results` + REST. Splunk app bundle in [`splunk_app/agentgate/`](splunk_app/agentgate/) ships savedsearches.conf, collections.conf, transforms.conf, dashboard XML, app.conf, metadata. |
| **Splunk MCP Server** | Direct | v1.2.0 installed and smoke-tested. Encrypted-token auth. AgentGate sits in front of MCP. |
| **Splunk Hosted Models** (Foundation-Sec) | Direct | Foundation-Sec-1.1-8B-Instruct is the reasoning stage; Ollama on dev license today, swap to `\| ai provider=splunk model=foundation-sec-1.1-8b-instruct` on Cloud. |
| **Splunk AI Assistant (SAIA)** | Indirect | SAIA tools (`saia_generate_spl`, `saia_explain_spl`, `saia_optimize_spl`, `saia_ask_splunk_question`) are exposed through the MCP Server. Any agent that calls them through MCP is gated by AgentGate's five stages. |
| **Splunk AI Toolkit / Cisco DTS** | Indirect | The `\| ai` command and Cisco Deep Time Series Model are the documented production targets for the reasoning and cost stages respectively. Dev license substitutes; one-line swap to Cloud. |

## Bonus prize chase

- **Best Use of Splunk MCP Server** ($1K) — AgentGate sits in front of the MCP server, exercises its tool catalog, and is the natural complement to the read-only MCP surface.
- **Best Use of Splunk Hosted Models** ($1K) — Foundation-Sec-1.1-8B-Instruct on the reasoning stage, demonstrably swappable to the Splunk-hosted invocation in production.
- **Best Use of Splunk Developer Tools** ($1K) — Built on the public `splunk-sdk` Python SDK (`splunklib.client` + `splunklib.results`), the Splunk REST API, KV-store collections, HEC, dashboard XML, and a fully-formed app bundle in `splunk_app/agentgate/` (savedsearches.conf, collections.conf, transforms.conf, dashboard XML, app.conf, metadata).

## Splunk references

Official docs and resources the build aligns to:

- [Splunk MCP Server on Splunkbase (app 7931)](https://splunkbase.splunk.com/app/7931)
- [About MCP Server for Splunk platform](https://help.splunk.com/en/splunk-cloud-platform/mcp-server-for-splunk-platform/1.2/about-mcp-server-for-splunk-platform)
- [Splunk MCP Server: Making Your Apps Agent-Ready](https://community.splunk.com/t5/Product-News-Announcements/GA-Splunk-MCP-Server-Making-Your-Apps-quot-Agent-Ready-quot/ba-p/759935)
- [Foundation-Sec-1.1-8B-Instruct on Hugging Face](https://huggingface.co/fdtn-ai/Foundation-Sec-8B-Instruct)
- [Splunk Hosted Models overview](https://www.splunk.com/en_us/blog/artificial-intelligence/splunk-launches-hosted-generative-ai-models.html)
- [Splunk Python SDK (`splunk-sdk-python`)](https://github.com/splunk/splunk-sdk-python)
- [Splunk Enterprise Security 8 API reference (Findings + Investigations)](https://help.splunk.com/en/splunk-enterprise-security-8/api-reference/8.3/splunk-enterprise-security-api-reference)
- [Splunk Developer Program](https://dev.splunk.com/) (developer license)
- [Splunk Community Slack — #splunk-ai-hackathon](https://splk.it/slack)

## License

Apache 2.0.
