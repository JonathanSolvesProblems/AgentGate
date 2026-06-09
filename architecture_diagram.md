# AgentGate Architecture

Splunk-native pre-action governance + blast-radius layer for AI agents acting on Splunk. Repository root canonical architecture artifact (Devpost-required filename).

## Three planes

```
┌──────────────────────────────────────────────────────────────────────┐
│ AGENT PLANE                                                          │
│   Any LLM agent (Claude, Cursor, splunklib.ai Agent, SOAR playbook)  │
│   issues an MCP tool call against Splunk.                            │
└────────────────────────────────┬─────────────────────────────────────┘
                                 │  ToolCall(agent_id, tool_name, args,
                                 │           raw_user_prompt,
                                 │           incoming_context[])
                                 ▼
┌──────────────────────────────────────────────────────────────────────┐
│ AGENTGATE PIPELINE  (agentgate/middleware/)                          │
│                                                                      │
│   1. injection      heuristic + obfuscation-normalised scan over     │
│                     tool args + incoming_context (logs the agent     │
│                     just read). 11 patterns drawn from OWASP LLM01,  │
│                     AgentDojo templates, Simon Willison's catalogue. │
│                     → severity, hits[]                               │
│                                                                      │
│   2. blast_radius   NetworkX walk of the KO graph                    │
│                     saved_search → references → assets               │
│                     → techniques_lost, compliance_lost,              │
│                       assets_affected (each with redundancy count)   │
│                                                                      │
│   3. cost           SPL cost prediction (SVC-hours)                  │
│                     Cloud target: Cisco Deep Time Series Model       │
│                                                                      │
│   4. reasoning      Foundation-Sec-1.1-8B-Instruct                   │
│                     (Splunk hosted in production, Ollama on dev      │
│                     license). ADVISORY — does NOT gate decisions.    │
│                     Only invoked when prior severity ≥ medium. Its   │
│                     paragraph attaches to the Finding so a human     │
│                     reviewer reads the risk in plain English.        │
│                                                                      │
│   5. policy         Deterministic rule engine over the 12-policy     │
│                     library mapped to NIST AI RMF, OWASP LLM Top 10, │
│                     EU AI Act Art. 14, PCI DSS 10, HIPAA 164.308,    │
│                     SOX, ISO/IEC 42001.                              │
│                                                                      │
│   6. decision       Synthesis: BLOCK > REQUIRE_APPROVAL > ALLOW      │
│                                                                      │
└────────┬─────────────────────────────────┬───────────────────────────┘
         │                                 │
         ▼                                 ▼
┌────────────────────────┐      ┌──────────────────────────────────────┐
│ SPLUNK MCP SERVER      │      │ ES 8 v2 FINDINGS API                 │
│ (read tools — splunk_  │      │  POST /public/v2/investigations/{id}/│
│  run_query, splunk_    │      │       findings                       │
│  get_indexes, …)       │      │  (mocked here as agentgate_findings  │
│ Splunkbase app 7931    │      │   KV collection for the dev license) │
└────────────────────────┘      │  Analyst approves in Splunk UI.      │
                                └──────────────────────────────────────┘

         All decisions, regardless of outcome, fan out to:

┌──────────────────────────────────────────────────────────────────────┐
│ AUDIT INDEX (HEC, sourcetype=agentgate:event)                        │
│   Every gate verdict: stages[], decision, elapsed_ms, finding_id     │
│   Visualised in the AgentGate Audit dashboard inside Splunk Web.     │
└──────────────────────────────────────────────────────────────────────┘
```

## How the app interacts with Splunk

| Surface | How AgentGate uses it |
|---|---|
| Splunk REST `/services/saved/searches` | Reads the saved-search portfolio to build the KO graph. |
| Splunk REST `/servicesNS/.../storage/collections/data/agentgate_assets` | Reads asset criticality + compliance tags from the KV collection. |
| Splunk MCP Server (Splunkbase 7931, v1.2.0) | Read-only tool surface the agent's read calls flow through. |
| HEC (`/services/collector/event`) | Emits every gate verdict to `agentgate_audit` (immutable system of record). |
| KV collection `agentgate_findings` | Persists non-ALLOW verdicts as a mock of ES 8 v2 Findings until ES instance is available. |
| Dashboard `agentgate_audit` | Renders decisions over time, blocks by policy, latency profile, pending findings. |
| Splunkbase-style app bundle `splunk_app/agentgate/` | Ships savedsearches.conf, collections.conf, transforms.conf, dashboard XML for one-shot install. |

## How AI models / agents are integrated

```
                       ┌────────────────────────────────────┐
                       │  Calling agent (LLM via MCP)       │
                       │  Claude / Cursor / splunklib.ai    │
                       └─────────────────┬──────────────────┘
                                         │ tool_call
                                         ▼
┌──────────────────────────────────────────────────────────────────────┐
│ AgentGate pipeline (Python 3.12, splunk-sdk + httpx + NetworkX)      │
│                                                                      │
│  Stages 1-3, 5: pure Python, deterministic, sub-millisecond          │
│                                                                      │
│  Stage 4 (advisory):                                                 │
│     Ollama  --HTTP-->  Foundation-Sec-1.1-8B-Instruct (Q4_K_M GGUF)  │
│     Production path:                                                 │
│        |  Splunk REST  -->  | ai provider=splunk                     │
│                                model=foundation-sec-1.1-8b-instruct  │
│                                                                      │
│  Cost stage (dev): static heuristic                                  │
│  Production:                                                         │
│     | apply CDTSM <fields> time_field=_time                          │
│       forecast_k=128 quantiles="..." conf_interval=95                │
└──────────────────────────────────────────────────────────────────────┘
```

## Data flow

1. Calling agent issues a `ToolCall` (agent_id, tool_name, arguments, raw_user_prompt, incoming_context).
2. Pipeline runs the five evaluators sequentially. Each returns a `StageResult` (severity, elapsed_ms, reasons, details).
3. Decision synthesis picks the strongest action across all matched policies (BLOCK > REQUIRE_APPROVAL > ALLOW).
4. HEC audit emitter POSTs a structured event to `agentgate_audit`.
5. If the decision is non-ALLOW, a Finding is drafted into `agentgate_findings` (status=blocked for BLOCK, status=pending for REQUIRE_APPROVAL).
6. Foundation-Sec reasoning paragraph attaches to the Finding for human reviewers.
7. Audit dashboard surfaces every decision in near-real-time.

## Module map

| Module | Responsibility |
|---|---|
| `agentgate/config.py` | Settings loaded once from `.env` via Pydantic. |
| `agentgate/splunk_client.py` | SDK service + stateless REST helper. |
| `agentgate/models.py` | `ToolCall`, `StageResult`, `GateVerdict`, `Decision`, `Severity`. |
| `agentgate/graph.py` | SPL parser, NetworkX graph builder, `blast_radius()`. |
| `agentgate/policies.py` | 12-policy seed library with standards citations. |
| `agentgate/middleware/injection.py` | 11 patterns + homoglyph/zero-width normalisation. |
| `agentgate/middleware/blast_radius.py` | Graph-driven severity scoring. |
| `agentgate/middleware/cost.py` | SVC-hour prediction (CDTSM target on Cloud). |
| `agentgate/middleware/reasoning.py` | Foundation-Sec-8B via Ollama. Advisory. |
| `agentgate/middleware/policy.py` | Deterministic policy rule engine. |
| `agentgate/middleware/pipeline.py` | Orchestrator + decision synthesis. |
| `agentgate/audit.py` | HEC emitter for the audit index. |
| `agentgate/findings.py` | Persists non-ALLOW verdicts. |
| `scripts/seed_splunk.py` | Provisions indexes, HEC tokens, saved searches, KV assets, sample events. |
| `scripts/install_dashboard.py` | Installs the audit dashboard via REST. |
| `scripts/demo.py` | Four canonical scenarios end-to-end. |
| `scripts/build_app.py` | Packages `splunk_app/agentgate/` as `dist/agentgate.spl`. |
| `splunk_app/agentgate/` | Splunk app bundle (app.conf, savedsearches.conf, collections.conf, transforms.conf, dashboard XML). |

## Deterministic vs generative

| Surface | Mode | Why |
|---|---|---|
| Injection detection | Deterministic | Auditable, fast, publishable precision/recall. |
| KO dependency graph | Deterministic | Reproducible, fits compliance audit. |
| Cost prediction | Deterministic | Math is math. |
| Side-effect explanation | Generative | Reasoning over messy multi-fact context is where LLMs earn their keep. |
| Policy decision | Deterministic | A decision a human can re-derive from the same evidence. |

Generative output never gates a decision — it informs the human who will. This is the thesis.

## Measured performance

### Decision path (every gate decision)

| Metric | Value | Test |
|---|---|---|
| Injection precision (in-scope) | 1.000 (35 positives, AgentDojo + adversarial) | `tests/test_injection.py` |
| Injection recall (in-scope) | 0.971 (34/35, leet bypass xfail) | `tests/test_injection.py` |
| Injection specificity | 1.000 (26 negatives) | `tests/test_injection.py` |
| Out-of-scope passthrough | 8/8 (INJECAGENT-style tool hijacking, routed to reasoning) | `tests/test_injection.py` |
| Policy-gate FPR | 0.000 (20 benign tool calls) | `tests/test_pipeline.py` |
| Deterministic p50 latency | 0.23 ms | `tests/test_latency.py` |
| Deterministic p95 latency | 0.56 ms | `tests/test_latency.py` |

### Reasoning path (advisory, attached to Finding)

| Metric | Value | Test |
|---|---|---|
| Foundation-Sec mean | 9.4 s | `tests/test_latency.py --runslow` |
| Foundation-Sec p50 | 8.2 s | `tests/test_latency.py --runslow` |
| Foundation-Sec max | 13.1 s | `tests/test_latency.py --runslow` |
| Inference throughput | ~30 tok/s on RTX 5060 8 GiB | `scripts/smoke_test_ollama.py` |

## Production path

- Replace Ollama-hosted Foundation-Sec with Splunk Hosted Models (`| ai provider=splunk model=foundation-sec-1.1-8b-instruct`) on Splunk Cloud Platform.
- Replace the cost stage's static heuristic with `| apply CDTSM ...` baselines on Cloud.
- Replace `agentgate_findings` KV with real ES 8 v2 `/public/v2/investigations/{id}/findings`.
- When Splunk MCP custom-tool registration ships, expose the `propose_*` write tools as native MCP tools so any MCP client picks them up automatically.
