# AgentGate Architecture

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
│   1. injection      heuristic prompt-injection scan over tool args   │
│                     + incoming_context (logs the agent just read)    │
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
│   4. reasoning      Foundation-Sec-8B (Splunk hosted, or Ollama      │
│                     local). ADVISORY — it does NOT gate decisions.   │
│                     Only invoked when prior severity ≥ medium. Its   │
│                     paragraph attaches to the Finding so a human     │
│                     reviewer reads the risk in plain English.        │
│                                                                      │
│   5. policy         Deterministic rule engine over the 12-policy     │
│                     library mapped to NIST AI RMF, OWASP LLM Top 10, │
│                     EU AI Act Art. 14, PCI DSS 10, HIPAA, SOX, ISO   │
│                     42001.                                           │
│                                                                      │
│   6. decision       Synthesis: BLOCK > REQUIRE_APPROVAL > ALLOW      │
│                                                                      │
└────────┬─────────────────────────────────┬───────────────────────────┘
         │                                 │
         ▼                                 ▼
┌────────────────────────┐      ┌──────────────────────────────────────┐
│ SPLUNK MCP SERVER      │      │ ES 8 v2 FINDINGS API (mocked here    │
│ (read tools only —     │      │  as agentgate_findings KV)           │
│  splunk_run_query,     │      │  POST /investigations/{id}/findings  │
│  splunk_get_indexes,…) │      │  Analyst approves in Splunk UI.      │
└────────────────────────┘      └──────────────────────────────────────┘

         All decisions, regardless of outcome, fan out to:

┌──────────────────────────────────────────────────────────────────────┐
│ AUDIT INDEX (HEC, sourcetype=agentgate:event)                        │
│   Every gate verdict: stages[], decision, elapsed_ms, finding_id     │
│   Visualised in the AgentGate Audit dashboard.                       │
└──────────────────────────────────────────────────────────────────────┘
```

## Module map

| Module | Responsibility |
|---|---|
| `agentgate/config.py` | Settings loaded once from `.env` via Pydantic. |
| `agentgate/splunk_client.py` | Singleton SDK service + REST helper. |
| `agentgate/models.py` | `ToolCall`, `StageResult`, `GateVerdict`, `Decision`, `Severity`, `Policy`. |
| `agentgate/graph.py` | SPL parser, NetworkX graph builder, `blast_radius()`. |
| `agentgate/policies.py` | The 12-policy seed library with standards citations. |
| `agentgate/middleware/injection.py` | 11 heuristic patterns. |
| `agentgate/middleware/blast_radius.py` | Graph-driven severity scoring. |
| `agentgate/middleware/cost.py` | SVC-hour prediction (static; CDTSM on Cloud). |
| `agentgate/middleware/reasoning.py` | Foundation-Sec-8B via Ollama. |
| `agentgate/middleware/policy.py` | Deterministic policy rule engine. |
| `agentgate/middleware/pipeline.py` | Orchestrator + decision synthesis. |
| `agentgate/audit.py` | HEC emitter for the audit index. |
| `agentgate/findings.py` | Persists non-ALLOW verdicts as Findings in the KV collection. |
| `scripts/seed_splunk.py` | Provisions indexes, HEC, 12 saved searches, KV assets, sample events. |
| `scripts/install_dashboard.py` | Installs the audit dashboard via REST. |
| `scripts/demo.py` | Runs the three canonical scenarios end-to-end. |
| `splunk_app/agentgate/` | Splunk app bundle (app.conf, dashboard, collections, transforms). |

## Deterministic vs generative

| Surface | Mode | Why |
|---|---|---|
| Injection detection | Deterministic | Auditable, fast, publishable precision/recall. |
| KO dependency graph | Deterministic | Reproducible, fits compliance audit. |
| Cost prediction | Deterministic | Math is math. |
| Side-effect explanation | Generative | Reasoning over messy multi-fact context is where LLMs earn their keep. |
| Policy decision | Deterministic | A decision a human can re-derive from the same evidence. |

Generative output never gates a decision. It informs the analyst who will.

## Data flow

1. Agent issues a `ToolCall`.
2. Pipeline runs five evaluators sequentially. Each returns a `StageResult` with severity, elapsed time, and structured details.
3. Decision synthesis chooses ALLOW / REQUIRE_APPROVAL / BLOCK by picking the strongest action across all matched policies.
4. HEC audit emitter writes a structured event to `agentgate_audit`.
5. If the decision is non-ALLOW, a Finding is drafted into `agentgate_findings` (mock for ES 8 v2 `/findings`).
6. The audit dashboard displays decisions over time, blocks by policy, agent decision mix, stage latency profile, and the pending-findings queue.

## Performance (measured)

### Decision path (every gate decision)

| Metric | Value | Test |
|---|---|---|
| Injection precision (in-scope) | 1.000 (35 positives, AgentDojo + adversarial) | `tests/test_injection.py` |
| Injection recall (in-scope) | 0.971 (34/35, leet bypass xfail) | `tests/test_injection.py` |
| Injection specificity | 1.000 (26 negatives) | `tests/test_injection.py` |
| Out-of-scope passthrough | 8/8 (INJECAGENT-style tool hijacking) | `tests/test_injection.py` |
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

The reasoning stage is **advisory**, not gate-deciding. Its output explains the Finding to a human reviewer; the BLOCK / REQUIRE_APPROVAL / ALLOW verdict is produced entirely by the deterministic policy engine. This separation means the latency that matters for the gate decision is sub-millisecond, while the slower semantic explanation runs in parallel with the analyst's notification.

## Production path

- Replace Ollama-hosted Foundation-Sec with Splunk Hosted Models (`| ai provider=splunk model=foundation-sec-1.1-8b-instruct`) on Splunk Cloud Platform.
- Replace the cost stage's static heuristic with `| apply CDTSM ...` baselines on Cloud.
- Replace `agentgate_findings` KV with real ES 8 v2 `/public/v2/investigations/{id}/findings`.
- When Splunk MCP custom-tool registration ships, expose the `propose_*` write tools as native MCP tools so any MCP client picks them up automatically.
