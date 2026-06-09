# AgentGate vs adjacent products

A cited side-by-side against everything in this space that shipped on or before 2026-06-09. The moat is intentionally narrow: a **Splunk-native pre-action gate** that combines a **knowledge-object dependency graph blast-radius walk** with an **ES 8 v2 Findings approval artifact** and a **deterministic verdict path**. Nothing below matches that combination.

## Capability matrix

| Capability | **AgentGate** | Splunk MCP Telemetry Dashboard v1.2 | Splunkbase MCP Watch | Cisco DefenseClaw 0.7.x | Microsoft Agent Governance Toolkit | Splunk MCP Server 1.2 native |
|---|---|---|---|---|---|---|
| **Pre-action enforcement** (gates the call before execution) | **Yes** | No (post-hoc audit) | No (post-hoc flag) | Partial (block on HIGH/CRITICAL after observation) | No (logs only) | Coarse (tool enable/disable) |
| **KO dependency-graph blast radius** (per-asset redundancy, MITRE technique loss, compliance-tag loss) | **Yes** | No | No | No | No | No |
| **ES 8 v2 Findings as approval artifact** | **Yes** (mock; production swap is one file) | No | No | No | No | No |
| **Splunk-native HEC audit trail** | **Yes** | Yes (own surface) | Yes | Optional forwarder | No (generic) | Telemetry only |
| **Policy library mapped to named standards** | **Yes** (NIST AI RMF, OWASP LLM Top 10, PCI DSS 10.6, HIPAA 164.308, SOX, ISO 42001, EU AI Act 14) | No | Anti-pattern rules only | OWASP LLM Top 10 | OWASP Agentic Top 10 | No |
| **Deterministic verdict path (LLM never gates)** | **Yes** (`_decide()` reads only the policy stage) | n/a | n/a | LLM-assisted | LLM-assisted | n/a |
| **Security-tuned reasoning attached to the Finding** | **Yes** (Foundation-Sec-8B, advisory) | No | No | Generic LLM | Generic LLM | No |
| **Splunk-shipped (no install if customer is already on Splunk)** | Splunk app bundled (`.spl`) | **Yes** | Yes (Splunkbase) | No (external sidecar) | No | **Yes** |
| **Open source** | Apache 2.0 | Proprietary | Mixed | Apache 2.0 | MIT | Proprietary |

## What each adjacent product is and is not

### Splunk MCP Telemetry Dashboard v1.2 (Splunk, May 2026)

Bundled with Splunk MCP Server 1.2 GA. Audits agent activity that has already executed — tool-call counts, timing, success rate, per-token usage. **Validates the visibility half of the problem.** Does not gate, does not blast-radius, does not emit ES 8 Findings. Complementary to AgentGate, not a competitor.

### Splunkbase MCP Watch (third-party, Splunkbase app 8765)

Flags "anti-pattern" MCP calls after they happen — e.g. a tool call referencing too many indexes, a `delete` primitive, a missing time filter. Rule-based, no graph, no compliance mapping, no pre-action enforcement. Useful complement; AgentGate's gating layer would prevent the patterns MCP Watch catches retroactively.

### Cisco DefenseClaw (open source, currently 0.7.x as of June 2026)

Go-based sidecar that intercepts prompts / completions / tool calls and forwards them to a SIEM via HEC. Has block / allow mode but: no Splunk knowledge-object graph, no ES 8 Findings, no Splunk-native policy library, no per-asset redundancy. Generic LLM-proxy firewall. Architecturally a different category — it sits at the LLM API boundary, not the Splunk MCP boundary.

### Microsoft Agent Governance Toolkit (open source)

Framework-agnostic policy enforcement for LangChain / AutoGen / CrewAI. Zero Splunk integration. Zero blast-radius. Zero compliance tag walk. The OWASP Agentic Top 10 coverage is the only overlap and it is generic.

### Splunk MCP Server 1.2 native

The MCP server itself can be configured to enable/disable individual tools globally. That is coarse-grained (all-or-nothing per tool) and does not consider the per-call argument shape, the blast-radius of the action, or compliance mapping. AgentGate sits in front of MCP Server, takes the tool call, and runs a per-call decision.

## Where AgentGate intentionally does **not** compete

- **Tool-execution hijacking via legitimate-looking actions** (e.g. INJECAGENT "Please unlock my front door" patterns). Out of the heuristic threat model. Routed to the advisory Foundation-Sec stage in production. Documented in the README's "What we did NOT validate" section and asserted in `tests/test_injection.py::test_out_of_scope_intentionally_missed`.
- **Post-incident forensic timelines.** Splunk ES handles that.
- **Generic LLM observability** (Traceloop / OpenLLMetry / etc.). That layer is the upstream telemetry; AgentGate is the downstream gate that consumes its decisions.

## Sources

- Splunk MCP Server 1.2 release notes: https://help.splunk.com/en/splunk-cloud-platform/mcp-server-for-splunk-platform/1.2/release-notes
- MCP Telemetry Dashboard documentation: https://help.splunk.com/en/splunk-cloud-platform/mcp-server-for-splunk-platform/1.2/mcp-telemetry-dashboard
- Splunkbase MCP Watch app page: https://splunkbase.splunk.com/app/8765
- Cisco DefenseClaw repo: https://github.com/cisco-ai-defense/defenseclaw
- Microsoft Agent Governance Toolkit: https://github.com/microsoft/agent-governance-toolkit
- AgentGate verdict path: [`agentgate/middleware/pipeline.py`](../agentgate/middleware/pipeline.py) (`_decide()` reads only the policy stage; gating-stage exceptions fail closed via the `GATING_STAGE` constant)
- AgentGate ES 8 Findings shape: [`agentgate/findings.py`](../agentgate/findings.py)
