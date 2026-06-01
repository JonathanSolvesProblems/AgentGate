# AgentGate

Splunk-native pre-action governance and blast-radius control layer for AI agents acting on Splunk.

Entry for the [Splunk Agentic Ops Hackathon](https://splunk.devpost.com/) (deadline 2026-06-15).

## What it does

AgentGate intercepts every tool call an AI agent makes against Splunk and runs a six-stage decision pipeline before allowing the action:

1. **Prompt-injection check** via `splunklib.ai.detect_injection` on tool inputs
2. **Static blast-radius walk** of the Splunk knowledge object graph (savedsearches, datamodels, dashboards, ES correlation rules)
3. **Cost prediction** using historical job inspector data + Cisco Deep Time Series Model baselines
4. **Side-effect reasoning** via Foundation-Sec-1.1-8B (security-tuned hosted model)
5. **Policy rule engine** mapping to NIST AI RMF, OWASP LLM Top 10, EU AI Act Article 14
6. **Decision** — allow, block, or queue as an ES 8 Investigation Finding for human approval

Every decision is written back to a Splunk audit index via HEC, giving compliance teams a single pane for every agent action ever taken.

## Architecture

See [`docs/architecture.md`](docs/architecture.md).

## Setup

Requires Python 3.12, Splunk Enterprise 10.x (Developer License or Free Trial), Ollama (for local Foundation-Sec inference on dev license), and the Splunk MCP Server app installed in Splunk.

```powershell
py -3.12 -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
# edit .env, paste your Splunk bearer token
python scripts\smoke_test_splunk.py
```

## Track + bonus prizes

- **Track**: Security primary, framed for Grand Prize
- **Bonus prize chase**: Splunk MCP Server, Splunk Hosted Models (Foundation-Sec), Splunk Developer Tools (`splunklib.ai`)

## Defensible uniqueness statement

No other tool combines pre-action blast-radius preview, prompt-injection-aware tool interception via `splunklib.ai`, Splunk-native policy enforcement, ES 8 v2 Findings as the analyst approval artifact, security-tuned reasoning with Foundation-Sec-1.1-8B, and a full agent audit trail in Splunk's own indexes.

## License

Apache 2.0.
