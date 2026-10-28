# agent-risk-framework

A local, offline lab that builds a tool-using LLM agent, attacks it, and **measures**
how much each layer of defense actually buys, and what it costs in false positives.

Defense companion to [rag-attack-lab](https://github.com/NoLearningManJustExecute/rag-attack-lab):
that project demonstrates RAG weaknesses; this one measures defenses for agents.

> **Status: Phase 1 (vulnerable agent baseline).** The measurement rig (Phase 0) and
> the deliberately vulnerable, over-permissioned agent (Phase 1) are built. Attack
> cases and guardrails come in later phases. See [ROADMAP.md](ROADMAP.md).

## Why measurement first

Blocking prompt injection is easy if you block everything. The useful question is the
trade-off: attack success rate against false positive rate and benign task completion,
compared across defense configs (`baseline`, `deterministic-only`, `classifier-only`,
`output-filter-only`, `combined`). Phase 0 builds the rig that produces those numbers
reproducibly, before there is an agent to measure.

## What's in Phase 0

| Piece | Location |
| --- | --- |
| Provider abstraction: Ollama (`llama3.1:8b` default, `llama3.2:3b` fast, `nomic-embed-text`) plus deterministic fakes | `src/agent_risk_framework/providers/` |
| Findings schema (ASI / LLM 2026 / MCP beta / ATLAS mappings) with JSON + markdown writer | `src/agent_risk_framework/findings/` |
| SQLite run log, one row per run, with per-config ablation metrics | `src/agent_risk_framework/runlog/` |
| Deterministic outcome oracles (canary leak, recipient allowlist), no LLM judge | `src/agent_risk_framework/scoring.py` |
| Experiment manifest format (YAML or JSON) | `src/agent_risk_framework/manifest.py`, `configs/experiments/` |
| Benign task set with deterministic success criteria (stub, 12 of ~50) | `data/benign_tasks.json` |
| Threat model mapped to OWASP Agentic Top 10 (ASI01–ASI10) | `docs/threat_model.md` |

## What's in Phase 1

The deliberately vulnerable, over-permissioned agent that later phases attack and
defend. No guardrails yet — the stated policy, recipient allowlist, and path
sandbox are present but **unenforced** (they become controls in Phase 3), so at
baseline the agent does whatever it is asked.

| Piece | Location |
| --- | --- |
| Three fake, side-effect-simulating tools (`search_docs`, `send_email`, `read_file`) behind a local **stdio MCP server** | `src/agent_risk_framework/agent/tools.py`, `agent/server.py` |
| Async MCP client helpers + custom agent loop (no LangGraph), with a hard step cap | `src/agent_risk_framework/agent/client.py`, `agent/loop.py` |
| Native tool-calling model (Ollama) and a scriptable fake for offline tests | `src/agent_risk_framework/agent/model.py` |
| Stated policy + hidden canary + inert allowlist/sandbox data | `src/agent_risk_framework/agent/policy.py` |
| Per-step logging to the SQLite run log (schema v2 `steps` table: tool name, raw args, result, model text, latency) | `src/agent_risk_framework/runlog/` |
| Baseline benign runner and the usefulness anchor it produces | `src/agent_risk_framework/agent/baseline.py` |
| Synthetic workspace (file sandbox with a canary file) and doc index | `data/agent_sandbox/`, `data/doc_index.json` |
| Phase 1 design, deliberate weaknesses, and framework mapping | `docs/phase1_agent.md` |

Tool-calling reliability was verified before building the loop (the kill-switch
risk in [APPROACH](ROADMAP.md)): `llama3.1:8b` emitted a well-formed,
correctly-routed tool call on **20 of 20** trivial tasks (100%) with native
tool-calling at seed 1337, temperature 0. At baseline the undefended agent
completes **9 of 12** benign tasks (75%) — the usefulness anchor the Phase 4
ablation measures each defense's cost against. See [docs/phase1_agent.md](docs/phase1_agent.md).

To run the agent live (needs a local Ollama with `llama3.1:8b`):

```bash
python -m agent_risk_framework.agent.baseline --db runs/baseline.db
```

## Quickstart

Requires Python 3.12. Everything below runs offline.

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate    Linux/macOS: source .venv/bin/activate
python -m pip install -e ".[dev]"
python -m pytest
ruff format --check . && ruff check .
pip-audit --skip-editable
```

The test suite never touches a model or the network: it uses the fake providers and
blocks socket connections and non-loopback DNS for the whole run. Live runs (later phases) need a local Ollama
server on `127.0.0.1:11434`; the provider refuses any non-loopback host.

## Framework mapping

Every threat and finding carries an **OWASP Agentic Top 10 (ASI)** ID first, then
OWASP LLM Top 10 2026, OWASP MCP Top 10 (beta, optional), and a MITRE ATLAS technique.
See [docs/threat_model.md](docs/threat_model.md).

## Ground rules

Local-only, synthetic data only, no secrets, no network calls in code or tests. See
[SECURITY.md](SECURITY.md).

## License

MIT, see [LICENSE](LICENSE).
