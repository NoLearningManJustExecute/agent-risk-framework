# agent-risk-framework

A local, offline lab that builds a tool-using LLM agent, attacks it, and **measures**
how much each layer of defense actually buys, and what it costs in false positives.

Defense companion to [rag-attack-lab](https://github.com/NoLearningManJustExecute/rag-attack-lab):
that project demonstrates RAG weaknesses; this one measures defenses for agents.

> **Status: Phase 0 (measurement rig).** The agent, attack cases, and guardrails come
> in later phases. See [ROADMAP.md](ROADMAP.md).

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
