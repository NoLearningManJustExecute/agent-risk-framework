# agent-risk-framework

A local, offline lab that builds a tool-using LLM agent, attacks it, and **measures**
how much each layer of defense actually buys, and what it costs in false positives.

Defense companion to [rag-attack-lab](https://github.com/NoLearningManJustExecute/rag-attack-lab):
that project demonstrates RAG weaknesses; this one measures defenses for agents.

> **Status: Phase 4 (defense ablation).** The measurement rig (Phase 0), the
> deliberately vulnerable agent (Phase 1), the attack set with its baseline numbers
> (Phase 2), six independently switchable guardrails with a decision log (Phase 3 and
> 3.5) and the ablation that measures them (Phase 4) are built. Headline: **attack
> success 67% → 0% with all six controls, at a 17% false-positive rate; benign task
> success 91% → 81%**. See [ROADMAP.md](ROADMAP.md).

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
| Benign task set with deterministic success criteria (stub, 13 of ~50) | `data/benign_tasks.json` |
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

## What's in Phase 2

Thirteen attack cases, each in a plain and an obfuscated variant, run against the
undefended agent: direct prompts, **indirect injection through tool-returned
content**, **exfiltration through tool arguments**, and MCP attacks (**poisoned tool
description, post-approval rug pull, shadow tool**). Each run gets a throwaway
synthetic lab and is scored by a deterministic oracle against the tool-call log
(no LLM judge). The benign set is scored as two separate measures, task success and
benign-input violation.

| Piece | Location |
| --- | --- |
| Attack cases + scenarios (framework mapping, payloads, oracle per scenario) | `data/attack_scenarios.json`, `src/agent_risk_framework/attacks/scenarios.py` |
| Per-run lab, harness containment, MCP mutations (poisoned tool, rug pull, shadow tool) | `src/agent_risk_framework/attacks/lab.py` |
| Deterministic oracles over the step log; benign task success and violation | `src/agent_risk_framework/attacks/oracles.py` |
| N-run experiment runner, findings, markdown report | `src/agent_risk_framework/attacks/runner.py`, `configs/experiments/phase2_baseline.yaml` |
| Run log schema v3 (`verdicts` table, benign-input violation rate) | `src/agent_risk_framework/runlog/` |
| Design, results and caveats · generated results · findings | `docs/phase2_attacks.md`, `docs/phase2_results.md`, `findings/` |

Baseline (`llama3.1:8b`, temp 0, N=10 per case): **attack success 160/260 (62%)**,
benign **task success 90/120 (75%)**, **benign-input violation 20/120 (17%)**. At
temperature 0 the 10 runs per case are near-identical, so N shows reproducibility
rather than spread; see [docs/phase2_attacks.md](docs/phase2_attacks.md).

```bash
python -m agent_risk_framework.attacks.runner --db runs/phase2.db --findings-dir findings --report docs/phase2_results.md
```

## What's in Phase 3

Five guardrails, each an independent on/off switch, built for where Phase 2 showed
this model actually breaks: direct prompts and MCP tool definitions. Every control
logs every decision (allow or block) to the run log, and every run is scored into
one outcome bucket (`succeeded`, `blocked_by_control`, `did_not_execute`,
`failed_other`) that records which control gets the credit.

| Control | What it does | Targets |
| --- | --- | --- |
| `tool_permissions` | Recipient allowlist on any recipient argument (strict, fails closed); `read_file` sandboxed to the workspace, secret store denied | AC01, AC02 |
| `tool_integrity` | Vets tool descriptions, pins definitions at approval against a reviewed registry, quarantines drift (rug pull), late and shadow tools | AC11, AC12A, AC12B |
| `approval_gate` | State-changing calls need approval rendered from the real call; a deterministic simulated reviewer approves | AC07, unrequested sends on benign input |
| `input_classifier` | Rule-based injection/override/leak classifier on the user prompt | AC05 (and AC04) |
| `output_classifier` | The same rules on tool output. Defense in depth only: this model ignored tool-output injection at baseline (AC09/AC10 0/20) | AC09, AC10 |
| `egress_filter` (Phase 3.5) | Secret/PII filter: blocks a call whose arguments carry a canary, secret-store value or secret-shaped string; redacts secrets in tool output before the model reads it. Maps to LLM02:2026 | AC03, AC10, AC12A |

| Piece | Location |
| --- | --- |
| Controls, switches and presets, engine | `src/agent_risk_framework/guardrails/` |
| Outcome buckets and control credit | `src/agent_risk_framework/attacks/attribution.py` |
| Run log schema v4 (`decisions`, `attributions`, `run_controls`); v5 widens the enum lists for Phase 3.5 | `src/agent_risk_framework/runlog/` |
| Reviewed tool registry (SHA-256 pins) | `configs/tool_registry.json` |
| Design, decision-log format, scoring rules, isolation tests, smoke run | `docs/phase3_guardrails.md` |
| Egress filter: what it inspects, credit rule, overlap with the permission layer | `docs/phase3_5_egress.md` |

Offline tests prove that each control, switched on alone, blocks its target attack
and does **not** block the matching benign task. A live N=1 wiring check under all
five controls: **0/24 attacks succeeded**, 21 were blocked and credited, and **0/13
benign tasks were blocked**. Rates come from the Phase 4 ablation. AC08 left the
attack set: it is benign task BT-013, scored by `benign_input_violation`.

```bash
python -m agent_risk_framework.attacks.runner --manifest configs/experiments/phase3_combined_smoke.yaml --db runs/phase3-smoke.db
```

## What's in Phase 4

The defense ablation:
- **Arms.** Eight: `baseline`, each of the six controls alone, and `combined`.
- **Cases.** The 24 attack scenarios, plus a benign set grown first to 45 tasks, 30 of
  them adversarial-looking but legitimate.
- **Runs.** N=10 per case per arm on `llama3.1:8b` at temperature 0: 5,520 runs,
  0 errors.

The chart and the full table in
[docs/phase4_ablation.md](docs/phase4_ablation.md) are generated from the run log;
the summary below is copied from that table.

![Attack success, false-positive rate and task success per arm](docs/phase4_ablation.svg)

| Arm | Attack success | False-positive rate | Benign task success |
| --- | --- | --- | --- |
| `baseline` | 160/240 (67%) | 0/450 (0%) | 410/450 (91%) |
| `tool_permissions` | 50/240 (21%) | 10/450 (2%) | 410/450 (91%) |
| `tool_integrity` | 110/240 (46%) | 0/450 (0%) | 410/450 (91%) |
| `approval_gate` | 70/240 (29%) | 39/450 (9%) | 409/450 (91%) |
| `input_classifier` | 110/240 (46%) | 40/450 (9%) | 370/450 (82%) |
| `output_classifier` | 160/240 (67%) | 0/450 (0%) | 410/450 (91%) |
| `egress_filter` | 150/240 (62%) | 0/450 (0%) | 410/450 (91%) |
| `combined` | 0/240 (0%) | 75/450 (17%) | 365/450 (81%) |

What the numbers say:
- **Most value.** `tool_permissions` buys the most, at the lowest cost.
- **Only benign losses.** `input_classifier` is the only control that loses
  legitimate work: its four pinned false positives.
- **No demonstrated effect.**
  - `output_classifier`'s credit is interception on cases this model never fell for.
  - `egress_filter` stops one case alone, and `combined` pre-empts it.
- **N measures repeatability.** At temperature 0 each case repeats identically, so
  N=10 shows repeatability, not spread.

The full table also has detection, FNR, violations, latency, buckets, credit by
basis, per-scenario and per-task detail. It is in
[docs/phase4_ablation.md](docs/phase4_ablation.md), with the findings.

```bash
python -m agent_risk_framework.attacks.ablation --manifest configs/experiments/phase4_ablation.yaml --db runs/phase4.db
python -m agent_risk_framework.attacks.ablation_report --db runs/phase4.db
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
