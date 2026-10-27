# agent-risk-framework — Roadmap

Companion to rag-attack-lab. Project 1 proves the vulnerabilities; project 2 builds a tool-using LLM agent and defends it, then **measures** how well each defense works.

Framework mapping (primary → secondary → tertiary):
- **OWASP Top 10 for Agentic Applications 2026** (ASI01–ASI10, published 2025-12-09) — primary
- **OWASP Top 10 for LLMs 2026** — secondary (shared vocabulary with rag-attack-lab)
- **OWASP MCP Top 10** (beta, Phase 3) — tertiary, labeled beta
- **MITRE ATLAS** — technique IDs, same as project 1

Stack: Ollama (llama3.1:8b default, llama3.2:3b fast) · custom agent loop (no LangGraph) · tools behind a local **stdio MCP server** · LLM Guard for classifier/output filter · SQLite · Streamlit dashboard · Python 3.12 · offline deterministic tests (fake provider + fake embeddings). $0, local-only, synthetic data only.

Status key: DONE / IN PROGRESS / TODO / BLOCKED / PARKED

---

## Phases

### Phase 0 — Foundation (build the measurement rig before the agent) — TODO, NEXT
Provider abstraction (real Ollama + fake deterministic provider) · attack runner · **deterministic detectors** · findings schema (JSON + markdown) · SQLite run logging · experiment manifests · **benign task set (~50 legit tasks)** · threat model mapped to ASI · offline tests · CI (pytest, ruff, pip-audit).
Gate: tests pass · a run writes to SQLite · a finding is generated · benign set loads · threat model done.

### Phase 1 — Vulnerable agent baseline — TODO
Deliberately over-permissioned local agent · fake tools (search, email, file) **behind a local stdio MCP server** · tool-execution logging · baseline report.
Gate: tools callable · every action logged · runs reproducible · **tool-calling reliability verified on llama3.1:8b in week 1** (kill-switch risk — see Approach §Risks).

### Phase 2 — Attack scenarios — TODO
Prove prompt-to-action escalation. Baseline expectation = **attack succeeds** (undefended). Includes indirect injection via a tool-returned email/file, exfiltration through tool arguments (confused deputy), MCP-specific attacks (poisoned tool description, post-approval rug pull, shadow tool), and obfuscated variants.
Gate: attacks run automatically · findings generated · success metrics recorded over N runs.

### Phase 3 — Guardrail engine — TODO
Prompt classifier **on user input AND tool output** · policy engine · least-privilege tool-permission layer (recipient allowlist, path sandbox) · output filter · approval gate for side effects.
Gate: attacks detected · blocked actions recorded · false positives measurable against the benign set.

### Phase 4 — Defense ablation (the headline) — TODO
Configs: baseline · deterministic-controls-only · classifier-only · output-filter-only · combined.
Gate: attack success rate, detection rate, FPR, FNR, and benign-task completion rate measured for each config.

### Phase 5 — Portfolio release — TODO
README · PDF findings report · threat model · architecture diagram · screenshots · demo recording · publish.
Gate: evidence for every claim · reproducible · public-ready (secret scanning + push protection on, private vuln reporting on, topics added).

---

## Headline target
"Agent guardrail lab: cut attack success from X% to Y% at Z% false-positive cost, with ablation by control layer, mapped to the OWASP Agentic Top 10." A number, not an adjective.
