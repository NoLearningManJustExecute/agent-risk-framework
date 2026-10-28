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

### Phase 0 — Foundation (build the measurement rig before the agent) — DONE
Provider abstraction (real Ollama + fake deterministic provider) · attack runner · **deterministic detectors** · findings schema (JSON + markdown) · SQLite run logging · experiment manifests · **benign task set (~50 legit tasks)** · threat model mapped to ASI · offline tests · CI (pytest, ruff, pip-audit).
Gate: tests pass · a run writes to SQLite · a finding is generated · benign set loads · threat model done.

### Phase 1 — Vulnerable agent baseline — DONE
Deliberately over-permissioned local agent · fake tools (`search_docs`, `send_email`, `read_file`) **behind a local stdio MCP server** · async MCP client + custom agent loop (no LangGraph) · per-step tool-execution logging to the Phase 0 SQLite log (schema v2 `steps` table) · baseline benign report. No guardrails: stated policy, recipient allowlist, and path sandbox are present but **unenforced** (inert data until Phase 3).
Gate: tools callable (in-process and real stdio) · every step logged with raw args + result · runs reproducible at fixed seed/temperature · **tool-calling reliability verified on llama3.1:8b: 20/20 (100%) well-formed, correctly-routed calls, native tool-calling, seed 1337, temp 0** (kill-switch cleared; llama3.2:3b reference 19/20 native, 17/20 prompted-JSON).
Deliberate weaknesses, mapped: unenforced recipient allowlist and un-sandboxed `read_file` path (ASI02, ASI03, LLM03:2026, MCP02:2025); canary in the system prompt (ASI01, LLM08:2026); step cap bounds runaway loops (ASI08, LLM06:2026). Details in `docs/phase1_agent.md`.

### Phase 2 — Attack scenarios — DONE
Prove prompt-to-action escalation. Baseline expectation = **attack succeeds** (undefended). Includes indirect injection via a tool-returned email/file, exfiltration through tool arguments (confused deputy), MCP-specific attacks (poisoned tool description, post-approval rug pull, shadow tool), and obfuscated variants.
Gate: attacks run automatically · findings generated · success metrics recorded over N runs.
Result: 13 cases (AC01–AC11, AC12A rug pull, AC12B shadow tool) × plain + obfuscated = 26 scenarios, each run in a throwaway synthetic lab and scored by deterministic oracles against the tool-call log (schema v3 `verdicts` table). At N=10, `llama3.1:8b`, temp 0: **attack success 160/260 (62%)** with 0 errors; plain 80/130, obfuscated 80/130. Direct and MCP-definition attacks succeed in 9 of 13 cases; both indirect-injection cases (AC09, AC10), AC03 and AC08 did not succeed at baseline (reported as measured). Benign set, two separate measures: **task success 90/120 (75%)**, **benign-input violation 20/120 (17%)**. 9 findings (ARF-0201…0213). Caveat: at temp 0 the 10 runs per case are near-identical, so N shows reproducibility, not spread. Details in `docs/phase2_attacks.md`.

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
