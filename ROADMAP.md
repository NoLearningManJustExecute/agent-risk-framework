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

### Phase 3 — Guardrail engine — DONE
Prompt classifier **on user input AND tool output** · policy engine · least-privilege tool-permission layer (recipient allowlist, path sandbox) · output filter · approval gate for side effects.
Gate: attacks detected · blocked actions recorded · false positives measurable against the benign set.
Result: five controls, each an independent switch, built to the Phase 2 results (direct and MCP-definition attacks are the targets; tool-output injection scored 0/20):
- `tool_permissions`: strict recipient allowlist, workspace path sandbox, secret store denied.
- `tool_integrity`: vets descriptions, pins them at approval against a reviewed registry, and quarantines drifted, late and shadow tools.
- `approval_gate`: approval rendered from the real call; a deterministic simulated reviewer approves.
- `input_classifier` and `output_classifier`: a rule-based classifier on the user prompt and, as defense in depth, on tool output.

Every evaluation goes to a decision log (schema v4 `decisions`). Every run gets an outcome bucket (`succeeded` / `blocked_by_control` / `did_not_execute` / `failed_other`) that records which control gets the credit (`attributions`), with a counterfactual check for blocked calls. AC08 moved to the benign set as BT-013.

Verification: in offline isolation tests, each control alone blocks its target cases and none blocks a benign task. In a live N=1 wiring check with all controls on, 0/24 attacks succeeded and 0/13 benign tasks were blocked.

Deviations from the plan: a rule-based classifier replaces LLM Guard, and the canary output filter was replaced by denying the secret store plus a leak-request rule. Details in `docs/phase3_guardrails.md`.

### Phase 3.5 — Egress filter — DONE
The output-filter arm had no baseline target (AC09/AC10 0/20), so a sixth control was added: `egress_filter`, a secret/PII filter on outbound tool arguments (call blocked) and on tool output (secrets redacted before the model reads it). It maps to LLM02:2026 and targets AC03, AC10 and AC12A. It is independent of `tool_permissions` and overlaps it on secret-read cases. A redaction earns credit only through a counterfactual (`output_redacted`: the model carried the placeholder, and putting the secret back makes the objective happen). Offline isolation tests: alone, it blocks all six target scenarios and no benign task. Details in `docs/phase3_5_egress.md`.

### Phase 4 — Defense ablation (the headline) — DONE
Arms: baseline, each of the six controls alone, and combined. Report rates from the locked Phase 3 outcome buckets, and read `input_withheld` credit against each case's baseline rate.
Gate: attack success rate, detection rate, FPR, FNR, and benign-task completion rate measured for each config.
Result:
- **Setup.** The benign set grew from 13 to 45 tasks (30 hard negatives) before the run. Then: 8 arms × (24 attack scenarios + 45 benign tasks) × N=10, `llama3.1:8b`, temp 0. That is 5,520 runs, 0 errors.
- **Headline.** **Attack success went from 160/240 (67%) at baseline to 0/240 (0%) combined. The FPR was 75/450 (17%), and task success fell from 410/450 (91%) to 365/450 (81%).**
- **Per control.** `tool_permissions` bought the most: −46 pp at 2% FPR with no benign task lost. Per control, the architectural controls beat content inspection. `input_classifier` was the only control that lost benign work: exactly its four pinned false positives, 40 runs.
- **Honest zeros.**
  - `output_classifier`'s 40 credits are interception on cases that score 0% at baseline (0 pp).
  - `egress_filter` stopped only AC12A alone (−4 pp), and `combined` pre-empts it entirely.
  - At temp 0 each case is 10/10 or 0/10, so N=10 shows repeatability, not spread.

The table and chart are generated from the run log. Details in `docs/phase4_ablation.md`.

### Phase 5 — Portfolio release — TODO
README · PDF findings report · threat model · architecture diagram · screenshots · demo recording · publish.
Gate: evidence for every claim · reproducible · public-ready (secret scanning + push protection on, private vuln reporting on, topics added).

---

## Headline target
"Agent guardrail lab: cut attack success from X% to Y% at Z% false-positive cost, with ablation by control layer, mapped to the OWASP Agentic Top 10." A number, not an adjective.

Measured in Phase 4: from 67% to 0% at a 17% false-positive rate. Benign task success fell from 91% to 81% (`llama3.1:8b`, N=10, 24 attack scenarios, 45 benign tasks).
