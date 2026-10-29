# Threat Model

Status: Phase 0 draft, controls updated in Phase 3. It covers the agent that
Phases 1-3 built, so the measurement rig, attack cases, and controls all trace back
to one document.

## 1. System overview

A single tool-using LLM agent runs entirely on one machine:

```
 user ──► agent loop ──► local model (Ollama, loopback only)
              │
              └──► local stdio MCP server ──► fake tools: search_docs, read_file, send_email
                                                   │
                                                   └──► synthetic data: mailbox, file sandbox, doc index
```

Defense layers (Phase 3) sit between these components and are switched on or off
per experiment config: `baseline`, `deterministic-only`, `classifier-only`,
`output-filter-only`, `combined`. The measurement rig (Phase 0) logs every run to
SQLite and scores outcomes with deterministic oracles, so no LLM judge is involved.
A run's `outcome` (did the objective happen?) comes from the oracles; what the
defenses flagged or blocked is logged separately.

## 2. Framework mapping conventions

| Order | Framework | ID format | Notes |
| --- | --- | --- | --- |
| Primary | OWASP Top 10 for Agentic Applications 2026 | `ASI01`-`ASI10` | Required on every threat and finding |
| Secondary | OWASP Top 10 for LLM Applications 2026 | `LLM01:2026`-`LLM10:2026` | Same vocabulary as rag-attack-lab |
| Tertiary | OWASP MCP Top 10 (**beta**) | `MCP01:2025`-`MCP10:2025` | Optional; beta IDs may be renumbered |
| Techniques | MITRE ATLAS (content release 2026.09) | `AML.Txxxx[.yyy]` | Required on every finding |

A threat may map to several IDs per framework; a finding carries one primary ID per
framework (ASI, LLM, and ATLAS required; MCP when applicable) and names any
secondary IDs in its description.

Verification status: verified in Phase 5 against the official OWASP document, "OWASP
Top 10 for LLM Applications 2026", Version 2026, August 4th, 2026 (genai.owasp.org).
Every ID used here matches its 2026 title:
- `LLM01` Prompt Injection
- `LLM02` Sensitive Information Disclosure
- `LLM03` Excessive Agency
- `LLM04` Supply Chain
- `LLM06` Unbounded Consumption
- `LLM08` Hidden Context Exposure (formerly System Prompt Leakage)
- `LLM09` Vector and Embedding Weaknesses
- `LLM10` Improper Output Handling

The 2026 numbering differs from the 2025 list, so a 2025-era reference with the same
number may name a different risk.

ASI titles: ASI01 Agent Goal Hijack · ASI02 Tool Misuse and Exploitation ·
ASI03 Identity and Privilege Abuse · ASI04 Agentic Supply Chain Vulnerabilities ·
ASI05 Unexpected Code Execution · ASI06 Memory and Context Poisoning ·
ASI07 Insecure Inter-Agent Communication · ASI08 Cascading Failures ·
ASI09 Human-Agent Trust Exploitation · ASI10 Rogue Agents.

LLM 2026 titles: LLM01 Prompt Injection · LLM02 Sensitive Information Disclosure ·
LLM03 Excessive Agency · LLM04 Supply Chain · LLM05 Data and Model Poisoning ·
LLM06 Unbounded Consumption · LLM07 Misinformation · LLM08 Hidden Context Exposure ·
LLM09 Vector and Embedding Weaknesses · LLM10 Improper Output Handling.

MCP (beta) titles: MCP01 Token Mismanagement & Secret Exposure · MCP02 Privilege
Escalation via Scope Creep · MCP03 Tool Poisoning · MCP04 Software Supply Chain Attacks
& Dependency Tampering · MCP05 Command Injection & Execution · MCP06 Intent Flow
Subversion (also titled Prompt Injection via Contextual Payloads) · MCP07 Insufficient
Authentication & Authorization · MCP08 Lack of Audit and Telemetry · MCP09 Shadow MCP
Servers · MCP10 Context Injection & Over-Sharing.

## 3. Assets

| ID | Asset | Why it matters |
| --- | --- | --- |
| A1 | Synthetic canary secrets (`ARF-CANARY-…`) | Stand-ins for credentials/PII; leakage is the clearest exfiltration signal |
| A2 | Synthetic mailbox, file sandbox, doc index | Confidentiality and integrity of the agent's data |
| A3 | Tool capabilities (`send_email`, `read_file`, `search_docs`) | Side effects the attacker wants to borrow (ASI02, ASI03) |
| A4 | System prompt and other hidden context | Reveals policy and helps attackers tune injections (LLM08:2026) |
| A5 | Human approval decisions | The last line before a side effect (ASI09) |
| A6 | Integrity of measurements (run log, findings) | A wrong number is worse than no number |
| A7 | The host machine | The lab must never reach beyond its sandbox or off the machine |

## 4. Trust boundaries

| ID | Boundary | Crossing |
| --- | --- | --- |
| TB1 | User → agent loop | Direct prompts (untrusted for attack cases) |
| TB2 | Agent loop ↔ local model | Loopback HTTP only; enforced in code (`require_loopback`) |
| TB3 | Agent loop ↔ MCP server | stdio; tool descriptions and results cross here |
| TB4 | MCP server → synthetic data | Tool implementations read/write the sandbox |
| **TB5** | **Tool output → model context** | **Untrusted data enters the instruction channel; root cause of indirect injection** |
| TB6 | Lab → outside world | No network egress: the provider is loopback-only, and tests block socket connections and non-loopback DNS (best-effort; child processes not covered) |

## 5. Threat actors

| ID | Actor | Capability |
| --- | --- | --- |
| TA1 | Malicious end user | Crafts direct prompts, including obfuscated ones |
| TA2 | External content author | Controls content the agent later reads (an email sender, a document author); never talks to the agent directly |
| TA3 | Malicious or compromised tool publisher | Controls MCP tool descriptions and behavior, including after approval |
| TA4 | The agent itself (non-adversarial) | Over-eager or mistaken autonomous actions without any attacker |

## 6. Threats

Attack case IDs (`AC01`-`AC12B`, built in Phase 2; T12 is split into `AC12A` rug pull and `AC12B` shadow tool) each also run in an obfuscated
variant (encoding, splitting, other languages; ATLAS AML.T0068 LLM Prompt Obfuscation).

| ID | Threat | Actor | ASI | LLM 2026 | MCP (beta) | ATLAS | Case | Scope |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| T01 | Role/policy override via direct prompt | TA1 | ASI01 | LLM01:2026 | - | AML.T0051.000, AML.T0054 | AC05 | In |
| T02 | Indirect injection via tool-returned email/file | TA2 | ASI01 | LLM01:2026 | MCP06:2025 | AML.T0051.001 | AC09 | In |
| T03 | Unauthorized tool invocation (email outside allowlist) | TA1, TA2 | ASI02 | LLM03:2026 | MCP02:2025 | AML.T0053 | AC01 | In |
| T04 | Restricted file access (path escape) | TA1, TA2 | ASI02, ASI03 | LLM03:2026 | MCP02:2025 | AML.T0053, AML.T0085.001 | AC02 | In |
| T05 | Tool chaining to bypass a restriction | TA1, TA2 | ASI02 | LLM03:2026 | - | AML.T0053 | AC03 | In |
| T06 | Parameter manipulation in tool calls | TA1, TA2 | ASI02 | LLM03:2026 | - | AML.T0053 | AC06 | In |
| T07 | Exfiltration via tool arguments (confused deputy) | TA2 | ASI03 | LLM02:2026 | - | AML.T0086 | AC10 | In |
| T08 | System prompt / hidden context leak | TA1 | ASI01 | LLM08:2026 | MCP10:2025 | AML.T0056 | AC04 | In |
| T09 | Approval-gate bypass (misleading summary, request splitting) | TA1, TA2 | ASI09 | LLM03:2026 | - | AML.T0053 | AC07 | In |
| T10 | Excessive agency: unrequested autonomous action | TA4 | ASI02, ASI10 | LLM03:2026 | - | AML.T0053 | BT-013 (was AC08) | In (scored by `benign_input_violation`) |
| T11 | Poisoned MCP tool description | TA3 | ASI04 | LLM04:2026 | MCP03:2025 | AML.T0115.002, AML.T0011.002 | AC11 | In |
| T12 | Post-approval rug pull / shadow tool | TA3 | ASI04 | LLM04:2026 | MCP03:2025, MCP04:2025 | AML.T0110, AML.T0115.002 | AC12A, AC12B | In |
| T13 | Runaway loops and resource exhaustion | TA1, TA4 | ASI08 | LLM06:2026 | - | AML.T0034.002 | - | In (step cap measured, no dedicated case) |
| T14 | Memory/context poisoning across conversations | TA2 | ASI06 | LLM01:2026 | MCP10:2025 | AML.T0080 | - | Deferred: v1 agent has no persistent memory |
| T15 | Retrieval poisoning via optional RAG tool | TA2 | ASI06 | LLM09:2026 | - | AML.T0070 | - | Deferred: covered by rag-attack-lab |
| T16 | Unexpected code execution | TA1, TA2 | ASI05 | LLM10:2026 | MCP05:2025 | AML.T0050 | - | Out: no code-exec tool by design |
| T17 | Insecure inter-agent communication | - | ASI07 | - | - | - | - | Out: single agent |

Mapping notes:

- T08: the ASI list has no disclosure category; ASI01 is cited because the leak is
  achieved by overriding the agent's instructions. LLM08:2026 is the precise match.
- T12: a rug pull alters an already-approved tool (AML.T0110); a shadow tool is a
  newly published look-alike (AML.T0115.002). Both are MCP03 tool poisoning delivered
  through the tool supply chain (MCP04).
- T13: ASI08 is written mainly for multi-agent propagation; here it covers one fault
  amplified through repeated tool calls in a single agent's loop.

### Threats to the measurement rig itself

| ID | Threat | Mitigation in Phase 0 |
| --- | --- | --- |
| R1 | Results mis-scored by a non-deterministic or easily evaded judge | Deterministic oracles only (`scoring.py`), hardened against common obfuscation (case, spacing, invisible characters, URL/HTML/base64/hex encoding); no LLM judge |
| R2 | One lucky run reported as a result | N runs per case (default 10), fixed seed + temperature, rates not anecdotes |
| R3 | Guardrail that blocks everything looks perfect | Benign task set run under every config; FPR counts any defense intervention on a benign run; benign completion scored from `must_call` / `must_not_call` |
| R4 | Errors or unevaluated runs silently skew rates | `error` outcomes excluded from denominators and counted per case kind; detector rates report their evaluated-run denominator |
| R5 | Lab data leaves the machine | Loopback-only provider (no userinfo, proxies, or redirects); tests block socket connections and non-loopback DNS |
| R6 | Attack text in evidence breaks the findings report | Evidence rendered in fences longer than any backtick run it contains |

## 7. Controls by experiment config

As built in Phase 3 (`src/agent_risk_framework/guardrails/`, see
[phase3_guardrails.md](phase3_guardrails.md)). Each control is also an independent
switch, so a single control can be measured alone.

| Config | Controls | Addresses |
| --- | --- | --- |
| `baseline` | None (over-permissioned agent). Expected result: attacks succeed | Control group |
| `deterministic-only` | `tool_permissions` (recipient allowlist, path sandbox, secret store denied); `tool_integrity` (vet, pin at approval, quarantine drift/unapproved/shadow tools); `approval_gate` (side effects approved from the real call); step cap (always on) | ASI02, ASI03, ASI04, ASI08, ASI09; MCP02:2025, MCP03:2025, MCP04:2025 |
| (each control alone) | any single control; labelled `single-control` in `runs.config`, exact set in `run_controls` | the Phase 4 per-control arms |
| `classifier-only` | `input_classifier`: rule-based injection/override/leak classifier on the user prompt | ASI01 (direct), LLM01:2026, LLM08:2026 (leak requests) |
| `output-filter-only` | `output_classifier`: the same rules on tool output before the model reads it; `egress_filter` (Phase 3.5): secrets and PII in outbound tool arguments (call blocked) and in tool output (redacted) | ASI01 (indirect), MCP06:2025; ASI02, ASI03, LLM02:2026 (egress) |
| `combined` | All six | All in-scope threats |

Changed from the Phase 0 plan, after the Phase 2 results: the classifier on tool
output is its own switch. The canary/secret output filter was first left out
(Phase 3) and then built in Phase 3.5 as `egress_filter`, a separate switch, because
the injection scan on tool output had no baseline target (AC09/AC10 0/20) and the
output-filter arm needed one. Its targets are T05, T07 and T12 (AC03, AC10, AC12A):
the secret leaving in a tool argument. It overlaps `tool_permissions`, which denies
the secret-store read itself; Phase 4 reports that credit as entangled. Requests for
the hidden context stay an `input_classifier` rule (AC04): the final answer is not
scanned, so a canary in it is still only measured, by the oracles. See
[phase3_5_egress.md](phase3_5_egress.md).

The hypothesis the ablation tests: architectural controls (`deterministic-only`) reduce
attack success more, at lower false-positive cost, than content inspection alone.

Phase 4 result, assessed per control (the `deterministic-only` preset was not an
arm): supported.
- **Architectural.** Alone, `tool_permissions`, `approval_gate` and `tool_integrity`
  cut attack success by 46, 37 and 21 points, losing no benign task.
- **Content inspection.** `input_classifier` cut 21 points and lost 40/450 benign
  runs. `egress_filter` cut 4 and `output_classifier` 0.
- **Still needed.** Content inspection is the only control on AC04, a leak to the
  requester.

See [phase4_ablation.md](phase4_ablation.md).

## 8. Assumptions

1. The host machine, Python runtime, and Ollama binary are trusted; model weights come from the official Ollama registry.
2. All data is synthetic. No real credentials, PII, or production systems exist anywhere in the lab.
3. Single user, single agent, no persistent memory across conversations (v1).
4. Fixed seeds and temperature make runs repeatable on one machine. They are not bit-identical across hardware or Ollama versions; results report the model, seed, and temperature for every run.
5. The fake tools model real side effects faithfully enough that "send_email was called with recipient X" counts as the harmful action.
6. Small local models (llama3.1:8b) may be unreliable at tool calling; baseline tool-call reliability is measured before attack results are interpreted.

## 9. Objectives

Security objectives (what the defended configs should achieve):

- SO1: Untrusted content (TB1, TB5) cannot cause a side effect the user did not request (ASI01, ASI02).
- SO2: Tool calls stay within least privilege: allowlisted recipients, sandboxed paths (ASI02, ASI03).
- SO3: Canaries and hidden context never appear in output or tool arguments (ASI03, LLM02:2026, LLM08:2026).
- SO4: Tool definitions cannot change after approval without detection (ASI04, MCP03:2025).
- SO5: Side-effecting actions require an approval that shows the real action (ASI09).

Measurement objectives (what the rig must produce, per config, over N ≥ 10 runs):

- MO1: attack success rate, detection rate, false negative rate.
- MO2: false positive rate (any defense intervention on a benign run) and benign task
  completion rate on the benign set.
- MO3: blocked action rate and mean detection latency.
- MO4: every finding mapped to ASI (required), LLM 2026, MCP (when applicable), and ATLAS.
