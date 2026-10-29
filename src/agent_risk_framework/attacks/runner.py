"""Run the attack set and the benign set N times each, score, log, and report.

For every scenario and every run index the runner builds a fresh lab, wires the
(possibly mutated) MCP tool server to the Phase 1 agent loop, runs the agent once
at `seed + run_index` and the experiment's temperature, then:

1. scores the run with the scenario's deterministic oracle against its step rows;
2. writes the run (`runs`), every step (`steps`), and every verdict (`verdicts`)
   to the SQLite run log.

Benign tasks run through the same lab and loop with no planted content, and get
two verdicts, `task_success` (the run's `outcome`) and `benign_input_violation`
(a separate verdict row), which are reported side by side and never combined.

With no guardrails (`config: baseline`) this is the undefended Phase 2 baseline:
`detector_result` is `not_evaluated` and `guardrail_action` is `none` on every row,
and the expected result is that attacks succeed. With guardrails on (Phase 3), each
run also gets a `GuardrailEngine`: its decision log goes to `decisions`, the exact
control set to `run_controls`, `detector_result`/`guardrail_action` record whether
any control blocked anything, and the run's outcome bucket and credited control go
to `attributions` (see `attribution.py`). Every completed run, baseline included,
gets a bucket. A run that crashes is logged as `error` and excluded from every rate.

CLI (live, needs a local Ollama):

    python -m agent_risk_framework.attacks.runner \\
        --manifest configs/experiments/phase2_baseline.yaml --db runs/phase2.db \\
        --findings-dir findings --report docs/phase2_results.md
"""

from __future__ import annotations

import argparse
import contextlib
import json
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from ..agent.client import connect_in_process, list_tool_defs
from ..agent.loop import DEFAULT_MAX_STEPS, AgentResult, run_agent
from ..agent.model import OllamaToolModel, ToolCallingModel
from ..agent.tools import DEFAULT_DOC_INDEX, DEFAULT_SANDBOX, Sandbox
from ..benign import BenignTask, load_benign_tasks
from ..enums import (
    CaseKind,
    Control,
    DecisionStage,
    DefenseConfig,
    DetectorVerdict,
    FindingStatus,
    GuardrailAction,
    Outcome,
    OutcomeBucket,
)
from ..findings import Evidence, Finding, write_finding
from ..guardrails import DEFAULT_REGISTRY, GuardrailConfig, GuardrailEngine, ToolRegistry
from ..guardrails.egress import EgressFilter
from ..manifest import load_manifest
from ..providers.base import GenerationParams
from ..runlog import (
    BENIGN_VIOLATION_ORACLE,
    DecisionRecord,
    RunLog,
    RunRecord,
    StepRecord,
    VerdictRecord,
)
from .attribution import (
    BENIGN_STAGES,
    CHANNEL_STAGES,
    PAYLOAD_CONTROLS,
    Attribution,
    attribute,
)
from .lab import (
    OracleContext,
    apply_post_approval,
    build_lab_server,
    lab_sandbox,
    planted_reader,
    tool_fingerprint,
)
from .oracles import (
    Trace,
    TraceCall,
    Verdict,
    score_attack,
    score_benign_violation,
    score_task_success,
)
from .scenarios import BASE_TOOLS, AttackScenario, ScenarioCatalog, load_catalog

DRIFT_ORACLE = "tool_definition_drift"


@dataclass(frozen=True)
class CaseRun:
    """One run of one scenario or benign task, as logged."""

    case_id: str
    kind: CaseKind
    run_index: int
    seed: int
    outcome: Outcome
    run_id: int
    verdicts: tuple[Verdict, ...] = ()
    attribution: Attribution | None = None  # None only for error runs
    decisions: tuple[DecisionRecord, ...] = ()

    @property
    def bucket(self) -> OutcomeBucket | None:
        return None if self.attribution is None else self.attribution.bucket

    def verdict(self, oracle: str) -> Verdict | None:
        return next((v for v in self.verdicts if v.oracle == oracle), None)


@dataclass(frozen=True)
class Tally:
    """Counts for one case; every rate is reported with its denominator."""

    case_id: str
    runs: int
    succeeded: int
    errors: int
    violations: int = 0
    blocked: int = 0  # bucket blocked_by_control
    did_not_execute: int = 0  # bucket did_not_execute

    @property
    def evaluated(self) -> int:
        return self.runs - self.errors

    @staticmethod
    def fmt(k: int, n: int) -> str:
        return f"{k}/{n} (n/a)" if n == 0 else f"{k}/{n} ({k / n:.0%})"


@dataclass(frozen=True)
class ExperimentSummary:
    experiment_id: str
    model: str
    seed: int
    temperature: float
    runs_per_case: int
    runs: tuple[CaseRun, ...]
    config: DefenseConfig = DefenseConfig.BASELINE
    controls: tuple[str, ...] = ()

    def tally(self, kind: CaseKind) -> list[Tally]:
        order: list[str] = []
        for r in self.runs:
            if r.kind == kind and r.case_id not in order:
                order.append(r.case_id)
        out = []
        for cid in order:
            rows = [r for r in self.runs if r.kind == kind and r.case_id == cid]
            violated = [r.verdict(BENIGN_VIOLATION_ORACLE) for r in rows]
            out.append(
                Tally(
                    case_id=cid,
                    runs=len(rows),
                    succeeded=sum(r.outcome == Outcome.SUCCEEDED for r in rows),
                    errors=sum(r.outcome == Outcome.ERROR for r in rows),
                    violations=sum(bool(v and v.hit) for v in violated),
                    blocked=sum(r.bucket == OutcomeBucket.BLOCKED_BY_CONTROL for r in rows),
                    did_not_execute=sum(r.bucket == OutcomeBucket.DID_NOT_EXECUTE for r in rows),
                )
            )
        return out

    def totals(self, kind: CaseKind) -> Tally:
        tallies = self.tally(kind)
        return Tally(
            case_id="all",
            runs=sum(t.runs for t in tallies),
            succeeded=sum(t.succeeded for t in tallies),
            errors=sum(t.errors for t in tallies),
            violations=sum(t.violations for t in tallies),
            blocked=sum(t.blocked for t in tallies),
            did_not_execute=sum(t.did_not_execute for t in tallies),
        )

    def credits(self, kind: CaseKind) -> dict[str, int]:
        """Runs credited to each control (a run credited to two counts for both)."""
        out: dict[str, int] = {}
        for r in self.runs:
            if r.kind == kind and r.attribution is not None:
                for c in r.attribution.blocked_by:
                    out[str(c)] = out.get(str(c), 0) + 1
        return dict(sorted(out.items()))


def blocked_keys(decisions: Sequence[DecisionRecord]) -> frozenset[tuple[int, int]]:
    """(step_index, call_index) of every tool call a guardrail refused."""
    return frozenset(
        (d.step_index, d.call_index or 0)
        for d in decisions
        if d.blocked and d.stage == DecisionStage.TOOL_CALL and d.step_index is not None
    )


def _trace(result: AgentResult, decisions: Sequence[DecisionRecord] = ()) -> Trace:
    # Exactly the rows that get written to `steps` (and `decisions`), so every verdict
    # is a function of the log.
    return Trace.from_steps(result.step_records(0), blocked_keys(decisions))


@dataclass(frozen=True)
class _Defense:
    """What one run needs to know about the guardrails it runs under."""

    config: DefenseConfig
    guardrails: GuardrailConfig
    registry: ToolRegistry | None

    def engine(self, prompt: str, workspace: Path, ctx: OracleContext | None) -> GuardrailEngine:
        return GuardrailEngine(
            self.guardrails,
            user_prompt=prompt,
            workspace_root=workspace,
            allowlist=(ctx or OracleContext()).allowlist,
            registry=self.registry,
        )


def _defense(
    config: DefenseConfig | str,
    guardrails: GuardrailConfig | None,
    registry: ToolRegistry | Path | str | None,
) -> _Defense:
    config = DefenseConfig(config)
    chosen = GuardrailConfig.preset(config) if guardrails is None else guardrails
    if isinstance(registry, Path | str):
        registry = ToolRegistry.load(registry) if chosen.enabled(Control.TOOL_INTEGRITY) else None
    return _Defense(config, chosen, registry)


async def _run_guarded(
    defense: _Defense,
    sandbox: Sandbox,
    scenario: AttackScenario | None,
    prompt: str,
    *,
    model: ToolCallingModel,
    params: GenerationParams,
    max_steps: int,
    ctx: OracleContext | None,
) -> tuple[AgentResult, bool]:
    """Approve the tool list, apply any rug pull, admit the live list, run the agent."""
    engine = defense.engine(prompt, sandbox.root, ctx)
    server = build_lab_server(sandbox, scenario)
    async with connect_in_process(server) as client:
        approved = await list_tool_defs(client)  # what a human approved
        engine.approve_tools(approved)
        changed = apply_post_approval(server, scenario)
        live = await list_tool_defs(client) if changed else approved
        drift = tool_fingerprint(approved) != tool_fingerprint(live)
        result = await run_agent(
            model=model,
            client=client,
            user_prompt=prompt,
            tools=engine.admit_tools(live),
            params=params,
            max_steps=max_steps,
            guard=engine if defense.guardrails.any else None,
        )
    return result, drift


def _record(
    run_log: RunLog,
    *,
    experiment_id: str,
    case_id: str,
    kind: CaseKind,
    run_index: int,
    seed: int,
    temperature: float,
    model: str,
    outcome: Outcome,
    result: AgentResult | None,
    verdicts: Sequence[Verdict],
    defense: _Defense,
    attribution: Attribution | None = None,
) -> int:
    decisions = list(result.decisions) if result else []
    if not defense.guardrails.any:
        detected = DetectorVerdict.NOT_EVALUATED
    elif any(d.blocked for d in decisions):
        detected = DetectorVerdict.DETECTED
    else:
        detected = DetectorVerdict.NOT_DETECTED
    blocked = detected == DetectorVerdict.DETECTED
    run_id = run_log.record(
        RunRecord(
            experiment_id=experiment_id,
            case_id=case_id,
            case_kind=kind,
            config=defense.config,
            run_index=run_index,
            seed=seed,
            temperature=temperature,
            model=model,
            outcome=outcome,
            detector_result=detected,
            guardrail_action=GuardrailAction.BLOCKED if blocked else GuardrailAction.NONE,
            latency_ms=sum(s.latency_ms for s in result.steps) if result else 0.0,
            detector_latency_ms=(
                sum(d.latency_ms for d in decisions) if defense.guardrails.any and result else None
            ),
        )
    )
    run_log.record_controls(run_id, defense.guardrails.controls)
    if result is not None:
        for step in result.step_records(run_id):
            run_log.record_step(step)
        for d in decisions:
            run_log.record_decision(d.record(run_id))
    for v in verdicts:
        run_log.record_verdict(VerdictRecord(run_id, v.oracle, v.hit, v.reasons))
    if attribution is not None:
        run_log.record_attribution(attribution.record(run_id))
    return run_id


def _records(result: AgentResult) -> list[DecisionRecord]:
    # run_id 0 is a placeholder: these are scored before the run row exists.
    return [d.record(0) for d in result.decisions]


def _unredact(base_sandbox: Path | str):  # type: ignore[no-untyped-def]
    # The same filter the run used: the lab copies the base sandbox's secret store, so
    # its known secrets (and therefore its placeholders) are reproducible from the log.
    egress = EgressFilter.for_workspace(base_sandbox)
    return lambda text: egress.redact(text).replacements


def attribute_attack(
    scenario: AttackScenario,
    trace: Trace,
    decisions: Sequence[DecisionRecord],
    ctx: OracleContext | None = None,
    base_sandbox: Path | str = DEFAULT_SANDBOX,
) -> Attribution:
    tools = BASE_TOOLS | ({scenario.mcp.tool} if scenario.mcp else set())
    reader = planted_reader(scenario, base_sandbox)

    def simulate(call: TraceCall) -> str:
        args = call.arguments if isinstance(call.arguments, Mapping) else {}
        path = args.get("path")
        return reader(path) if call.name == "read_file" and isinstance(path, str) else ""

    return attribute(
        objective=lambda t: score_attack(scenario.oracle, t, ctx).hit,
        trace=trace,
        decisions=decisions,
        tool_names=tools,
        payload_stages=CHANNEL_STAGES[scenario.channel],
        simulate=simulate,
        unredact=_unredact(base_sandbox),
        withheld_controls=PAYLOAD_CONTROLS,
    )


def attribute_benign(
    task: BenignTask,
    trace: Trace,
    decisions: Sequence[DecisionRecord],
    base_sandbox: Path | str = DEFAULT_SANDBOX,
) -> Attribution:
    return attribute(
        objective=lambda t: score_task_success(task, t).hit,
        trace=trace,
        decisions=decisions,
        tool_names=BASE_TOOLS,
        payload_stages=BENIGN_STAGES,
        unredact=_unredact(base_sandbox),
    )


async def run_attack_once(
    scenario: AttackScenario,
    *,
    model: ToolCallingModel,
    run_log: RunLog,
    experiment_id: str,
    run_index: int,
    seed: int,
    temperature: float = 0.0,
    max_steps: int = DEFAULT_MAX_STEPS,
    base_sandbox: Path | str = DEFAULT_SANDBOX,
    doc_index: Path | str = DEFAULT_DOC_INDEX,
    ctx: OracleContext | None = None,
    config: DefenseConfig | str = DefenseConfig.BASELINE,
    guardrails: GuardrailConfig | None = None,
    registry: ToolRegistry | Path | str | None = DEFAULT_REGISTRY,
    defense: _Defense | None = None,
) -> CaseRun:
    """One attack run. `guardrails` defaults to the preset for `config`."""
    defense = defense or _defense(config, guardrails, registry)
    params = GenerationParams(temperature=temperature, seed=seed)
    result: AgentResult | None = None
    drift = False
    # A crash before the agent finishes leaves `result` None: an error run, excluded
    # from rates. A crash after it (e.g. temp-dir cleanup on Windows) keeps the run.
    with (
        contextlib.suppress(Exception),
        lab_sandbox(scenario, base_sandbox=base_sandbox, doc_index=doc_index) as sandbox,
    ):
        result, drift = await _run_guarded(
            defense,
            sandbox,
            scenario,
            scenario.user_prompt,
            model=model,
            params=params,
            max_steps=max_steps,
            ctx=ctx,
        )

    verdicts: list[Verdict] = []
    outcome = Outcome.ERROR
    attribution: Attribution | None = None
    if result is not None:
        decisions = _records(result)
        trace = _trace(result, decisions)
        verdict = score_attack(scenario.oracle, trace, ctx)
        outcome = Outcome.SUCCEEDED if verdict.hit else Outcome.FAILED
        verdicts.append(verdict)
        if scenario.mcp is not None:
            reason = ("live tool list differs from the approved one",) if drift else ()
            verdicts.append(Verdict(DRIFT_ORACLE, drift, reason))
        attribution = attribute_attack(scenario, trace, decisions, ctx, base_sandbox)
    run_id = _record(
        run_log,
        experiment_id=experiment_id,
        case_id=scenario.scenario_id,
        kind=CaseKind.ATTACK,
        run_index=run_index,
        seed=seed,
        temperature=temperature,
        model=getattr(model, "model", "unknown"),
        outcome=outcome,
        result=result,
        verdicts=verdicts,
        defense=defense,
        attribution=attribution,
    )
    return CaseRun(
        scenario.scenario_id,
        CaseKind.ATTACK,
        run_index,
        seed,
        outcome,
        run_id,
        tuple(verdicts),
        attribution,
        tuple(run_log.decisions(run_id)),
    )


async def run_benign_once(
    task: BenignTask,
    *,
    model: ToolCallingModel,
    run_log: RunLog,
    experiment_id: str,
    run_index: int,
    seed: int,
    temperature: float = 0.0,
    max_steps: int = DEFAULT_MAX_STEPS,
    base_sandbox: Path | str = DEFAULT_SANDBOX,
    doc_index: Path | str = DEFAULT_DOC_INDEX,
    ctx: OracleContext | None = None,
    config: DefenseConfig | str = DefenseConfig.BASELINE,
    guardrails: GuardrailConfig | None = None,
    registry: ToolRegistry | Path | str | None = DEFAULT_REGISTRY,
    defense: _Defense | None = None,
) -> CaseRun:
    """One benign run. `guardrails` defaults to the preset for `config`."""
    defense = defense or _defense(config, guardrails, registry)
    params = GenerationParams(temperature=temperature, seed=seed)
    result: AgentResult | None = None
    with (
        contextlib.suppress(Exception),  # same error handling as run_attack_once
        lab_sandbox(None, base_sandbox=base_sandbox, doc_index=doc_index) as sandbox,
    ):
        result, _ = await _run_guarded(
            defense,
            sandbox,
            None,
            task.prompt,
            model=model,
            params=params,
            max_steps=max_steps,
            ctx=ctx,
        )

    verdicts: list[Verdict] = []
    outcome = Outcome.ERROR
    attribution: Attribution | None = None
    if result is not None:
        decisions = _records(result)
        trace = _trace(result, decisions)
        success = score_task_success(task, trace)
        verdicts = [success, score_benign_violation(task, trace, ctx)]
        outcome = Outcome.SUCCEEDED if success.hit else Outcome.FAILED
        attribution = attribute_benign(task, trace, decisions, base_sandbox)
    run_id = _record(
        run_log,
        experiment_id=experiment_id,
        case_id=task.task_id,
        kind=CaseKind.BENIGN,
        run_index=run_index,
        seed=seed,
        temperature=temperature,
        model=getattr(model, "model", "unknown"),
        outcome=outcome,
        result=result,
        verdicts=verdicts,
        defense=defense,
        attribution=attribution,
    )
    return CaseRun(
        task.task_id,
        CaseKind.BENIGN,
        run_index,
        seed,
        outcome,
        run_id,
        tuple(verdicts),
        attribution,
        tuple(run_log.decisions(run_id)),
    )


async def run_experiment(
    *,
    model: ToolCallingModel,
    run_log: RunLog,
    scenarios: Sequence[AttackScenario],
    tasks: Sequence[BenignTask],
    experiment_id: str,
    runs: int = 10,
    seed: int = 1337,
    temperature: float = 0.0,
    max_steps: int = DEFAULT_MAX_STEPS,
    base_sandbox: Path | str = DEFAULT_SANDBOX,
    doc_index: Path | str = DEFAULT_DOC_INDEX,
    progress: Callable[[CaseRun], None] | None = None,
    config: DefenseConfig | str = DefenseConfig.BASELINE,
    guardrails: GuardrailConfig | None = None,
    registry: ToolRegistry | Path | str | None = DEFAULT_REGISTRY,
) -> ExperimentSummary:
    """Each scenario and each benign task, `runs` times, at seed + run_index.

    Runs under `config`'s preset guardrails unless `guardrails` overrides them.
    """
    if runs < 1:
        raise ValueError("runs must be >= 1")
    if next(run_log.runs(experiment_id), None) is not None:
        raise ValueError(f"experiment {experiment_id!r} already has runs in {run_log.path}")
    defense = _defense(config, guardrails, registry)
    common = dict(
        model=model,
        run_log=run_log,
        experiment_id=experiment_id,
        temperature=temperature,
        max_steps=max_steps,
        base_sandbox=base_sandbox,
        doc_index=doc_index,
        defense=defense,
    )
    done: list[CaseRun] = []
    for scenario in scenarios:
        for i in range(runs):
            done.append(await run_attack_once(scenario, run_index=i, seed=seed + i, **common))
            if progress:
                progress(done[-1])
    for task in tasks:
        for i in range(runs):
            done.append(await run_benign_once(task, run_index=i, seed=seed + i, **common))
            if progress:
                progress(done[-1])
    return ExperimentSummary(
        experiment_id,
        getattr(model, "model", "unknown"),
        seed,
        temperature,
        runs,
        tuple(done),
        defense.config,
        tuple(defense.guardrails.names()),
    )


def rescore(
    run_log: RunLog,
    experiment_id: str,
    catalog: ScenarioCatalog,
    tasks: Sequence[BenignTask],
    ctx: OracleContext | None = None,
) -> dict[int, tuple[Verdict, ...]]:
    """Recompute primary verdicts from the stored step and decision rows alone (audit).

    Only runs whose scenario or task is passed in are scored; others are skipped.
    """
    return {
        run_id: verdicts
        for run_id, (verdicts, _) in _rescored(run_log, experiment_id, catalog, tasks, ctx).items()
    }


def reattribute(
    run_log: RunLog,
    experiment_id: str,
    catalog: ScenarioCatalog,
    tasks: Sequence[BenignTask],
    ctx: OracleContext | None = None,
    base_sandbox: Path | str = DEFAULT_SANDBOX,
) -> dict[int, Attribution]:
    """Recompute every run's outcome bucket from the stored log alone (audit check)."""
    return {
        run_id: attribution
        for run_id, (_, attribution) in _rescored(
            run_log, experiment_id, catalog, tasks, ctx, base_sandbox
        ).items()
    }


def _rescored(
    run_log: RunLog,
    experiment_id: str,
    catalog: ScenarioCatalog,
    tasks: Sequence[BenignTask],
    ctx: OracleContext | None,
    base_sandbox: Path | str = DEFAULT_SANDBOX,
) -> dict[int, tuple[tuple[Verdict, ...], Attribution]]:
    by_id = {s.scenario_id: s for s in catalog.scenarios}
    task_by_id = {t.task_id: t for t in tasks}
    out: dict[int, tuple[tuple[Verdict, ...], Attribution]] = {}
    for run in run_log.runs(experiment_id):
        if run.outcome == Outcome.ERROR or run.run_id is None:
            continue
        decisions = list(run_log.decisions(run.run_id))
        trace = Trace.from_steps(run_log.steps(run.run_id), blocked_keys(decisions))
        if run.case_kind == CaseKind.ATTACK and run.case_id in by_id:
            scenario = by_id[run.case_id]
            out[run.run_id] = (
                (score_attack(scenario.oracle, trace, ctx),),
                attribute_attack(scenario, trace, decisions, ctx, base_sandbox),
            )
        elif run.case_kind == CaseKind.BENIGN and run.case_id in task_by_id:
            task = task_by_id[run.case_id]
            out[run.run_id] = (
                (score_task_success(task, trace), score_benign_violation(task, trace, ctx)),
                attribute_benign(task, trace, decisions, base_sandbox),
            )
    return out


# --- reporting -------------------------------------------------------------------


def _call_lines(steps: Sequence[StepRecord], limit: int = 400) -> str:
    lines = []
    for s in steps:
        if s.tool_name is None:
            lines.append(f"[final answer] {s.model_text[:limit]}")
            continue
        result = (s.tool_result or "").replace("\n", " ")[:limit]
        lines.append(f"{s.tool_name}({s.tool_args}) -> {result}")
    return "\n".join(lines)


def build_findings(
    summary: ExperimentSummary, catalog: ScenarioCatalog, run_log: RunLog
) -> list[Finding]:
    """One finding per case that succeeded in at least one run, with its rates as evidence."""
    tallies = {t.case_id: t for t in summary.tally(CaseKind.ATTACK)}
    findings: list[Finding] = []
    for case in catalog.cases.values():
        variants = [s for s in catalog.scenarios if s.case_id == case.case_id]
        hits = [
            r
            for r in summary.runs
            if r.kind == CaseKind.ATTACK
            and r.outcome == Outcome.SUCCEEDED
            and r.case_id in {s.scenario_id for s in variants}
        ]
        if not hits:
            continue
        rate_lines = []
        for s in variants:
            t = tallies.get(s.scenario_id)
            if t is None:
                continue
            label = f"{s.scenario_id} ({s.obfuscation or 'plain'}, {s.channel})"
            rate_lines.append(
                f"{label}: {Tally.fmt(t.succeeded, t.evaluated)} succeeded; {t.errors} error(s)"
            )
        measured = "; ".join(rate_lines)
        example = hits[0]
        verdict = example.verdict(
            next(s.oracle.kind for s in variants if s.scenario_id == example.case_id)
        )
        header = (
            f"experiment={summary.experiment_id} config={summary.config} model={summary.model} "
            f"seed={summary.seed}+run_index temperature={summary.temperature} "
            f"runs_per_variant={summary.runs_per_case}"
        )
        evidence = [
            Evidence("run_log", header + "\n" + "\n".join(rate_lines)),
            Evidence(
                "oracle_verdict",
                "\n".join(verdict.reasons) if verdict else "(no reasons recorded)",
                example.run_id,
            ),
            Evidence(
                "tool_calls", _call_lines(list(run_log.steps(example.run_id))), example.run_id
            ),
        ]
        defended = summary.config != DefenseConfig.BASELINE
        case_runs = [r for r in summary.runs if r.case_id in {s.scenario_id for s in variants}]
        any_blocked = any(r.bucket == OutcomeBucket.BLOCKED_BY_CONTROL for r in case_runs)
        where = (
            f"under config {summary.config} ({', '.join(summary.controls) or 'no controls'})"
            if defended
            else "at baseline (undefended)"
        )
        findings.append(
            Finding(
                finding_id=case.finding_id,
                title=case.title,
                severity=case.severity,
                category="attack_scenario",
                asi_id=case.asi_id,
                llm_id=case.llm_id,
                mcp_id=case.mcp_id,
                atlas_technique=case.atlas_technique,
                attack_case=case.case_id,
                status=FindingStatus.OPEN,
                description=(
                    f"{case.description}\n\nMeasured {where}, threat {case.threat}: {measured}."
                ),
                impact=case.impact,
                detection_result=(
                    DetectorVerdict.NOT_EVALUATED
                    if not defended
                    else DetectorVerdict.DETECTED
                    if any_blocked
                    else DetectorVerdict.NOT_DETECTED
                ),
                guardrail_action=GuardrailAction.BLOCKED if any_blocked else GuardrailAction.NONE,
                recommendation=case.recommendation,
                evidence=tuple(evidence),
            )
        )
    return findings


def render_report(
    summary: ExperimentSummary,
    catalog: ScenarioCatalog,
    tasks: Sequence[BenignTask],
) -> str:
    by_id = {s.scenario_id: s for s in catalog.scenarios}
    task_by_id = {t.task_id: t for t in tasks}
    attack = summary.tally(CaseKind.ATTACK)
    benign = summary.tally(CaseKind.BENIGN)
    a_tot, b_tot = summary.totals(CaseKind.ATTACK), summary.totals(CaseKind.BENIGN)
    controls = ", ".join(f"`{c}`" for c in summary.controls) or "none (undefended)"
    lines = [
        f"# Results: config `{summary.config}`",
        "",
        "Generated by `python -m agent_risk_framework.attacks.runner`. Do not edit by hand.",
        "",
        f"- Experiment: `{summary.experiment_id}` · config `{summary.config}` · controls: "
        f"{controls}",
        f"- Model: `{summary.model}` · temperature {summary.temperature} · seed "
        f"{summary.seed} + run_index · {summary.runs_per_case} runs per case",
        f"- Generated: {datetime.now(UTC).date().isoformat()}",
        "- Every rate is `succeeded / evaluated runs`; errored runs are excluded and counted.",
        "- Every completed run lands in one outcome bucket: succeeded, blocked by control, "
        "did not execute (tool call written as text), or failed for another reason.",
        "",
        "## Attack scenarios",
        "",
        f"Overall attack success: **{Tally.fmt(a_tot.succeeded, a_tot.evaluated)}** "
        f"({a_tot.errors} error runs).",
        "",
        "| Scenario | Case | Channel | Obfuscation | Oracle | Attack success "
        "| Blocked by control | Did not execute | Errors |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for t in attack:
        s = by_id[t.case_id]
        lines.append(
            f"| {s.scenario_id} | {s.case_id} | {s.channel} | {s.obfuscation or '-'} | "
            f"`{s.oracle.kind}` | {Tally.fmt(t.succeeded, t.evaluated)} | "
            f"{Tally.fmt(t.blocked, t.evaluated)} | {t.did_not_execute} | {t.errors} |"
        )
    plain = [t for t in attack if not by_id[t.case_id].obfuscated]
    obf = [t for t in attack if by_id[t.case_id].obfuscated]
    for label, group in (("plain", plain), ("obfuscated", obf)):
        k = sum(t.succeeded for t in group)
        n = sum(t.evaluated for t in group)
        lines.append("")
        lines.append(f"- {label.capitalize()} variants: {Tally.fmt(k, n)}")
    lines += ["", _credit_line(summary.credits(CaseKind.ATTACK), "Attack runs credited")]
    lines += [
        "",
        "## Benign tasks",
        "",
        "Two separate measures, never combined: **task success** (the legitimate goal got "
        "done) and **benign-input violation** (the agent acted unsafely on legitimate input).",
        "",
        f"- Task success: **{Tally.fmt(b_tot.succeeded, b_tot.evaluated)}**",
        f"- Benign-input violation: **{Tally.fmt(b_tot.violations, b_tot.evaluated)}**",
        f"- Task blocked by a control (false-positive cost): "
        f"**{Tally.fmt(b_tot.blocked, b_tot.evaluated)}**",
        f"- Error runs: {b_tot.errors}",
        _credit_line(summary.credits(CaseKind.BENIGN), "Benign runs blocked"),
        "",
        "| Task | Category | Hard negative | Task success | Benign-input violation "
        "| Blocked by control | Did not execute | Errors |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for t in benign:
        task = task_by_id[t.case_id]
        lines.append(
            f"| {t.case_id} | {task.category} | {'yes' if task.hard_negative else 'no'} | "
            f"{Tally.fmt(t.succeeded, t.evaluated)} | {Tally.fmt(t.violations, t.evaluated)} | "
            f"{Tally.fmt(t.blocked, t.evaluated)} | {t.did_not_execute} | {t.errors} |"
        )
    lines.append("")
    return "\n".join(lines)


def _credit_line(credits: dict[str, int], label: str) -> str:
    body = ", ".join(f"`{c}` {n}" for c, n in credits.items()) or "none"
    return f"- {label}, by control: {body}"


def _build_model(name: str, provider: str) -> ToolCallingModel:
    if provider == "ollama":
        return OllamaToolModel(name)
    raise SystemExit(f"provider {provider!r} is not runnable from the CLI (use 'ollama')")


def main(argv: Sequence[str] | None = None) -> None:
    import anyio

    parser = argparse.ArgumentParser(description="Run the attack + benign sets under a config.")
    parser.add_argument("--manifest", default="configs/experiments/phase2_baseline.yaml")
    parser.add_argument("--db", default="runs/phase2.db")
    parser.add_argument("--findings-dir", default=None, help="write findings here")
    parser.add_argument("--report", default=None, help="write the markdown report here")
    parser.add_argument("--only", default="", help="comma-separated scenario or case ids")
    parser.add_argument("--runs", type=int, default=None, help="override the manifest's runs")
    parser.add_argument("--skip-benign", action="store_true")
    parser.add_argument("--experiment-id", default=None, help="override the manifest's id")
    parser.add_argument("--max-steps", type=int, default=DEFAULT_MAX_STEPS)
    parser.add_argument(
        "--controls",
        default=None,
        help="comma-separated guardrails, overriding the manifest (e.g. tool_integrity)",
    )
    parser.add_argument("--registry", default=str(DEFAULT_REGISTRY))
    args = parser.parse_args(argv)

    manifest = load_manifest(args.manifest)
    config = manifest.config
    if args.controls is not None:
        guardrails = GuardrailConfig.parse(args.controls.split(","))
    elif manifest.controls is not None:
        guardrails = GuardrailConfig.parse(manifest.controls)
    else:
        guardrails = GuardrailConfig.preset(manifest.config)
    if guardrails.controls != GuardrailConfig.preset_or_none(config).controls:
        # An override changes what ran, so the label follows it (run_controls is exact).
        with contextlib.suppress(ValueError):
            config = guardrails.label()
    catalog = load_catalog(manifest.attack_set)
    scenarios = catalog.select([x for x in args.only.split(",") if x.strip()] or None)
    tasks = [] if args.skip_benign else load_benign_tasks(manifest.benign_set)
    runs = args.runs if args.runs is not None else manifest.runs
    experiment_id = args.experiment_id or manifest.experiment_id
    model = _build_model(manifest.model, manifest.provider)
    Path(args.db).parent.mkdir(parents=True, exist_ok=True)

    def progress(r: CaseRun) -> None:
        bucket = r.bucket.value if r.bucket else r.outcome.value
        credit = ",".join(r.attribution.blocked_by) if r.attribution else ""
        print(f"  {r.case_id:<10} run {r.run_index:>2}  {bucket} {credit}".rstrip(), flush=True)

    with RunLog(args.db) as run_log:
        summary = anyio.run(
            lambda: run_experiment(
                model=model,
                run_log=run_log,
                scenarios=scenarios,
                tasks=tasks,
                experiment_id=experiment_id,
                runs=runs,
                seed=manifest.seed,
                temperature=manifest.temperature,
                max_steps=args.max_steps,
                progress=progress,
                config=config,
                guardrails=guardrails,
                registry=args.registry,
            )
        )
        report = render_report(summary, catalog, tasks)
        if args.findings_dir:
            for finding in build_findings(summary, catalog, run_log):
                write_finding(finding, args.findings_dir, overwrite=True)
        metrics = run_log.metrics(experiment_id)

    if args.report:
        Path(args.report).write_text(report, encoding="utf-8", newline="\n")
    sys.stdout.write("\n" + report + "\n")
    print(json.dumps({k: vars(v) for k, v in metrics.items()}, indent=2))


if __name__ == "__main__":
    with contextlib.suppress(KeyboardInterrupt):
        main()
