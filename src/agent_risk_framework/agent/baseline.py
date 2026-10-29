"""Baseline benign run: the usefulness anchor the Phase 4 ablation measures against.

Runs the benign task set through the undefended agent, logs every run and every
step to the SQLite run log, and reports the benign-task completion rate. There are
no defenses here, so `detector_result` is `not_evaluated` and `guardrail_action`
is `none`: this run measures only what the agent does on legitimate work.

Completion is scored deterministically from the tool-call log by the Phase 0
`BenignTask.completed` criteria (`must_call` / `must_not_call`), no LLM judge.

CLI (live, needs a local Ollama):

    python -m agent_risk_framework.agent.baseline --experiment-id baseline-benign
"""

from __future__ import annotations

import argparse
import contextlib
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from ..benign import BenignTask, load_benign_tasks
from ..enums import CaseKind, DefenseConfig, DetectorVerdict, Outcome
from ..providers.base import GenerationParams
from ..runlog import RunLog, RunRecord
from .client import connect_in_process
from .loop import DEFAULT_MAX_STEPS, run_agent
from .model import OllamaToolModel, ToolCallingModel
from .tools import DEFAULT_DOC_INDEX, DEFAULT_SANDBOX, Sandbox, build_tool_server


@dataclass(frozen=True)
class TaskResult:
    task_id: str
    outcome: Outcome
    called_tools: tuple[str, ...]
    stopped_reason: str
    steps: int


@dataclass(frozen=True)
class BaselineSummary:
    experiment_id: str
    model: str
    results: tuple[TaskResult, ...]

    @property
    def completed(self) -> int:
        return sum(r.outcome == Outcome.SUCCEEDED for r in self.results)

    @property
    def errors(self) -> int:
        return sum(r.outcome == Outcome.ERROR for r in self.results)

    @property
    def evaluated(self) -> int:
        return sum(r.outcome != Outcome.ERROR for r in self.results)

    @property
    def completion_rate(self) -> float | None:
        return None if self.evaluated == 0 else self.completed / self.evaluated


async def run_baseline(
    *,
    model: ToolCallingModel,
    run_log: RunLog,
    tasks: Sequence[BenignTask],
    experiment_id: str = "baseline-benign",
    sandbox_root: Path | str = DEFAULT_SANDBOX,
    doc_index: Path | str = DEFAULT_DOC_INDEX,
    seed: int = 1337,
    temperature: float = 0.0,
    max_steps: int = DEFAULT_MAX_STEPS,
) -> BaselineSummary:
    params = GenerationParams(temperature=temperature, seed=seed)
    results: list[TaskResult] = []

    for task in tasks:
        sandbox = Sandbox.load(sandbox_root, doc_index)  # fresh outbox per run
        server = build_tool_server(sandbox)
        result = None
        try:
            async with connect_in_process(server) as client:
                result = await run_agent(
                    model=model,
                    client=client,
                    user_prompt=task.prompt,
                    params=params,
                    max_steps=max_steps,
                )
        except Exception:
            # A crashed run is logged as ERROR and excluded from rates, not fatal.
            result = None

        if result is None:
            outcome, called, stopped, n_steps, latency_ms = Outcome.ERROR, (), "error", 0, 0.0
        else:
            called = tuple(sorted(result.called_tools))
            stopped = result.stopped_reason
            n_steps = len(result.steps)
            latency_ms = sum(s.latency_ms for s in result.steps)
            outcome = (
                Outcome.SUCCEEDED if task.completed(set(result.called_tools)) else Outcome.FAILED
            )

        run_id = run_log.record(
            RunRecord(
                experiment_id=experiment_id,
                case_id=task.task_id,
                case_kind=CaseKind.BENIGN,
                config=DefenseConfig.BASELINE,
                run_index=0,
                seed=seed,
                temperature=temperature,
                model=getattr(model, "model", "unknown"),
                outcome=outcome,
                detector_result=DetectorVerdict.NOT_EVALUATED,
                latency_ms=latency_ms,
            )
        )
        if result is not None:
            for record in result.step_records(run_id):
                run_log.record_step(record)
        results.append(TaskResult(task.task_id, outcome, called, stopped, n_steps))

    return BaselineSummary(experiment_id, getattr(model, "model", "unknown"), tuple(results))


def _build_model(name: str, provider: str) -> ToolCallingModel:
    if provider == "ollama":
        return OllamaToolModel(name)
    raise SystemExit(f"unknown provider {provider!r} (use 'ollama', or call run_baseline directly)")


def main(argv: Sequence[str] | None = None) -> None:
    import anyio

    parser = argparse.ArgumentParser(description="Run the benign task set at baseline.")
    parser.add_argument("--experiment-id", default="baseline-benign")
    parser.add_argument("--model", default="llama3.1:8b")
    parser.add_argument("--provider", default="ollama")
    parser.add_argument("--benign-set", default="data/benign_tasks.json")
    parser.add_argument("--sandbox", default=str(DEFAULT_SANDBOX))
    parser.add_argument("--doc-index", default=str(DEFAULT_DOC_INDEX))
    parser.add_argument("--db", default="runs/baseline.db")
    parser.add_argument("--seed", type=int, default=1337)
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument("--max-steps", type=int, default=DEFAULT_MAX_STEPS)
    args = parser.parse_args(argv)

    tasks = load_benign_tasks(args.benign_set)
    model = _build_model(args.model, args.provider)
    Path(args.db).parent.mkdir(parents=True, exist_ok=True)

    with RunLog(args.db) as run_log:
        summary = anyio.run(
            lambda: run_baseline(
                model=model,
                run_log=run_log,
                tasks=tasks,
                experiment_id=args.experiment_id,
                sandbox_root=args.sandbox,
                doc_index=args.doc_index,
                seed=args.seed,
                temperature=args.temperature,
                max_steps=args.max_steps,
            )
        )

    rate = summary.completion_rate
    print(f"\nbaseline benign run: {summary.experiment_id}  model={summary.model}")
    for r in summary.results:
        tools = ", ".join(r.called_tools) or "(none)"
        print(f"  {r.task_id:<8} {r.outcome.value:<10} steps={r.steps} [{tools}]")
    pct = "n/a" if rate is None else f"{rate:.0%}"
    print(
        f"\ncompleted {summary.completed}/{summary.evaluated} "
        f"(completion rate {pct}); errors {summary.errors}"
    )


if __name__ == "__main__":
    with contextlib.suppress(KeyboardInterrupt):
        main()
