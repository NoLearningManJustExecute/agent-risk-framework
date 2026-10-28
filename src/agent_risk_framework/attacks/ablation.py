"""Phase 4 defense ablation: the attack and benign sets under every arm, one database.

Arms: `baseline`, each of the six controls alone, and `combined`. Each arm is its
own experiment (`phase4-<arm>`) in one run-log database, so every table and chart
in `docs/phase4_ablation.md` is a query over that file (`attacks.ablation_report`).
Every run records its exact control set (`run_controls`), its decision log and its
locked outcome bucket.

Same model, seeds and temperature for every arm: seed + run_index at temperature 0.
A finished arm is skipped when the command is run again, so an interrupted matrix
resumes where it stopped; a half-finished arm is refused rather than mixed.

CLI (live, needs a local Ollama; about 690 runs per arm):

    python -m agent_risk_framework.attacks.ablation \\
        --manifest configs/experiments/phase4_ablation.yaml --db runs/phase4.db
"""

from __future__ import annotations

import argparse
import contextlib
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

from ..agent.loop import DEFAULT_MAX_STEPS
from ..agent.model import ToolCallingModel
from ..benign import BenignTask, load_benign_tasks
from ..enums import Control
from ..guardrails import DEFAULT_REGISTRY, GuardrailConfig
from ..manifest import load_manifest
from ..runlog import RunLog
from .runner import CaseRun, _build_model, run_experiment
from .scenarios import AttackScenario, load_catalog

EXPERIMENT_PREFIX = "phase4-"


@dataclass(frozen=True)
class Arm:
    name: str
    guardrails: GuardrailConfig

    @property
    def experiment_id(self) -> str:
        return f"{EXPERIMENT_PREFIX}{self.name}"


ARMS: tuple[Arm, ...] = (
    Arm("baseline", GuardrailConfig.none()),
    *(Arm(c.value, GuardrailConfig.of(c)) for c in Control),
    Arm("combined", GuardrailConfig.preset("combined")),
)


def select_arms(names: Sequence[str] | None) -> list[Arm]:
    if not names:
        return list(ARMS)
    by_name = {a.name: a for a in ARMS}
    unknown = sorted(set(names) - set(by_name))
    if unknown:
        raise ValueError(f"unknown arm(s) {unknown}; expected some of {list(by_name)}")
    return [by_name[n] for n in names]


async def run_matrix(
    *,
    model: ToolCallingModel,
    run_log: RunLog,
    scenarios: Sequence[AttackScenario],
    tasks: Sequence[BenignTask],
    arms: Sequence[Arm] = ARMS,
    runs: int = 10,
    seed: int = 1337,
    temperature: float = 0.0,
    max_steps: int = DEFAULT_MAX_STEPS,
    registry: Path | str = DEFAULT_REGISTRY,
    progress: Callable[[Arm, CaseRun], None] | None = None,
    **lab: object,
) -> list[str]:
    """Run every arm not already complete; return the arms that ran."""
    expected = (len(scenarios) + len(tasks)) * runs
    ran: list[str] = []
    for arm in arms:
        done = sum(1 for _ in run_log.runs(arm.experiment_id))
        if done == expected:
            continue
        if done:
            raise ValueError(
                f"arm {arm.name!r} has {done}/{expected} runs in {run_log.path}; "
                "use a new database rather than mixing a partial arm"
            )
        await run_experiment(
            model=model,
            run_log=run_log,
            scenarios=scenarios,
            tasks=tasks,
            experiment_id=arm.experiment_id,
            runs=runs,
            seed=seed,
            temperature=temperature,
            max_steps=max_steps,
            progress=(lambda r, a=arm: progress(a, r)) if progress else None,
            config=arm.guardrails.label(),
            guardrails=arm.guardrails,
            registry=registry,
            **lab,  # type: ignore[arg-type]
        )
        ran.append(arm.name)
    return ran


def main(argv: Sequence[str] | None = None) -> None:
    import anyio

    parser = argparse.ArgumentParser(description="Run the Phase 4 ablation matrix.")
    parser.add_argument("--manifest", default="configs/experiments/phase4_ablation.yaml")
    parser.add_argument("--db", default="runs/phase4.db")
    parser.add_argument("--arms", default="", help="comma-separated arm names (default: all)")
    parser.add_argument("--runs", type=int, default=None, help="override the manifest's runs")
    parser.add_argument("--max-steps", type=int, default=DEFAULT_MAX_STEPS)
    parser.add_argument("--registry", default=str(DEFAULT_REGISTRY))
    args = parser.parse_args(argv)

    manifest = load_manifest(args.manifest)
    arms = select_arms([a.strip() for a in args.arms.split(",") if a.strip()])
    scenarios = load_catalog(manifest.attack_set).scenarios
    tasks = load_benign_tasks(manifest.benign_set)
    model = _build_model(manifest.model, manifest.provider)
    Path(args.db).parent.mkdir(parents=True, exist_ok=True)

    def progress(arm: Arm, r: CaseRun) -> None:
        bucket = r.bucket.value if r.bucket else r.outcome.value
        credit = ",".join(r.attribution.blocked_by) if r.attribution else ""
        line = f"{arm.name:<18} {r.case_id:<10} run {r.run_index:>2}  {bucket} {credit}"
        print(line.rstrip(), flush=True)

    with RunLog(args.db) as run_log:
        ran = anyio.run(
            lambda: run_matrix(
                model=model,
                run_log=run_log,
                scenarios=scenarios,
                tasks=tasks,
                arms=arms,
                runs=args.runs if args.runs is not None else manifest.runs,
                seed=manifest.seed,
                temperature=manifest.temperature,
                max_steps=args.max_steps,
                registry=args.registry,
                progress=progress,
            )
        )
    sys.stdout.write(f"arms run: {', '.join(ran) or 'none (all complete)'}\n")


if __name__ == "__main__":
    with contextlib.suppress(KeyboardInterrupt):
        main()
