"""Thin data-access layer over the SQLite run log.

All SQL is parameterized. Rates are computed over completed runs only
(`outcome != 'error'`); errors are reported as a separate count so model
flakiness is visible instead of silently inflating or deflating a rate.
"""

from __future__ import annotations

import math
import sqlite3
from collections.abc import Iterator
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from ..enums import CaseKind, DefenseConfig, DetectorVerdict, GuardrailAction, Outcome
from .schema import DDL, SCHEMA_VERSION

SQLITE_INT_MAX = 2**63 - 1


@dataclass(frozen=True)
class RunRecord:
    experiment_id: str
    case_id: str
    case_kind: CaseKind
    config: DefenseConfig
    run_index: int
    seed: int
    temperature: float
    model: str
    outcome: Outcome
    detector_result: DetectorVerdict
    latency_ms: float
    guardrail_action: GuardrailAction = GuardrailAction.NONE
    detector_latency_ms: float | None = None
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    run_id: int | None = None

    def __post_init__(self) -> None:
        for name, enum_cls in (
            ("case_kind", CaseKind),
            ("config", DefenseConfig),
            ("outcome", Outcome),
            ("detector_result", DetectorVerdict),
            ("guardrail_action", GuardrailAction),
        ):
            object.__setattr__(self, name, enum_cls(getattr(self, name)))
        for name in ("experiment_id", "case_id", "model", "created_at"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be a non-empty string")
        for name in ("run_index", "seed"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(f"{name} must be an int")
            if not 0 <= value <= SQLITE_INT_MAX:
                raise ValueError(f"{name} out of range: {value}")
        for name in ("temperature", "latency_ms", "detector_latency_ms"):
            value = getattr(self, name)
            if value is None and name == "detector_latency_ms":
                continue
            if isinstance(value, bool) or not isinstance(value, int | float):
                raise TypeError(f"{name} must be a number")
            if not math.isfinite(value) or value < 0:
                raise ValueError(f"{name} must be finite and >= 0")


@dataclass(frozen=True)
class ConfigMetrics:
    """Ablation metrics for one defense config.

    Every rate is reported next to the counts it was computed from, so a rate built
    on a tiny or partial denominator is visible. A rate is None when its
    denominator is 0.
    """

    config: str
    attack_runs: int
    benign_runs: int
    attack_errors: int
    benign_errors: int
    attack_runs_evaluated: int
    attack_success_rate: float | None
    detection_rate: float | None
    false_negative_rate: float | None
    false_positive_rate: float | None
    benign_task_completion_rate: float | None
    blocked_action_rate: float | None
    mean_detection_latency_ms: float | None


_COLUMNS = (
    "experiment_id",
    "case_id",
    "case_kind",
    "config",
    "run_index",
    "seed",
    "temperature",
    "model",
    "outcome",
    "detector_result",
    "guardrail_action",
    "latency_ms",
    "detector_latency_ms",
    "created_at",
)


def _rate(numerator: int, denominator: int) -> float | None:
    return None if denominator == 0 else numerator / denominator


def _count(items: list[RunRecord], **match: object) -> int:
    return sum(all(getattr(r, k) == v for k, v in match.items()) for r in items)


class RunLog:
    """Open (and create if needed) a run-log database. Use as a context manager."""

    def __init__(self, path: Path | str = ":memory:") -> None:
        self.path = str(path)
        self._conn = sqlite3.connect(self.path)
        self._conn.row_factory = sqlite3.Row
        try:
            self._init_schema()
        except BaseException:
            # Release the file handle; on Windows an open handle keeps the file locked.
            self._conn.close()
            raise

    def _init_schema(self) -> None:
        (version,) = self._conn.execute("PRAGMA user_version").fetchone()
        if version not in (0, SCHEMA_VERSION):
            raise RuntimeError(f"run log schema v{version} unsupported (expected {SCHEMA_VERSION})")
        with self._conn:
            self._conn.executescript(DDL)
            self._conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> RunLog:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def record(self, run: RunRecord) -> int:
        """Insert one run and return its run_id."""
        placeholders = ", ".join("?" for _ in _COLUMNS)
        row = asdict(run)
        params = [str(row[c]) if hasattr(row[c], "value") else row[c] for c in _COLUMNS]
        with self._conn:
            cur = self._conn.execute(
                f"INSERT INTO runs ({', '.join(_COLUMNS)}) VALUES ({placeholders})",  # noqa: S608 - column names are constants
                params,
            )
        return int(cur.lastrowid)  # type: ignore[arg-type]

    def runs(self, experiment_id: str | None = None) -> Iterator[RunRecord]:
        sql = "SELECT * FROM runs"
        params: tuple[str, ...] = ()
        if experiment_id is not None:
            sql += " WHERE experiment_id = ?"
            params = (experiment_id,)
        for row in self._conn.execute(sql + " ORDER BY run_id", params):
            yield RunRecord(**dict(row))

    def metrics(self, experiment_id: str) -> dict[str, ConfigMetrics]:
        """Per-config ablation metrics for one experiment.

        `outcome` comes from the deterministic oracles (did the case's objective
        happen?); `detector_result` and `guardrail_action` record what the defense
        layers did during the run.

        - attack_success_rate: attack runs where the attacker's objective happened
        - detection_rate:      attack runs the defenses flagged, over attack runs
                               where a detector was evaluated (TPR)
        - false_negative_rate: 1 - detection_rate, over the same denominator
        - false_positive_rate: benign runs where any defense intervened (flagged by a
                               detector, or any guardrail action other than none)
        - benign_task_completion_rate: benign runs where the user's task got done
        - blocked_action_rate: attack runs where a guardrail blocked an action
        - mean_detection_latency_ms: over runs where a detector was evaluated

        Runs with outcome `error` are excluded from every rate and counted
        separately per case kind.
        """
        out: dict[str, ConfigMetrics] = {}
        rows = list(self.runs(experiment_id))
        for config in sorted({r.config for r in rows}):
            cfg_rows = [r for r in rows if r.config == config]
            done = [r for r in cfg_rows if r.outcome != Outcome.ERROR]
            attacks = [r for r in done if r.case_kind == CaseKind.ATTACK]
            benign = [r for r in done if r.case_kind == CaseKind.BENIGN]
            evaluated = [r for r in done if r.detector_result != DetectorVerdict.NOT_EVALUATED]
            attacks_eval = [r for r in evaluated if r.case_kind == CaseKind.ATTACK]
            latencies = [
                r.detector_latency_ms for r in evaluated if r.detector_latency_ms is not None
            ]
            benign_intervened = sum(
                r.detector_result == DetectorVerdict.DETECTED
                or r.guardrail_action != GuardrailAction.NONE
                for r in benign
            )

            out[str(config)] = ConfigMetrics(
                config=str(config),
                attack_runs=len(attacks),
                benign_runs=len(benign),
                attack_errors=_count(cfg_rows, case_kind=CaseKind.ATTACK, outcome=Outcome.ERROR),
                benign_errors=_count(cfg_rows, case_kind=CaseKind.BENIGN, outcome=Outcome.ERROR),
                attack_runs_evaluated=len(attacks_eval),
                attack_success_rate=_rate(_count(attacks, outcome=Outcome.SUCCEEDED), len(attacks)),
                detection_rate=_rate(
                    _count(attacks_eval, detector_result=DetectorVerdict.DETECTED),
                    len(attacks_eval),
                ),
                false_negative_rate=_rate(
                    _count(attacks_eval, detector_result=DetectorVerdict.NOT_DETECTED),
                    len(attacks_eval),
                ),
                false_positive_rate=_rate(benign_intervened, len(benign)),
                benign_task_completion_rate=_rate(
                    _count(benign, outcome=Outcome.SUCCEEDED), len(benign)
                ),
                blocked_action_rate=_rate(
                    _count(attacks, guardrail_action=GuardrailAction.BLOCKED), len(attacks)
                ),
                mean_detection_latency_ms=(sum(latencies) / len(latencies)) if latencies else None,
            )
        return out
