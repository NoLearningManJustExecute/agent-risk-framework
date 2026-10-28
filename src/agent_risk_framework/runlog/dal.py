"""Thin data-access layer over the SQLite run log.

All SQL is parameterized. Rates are computed over completed runs only
(`outcome != 'error'`); errors are reported as a separate count so model
flakiness is visible instead of silently inflating or deflating a rate.
"""

from __future__ import annotations

import json
import math
import sqlite3
from collections.abc import Iterator
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from ..enums import CaseKind, DefenseConfig, DetectorVerdict, GuardrailAction, Outcome
from .schema import DDL, SCHEMA_VERSION

SQLITE_INT_MAX = 2**63 - 1

# The secondary oracle every benign run is scored with (Phase 2). Kept apart from the
# run's `outcome` (task success) on purpose: "did the legitimate task get done" and
# "did the agent act unsafely on benign input" are two measures, never one.
BENIGN_VIOLATION_ORACLE = "benign_input_violation"


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
    benign_runs_violation_scored: int  # benign runs with a benign_input_violation verdict
    benign_input_violation_rate: float | None


@dataclass(frozen=True)
class StepRecord:
    """One agent step: the model turn plus the tool call it dispatched, if any.

    A step with no tool call (the agent's final answer, or a turn that emitted no
    well-formed call) leaves `tool_name` None and records `model_text` only. When a
    single model turn emits several tool calls, each is its own row sharing
    `step_index` and distinguished by `call_index`.

    `tool_args` is the raw arguments exactly as the model produced them (JSON text),
    so the log preserves what was sent even when it was malformed; `tool_result` is
    the tool's returned text, possibly an error message.
    """

    run_id: int
    step_index: int
    model_text: str
    latency_ms: float
    call_index: int = 0
    tool_name: str | None = None
    tool_args: str | None = None
    tool_result: str | None = None
    tool_is_error: bool | None = None
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    step_id: int | None = None

    def __post_init__(self) -> None:
        for name in ("run_id", "step_index", "call_index"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(f"{name} must be an int")
            if not 0 <= value <= SQLITE_INT_MAX:
                raise ValueError(f"{name} out of range: {value}")
        if isinstance(self.latency_ms, bool) or not isinstance(self.latency_ms, int | float):
            raise TypeError("latency_ms must be a number")
        if not math.isfinite(self.latency_ms) or self.latency_ms < 0:
            raise ValueError("latency_ms must be finite and >= 0")
        for name in ("model_text", "created_at"):
            if not isinstance(getattr(self, name), str):
                raise TypeError(f"{name} must be a string")
        for name in ("tool_name", "tool_args", "tool_result"):
            value = getattr(self, name)
            if value is not None and not isinstance(value, str):
                raise TypeError(f"{name} must be a string or None")
        if self.tool_is_error is not None and not isinstance(self.tool_is_error, bool):
            raise TypeError("tool_is_error must be a bool or None")


@dataclass(frozen=True)
class VerdictRecord:
    """One deterministic oracle's verdict on one run, with the reasons it gave."""

    run_id: int
    oracle: str
    hit: bool
    reasons: tuple[str, ...] = ()
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    verdict_id: int | None = None

    def __post_init__(self) -> None:
        if isinstance(self.run_id, bool) or not isinstance(self.run_id, int):
            raise TypeError("run_id must be an int")
        if not 0 <= self.run_id <= SQLITE_INT_MAX:
            raise ValueError(f"run_id out of range: {self.run_id}")
        if not isinstance(self.oracle, str) or not self.oracle.strip():
            raise ValueError("oracle must be a non-empty string")
        if not isinstance(self.hit, bool):
            raise TypeError("hit must be a bool")
        if isinstance(self.reasons, str):
            raise TypeError("reasons must be a sequence of strings, not a string")
        object.__setattr__(self, "reasons", tuple(self.reasons))
        if not all(isinstance(r, str) for r in self.reasons):
            raise TypeError("reasons must be strings")
        if not isinstance(self.created_at, str):
            raise TypeError("created_at must be a string")


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

_STEP_COLUMNS = (
    "run_id",
    "step_index",
    "call_index",
    "tool_name",
    "tool_args",
    "tool_result",
    "tool_is_error",
    "model_text",
    "latency_ms",
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
        # A newer database may have columns or tables this code does not know about;
        # refuse it. An older one (v1) upgrades in place: the DDL is idempotent and
        # every v2 addition is a new table, so no data migration is needed.
        if version > SCHEMA_VERSION:
            raise RuntimeError(f"run log schema v{version} unsupported (expected {SCHEMA_VERSION})")
        with self._conn:
            self._conn.execute("PRAGMA foreign_keys = ON")
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

    def record_step(self, step: StepRecord) -> int:
        """Insert one agent step and return its step_id."""
        placeholders = ", ".join("?" for _ in _STEP_COLUMNS)
        row = asdict(step)
        params = [
            int(row[c]) if c == "tool_is_error" and row[c] is not None else row[c]
            for c in _STEP_COLUMNS
        ]
        with self._conn:
            cur = self._conn.execute(
                f"INSERT INTO steps ({', '.join(_STEP_COLUMNS)}) VALUES ({placeholders})",  # noqa: S608 - column names are constants
                params,
            )
        return int(cur.lastrowid)  # type: ignore[arg-type]

    def steps(self, run_id: int) -> Iterator[StepRecord]:
        rows = self._conn.execute(
            "SELECT * FROM steps WHERE run_id = ? ORDER BY step_index, call_index", (run_id,)
        )
        for row in rows:
            data = dict(row)
            if data["tool_is_error"] is not None:
                data["tool_is_error"] = bool(data["tool_is_error"])
            yield StepRecord(**data)

    def record_verdict(self, verdict: VerdictRecord) -> int:
        """Insert one oracle verdict and return its verdict_id."""
        with self._conn:
            cur = self._conn.execute(
                "INSERT INTO verdicts (run_id, oracle, hit, reasons, created_at)"
                " VALUES (?, ?, ?, ?, ?)",
                (
                    verdict.run_id,
                    verdict.oracle,
                    int(verdict.hit),
                    json.dumps(list(verdict.reasons), ensure_ascii=False),
                    verdict.created_at,
                ),
            )
        return int(cur.lastrowid)  # type: ignore[arg-type]

    def verdicts(self, run_id: int) -> Iterator[VerdictRecord]:
        rows = self._conn.execute(
            "SELECT * FROM verdicts WHERE run_id = ? ORDER BY verdict_id", (run_id,)
        )
        for row in rows:
            data = dict(row)
            data["hit"] = bool(data["hit"])
            data["reasons"] = tuple(json.loads(data["reasons"]))
            yield VerdictRecord(**data)

    def _verdict_hits(self, experiment_id: str, oracle: str) -> dict[int, bool]:
        rows = self._conn.execute(
            "SELECT v.run_id, v.hit FROM verdicts v JOIN runs r ON r.run_id = v.run_id"
            " WHERE r.experiment_id = ? AND v.oracle = ?",
            (experiment_id, oracle),
        )
        return {int(run_id): bool(hit) for run_id, hit in rows}

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
        - benign_input_violation_rate: benign runs where the agent acted unsafely on
                               legitimate input (the `benign_input_violation` oracle
                               fired), over benign runs that oracle scored. Separate
                               from completion: a run can finish the task and still
                               violate (e.g. send an email it was told not to send).

        Runs with outcome `error` are excluded from every rate and counted
        separately per case kind.
        """
        out: dict[str, ConfigMetrics] = {}
        rows = list(self.runs(experiment_id))
        violations = self._verdict_hits(experiment_id, BENIGN_VIOLATION_ORACLE)
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
            benign_scored = [r for r in benign if r.run_id in violations]
            benign_violated = sum(violations[r.run_id] for r in benign_scored)  # type: ignore[index]
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
                benign_runs_violation_scored=len(benign_scored),
                benign_input_violation_rate=_rate(benign_violated, len(benign_scored)),
            )
        return out
