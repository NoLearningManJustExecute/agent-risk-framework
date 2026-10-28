"""SQLite schema for the run log.

Three grains:

- `runs`     — one row per attack or benign run (the ablation grain from Phase 0).
- `steps`    — one row per agent step within a run (Phase 1): the model turn plus the
               tool call it dispatched, with raw arguments and the tool result. A step
               that produced no tool call (the agent's final answer) has a NULL
               `tool_name` and records `model_text` only.
- `verdicts` — one row per deterministic oracle evaluated on a run (Phase 2): the
               oracle name, whether it fired, and the reasons it gives. A run's
               `outcome` is derived from its primary oracle; secondary oracles (the
               benign-input violation check, tool-definition drift) live here only.

Schema v2 adds `steps` and v3 adds `verdicts`; older databases upgrade in place
because the DDL is idempotent (`CREATE TABLE IF NOT EXISTS`) and every addition is
a new table, never a new column on an existing one.
"""

from __future__ import annotations

from ..enums import CaseKind, DefenseConfig, DetectorVerdict, GuardrailAction, Outcome, values

SCHEMA_VERSION = 3


def _in(enum_cls) -> str:  # type: ignore[no-untyped-def]
    # Values come from our own enums, never from user input.
    return "(" + ", ".join(f"'{v}'" for v in values(enum_cls)) + ")"


DDL = f"""
CREATE TABLE IF NOT EXISTS runs (
    run_id              INTEGER PRIMARY KEY AUTOINCREMENT,
    experiment_id       TEXT    NOT NULL,
    case_id             TEXT    NOT NULL,
    case_kind           TEXT    NOT NULL CHECK (case_kind IN {_in(CaseKind)}),
    config              TEXT    NOT NULL CHECK (config IN {_in(DefenseConfig)}),
    run_index           INTEGER NOT NULL CHECK (run_index >= 0),
    seed                INTEGER NOT NULL,
    temperature         REAL    NOT NULL CHECK (temperature >= 0),
    model               TEXT    NOT NULL,
    outcome             TEXT    NOT NULL CHECK (outcome IN {_in(Outcome)}),
    detector_result     TEXT    NOT NULL CHECK (detector_result IN {_in(DetectorVerdict)}),
    guardrail_action    TEXT    NOT NULL CHECK (guardrail_action IN {_in(GuardrailAction)}),
    latency_ms          REAL    NOT NULL CHECK (latency_ms >= 0),
    detector_latency_ms REAL             CHECK (detector_latency_ms IS NULL
                                                OR detector_latency_ms >= 0),
    created_at          TEXT    NOT NULL,
    UNIQUE (experiment_id, case_kind, case_id, config, run_index)
);
CREATE INDEX IF NOT EXISTS idx_runs_experiment_config ON runs (experiment_id, config);

CREATE TABLE IF NOT EXISTS steps (
    step_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id        INTEGER NOT NULL REFERENCES runs (run_id),
    step_index    INTEGER NOT NULL CHECK (step_index >= 0),
    call_index    INTEGER NOT NULL CHECK (call_index >= 0),
    tool_name     TEXT,
    tool_args     TEXT,
    tool_result   TEXT,
    tool_is_error INTEGER CHECK (tool_is_error IN (0, 1)),
    model_text    TEXT    NOT NULL,
    latency_ms    REAL    NOT NULL CHECK (latency_ms >= 0),
    created_at    TEXT    NOT NULL,
    UNIQUE (run_id, step_index, call_index)
);
CREATE INDEX IF NOT EXISTS idx_steps_run ON steps (run_id, step_index, call_index);

CREATE TABLE IF NOT EXISTS verdicts (
    verdict_id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id     INTEGER NOT NULL REFERENCES runs (run_id),
    oracle     TEXT    NOT NULL,
    hit        INTEGER NOT NULL CHECK (hit IN (0, 1)),
    reasons    TEXT    NOT NULL,
    created_at TEXT    NOT NULL,
    UNIQUE (run_id, oracle)
);
CREATE INDEX IF NOT EXISTS idx_verdicts_run ON verdicts (run_id);
"""
