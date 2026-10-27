"""SQLite schema for the run log: one row per attack or benign run."""

from __future__ import annotations

from ..enums import CaseKind, DefenseConfig, DetectorVerdict, GuardrailAction, Outcome, values

SCHEMA_VERSION = 1


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
"""
