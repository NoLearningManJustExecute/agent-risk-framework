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

Phase 3 adds the guardrail grains:

- `decisions`    — the decision log: one row per guardrail evaluation (Phase 3): which
                   control, at which stage, on which input (`target`, plus the step
                   and call it belongs to), allow or block, and why. Allows are logged
                   too, so a control's false-positive cost can be read off the log.
- `attributions` — one row per completed run: its outcome bucket (`succeeded`,
                   `blocked_by_control`, `did_not_execute`, `failed_other`), which
                   control(s) get the credit, and on what basis.
- `run_controls` — the exact set of guardrails switched on for the run. `runs.config`
                   is the experiment's label; this is the ground truth Phase 4 keys on.

Schema v2 adds `steps`, v3 adds `verdicts`, v4 adds `decisions`, `attributions` and
`run_controls`; older databases upgrade in place because the DDL is idempotent
(`CREATE TABLE IF NOT EXISTS`) and every addition is a new table, never a new column
on an existing one.

v5 (Phase 3.5) adds no table; it widens the enum CHECK lists: the `egress_filter`
control, the `output_redacted` credit basis and the `single-control` config label.
SQLite cannot alter a CHECK constraint, so a v4 file opened here keeps its old lists:
it reads, and stores everything v4 could, but rejects the new values. Start a new
database for runs that use them.
"""

from __future__ import annotations

from ..enums import (
    BlockBasis,
    CaseKind,
    Control,
    DecisionAction,
    DecisionStage,
    DefenseConfig,
    DetectorVerdict,
    GuardrailAction,
    Outcome,
    OutcomeBucket,
    values,
)

SCHEMA_VERSION = 5


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

CREATE TABLE IF NOT EXISTS decisions (
    decision_id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id      INTEGER NOT NULL REFERENCES runs (run_id),
    seq         INTEGER NOT NULL CHECK (seq >= 0),
    control     TEXT    NOT NULL CHECK (control IN {_in(Control)}),
    stage       TEXT    NOT NULL CHECK (stage IN {_in(DecisionStage)}),
    target      TEXT    NOT NULL,
    action      TEXT    NOT NULL CHECK (action IN {_in(DecisionAction)}),
    reasons     TEXT    NOT NULL,
    step_index  INTEGER          CHECK (step_index IS NULL OR step_index >= 0),
    call_index  INTEGER          CHECK (call_index IS NULL OR call_index >= 0),
    latency_ms  REAL    NOT NULL CHECK (latency_ms >= 0),
    created_at  TEXT    NOT NULL,
    UNIQUE (run_id, seq)
);
CREATE INDEX IF NOT EXISTS idx_decisions_run ON decisions (run_id, seq);

CREATE TABLE IF NOT EXISTS attributions (
    run_id     INTEGER PRIMARY KEY REFERENCES runs (run_id),
    bucket     TEXT    NOT NULL CHECK (bucket IN {_in(OutcomeBucket)}),
    blocked_by TEXT    NOT NULL,
    basis      TEXT             CHECK (basis IS NULL OR basis IN {_in(BlockBasis)}),
    reasons    TEXT    NOT NULL,
    created_at TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS run_controls (
    run_id     INTEGER PRIMARY KEY REFERENCES runs (run_id),
    controls   TEXT    NOT NULL,
    created_at TEXT    NOT NULL
);
"""
