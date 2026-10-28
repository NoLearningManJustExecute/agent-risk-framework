from __future__ import annotations

import sqlite3

import pytest

from agent_risk_framework.runlog import SCHEMA_VERSION, RunLog, RunRecord, StepRecord


def a_run(log: RunLog) -> int:
    return log.record(
        RunRecord(
            experiment_id="exp-1",
            case_id="BT-001",
            case_kind="benign",
            config="baseline",
            run_index=0,
            seed=1337,
            temperature=0.0,
            model="fake-tools",
            outcome="succeeded",
            detector_result="not_evaluated",
            latency_ms=1.0,
        )
    )


def test_steps_record_and_read_back() -> None:
    with RunLog() as log:
        run_id = a_run(log)
        log.record_step(
            StepRecord(
                run_id=run_id,
                step_index=0,
                model_text="",
                latency_ms=12.0,
                tool_name="read_file",
                tool_args='{"path": "a.txt"}',
                tool_result="hello",
                tool_is_error=False,
            )
        )
        log.record_step(StepRecord(run_id=run_id, step_index=1, model_text="done", latency_ms=3.0))
        rows = list(log.steps(run_id))
    assert [(r.step_index, r.call_index, r.tool_name) for r in rows] == [
        (0, 0, "read_file"),
        (1, 0, None),
    ]
    assert rows[0].tool_is_error is False
    assert rows[0].tool_result == "hello"
    assert rows[1].tool_name is None and rows[1].model_text == "done"


def test_steps_ordered_by_step_then_call() -> None:
    with RunLog() as log:
        run_id = a_run(log)
        # insert out of order; read back must be sorted by (step_index, call_index)
        for step_index, call_index in [(1, 0), (0, 1), (0, 0)]:
            log.record_step(
                StepRecord(
                    run_id=run_id,
                    step_index=step_index,
                    call_index=call_index,
                    model_text="",
                    latency_ms=1.0,
                    tool_name="search_docs",
                    tool_args="{}",
                    tool_result="x",
                    tool_is_error=False,
                )
            )
        order = [(r.step_index, r.call_index) for r in log.steps(run_id)]
    assert order == [(0, 0), (0, 1), (1, 0)]


def test_duplicate_step_index_rejected() -> None:
    with RunLog() as log:
        run_id = a_run(log)
        log.record_step(StepRecord(run_id=run_id, step_index=0, model_text="", latency_ms=1.0))
        with pytest.raises(sqlite3.IntegrityError):
            log.record_step(StepRecord(run_id=run_id, step_index=0, model_text="", latency_ms=1.0))


def test_step_requires_existing_run() -> None:
    with RunLog() as log, pytest.raises(sqlite3.IntegrityError):
        # foreign_keys is ON: a step for a non-existent run is refused.
        log.record_step(StepRecord(run_id=999, step_index=0, model_text="", latency_ms=1.0))


def test_sql_check_rejects_bad_is_error_flag() -> None:
    with RunLog() as log:
        run_id = a_run(log)
        with pytest.raises(sqlite3.IntegrityError):
            log._conn.execute(
                "INSERT INTO steps (run_id, step_index, call_index, model_text, tool_is_error,"
                " latency_ms, created_at) VALUES (?,0,0,'',7,1,'t')",
                (run_id,),
            )


@pytest.mark.parametrize(
    "overrides",
    [
        {"step_index": -1},
        {"call_index": True},
        {"latency_ms": float("inf")},
        {"run_id": 1.5},
        {"model_text": None},
        {"tool_name": 3},
        {"tool_is_error": "no"},
    ],
)
def test_step_record_field_validation(overrides) -> None:
    base = dict(run_id=1, step_index=0, model_text="", latency_ms=1.0)
    base.update(overrides)
    with pytest.raises((TypeError, ValueError)):
        StepRecord(**base)


def test_v1_database_upgrades_in_place(tmp_path) -> None:
    db = tmp_path / "v1.db"
    conn = sqlite3.connect(db)
    # A minimal v1 database: the runs table only, user_version = 1, no steps table.
    conn.execute(
        "CREATE TABLE runs (run_id INTEGER PRIMARY KEY AUTOINCREMENT, experiment_id TEXT NOT NULL,"
        " case_id TEXT NOT NULL, case_kind TEXT NOT NULL, config TEXT NOT NULL,"
        " run_index INTEGER NOT NULL, seed INTEGER NOT NULL, temperature REAL NOT NULL,"
        " model TEXT NOT NULL, outcome TEXT NOT NULL, detector_result TEXT NOT NULL,"
        " guardrail_action TEXT NOT NULL, latency_ms REAL NOT NULL, detector_latency_ms REAL,"
        " created_at TEXT NOT NULL, UNIQUE (experiment_id, case_kind, case_id, config, run_index))"
    )
    conn.execute("PRAGMA user_version = 1")
    conn.commit()
    conn.close()
    with RunLog(db) as log:  # opening upgrades to the current version, adding new tables
        run_id = a_run(log)
        log.record_step(StepRecord(run_id=run_id, step_index=0, model_text="ok", latency_ms=1.0))
        assert len(list(log.steps(run_id))) == 1
        (version,) = log._conn.execute("PRAGMA user_version").fetchone()
    assert version == SCHEMA_VERSION == 4
