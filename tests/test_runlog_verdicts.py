from __future__ import annotations

import sqlite3

import pytest

from agent_risk_framework.runlog import (
    BENIGN_VIOLATION_ORACLE,
    SCHEMA_VERSION,
    RunLog,
    RunRecord,
    VerdictRecord,
)


def a_run(log: RunLog, **overrides) -> int:
    base = dict(
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
    base.update(overrides)
    return log.record(RunRecord(**base))


def test_verdict_record_and_read_back() -> None:
    with RunLog() as log:
        run_id = a_run(log)
        log.record_verdict(VerdictRecord(run_id, "task_success", True, ("ok",)))
        log.record_verdict(
            VerdictRecord(run_id, BENIGN_VIOLATION_ORACLE, False, ("hostile 'quote'; --",))
        )
        got = list(log.verdicts(run_id))
    assert [(v.oracle, v.hit, v.reasons) for v in got] == [
        ("task_success", True, ("ok",)),
        (BENIGN_VIOLATION_ORACLE, False, ("hostile 'quote'; --",)),
    ]


def test_one_verdict_per_oracle_per_run() -> None:
    with RunLog() as log:
        run_id = a_run(log)
        log.record_verdict(VerdictRecord(run_id, "x", True))
        with pytest.raises(sqlite3.IntegrityError):
            log.record_verdict(VerdictRecord(run_id, "x", False))


def test_verdict_requires_existing_run() -> None:
    with RunLog() as log, pytest.raises(sqlite3.IntegrityError):
        log.record_verdict(VerdictRecord(999, "x", True))


@pytest.mark.parametrize(
    "overrides",
    [
        {"run_id": "1"},
        {"run_id": True},
        {"run_id": -1},
        {"oracle": ""},
        {"hit": 1},
        {"reasons": "not-a-tuple"},
        {"reasons": (1,)},
    ],
)
def test_verdict_record_field_validation(overrides) -> None:
    base = dict(run_id=1, oracle="x", hit=True, reasons=())
    base.update(overrides)
    with pytest.raises((TypeError, ValueError)):
        VerdictRecord(**base)


def test_benign_violation_rate_is_separate_from_completion() -> None:
    # Four benign runs: completion and violation vary independently.
    combos = [(True, False), (True, True), (False, False), (False, True)]
    with RunLog() as log:
        for i, (done, violated) in enumerate(combos):
            run_id = a_run(log, run_index=i, outcome="succeeded" if done else "failed")
            log.record_verdict(VerdictRecord(run_id, BENIGN_VIOLATION_ORACLE, violated))
        # An unscored benign run (no violation verdict) is excluded from that denominator only.
        a_run(log, run_index=9)
        # An errored run is excluded from both.
        err = a_run(log, run_index=10, outcome="error")
        log.record_verdict(VerdictRecord(err, BENIGN_VIOLATION_ORACLE, True))
        # Another experiment's verdicts must not leak in.
        other = a_run(log, experiment_id="other")
        log.record_verdict(VerdictRecord(other, BENIGN_VIOLATION_ORACLE, True))
        m = log.metrics("exp-1")["baseline"]
    assert m.benign_runs == 5
    assert m.benign_task_completion_rate == 3 / 5
    assert m.benign_runs_violation_scored == 4
    assert m.benign_input_violation_rate == 2 / 4
    assert m.benign_errors == 1


def test_violation_rate_none_without_scored_runs() -> None:
    with RunLog() as log:
        a_run(log)
        m = log.metrics("exp-1")["baseline"]
    assert m.benign_runs_violation_scored == 0
    assert m.benign_input_violation_rate is None


def test_v2_database_upgrades_to_current(tmp_path) -> None:
    db = tmp_path / "v2.db"
    with RunLog(db) as log:
        run_id = a_run(log)
        log._conn.execute("DROP TABLE verdicts")
        log._conn.execute("PRAGMA user_version = 2")
        log._conn.commit()
    with RunLog(db) as log:
        log.record_verdict(VerdictRecord(run_id, "x", True))
        assert len(list(log.verdicts(run_id))) == 1
        (version,) = log._conn.execute("PRAGMA user_version").fetchone()
    assert version == SCHEMA_VERSION
