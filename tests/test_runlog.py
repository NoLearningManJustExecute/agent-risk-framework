from __future__ import annotations

import sqlite3

import pytest

from agent_risk_framework.enums import DefenseConfig, DetectorVerdict, GuardrailAction, Outcome
from agent_risk_framework.runlog import RunLog, RunRecord


def rec(**overrides) -> RunRecord:
    base = dict(
        experiment_id="exp-1",
        case_id="AC01",
        case_kind="attack",
        config="baseline",
        run_index=0,
        seed=1337,
        temperature=0.0,
        model="fake-llm",
        outcome="succeeded",
        detector_result="not_detected",
        latency_ms=12.5,
    )
    base.update(overrides)
    return RunRecord(**base)


def test_record_and_read_back(tmp_path) -> None:
    db = tmp_path / "runs.db"
    with RunLog(db) as log:
        run_id = log.record(rec(detector_latency_ms=0.4))
    with RunLog(db) as log:  # reopen: data persisted, schema reused
        (row,) = list(log.runs("exp-1"))
    assert row.run_id == run_id
    assert row.config is DefenseConfig.BASELINE
    assert row.outcome is Outcome.SUCCEEDED
    assert row.guardrail_action is GuardrailAction.NONE
    assert row.detector_latency_ms == 0.4


def test_duplicate_run_index_rejected() -> None:
    with RunLog() as log:
        log.record(rec())
        with pytest.raises(sqlite3.IntegrityError):
            log.record(rec())


def test_invalid_enum_rejected_before_sql() -> None:
    with pytest.raises(ValueError):
        rec(config="yolo")


def test_sql_check_constraints_backstop_raw_inserts() -> None:
    with RunLog() as log, pytest.raises(sqlite3.IntegrityError):
        log._conn.execute(
            "INSERT INTO runs (experiment_id, case_id, case_kind, config, run_index, seed,"
            " temperature, model, outcome, detector_result, guardrail_action, latency_ms,"
            " created_at) VALUES ('e','c','attack','baseline',0,1,0,'m','pwned',"
            "'detected','none',1,'t')"
        )


def test_hostile_strings_stored_verbatim() -> None:
    nasty = "AC01'); DROP TABLE runs;--"
    with RunLog() as log:
        log.record(rec(case_id=nasty))
        assert next(log.runs()).case_id == nasty


def test_unsupported_schema_version_refused(tmp_path) -> None:
    db = tmp_path / "future.db"
    conn = sqlite3.connect(db)
    conn.execute("PRAGMA user_version = 99")
    conn.close()
    with pytest.raises(RuntimeError, match="schema"):
        RunLog(db)


def test_metrics_per_config() -> None:
    with RunLog() as log:
        # baseline: 4 attack runs, 3 succeed, detector never fires; 2 benign both completed
        for i, outcome in enumerate(["succeeded", "succeeded", "succeeded", "failed"]):
            log.record(rec(run_index=i, outcome=outcome))
        for i in range(2):
            log.record(rec(case_id="BT-001", case_kind="benign", run_index=i))

        # combined: 4 attacks (1 succeeds, 3 detected+blocked), 1 error, 2 benign (1 flagged)
        for i in range(4):
            caught = i > 0
            log.record(
                rec(
                    config="combined",
                    run_index=i,
                    outcome="failed" if caught else "succeeded",
                    detector_result="detected" if caught else "not_detected",
                    guardrail_action="blocked" if caught else "none",
                    detector_latency_ms=2.0,
                )
            )
        log.record(rec(config="combined", run_index=9, outcome="error"))
        log.record(
            rec(
                config="combined",
                case_id="BT-001",
                case_kind="benign",
                run_index=0,
                detector_result="detected",
                guardrail_action="blocked",
                outcome="failed",
                detector_latency_ms=4.0,
            )
        )
        log.record(rec(config="combined", case_id="BT-001", case_kind="benign", run_index=1))

        # another experiment must not leak into these metrics
        log.record(rec(experiment_id="other", config="combined", run_index=0))

        m = log.metrics("exp-1")

    base, comb = m["baseline"], m["combined"]
    assert base.attack_success_rate == 0.75
    assert base.detection_rate == 0.0
    assert base.false_negative_rate == 1.0
    assert base.false_positive_rate == 0.0
    assert base.benign_task_completion_rate == 1.0
    assert base.mean_detection_latency_ms is None

    assert comb.attack_runs == 4
    assert comb.attack_runs_evaluated == 4
    assert (comb.attack_errors, comb.benign_errors) == (1, 0)
    assert comb.attack_success_rate == 0.25
    assert comb.detection_rate == 0.75
    assert comb.false_negative_rate == 0.25
    assert comb.blocked_action_rate == 0.75
    assert comb.false_positive_rate == 0.5
    assert comb.benign_task_completion_rate == 0.5
    assert comb.mean_detection_latency_ms == pytest.approx((2.0 * 4 + 4.0) / 5)


def test_not_evaluated_runs_excluded_from_detector_rates_and_counted() -> None:
    with RunLog() as log:
        log.record(
            rec(run_index=0, detector_result=DetectorVerdict.NOT_EVALUATED, detector_latency_ms=99)
        )
        log.record(
            rec(run_index=1, detector_result=DetectorVerdict.DETECTED, detector_latency_ms=1)
        )
        m = log.metrics("exp-1")["baseline"]
    assert m.detection_rate == 1.0
    assert m.false_negative_rate == 0.0
    assert (m.attack_runs, m.attack_runs_evaluated) == (2, 1)  # partial denominator is visible
    assert m.mean_detection_latency_ms == 1.0  # not_evaluated latency ignored
    assert m.false_positive_rate is None  # no benign runs: rate undefined, not zero


def test_benign_run_blocked_without_detection_is_a_false_positive() -> None:
    with RunLog() as log:
        log.record(
            rec(
                case_id="BT-001",
                case_kind="benign",
                outcome="failed",
                detector_result="not_evaluated",
                guardrail_action="blocked",
            )
        )
        log.record(rec(case_id="BT-002", case_kind="benign"))
        m = log.metrics("exp-1")["baseline"]
    assert m.false_positive_rate == 0.5
    assert m.benign_task_completion_rate == 0.5


def test_attack_and_benign_runs_may_share_a_case_id() -> None:
    with RunLog() as log:
        log.record(rec(case_id="X1"))
        log.record(rec(case_id="X1", case_kind="benign"))
        assert len(list(log.runs())) == 2


@pytest.mark.parametrize(
    "overrides",
    [
        {"seed": 1.5},
        {"seed": True},
        {"seed": 2**63},
        {"run_index": -1},
        {"temperature": "0.5"},
        {"latency_ms": float("inf")},
        {"detector_latency_ms": float("nan")},
        {"case_id": ""},
    ],
)
def test_run_record_field_validation(overrides) -> None:
    with pytest.raises((TypeError, ValueError)):
        rec(**overrides)


def test_failed_open_releases_file_handle(tmp_path) -> None:
    db = tmp_path / "incompatible.db"
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE runs (only_column TEXT)")
    conn.commit()
    conn.close()
    with pytest.raises(sqlite3.OperationalError):
        RunLog(db)
    db.unlink()  # would raise PermissionError on Windows if the handle leaked
