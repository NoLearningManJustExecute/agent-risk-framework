"""Export the run log as structured security telemetry (JSONL, OpenTelemetry-shaped).

One JSON object per line, one trace per run. Each record is a span in the
OpenTelemetry sense (`trace_id`, `span_id`, `parent_span_id`, `name`, start and end
time, `attributes`), so a collector or SIEM can ingest the file without knowing this
schema. The chain per run is:

    agent.run                       the run: case, arm, controls, outcome bucket, credit
      guardrail.decision            run-level checks (tool definitions, the user prompt)
      agent.step                    one reasoning step: the model turn
        agent.tool_selection        the tool call the model chose in that step
          guardrail.decision        the policy outcome for that call or its result

Content is not exported by default. Model text, tool arguments and tool results can
hold attack payloads or the lab's canaries, so each is reduced to its SHA-256 and
length; `--include-content` adds the raw text. Decision reasons are exported as
written: the egress filter's reasons name placeholders, never the secret.

Ids are derived from the run's identity (experiment, case, run index), not from
database row ids, so the same run exports to the same trace in any copy of the log.

CLI:

    python -m agent_risk_framework.runlog.export --db runs/phase4.db --out runs/audit.jsonl
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections.abc import Iterable, Iterator
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, TextIO

from ..enums import DecisionAction
from .dal import DecisionRecord, RunLog, RunRecord, StepRecord

SCHEMA_URL = "agent-risk-framework/audit-log/v1"


def _hex(*parts: object, size: int) -> str:
    digest = hashlib.sha256("\x1f".join(str(p) for p in parts).encode("utf-8")).hexdigest()
    return digest[:size]


def trace_id(run: RunRecord) -> str:
    """32 hex digits, stable for a run's identity."""
    return _hex(run.experiment_id, run.case_kind, run.case_id, run.config, run.run_index, size=32)


def _span_id(trace: str, *parts: object) -> str:
    return _hex(trace, *parts, size=16)


def _content(prefix: str, text: str | None, include: bool) -> dict[str, Any]:
    if text is None:
        return {}
    out: dict[str, Any] = {
        f"{prefix}.sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
        f"{prefix}.length": len(text),
    }
    if include:
        out[prefix] = text
    return out


def _end(start: str, latency_ms: float) -> str:
    return (datetime.fromisoformat(start) + timedelta(milliseconds=latency_ms)).isoformat()


def _span(
    trace: str,
    span: str,
    parent: str | None,
    name: str,
    start: str,
    latency_ms: float,
    attributes: dict[str, Any],
    *,
    error: bool = False,
) -> dict[str, Any]:
    return {
        "schema_url": SCHEMA_URL,
        "trace_id": trace,
        "span_id": span,
        "parent_span_id": parent,
        "name": name,
        "start_time": start,
        "end_time": _end(start, latency_ms),
        "status": {"code": "ERROR" if error else "OK"},
        "attributes": attributes,
    }


def _decision(trace: str, parent: str, d: DecisionRecord) -> dict[str, Any]:
    blocked = d.action == DecisionAction.BLOCK
    record = _span(
        trace,
        _span_id(trace, "decision", d.seq),
        parent,
        "guardrail.decision",
        d.created_at,
        d.latency_ms,
        {
            "security.control": str(d.control),
            "security.stage": str(d.stage),
            "security.target": d.target,
            "security.policy.outcome": str(d.action),
            "security.policy.reasons": list(d.reasons),
            "security.decision.seq": d.seq,
            "agent.step.index": d.step_index,
            "agent.tool.call.index": d.call_index,
        },
        error=blocked,
    )
    record["severity_text"] = "WARN" if blocked else "INFO"
    return record


def run_records(
    log: RunLog, run: RunRecord, *, include_content: bool = False
) -> Iterator[dict[str, Any]]:
    """The spans for one run, root first, children after their parent."""
    if run.run_id is None:
        raise ValueError("run without an id")
    trace = trace_id(run)
    root = _span_id(trace, "run")
    attribution = log.attribution(run.run_id)
    controls = log.controls(run.run_id)
    yield _span(
        trace,
        root,
        None,
        "agent.run",
        run.created_at,
        run.latency_ms,
        {
            "experiment.id": run.experiment_id,
            "case.id": run.case_id,
            "case.kind": str(run.case_kind),
            "defense.config": str(run.config),
            "defense.controls": sorted(str(c) for c in controls or ()),
            "gen_ai.request.model": run.model,
            "gen_ai.request.seed": run.seed,
            "gen_ai.request.temperature": run.temperature,
            "run.index": run.run_index,
            "run.outcome": str(run.outcome),
            "run.guardrail_action": str(run.guardrail_action),
            "run.bucket": str(attribution.bucket) if attribution else None,
            "run.credited_controls": [str(c) for c in attribution.blocked_by]
            if attribution
            else [],
            "run.credit_basis": str(attribution.basis)
            if attribution and attribution.basis
            else None,
        },
    )

    decisions = list(log.decisions(run.run_id))
    for d in decisions:
        if d.step_index is None:
            yield _decision(trace, root, d)
    by_call: dict[tuple[int, int], list[DecisionRecord]] = {}
    for d in decisions:
        if d.step_index is not None:
            by_call.setdefault((d.step_index, d.call_index or 0), []).append(d)

    steps: dict[int, list[StepRecord]] = {}
    for s in log.steps(run.run_id):
        steps.setdefault(s.step_index, []).append(s)
    for index, calls in steps.items():
        step_span = _span_id(trace, "step", index)
        first = calls[0]
        yield _span(
            trace,
            step_span,
            root,
            "agent.step",
            first.created_at,
            sum(s.latency_ms for s in calls),
            {
                "agent.step.index": index,
                "agent.step.tool_calls": sum(1 for s in calls if s.tool_name is not None),
                **_content("gen_ai.completion", first.model_text, include_content),
            },
        )
        for s in calls:
            if s.tool_name is None:
                continue
            call_span = _span_id(trace, "call", index, s.call_index)
            yield _span(
                trace,
                call_span,
                step_span,
                "agent.tool_selection",
                s.created_at,
                0.0,
                {
                    "gen_ai.tool.name": s.tool_name,
                    "agent.step.index": index,
                    "agent.tool.call.index": s.call_index,
                    "agent.tool.executed": s.tool_result is not None,
                    "agent.tool.is_error": s.tool_is_error,
                    **_content("gen_ai.tool.arguments", s.tool_args, include_content),
                    **_content("gen_ai.tool.result", s.tool_result, include_content),
                },
                error=bool(s.tool_is_error),
            )
            for d in by_call.pop((index, s.call_index), []):
                yield _decision(trace, call_span, d)
    # Decisions on a call that left no step row (none expected) stay attached to the run.
    for leftover in by_call.values():
        for d in leftover:
            yield _decision(trace, root, d)


def export(
    log: RunLog,
    out: TextIO,
    *,
    experiments: Iterable[str] | None = None,
    include_content: bool = False,
) -> int:
    """Write every selected run as JSONL; return the number of records written."""
    wanted = set(experiments) if experiments else None
    count = 0
    for run in log.runs():
        if wanted is not None and run.experiment_id not in wanted:
            continue
        for record in run_records(log, run, include_content=include_content):
            out.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
            count += 1
    return count


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Export the run log as JSONL telemetry.")
    parser.add_argument("--db", required=True)
    parser.add_argument("--out", default="-", help="output path, or - for stdout")
    parser.add_argument(
        "--experiment", action="append", default=[], help="repeat to select experiments"
    )
    parser.add_argument("--include-content", action="store_true")
    args = parser.parse_args(argv)

    if not Path(args.db).is_file():
        parser.error(f"no run log at {args.db}")
    with RunLog(args.db) as log:
        if args.out == "-":
            n = export(
                log, sys.stdout, experiments=args.experiment, include_content=args.include_content
            )
        else:
            Path(args.out).parent.mkdir(parents=True, exist_ok=True)
            with open(args.out, "w", encoding="utf-8", newline="\n") as fh:
                n = export(
                    log, fh, experiments=args.experiment, include_content=args.include_content
                )
    sys.stderr.write(f"{n} records\n")


if __name__ == "__main__":
    main()
