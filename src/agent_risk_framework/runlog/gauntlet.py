"""Export the run log as gauntlet traces and labels (agent-detection-gauntlet schema 0.2).

One run becomes one trace; each line is one event. Per run, in order:

    session.start
      retrieval          one per tool definition the MCP server listed (data source
                         `mcp.tool_definition`); trusted only if it matches the registry
      guardrail.action   tool-definition checks (tool_integrity)
      user.prompt        the user message (trusted)
      guardrail.action   prompt checks (input_classifier)
      per agent step:
        llm.request      the first one carries the stated policy (the system prompt
                         minus its tool list, which the retrievals above carry)
        llm.response     the model's text for the turn
        tool.call        one per call the model made
          guardrail.action  checks on the call
          tool.result    what the tool returned (absent when a guardrail blocked the call)
          guardrail.action  checks on the result
    session.end

Ground truth never enters a trace: the trace id is a hash of the run's identity, and
case, arm, outcome and oracle verdicts go to the labels file only. Attribute names
follow the OpenTelemetry GenAI conventions the gauntlet schema pins; everything else
is `adg.*`. Provenance (trust, data labels, content references) is described in
`provenance.py` and docs/gauntlet_export.md.

The run log stores model latencies, not a wall-clock time per event, so timestamps are
reconstructed: every trace starts at the same fixed epoch (`EPOCH`), each step advances
by its model latency, and events within a step are one microsecond apart. Real start
times are dropped on purpose: the lab runs every attack before any benign task, so wall
time alone would separate the labels. For the same reason files list traces in trace-id
order, not run order.

`tool.result` carries what the tool returned, as the run log stores it. When a guardrail
withheld or redacted the result, the model saw less; the `guardrail.action` that follows
says so.

Every exported file is scanned with the leak guard (`tools/leak_guard.py --text`); any
hit, or a missing guard, aborts the export and removes what was written.

CLI:

    python -m agent_risk_framework.runlog.gauntlet --db runs/phase4.db \\
        --experiment phase4-baseline --experiment phase4-combined \\
        --out runs/gauntlet --model-digest <ollama digest>
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
from collections.abc import Callable, Iterable, Iterator, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import anyio

from ..agent.client import connect_in_process, list_tool_defs
from ..agent.model import ToolDef
from ..agent.policy import STATED_POLICY
from ..attacks.lab import apply_post_approval, build_lab_server, lab_sandbox
from ..attacks.scenarios import AttackScenario, load_catalog
from ..benign import BenignTask, load_benign_tasks
from ..enums import CaseKind, DecisionAction, DecisionStage, DefenseConfig, Outcome
from ..guardrails.integrity import DEFAULT_REGISTRY, ToolRegistry, definition_hash
from .dal import DecisionRecord, RunLog, RunRecord, StepRecord
from .provenance import (
    DEFAULT_K,
    SEARCH_SOURCE,
    TRUSTED,
    UNTRUSTED,
    classify_path,
    content_labels,
    host_identifiers,
    ordered_labels,
    overlap_refs,
    redact,
)

SCHEMA_VERSION = "0.2"
SOURCE = "agent-risk-framework"
AGENT_NAME = "agent-risk-framework"
PROVIDER = "ollama"
DEFAULT_SCENARIOS = Path("data/attack_scenarios.json")
DEFAULT_BENIGN = Path("data/benign_tasks.json")
DEFAULT_LEAK_GUARD = Path("tools/leak_guard.py")
TICK = timedelta(microseconds=1)
# Every trace starts here. Real start times would leak the label: the lab runs all attack
# cases before the benign tasks, so wall-clock time alone separates them.
EPOCH = datetime(2026, 1, 1, tzinfo=UTC)

# Decision stage in the run log -> adg.guardrail.stage.
_STAGES = {
    DecisionStage.USER_PROMPT: "user_prompt",
    DecisionStage.TOOL_DEFINITION: "tool_definition",
    DecisionStage.TOOL_CALL: "tool_call",
    DecisionStage.TOOL_RESULT: "tool_result",
}


class ExportError(RuntimeError):
    """The export cannot be completed safely; nothing is left behind."""


def trace_id(run: RunRecord) -> str:
    """Opaque and stable: a hash of the run's identity, so the id carries no label."""
    ident = "\x1f".join(
        str(p) for p in (run.experiment_id, run.case_kind, run.case_id, run.config, run.run_index)
    )
    return "arf-" + hashlib.sha256(ident.encode("utf-8")).hexdigest()[:24]


def source_run_id(run: RunRecord) -> str:
    return f"{run.experiment_id}:{run.case_kind}:{run.case_id}:{run.run_index}"


def attack_class(scenario_id: str) -> str:
    """The scenario family: AC01 and its obfuscated variant AC01-OBF are one class."""
    return scenario_id.removesuffix("-OBF")


def condition(run: RunRecord, controls: frozenset[str]) -> str:
    """The experiment arm: baseline, combined, or the single control switched on."""
    if run.config in (DefenseConfig.SINGLE_CONTROL, DefenseConfig.CLASSIFIER_ONLY) and (
        len(controls) == 1
    ):
        return next(iter(controls))
    return str(run.config)


def _stamp(value: datetime) -> str:
    # Fixed width (always six fraction digits), so string order is time order.
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _args_text(raw: str | None) -> tuple[Any, str]:
    """Tool arguments as JSON (or the raw string) plus the text used for provenance.

    The text is `key: value` per argument, values decoded, so an email body that copies
    a file keeps the file's own line breaks and can match it verbatim.
    """
    if raw is None:
        return None, ""
    try:
        parsed = json.loads(raw)
    except ValueError:
        return raw, raw
    if isinstance(parsed, dict):
        lines = []
        for key in sorted(parsed):
            value = parsed[key]
            shown = value if isinstance(value, str) else json.dumps(value, sort_keys=True)
            lines.append(f"{key}: {shown}")
        return parsed, "\n".join(lines)
    return parsed, json.dumps(parsed, sort_keys=True)


def _tool_line(tool: ToolDef) -> str:
    params = ", ".join((tool.parameters.get("properties") or {}).keys())
    return f"{tool.name}({params}): {tool.description}"


async def _listed_tools(scenario: AttackScenario | None) -> list[ToolDef]:
    with lab_sandbox(scenario) as sandbox:
        server = build_lab_server(sandbox, scenario)
        async with connect_in_process(server) as client:
            approved = await list_tool_defs(client)
            if apply_post_approval(server, scenario):
                return await list_tool_defs(client)
            return approved


@dataclass
class Catalog:
    """What the run log does not store: prompts and the tool list each case saw."""

    scenarios: dict[str, AttackScenario]
    tasks: dict[str, BenignTask]
    registry: ToolRegistry
    _tools: dict[str | None, list[ToolDef]] = field(default_factory=dict)

    @classmethod
    def load(
        cls,
        scenarios: Path | str = DEFAULT_SCENARIOS,
        benign: Path | str = DEFAULT_BENIGN,
        registry: Path | str = DEFAULT_REGISTRY,
    ) -> Catalog:
        catalog = load_catalog(scenarios)
        return cls(
            {s.scenario_id: s for s in catalog.scenarios},
            {t.task_id: t for t in load_benign_tasks(benign)},
            ToolRegistry.load(registry),
        )

    def prompt(self, run: RunRecord) -> str:
        if run.case_kind == CaseKind.ATTACK:
            return self.scenario(run.case_id).user_prompt
        task = self.tasks.get(run.case_id)
        if task is None:
            raise ExportError(f"benign task {run.case_id} is not in the task file")
        return task.prompt

    def scenario(self, case_id: str) -> AttackScenario:
        scenario = self.scenarios.get(case_id)
        if scenario is None:
            raise ExportError(f"attack scenario {case_id} is not in the scenario file")
        return scenario

    def tools(self, run: RunRecord) -> list[ToolDef]:
        key = run.case_id if run.case_kind == CaseKind.ATTACK else None
        if key not in self._tools:
            scenario = self.scenario(run.case_id) if key is not None else None
            self._tools[key] = anyio.run(_listed_tools, scenario)
        return self._tools[key]

    def reviewed(self, tool: ToolDef) -> bool:
        entry = self.registry.tools.get(tool.name)
        return entry is not None and entry.sha256 == definition_hash(tool)


@dataclass
class _Event:
    span: str
    parent: str | None
    event_type: str
    at: datetime
    attributes: dict[str, Any]
    text: str | None = None  # provenance text; None: not content-bearing for refs


@dataclass
class _Builder:
    trace: str
    clock: datetime
    redactor: Callable[[str], str]
    events: list[_Event] = field(default_factory=list)

    def add(
        self,
        event_type: str,
        parent: str | None,
        attributes: dict[str, Any],
        text: str | None = None,
        *,
        trust: str | None = None,
        labels: Iterable[str] = (),
    ) -> str:
        span = f"e{len(self.events):03d}"
        attrs = dict(attributes)
        if text:
            text = self.redactor(text)
            attrs["adg.content.text"] = text
            found = ordered_labels({*labels, *content_labels(text)})
            if found:
                attrs["adg.data.labels"] = found
        if trust is not None:
            attrs["adg.source.trust"] = trust
        self.events.append(_Event(span, parent, event_type, self.clock, attrs, text or None))
        self.clock += TICK
        return span


def _guardrail(b: _Builder, parent: str, d: DecisionRecord) -> None:
    decision = "allow"
    if d.action == DecisionAction.BLOCK:
        redacted = str(d.control) == "egress_filter" and any(
            r.startswith("redacted") for r in d.reasons
        )
        decision = "redact" if redacted else "block"
    b.add(
        "guardrail.action",
        parent,
        {
            "adg.guardrail.decision": decision,
            "adg.guardrail.name": str(d.control),
            "adg.guardrail.stage": _STAGES[DecisionStage(d.stage)],
        },
    )


def _result_source(call: StepRecord, untrusted_tools: set[str]) -> tuple[str, tuple[str, ...]]:
    if call.tool_name in untrusted_tools:
        return UNTRUSTED, ()
    if call.tool_name == "read_file":
        args, _ = _args_text(call.tool_args)
        path = args.get("path") if isinstance(args, dict) else None
        if not isinstance(path, str):
            return TRUSTED, ()
        if call.tool_result == f"No file at {path!r}.":
            return TRUSTED, ()  # the harness's own message, no file content
        source = classify_path(path)
        return source.trust, source.labels
    if call.tool_name == "search_docs":
        return SEARCH_SOURCE
    return TRUSTED, ()


def build_trace(
    log: RunLog,
    run: RunRecord,
    catalog: Catalog,
    *,
    ks: Sequence[int] = (DEFAULT_K,),
    redactor: Callable[[str], str] = redact,
) -> dict[int, list[dict[str, Any]]]:
    """The events of one run as gauntlet trace lines, one version per content-ref K.

    The versions differ only in `adg.content.ref`.
    """
    if run.run_id is None:
        raise ExportError("run without an id")
    steps = list(log.steps(run.run_id))
    decisions = list(log.decisions(run.run_id))
    trace = trace_id(run)
    b = _Builder(trace, EPOCH, redactor)
    model = {"gen_ai.request.model": run.model, "gen_ai.provider.name": PROVIDER}

    start_attrs: dict[str, Any] = {
        "gen_ai.operation.name": "invoke_agent",
        "gen_ai.agent.name": AGENT_NAME,
        "gen_ai.conversation.id": trace,
        **model,
    }
    root = b.add("session.start", None, start_attrs)

    early = [d for d in decisions if d.step_index is None]
    untrusted_tools: set[str] = set()
    for tool in catalog.tools(run):
        reviewed = catalog.reviewed(tool)
        if not reviewed:
            untrusted_tools.add(tool.name)
        b.add(
            "retrieval",
            root,
            {
                "gen_ai.operation.name": "retrieval",
                "gen_ai.data_source.id": "mcp.tool_definition",
                "gen_ai.tool.name": tool.name,
            },
            _tool_line(tool),
            trust=TRUSTED if reviewed else UNTRUSTED,
            labels=("internal",),
        )
    for d in early:
        if d.stage == DecisionStage.TOOL_DEFINITION:
            _guardrail(b, root, d)
    prompt = b.add(
        "user.prompt", root, {}, catalog.prompt(run), trust=TRUSTED, labels=("internal",)
    )
    for d in early:
        if d.stage != DecisionStage.TOOL_DEFINITION:
            _guardrail(b, prompt, d)

    by_call: dict[tuple[int, int], list[DecisionRecord]] = {}
    for d in decisions:
        if d.step_index is not None:
            by_call.setdefault((d.step_index, d.call_index or 0), []).append(d)
    by_step: dict[int, list[StepRecord]] = {}
    for s in steps:
        by_step.setdefault(s.step_index, []).append(s)

    clock = b.clock
    for index in sorted(by_step):
        calls = sorted(by_step[index], key=lambda s: s.call_index)
        first = calls[0]
        b.clock = clock
        request_attrs = {
            "gen_ai.operation.name": "chat",
            "gen_ai.request.temperature": run.temperature,
            "gen_ai.request.seed": run.seed,
            **model,
        }
        if index == 0:
            request = b.add(
                "llm.request",
                root,
                request_attrs,
                STATED_POLICY,
                trust=TRUSTED,
                labels=("internal",),
            )
        else:
            request = b.add("llm.request", root, request_attrs)
        clock = clock + timedelta(milliseconds=first.latency_ms)
        b.clock = max(b.clock, clock)
        response_attrs = {"gen_ai.operation.name": "chat", "gen_ai.response.model": run.model}
        response = b.add("llm.response", request, response_attrs, first.model_text or None)
        for s in calls:
            if s.tool_name is None:
                continue
            args, args_text = _args_text(s.tool_args)
            call_id = f"{trace}:{index}:{s.call_index}"
            call = b.add(
                "tool.call",
                response,
                {
                    "gen_ai.operation.name": "execute_tool",
                    "gen_ai.tool.name": s.tool_name,
                    "gen_ai.tool.call.id": call_id,
                    "gen_ai.tool.call.arguments": _redact_json(args, b.redactor),
                },
                args_text or None,
            )
            mine = by_call.pop((index, s.call_index), [])
            blocked = False
            for d in mine:
                if d.stage == DecisionStage.TOOL_CALL:
                    _guardrail(b, call, d)
                    blocked = blocked or d.action == DecisionAction.BLOCK
            if not blocked and s.tool_result is not None:
                trust, labels = _result_source(s, untrusted_tools)
                b.add(
                    "tool.result",
                    call,
                    {
                        "gen_ai.operation.name": "execute_tool",
                        "gen_ai.tool.name": s.tool_name,
                        "gen_ai.tool.call.id": call_id,
                        "gen_ai.tool.call.result": b.redactor(s.tool_result),
                    },
                    s.tool_result or None,
                    trust=trust,
                    labels=labels,
                )
            for d in mine:
                if d.stage != DecisionStage.TOOL_CALL:
                    _guardrail(b, call, d)
        clock = b.clock
    for leftover in by_call.values():
        for d in leftover:
            _guardrail(b, root, d)
    b.add("session.end", root, {})

    versions: dict[int, list[dict[str, Any]]] = {}
    for k in ks:
        refs = overlap_refs([e.text for e in b.events], k)
        lines = []
        for event, mine in zip(b.events, refs, strict=True):
            attrs = dict(event.attributes)
            if mine:
                attrs["adg.content.ref"] = [b.events[j].span for j in mine]
            lines.append(
                {
                    "schema_version": SCHEMA_VERSION,
                    "trace_id": trace,
                    "span_id": event.span,
                    "parent_span_id": event.parent,
                    "timestamp": _stamp(event.at),
                    "event_type": event.event_type,
                    "attributes": attrs,
                }
            )
        _check_integrity(lines)
        versions[k] = lines
    return versions


def _redact_json(value: Any, redactor: Callable[[str], str]) -> Any:
    if isinstance(value, str):
        return redactor(value)
    if isinstance(value, list):
        return [_redact_json(v, redactor) for v in value]
    if isinstance(value, dict):
        return {redactor(str(k)): _redact_json(v, redactor) for k, v in value.items()}
    return value


def _check_integrity(lines: Sequence[dict[str, Any]]) -> None:
    """The cross-event rules the gauntlet reader enforces, checked before writing."""
    seen: dict[str, int] = {}
    order = sorted(range(len(lines)), key=lambda i: (lines[i]["timestamp"], lines[i]["span_id"]))
    if order != list(range(len(lines))):
        raise ExportError(f"{lines[0]['trace_id']}: events are not in canonical order")
    for i, line in enumerate(lines):
        span = line["span_id"]
        if span in seen:
            raise ExportError(f"{line['trace_id']}: duplicate span {span}")
        parent = line["parent_span_id"]
        if parent is not None and parent not in seen:
            raise ExportError(f"{line['trace_id']}: parent {parent} of {span} is not earlier")
        for ref in line["attributes"].get("adg.content.ref", []):
            if ref not in seen:
                raise ExportError(f"{line['trace_id']}: {span} refs {ref}, not earlier")
        seen[span] = i


def label(run: RunRecord, controls: frozenset[str]) -> dict[str, Any]:
    """The run's ground truth. The attack outcome is the scenario's deterministic oracle."""
    malicious = run.case_kind == CaseKind.ATTACK
    return {
        "schema_version": SCHEMA_VERSION,
        "trace_id": trace_id(run),
        "label": "malicious" if malicious else "benign",
        "attack_class": attack_class(run.case_id) if malicious else None,
        "attack_succeeded": (run.outcome == Outcome.SUCCEEDED) if malicious else None,
        "mutation": None,
        "guardrails": "on" if controls else "off",
        "split": None,
        "source": SOURCE,
        "scenario_id": run.case_id if malicious else None,
        "task_id": None if malicious else run.case_id,
        "condition": condition(run, controls),
        "source_run_id": source_run_id(run),
    }


def _dump(record: dict[str, Any]) -> str:
    return json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


@dataclass(frozen=True)
class ExportSummary:
    runs: int
    skipped_errors: int
    files: tuple[Path, ...]


def selected_runs(log: RunLog, experiments: Sequence[str]) -> Iterator[RunRecord]:
    for experiment in experiments:
        found = False
        for run in log.runs(experiment):
            found = True
            yield run
        if not found:
            raise ExportError(f"no runs for experiment {experiment!r} in the run log")


def export(
    log: RunLog,
    out: Path,
    experiments: Sequence[str],
    catalog: Catalog,
    *,
    ks: Sequence[int] = (DEFAULT_K,),
    redactor: Callable[[str], str] | None = None,
) -> ExportSummary:
    """Write `<out>/k<K>/traces/<experiment>.jsonl` per K and one `<out>/labels.jsonl`.

    Traces and labels are written in trace-id order, never run-log order: the lab runs
    attacks before benign tasks, so file position would give the label away.
    """
    if redactor is None:
        identifiers = host_identifiers()

        def redactor(text: str) -> str:
            return redact(text, identifiers)

    traces: dict[tuple[int, str], dict[str, list[dict[str, Any]]]] = {}
    labels: dict[str, dict[str, Any]] = {}
    skipped = 0
    for run in selected_runs(log, experiments):
        if run.outcome == Outcome.ERROR or run.run_id is None:
            skipped += 1
            continue
        controls = frozenset(str(c) for c in (log.controls(run.run_id) or ()))
        for k, lines in build_trace(log, run, catalog, ks=ks, redactor=redactor).items():
            traces.setdefault((k, run.experiment_id), {})[trace_id(run)] = lines
        labels[trace_id(run)] = label(run, controls)

    out.mkdir(parents=True, exist_ok=True)
    files = [out / "labels.jsonl"]
    _write_lines(files[0], (labels[t] for t in sorted(labels)))
    for (k, experiment), by_trace in sorted(traces.items()):
        path = out / f"k{k}" / "traces" / f"{experiment}.jsonl"
        _write_lines(path, (line for t in sorted(by_trace) for line in by_trace[t]))
        files.append(path)
    return ExportSummary(len(labels), skipped, tuple(files))


def _write_lines(path: Path, records: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        for record in records:
            fh.write(_dump(record) + "\n")


EXPORT_ENTRIES = frozenset({"export_manifest.json", "labels.jsonl"})


def _is_previous_export(path: Path) -> bool:
    """Only the exporter's own layout: the manifest, labels, and k<N>/traces/*.jsonl."""
    if not (path / "export_manifest.json").is_file():
        return False
    for entry in path.iterdir():
        if entry.name in EXPORT_ENTRIES and entry.is_file():
            continue
        if not (entry.is_dir() and entry.name[:1] == "k" and entry.name[1:].isdigit()):
            return False
        inner = list(entry.iterdir())
        if [i.name for i in inner] != ["traces"] or not inner[0].is_dir():
            return False
        if any(f.suffix != ".jsonl" or not f.is_file() for f in inner[0].iterdir()):
            return False
    return True


def leak_guard(files: Sequence[Path], guard: Path = DEFAULT_LEAK_GUARD) -> None:
    """Scan every file with the leak guard. A hit or a missing guard raises."""
    if not guard.is_file():
        raise ExportError(f"leak guard not found at {guard.as_posix()}; refusing to export")
    args = [sys.executable, str(guard)]
    for f in files:
        args += ["--text", str(f)]
    proc = subprocess.run(args, capture_output=True, text=True, check=False)  # noqa: S603
    if proc.returncode != 0:
        tail = proc.stdout.strip().splitlines()[-1:] or ["no output"]
        raise ExportError(f"leak guard blocked the export ({proc.returncode}): {tail[0]}")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _commit() -> str | None:
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "HEAD"],  # noqa: S607
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return None
    sha = proc.stdout.strip()
    return sha if proc.returncode == 0 and len(sha) == 40 else None


def write_manifest(
    out: Path,
    summary: ExportSummary,
    *,
    db: Path,
    experiments: Sequence[str],
    ks: Sequence[int],
    model: str | None,
    model_digest: str | None,
) -> Path:
    """Repo-relative facts only: the db by file name, files relative to `out`."""
    manifest = {
        "source": SOURCE,
        "schema_version": SCHEMA_VERSION,
        "source_commit": _commit(),
        "run_log": db.name,
        "experiments": list(experiments),
        "model": model,
        "model_digest": model_digest,
        "content_ref_k": list(ks),
        "runs_exported": summary.runs,
        "runs_skipped_error": summary.skipped_errors,
        "files": {f.relative_to(out).as_posix(): _sha256(f) for f in sorted(summary.files)},
    }
    path = out / "export_manifest.json"
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Export the run log as gauntlet traces.")
    parser.add_argument("--db", required=True)
    parser.add_argument("--out", required=True, help="output directory (created, replaced)")
    parser.add_argument("--experiment", action="append", required=True)
    parser.add_argument("--k", type=int, action="append", help="content-ref K; repeatable")
    parser.add_argument("--model-digest", default=None)
    parser.add_argument("--scenarios", default=str(DEFAULT_SCENARIOS))
    parser.add_argument("--benign", default=str(DEFAULT_BENIGN))
    parser.add_argument("--registry", default=str(DEFAULT_REGISTRY))
    parser.add_argument("--leak-guard", default=str(DEFAULT_LEAK_GUARD))
    args = parser.parse_args(argv)

    db = Path(args.db)
    if not db.is_file():
        parser.error(f"no run log named {db.name}")
    ks = sorted(set(args.k or [DEFAULT_K]))
    out = Path(args.out)
    # Only an empty directory or a previous export (exactly the exporter's layout) is
    # replaced, and only after the new export has passed the leak guard.
    if out.exists() and any(out.iterdir()) and not _is_previous_export(out):
        parser.error("--out exists and is not a previous export; choose an empty directory")
    staging = out.with_name(out.name + ".partial")
    if staging.exists():
        parser.error(f"{staging.name} exists from an interrupted export; remove it first")
    catalog = Catalog.load(args.scenarios, args.benign, args.registry)
    try:
        with RunLog(db) as log:
            summary = export(log, staging, args.experiment, catalog, ks=ks)
            models = {r.model for e in args.experiment for r in log.runs(e)}
        manifest = write_manifest(
            staging,
            summary,
            db=db,
            experiments=args.experiment,
            ks=ks,
            model=next(iter(models)) if len(models) == 1 else None,
            model_digest=args.model_digest,
        )
        leak_guard([*summary.files, manifest], Path(args.leak_guard))
    except BaseException:
        # Anything the leak guard did not pass is removed, interrupts included.
        shutil.rmtree(staging, ignore_errors=True)
        raise
    if out.exists():
        shutil.rmtree(out)
    staging.rename(out)
    sys.stderr.write(
        f"{summary.runs} runs exported ({summary.skipped_errors} error runs skipped), "
        f"{len(summary.files) + 1} files, leak guard clean\n"
    )


if __name__ == "__main__":
    main()
