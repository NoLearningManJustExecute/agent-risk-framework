"""The demo runs offline with the scripted model and renders its transcript."""

from __future__ import annotations

from pathlib import Path

import anyio
import pytest

from agent_risk_framework.attacks.scenarios import load_catalog
from agent_risk_framework.demo import _Scripted, main, measured_results, render_svg, run_demo

REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def at_repo_root(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(REPO_ROOT)  # the demo reads data/ and configs/ like the CLI does


def _ac01():  # type: ignore[no-untyped-def]
    catalog = load_catalog(REPO_ROOT / "data" / "attack_scenarios.json")
    return next(s for s in catalog.scenarios if s.scenario_id == "AC01")


def test_attack_succeeds_undefended_and_is_blocked_with_controls(at_repo_root: None) -> None:
    lines = anyio.run(
        lambda: run_demo(_ac01(), _Scripted(), ["baseline", "tool_permissions", "combined"])
    )
    text = "\n".join(lines)
    sections = text.split("== arm: ")[1:]
    assert [s.split()[0] for s in sections] == ["baseline", "tool_permissions", "combined"]
    assert "result ATTACK SUCCEEDED" in sections[0]
    assert "result ATTACK BLOCKED, credited to tool_permissions (call_blocked)" in sections[1]
    assert "BLOCKED by approval_gate" in sections[2] and "(controls: all six)" in sections[2]
    assert all(len(line) <= 100 for line in lines)
    assert chr(0x2014) not in text  # no em dashes in published output


def test_svg_animates_every_line_and_the_still_frame_does_not() -> None:
    lines = ["$ demo", "", "== arm: baseline", "  result ATTACK SUCCEEDED", "  guard  BLOCKED"]
    svg = render_svg(lines, seconds=10)
    assert svg.startswith("<svg") and svg.count("<text") == 4
    assert svg.count("animation-delay") == 4 and 'class="bad"' in svg and 'class="good"' in svg
    still = render_svg(lines, animate=False)
    assert "animation-delay" not in still and "animation:in" not in still


def test_cli_writes_transcript_and_svgs(at_repo_root: None, tmp_path: Path) -> None:
    out = tmp_path / "demo"
    main(
        [
            "--fake",
            "--arms",
            "baseline,tool_permissions",
            "--transcript",
            str(out / "t.txt"),
            "--svg",
            str(out / "d.svg"),
            "--still",
            str(out / "s.svg"),
        ]
    )
    assert "ATTACK SUCCEEDED" in (out / "t.txt").read_text(encoding="utf-8")
    assert (out / "d.svg").is_file() and (out / "s.svg").is_file()


def test_terminal_output_does_not_repeat_the_command_but_the_transcript_does(
    at_repo_root: None, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    transcript = tmp_path / "t.txt"
    main(["--fake", "--arms", "baseline", "--transcript", str(transcript)])
    printed = capsys.readouterr().out
    assert printed.startswith("case AC01")
    assert "$ python" not in printed
    assert transcript.read_text(encoding="utf-8").startswith("$ python -m")


def test_results_print_the_committed_phase4_numbers(
    at_repo_root: None, capsys: pytest.CaptureFixture[str]
) -> None:
    main(["--results"])
    printed = capsys.readouterr().out
    rows = {line.split()[0]: line.split(maxsplit=1)[1] for line in printed.splitlines()[3:6]}
    assert rows["baseline"].split()[::2] == ["160/240", "0/450", "0/450", "410/450"]
    assert rows["tool_permissions"].split()[::2] == ["50/240", "10/450", "0/450", "410/450"]
    assert rows["input_classifier"].split()[::2] == ["110/240", "40/450", "40/450", "370/450"]
    assert all(len(line) <= 100 for line in printed.splitlines())


def test_results_fail_closed_without_the_table() -> None:
    with pytest.raises(ValueError):
        measured_results("# no table here")
    with pytest.raises(ValueError):
        measured_results("### Security vs usefulness, per arm\n\n| Arm | Attack success |\n")


def test_cli_rejects_unknown_case_and_arm(at_repo_root: None) -> None:
    with pytest.raises(SystemExit):
        main(["--fake", "--case", "AC99"])
    with pytest.raises(SystemExit):
        main(["--fake", "--arms", "firewall"])
