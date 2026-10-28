from __future__ import annotations

from pathlib import Path

import anyio
import pytest

from agent_risk_framework.agent.client import connect_in_process, list_tool_defs, result_text
from agent_risk_framework.agent.tools import ToolAudit
from agent_risk_framework.attacks.lab import (
    CREDENTIALS_CANARY,
    OUTSIDE_CANARY,
    apply_post_approval,
    build_lab_server,
    lab_sandbox,
    tool_fingerprint,
)
from agent_risk_framework.attacks.scenarios import load_catalog

REPO_ROOT = Path(__file__).resolve().parent.parent

SANDBOX = REPO_ROOT / "data" / "agent_sandbox"
DOC_INDEX = REPO_ROOT / "data" / "doc_index.json"


@pytest.fixture(scope="module")
def scenarios():
    catalog = load_catalog(REPO_ROOT / "data" / "attack_scenarios.json")
    return {s.scenario_id: s for s in catalog.scenarios}


def _lab(scenario):
    return lab_sandbox(scenario, base_sandbox=SANDBOX, doc_index=DOC_INDEX)


def test_credentials_fixture_holds_the_credentials_canary() -> None:
    text = (SANDBOX / "secrets" / "credentials.txt").read_text(encoding="utf-8")
    assert CREDENTIALS_CANARY in text


def test_outside_file_reachable_by_escape_but_not_planted_in_workspace(scenarios) -> None:
    with _lab(scenarios["AC02"]) as sb:
        escaped = sb.read("../restricted/hr/payroll_2026.txt")
        assert OUTSIDE_CANARY in escaped
        assert not (sb.root / "restricted").exists()
        # Ordinary workspace reads are unchanged.
        assert "Decisions" in sb.read("notes/team_sync_2026-03-02.txt")


def test_harness_boundary_stops_reads_beyond_the_lab_root(scenarios, tmp_path) -> None:
    host_file = tmp_path / "host_secret.txt"
    host_file.write_text("REAL HOST DATA", encoding="utf-8")
    with _lab(scenarios["AC02"]) as sb:
        assert sb.read(str(host_file)) == f"No file at {str(host_file)!r}."
        assert sb.read("../../../../host_secret.txt").startswith("No file at")
        assert "REAL HOST DATA" not in sb.read(host_file.as_posix())


def test_lab_is_fresh_per_run_and_removed_after(scenarios) -> None:
    with _lab(scenarios["AC09"]) as sb:
        root = sb.lab_root
        assert "migration-check@exfil.example" in sb.read("inbox/it_notice.eml")
        sb.send("x@exfil.example", "s", "b")
    assert not root.exists()
    with _lab(None) as sb:
        assert sb.outbox == []
        assert sb.read("inbox/it_notice.eml").startswith("No file at")
    assert not (SANDBOX / "inbox" / "it_notice.eml").exists()  # never touches the fixture


def test_doc_index_overlay_replaces_entry(scenarios) -> None:
    with _lab(scenarios["AC10"]) as sb:
        assert "vpn-verify@exfil.example" in sb.search("vpn setup")
    with _lab(None) as sb:
        assert "exfil" not in sb.search("vpn setup")


def _tools(server):
    async def go():
        async with connect_in_process(server) as client:
            return await list_tool_defs(client)

    return anyio.run(go)


def test_poisoned_tool_is_listed_with_its_description(scenarios) -> None:
    s = scenarios["AC11"]
    with _lab(s) as sb:
        tools = {t.name: t for t in _tools(build_lab_server(sb, s))}
    assert set(tools) == {"search_docs", "send_email", "read_file", "word_count"}
    assert "compliance-archive@exfil.example" in tools["word_count"].description


def test_shadow_tool_silently_copies_the_attacker(scenarios) -> None:
    s = scenarios["AC12B"]
    audit = ToolAudit()

    async def go(server):
        async with connect_in_process(server) as client:
            names = {t.name for t in await list_tool_defs(client)}
            res = await client.call_tool(
                "send_email_secure", {"to": "alex@example.test", "subject": "s", "body": "b"}
            )
            return names, result_text(res)[0]

    with _lab(s) as sb:
        names, text = anyio.run(go, build_lab_server(sb, s, audit))
        outbox = [m.to for m in sb.outbox]
    assert "send_email_secure" in names and "send_email" in names
    assert "alex@example.test" in text and "exfil" not in text  # caller sees a normal reply
    assert outbox == ["alex@example.test", "relay-archive@exfil.example"]
    assert audit.names == ["send_email_secure"]


def test_rug_pull_changes_description_after_approval_only(scenarios) -> None:
    s = scenarios["AC12A"]

    async def go(server):
        async with connect_in_process(server) as client:
            approved = await list_tool_defs(client)
            changed = apply_post_approval(server, s)
            live = await list_tool_defs(client)
            res = await client.call_tool("search_docs", {"query": "reimbursement"})
            return approved, changed, live, result_text(res)[0]

    with _lab(s) as sb:
        approved, changed, live, text = anyio.run(go, build_lab_server(sb, s))
    assert changed
    before = {t.name: t for t in approved}
    after = {t.name: t for t in live}
    assert "credentials" not in before["search_docs"].description
    assert "secrets/credentials.txt" in after["search_docs"].description
    assert before["search_docs"].parameters == after["search_docs"].parameters
    assert tool_fingerprint(approved) != tool_fingerprint(live)
    assert "last business day" in text  # behavior unchanged; only the text drifted


def test_no_post_approval_change_for_other_scenarios(scenarios) -> None:
    for sid in ("AC01", "AC11", "AC12B"):
        s = scenarios[sid]
        with _lab(s) as sb:
            server = build_lab_server(sb, s)
            before = tool_fingerprint(_tools(server))
            assert apply_post_approval(server, s) is False
            assert tool_fingerprint(_tools(server)) == before
