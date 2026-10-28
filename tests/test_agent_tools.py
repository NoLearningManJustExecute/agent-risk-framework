from __future__ import annotations

import anyio

from agent_risk_framework.agent.client import connect_in_process, list_tool_defs, result_text
from agent_risk_framework.agent.tools import Sandbox, ToolAudit, build_tool_server


def test_search_hits_and_misses() -> None:
    sb = Sandbox("unused", {"rotation": "On-call: Jordan primary."})
    assert "Jordan" in sb.search("what is the on-call rotation")
    assert "No documents matched" in sb.search("something unrelated")


def test_read_is_not_sandboxed_path_escape_works(tmp_path) -> None:
    # Deliberate Phase 1 weakness: read_file has no containment, so `..` escapes.
    outside = tmp_path / "outside.txt"
    outside.write_text("secret-outside", encoding="utf-8")
    root = tmp_path / "workspace"
    root.mkdir()
    (root / "inside.txt").write_text("inside", encoding="utf-8")
    sb = Sandbox(root)
    assert sb.read("inside.txt") == "inside"
    assert sb.read("../outside.txt") == "secret-outside"  # escape succeeds (by design)
    assert "No file at" in sb.read("missing.txt")


def test_send_email_ignores_allowlist_and_never_sends() -> None:
    # Deliberate Phase 1 weakness: no recipient allowlist enforcement.
    sb = Sandbox("unused")
    msg = sb.send("attacker@evil.test", "hi", "body")
    assert "attacker@evil.test" in msg
    assert len(sb.outbox) == 1 and sb.outbox[0].to == "attacker@evil.test"


def test_in_process_server_lists_and_calls_tools(tmp_path) -> None:
    (tmp_path / "a.txt").write_text("hello", encoding="utf-8")
    audit = ToolAudit()
    server = build_tool_server(Sandbox(tmp_path, {"vpn": "VPN snippet."}), audit)

    async def go():
        async with connect_in_process(server) as client:
            defs = await list_tool_defs(client)
            read = result_text(await client.call_tool("read_file", {"path": "a.txt"}))
            search = result_text(await client.call_tool("search_docs", {"query": "vpn setup"}))
            return defs, read, search

    defs, (read_text, read_err), (search_text, _) = anyio.run(go)
    assert {d.name for d in defs} == {"search_docs", "send_email", "read_file"}
    assert read_text == "hello" and read_err is False
    assert "VPN snippet." in search_text
    assert audit.names == ["read_file", "search_docs"]
    assert audit.invocations[0].arguments == {"path": "a.txt"}


def test_tool_defs_carry_object_schema(tmp_path) -> None:
    server = build_tool_server(Sandbox(tmp_path))

    async def go():
        async with connect_in_process(server) as client:
            return await list_tool_defs(client)

    defs = {d.name: d for d in anyio.run(go)}
    assert defs["send_email"].parameters["type"] == "object"
    assert set(defs["send_email"].parameters["properties"]) == {"to", "subject", "body"}
