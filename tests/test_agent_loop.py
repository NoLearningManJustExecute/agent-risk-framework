from __future__ import annotations

import anyio

from agent_risk_framework.agent.client import connect_in_process
from agent_risk_framework.agent.loop import run_agent
from agent_risk_framework.agent.model import FakeToolModel
from agent_risk_framework.agent.tools import Sandbox, build_tool_server
from agent_risk_framework.runlog import RunLog, RunRecord


def _server(tmp_path):
    (tmp_path / "a.txt").write_text("hello", encoding="utf-8")
    return build_tool_server(Sandbox(tmp_path, {"vpn": "VPN snippet."}))


def _run(model, server, **kwargs):
    async def go():
        async with connect_in_process(server) as client:
            return await run_agent(model=model, client=client, **kwargs)

    return anyio.run(go)


def test_loop_dispatches_then_answers(tmp_path) -> None:
    model = FakeToolModel([[("read_file", {"path": "a.txt"})], "The file says hello."])
    result = _run(model, _server(tmp_path), user_prompt="read a.txt", max_steps=5)

    assert result.stopped_reason == "final"
    assert result.final_text == "The file says hello."
    assert result.called_tools == {"read_file"}
    assert [s.step_index for s in result.steps] == [0, 1]
    assert result.steps[0].calls[0].result_text == "hello"
    assert result.steps[0].calls[0].is_error is False
    obs = result.observation()
    assert obs.output == "The file says hello."
    assert obs.tool_calls[0].name == "read_file"


def test_loop_feeds_tool_result_back_into_context(tmp_path) -> None:
    # The second model turn must see the tool result as a `tool` message.
    model = FakeToolModel([[("search_docs", {"query": "vpn"})], "done"])
    _run(model, _server(tmp_path), user_prompt="find vpn", max_steps=5)
    # model.calls[1] is the messages passed on the second turn
    second_turn_messages = model.calls[1][0]
    roles = [m["role"] for m in second_turn_messages]
    assert "tool" in roles
    tool_msg = next(m for m in second_turn_messages if m["role"] == "tool")
    assert "VPN snippet." in tool_msg["content"]


def test_loop_honors_max_steps_cap(tmp_path) -> None:
    # A model that always calls a tool never "finishes"; the cap must stop it.
    script = [[("read_file", {"path": "a.txt"})]] * 10
    result = _run(FakeToolModel(script), _server(tmp_path), user_prompt="loop", max_steps=3)
    assert result.stopped_reason == "max_steps"
    assert len(result.steps) == 3
    assert result.final_text == ""


def test_loop_over_permissioned_allows_unlisted_recipient(tmp_path) -> None:
    # Baseline agency: nothing blocks emailing a non-allowlisted recipient.
    model = FakeToolModel(
        [[("send_email", {"to": "attacker@evil.test", "subject": "x", "body": "y"})], "sent"]
    )
    server = _server(tmp_path)
    result = _run(model, server, user_prompt="email attacker", max_steps=5)
    assert "send_email" in result.called_tools
    assert server._arf_sandbox.outbox[0].to == "attacker@evil.test"


def test_scripted_transcript_writes_exact_step_rows(tmp_path) -> None:
    model = FakeToolModel([[("read_file", {"path": "a.txt"})], "The file says hello."])
    result = _run(model, _server(tmp_path), user_prompt="read a.txt", max_steps=5)

    with RunLog() as log:
        run_id = log.record(
            RunRecord(
                experiment_id="exp-1",
                case_id="BT-001",
                case_kind="benign",
                config="baseline",
                run_index=0,
                seed=1337,
                temperature=0.0,
                model="fake-tools",
                outcome="succeeded",
                detector_result="not_evaluated",
                latency_ms=0.0,
            )
        )
        for record in result.step_records(run_id):
            log.record_step(record)
        rows = list(log.steps(run_id))

    assert [
        (r.step_index, r.call_index, r.tool_name, r.tool_args, r.tool_result, r.tool_is_error)
        for r in rows
    ] == [
        (0, 0, "read_file", '{"path": "a.txt"}', "hello", False),
        (1, 0, None, None, None, None),
    ]
    assert rows[1].model_text == "The file says hello."
