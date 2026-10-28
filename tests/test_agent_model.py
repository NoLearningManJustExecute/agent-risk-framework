from __future__ import annotations

from typing import Any

import pytest

from agent_risk_framework.agent.model import FakeToolModel, OllamaToolModel, ToolDef
from agent_risk_framework.providers.base import GenerationParams

TOOLS = [
    ToolDef(
        "search_docs", "search", {"type": "object", "properties": {"query": {"type": "string"}}}
    )
]


def _transport(message: dict[str, Any]):
    captured: dict[str, Any] = {}

    def transport(url: str, payload: dict[str, Any], timeout_s: float) -> dict[str, Any]:
        captured["url"] = url
        captured["payload"] = payload
        return {"message": message}

    return transport, captured


def test_ollama_parses_tool_call_and_sends_tools_and_seed() -> None:
    transport, captured = _transport(
        {
            "role": "assistant",
            "content": "",
            "tool_calls": [{"function": {"name": "search_docs", "arguments": {"query": "vpn"}}}],
        }
    )
    model = OllamaToolModel("llama3.1:8b", transport=transport)
    turn = model.generate(
        [{"role": "user", "content": "find vpn"}], TOOLS, GenerationParams(seed=1337)
    )
    assert captured["url"].endswith("/api/chat")
    assert captured["payload"]["options"]["seed"] == 1337
    assert captured["payload"]["tools"][0]["function"]["name"] == "search_docs"
    assert len(turn.tool_calls) == 1
    assert turn.tool_calls[0].name == "search_docs"
    assert turn.tool_calls[0].arguments == {"query": "vpn"}
    assert turn.tool_calls[0].raw_arguments == '{"query": "vpn"}'


def test_ollama_normalizes_string_arguments() -> None:
    transport, _ = _transport(
        {
            "role": "assistant",
            "content": "",
            "tool_calls": [{"function": {"name": "search_docs", "arguments": '{"query": "x"}'}}],
        }
    )
    turn = OllamaToolModel(transport=transport).generate([{"role": "user", "content": "x"}], TOOLS)
    assert turn.tool_calls[0].arguments == {"query": "x"}
    assert turn.tool_calls[0].raw_arguments == '{"query": "x"}'


def test_ollama_final_answer_has_no_tool_calls() -> None:
    transport, _ = _transport({"role": "assistant", "content": "the answer is 42"})
    turn = OllamaToolModel(transport=transport).generate([{"role": "user", "content": "x"}], TOOLS)
    assert turn.tool_calls == ()
    assert turn.text == "the answer is 42"
    assert turn.assistant_message["content"] == "the answer is 42"


def test_ollama_malformed_response_raises() -> None:
    def bad(url, payload, timeout_s):
        return {"not_a_message": 1}

    with pytest.raises(ValueError, match="message"):
        OllamaToolModel(transport=bad).generate([{"role": "user", "content": "x"}], TOOLS)


def test_ollama_rejects_non_loopback_base_url() -> None:
    with pytest.raises(ValueError, match="loopback"):
        OllamaToolModel(base_url="http://evil.example")


def test_fake_tool_model_replays_script() -> None:
    model = FakeToolModel([[("read_file", {"path": "a.txt"})], "all done"])
    first = model.generate([], TOOLS)
    assert first.tool_calls[0].name == "read_file"
    assert first.tool_calls[0].raw_arguments == '{"path": "a.txt"}'
    second = model.generate([], TOOLS)
    assert second.tool_calls == () and second.text == "all done"
    # exhausted script -> empty turn, which ends the loop
    assert model.generate([], TOOLS).text == ""
