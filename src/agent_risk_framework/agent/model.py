"""The tool-calling model interface, plus a live Ollama adapter and a fake.

Phase 0's `LLMProvider` returns plain text; a tool-using agent needs structured
tool calls. This module adds that as a separate, small interface rather than
widening the provider, so the ablation code that depends on the text provider is
untouched.

`OllamaToolModel` uses Ollama's native tool-calling (`/api/chat` with a `tools`
field), reusing the loopback-only transport from `providers.ollama` so the
local-only guarantee and the injectable transport carry over unchanged.
`FakeToolModel` replays a scripted sequence of turns for deterministic offline
tests.
"""

from __future__ import annotations

import json
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from ..providers.base import GenerationParams
from ..providers.ollama import DEFAULT_BASE_URL, DEFAULT_CHAT_MODEL, Transport, require_loopback
from ..providers.ollama import urllib_transport as _urllib_transport


@dataclass(frozen=True)
class ToolDef:
    name: str
    description: str
    parameters: dict[str, Any]  # JSON Schema object for the arguments


@dataclass(frozen=True)
class ToolCall:
    name: str
    arguments: dict[str, Any]
    raw_arguments: str  # arguments as JSON text, for faithful logging


@dataclass(frozen=True)
class ModelTurn:
    """One model response: free text and zero or more tool calls."""

    text: str
    tool_calls: tuple[ToolCall, ...]
    model: str
    latency_ms: float
    assistant_message: dict[str, Any] = field(default_factory=dict, compare=False)


@runtime_checkable
class ToolCallingModel(Protocol):
    model: str

    def generate(
        self,
        messages: Sequence[dict[str, Any]],
        tools: Sequence[ToolDef],
        params: GenerationParams | None = None,
    ) -> ModelTurn: ...


def _normalize_arguments(raw: Any) -> tuple[dict[str, Any], str]:
    """Return (parsed dict, raw JSON text) for a tool call's arguments."""
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return {}, raw
        return (parsed if isinstance(parsed, dict) else {}), raw
    if isinstance(raw, dict):
        return raw, json.dumps(raw, sort_keys=True)
    return {}, json.dumps(raw)


class OllamaToolModel:
    """Native tool-calling against a local Ollama server (loopback only)."""

    name = "ollama"

    def __init__(
        self,
        model: str = DEFAULT_CHAT_MODEL,
        *,
        base_url: str = DEFAULT_BASE_URL,
        timeout_s: float = 300.0,
        transport: Transport | None = None,
    ) -> None:
        self.model = model
        self.base_url = require_loopback(base_url)
        self.timeout_s = timeout_s
        self._transport = transport or _urllib_transport

    @staticmethod
    def _tools_payload(tools: Sequence[ToolDef]) -> list[dict[str, Any]]:
        return [
            {
                "type": "function",
                "function": {
                    "name": t.name,
                    "description": t.description,
                    "parameters": t.parameters,
                },
            }
            for t in tools
        ]

    def generate(
        self,
        messages: Sequence[dict[str, Any]],
        tools: Sequence[ToolDef],
        params: GenerationParams | None = None,
    ) -> ModelTurn:
        params = params or GenerationParams()
        options: dict[str, Any] = {"temperature": params.temperature}
        if params.seed is not None:
            options["seed"] = params.seed
        if params.max_tokens is not None:
            options["num_predict"] = params.max_tokens
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": list(messages),
            "stream": False,
            "options": options,
        }
        if tools:
            payload["tools"] = self._tools_payload(tools)
        start = time.perf_counter()
        data = self._transport(f"{self.base_url}/api/chat", payload, self.timeout_s)
        latency_ms = (time.perf_counter() - start) * 1000
        message = data.get("message") if isinstance(data, dict) else None
        if not isinstance(message, dict):
            raise ValueError("malformed /api/chat response: missing message")
        calls: list[ToolCall] = []
        for raw_call in message.get("tool_calls") or []:
            fn = raw_call.get("function", {}) if isinstance(raw_call, dict) else {}
            name = fn.get("name")
            if not isinstance(name, str):
                continue
            args, raw_args = _normalize_arguments(fn.get("arguments"))
            calls.append(ToolCall(name=name, arguments=args, raw_arguments=raw_args))
        text = message.get("content") or ""
        return ModelTurn(
            text=text if isinstance(text, str) else "",
            tool_calls=tuple(calls),
            model=self.model,
            latency_ms=latency_ms,
            assistant_message=message,
        )


class FakeToolModel:
    """Replays scripted turns; ignores message content. For offline tests.

    Each scripted turn is either a list of `(name, arguments)` tool calls, or a
    string (a final answer). After the script is exhausted it returns empty text,
    which ends the loop.
    """

    name = "fake"

    def __init__(
        self, script: Sequence[list[tuple[str, dict[str, Any]]] | str], model: str = "fake-tools"
    ) -> None:
        self.model = model
        self._script = list(script)
        self._i = 0
        self.calls: list[tuple[tuple[dict[str, Any], ...], tuple[ToolDef, ...]]] = []

    def generate(
        self,
        messages: Sequence[dict[str, Any]],
        tools: Sequence[ToolDef],
        params: GenerationParams | None = None,
    ) -> ModelTurn:
        self.calls.append((tuple(messages), tuple(tools)))
        if self._i >= len(self._script):
            return ModelTurn("", (), self.model, 0.0, {"role": "assistant", "content": ""})
        turn = self._script[self._i]
        self._i += 1
        if isinstance(turn, str):
            return ModelTurn(turn, (), self.model, 0.0, {"role": "assistant", "content": turn})
        calls = tuple(
            ToolCall(
                name=name, arguments=dict(args), raw_arguments=json.dumps(args, sort_keys=True)
            )
            for name, args in turn
        )
        assistant = {
            "role": "assistant",
            "content": "",
            "tool_calls": [{"function": {"name": c.name, "arguments": c.arguments}} for c in calls],
        }
        return ModelTurn("", calls, self.model, 0.0, assistant)
