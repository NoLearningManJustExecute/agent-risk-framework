"""The custom agent loop: model -> parse tool calls -> dispatch -> feed back.

No framework. One model turn per step; each turn may emit zero or more tool calls.
Tool calls are dispatched to the MCP server and their results appended to the
conversation as `tool` messages, then the loop repeats until the model answers
with no tool call or a hard `max_steps` cap is hit (the cap bounds runaway loops;
threat T13 / ASI08 / LLM06:2026). The agent is over-permissioned on purpose: any
listed tool may be called with any arguments, and nothing inspects or blocks a
call — defenses arrive in Phase 3.

The loop writes nothing to disk; it returns an `AgentResult` that the caller
persists (`step_records`) and scores (`observation`, `called_tools`).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field

import anyio

from ..providers.base import GenerationParams
from ..runlog import StepRecord
from ..scoring import Observation
from ..scoring import ToolCall as ScoringToolCall
from .client import Client, list_tool_defs, result_text
from .model import ToolCall, ToolCallingModel, ToolDef
from .policy import build_system_prompt

DEFAULT_MAX_STEPS = 8


@dataclass(frozen=True)
class ExecutedCall:
    call: ToolCall
    result_text: str
    is_error: bool


@dataclass(frozen=True)
class AgentStep:
    step_index: int
    model_text: str
    latency_ms: float  # latency of the model turn that produced this step
    calls: tuple[ExecutedCall, ...] = ()


@dataclass(frozen=True)
class AgentResult:
    final_text: str
    steps: tuple[AgentStep, ...]
    stopped_reason: str  # "final" (model answered) | "max_steps" (cap hit)
    model: str
    tool_error: bool = field(default=False)  # any tool call returned an error result

    @property
    def called_tools(self) -> frozenset[str]:
        return frozenset(ec.call.name for step in self.steps for ec in step.calls)

    def observation(self) -> Observation:
        """A Phase 0 `Observation` for the deterministic oracles."""
        calls = tuple(
            ScoringToolCall(name=ec.call.name, arguments=ec.call.arguments)
            for step in self.steps
            for ec in step.calls
        )
        return Observation(output=self.final_text, tool_calls=calls)

    def step_records(self, run_id: int) -> list[StepRecord]:
        """One row per step (final-answer step) or per tool call within a step."""
        records: list[StepRecord] = []
        for step in self.steps:
            if not step.calls:
                records.append(
                    StepRecord(
                        run_id=run_id,
                        step_index=step.step_index,
                        model_text=step.model_text,
                        latency_ms=step.latency_ms,
                    )
                )
                continue
            for call_index, ec in enumerate(step.calls):
                records.append(
                    StepRecord(
                        run_id=run_id,
                        step_index=step.step_index,
                        call_index=call_index,
                        model_text=step.model_text,
                        latency_ms=step.latency_ms,
                        tool_name=ec.call.name,
                        tool_args=ec.call.raw_arguments,
                        tool_result=ec.result_text,
                        tool_is_error=ec.is_error,
                    )
                )
        return records


def _tool_lines(tools: Sequence[ToolDef]) -> list[str]:
    lines = []
    for t in tools:
        params = ", ".join((t.parameters.get("properties") or {}).keys())
        lines.append(f"{t.name}({params}): {t.description}")
    return lines


async def run_agent(
    *,
    model: ToolCallingModel,
    client: Client,
    user_prompt: str,
    system_prompt: str | None = None,
    tools: Sequence[ToolDef] | None = None,
    params: GenerationParams | None = None,
    max_steps: int = DEFAULT_MAX_STEPS,
) -> AgentResult:
    if max_steps < 1:
        raise ValueError("max_steps must be >= 1")
    if tools is None:
        tools = await list_tool_defs(client)
    if system_prompt is None:
        system_prompt = build_system_prompt(_tool_lines(tools))

    messages: list[dict] = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt},
    ]
    steps: list[AgentStep] = []
    final_text = ""
    stopped_reason = "max_steps"
    any_tool_error = False

    for step_index in range(max_steps):
        # The model call is synchronous (and may block on a local HTTP request);
        # run it off the event loop so dispatch stays responsive.
        turn = await anyio.to_thread.run_sync(lambda m=messages: model.generate(m, tools, params))
        if not turn.tool_calls:
            steps.append(AgentStep(step_index, turn.text, turn.latency_ms))
            final_text = turn.text
            stopped_reason = "final"
            break

        messages.append(turn.assistant_message or {"role": "assistant", "content": turn.text})
        executed: list[ExecutedCall] = []
        for call in turn.tool_calls:
            raw_result = await client.call_tool(call.name, call.arguments)
            text, is_error = result_text(raw_result)
            any_tool_error = any_tool_error or is_error
            executed.append(ExecutedCall(call=call, result_text=text, is_error=is_error))
            messages.append({"role": "tool", "tool_name": call.name, "content": text})
        steps.append(AgentStep(step_index, turn.text, turn.latency_ms, tuple(executed)))

    return AgentResult(
        final_text=final_text,
        steps=tuple(steps),
        stopped_reason=stopped_reason,
        model=getattr(model, "model", "unknown"),
        tool_error=any_tool_error,
    )
