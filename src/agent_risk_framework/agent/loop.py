"""The custom agent loop: model -> parse tool calls -> dispatch -> feed back.

No framework. One model turn per step; each turn may emit zero or more tool calls.
Tool calls are dispatched to the MCP server and their results appended to the
conversation as `tool` messages, then the loop repeats until the model answers
with no tool call or a hard `max_steps` cap is hit (the cap bounds runaway loops;
threat T13 / ASI08 / LLM06:2026). The agent is over-permissioned on purpose: any
listed tool may be called with any arguments, and nothing inspects or blocks a
call unless a `guard` is passed.

Phase 3 hooks the guardrail engine in through the optional `guard` argument:
the user prompt is screened before the first model turn (a block ends the run with
no answer), each tool call is checked before dispatch (a blocked call is not
executed; the model is told it was blocked), and each tool result is checked
before the model reads it (a withheld result is replaced in the conversation, a
redacted one has its secrets replaced by placeholders, and in both cases the step
log keeps the real result). With `guard=None` the loop is exactly the Phase 1
baseline.

The loop writes nothing to disk; it returns an `AgentResult` that the caller
persists (`step_records`) and scores (`observation`, `called_tools`).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol

import anyio

from ..providers.base import GenerationParams
from ..runlog import StepRecord
from ..scoring import Observation
from ..scoring import ToolCall as ScoringToolCall
from .client import Client, list_tool_defs, result_text
from .model import ToolCall, ToolCallingModel, ToolDef
from .policy import build_system_prompt

DEFAULT_MAX_STEPS = 8
STOPPED_BY_GUARD = "blocked"


class Guard(Protocol):
    """What the loop needs from a guardrail engine (`guardrails.GuardrailEngine`)."""

    decisions: Sequence[Any]

    def screen_prompt(self, prompt: str | None = None) -> bool: ...

    def check_call(self, call: ToolCall, step_index: int, call_index: int) -> tuple[Any, ...]: ...

    def check_result(
        self, call: ToolCall, text: str, step_index: int, call_index: int
    ) -> ResultCheck: ...


@dataclass(frozen=True)
class ResultCheck:
    """What the guard decided about one tool result before the model reads it."""

    withheld_by: tuple[Any, ...] = ()  # controls that keep the whole result back
    redacted_by: tuple[Any, ...] = ()  # controls that cut secrets out of it
    redacted_text: str = ""  # the result with placeholders, when redacted


@dataclass(frozen=True)
class ExecutedCall:
    call: ToolCall
    result_text: str  # what the tool returned, or the block notice if it never ran
    is_error: bool
    blocked_by: tuple[str, ...] = ()  # controls that refused the call (not executed)
    withheld_by: tuple[str, ...] = ()  # controls that kept the result from the model
    redacted_by: tuple[str, ...] = ()  # controls that redacted secrets in what it saw


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
    stopped_reason: str  # "final" (model answered) | "max_steps" (cap hit) | "blocked"
    model: str
    tool_error: bool = field(default=False)  # any tool call returned an error result
    decisions: tuple[Any, ...] = ()  # the guard's decision log, in order (empty: no guard)

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


def _names(controls: Sequence[Any]) -> tuple[str, ...]:
    return tuple(sorted(str(c) for c in controls))


def _blocked_message(controls: Sequence[Any]) -> str:
    # Deliberately generic: the reasons stay in the decision log, not in model context.
    return f"Blocked by guardrail ({', '.join(_names(controls))}): this tool call was not executed."


_WITHHELD_BECAUSE = {
    "output_classifier": "instructions addressed to the assistant",
    "egress_filter": "secret material",
}


def _withheld_message(controls: Sequence[Any]) -> str:
    names = _names(controls)
    why = " and ".join(_WITHHELD_BECAUSE.get(n, "blocked content") for n in names)
    return f"[Tool output withheld by guardrail ({', '.join(names)}): it contained {why}.]"


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
    guard: Guard | None = None,
) -> AgentResult:
    if max_steps < 1:
        raise ValueError("max_steps must be >= 1")
    model_name = getattr(model, "model", "unknown")
    if guard is not None and not guard.screen_prompt(user_prompt):
        # Stopped before the model saw anything: no steps, no answer.
        return AgentResult("", (), STOPPED_BY_GUARD, model_name, decisions=tuple(guard.decisions))
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
        for call_index, call in enumerate(turn.tool_calls):
            blocked = guard.check_call(call, step_index, call_index) if guard else ()
            if blocked:
                text = _blocked_message(blocked)
                executed.append(ExecutedCall(call, text, True, blocked_by=_names(blocked)))
                messages.append({"role": "tool", "tool_name": call.name, "content": text})
                continue
            raw_result = await client.call_tool(call.name, call.arguments)
            text, is_error = result_text(raw_result)
            any_tool_error = any_tool_error or is_error
            check = guard.check_result(call, text, step_index, call_index) if guard else None
            seen = text
            if check is not None and check.withheld_by:
                seen = _withheld_message(check.withheld_by)
            elif check is not None and check.redacted_by:
                seen = check.redacted_text
            executed.append(
                ExecutedCall(
                    call,
                    text,
                    is_error,
                    withheld_by=_names(check.withheld_by) if check else (),
                    redacted_by=_names(check.redacted_by) if check else (),
                )
            )
            messages.append({"role": "tool", "tool_name": call.name, "content": seen})
        steps.append(AgentStep(step_index, turn.text, turn.latency_ms, tuple(executed)))

    return AgentResult(
        final_text=final_text,
        steps=tuple(steps),
        stopped_reason=stopped_reason,
        model=model_name,
        tool_error=any_tool_error,
        decisions=tuple(guard.decisions) if guard else (),
    )
