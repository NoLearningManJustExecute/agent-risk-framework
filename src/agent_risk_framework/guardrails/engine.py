"""The guardrail engine: runs the enabled controls at each stage and logs every decision.

Stages, in the order a run meets them:

1. `tool_definition`: `approve_tools` (the first listing, what a human signs off)
   and `admit_tools` (the listing the run actually uses). Tool integrity.
2. `user_prompt`: `screen_prompt`, before the first model turn. Input classifier;
   a block stops the run.
3. `tool_call`: `check_call`, before dispatch. Tool permissions, tool integrity
   (no calls to quarantined tools), approval gate, egress filter (no secret in any
   argument). Every enabled control is evaluated, without short-circuiting, so the
   log shows each control that would have refused; the call is blocked if any did.
4. `tool_result`: `check_result`, before the result reaches the model. Output
   classifier (a block withholds the result) and egress filter (a block redacts the
   secrets in it, or withholds it when a secret is only visible encoded). The tool
   already ran, and the step log keeps its real result.

Every evaluation, allow or block, is one `Decision` in `decisions`, in order. A
disabled control is never evaluated and never logged. With no control enabled the
engine is inert: it allows everything and logs nothing.
"""

from __future__ import annotations

import time
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

from ..agent.loop import ResultCheck
from ..agent.model import ToolCall, ToolDef
from ..agent.policy import ORG_DOMAINS, RECIPIENT_ALLOWLIST, RESTRICTED_PATHS
from ..enums import Control, DecisionAction, DecisionStage
from ..runlog import DecisionRecord
from .approval import ApprovalGate, Reviewer, SimulatedReviewer
from .classifier import DEFAULT_THRESHOLD, classify
from .config import GuardrailConfig
from .egress import EgressFilter
from .integrity import DefinitionCheck, ToolIntegrity, ToolRegistry
from .permissions import ToolPermissions

USER_PROMPT_TARGET = "user_prompt"


@dataclass(frozen=True)
class Decision:
    """One guardrail evaluation, before it is tied to a logged run."""

    seq: int
    control: Control
    stage: DecisionStage
    target: str
    action: DecisionAction
    reasons: tuple[str, ...]
    step_index: int | None = None
    call_index: int | None = None
    latency_ms: float = 0.0

    @property
    def blocked(self) -> bool:
        return self.action == DecisionAction.BLOCK

    def record(self, run_id: int) -> DecisionRecord:
        return DecisionRecord(
            run_id=run_id,
            seq=self.seq,
            control=self.control,
            stage=self.stage,
            target=self.target,
            action=self.action,
            reasons=self.reasons,
            step_index=self.step_index,
            call_index=self.call_index,
            latency_ms=self.latency_ms,
        )


def _verdict(problems: Sequence[str]) -> tuple[bool, tuple[str, ...]]:
    return (not problems, tuple(problems) or ("no rule violated",))


class GuardrailEngine:
    def __init__(
        self,
        config: GuardrailConfig,
        *,
        user_prompt: str,
        workspace_root: Path | str | None = None,
        allowlist: Iterable[str] = RECIPIENT_ALLOWLIST,
        org_domains: Iterable[str] = ORG_DOMAINS,
        restricted_paths: Iterable[str] = RESTRICTED_PATHS,
        registry: ToolRegistry | None = None,
        reviewer: Reviewer | None = None,
        classifier_threshold: int = DEFAULT_THRESHOLD,
        egress: EgressFilter | None = None,
    ) -> None:
        self.config = config
        self.user_prompt = user_prompt
        self.threshold = classifier_threshold
        self.permissions = ToolPermissions(
            allowlist=allowlist, workspace_root=workspace_root, restricted_paths=restricted_paths
        )
        self.integrity = ToolIntegrity(registry)
        self.gate = ApprovalGate(
            reviewer or SimulatedReviewer(user_prompt, org_domains=tuple(org_domains))
        )
        self.egress = egress or EgressFilter.for_workspace(
            workspace_root, restricted=restricted_paths
        )
        self.decisions: list[Decision] = []

    # --- logging ------------------------------------------------------------------

    def _log(
        self,
        control: Control,
        stage: DecisionStage,
        target: str,
        allowed: bool,
        reasons: Sequence[str],
        started: float,
        step_index: int | None = None,
        call_index: int | None = None,
    ) -> Decision:
        decision = Decision(
            seq=len(self.decisions),
            control=control,
            stage=stage,
            target=target,
            action=DecisionAction.ALLOW if allowed else DecisionAction.BLOCK,
            reasons=tuple(reasons) or (("allowed",) if allowed else ("blocked",)),
            step_index=step_index,
            call_index=call_index,
            latency_ms=(time.perf_counter() - started) * 1000,
        )
        self.decisions.append(decision)
        return decision

    def _on(self, control: Control) -> bool:
        return self.config.enabled(control)

    # --- stages -------------------------------------------------------------------

    def _definition_decisions(self, checks: Sequence[DefinitionCheck], started: float) -> None:
        for check in checks:
            self._log(
                Control.TOOL_INTEGRITY,
                DecisionStage.TOOL_DEFINITION,
                check.tool,
                check.allowed,
                check.reasons,
                started,
            )

    def approve_tools(self, tools: Sequence[ToolDef]) -> None:
        """Vet and pin the tool list a human approved (no-op unless integrity is on)."""
        if not self._on(Control.TOOL_INTEGRITY):
            return
        started = time.perf_counter()
        self._definition_decisions(self.integrity.approve(tools), started)

    def admit_tools(self, tools: Sequence[ToolDef]) -> list[ToolDef]:
        """The tools the model may see this run (all of them unless integrity is on)."""
        if not self._on(Control.TOOL_INTEGRITY):
            return list(tools)
        started = time.perf_counter()
        allowed, checks = self.integrity.admit(tools)
        self._definition_decisions(checks, started)
        return allowed

    def screen_prompt(self, prompt: str | None = None) -> bool:
        """True if the run may proceed. Input classifier on the user prompt."""
        if not self._on(Control.INPUT_CLASSIFIER):
            return True
        started = time.perf_counter()
        verdict = classify(self.user_prompt if prompt is None else prompt, threshold=self.threshold)
        d = self._log(
            Control.INPUT_CLASSIFIER,
            DecisionStage.USER_PROMPT,
            USER_PROMPT_TARGET,
            not verdict.flagged,
            verdict.reasons(),
            started,
        )
        return not d.blocked

    def check_call(self, call: ToolCall, step_index: int, call_index: int) -> tuple[Control, ...]:
        """The controls that refuse this call (empty: dispatch it)."""
        blockers: list[Control] = []
        checks = (
            (Control.TOOL_PERMISSIONS, lambda: _verdict(self.permissions.problems(call))),
            (Control.TOOL_INTEGRITY, lambda: _verdict(self.integrity.call_problems(call))),
            (Control.APPROVAL_GATE, lambda: self.gate.review(call)),
            (Control.EGRESS_FILTER, lambda: _verdict(self.egress.arg_problems(call))),
        )
        for control, run in checks:
            if not self._on(control):
                continue
            started = time.perf_counter()
            allowed, reasons = run()
            d = self._log(
                control,
                DecisionStage.TOOL_CALL,
                call.name,
                allowed,
                reasons,
                started,
                step_index,
                call_index,
            )
            if d.blocked:
                blockers.append(control)
        return tuple(blockers)

    def check_result(
        self, call: ToolCall, text: str, step_index: int, call_index: int
    ) -> ResultCheck:
        """What the model may see of this tool result: all, redacted, or nothing."""
        withheld: list[Control] = []
        redacted_by: tuple[Control, ...] = ()
        redacted_text = ""
        if self._on(Control.OUTPUT_CLASSIFIER):
            started = time.perf_counter()
            verdict = classify(text, threshold=self.threshold)
            d = self._log(
                Control.OUTPUT_CLASSIFIER,
                DecisionStage.TOOL_RESULT,
                call.name,
                not verdict.flagged,
                verdict.reasons(),
                started,
                step_index,
                call_index,
            )
            if d.blocked:
                withheld.append(Control.OUTPUT_CLASSIFIER)
        if self._on(Control.EGRESS_FILTER):
            started = time.perf_counter()
            redaction = self.egress.redact(text)
            self._log(
                Control.EGRESS_FILTER,
                DecisionStage.TOOL_RESULT,
                call.name,
                not redaction.changed,
                redaction.reasons(),
                started,
                step_index,
                call_index,
            )
            if redaction.withheld:
                withheld.append(Control.EGRESS_FILTER)
            elif redaction.changed:
                redacted_by, redacted_text = (Control.EGRESS_FILTER,), redaction.text
        return ResultCheck(tuple(withheld), redacted_by, redacted_text)
