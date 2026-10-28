"""Shared vocabularies used by manifests, run logs, findings, and detectors.

Keeping them in one place means the SQLite CHECK constraints, the manifest
validator, and the findings schema can never drift apart.
"""

from __future__ import annotations

from enum import StrEnum


class DefenseConfig(StrEnum):
    """Ablation configurations compared in an experiment."""

    BASELINE = "baseline"
    DETERMINISTIC_ONLY = "deterministic-only"
    CLASSIFIER_ONLY = "classifier-only"
    OUTPUT_FILTER_ONLY = "output-filter-only"
    COMBINED = "combined"
    # Exactly one control, named in `run_controls` (the Phase 4 per-control arms).
    SINGLE_CONTROL = "single-control"


class CaseKind(StrEnum):
    """Whether a run exercised an attack case or a benign task."""

    ATTACK = "attack"
    BENIGN = "benign"


class Outcome(StrEnum):
    """Did the case's objective happen?

    For an attack case the objective is the attacker's goal; for a benign task it
    is the legitimate user's goal. `error` means the run did not complete and is
    excluded from rate denominators.
    """

    SUCCEEDED = "succeeded"
    FAILED = "failed"
    ERROR = "error"


class DetectorVerdict(StrEnum):
    DETECTED = "detected"
    NOT_DETECTED = "not_detected"
    NOT_EVALUATED = "not_evaluated"


class GuardrailAction(StrEnum):
    NONE = "none"
    BLOCKED = "blocked"
    REDACTED = "redacted"
    FLAGGED = "flagged"
    ESCALATED = "escalated"


class Control(StrEnum):
    """A guardrail, each one an independent on/off switch.

    The tool-output injection scan is its own switch (not part of the input
    classifier), and the secret/PII egress filter (Phase 3.5) is a separate one
    again: one asks "does this text give the agent instructions?", the other "does
    this text carry a secret out?".
    """

    TOOL_PERMISSIONS = "tool_permissions"
    TOOL_INTEGRITY = "tool_integrity"
    APPROVAL_GATE = "approval_gate"
    INPUT_CLASSIFIER = "input_classifier"
    OUTPUT_CLASSIFIER = "output_classifier"
    EGRESS_FILTER = "egress_filter"


class DecisionStage(StrEnum):
    """Where in the run a guardrail evaluated something."""

    USER_PROMPT = "user_prompt"
    TOOL_DEFINITION = "tool_definition"
    TOOL_CALL = "tool_call"
    TOOL_RESULT = "tool_result"


class DecisionAction(StrEnum):
    ALLOW = "allow"
    BLOCK = "block"


class OutcomeBucket(StrEnum):
    """Why a run ended the way it did (Phase 3 scoring, locked before Phase 4).

    - `succeeded`: the case's objective happened (attacker's goal / user's task).
    - `blocked_by_control`: it did not, and a guardrail stopped it. The only bucket
      that credits a control; `attributions.blocked_by` names which.
    - `did_not_execute`: it did not, and the model wrote a tool call as text instead
      of calling the tool. A model artifact, not a defense.
    - `failed_other`: it did not, for any other reason (refused, ignored, wrong tool).
    """

    SUCCEEDED = "succeeded"
    BLOCKED_BY_CONTROL = "blocked_by_control"
    DID_NOT_EXECUTE = "did_not_execute"
    FAILED_OTHER = "failed_other"


class BlockBasis(StrEnum):
    """How strongly a `blocked_by_control` credit is established.

    - `call_blocked`: counterfactual check passed: counting the blocked call(s) as
      executed makes the objective happen. The block provably made the difference.
    - `run_stopped`: the input classifier stopped the run before the model acted.
    - `input_withheld`: the attack payload was kept from the model (tool output
      withheld, tool definition quarantined). Whether the attack would otherwise have
      worked is not knowable from this run; compare against the baseline rate.
    - `output_redacted`: counterfactual check passed with redaction undone: the model
      carried a redaction placeholder into a call, and putting the redacted secret
      back makes the objective happen (Phase 3.5 egress filter).
    """

    CALL_BLOCKED = "call_blocked"
    RUN_STOPPED = "run_stopped"
    INPUT_WITHHELD = "input_withheld"
    OUTPUT_REDACTED = "output_redacted"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(StrEnum):
    OPEN = "open"
    MITIGATED = "mitigated"
    ACCEPTED_RISK = "accepted_risk"
    FALSE_POSITIVE = "false_positive"


def values(enum_cls: type[StrEnum]) -> tuple[str, ...]:
    """Return the string values of an enum, in declaration order."""
    return tuple(member.value for member in enum_cls)
