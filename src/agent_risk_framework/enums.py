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
