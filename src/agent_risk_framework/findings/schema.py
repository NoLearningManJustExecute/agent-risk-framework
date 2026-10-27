"""Finding record: one security weakness, with framework mappings and evidence.

Mapping precedence follows the threat model: OWASP Agentic Top 10 (ASI) is
required and primary; OWASP LLM Top 10 2026 is secondary; OWASP MCP Top 10 is
optional because that list is still in beta; MITRE ATLAS technique is required.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any

from ..enums import DetectorVerdict, FindingStatus, GuardrailAction, Severity

SCHEMA_VERSION = 1

# [0-9], not \d: \d also matches non-ASCII digits, which would reach filenames.
FINDING_ID_RE = re.compile(r"^ARF-[0-9]{4,8}$")
ASI_ID_RE = re.compile(r"^ASI(0[1-9]|10)$")
LLM_ID_RE = re.compile(r"^LLM(0[1-9]|10):2026$")
MCP_ID_RE = re.compile(r"^MCP(0[1-9]|10):2025$")
ATLAS_RE = re.compile(r"^AML\.T[0-9]{4}(\.[0-9]{3})?$")
EVIDENCE_KIND_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")

REQUIRED_TEXT = ("title", "category", "attack_case", "description", "impact", "recommendation")


class FindingValidationError(ValueError):
    pass


@dataclass(frozen=True)
class Evidence:
    """One piece of supporting evidence. `content` is untrusted (may hold attack text)."""

    kind: str  # e.g. "transcript_excerpt", "tool_call", "run_log"
    content: str
    run_id: int | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.kind, str) or not EVIDENCE_KIND_RE.fullmatch(self.kind):
            raise FindingValidationError(f"invalid evidence.kind: {self.kind!r}")
        if not isinstance(self.content, str):
            raise FindingValidationError("evidence.content must be a string")
        if self.run_id is not None and (
            isinstance(self.run_id, bool) or not isinstance(self.run_id, int)
        ):
            raise FindingValidationError("evidence.run_id must be an int or null")


@dataclass(frozen=True)
class Finding:
    finding_id: str
    title: str
    severity: Severity
    category: str
    asi_id: str
    llm_id: str
    atlas_technique: str
    attack_case: str
    status: FindingStatus
    description: str
    impact: str
    detection_result: DetectorVerdict
    guardrail_action: GuardrailAction
    recommendation: str
    evidence: tuple[Evidence, ...] = ()
    mcp_id: str | None = None  # OWASP MCP Top 10 is beta; mappings may change
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def __post_init__(self) -> None:
        # Coerce plain strings into enums so from_dict and direct use behave the same.
        for name, enum_cls in (
            ("severity", Severity),
            ("status", FindingStatus),
            ("detection_result", DetectorVerdict),
            ("guardrail_action", GuardrailAction),
        ):
            try:
                object.__setattr__(self, name, enum_cls(getattr(self, name)))
            except ValueError as exc:
                raise FindingValidationError(f"invalid {name}: {exc}") from exc
        object.__setattr__(self, "evidence", tuple(self.evidence))
        self._validate()

    def _validate(self) -> None:
        checks = (
            ("finding_id", FINDING_ID_RE, self.finding_id),
            ("asi_id", ASI_ID_RE, self.asi_id),
            ("llm_id", LLM_ID_RE, self.llm_id),
            ("atlas_technique", ATLAS_RE, self.atlas_technique),
        )
        for name, pattern, value in checks:
            if not isinstance(value, str) or not pattern.fullmatch(value):
                raise FindingValidationError(f"invalid {name}: {value!r}")
        if self.mcp_id is not None and not MCP_ID_RE.fullmatch(self.mcp_id):
            raise FindingValidationError(f"invalid mcp_id: {self.mcp_id!r}")
        for name in REQUIRED_TEXT:
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise FindingValidationError(f"{name} must be a non-empty string")
        if not all(isinstance(e, Evidence) for e in self.evidence):
            raise FindingValidationError("evidence items must be Evidence instances")
        try:
            parsed = datetime.fromisoformat(self.timestamp)
        except (TypeError, ValueError) as exc:
            raise FindingValidationError(f"invalid timestamp: {self.timestamp!r}") from exc
        if parsed.tzinfo is None:
            raise FindingValidationError("timestamp must be timezone-aware")

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        for name in ("severity", "status", "detection_result", "guardrail_action"):
            data[name] = str(data[name])
        data["evidence"] = [asdict(e) for e in self.evidence]
        return {"schema_version": SCHEMA_VERSION, **data}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Finding:
        data = dict(data)
        version = data.pop("schema_version", SCHEMA_VERSION)
        if version != SCHEMA_VERSION:
            raise FindingValidationError(f"unsupported schema_version {version!r}")
        known = set(cls.__dataclass_fields__)
        unknown = set(data) - known
        if unknown:
            raise FindingValidationError(f"unknown fields: {sorted(unknown)}")
        raw_evidence = data.pop("evidence", [])
        if not isinstance(raw_evidence, list) or not all(isinstance(e, dict) for e in raw_evidence):
            raise FindingValidationError("evidence must be a list of objects")
        try:
            evidence = tuple(Evidence(**e) for e in raw_evidence)
            return cls(evidence=evidence, **data)
        except TypeError as exc:  # missing or unexpected fields
            raise FindingValidationError(str(exc)) from exc
