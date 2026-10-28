"""Guardrails: six independently switchable controls and a decision log.

- `tool_permissions`  (deterministic): recipient allowlist on any recipient
  argument; `read_file` sandboxed to the workspace root, secret store denied.
- `tool_integrity`    (deterministic): vet tool definitions, pin them at approval,
  quarantine drift (rug pull), unapproved and shadow tools.
- `approval_gate`     (deterministic): state-changing calls need approval, rendered
  from the real call; a simulated reviewer approves.
- `input_classifier`  (rule-based): injection/override in the user prompt.
- `output_classifier` (rule-based): the same rules on tool output, before the model
  reads it. Defense in depth: this model gave it no baseline target (AC09/AC10 0/20).
- `egress_filter`     (rule-based, Phase 3.5): secrets and PII in outbound tool
  arguments (call blocked) and in tool output (redacted before the model reads it).

`GuardrailEngine` runs whichever are enabled (`GuardrailConfig`) and logs every
evaluation, allow or block, as a `Decision`.
"""

from .approval import ApprovalGate, SimulatedReviewer, render_call
from .classifier import Classification, classify
from .config import PRESETS, GuardrailConfig
from .egress import EgressFilter, Redaction
from .engine import Decision, GuardrailEngine
from .integrity import (
    DEFAULT_REGISTRY,
    ToolIntegrity,
    ToolRegistry,
    definition_hash,
    vet_definition,
)
from .permissions import ToolPermissions, path_problems, recipient_problems

__all__ = [
    "DEFAULT_REGISTRY",
    "PRESETS",
    "ApprovalGate",
    "Classification",
    "Decision",
    "EgressFilter",
    "GuardrailConfig",
    "GuardrailEngine",
    "Redaction",
    "SimulatedReviewer",
    "ToolIntegrity",
    "ToolPermissions",
    "ToolRegistry",
    "classify",
    "definition_hash",
    "path_problems",
    "recipient_problems",
    "render_call",
    "vet_definition",
]
