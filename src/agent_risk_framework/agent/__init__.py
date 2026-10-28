"""The deliberately vulnerable, over-permissioned tool-using agent (Phase 1).

Fake tools behind a local stdio MCP server, an async MCP client, and a custom
agent loop with full per-step logging to the Phase 0 SQLite run log. No
guardrails: the stated policy, recipient allowlist, and path sandbox are present
but unenforced. Defenses arrive in Phase 3.
"""

from .loop import AgentResult, AgentStep, ExecutedCall, run_agent
from .model import FakeToolModel, ModelTurn, OllamaToolModel, ToolCall, ToolCallingModel, ToolDef
from .policy import SYSTEM_CANARY, build_system_prompt
from .tools import Sandbox, ToolAudit, ToolInvocation, build_tool_server

__all__ = [
    "SYSTEM_CANARY",
    "AgentResult",
    "AgentStep",
    "ExecutedCall",
    "FakeToolModel",
    "ModelTurn",
    "OllamaToolModel",
    "Sandbox",
    "ToolAudit",
    "ToolCall",
    "ToolCallingModel",
    "ToolDef",
    "ToolInvocation",
    "build_system_prompt",
    "build_tool_server",
    "run_agent",
]
