"""Thin helpers over the MCP `Client`: connect, list tools, read a result.

These isolate the agent loop from the MCP SDK's surface so a version bump touches
one file. `connect_in_process` wires the client straight to a server object (no
sockets, no subprocess) for tests and dry runs; `stdio_params` builds the launch
parameters for the real stdio subprocess used in live runs.
"""

from __future__ import annotations

import sys
from typing import Any

from mcp import Client, StdioServerParameters
from mcp.server.mcpserver import MCPServer

from .model import ToolDef
from .tools import DEFAULT_DOC_INDEX, DEFAULT_SANDBOX


def connect_in_process(server: MCPServer, *, mode: str = "auto") -> Client:
    """A client bound to an in-process server (no network, no subprocess)."""
    return Client(server, mode=mode)


def stdio_params(
    sandbox_root: str = str(DEFAULT_SANDBOX), doc_index: str = str(DEFAULT_DOC_INDEX)
) -> StdioServerParameters:
    """Launch parameters for the stdio tool server as a subprocess."""
    return StdioServerParameters(
        command=sys.executable,
        args=["-m", "agent_risk_framework.agent.server", sandbox_root, doc_index],
    )


def connect_stdio(
    sandbox_root: str = str(DEFAULT_SANDBOX), doc_index: str = str(DEFAULT_DOC_INDEX)
) -> Client:
    """A client that launches and talks to the stdio tool server subprocess."""
    return Client(stdio_params(sandbox_root, doc_index))


async def list_tool_defs(client: Client) -> list[ToolDef]:
    """Fetch the server's tools as `ToolDef`s for the model's tool list."""
    listing = await client.list_tools()
    defs: list[ToolDef] = []
    for tool in listing.tools:
        schema = dict(tool.input_schema or {})
        schema.setdefault("type", "object")
        defs.append(ToolDef(name=tool.name, description=tool.description or "", parameters=schema))
    return defs


def result_text(result: Any) -> tuple[str, bool]:
    """Flatten a CallToolResult into (text, is_error)."""
    is_error = bool(getattr(result, "is_error", False))
    parts: list[str] = []
    for block in getattr(result, "content", None) or []:
        text = getattr(block, "text", None)
        if isinstance(text, str):
            parts.append(text)
    return "\n".join(parts), is_error
