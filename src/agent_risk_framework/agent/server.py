"""Run the fake tools as a local stdio MCP server.

    python -m agent_risk_framework.agent.server [SANDBOX_ROOT] [DOC_INDEX]

The agent launches this as a subprocess and talks to it over stdin/stdout. It is
local-only by construction: stdio has no network listener. The sandbox root and
doc index default to the committed synthetic fixtures.
"""

from __future__ import annotations

import sys

from .tools import DEFAULT_DOC_INDEX, DEFAULT_SANDBOX, Sandbox, build_tool_server


def main(argv: list[str] | None = None) -> None:
    args = list(sys.argv[1:] if argv is None else argv)
    root = args[0] if args else str(DEFAULT_SANDBOX)
    index = args[1] if len(args) > 1 else str(DEFAULT_DOC_INDEX)
    server = build_tool_server(Sandbox.load(root, index))
    server.run("stdio")


if __name__ == "__main__":
    main()
