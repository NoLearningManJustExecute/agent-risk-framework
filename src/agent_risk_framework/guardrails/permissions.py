"""Least-privilege tool-permission layer: deterministic checks before dispatch.

Two rules, both inert data in Phase 1 and enforced here:

- **Recipient allowlist.** Any call carrying a recipient argument (`to`, `cc`,
  `bcc`, on any tool, so a look-alike send tool is covered too) must name only
  approved addresses. Parsing is strict and fails closed: a value that is not a
  string, contains a header line break, holds no address, or holds more `@` signs
  than parsed addresses (something the parser dropped) is refused.
- **Path sandbox.** `read_file` paths must stay inside the workspace root, checked
  both lexically (no absolute path, drive letter or `..` that climbs out) and after
  resolving symlinks against the real root, and must not enter a restricted
  subtree (the secret store).

A call whose arguments could not be parsed as a JSON object is refused: this layer
never guesses what an unreadable call would do.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from email.utils import getaddresses
from pathlib import Path, PurePosixPath
from typing import Any

from ..agent.model import ToolCall
from ..agent.policy import RECIPIENT_ALLOWLIST, RECIPIENT_ARGS, RESTRICTED_PATHS

_DRIVE_RE = re.compile(r"^[A-Za-z]:")
_HEADER_BREAK_RE = re.compile(r"[\r\n]")
_ADDRESS_RE = re.compile(r"[^\s<>,;:\"'()\[\]]+@[^\s<>,;:\"'()\[\]]+")
PATH_TOOLS = ("read_file",)


def _parsed_arguments(call: ToolCall) -> Mapping[str, Any] | None:
    # `arguments` is {} when the model's raw JSON did not parse; tell that apart from
    # a genuinely empty call by looking at the raw text.
    if call.arguments or call.raw_arguments.strip() in ("", "{}"):
        return call.arguments
    return None


def recipient_problems(value: Any, allowed: frozenset[str]) -> list[str]:
    """Why one recipient value is not acceptable (empty list: it is)."""
    if not isinstance(value, str):
        return [f"non-string recipient value {value!r}"]
    if _HEADER_BREAK_RE.search(value):
        return ["header line break in recipient"]
    parsed = {addr.strip().casefold() for _, addr in getaddresses([value]) if "@" in addr}
    found = {a.casefold() for a in _ADDRESS_RE.findall(value)}
    addresses = parsed | found
    if not addresses:
        return [f"no address in {value!r}"]
    if value.count("@") > len(addresses):
        return [f"unparseable recipient list {value!r}"]
    return [f"{a!r} is not on the recipient allowlist" for a in sorted(addresses - allowed)]


def path_problems(path: Any, root: Path | None, restricted: Iterable[str]) -> list[str]:
    """Why one `read_file` path is not acceptable (empty list: it is)."""
    if not isinstance(path, str) or not path.strip():
        return [f"invalid path {path!r}"]
    norm = path.replace("\\", "/")
    if norm.startswith("/") or _DRIVE_RE.match(norm):
        return [f"absolute path {path!r} leaves the workspace"]
    depth = 0
    parts: list[str] = []
    for part in norm.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            depth -= 1
            if depth < 0:
                return [f"path {path!r} climbs out of the workspace"]
            parts.pop()
        else:
            depth += 1
            parts.append(part)
    if root is not None:
        try:
            resolved = (root / norm).resolve()
            inside = resolved.is_relative_to(root.resolve())
        except (OSError, ValueError):
            return [f"path {path!r} could not be resolved"]
        if not inside:
            return [f"path {path!r} resolves outside the workspace"]
    rel = PurePosixPath(*parts).as_posix().casefold() if parts else ""
    for prefix in restricted:
        p = prefix.casefold().rstrip("/")
        if rel == p or rel.startswith(p + "/"):
            return [f"path {path!r} is in the restricted area {prefix!r}"]
    return []


class ToolPermissions:
    """Checks one tool call against the allowlist and the path sandbox."""

    def __init__(
        self,
        *,
        allowlist: Iterable[str] = RECIPIENT_ALLOWLIST,
        workspace_root: Path | str | None = None,
        restricted_paths: Iterable[str] = RESTRICTED_PATHS,
    ) -> None:
        self.allowed = frozenset(a.strip().casefold() for a in allowlist)
        self.root = None if workspace_root is None else Path(workspace_root)
        self.restricted = tuple(restricted_paths)

    def problems(self, call: ToolCall) -> list[str]:
        args = _parsed_arguments(call)
        if args is None:
            return [f"{call.name}: unreadable arguments"]
        problems: list[str] = []
        for key, value in args.items():
            if isinstance(key, str) and key.casefold() in RECIPIENT_ARGS:
                items = value if isinstance(value, list | tuple) else [value]
                for item in items or [None]:
                    problems += [f"{key}: {p}" for p in recipient_problems(item, self.allowed)]
        if call.name in PATH_TOOLS:
            problems += path_problems(args.get("path"), self.root, self.restricted)
        if call.name == "send_email" and "to" not in args:
            problems.append("send_email without a 'to' recipient")
        return problems
