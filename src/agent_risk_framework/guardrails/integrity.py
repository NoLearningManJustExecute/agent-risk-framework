"""MCP tool-definition integrity: vet, pin, detect drift, detect shadow tools.

Phase 2's MCP attacks never needed a tool call to land: a tool *definition* is
model context. This control treats definitions as untrusted input and works at
two moments.

**Approval** (`approve`, the first listing a human would sign off on). Each tool
is checked against the reviewed registry (`configs/tool_registry.json`: the
SHA-256 of every reviewed tool's name, description and input schema), then vetted:

- `definition_mismatch`: a registry tool whose live definition differs from its pin;
- `shadow_tool`: a new tool whose name contains or is contained in a reviewed
  tool's name, or that takes exactly a reviewed tool's parameters
  (`send_email_secure` next to `send_email`);
- `cross_tool_reference`: the description names another tool, so it is trying to
  change how that tool is used (catches the poisoned and shadow descriptions in
  every language, because tool names are not translated);
- `embedded_address`: an email address or URL in a description;
- `hidden_characters`, `encoded_payload`: invisible characters or a base64 blob;
- the injection classifier's rules (instruction markup, `you must`, hiding things
  from the user, secret-store paths) at its normal threshold.

Clean tools are pinned (trust on first use for tools not in the registry);
flagged ones are quarantined.

**Admission** (`admit`, every later listing, e.g. at run start). The live list is
compared to the pins: a changed definition (`drift`, the rug pull) or a tool that
appeared after approval (`unapproved_tool`) is quarantined: removed from the
model's tool list, and any call to it is refused (`check_call`). Quarantine fails
closed; serving the pinned description of a tool whose server-side definition has
changed would trust the server that just changed it.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from ..agent.model import ToolCall, ToolDef
from .classifier import classify
from .text import decoded_payloads, hidden_characters, normalize

DEFAULT_REGISTRY = Path("configs/tool_registry.json")
_ADDRESS_RE = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+|\bhttps?://\S+")


def definition_hash(tool: ToolDef) -> str:
    """SHA-256 over one tool's name, description and input schema."""
    canon = json.dumps([tool.name, tool.description, tool.parameters], sort_keys=True)
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()


def parameter_names(tool: ToolDef) -> tuple[str, ...]:
    return tuple(sorted((tool.parameters.get("properties") or {}).keys()))


@dataclass(frozen=True)
class RegistryEntry:
    sha256: str
    parameters: tuple[str, ...]


@dataclass(frozen=True)
class ToolRegistry:
    """Reviewed tool definitions, by name. Empty registry: trust on first use only."""

    tools: Mapping[str, RegistryEntry]

    @classmethod
    def empty(cls) -> ToolRegistry:
        return cls({})

    @classmethod
    def from_tools(cls, tools: Iterable[ToolDef]) -> ToolRegistry:
        return cls({t.name: RegistryEntry(definition_hash(t), parameter_names(t)) for t in tools})

    @classmethod
    def load(cls, path: Path | str = DEFAULT_REGISTRY) -> ToolRegistry:
        data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
        tools = data.get("tools") if isinstance(data, dict) else None
        if not isinstance(tools, dict):
            raise ValueError(f"{path}: registry needs a 'tools' object")
        out: dict[str, RegistryEntry] = {}
        for name, entry in tools.items():
            sha, params = entry.get("sha256"), entry.get("parameters")
            if not (isinstance(sha, str) and re.fullmatch(r"[0-9a-f]{64}", sha)):
                raise ValueError(f"{path}: {name} needs a sha256 hex digest")
            if not (isinstance(params, list) and all(isinstance(p, str) for p in params)):
                raise ValueError(f"{path}: {name} needs a list of parameter names")
            out[name] = RegistryEntry(sha, tuple(sorted(params)))
        return cls(out)

    def to_json(self) -> str:
        data = {
            "version": 1,
            "description": (
                "Reviewed MCP tool definitions. sha256 covers name, description and input "
                "schema; regenerate with python -m agent_risk_framework.guardrails.integrity "
                "--write-registry after reviewing a tool change."
            ),
            "tools": {
                name: {"sha256": e.sha256, "parameters": list(e.parameters)}
                for name, e in sorted(self.tools.items())
            },
        }
        return json.dumps(data, indent=2) + "\n"


def _squash(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.casefold())


def _mentions_tool(text: str, name: str) -> bool:
    return re.search(rf"(?<![a-z0-9_]){re.escape(name.casefold())}(?![a-z0-9_])", text) is not None


def vet_definition(tool: ToolDef, *, others: Iterable[str], registry: ToolRegistry) -> list[str]:
    """Why this definition should not be trusted (empty list: it passes)."""
    problems: list[str] = []
    reviewed = registry.tools.get(tool.name)
    if reviewed is not None:
        if reviewed.sha256 != definition_hash(tool):
            problems.append("definition_mismatch: differs from the reviewed registry pin")
    else:
        squashed, params = _squash(tool.name), parameter_names(tool)
        for name, entry in registry.tools.items():
            other = _squash(name)
            if other in squashed or squashed in other:
                problems.append(f"shadow_tool: name overlaps reviewed tool {name!r}")
            elif params and params == entry.parameters:
                problems.append(f"shadow_tool: same parameters as reviewed tool {name!r}")
    desc = tool.description
    texts = [normalize(desc)] + [normalize(p) for p in decoded_payloads(desc)]
    referenced = sorted(
        {n for n in others if n != tool.name and any(_mentions_tool(t, n) for t in texts)}
    )
    if referenced:
        problems.append(f"cross_tool_reference: description names {referenced}")
    if any(_ADDRESS_RE.search(t) for t in texts):
        problems.append("embedded_address: description contains an address or URL")
    hidden = hidden_characters(desc)
    if hidden:
        problems.append(f"hidden_characters: {sorted(set(hidden))}")
    if decoded_payloads(desc):
        problems.append("encoded_payload: description carries a base64 payload")
    verdict = classify(desc)
    if verdict.flagged:
        problems.append(f"injection_rules: {verdict.reasons()[0]}")
    return problems


@dataclass(frozen=True)
class DefinitionCheck:
    tool: str
    allowed: bool
    reasons: tuple[str, ...]


class ToolIntegrity:
    """Pins vetted definitions at approval and quarantines anything that drifts."""

    def __init__(self, registry: ToolRegistry | None = None) -> None:
        self.registry = registry or ToolRegistry.empty()
        self.pins: dict[str, str] = {}
        self.rejected: dict[str, tuple[str, ...]] = {}
        self.admitted: frozenset[str] = frozenset()
        self._admission_done = False

    def approve(self, tools: Sequence[ToolDef]) -> list[DefinitionCheck]:
        names = {t.name for t in tools} | set(self.registry.tools)
        checks: list[DefinitionCheck] = []
        for tool in tools:
            problems = vet_definition(tool, others=names, registry=self.registry)
            if problems:
                self.rejected[tool.name] = tuple(problems)
                checks.append(DefinitionCheck(tool.name, False, tuple(problems)))
            else:
                self.pins[tool.name] = definition_hash(tool)
                checks.append(DefinitionCheck(tool.name, True, ("vetted and pinned",)))
        return checks

    def admit(self, tools: Sequence[ToolDef]) -> tuple[list[ToolDef], list[DefinitionCheck]]:
        """The tools the model may see, plus one check per listed tool."""
        allowed: list[ToolDef] = []
        checks: list[DefinitionCheck] = []
        for tool in tools:
            pin = self.pins.get(tool.name)
            if tool.name in self.rejected:
                reasons = ("quarantined: rejected at approval",)
            elif pin is None:
                reasons = ("unapproved_tool: appeared after approval",)
            elif pin != definition_hash(tool):
                reasons = ("drift: definition changed since approval",)
            else:
                allowed.append(tool)
                checks.append(DefinitionCheck(tool.name, True, ("matches its pin",)))
                continue
            checks.append(DefinitionCheck(tool.name, False, reasons))
        self.admitted = frozenset(t.name for t in allowed)
        self._admission_done = True
        return allowed, checks

    def call_problems(self, call: ToolCall) -> list[str]:
        if not self._admission_done:
            return ["tool list was never admitted"]
        if call.name in self.admitted:
            return []
        return [f"{call.name!r} is not an admitted tool (quarantined or never listed)"]


async def _base_tool_defs() -> list[ToolDef]:
    import tempfile

    from ..agent.client import connect_in_process, list_tool_defs
    from ..agent.tools import Sandbox, build_tool_server

    with tempfile.TemporaryDirectory(prefix="arf-registry-") as tmp:
        async with connect_in_process(build_tool_server(Sandbox(tmp))) as client:
            return await list_tool_defs(client)


def base_registry() -> ToolRegistry:
    """The registry the Phase 1 tool server would produce right now."""
    import anyio

    return ToolRegistry.from_tools(anyio.run(_base_tool_defs))


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Show or rewrite the reviewed tool registry.")
    parser.add_argument("--registry", default=str(DEFAULT_REGISTRY))
    parser.add_argument("--write-registry", action="store_true")
    args = parser.parse_args(argv)
    text = base_registry().to_json()
    if args.write_registry:
        Path(args.registry).write_text(text, encoding="utf-8", newline="\n")
    print(text, end="")


if __name__ == "__main__":
    main()
