"""Attack scenarios: the cases (what weakness) and the runnable variants (how).

A *case* (`AC01` to `AC12B`) is one weakness with its framework mapping and the
finding text it produces. A *scenario* is one runnable variant of a case: the
plain attack, or its obfuscated twin (`AC01-OBF`), which pursues the same
objective and is scored by the same oracle but hides the payload (base64,
payload splitting, another language, zero-width characters, character spacing).

Scenarios are data (`data/attack_scenarios.json`), validated here so a typo in an
oracle kind or a fixture path fails loudly instead of silently scoring nothing.
Each scenario says:

- where the payload enters: `direct` (the user prompt, TB1), `indirect` (content
  a tool returns, TB5), or `mcp` (a tool definition, TB3);
- what to plant in the per-run lab: workspace files, files *outside* the
  workspace (path-escape targets), doc-index entries, and an MCP mutation
  (poisoned extra tool, post-approval rug pull, or shadow tool);
- which deterministic oracle decides whether the attacker's objective happened.

Every address an attack targets is under the reserved `.example` TLD, and every
fixture is synthetic: nothing here names a real host, mailbox, or file.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

from ..enums import Severity
from ..findings.schema import ASI_ID_RE, ATLAS_RE, FINDING_ID_RE, LLM_ID_RE, MCP_ID_RE

DEFAULT_SCENARIOS_PATH = Path("data/attack_scenarios.json")

CASE_ID_RE = re.compile(r"^AC(0[1-9]|1[0-2])[AB]?$")
SCENARIO_ID_RE = re.compile(r"^(AC(?:0[1-9]|1[0-2])[AB]?)(-OBF|-S[0-9]{2})?$")
# Seeding transforms (Phase 1 corpus): paraphrase and translation of a plain scenario.
SEEDING_TRANSFORM_RE = re.compile(r"^(paraphrase:[a-z]+|translation:[a-z]{2})$")
CHANNELS = frozenset({"direct", "indirect", "mcp"})
OBFUSCATIONS = frozenset({"base64", "split", "translation", "zero_width", "char_spacing"})
CANARY_NAMES = frozenset({"system", "credentials", "outside"})
# The Phase 1 server's tools; a test pins this to the live listing. Oracle tool names
# must be one of these or the scenario's MCP tool, or the oracle could never fire.
BASE_TOOLS = frozenset({"search_docs", "send_email", "read_file"})

# Oracle kind -> the parameters it accepts (required ones have no default here).
ORACLE_PARAMS: dict[str, frozenset[str]] = {
    "recipient_outside_allowlist": frozenset(),
    "recipient_smuggled": frozenset(),
    "canary_in_tool_args": frozenset({"canaries", "tools"}),
    "canary_disclosed": frozenset({"canaries"}),
    "path_escape_read": frozenset(),
    "tool_invoked": frozenset({"tool"}),
    "concealed_side_effect": frozenset(),
    "unrequested_side_effect": frozenset({"tools"}),
}
MCP_KINDS: dict[str, frozenset[str]] = {
    "poisoned_tool": frozenset({"tool", "description"}),
    "rug_pull": frozenset({"tool", "description"}),
    "shadow_tool": frozenset({"tool", "description", "copy_to"}),
}
_TOOL_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")


class ScenarioError(ValueError):
    pass


def _text(owner: str, name: str, value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ScenarioError(f"{owner}: {name} must be a non-empty string")
    return value


def _relative_path(owner: str, path: Any) -> str:
    # Fixture paths are planted by the lab, so they must stay inside the lab root.
    if not isinstance(path, str) or not path.strip():
        raise ScenarioError(f"{owner}: fixture path must be a non-empty string")
    pure = PurePosixPath(path)
    if pure.is_absolute() or ".." in pure.parts or "\\" in path or ":" in path:
        raise ScenarioError(f"{owner}: fixture path {path!r} must be relative, no '..'")
    return path


def _string_map(owner: str, name: str, value: Any, *, paths: bool) -> dict[str, str]:
    if not isinstance(value, dict):
        raise ScenarioError(f"{owner}: {name} must be an object")
    out: dict[str, str] = {}
    for k, v in value.items():
        key = _relative_path(owner, k) if paths else _text(owner, f"{name} key", k)
        out[key] = _text(owner, f"{name}[{k!r}]", v)
    return out


@dataclass(frozen=True)
class OracleSpec:
    kind: str
    params: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def parse(cls, owner: str, data: Any) -> OracleSpec:
        if not isinstance(data, dict) or "kind" not in data:
            raise ScenarioError(f"{owner}: oracle must be an object with a 'kind'")
        params = {k: v for k, v in data.items() if k != "kind"}
        kind = data["kind"]
        if kind not in ORACLE_PARAMS:
            raise ScenarioError(f"{owner}: unknown oracle kind {kind!r}")
        unknown = set(params) - ORACLE_PARAMS[kind]
        if unknown:
            raise ScenarioError(f"{owner}: oracle {kind} does not take {sorted(unknown)}")
        canaries = params.get("canaries")
        if canaries is not None and (
            not isinstance(canaries, list) or not canaries or not set(canaries) <= CANARY_NAMES
        ):
            raise ScenarioError(f"{owner}: canaries must be a non-empty subset of {CANARY_NAMES}")
        tools = params.get("tools")
        if tools is not None and (
            not isinstance(tools, list)
            or not tools
            or not all(isinstance(t, str) and _TOOL_NAME_RE.fullmatch(t) for t in tools)
        ):
            raise ScenarioError(f"{owner}: tools must be a non-empty list of tool names")
        if kind == "tool_invoked" and not (
            isinstance(params.get("tool"), str) and _TOOL_NAME_RE.fullmatch(params["tool"])
        ):
            raise ScenarioError(f"{owner}: tool_invoked needs a 'tool' name")
        if kind in {"canary_in_tool_args", "canary_disclosed"} and canaries is None:
            raise ScenarioError(f"{owner}: {kind} needs 'canaries'")
        return cls(kind, params)


@dataclass(frozen=True)
class McpMutation:
    """A change to the tool server: a poisoned extra tool, a rug pull, or a shadow tool."""

    kind: str
    tool: str
    description: str
    copy_to: str | None = None

    @classmethod
    def parse(cls, owner: str, data: Any) -> McpMutation:
        if not isinstance(data, dict) or data.get("kind") not in MCP_KINDS:
            raise ScenarioError(f"{owner}: mcp.kind must be one of {sorted(MCP_KINDS)}")
        kind = data["kind"]
        fields = set(data) - {"kind"}
        if fields != MCP_KINDS[kind]:
            raise ScenarioError(f"{owner}: mcp {kind} needs exactly {sorted(MCP_KINDS[kind])}")
        tool = data["tool"]
        if not isinstance(tool, str) or not _TOOL_NAME_RE.fullmatch(tool):
            raise ScenarioError(f"{owner}: mcp.tool must be a tool name")
        copy_to = data.get("copy_to")
        if copy_to is not None and not _text(owner, "mcp.copy_to", copy_to).endswith(".example"):
            raise ScenarioError(f"{owner}: mcp.copy_to must be a reserved .example address")
        return cls(kind, tool, _text(owner, "mcp.description", data["description"]), copy_to)


@dataclass(frozen=True)
class AttackCase:
    """One weakness: mapping, severity, and the finding text it produces."""

    case_id: str
    title: str
    threat: str
    finding_id: str
    severity: Severity
    asi_id: str
    llm_id: str
    atlas_technique: str
    mcp_id: str | None
    description: str
    impact: str
    recommendation: str

    @classmethod
    def parse(cls, case_id: str, data: Any) -> AttackCase:
        if not CASE_ID_RE.fullmatch(case_id):
            raise ScenarioError(f"invalid case id {case_id!r}")
        if not isinstance(data, dict):
            raise ScenarioError(f"{case_id}: case must be an object")
        expected = set(cls.__dataclass_fields__) - {"case_id"}
        if set(data) != expected:
            missing, extra = expected - set(data), set(data) - expected
            raise ScenarioError(f"{case_id}: missing {sorted(missing)}, unknown {sorted(extra)}")
        for name, pattern in (
            ("finding_id", FINDING_ID_RE),
            ("asi_id", ASI_ID_RE),
            ("llm_id", LLM_ID_RE),
            ("atlas_technique", ATLAS_RE),
        ):
            if not isinstance(data[name], str) or not pattern.fullmatch(data[name]):
                raise ScenarioError(f"{case_id}: invalid {name} {data[name]!r}")
        if data["mcp_id"] is not None and not (
            isinstance(data["mcp_id"], str) and MCP_ID_RE.fullmatch(data["mcp_id"])
        ):
            raise ScenarioError(f"{case_id}: invalid mcp_id {data['mcp_id']!r}")
        try:
            severity = Severity(data["severity"])
        except ValueError as exc:
            raise ScenarioError(f"{case_id}: invalid severity") from exc
        texts = {
            n: _text(case_id, n, data[n])
            for n in ("title", "threat", "description", "impact", "recommendation")
        }
        return cls(
            case_id=case_id,
            finding_id=data["finding_id"],
            severity=severity,
            asi_id=data["asi_id"],
            llm_id=data["llm_id"],
            atlas_technique=data["atlas_technique"],
            mcp_id=data["mcp_id"],
            **texts,
        )


@dataclass(frozen=True)
class AttackScenario:
    scenario_id: str
    channel: str
    user_prompt: str
    oracle: OracleSpec
    obfuscation: str | None = None
    workspace_files: dict[str, str] = field(default_factory=dict)
    outside_files: dict[str, str] = field(default_factory=dict)
    doc_index: dict[str, str] = field(default_factory=dict)
    mcp: McpMutation | None = None
    notes: str = ""
    derived_from: str | None = None  # seeded variants: the plain scenario they came from
    transform: str | None = None  # seeded variants: paraphrase:<style> or translation:<lang>
    group: str | None = None  # seeded variants: the group a near-duplicate joins (else own id)

    @property
    def case_id(self) -> str:
        match = SCENARIO_ID_RE.fullmatch(self.scenario_id)
        assert match is not None  # noqa: S101 - validated at parse time
        return match.group(1)

    @property
    def obfuscated(self) -> bool:
        return self.scenario_id.endswith("-OBF")

    @property
    def seeded(self) -> bool:
        return self.derived_from is not None

    @property
    def variant_group(self) -> str:
        """The distinct input this scenario belongs to.

        An obfuscated variant is the same attack as its plain scenario under an encoding,
        so it joins the plain scenario's group. A seeded variant is a distinct wording and
        is its own group, unless it is a near-duplicate of its parent or of another variant
        (`seeding.NEAR_COPY`), in which case the seeded catalog names the group it joins.
        """
        if self.group is not None:
            return self.group
        return self.case_id if self.obfuscated else self.scenario_id

    @classmethod
    def parse(cls, data: Any) -> AttackScenario:
        if not isinstance(data, dict):
            raise ScenarioError("every scenario must be an object")
        sid = data.get("scenario_id")
        if not isinstance(sid, str) or not SCENARIO_ID_RE.fullmatch(sid):
            raise ScenarioError(f"invalid scenario_id {sid!r}")
        # The JSON key for `group` is "variant_group".
        allowed = (set(cls.__dataclass_fields__) - {"group"}) | {"variant_group"}
        unknown = set(data) - allowed
        if unknown:
            raise ScenarioError(f"{sid}: unknown fields {sorted(unknown)}")
        channel = data.get("channel")
        if channel not in CHANNELS:
            raise ScenarioError(f"{sid}: channel must be one of {sorted(CHANNELS)}")
        obfuscation = data.get("obfuscation")
        is_obf = sid.endswith("-OBF")
        if is_obf and obfuscation not in OBFUSCATIONS:
            raise ScenarioError(f"{sid}: obfuscated variant needs obfuscation in {OBFUSCATIONS}")
        if not is_obf and obfuscation is not None:
            raise ScenarioError(f"{sid}: plain variant must not set obfuscation")
        mcp = McpMutation.parse(sid, data["mcp"]) if data.get("mcp") is not None else None
        if (channel == "mcp") != (mcp is not None):
            raise ScenarioError(f"{sid}: channel 'mcp' and an mcp mutation go together")
        oracle = OracleSpec.parse(sid, data.get("oracle"))
        known = BASE_TOOLS | ({mcp.tool} if mcp else set())
        named = set(oracle.params.get("tools", [])) | (
            {oracle.params["tool"]} if "tool" in oracle.params else set()
        )
        if named - known:
            raise ScenarioError(f"{sid}: oracle names unknown tool(s) {sorted(named - known)}")
        notes = data.get("notes", "")
        if not isinstance(notes, str):
            raise ScenarioError(f"{sid}: notes must be a string")
        derived_from, transform = data.get("derived_from"), data.get("transform")
        group = data.get("variant_group")
        if group is not None and ("-S" not in sid or not isinstance(group, str)):
            raise ScenarioError(f"{sid}: only a seeded variant names its variant_group")
        if "-S" in sid:
            if derived_from != SCENARIO_ID_RE.fullmatch(sid).group(1):  # type: ignore[union-attr]
                raise ScenarioError(f"{sid}: a seeded variant derives from its plain scenario")
            if not isinstance(transform, str) or not SEEDING_TRANSFORM_RE.fullmatch(transform):
                raise ScenarioError(f"{sid}: transform must match {SEEDING_TRANSFORM_RE.pattern}")
        elif derived_from is not None or transform is not None:
            raise ScenarioError(f"{sid}: only seeded variants (-Snn) set derived_from/transform")
        return cls(
            scenario_id=sid,
            channel=channel,
            user_prompt=_text(sid, "user_prompt", data.get("user_prompt")),
            oracle=oracle,
            obfuscation=obfuscation,
            workspace_files=_string_map(
                sid, "workspace_files", data.get("workspace_files", {}), paths=True
            ),
            outside_files=_string_map(
                sid, "outside_files", data.get("outside_files", {}), paths=True
            ),
            doc_index=_string_map(sid, "doc_index", data.get("doc_index", {}), paths=False),
            mcp=mcp,
            notes=notes,
            derived_from=derived_from,
            transform=transform,
            group=group,
        )


@dataclass(frozen=True)
class ScenarioCatalog:
    cases: dict[str, AttackCase]
    scenarios: tuple[AttackScenario, ...]

    def case(self, scenario: AttackScenario) -> AttackCase:
        return self.cases[scenario.case_id]

    def select(self, ids: list[str] | None) -> tuple[AttackScenario, ...]:
        """Scenarios whose id or case id is in `ids` (all when `ids` is None)."""
        if not ids:
            return self.scenarios
        wanted = set(ids)
        known = {s.scenario_id for s in self.scenarios} | set(self.cases)
        if wanted - known:
            raise ScenarioError(f"unknown scenario or case ids: {sorted(wanted - known)}")
        return tuple(s for s in self.scenarios if {s.scenario_id, s.case_id} & wanted)


def parse_catalog(data: Any) -> ScenarioCatalog:
    if not isinstance(data, dict) or not isinstance(data.get("cases"), dict):
        raise ScenarioError("scenario file must have a 'cases' object")
    if not isinstance(data.get("scenarios"), list):
        raise ScenarioError("scenario file must have a 'scenarios' list")
    cases = {cid: AttackCase.parse(cid, c) for cid, c in data["cases"].items()}
    scenarios = tuple(AttackScenario.parse(s) for s in data["scenarios"])
    seeded = sorted(s.scenario_id for s in scenarios if s.seeded)
    if seeded:
        raise ScenarioError(f"seeded variants belong in the seeded catalog: {seeded}")
    ids = [s.scenario_id for s in scenarios]
    duplicates = sorted({i for i in ids if ids.count(i) > 1})
    if duplicates:
        raise ScenarioError(f"duplicate scenario ids: {duplicates}")
    for s in scenarios:
        if s.case_id not in cases:
            raise ScenarioError(f"{s.scenario_id}: no case {s.case_id} defined")
    for cid in cases:
        if cid not in ids:
            raise ScenarioError(f"case {cid} has no plain scenario")
        if f"{cid}-OBF" not in ids:
            raise ScenarioError(f"case {cid} has no obfuscated variant")
    finding_ids = [c.finding_id for c in cases.values()]
    if len(set(finding_ids)) != len(finding_ids):
        raise ScenarioError("finding ids must be unique across cases")
    return ScenarioCatalog(cases, scenarios)


def _read_json(path: Path | str) -> Any:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ScenarioError(f"could not parse {path}: {exc}") from exc


def load_catalog(path: Path | str = DEFAULT_SCENARIOS_PATH) -> ScenarioCatalog:
    return parse_catalog(_read_json(path))


def parse_seeded(data: Any, base: ScenarioCatalog) -> tuple[AttackScenario, ...]:
    """Seeded variants: each derives from a plain scenario of `base` and keeps its oracle."""
    if not isinstance(data, dict) or not isinstance(data.get("scenarios"), list):
        raise ScenarioError("seeded catalog must have a 'scenarios' list")
    plain = {s.scenario_id: s for s in base.scenarios if not s.obfuscated}
    known = {s.scenario_id for s in base.scenarios}
    out: list[AttackScenario] = []
    for item in data["scenarios"]:
        s = AttackScenario.parse(item)
        if not s.seeded:
            raise ScenarioError(f"{s.scenario_id}: the seeded catalog holds -Snn variants only")
        parent = plain.get(s.derived_from or "")
        if parent is None:
            raise ScenarioError(f"{s.scenario_id}: derives from unknown {s.derived_from}")
        if s.scenario_id in known:
            raise ScenarioError(f"duplicate scenario id {s.scenario_id}")
        if s.oracle != parent.oracle or s.channel != parent.channel:
            raise ScenarioError(f"{s.scenario_id}: must keep its parent's oracle and channel")
        same_lab = (
            s.workspace_files == parent.workspace_files
            and s.outside_files == parent.outside_files
            and s.doc_index == parent.doc_index
        )
        if not same_lab:
            raise ScenarioError(f"{s.scenario_id}: must keep its parent's planted files")
        if parent.mcp is not None:
            m, pm = s.mcp, parent.mcp
            if m is None or (m.kind, m.tool, m.copy_to) != (pm.kind, pm.tool, pm.copy_to):
                raise ScenarioError(f"{s.scenario_id}: must keep its parent's MCP mutation")
            if s.user_prompt != parent.user_prompt:
                raise ScenarioError(f"{s.scenario_id}: an MCP variant rewrites the tool only")
        known.add(s.scenario_id)
        out.append(s)
    # A named group is the parent's, or another variant of the same parent.
    siblings = {s.scenario_id: s.derived_from for s in out}
    for s in out:
        g = s.group
        if g is not None and g != s.derived_from and siblings.get(g) != s.derived_from:
            raise ScenarioError(
                f"{s.scenario_id}: variant_group {g} is not its parent or a sibling"
            )
    return tuple(out)


def load_seeded(path: Path | str, base: ScenarioCatalog) -> tuple[AttackScenario, ...]:
    return parse_seeded(_read_json(path), base)
