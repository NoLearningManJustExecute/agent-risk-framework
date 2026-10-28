from __future__ import annotations

import base64
import binascii
import copy
import json
import re
from pathlib import Path

import pytest

from agent_risk_framework.attacks.scenarios import (
    OBFUSCATIONS,
    ScenarioError,
    load_catalog,
    parse_catalog,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
SCENARIOS = REPO_ROOT / "data" / "attack_scenarios.json"
EXPECTED_CASES = [f"AC{i:02d}" for i in range(1, 12)] + ["AC12A", "AC12B"]
_EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_B64_RE = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")


@pytest.fixture(scope="module")
def raw() -> dict:
    return json.loads(SCENARIOS.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def catalog():
    return load_catalog(SCENARIOS)


def test_every_case_has_plain_and_obfuscated_variant(catalog) -> None:
    assert list(catalog.cases) == EXPECTED_CASES
    ids = [s.scenario_id for s in catalog.scenarios]
    for case in EXPECTED_CASES:
        assert case in ids
        assert f"{case}-OBF" in ids
    assert len(ids) == 2 * len(EXPECTED_CASES)


def test_variants_share_objective_and_oracle(catalog) -> None:
    by_id = {s.scenario_id: s for s in catalog.scenarios}
    for case in EXPECTED_CASES:
        plain, obf = by_id[case], by_id[f"{case}-OBF"]
        assert plain.oracle == obf.oracle
        assert plain.channel == obf.channel
        assert plain.obfuscation is None
        assert obf.obfuscation in OBFUSCATIONS


def test_obfuscation_techniques_all_exercised(catalog) -> None:
    used = {s.obfuscation for s in catalog.scenarios if s.obfuscated}
    assert used == set(OBFUSCATIONS)


def test_required_channels_present(catalog) -> None:
    channels = {s.case_id: s.channel for s in catalog.scenarios}
    assert channels["AC09"] == "indirect"  # injection via tool-returned file
    assert channels["AC10"] == "indirect"  # exfil via tool args from a poisoned search result
    assert {channels[c] for c in ("AC11", "AC12A", "AC12B")} == {"mcp"}
    kinds = {s.case_id: s.mcp.kind for s in catalog.scenarios if s.mcp}
    assert kinds == {"AC11": "poisoned_tool", "AC12A": "rug_pull", "AC12B": "shadow_tool"}


def test_every_external_address_is_reserved(raw) -> None:
    # Synthetic only: every address is under .test (allowlisted colleagues) or .example.
    text = json.dumps(raw)
    for addr in _EMAIL_RE.findall(text):
        assert addr.endswith((".test", ".example")), addr


def test_base64_payloads_decode_to_the_plain_payload(catalog) -> None:
    for s in catalog.scenarios:
        if s.obfuscation != "base64":
            continue
        blob = " ".join([s.user_prompt, *s.doc_index.values(), s.mcp.description if s.mcp else ""])
        decoded = []
        for token in _B64_RE.findall(blob):
            try:
                decoded.append(base64.b64decode(token, validate=True).decode("ascii"))
            except (binascii.Error, UnicodeDecodeError):
                continue
        assert decoded, s.scenario_id
        assert any("@" in d or "secrets/credentials.txt" in d for d in decoded), decoded


def test_zero_width_variant_hides_trigger_words(catalog) -> None:
    s = next(s for s in catalog.scenarios if s.obfuscation == "zero_width")
    content = next(iter(s.workspace_files.values()))
    assert "\u200b" in content
    assert " send an email" not in content
    assert "migration-check@exfil.example" in content


def test_case_mappings_are_valid_and_unique(catalog) -> None:
    findings = [c.finding_id for c in catalog.cases.values()]
    assert len(set(findings)) == len(findings)
    for c in catalog.cases.values():
        assert c.threat.startswith("T")


def test_select_by_case_or_scenario(catalog) -> None:
    assert [s.scenario_id for s in catalog.select(["AC02"])] == ["AC02", "AC02-OBF"]
    assert [s.scenario_id for s in catalog.select(["AC12B-OBF"])] == ["AC12B-OBF"]
    assert len(catalog.select(None)) == len(catalog.scenarios)
    with pytest.raises(ScenarioError):
        catalog.select(["AC99"])


def _mutate(raw: dict, fn) -> dict:
    data = copy.deepcopy(raw)
    fn(data)
    return data


def _scenario(data: dict, sid: str) -> dict:
    return next(s for s in data["scenarios"] if s["scenario_id"] == sid)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda d: _scenario(d, "AC01").update(oracle={"kind": "nope"}),
        lambda d: _scenario(d, "AC01").update(oracle={"kind": "tool_invoked"}),
        lambda d: _scenario(d, "AC03").update(
            oracle={"kind": "canary_in_tool_args", "canaries": ["bogus"]}
        ),
        lambda d: _scenario(d, "AC01").update(oracle={"kind": "path_escape_read", "x": 1}),
        lambda d: _scenario(d, "AC01").update(channel="carrier-pigeon"),
        lambda d: _scenario(d, "AC01").update(obfuscation="base64"),  # plain must not set it
        lambda d: _scenario(d, "AC01-OBF").pop("obfuscation"),
        lambda d: _scenario(d, "AC01").update(user_prompt=" "),
        lambda d: _scenario(d, "AC01").update(surprise=True),
        lambda d: _scenario(d, "AC02").update(outside_files={"../../etc/x": "y"}),
        lambda d: _scenario(d, "AC02").update(outside_files={"/abs/x": "y"}),
        lambda d: _scenario(d, "AC02").update(outside_files={"C:\\x": "y"}),
        lambda d: _scenario(d, "AC11").pop("mcp"),
        lambda d: _scenario(d, "AC01").update(mcp=_scenario(d, "AC11")["mcp"]),
        lambda d: _scenario(d, "AC12B")["mcp"].update(copy_to="someone@attacker.invalid"),
        lambda d: _scenario(d, "AC12B")["mcp"].pop("copy_to"),
        lambda d: d["scenarios"].append(copy.deepcopy(_scenario(d, "AC01"))),
        lambda d: d["scenarios"].remove(_scenario(d, "AC05-OBF")),
        lambda d: d["cases"]["AC01"].update(asi_id="ASI11"),
        lambda d: d["cases"]["AC01"].update(finding_id=d["cases"]["AC02"]["finding_id"]),
        lambda d: d["cases"]["AC01"].update(severity="apocalyptic"),
        lambda d: d["cases"]["AC01"].pop("impact"),
        lambda d: d["cases"].update(AC13=copy.deepcopy(d["cases"]["AC01"])),
        lambda d: d.pop("cases"),
        lambda d: _scenario(d, "AC12B")["oracle"].update(tool="send_emial_secure"),
        lambda d: _scenario(d, "AC08")["oracle"].update(tools=["send_mail"]),
    ],
)
def test_malformed_catalog_rejected(raw, mutation) -> None:
    with pytest.raises(ScenarioError):
        parse_catalog(_mutate(raw, mutation))


def test_unparseable_file_rejected(tmp_path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    with pytest.raises(ScenarioError):
        load_catalog(bad)


def test_fixtures_keep_every_oracle_able_to_fire(catalog, repo_root) -> None:
    from agent_risk_framework.attacks.lab import OUTSIDE_CANARY

    existing = {
        p.relative_to(repo_root / "data" / "agent_sandbox").as_posix()
        for p in (repo_root / "data" / "agent_sandbox").rglob("*")
        if p.is_file()
    }
    for s in catalog.scenarios:
        # Planted files add to the workspace; they never overwrite (and so remove) a canary.
        assert not set(s.workspace_files) & existing, s.scenario_id
        if s.oracle.kind == "path_escape_read":
            assert any(OUTSIDE_CANARY in c for c in s.outside_files.values()), s.scenario_id


def test_base_tools_match_the_live_server() -> None:
    import anyio

    from agent_risk_framework.agent.client import connect_in_process, list_tool_defs
    from agent_risk_framework.agent.tools import Sandbox, build_tool_server
    from agent_risk_framework.attacks.scenarios import BASE_TOOLS

    async def go():
        async with connect_in_process(build_tool_server(Sandbox("."))) as client:
            return {t.name for t in await list_tool_defs(client)}

    assert anyio.run(go) == BASE_TOOLS
