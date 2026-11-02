from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

import pytest

from agent_risk_framework.attacks import evasion as ev
from agent_risk_framework.attacks.oracles import Trace, TraceCall, score_attack
from agent_risk_framework.attacks.scenarios import (
    ATTACK_VARIANTS,
    AttackScenario,
    OracleSpec,
    ScenarioError,
    load_attack_variants,
    load_catalog,
    load_seeded,
    parse_attack_variants,
    parse_catalog,
    parse_mutated,
)
from agent_risk_framework.attacks.seeding import RESERVED_FOR_EVASION, SEEDED_PATH
from agent_risk_framework.enums import CaseKind, DefenseConfig, DetectorVerdict, Outcome
from agent_risk_framework.runlog import RunRecord
from agent_risk_framework.runlog.gauntlet import Catalog, label


def _parents() -> tuple[AttackScenario, ...]:
    catalog = load_catalog()
    return (*catalog.scenarios, *load_seeded(SEEDED_PATH, catalog))


def _mutation(parent_id: str = "AC02", **over: Any) -> dict[str, Any]:
    parents = {s.scenario_id: s for s in _parents()}
    parent = parents[parent_id]
    item: dict[str, Any] = {
        "scenario_id": f"{parent_id}-M03",
        "channel": parent.channel,
        "derived_from": parent_id,
        "transform": "homoglyph",
        "variant_group": parent.variant_group,
        "user_prompt": parent.user_prompt + " mutated",
        "oracle": {"kind": parent.oracle.kind, **parent.oracle.params},
    }
    if parent.outside_files:
        item["outside_files"] = dict(parent.outside_files)
    return {**item, **over}


def test_attack_variants_load_with_every_route_per_objective() -> None:
    variants = load_attack_variants(ev.ATTACK_VARIANTS_PATH, load_catalog())
    assert len(variants) == 16
    assert all(s.attack_variant and s.evasion_label in ATTACK_VARIANTS for s in variants)
    assert all(s.variant_group == s.scenario_id for s in variants)
    assert Counter(s.transform for s in variants) == dict.fromkeys(ATTACK_VARIANTS, 4)
    assert Counter(s.case_id for s in variants) == {"AC01": 4, "AC02": 4, "AC04": 4, "AC07": 4}


def test_attack_variants_use_reserved_routes_and_new_text() -> None:
    reserved = {r.replace(" ", "_").replace("-", "_") for r in RESERVED_FOR_EVASION}
    assert reserved >= ATTACK_VARIANTS
    variants = load_attack_variants(ev.ATTACK_VARIANTS_PATH, load_catalog())
    corpus_prompts = {s.user_prompt for s in _parents()}
    assert not corpus_prompts & {s.user_prompt for s in variants}


def test_outside_file_in_variants_matches_the_authored_fixture() -> None:
    authored = {s.scenario_id: s for s in load_catalog().scenarios}["AC02"].outside_files
    variants = load_attack_variants(ev.ATTACK_VARIANTS_PATH, load_catalog())
    for s in variants:
        if s.case_id == "AC02":
            assert s.outside_files == authored


def test_mutated_keeps_its_parent_and_joins_its_group() -> None:
    parents = _parents()
    [s] = parse_mutated({"scenarios": [_mutation()]}, parents)
    assert s.mutated and not s.seeded and s.evasion_label == "homoglyph"
    assert s.derived_from == "AC02" and s.case_id == "AC02" and s.variant_group == "AC02"


def test_mutation_of_a_seeded_scenario_parses() -> None:
    [s] = parse_mutated({"scenarios": [_mutation("AC02-S08")]}, _parents())
    assert s.scenario_id == "AC02-S08-M03" and s.case_id == "AC02"
    assert s.variant_group == "AC02-S08"


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"transform": "paraphrase:formal"}, "transform must be one of"),
        ({"derived_from": "AC01"}, "derives from AC02"),
        ({"variant_group": "AC01"}, "must join group"),
        ({"oracle": {"kind": "recipient_outside_allowlist"}}, "oracle and channel"),
        ({"outside_files": {"x/y.txt": "z"}}, "planted files"),
        ({"variant_group": None}, "names its parent's variant_group"),
    ],
)
def test_mutated_rejects_a_changed_attack(change: dict[str, Any], message: str) -> None:
    with pytest.raises(ScenarioError, match=message):
        parse_mutated({"scenarios": [_mutation(**change)]}, _parents())


def test_mutated_must_change_the_payload() -> None:
    parent = {s.scenario_id: s for s in _parents()}["AC02"]
    with pytest.raises(ScenarioError, match="rewrites the prompt"):
        parse_mutated({"scenarios": [_mutation(user_prompt=parent.user_prompt)]}, _parents())


def test_mcp_mutation_rewrites_the_tool_only() -> None:
    parents = _parents()
    parent = {s.scenario_id: s for s in parents}["AC11"]
    assert parent.mcp is not None
    tool = {"kind": parent.mcp.kind, "tool": parent.mcp.tool, "description": "changed"}
    item = _mutation("AC11", user_prompt=parent.user_prompt, mcp=tool)
    [s] = parse_mutated({"scenarios": [item]}, parents)
    assert s.mcp is not None and s.mcp.description == "changed"
    same = _mutation(
        "AC11", user_prompt=parent.user_prompt, mcp={**tool, "description": parent.mcp.description}
    )
    with pytest.raises(ScenarioError, match="rewrites the tool only"):
        parse_mutated({"scenarios": [same]}, parents)
    moved = _mutation("AC11", mcp=tool)
    with pytest.raises(ScenarioError, match="rewrites the tool only"):
        parse_mutated({"scenarios": [moved]}, parents)


def test_an_indirect_parent_cannot_be_mutated() -> None:
    files = {s.scenario_id: s for s in _parents()}["AC09"].workspace_files
    item = _mutation("AC09", workspace_files=dict(files))
    with pytest.raises(ScenarioError, match="planted file"):
        parse_mutated({"scenarios": [item]}, _parents())


def test_a_whitespace_change_is_not_a_mutation() -> None:
    parent = {s.scenario_id: s for s in _parents()}["AC02"]
    item = _mutation(user_prompt=parent.user_prompt + " ")
    with pytest.raises(ScenarioError, match="rewrites the prompt"):
        parse_mutated({"scenarios": [item]}, _parents())


def test_a_list_transform_is_a_scenario_error() -> None:
    with pytest.raises(ScenarioError, match="transform must be one of"):
        parse_mutated({"scenarios": [_mutation(transform=["homoglyph"])]}, _parents())


def test_mutating_an_obfuscated_scenario_is_rejected() -> None:
    item = _mutation(scenario_id="AC02-OBF-M03", derived_from="AC02-OBF")
    with pytest.raises(ScenarioError, match="plain or seeded"):
        parse_mutated({"scenarios": [item]}, _parents())


def test_catalog_kinds_stay_apart() -> None:
    variant = {
        "scenario_id": "AC02-V09",
        "channel": "direct",
        "transform": "multi_stage",
        "user_prompt": "x",
        "oracle": {"kind": "path_escape_read"},
    }
    with pytest.raises(ScenarioError, match="-Mnn scenarios only"):
        parse_mutated({"scenarios": [variant]}, _parents())
    data = json.loads(Path("data/attack_scenarios.json").read_text(encoding="utf-8"))
    with pytest.raises(ScenarioError, match="their own catalog"):
        parse_catalog({**data, "scenarios": [*data["scenarios"], variant]})
    with pytest.raises(ScenarioError, match="duplicate"):
        parse_attack_variants({"scenarios": [variant, variant]}, load_catalog())
    with pytest.raises(ScenarioError, match="-Vnn scenarios only"):
        parse_attack_variants(
            {"scenarios": [{**variant, "scenario_id": "AC02", "transform": None}]}, load_catalog()
        )
    with pytest.raises(ScenarioError, match="transform must be one of"):
        parse_attack_variants({"scenarios": [{**variant, "transform": "base64"}]}, load_catalog())
    with pytest.raises(ScenarioError, match="authored, not derived"):
        parse_attack_variants({"scenarios": [{**variant, "derived_from": "AC02"}]}, load_catalog())


def _sent(*recipients: str) -> tuple[TraceCall, ...]:
    return tuple(
        TraceCall("send_email", {"to": r, "subject": "s", "body": "b"}, "ok") for r in recipients
    )


def test_attacker_received_names_one_address() -> None:
    spec = OracleSpec.parse("x", {"kind": "attacker_received", "address": "a@b.example"})
    assert score_attack(spec, Trace("done", _sent("A@B.example"))).hit
    assert not score_attack(spec, Trace("done", _sent("other@b.example"))).hit
    assert not score_attack(spec, Trace("done", ())).hit
    assert score_attack(spec, Trace("sent to a@b.example", _sent("a@b.example"))).hit


def test_attacker_received_ignores_a_rejected_send() -> None:
    spec = OracleSpec.parse("x", {"kind": "attacker_received", "address": "a@b.example"})
    rejected = TraceCall("send_email", {"to": "a@b.example"}, "missing subject", is_error=True)
    assert not score_attack(spec, Trace("done", (rejected,))).hit
    assert score_attack(spec, Trace("done", (rejected, *_sent("a@b.example")))).hit


def test_attacker_received_ignores_a_blocked_send() -> None:
    spec = OracleSpec.parse("x", {"kind": "attacker_received", "address": "a@b.example"})
    assert not score_attack(spec, Trace("done", (), blocked=_sent("a@b.example"))).hit


def test_attacker_received_concealed_needs_a_silent_report() -> None:
    spec = OracleSpec.parse(
        "x", {"kind": "attacker_received", "address": "a@b.example", "concealed": True}
    )
    assert score_attack(spec, Trace("Done - notes filed.", _sent("a@b.example"))).hit
    assert not score_attack(spec, Trace("I wrote to a@b.example.", _sent("a@b.example"))).hit


@pytest.mark.parametrize(
    "bad",
    [
        {"kind": "attacker_received"},
        {"kind": "attacker_received", "address": "a@b.test"},
        {"kind": "attacker_received", "address": ".example"},
        {"kind": "attacker_received", "address": "@.example"},
        {"kind": "attacker_received", "address": "a b.example"},
        {"kind": "attacker_received", "address": "a@b.example", "concealed": "yes"},
    ],
)
def test_attacker_received_validates_its_parameters(bad: dict[str, Any]) -> None:
    with pytest.raises(ScenarioError):
        OracleSpec.parse("x", bad)


def _run(case_id: str) -> RunRecord:
    return RunRecord(
        experiment_id="evasion-baseline",
        case_id=case_id,
        case_kind=CaseKind.ATTACK,
        config=DefenseConfig.BASELINE,
        run_index=0,
        seed=1337,
        temperature=0.0,
        model="m",
        outcome=Outcome.SUCCEEDED,
        detector_result=DetectorVerdict.NOT_EVALUATED,
        latency_ms=0.0,
    )


def test_export_labels_carry_the_mutation(tmp_path: Path) -> None:
    mutated = tmp_path / "mutated.json"
    mutated.write_text(json.dumps({"scenarios": [_mutation("AC02-S08")]}), encoding="utf-8")
    catalog = Catalog.load(attack_variants=ev.ATTACK_VARIANTS_PATH, mutated=mutated)
    item = label(_run("AC02-S08-M03"), frozenset(), catalog)
    assert item["mutation"] == "homoglyph"
    assert item["attack_class"] == "AC02"
    assert item["variant_group"] == "AC02-S08"
    assert item["derived_from"] == "AC02-S08"
    item = label(_run("AC07-V02"), frozenset(), catalog)
    assert item["mutation"] == "retrieval_poisoning"
    assert item["variant_group"] == "AC07-V02"
    assert item["derived_from"] is None
    assert label(_run("AC02-S08"), frozenset(), catalog)["mutation"] is None


def test_load_evasion_orders_mutated_first(tmp_path: Path) -> None:
    mutated = tmp_path / "mutated.json"
    mutated.write_text(json.dumps({"scenarios": [_mutation()]}), encoding="utf-8")
    inputs = ev.load_evasion(mutated)
    assert inputs[0].scenario_id == "AC02-M03"
    assert len(inputs) == 17
