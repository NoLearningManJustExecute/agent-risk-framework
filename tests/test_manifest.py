from __future__ import annotations

import json

import pytest

from agent_risk_framework.enums import DefenseConfig
from agent_risk_framework.manifest import (
    ExperimentManifest,
    ManifestError,
    load_manifest,
)

MINIMAL = {"experiment_id": "exp-1", "config": "baseline", "attack_set": "smoke"}


def test_shipped_example_manifests_load(repo_root) -> None:
    yaml_m = load_manifest(repo_root / "configs/experiments/baseline_smoke.yaml")
    json_m = load_manifest(repo_root / "configs/experiments/combined_smoke.json")
    assert yaml_m.config is DefenseConfig.BASELINE
    assert json_m.config is DefenseConfig.COMBINED
    assert yaml_m.runs >= 10  # N >= 10 runs per case, per the measurement objectives


def test_defaults() -> None:
    m = ExperimentManifest.from_dict(MINIMAL)
    assert (m.runs, m.seed, m.temperature) == (10, 1337, 0.0)
    assert m.model == "llama3.1:8b"
    assert m.run_seeds()[:3] == [1337, 1338, 1339]


@pytest.mark.parametrize("config", [c.value for c in DefenseConfig])
def test_all_five_configs_accepted(config: str) -> None:
    assert ExperimentManifest.from_dict({**MINIMAL, "config": config}).config == config


@pytest.mark.parametrize(
    "overrides",
    [
        {"config": "deterministic"},
        {"experiment_id": "Has Spaces"},
        {"experiment_id": "../escape"},
        {"attack_set": ""},
        {"runs": 0},
        {"runs": True},
        {"runs": 2.5},
        {"seed": -1},
        {"temperature": 3.0},
        {"temperature": "hot"},
        {"provider": "openai"},
        {"temprature": 0.5},  # typo must fail loudly
        {"runs": 10**9},
        {"seed": 2**31},  # beyond a 32-bit model seed
        {"seed": 2**31 - 5, "runs": 10},  # last per-run seed overflows
        {"benign_set": None},  # dropping the benign set would hide FPR
        {"benign_set": ""},
        {"description": [1, 2]},
    ],
)
def test_invalid_manifests_rejected(overrides: dict) -> None:
    with pytest.raises(ManifestError):
        ExperimentManifest.from_dict({**MINIMAL, **overrides})


def test_missing_required_key() -> None:
    with pytest.raises(ManifestError):
        ExperimentManifest.from_dict({"experiment_id": "x", "config": "baseline"})


def test_yaml_and_json_equivalent(tmp_path) -> None:
    (tmp_path / "m.json").write_text(json.dumps(MINIMAL), encoding="utf-8")
    (tmp_path / "m.yml").write_text(
        "experiment_id: exp-1\nconfig: baseline\nattack_set: smoke\n", encoding="utf-8"
    )
    assert load_manifest(tmp_path / "m.json") == load_manifest(tmp_path / "m.yml")


def test_yaml_loader_is_safe(tmp_path) -> None:
    p = tmp_path / "evil.yaml"
    p.write_text("!!python/object/apply:os.system ['echo pwned']\n", encoding="utf-8")
    with pytest.raises(ManifestError):
        load_manifest(p)


def test_duplicate_keys_rejected(tmp_path) -> None:
    (tmp_path / "dup.yaml").write_text(
        "experiment_id: e\nconfig: baseline\nattack_set: s\nruns: 10\nruns: 1000\n",
        encoding="utf-8",
    )
    (tmp_path / "dup.json").write_text(
        '{"experiment_id": "e", "config": "baseline", "attack_set": "s", "runs": 1, "runs": 9}',
        encoding="utf-8",
    )
    for name in ("dup.yaml", "dup.json"):
        with pytest.raises(ManifestError, match="duplicate"):
            load_manifest(tmp_path / name)


def test_windows_encodings(tmp_path) -> None:
    bom = tmp_path / "bom.json"
    bom.write_text(json.dumps(MINIMAL), encoding="utf-8-sig")
    assert load_manifest(bom).experiment_id == "exp-1"
    utf16 = tmp_path / "utf16.yaml"
    utf16.write_text("experiment_id: exp-1\n", encoding="utf-16")
    with pytest.raises(ManifestError, match="UTF-8"):
        load_manifest(utf16)


def test_unsupported_extension_and_non_mapping(tmp_path) -> None:
    (tmp_path / "m.toml").write_text("x = 1", encoding="utf-8")
    with pytest.raises(ManifestError):
        load_manifest(tmp_path / "m.toml")
    (tmp_path / "list.json").write_text("[1, 2]", encoding="utf-8")
    with pytest.raises(ManifestError):
        load_manifest(tmp_path / "list.json")


def test_to_dict_roundtrip() -> None:
    m = ExperimentManifest.from_dict({**MINIMAL, "config": "classifier-only"})
    assert ExperimentManifest.from_dict(m.to_dict()) == m
    assert m.to_dict()["config"] == "classifier-only"
