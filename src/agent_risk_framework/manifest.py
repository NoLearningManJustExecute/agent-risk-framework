"""Experiment manifests: which defense config, which attack set, how many runs.

A manifest is YAML (.yaml/.yml) or JSON (.json). Unknown keys are rejected so a
typo like `temprature` fails loudly instead of silently running with defaults.

Example (YAML):

    experiment_id: baseline-smoke
    config: baseline
    attack_set: smoke
    runs: 10
    seed: 1337
    temperature: 0.0

`controls` (optional, Phase 3) overrides the guardrails the `config` preset turns
on, so a single control can be isolated: `controls: [tool_integrity]`. Omit it to
use the preset. The run log records the exact set per run (`run_controls`).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from .enums import Control, DefenseConfig
from .providers.ollama import DEFAULT_CHAT_MODEL

EXPERIMENT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
PROVIDERS = frozenset({"ollama", "fake"})
MAX_TEMPERATURE = 2.0
MAX_RUNS = 10_000
MAX_SEED = 2**31 - 1


class ManifestError(ValueError):
    pass


@dataclass(frozen=True)
class ExperimentManifest:
    experiment_id: str
    config: DefenseConfig
    attack_set: str
    runs: int = 10
    seed: int = 1337
    temperature: float = 0.0
    provider: str = "ollama"
    model: str = DEFAULT_CHAT_MODEL
    benign_set: str = "data/benign_tasks.json"
    description: str = ""
    controls: list[str] | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.experiment_id, str) or not EXPERIMENT_ID_RE.fullmatch(
            self.experiment_id
        ):
            raise ManifestError(f"invalid experiment_id {self.experiment_id!r}")
        try:
            object.__setattr__(self, "config", DefenseConfig(self.config))
        except ValueError as exc:
            allowed = [c.value for c in DefenseConfig]
            raise ManifestError(
                f"invalid config {self.config!r}; expected one of {allowed}"
            ) from exc
        if not isinstance(self.attack_set, str) or not self.attack_set.strip():
            raise ManifestError("attack_set must be a non-empty string")
        # bool is an int subclass; reject it explicitly so `runs: true` is an error.
        if isinstance(self.runs, bool) or not isinstance(self.runs, int) or self.runs < 1:
            raise ManifestError("runs must be an integer >= 1")
        if self.runs > MAX_RUNS:
            raise ManifestError(f"runs must be <= {MAX_RUNS}")
        if isinstance(self.seed, bool) or not isinstance(self.seed, int) or self.seed < 0:
            raise ManifestError("seed must be an integer >= 0")
        # Every per-run seed (seed + run_index) must fit a signed 32-bit model seed.
        if self.seed + self.runs - 1 > MAX_SEED:
            raise ManifestError(f"seed + runs - 1 must be <= {MAX_SEED}")
        if isinstance(self.temperature, bool) or not isinstance(self.temperature, int | float):
            raise ManifestError("temperature must be a number")
        if not 0 <= self.temperature <= MAX_TEMPERATURE:
            raise ManifestError(f"temperature must be within [0, {MAX_TEMPERATURE}]")
        object.__setattr__(self, "temperature", float(self.temperature))
        if self.provider not in PROVIDERS:
            raise ManifestError(f"provider must be one of {sorted(PROVIDERS)}")
        if not isinstance(self.model, str) or not self.model.strip():
            raise ManifestError("model must be a non-empty string")
        # Required: without the benign set there is no false positive rate.
        if not isinstance(self.benign_set, str) or not self.benign_set.strip():
            raise ManifestError("benign_set must be a non-empty path string")
        if not isinstance(self.description, str):
            raise ManifestError("description must be a string")
        if self.controls is not None:
            allowed = {c.value for c in Control}
            if (
                not isinstance(self.controls, list)
                or not all(isinstance(c, str) for c in self.controls)
                or set(self.controls) - allowed
                or len(set(self.controls)) != len(self.controls)
            ):
                raise ManifestError(
                    f"controls must be a list of distinct names from {sorted(allowed)}"
                )

    def run_seeds(self) -> list[int]:
        """Seed for each run index: base seed + index, so every run is reproducible."""
        return [self.seed + i for i in range(self.runs)]

    def to_dict(self) -> dict[str, Any]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__} | {
            "config": self.config.value
        }

    @classmethod
    def from_dict(cls, data: Any) -> ExperimentManifest:
        if not isinstance(data, dict):
            raise ManifestError("manifest must be a mapping")
        unknown = set(data) - set(cls.__dataclass_fields__)
        if unknown:
            raise ManifestError(f"unknown manifest keys: {sorted(unknown)}")
        try:
            return cls(**data)
        except TypeError as exc:  # missing required keys
            raise ManifestError(str(exc)) from exc


class _StrictSafeLoader(yaml.SafeLoader):
    """SafeLoader that rejects duplicate keys instead of keeping the last one."""


def _construct_mapping(loader: _StrictSafeLoader, node: yaml.MappingNode) -> dict[Any, Any]:
    seen: set[Any] = set()
    for key_node, _ in node.value:
        key = loader.construct_object(key_node)
        if key in seen:
            raise yaml.constructor.ConstructorError(
                None, None, f"duplicate key {key!r}", key_node.start_mark
            )
        seen.add(key)
    return loader.construct_mapping(node, deep=True)


_StrictSafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_mapping,  # type: ignore[arg-type]
)


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    keys = [k for k, _ in pairs]
    duplicates = sorted({k for k in keys if keys.count(k) > 1})
    if duplicates:
        raise ManifestError(f"duplicate keys: {duplicates}")
    return dict(pairs)


def load_manifest(path: Path | str) -> ExperimentManifest:
    p = Path(path)
    try:
        # utf-8-sig tolerates the BOM some Windows editors add.
        text = p.read_text(encoding="utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ManifestError(f"{p} is not UTF-8 text: {exc}") from exc
    suffix = p.suffix.lower()
    try:
        if suffix in {".yaml", ".yml"}:
            data = yaml.load(text, Loader=_StrictSafeLoader)  # noqa: S506 - SafeLoader subclass
        elif suffix == ".json":
            data = json.loads(text, object_pairs_hook=_reject_duplicate_json_keys)
        else:
            raise ManifestError(f"unsupported manifest extension {suffix!r}")
    except (yaml.YAMLError, json.JSONDecodeError) as exc:
        raise ManifestError(f"could not parse {p}: {exc}") from exc
    return ExperimentManifest.from_dict(data)
