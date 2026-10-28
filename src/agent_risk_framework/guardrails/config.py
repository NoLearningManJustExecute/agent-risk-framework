"""Which guardrails are on: six independent switches plus the Phase 4 presets.

Every control can be switched on alone, so Phase 4 can measure each one in
isolation as well as in the named ablation configs:

| Preset (`DefenseConfig`) | Controls |
| --- | --- |
| `baseline`           | none (the Phase 1/2 undefended agent) |
| `deterministic-only` | tool_permissions, tool_integrity, approval_gate |
| `classifier-only`    | input_classifier |
| `output-filter-only` | output_classifier, egress_filter |
| `combined`           | all six |
| `single-control`     | a label, not a preset: exactly one control, named in `run_controls` |

The classifiers are rule-based and deterministic too; "deterministic-only" means
the architectural controls (what a tool may do, which tools exist, who approves a
side effect), as opposed to the content-inspection controls (what the text says).
"Output filter" means both scans on the tool boundary: injected instructions coming
back (`output_classifier`) and secrets going out (`egress_filter`).
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from ..enums import Control, DefenseConfig

PRESETS: dict[DefenseConfig, frozenset[Control]] = {
    DefenseConfig.BASELINE: frozenset(),
    DefenseConfig.DETERMINISTIC_ONLY: frozenset(
        {Control.TOOL_PERMISSIONS, Control.TOOL_INTEGRITY, Control.APPROVAL_GATE}
    ),
    DefenseConfig.CLASSIFIER_ONLY: frozenset({Control.INPUT_CLASSIFIER}),
    DefenseConfig.OUTPUT_FILTER_ONLY: frozenset({Control.OUTPUT_CLASSIFIER, Control.EGRESS_FILTER}),
    DefenseConfig.COMBINED: frozenset(Control),
}


@dataclass(frozen=True)
class GuardrailConfig:
    """The set of enabled controls. Immutable; build with `of`, `preset` or `none`."""

    controls: frozenset[Control] = frozenset()

    def __post_init__(self) -> None:
        if isinstance(self.controls, str):
            raise TypeError("controls must be a collection of control names, not a string")
        try:
            object.__setattr__(self, "controls", frozenset(Control(c) for c in self.controls))
        except ValueError as exc:
            allowed = [c.value for c in Control]
            raise ValueError(f"unknown control; expected some of {allowed}") from exc

    @classmethod
    def none(cls) -> GuardrailConfig:
        return cls()

    @classmethod
    def of(cls, *controls: Control | str) -> GuardrailConfig:
        return cls(frozenset(controls))

    @classmethod
    def parse(cls, names: Iterable[str]) -> GuardrailConfig:
        return cls(frozenset(n.strip() for n in names if n.strip()))

    @classmethod
    def preset(cls, config: DefenseConfig | str) -> GuardrailConfig:
        config = DefenseConfig(config)
        if config not in PRESETS:
            raise ValueError(f"{config.value!r} is a label, not a preset; name the controls")
        return cls(PRESETS[config])

    @classmethod
    def preset_or_none(cls, config: DefenseConfig | str) -> GuardrailConfig:
        """The preset's controls, or no controls for a label that is not a preset."""
        return cls(PRESETS.get(DefenseConfig(config), frozenset()))

    def label(self) -> DefenseConfig:
        """The preset this control set is exactly, else `single-control` for one control."""
        for config, controls in PRESETS.items():
            if controls == self.controls:
                return config
        if len(self.controls) == 1:
            return DefenseConfig.SINGLE_CONTROL
        raise ValueError(f"no label for the control set {self.names()}")

    def enabled(self, control: Control) -> bool:
        return control in self.controls

    @property
    def any(self) -> bool:
        return bool(self.controls)

    def names(self) -> list[str]:
        return sorted(c.value for c in self.controls)
