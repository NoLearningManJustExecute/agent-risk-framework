"""Benign task set: legitimate requests used to measure false positives.

Without these, a guardrail that blocks everything would look perfect. Every
defense config runs the benign set alongside the attack set, so the false
positive rate and benign task completion rate come from the same experiment.

Each task carries deterministic success criteria (`must_call`, `must_not_call`)
so benign task completion can be scored from the tool-call log, the same way
attack outcomes are, without an LLM judge.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

TASK_ID_RE = re.compile(r"^BT-[0-9]{3}$")
TOOL_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
DEFAULT_BENIGN_PATH = Path("data/benign_tasks.json")


class BenignTaskError(ValueError):
    pass


def _tool_names(task_id: str, name: str, value: Any) -> tuple[str, ...]:
    if not isinstance(value, list | tuple) or not all(
        isinstance(v, str) and TOOL_NAME_RE.fullmatch(v) for v in value
    ):
        raise BenignTaskError(f"{task_id}: {name} must be a list of tool names")
    return tuple(value)


@dataclass(frozen=True)
class BenignTask:
    task_id: str
    category: str
    prompt: str
    must_call: tuple[str, ...] = ()  # tools the task cannot be completed without
    must_not_call: tuple[str, ...] = ()  # tools whose use means the task went wrong
    hard_negative: bool = False  # legit, but phrased like an attack (FPR stress test)
    notes: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.task_id, str) or not TASK_ID_RE.fullmatch(self.task_id):
            raise BenignTaskError(f"invalid task_id {self.task_id!r}")
        for name in ("category", "prompt"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise BenignTaskError(f"{self.task_id}: {name} must be a non-empty string")
        for name in ("must_call", "must_not_call"):
            object.__setattr__(self, name, _tool_names(self.task_id, name, getattr(self, name)))
        overlap = set(self.must_call) & set(self.must_not_call)
        if overlap:
            raise BenignTaskError(f"{self.task_id}: {sorted(overlap)} in both must lists")
        if not isinstance(self.hard_negative, bool):
            raise BenignTaskError(f"{self.task_id}: hard_negative must be true or false")
        if not isinstance(self.notes, str):
            raise BenignTaskError(f"{self.task_id}: notes must be a string")

    def completed(self, called_tools: set[str] | frozenset[str]) -> bool:
        """Deterministic success check against the set of tools a run called."""
        return set(self.must_call) <= called_tools and not set(self.must_not_call) & called_tools


def parse_benign_tasks(data: Any) -> list[BenignTask]:
    if not isinstance(data, dict) or not isinstance(data.get("tasks"), list):
        raise BenignTaskError("benign task file must be an object with a 'tasks' list")
    if not all(isinstance(item, dict) for item in data["tasks"]):
        raise BenignTaskError("every task entry must be an object")
    try:
        tasks = [BenignTask(**item) for item in data["tasks"]]
    except TypeError as exc:
        raise BenignTaskError(f"malformed task entry: {exc}") from exc
    ids = [t.task_id for t in tasks]
    duplicates = sorted({i for i in ids if ids.count(i) > 1})
    if duplicates:
        raise BenignTaskError(f"duplicate task_id(s): {duplicates}")
    return tasks


def load_benign_tasks(path: Path | str = DEFAULT_BENIGN_PATH) -> list[BenignTask]:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BenignTaskError(f"could not parse {path}: {exc}") from exc
    return parse_benign_tasks(data)
