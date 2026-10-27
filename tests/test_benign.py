from __future__ import annotations

import json

import pytest

from agent_risk_framework.benign import (
    BenignTask,
    BenignTaskError,
    load_benign_tasks,
    parse_benign_tasks,
)


@pytest.fixture
def shipped(repo_root) -> list[BenignTask]:
    return load_benign_tasks(repo_root / "data/benign_tasks.json")


def test_shipped_benign_set_loads(shipped) -> None:
    assert len(shipped) >= 10
    assert len({t.task_id for t in shipped}) == len(shipped)
    assert sum(t.hard_negative for t in shipped) >= 2, "need attack-looking legit tasks for FPR"
    assert any(not t.must_call for t in shipped), "need at least one no-tool task"
    assert all(t.must_call or t.must_not_call for t in shipped), "every task needs a criterion"


def test_shipped_benign_set_uses_only_synthetic_addresses(shipped) -> None:
    for task in shipped:
        for word in task.prompt.split():
            if "@" in word:
                assert word.rstrip(".,").endswith(".test"), word


def test_completion_criteria() -> None:
    task = BenignTask("BT-001", "draft", "draft, do not send", ("read_file",), ("send_email",))
    assert task.completed({"read_file"})
    assert task.completed({"read_file", "search_docs"})
    assert not task.completed(set())
    assert not task.completed({"read_file", "send_email"})


def _task(**overrides) -> dict:
    return {"task_id": "BT-001", "category": "x", "prompt": "do a thing", **overrides}


@pytest.mark.parametrize(
    "data",
    [
        [],
        {"tasks": "nope"},
        {"tasks": ["BT-001"]},
        {"tasks": [_task(task_id="T1")]},
        {"tasks": [_task(task_id="BT-\u0661\u0662\u0663")]},  # non-ASCII digits
        {"tasks": [_task(prompt="")]},
        {"tasks": [_task(), _task()]},
        {"tasks": [_task(surprise=True)]},
        {"tasks": [_task(must_call="read_file")]},  # string, not list
        {"tasks": [_task(must_call=["Read File"])]},
        {"tasks": [_task(must_call=["x"], must_not_call=["x"])]},
        {"tasks": [_task(hard_negative="false")]},
        {"tasks": [_task(notes=5)]},
    ],
)
def test_invalid_benign_sets_rejected(data) -> None:
    with pytest.raises(BenignTaskError):
        parse_benign_tasks(data)


def test_bom_tolerated_and_bad_json_wrapped(tmp_path) -> None:
    good = tmp_path / "bom.json"
    good.write_text(json.dumps({"tasks": [_task()]}), encoding="utf-8-sig")
    assert load_benign_tasks(good)[0].task_id == "BT-001"
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    with pytest.raises(BenignTaskError):
        load_benign_tasks(bad)
