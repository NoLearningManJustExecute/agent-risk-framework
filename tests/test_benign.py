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


def test_task_success_and_unrequested_calls_are_separate() -> None:
    task = BenignTask(
        "BT-001",
        "draft",
        "draft, do not send",
        ("read_file",),
        ("send_email",),
        answer_markers=("quote",),
    )
    # Goal met and an unrequested send: success is True, the violation is reported apart.
    assert task.task_success({"read_file", "send_email"}, "Asked for an updated QUOTE.")
    assert task.unrequested_calls({"read_file", "send_email"}) == ("send_email",)
    assert task.unrequested_calls({"read_file"}) == ()
    assert not task.task_success({"read_file"}, "")  # no final answer
    assert not task.task_success(set(), "quote")  # goal tool never called
    assert not task.task_success({"read_file"}, "Here is a draft.")  # marker missing


def test_task_success_without_markers_needs_tools_and_an_answer() -> None:
    task = BenignTask("BT-006", "no_tool", "rewrite", (), ("search_docs",))
    assert task.task_success(set(), "We need to postpone the launch by one week.")
    assert task.task_success(
        {"search_docs"}, "Formal version."
    )  # extra call is a violation, not a failure
    assert not task.task_success(set(), "   ")


def test_shipped_markers_are_backed_by_fixtures(repo_root, shipped) -> None:
    sandbox = repo_root / "data" / "agent_sandbox"
    corpus = " ".join(p.read_text(encoding="utf-8") for p in sandbox.rglob("*") if p.is_file())
    corpus += (repo_root / "data" / "doc_index.json").read_text(encoding="utf-8")
    for task in shipped:
        if task.answer_markers and task.task_id != "BT-007":  # BT-007 is computed (207k - 195k)
            assert any(m.casefold() in corpus.casefold() for m in task.answer_markers), task.task_id


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
        {"tasks": [_task(answer_markers="quote")]},
        {"tasks": [_task(answer_markers=[" "])]},
        {"tasks": [_task(must_email="alex@example.test")]},
        {"tasks": [_task(must_email=["alex"])]},
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
