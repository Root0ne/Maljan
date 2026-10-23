"""The process tree nests by the parent that was running, and no loop hides a process (RC-16)."""

from __future__ import annotations

import logging
from typing import Any

from maljan.reporting.ledger_projection import _as_tree
from maljan.reporting.models import ProcessNode


def _flat(root: ProcessNode) -> list[int]:
    return [root.pid, *(p for child in root.children for p in _flat(child))]


def test_a_reused_pid_parents_the_children_listed_after_it() -> None:
    first = ProcessNode(pid=10, ppid=1, name="first")
    early_child = ProcessNode(pid=11, ppid=10, name="early")
    second = ProcessNode(pid=10, ppid=1, name="second")
    late_child = ProcessNode(pid=12, ppid=10, name="late")
    roots = _as_tree([first, early_child, second, late_child])
    assert [r.name for r in roots] == ["first", "second"]
    assert [c.name for c in first.children] == ["early"]
    assert [c.name for c in second.children] == ["late"]


def test_a_loop_of_parents_loses_nobody_and_is_logged(caplog: Any) -> None:
    a = ProcessNode(pid=1, ppid=2, name="a")
    b = ProcessNode(pid=2, ppid=1, name="b")
    with caplog.at_level(logging.WARNING):
        roots = _as_tree([a, b])
    assert sorted(p for r in roots for p in _flat(r)) == [1, 2]
    assert "parent loop" in caplog.text


def test_a_plain_tree_is_nested_as_before() -> None:
    root = ProcessNode(pid=1, ppid=0, name="root")
    child = ProcessNode(pid=2, ppid=1, name="child")
    orphan = ProcessNode(pid=3, ppid=99, name="orphan")
    assert _as_tree([root, child, orphan]) == [root, orphan]
    assert root.children == [child]


def test_rows_with_no_pid_stay_flat_and_serialise() -> None:
    rows = [ProcessNode(pid=0, ppid=0, name=f"row{i}") for i in range(300)]
    roots = _as_tree(rows)
    assert roots == rows
    assert all(not r.children for r in roots)
    for r in roots[:3]:
        r.model_dump_json()


def test_a_row_that_is_its_own_parent_is_a_root() -> None:
    selfish = ProcessNode(pid=5, ppid=5, name="selfish")
    assert _as_tree([selfish]) == [selfish]
    assert not selfish.children


def test_a_long_chain_is_linear_enough() -> None:
    nodes = [ProcessNode(pid=i + 1, ppid=i, name=f"p{i}") for i in range(5000)]
    roots = _as_tree(nodes)
    assert len(roots) == 1
