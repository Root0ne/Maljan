"""One sandbox process is one STIX process object, however many places the tree holds it.

Two readings of a parent that differ (one with its command line, one without)
are two processes, and each can hold the same child. The child is one process
(the same pid, parent, image and command line): the export writes it once,
with the children of every place it stands, and each parent names it.
"""

from __future__ import annotations

from maljan.reporting.dedupe import distinct_processes
from maljan.reporting.models import ProcessNode
from maljan.reporting.renderers.stix_renderer import _processes_to_observables


def _child() -> ProcessNode:
    return ProcessNode(pid=20, ppid=10, name="cmd.exe", command_line="cmd /c whoami")


def test_a_child_under_two_readings_of_its_parent_is_one_object() -> None:
    grandchild = ProcessNode(pid=30, ppid=20, name="whoami.exe", command_line="whoami")
    first = ProcessNode(
        pid=10, ppid=1, name="s.exe", command_line="s.exe /run", children=[_child()]
    )
    second = ProcessNode(
        pid=10,
        ppid=1,
        name="s.exe",
        command_line="",
        children=[_child().model_copy(update={"children": [grandchild]})],
    )

    objects = _processes_to_observables(distinct_processes([first, second]))

    processes = [o for o in objects if o.type == "process"]
    assert sorted(o.pid for o in processes) == [10, 10, 20, 30]
    (child,) = [o for o in processes if o.pid == 20]
    (leaf,) = [o for o in processes if o.pid == 30]
    assert child.child_refs == [leaf.id]
    parents = [o for o in processes if o.pid == 10]
    assert all(o.child_refs == [child.id] for o in parents)
    # Every reference names an object the export holds, and one image is one file.
    ids = {o.id for o in objects}
    assert all(ref in ids for o in processes for ref in o.child_refs)
    assert sorted(o.name for o in objects if o.type == "file") == [
        "cmd.exe",
        "s.exe",
        "whoami.exe",
    ]


def test_a_plain_tree_is_written_as_before() -> None:
    child = _child()
    root = ProcessNode(pid=10, ppid=1, name="s.exe", command_line="s.exe /run", children=[child])

    objects = _processes_to_observables(distinct_processes([root]))

    assert [o.type for o in objects] == ["file", "process", "file", "process"]
    child_obj, root_obj = objects[1], objects[3]
    assert (child_obj.pid, root_obj.pid) == (20, 10)
    assert root_obj.child_refs == [child_obj.id]
    assert child_obj.image_ref == objects[0].id and root_obj.image_ref == objects[2].id


def test_a_process_repeated_below_itself_leaves_the_references_a_tree() -> None:
    # A -> B -> A' (A read again) holding C: A' is A, so A holds C, and B does
    # not name its own ancestor.
    leaf = ProcessNode(pid=3, ppid=1, name="c.exe", command_line="c")
    again = ProcessNode(pid=1, ppid=0, name="a.exe", command_line="a", children=[leaf])
    middle = ProcessNode(pid=2, ppid=1, name="b.exe", command_line="b", children=[again])
    root = ProcessNode(pid=1, ppid=0, name="a.exe", command_line="a", children=[middle])

    objects = _processes_to_observables(distinct_processes([root]))

    processes = {o.id: o for o in objects if o.type == "process"}
    by_pid = {o.pid: o for o in processes.values()}
    assert sorted(by_pid) == [1, 2, 3] and len(processes) == 3
    assert set(by_pid[1].child_refs) == {by_pid[2].id, by_pid[3].id}
    assert by_pid[2].child_refs == [] and by_pid[3].child_refs == []

    def _acyclic(ref: str, path: frozenset[str]) -> bool:
        if ref in path:
            return False
        return all(_acyclic(child, path | {ref}) for child in processes[ref].child_refs)

    assert all(_acyclic(ref, frozenset()) for ref in processes)
