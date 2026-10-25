"""The disclosure record says where the sample's bytes were read, and what kept each reader.

The isolation part is read from the run's own records: the ledger entries
whose tools declare an argument as the sample (role ``path`` or ``carved``),
the settings blocks that declare where their server sees it, and the reads in
the worker the platform notes as they happen. A tool server started over stdio
is measured by the worker when it starts. A row is isolated only when it was
measured and every check held. A field that could not be read is absent and
never counts as passing. A server reached at an address is "not verified", and
a run that read nothing claims nothing.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from maljan.analysis import isolation
from maljan.analysis.disclosure import DISCLOSURE_VERSION, disclosure_lines, disclosure_record
from maljan.analysis.isolation import (
    CHILD,
    IN_PROCESS,
    LOCAL_SERVICE,
    NOT_MEASURED_CHILD,
    NOT_MEASURED_DISAGREE,
    NOT_MEASURED_REMOTE,
    NOT_MEASURED_SERVICE,
    REMOTE_SERVICE,
    REPORT_LABEL,
    REPORT_SOURCE,
    WORKER_LABEL,
    WORKER_SOURCE,
    isolation_lines,
    measure_process,
    note_in_process,
    note_process,
    note_read_in_worker,
    noted,
    sample_readers,
)

STDIO = {"mcp.servers.analysis.transport": "stdio", "mcp.servers.analysis.url": ""}
WORKER = {"uid": 1000, "cap_eff_zero": True, "no_new_privs": False, "platform_names_in_env": []}
# A child measured as kept from the worker on every count.
KEPT = {
    "uid": 10002,
    "same_uid_as_worker": False,
    "shares_group_with_worker": False,
    "own_pid_namespace": True,
    "own_net_namespace": True,
    "own_mount_namespace": True,
    "cap_eff_zero": True,
    "cap_prm_zero": True,
    "cap_amb_zero": True,
    "no_new_privs": True,
    "platform_names_in_env": [],
}
# A child of the worker as the shipped stack starts one today.
SHARED = {
    "uid": 1000,
    "same_uid_as_worker": True,
    "shares_group_with_worker": True,
    "own_pid_namespace": False,
    "own_net_namespace": False,
    "own_mount_namespace": False,
    "cap_eff_zero": True,
    "cap_prm_zero": True,
    "cap_amb_zero": True,
    "no_new_privs": False,
    "platform_names_in_env": [],
}
# The walk of a started process that had no descendant.
NO_TREE = {"descendants": [], "descendants_judged": True, "descendants_why": ""}
KEPT = {**KEPT, **NO_TREE}
SHARED = {**SHARED, **NO_TREE}


def _entry(source: str, tool: str = "t", *, arguments: dict | None = None, **over: Any) -> dict:
    facts: dict[str, Any] = {"v": 1, "kind": "format_info"}
    if arguments is not None:
        facts["arguments"] = arguments
    row: dict[str, Any] = {"id": "ev_1", "tool": tool, "args": {}, "ok": True, "facts": facts}
    if source:
        row["source"] = source
    row.update(over)
    return row


def _reads(source: str = "mcp:analysis") -> dict:
    return _entry(source, "pe_info", arguments={"path": "path"})


def _part(snapshot: dict, entries: list, opened: dict | None = None) -> dict:
    record = disclosure_record(snapshot, entries=entries, opened=opened or {}, worker=WORKER)
    return dict(record["isolation"])


@pytest.fixture(autouse=True)
def _clean_notes() -> Iterator[None]:
    yield
    isolation._NOTES.clear()


# ---------------------------------------------------------------------------
# Which sources read the sample
# ---------------------------------------------------------------------------


def test_a_tool_that_declares_the_sample_as_an_argument_read_it() -> None:
    readers, unsourced = sample_readers(
        STDIO,
        [
            _reads(),
            _entry("mcp:analysis", "carve", arguments={"carved": "carved_path"}),
            _entry("mcp:analysis", "iocs_from_text", arguments={"text": "text"}),
            _entry("mcp:knowledge", "attck_lookup"),
            _entry("mcp:analysis", "pe_info", arguments={"path": "path"}, repeated_of="ev_0"),
            _entry("", "pe_info", arguments={"path": "path"}),
        ],
        lambda source: None,
    )
    assert readers == {"mcp:analysis": 2}
    assert unsourced == 1


def test_every_call_through_a_block_that_declares_where_it_sees_the_sample_read_it() -> None:
    for leaf in ("sample_mount", "work_dir", "sample_open.open_tool"):
        snapshot = {f"static.decomp.{leaf}": "x"}
        readers, _ = sample_readers(
            snapshot,
            [_entry("provider:decomp", "decompile")],
            lambda source: "static.decomp",
        )
        assert readers == {"provider:decomp": 1}, leaf


def test_an_undeclared_tool_handed_one_of_the_jobs_sample_paths_read_it() -> None:
    from maljan.analysis.disclosure import job_sample_paths

    container = SimpleNamespace(
        sample_path="/app/data/uploads/.tmp/abc.exe",
        server_sample_paths={"remote": "/data/samples/.work/abc.exe"},
        static_sample_paths={"r2": "/app/data/samples/r2-work/abc.exe"},
    )
    paths = job_sample_paths(container)
    undeclared = {"id": "ev_9", "tool": "anything", "facts": {"v": 1}, "ok": True}
    readers, _ = sample_readers(
        {},
        [
            {**undeclared, "source": "mcp:plugged", "args": {"file": paths[0]}},
            {**undeclared, "source": "mcp:remote", "args": {"f": "/data/samples//.work/abc.exe"}},
            {**undeclared, "source": "mcp:r2ish", "args": {"target": paths[2], "n": 3}},
            {**undeclared, "source": "mcp:other", "args": {"file": "/etc/hosts"}},
            {**undeclared, "source": "mcp:empty", "args": {"file": ""}},
        ],
        lambda source: None,
        paths,
    )
    assert readers == {"mcp:plugged": 1, "mcp:remote": 1, "mcp:r2ish": 1}


def test_a_run_record_counts_a_call_handed_the_sample_path() -> None:
    entry = {"id": "ev_9", "tool": "scan", "source": "mcp:analysis", "facts": {"v": 1}}
    entry["args"] = {"target": "/tmp/s.bin"}
    record = disclosure_record(STDIO, entries=[entry], worker=WORKER, sample_paths=["/tmp/s.bin"])
    assert [row["source"] for row in record["isolation"]["rows"]] == ["mcp:analysis"]
    record = disclosure_record(STDIO, entries=[entry], worker=WORKER)
    assert record["isolation"]["rows"] == []


def test_finding_the_readers_is_linear_in_the_entries() -> None:
    def timed(count: int) -> float:
        entries = [_reads(f"mcp:s{i % 50}") for i in range(count)]
        started = time.perf_counter()
        sample_readers(STDIO, entries, lambda source: None)
        return time.perf_counter() - started

    small, large = timed(2_000), timed(20_000)
    assert large < max(small, 1e-3) * 40


# ---------------------------------------------------------------------------
# Measuring a process
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not Path("/proc/self/status").exists(), reason="no procfs")
def test_a_child_of_the_worker_is_measured_as_sharing_the_worker() -> None:
    child = subprocess.Popen(
        [sys.executable, "-I", "-c", "import time; time.sleep(30)"],
        env={"PATH": os.environ.get("PATH", "")},
    )
    try:
        measured = measure_process(child.pid, ["PATH", "DATABASE_URL", "MALJAN_STAGING_DIR"])
    finally:
        child.kill()
        child.wait()
    assert measured["uid"] == os.geteuid()
    assert measured["same_uid_as_worker"] is True
    assert measured["own_pid_namespace"] is False
    assert measured["own_net_namespace"] is False
    assert measured["own_mount_namespace"] is False
    assert measured["platform_names_in_env"] == ["DATABASE_URL"]
    assert measured["cap_eff_zero"] in (True, False)
    assert measured["no_new_privs"] in (True, False)


def test_a_process_that_cannot_be_read_is_absent_never_a_pass() -> None:
    measured = measure_process(2**22 + 12345, ["PATH"])
    assert {key: measured[key] for key in isolation.MEASURED_FIELDS if key != "uid"} == {
        "same_uid_as_worker": None,
        "shares_group_with_worker": None,
        "own_pid_namespace": None,
        "own_net_namespace": None,
        "own_mount_namespace": None,
        "cap_eff_zero": None,
        "cap_prm_zero": None,
        "cap_amb_zero": None,
        "no_new_privs": None,
        "platform_names_in_env": [],
    }
    assert measured["uid"] is None


def _status_of(**lines: str) -> dict[str, str]:
    """A process status whose ids differ from the worker's, with ``lines`` laid over it."""
    other = str(os.geteuid() + 7)
    group = str(max(os.getegid(), *os.getgroups(), 0) + 7)
    status = {
        "Uid": " ".join([other] * 4),
        "Gid": " ".join([group] * 4),
        "Groups": group,
        "CapEff": "0" * 16,
        "CapPrm": "0" * 16,
        "CapAmb": "0" * 16,
        "NoNewPrivs": "1",
    }
    status.update(lines)
    return status


@pytest.mark.parametrize(
    "key, field",
    [("CapEff", "cap_eff_zero"), ("CapPrm", "cap_prm_zero"), ("CapAmb", "cap_amb_zero")],
)
def test_each_capability_set_is_read_and_one_that_cannot_be_read_is_absent(
    monkeypatch: pytest.MonkeyPatch, key: str, field: str
) -> None:
    for value, expected in (("0000000000000000", True), ("0000000000002000", False), ("zz", None)):
        monkeypatch.setattr(isolation, "_status", lambda pid, v=value: _status_of(**{key: v}))
        assert measure_process(4242, [])[field] is expected, (key, value)
    missing = _status_of()
    del missing[key]
    monkeypatch.setattr(isolation, "_status", lambda pid: missing)
    assert measure_process(4242, [])[field] is None


@pytest.mark.parametrize(
    "value, said",
    [
        (True, "a mount namespace of its own"),
        (False, "the worker's mount namespace"),
        (None, "its mount namespace could not be compared"),
    ],
)
def test_the_mount_check_is_said_as_the_namespace_it_compares(value: Any, said: str) -> None:
    note = {"where": CHILD, **KEPT, "own_mount_namespace": value}
    line = isolation_lines(_part(STDIO, [_reads()], {"mcp:analysis": [note]}))[2]
    assert f"; {said};" in line
    assert "view of the filesystem" not in line


@pytest.mark.skipif(not Path("/proc/self/status").exists(), reason="no procfs")
def test_a_launcher_is_measured_with_the_server_it_started_under_it() -> None:
    launcher = subprocess.Popen(
        ["/bin/sh", "-c", f"'{sys.executable}' -I -c 'import time; time.sleep(30)' & wait"],
        env={"PATH": os.environ.get("PATH", "")},
    )
    try:
        deadline = time.monotonic() + 10
        tree = isolation.measure_tree(launcher.pid, ["PATH", "JWT_SECRET_KEY"])
        while not tree["descendants"] and time.monotonic() < deadline:
            time.sleep(0.05)
            tree = isolation.measure_tree(launcher.pid, ["PATH", "JWT_SECRET_KEY"])
    finally:
        launcher.kill()
        launcher.wait()
    assert tree["descendants_judged"] is True
    assert tree["same_uid_as_worker"] is True
    (server,) = tree["descendants"]
    assert server["same_uid_as_worker"] is True
    # Read from its own environment, not taken from the names the started one was handed.
    assert tree["platform_names_in_env"] == ["JWT_SECRET_KEY"]
    assert server["platform_names_in_env"] == []


def _one_child_tree(monkeypatch: pytest.MonkeyPatch, names: list[str] | None) -> dict:
    monkeypatch.setattr(isolation, "_children", lambda pid: [4243] if pid == 4242 else [])
    monkeypatch.setattr(isolation, "_status", lambda pid: _status_of())
    monkeypatch.setattr(isolation, "environ_names", lambda pid: names)
    return isolation.measure_tree(4242, ["PATH"])


def test_a_descendant_whose_launcher_added_a_platform_variable_is_read_as_holding_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tree = _one_child_tree(monkeypatch, ["PATH", "HOME", "DATABASE_URL"])
    assert tree["platform_names_in_env"] == []
    (server,) = tree["descendants"]
    assert server["platform_names_in_env"] == ["DATABASE_URL"]
    note = {"where": CHILD, **KEPT, "descendants": [{**KEPT, **server}]}
    part = _part(STDIO, [_reads()], {"mcp:analysis": [note]})
    assert part["rows"][0]["descendants_failing"] == 1
    assert part["isolated"] is False


def test_a_descendant_whose_environment_cannot_be_read_is_unknown_and_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (server,) = _one_child_tree(monkeypatch, None)["descendants"]
    assert server["platform_names_in_env"] is None
    note = {"where": CHILD, **KEPT, "descendants": [{**KEPT, **server}]}
    assert _part(STDIO, [_reads()], {"mcp:analysis": [note]})["isolated"] is False


def test_environ_names_keeps_names_only(tmp_path: Path) -> None:
    child = subprocess.Popen(
        [sys.executable, "-I", "-c", "import time; time.sleep(30)"],
        env={"PATH": os.environ.get("PATH", ""), "X2_NAME_ONLY": "value-not-kept"},
    )
    try:
        # Read once the child has exec'd: before that its environment reads empty.
        deadline = time.monotonic() + 10
        names = isolation.environ_names(child.pid)
        while not names and time.monotonic() < deadline:
            time.sleep(0.05)
            names = isolation.environ_names(child.pid)
    finally:
        child.kill()
        child.wait()
    assert names is not None and "X2_NAME_ONLY" in names
    assert not any("value-not-kept" in name for name in names)
    assert isolation.environ_names(2**22 + 12345) is None


def test_a_tree_wider_than_the_bound_is_not_judged(monkeypatch: pytest.MonkeyPatch) -> None:
    wide = list(range(10_000, 10_000 + isolation.MAX_TREE_PROCESSES + 5))
    monkeypatch.setattr(isolation, "_children", lambda pid: wide if pid == 1 else [])
    monkeypatch.setattr(isolation, "_status", lambda pid: _status_of())
    tree = isolation.measure_tree(1, [])
    assert tree["descendants_judged"] is False
    assert str(isolation.MAX_TREE_PROCESSES) in tree["descendants_why"]
    assert len(tree["descendants"]) == isolation.MAX_TREE_PROCESSES - 1


def test_a_tree_whose_children_cannot_be_read_is_not_judged(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(isolation, "_children", lambda pid: None)
    monkeypatch.setattr(isolation, "_gone", lambda pid: False)
    monkeypatch.setattr(isolation, "_status", lambda pid: _status_of())
    tree = isolation.measure_tree(4242, [])
    assert tree["descendants_judged"] is False
    assert tree["descendants_why"] == "the children of a process in its tree could not be read"


def test_every_process_of_the_tree_is_held_to_the_checks() -> None:
    passing_server = {**KEPT, "uid": 10003}
    launcher_then_kept = {**SHARED, "descendants": [passing_server]}
    part = _part(STDIO, [_reads()], {"mcp:analysis": [{"where": CHILD, **launcher_then_kept}]})
    row = part["rows"][0]
    assert (row["descendants"], row["descendants_failing"], row["isolated"]) == (1, 0, False)
    line = isolation_lines(part)[2]
    assert "Its 1 descendant process was measured too, and every one passed." in line
    assert "every one is held to the checks. So: not isolated." in line

    kept_then_failing = {**KEPT, "descendants": [SHARED]}
    part = _part(STDIO, [_reads()], {"mcp:analysis": [{"where": CHILD, **kept_then_failing}]})
    assert part["rows"][0]["descendants_failing"] == 1
    assert part["isolated"] is False

    kept_tree = {**KEPT, "descendants": [passing_server]}
    part = _part(STDIO, [_reads()], {"mcp:analysis": [{"where": CHILD, **kept_tree}]})
    assert part["isolated"] is True


def test_a_start_whose_tree_was_not_walked_or_not_judged_is_never_isolated() -> None:
    unwalked = {key: value for key, value in KEPT.items() if key not in NO_TREE}
    part = _part(STDIO, [_reads()], {"mcp:analysis": [{"where": CHILD, **unwalked}]})
    assert part["isolated"] is False
    assert isolation.DESCENDANTS_UNRECORDED in isolation_lines(part)[2]
    cut = {**KEPT, "descendants_judged": False, "descendants_why": "its tree was cut"}
    part = _part(STDIO, [_reads()], {"mcp:analysis": [{"where": CHILD, **cut}]})
    assert part["isolated"] is False
    assert "Its descendant processes were not judged (its tree was cut)" in isolation_lines(part)[2]


# ---------------------------------------------------------------------------
# A declared launcher (FU-F)
# ---------------------------------------------------------------------------

# A block that declares the process the worker starts for it a launcher.
LAUNCHED = {**STDIO, "mcp.servers.analysis.launcher_depth": 1}
# A server under a launcher, measured as kept from the worker.
UNDER = {**KEPT, "uid": 10003, "depth": 1}
LAUNCHER_SAID = (
    "Its block declares the process the worker started a launcher that does not read the "
    "sample (the block's word, not measured)"
)


def test_the_walk_records_how_deep_each_descendant_sits(monkeypatch: pytest.MonkeyPatch) -> None:
    tree = {4242: [4243], 4243: [4244]}
    monkeypatch.setattr(isolation, "_children", lambda pid: tree.get(pid, []))
    monkeypatch.setattr(isolation, "_status", lambda pid: _status_of())
    monkeypatch.setattr(isolation, "environ_names", lambda pid: ["PATH"])
    walked = isolation.measure_tree(4242, ["PATH"])
    assert [process["depth"] for process in walked["descendants"]] == [1, 2]


def test_a_declared_launcher_is_held_to_its_environment_and_its_server_to_every_check() -> None:
    note = {"where": CHILD, **SHARED, "descendants": [UNDER]}
    part = _part(LAUNCHED, [_reads()], {"mcp:analysis": [note]})
    row = part["rows"][0]
    assert (row["launcher_depth"], row["under_launcher"], row["isolated"]) == (1, 1, True)
    assert (row["isolated_by"], part["isolated"], part["isolated_by"]) == (
        "declaration",
        True,
        "declaration",
    )
    # The headline names the declaration too, not only the row.
    assert isolation_lines(part)[0] == (
        "Every source that read the sample's bytes was kept from the worker as measured, but "
        "for tool server `analysis` that rests on its block's declaration of a launcher."
    )
    line = isolation_lines(part)[2]
    # What the launcher was measured as is still said, beside the block's word.
    assert "it ran as user 1000 (one of its real" in line
    assert LAUNCHER_SAID in line
    passed = "1 process under the launcher was measured, and every process of the tree passed."
    assert passed in line
    assert line.endswith("So: isolated by its block's declaration.")
    # The same tree without the declaration is judged as it always was.
    part = _part(STDIO, [_reads()], {"mcp:analysis": [note]})
    assert part["rows"][0]["launcher_depth"] == 0
    assert part["isolated"] is False
    assert LAUNCHER_SAID not in isolation_lines(part)[2]


def test_a_launcher_that_holds_a_platform_variable_keeps_the_row_from_isolated() -> None:
    leaky = {**SHARED, "platform_names_in_env": ["DATABASE_URL"], "descendants": [UNDER]}
    part = _part(LAUNCHED, [_reads()], {"mcp:analysis": [{"where": CHILD, **leaky}]})
    assert part["isolated"] is False
    unread = {**SHARED, "platform_names_in_env": None, "descendants": [UNDER]}
    part = _part(LAUNCHED, [_reads()], {"mcp:analysis": [{"where": CHILD, **unread}]})
    assert part["isolated"] is False


def test_a_launcher_with_no_measured_process_under_it_proves_nothing() -> None:
    # A container client: the server runs where this run cannot see it.
    part = _part(LAUNCHED, [_reads()], {"mcp:analysis": [{"where": CHILD, **SHARED}]})
    row = part["rows"][0]
    assert (row["under_launcher"], row["isolated"]) == (0, False)
    assert row["isolated_by"] == part["isolated_by"] == ""
    assert "No process under the launcher was measured" in isolation_lines(part)[2]


def test_every_process_under_a_launcher_is_held_to_every_check() -> None:
    note = {"where": CHILD, **SHARED, "descendants": [UNDER, {**SHARED, "depth": 2}]}
    part = _part(LAUNCHED, [_reads()], {"mcp:analysis": [note]})
    row = part["rows"][0]
    assert (row["under_launcher"], row["descendants_failing"], row["isolated"]) == (2, 1, False)
    assert (
        "2 processes under the launcher were measured, and 1 of the tree did not pass."
        in isolation_lines(part)[2]
    )


def test_a_launcher_of_two_levels_covers_its_own_child_and_no_further() -> None:
    helper = {**SHARED, "depth": 1}
    server = {**KEPT, "uid": 10003, "depth": 2}
    note = {"where": CHILD, **SHARED, "descendants": [helper, server]}
    two = {**STDIO, "mcp.servers.analysis.launcher_depth": 2}
    part = _part(two, [_reads()], {"mcp:analysis": [note]})
    assert (part["rows"][0]["under_launcher"], part["isolated"]) == (1, True)
    assert "the top 2 levels of its tree a launcher" in isolation_lines(part)[2]
    # Declared one level, the helper is a reader like any other, and fails.
    part = _part(LAUNCHED, [_reads()], {"mcp:analysis": [note]})
    assert part["isolated"] is False


def test_under_a_launcher_a_walk_without_depths_is_not_judged() -> None:
    note = {"where": CHILD, **SHARED, "descendants": [{**KEPT, "uid": 10003}]}
    part = _part(LAUNCHED, [_reads()], {"mcp:analysis": [note]})
    row = part["rows"][0]
    assert (row["descendants_judged"], row["isolated"]) == (False, False)
    assert isolation.DEPTH_UNRECORDED in isolation_lines(part)[2]


def test_a_launcher_declared_on_a_server_reached_at_an_address_changes_nothing() -> None:
    snapshot = {
        "mcp.servers.analysis.transport": "http",
        "mcp.servers.analysis.url": "http://127.0.0.1:9000",
        "mcp.servers.analysis.launcher_depth": 1,
    }
    part = _part(snapshot, [_reads()])
    row = part["rows"][0]
    assert (row["where"], row["launcher_depth"], row["isolated"]) == (LOCAL_SERVICE, 0, False)


def test_the_launcher_is_a_declaration_field_recorded_only_where_an_operator_set_it() -> None:
    from pydantic import ValidationError

    from maljan.core.config import MCPServerConfig, Settings
    from maljan.core.settings_overrides import trim_declarations
    from maljan.core.tool_declarations import DECLARATION_FIELDS, strip_declaration_defaults

    assert "launcher_depth" in DECLARATION_FIELDS
    assert MCPServerConfig().launcher_depth is None
    with pytest.raises(ValidationError):
        MCPServerConfig(launcher_depth=-1)
    # Unset, it moves no stored row; set, it is the operator's and is stored.
    default = Settings().mcp.servers["analysis"]
    dumped = default.model_dump(mode="json")
    assert "launcher_depth" not in strip_declaration_defaults(dumped, default)
    assert (
        strip_declaration_defaults({**dumped, "launcher_depth": 1}, default)["launcher_depth"] == 1
    )
    key = "mcp.servers.analysis.launcher_depth"
    stored = {"mcp.servers": {"analysis": {"launcher_depth": 1}}}
    assert trim_declarations({key: 1}, Settings(), stored)[key] == 1
    assert key not in trim_declarations({key: None}, Settings(), {})


def test_a_permitted_or_ambient_capability_is_said_and_keeps_the_reader_from_isolated() -> None:
    part = _part(
        STDIO, [_reads()], {"mcp:analysis": [{"where": CHILD, **KEPT, "cap_prm_zero": False}]}
    )
    assert part["isolated"] is False
    assert "; permitted capabilities;" in isolation_lines(part)[2]


@pytest.mark.parametrize("field", range(4))
def test_any_of_the_four_user_ids_being_the_workers_shares_the_worker(
    monkeypatch: pytest.MonkeyPatch, field: int
) -> None:
    ids = [str(os.geteuid() + 7)] * 4
    ids[field] = str(os.geteuid())
    monkeypatch.setattr(isolation, "_status", lambda pid: _status_of(Uid=" ".join(ids)))
    assert measure_process(4242, [])["same_uid_as_worker"] is True


def test_four_user_ids_none_of_them_the_workers_do_not_share_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(isolation, "_status", lambda pid: _status_of())
    measured = measure_process(4242, [])
    assert measured["same_uid_as_worker"] is False
    assert measured["shares_group_with_worker"] is False


@pytest.mark.parametrize("uid_line", ["", "1 2 3", "1 2 x 4"])
def test_a_user_id_line_that_cannot_be_read_whole_is_absent(
    monkeypatch: pytest.MonkeyPatch, uid_line: str
) -> None:
    monkeypatch.setattr(isolation, "_status", lambda pid: _status_of(Uid=uid_line))
    assert measure_process(4242, [])["same_uid_as_worker"] is None


def test_a_group_id_or_a_supplementary_group_of_the_workers_shares_a_group(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mine = str(os.getegid())
    other = _status_of()["Gid"].split()[0]
    for lines in (
        {"Gid": f"{other} {other} {mine} {other}"},
        {"Groups": f"{other} {mine}"},
    ):
        monkeypatch.setattr(isolation, "_status", lambda pid, lines=lines: _status_of(**lines))
        assert measure_process(4242, [])["shares_group_with_worker"] is True, lines
    without_groups = _status_of()
    del without_groups["Groups"]
    monkeypatch.setattr(isolation, "_status", lambda pid: without_groups)
    assert measure_process(4242, [])["shares_group_with_worker"] is None


# ---------------------------------------------------------------------------
# The part
# ---------------------------------------------------------------------------


def test_the_record_carries_the_part_and_says_its_version() -> None:
    record = disclosure_record(STDIO, entries=[_reads()], worker=WORKER)
    assert record["v"] == DISCLOSURE_VERSION == 4
    assert record["isolation"]["rows"][0]["source"] == "mcp:analysis"


def test_a_read_in_the_worker_is_never_isolated() -> None:
    part = _part(
        STDIO,
        [_reads("pack")],
        {REPORT_SOURCE: [{"where": IN_PROCESS, "label": REPORT_LABEL}]},
    )
    rows = {row["source"]: row for row in part["rows"]}
    assert rows["pack"]["where"] == IN_PROCESS
    assert rows["pack"]["label"] == "Triage pack"
    assert rows[REPORT_SOURCE]["label"] == REPORT_LABEL
    assert not any(row["isolated"] for row in rows.values())
    assert part["isolated"] is False


def test_a_child_kept_from_the_worker_on_every_count_is_isolated() -> None:
    part = _part(STDIO, [_reads()], {"mcp:analysis": [{"where": CHILD, **KEPT}]})
    assert part["rows"][0]["isolated"] is True
    assert part["isolated"] is True
    assert part["rows"][0]["isolated_by"] == part["isolated_by"] == "measurement"
    lines = isolation_lines(part)
    assert lines[0] == (
        "Every source that read the sample's bytes was measured as kept from the worker."
    )
    assert "So: isolated." in lines[2]


@pytest.mark.parametrize(
    "field, value",
    [
        ("same_uid_as_worker", True),
        ("shares_group_with_worker", True),
        ("shares_group_with_worker", None),
        ("own_pid_namespace", False),
        ("own_mount_namespace", False),
        ("own_net_namespace", False),
        ("cap_eff_zero", False),
        ("cap_prm_zero", False),
        ("cap_amb_zero", False),
        ("cap_prm_zero", None),
        ("cap_amb_zero", None),
        ("no_new_privs", False),
        ("platform_names_in_env", ["SETTINGS_ENCRYPTION_KEY"]),
        ("same_uid_as_worker", None),
        ("own_pid_namespace", None),
        ("cap_eff_zero", None),
        ("no_new_privs", None),
        ("platform_names_in_env", None),
    ],
)
def test_any_check_that_failed_or_could_not_be_read_keeps_a_child_from_isolated(
    field: str, value: Any
) -> None:
    part = _part(STDIO, [_reads()], {"mcp:analysis": [{"where": CHILD, **KEPT, field: value}]})
    assert part["rows"][0]["isolated"] is False
    assert part["isolated"] is False


def test_a_block_that_declares_it_needs_the_network_is_not_held_to_one_of_its_own() -> None:
    snapshot = {**STDIO, "mcp.servers.analysis.roles": ["sandbox"]}
    open_net = {"where": CHILD, **KEPT, "own_net_namespace": False}
    part = _part(snapshot, [_reads()], {"mcp:analysis": [open_net]})
    assert part["rows"][0]["needs_network"] is True
    assert part["rows"][0]["isolated"] is True
    # Only the network is lifted.
    shared_user = {**open_net, "same_uid_as_worker": True}
    part = _part(snapshot, [_reads()], {"mcp:analysis": [shared_user]})
    assert part["rows"][0]["isolated"] is False


def test_a_child_the_worker_could_not_measure_is_said_and_not_isolated() -> None:
    part = _part(STDIO, [_reads()])
    row = part["rows"][0]
    assert (row["where"], row["isolated"], row["why_not_measured"]) == (
        CHILD,
        False,
        NOT_MEASURED_CHILD,
    )
    assert isolation_lines(part)[2].endswith("so its isolation cannot be told.")


def test_starts_measured_differently_leave_the_differing_field_absent() -> None:
    part = _part(
        STDIO,
        [_reads()],
        {"mcp:analysis": [{"where": CHILD, **KEPT}, {"where": CHILD, **KEPT, "uid": 10003}]},
    )
    row = part["rows"][0]
    assert row["uid"] is None
    assert row["attaches"] == 2
    assert row["why_not_measured"] == NOT_MEASURED_DISAGREE
    assert row["isolated"] is True


def test_a_server_reached_at_an_address_is_not_verified() -> None:
    snapshot = {
        "mcp.servers.near.transport": "streamable-http",
        "mcp.servers.near.url": "http://tools:8089/mcp",
        "mcp.servers.far.transport": "streamable-http",
        "mcp.servers.far.url": "https://tools.example.org/mcp",
    }
    part = _part(snapshot, [_reads("mcp:near"), _reads("mcp:far")])
    rows = {row["source"]: row for row in part["rows"]}
    assert (rows["mcp:near"]["where"], rows["mcp:near"]["why_not_measured"]) == (
        LOCAL_SERVICE,
        NOT_MEASURED_SERVICE,
    )
    assert (rows["mcp:far"]["where"], rows["mcp:far"]["why_not_measured"]) == (
        REMOTE_SERVICE,
        NOT_MEASURED_REMOTE,
    )
    lines = isolation_lines(part)
    assert any(line.endswith("so not verified by this run.") for line in lines)
    assert any(line.endswith("so this run cannot tell what isolation it had.") for line in lines)


def test_a_run_that_read_nothing_claims_nothing() -> None:
    part = _part(STDIO, [_entry("mcp:knowledge", "attck_lookup")])
    assert part["rows"] == []
    assert part["isolated"] is False
    assert isolation_lines(part) == [
        "This run recorded no read of the sample's bytes, so nothing is said of it."
    ]


def test_a_read_with_no_source_keeps_the_run_from_isolated() -> None:
    part = _part(
        STDIO,
        [_reads(), _entry("", "pe_info", arguments={"path": "path"})],
        {"mcp:analysis": [{"where": CHILD, **KEPT}]},
    )
    assert part["unsourced_reads"] == 1
    assert part["isolated"] is False
    assert isolation_lines(part)[-1] == (
        "1 call that read the sample recorded no source, so where it ran cannot be told."
    )


def test_a_version_one_record_renders_as_it_did() -> None:
    record = disclosure_record(STDIO, entries=[_reads()], worker=WORKER)
    old = {key: value for key, value in record.items() if key != "isolation"}
    old["v"] = 1
    assert isolation_lines(old.get("isolation")) == []
    assert disclosure_lines(old) == disclosure_lines(record)


def test_the_report_prints_the_part_inside_the_disclosure_block() -> None:
    from maljan.analysis.disclosure import FOOTNOTE_SENTENCE
    from maljan.analysis.disclosure import INTRO_SENTENCE as DISCLOSURE_INTRO
    from maljan.analysis.isolation import INTRO_SENTENCE
    from maljan.reporting.models import FileHashes, MalwareReport, SampleIdentity
    from maljan.reporting.renderers.markdown import MarkdownRenderer

    record = disclosure_record(
        STDIO,
        entries=[_reads(), _reads("pack")],
        opened={"mcp:analysis": [{"where": CHILD, **SHARED}]},
        worker={**WORKER, "platform_names_in_env": ["DATABASE_URL", "JWT_SECRET_KEY"]},
    )
    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        verdict="Malware",
        run_summary={"final_decision": "Malware", "disclosure": record},
    )
    markdown = MarkdownRenderer().render(report)
    assert markdown.index(DISCLOSURE_INTRO) < markdown.index(INTRO_SENTENCE)
    assert markdown.index(INTRO_SENTENCE) < markdown.index(FOOTNOTE_SENTENCE)
    assert (
        "- The worker process runs as user 1000; its environment holds the platform's own "
        "variables `DATABASE_URL`, `JWT_SECRET_KEY`."
    ) in markdown
    assert (
        "- Triage pack (`pack`) read the sample in the worker process itself: not isolated, "
        "since it shares the worker's memory, environment, files and network."
    ) in markdown
    assert (
        "- Tool server `analysis` (stdio, run on this machine) read the sample. The process the "
        "worker started for it was measured at its start: it ran as user 1000 (one of its real, "
        "effective, saved or filesystem user ids is the worker's); in a group of the worker's; "
        "sharing the worker's process table; the worker's mount namespace; the worker's "
        "network; no effective, permitted or ambient capabilities; no bar on gaining "
        "privileges; its environment held none of the platform's own variables. It had no "
        "descendant process when it was measured. So: not isolated."
    ) in markdown


# ---------------------------------------------------------------------------
# The reads in the worker that write no entry
# ---------------------------------------------------------------------------


def _drafting(path: str | None, calls: list[str]) -> None:
    from maljan.reporting.builder import build_consolidated_iocs
    from maljan.reporting.detection_signatures import OwnSample, build_detection_rules
    from maljan.reporting.models import (
        FileHashes,
        MalwareReport,
        NetworkDomain,
        NetworkIOCs,
        SampleIdentity,
    )

    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="c" * 64)),
        verdict="Malware",
        malware_category="loader",
        network=NetworkIOCs(
            domains=[
                NetworkDomain(fqdn=name, source="sandbox")
                for name in ("gate9.example.org", "relay4.example.net")
            ]
        ),
    )
    report.consolidated_iocs = build_consolidated_iocs(report)
    build_detection_rules(
        report, OwnSample(path=path, budget_seconds=60, on_open=lambda: calls.append("open"))
    )


def test_the_report_steps_check_notes_its_read_only_when_it_hands_the_engine_the_file(
    tmp_path: Path,
) -> None:
    from maljan.reporting import detection_signatures as drafts

    if not drafts._YARA_AVAILABLE:
        pytest.skip("yara-python is not installed")
    calls: list[str] = []
    _drafting(None, calls)
    assert calls == []
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"\x00" * 16 + b"gate9.example.org" + b"\x00" * 8)
    _drafting(str(sample), calls)
    assert calls == ["open"]


def test_the_report_node_notes_its_read_under_the_job() -> None:
    from maljan.pipeline.nodes import _noting_the_report_read

    note = _noting_the_report_read(SimpleNamespace(job_key=lambda: "job-d"))
    note()
    assert noted("job-d") == {REPORT_SOURCE: [{"where": IN_PROCESS, "label": REPORT_LABEL}]}


def test_the_routing_notes_the_workers_own_read(tmp_path: Path) -> None:
    from maljan.app import MaljanApp

    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"MZ" + b"\x00" * 62)
    app = SimpleNamespace(container=SimpleNamespace(job_key=lambda: "job-e"))
    MaljanApp._infer_sample_platform(app, str(sample), None)  # type: ignore[arg-type]
    assert noted("job-e") == {WORKER_SOURCE: [{"where": IN_PROCESS, "label": WORKER_LABEL}]}


# ---------------------------------------------------------------------------
# The job's notes
# ---------------------------------------------------------------------------


def test_notes_are_kept_per_job_and_dropped_when_asked() -> None:
    note_process("job-a", "mcp:analysis", KEPT)
    note_in_process("job-a", WORKER_SOURCE, WORKER_LABEL)
    note_in_process("job-a", WORKER_SOURCE, WORKER_LABEL)
    note_process("job-b", "mcp:analysis", SHARED)
    held = noted("job-a")
    assert [note["where"] for note in held["mcp:analysis"]] == [CHILD]
    assert held[WORKER_SOURCE] == [{"where": IN_PROCESS, "label": WORKER_LABEL}]
    isolation.forget("job-a")
    assert noted("job-a") == {}
    assert noted("job-b")["mcp:analysis"][0]["uid"] == SHARED["uid"]


def test_a_container_without_a_job_key_notes_nothing() -> None:
    note_read_in_worker(SimpleNamespace(), WORKER_SOURCE, WORKER_LABEL)
    assert isolation._NOTES == {}
    note_read_in_worker(SimpleNamespace(job_key=lambda: "job-c"), REPORT_SOURCE, REPORT_LABEL)
    assert noted("job-c")[REPORT_SOURCE][0]["label"] == REPORT_LABEL


def test_a_connection_test_measures_nothing(tmp_path: Path) -> None:
    from maljan.core.config import MCPServerConfig
    from maljan.providers.servers import ServerHandle

    handle = ServerHandle("probe", MCPServerConfig(transport="stdio", command="/bin/true"))
    handle._child_pids = (os.getpid(),)
    handle._job_id = "probe-x"
    handle._note_isolation()
    assert noted("probe-x") == {}
    handle.measures_isolation = True
    handle.declared_source = "provider:decomp"
    handle._launch_env_names = ("PATH",)
    handle._note_isolation()
    assert noted("probe-x")["provider:decomp"][0]["same_uid_as_worker"] is True


@pytest.mark.skipif(
    not sys.executable or not shutil.which(sys.executable),
    reason="no python interpreter available to launch the sidecar",
)
def test_a_jobs_stdio_server_is_measured_at_its_start_and_forgotten_at_teardown(
    tmp_path: Path,
) -> None:
    from maljan.core.container import ServiceContainer
    from maljan.core.settings_overrides import build_settings

    job_id = "job-isolation-measure"
    container = ServiceContainer(
        build_settings({}), mock=True, samples_dir=str(tmp_path), job_id=job_id
    )

    async def attach() -> dict:
        try:
            handle = container.get_server_registry().get("analysis")
            await handle.aopen(job_id)
            assert handle._child_pids, "the sidecar really is a child of this process"
            return dict(noted(job_id))
        finally:
            await container.aclose()

    held = asyncio.run(asyncio.wait_for(attach(), timeout=120))
    (measured,) = held["mcp:analysis"]
    assert measured["where"] == CHILD
    assert measured["same_uid_as_worker"] is True
    assert measured["own_pid_namespace"] is False
    assert measured["platform_names_in_env"] == []
    assert noted(job_id) == {}
