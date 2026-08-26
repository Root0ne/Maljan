"""Dynamic extractor signal-quality tests (§2.4).

Covers the FP-reduction + robustness hardening: benign-process injection
whitelist, process-tree cycle/duplicate handling, and registry query noise drop.
"""

from __future__ import annotations

from maljan.extractors.dynamic_extractor import (
    _build_process_tree,
    _extract_registry_mods,
)
from maljan.reporting.models import ProcessNode


def _flatten(roots: list[ProcessNode]) -> dict[int, ProcessNode]:
    out: dict[int, ProcessNode] = {}
    stack = list(roots)
    while stack:
        n = stack.pop()
        if n.pid in out:  # guard against any residual cycle
            continue
        out[n.pid] = n
        stack.extend(n.children)
    return out


class TestInjectionWhitelist:
    def test_benign_injector_not_flagged_malware_is(self) -> None:
        processes = [
            {"pid": 100, "ppid": 1, "name": "victim.exe"},
            {
                "pid": 4,
                "ppid": 1,
                "name": "C:\\Windows\\System32\\svchost.exe",
                "calls": [{"api": "CreateRemoteThread", "arguments": [{"ProcessId": 100}]}],
            },
            {
                "pid": 200,
                "ppid": 1,
                "name": "evil.exe",
                "calls": [{"api": "WriteProcessMemory", "arguments": [{"ProcessId": 100}]}],
            },
        ]
        nodes = _flatten(_build_process_tree(processes))
        assert nodes[4].injected_into == []  # benign svchost skipped
        assert nodes[200].injected_into == [100]  # real injector flagged


class TestProcessTreeRobustness:
    def test_cycle_does_not_hang_and_yields_nodes(self) -> None:
        processes = [
            {"pid": 1, "ppid": 2, "name": "a"},
            {"pid": 2, "ppid": 1, "name": "b"},
        ]
        roots = _build_process_tree(processes)
        nodes = _flatten(roots)
        assert set(nodes) == {1, 2}
        assert roots  # at least one node treated as root (cycle broken)

    def test_duplicate_pid_keeps_first(self) -> None:
        processes = [
            {"pid": 5, "ppid": 1, "name": "first", "command_line": "first.exe"},
            {"pid": 5, "ppid": 1, "name": "second", "command_line": "second.exe"},
        ]
        nodes = _flatten(_build_process_tree(processes))
        assert nodes[5].command_line == "first.exe"


class TestRegistryQueryDrop:
    def test_query_dropped_writes_kept(self) -> None:
        calls = [
            {
                "api": "RegQueryValueExA",
                "arguments": [{"FullName": "HKCU\\Software\\X", "ValueName": "v"}],
            },
            {
                "api": "RegSetValueExA",
                "arguments": [
                    {"FullName": "HKLM\\Software\\Y", "ValueName": "v", "Buffer": "data"}
                ],
            },
        ]
        mods = _extract_registry_mods(calls)
        ops = [m.operation for m in mods]
        assert "query" not in ops
        assert "modify" in ops
