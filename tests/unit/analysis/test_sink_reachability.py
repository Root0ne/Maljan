"""Unit tests for the Maltracker-inspired sink-reachability triage engine."""

from __future__ import annotations

from maljan.analysis.sink_reachability import (
    SENSITIVE_SINKS,
    _normalize_api,
    _sink_category,
    build_priority_hint,
    parse_call_graph,
    rank_suspicious_functions,
)

# A small synthetic call graph: ``main`` orchestrates an injection wrapper and
# a network setup, and also calls CreateRemoteThread directly.
NAMED_GRAPH = """
main -> alloc_wrapper
alloc_wrapper -> KERNEL32.dll::VirtualAllocEx
alloc_wrapper -> WriteProcessMemory
main -> net_setup
net_setup -> connect
main -> CreateRemoteThread
main -> printf
""".strip()

# A stripped/static binary: only Ghidra auto-names, no sink APIs.
STRIPPED_GRAPH = "\n".join(["FUN_08054232 -> FUN_080542a1", "FUN_080542a1 -> FUN_0805228b"])


class TestNormalize:
    def test_strips_module_prefix(self) -> None:
        assert _normalize_api("KERNEL32.dll::VirtualAllocEx") == "virtualallocex"

    def test_strips_thunk_and_stdcall(self) -> None:
        assert _normalize_api("thunk_WinExec") == "winexec"
        assert _normalize_api("__imp__WinExec@4") == "winexec"

    def test_zw_aliases_to_nt(self) -> None:
        assert _normalize_api("ZwWriteVirtualMemory") == "ntwritevirtualmemory"


class TestSinkCategory:
    def test_known_sinks(self) -> None:
        assert _sink_category("VirtualAllocEx") == "injection"
        assert _sink_category("connect") == "network"
        assert _sink_category("CryptEncrypt") == "crypto"

    def test_ansi_unicode_suffix(self) -> None:
        # RegSetValueExA -> regsetvalueex (persistence)
        assert _sink_category("RegSetValueExA") == "persistence"

    def test_non_sinks(self) -> None:
        assert _sink_category("printf") is None
        assert _sink_category("FUN_08054232") is None
        assert _sink_category("memcpy") is None


class TestParseCallGraph:
    def test_edges(self) -> None:
        fwd, rev = parse_call_graph("a -> b\nb -> c")
        assert fwd["a"] == {"b"}
        assert rev["c"] == {"b"}

    def test_ignores_garbage_lines(self) -> None:
        fwd, _ = parse_call_graph("header line\n\na -> b\n")
        assert fwd == {"a": {"b"}}


class TestRanking:
    def test_main_ranks_first_with_two_categories(self) -> None:
        fwd, rev = parse_call_graph(NAMED_GRAPH)
        ranked = rank_suspicious_functions(fwd, rev)
        assert ranked, "expected at least one suspicious function"
        top = ranked[0]
        assert top.name == "main"
        assert top.categories == {"injection", "network"}
        # main calls CreateRemoteThread directly -> distance 1.
        assert top.distance == 1

    def test_sink_nodes_excluded(self) -> None:
        fwd, rev = parse_call_graph(NAMED_GRAPH)
        ranked = rank_suspicious_functions(fwd, rev)
        names = {f.name for f in ranked}
        assert "WriteProcessMemory" not in names
        assert "connect" not in names

    def test_wrappers_present(self) -> None:
        fwd, rev = parse_call_graph(NAMED_GRAPH)
        names = {f.name for f in rank_suspicious_functions(fwd, rev)}
        assert "alloc_wrapper" in names
        assert "net_setup" in names

    def test_max_funcs_caps_output(self) -> None:
        fwd, rev = parse_call_graph(NAMED_GRAPH)
        assert len(rank_suspicious_functions(fwd, rev, max_funcs=1)) == 1


class TestAddress:
    def test_fun_name_yields_address(self) -> None:
        fwd, rev = parse_call_graph("FUN_08052f6c -> VirtualAllocEx")
        ranked = rank_suspicious_functions(fwd, rev)
        assert ranked[0].address == "0x8052f6c"

    def test_named_function_has_no_address(self) -> None:
        fwd, rev = parse_call_graph(NAMED_GRAPH)
        top = next(f for f in rank_suspicious_functions(fwd, rev) if f.name == "main")
        assert top.address is None


class TestBuildHint:
    def test_named_graph_produces_hint(self) -> None:
        hint = build_priority_hint(NAMED_GRAPH)
        assert "PRIORITY FUNCTIONS" in hint
        assert "main" in hint
        assert "injection" in hint

    def test_stripped_graph_is_empty(self) -> None:
        assert build_priority_hint(STRIPPED_GRAPH) == ""

    def test_empty_input_is_empty(self) -> None:
        assert build_priority_hint("") == ""


def test_catalogue_keys_are_normalized() -> None:
    # Every catalogue key must already be in normalized form (lowercase,
    # no decoration) so lookups are O(1) and self-consistent.
    for key in SENSITIVE_SINKS:
        assert key == _normalize_api(key), f"unnormalized catalogue key: {key}"
