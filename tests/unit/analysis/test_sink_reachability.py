"""Unit tests for the Maltracker-inspired sink-reachability triage engine."""

from __future__ import annotations

from maljan.analysis.sink_reachability import (
    FOLLOW_UP,
    SENSITIVE_SINKS,
    CallGraph,
    _normalize_api,
    _sink_category,
    build_priority_hint,
    priority_hint,
    rank_suspicious_functions,
)
from maljan.providers.static.ghidra.call_graph import (
    PRIORITY_FOLLOW_UP,
    call_graph_from_text,
)


def parse_call_graph(text: str) -> CallGraph:
    """Ghidra's edge text, as its provider reads it."""
    return call_graph_from_text(text)


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
        fwd, rev = parse_call_graph("a -> b\nb -> c").adjacency()
        assert fwd["a"] == {"b"}
        assert rev["c"] == {"b"}

    def test_ignores_garbage_lines(self) -> None:
        fwd, _ = parse_call_graph("header line\n\na -> b\n").adjacency()
        assert fwd == {"a": {"b"}}

    def test_a_graph_built_from_pairs_needs_no_text(self) -> None:
        graph = CallGraph.of_edges(
            [("main", "CreateRemoteThread"), ("", "x")], addresses={"main": "0x401000"}
        )
        [top] = rank_suspicious_functions(graph)
        assert (top.name, top.address, top.categories) == ("main", "0x401000", {"injection"})


class TestRanking:
    def test_main_ranks_first_with_two_categories(self) -> None:
        ranked = rank_suspicious_functions(parse_call_graph(NAMED_GRAPH))
        assert ranked, "expected at least one suspicious function"
        top = ranked[0]
        assert top.name == "main"
        assert top.categories == {"injection", "network"}
        # main calls CreateRemoteThread directly -> distance 1.
        assert top.distance == 1

    def test_sink_nodes_excluded(self) -> None:
        ranked = rank_suspicious_functions(parse_call_graph(NAMED_GRAPH))
        names = {f.name for f in ranked}
        assert "WriteProcessMemory" not in names
        assert "connect" not in names

    def test_wrappers_present(self) -> None:
        names = {f.name for f in rank_suspicious_functions(parse_call_graph(NAMED_GRAPH))}
        assert "alloc_wrapper" in names
        assert "net_setup" in names

    def test_max_funcs_caps_output(self) -> None:
        assert len(rank_suspicious_functions(parse_call_graph(NAMED_GRAPH), max_funcs=1)) == 1


class TestAddress:
    def test_fun_name_yields_address(self) -> None:
        ranked = rank_suspicious_functions(parse_call_graph("FUN_08052f6c -> VirtualAllocEx"))
        assert ranked[0].address == "0x8052f6c"

    def test_named_function_has_no_address(self) -> None:
        graph = parse_call_graph(NAMED_GRAPH)
        top = next(f for f in rank_suspicious_functions(graph) if f.name == "main")
        assert top.address is None


class TestBuildHint:
    def test_named_graph_produces_hint(self) -> None:
        hint = build_priority_hint(parse_call_graph(NAMED_GRAPH))
        assert "PRIORITY FUNCTIONS" in hint
        assert "main" in hint
        assert "injection" in hint

    def test_stripped_graph_is_empty(self) -> None:
        assert build_priority_hint(parse_call_graph(STRIPPED_GRAPH)) == ""

    def test_empty_input_is_empty(self) -> None:
        assert build_priority_hint(parse_call_graph("")) == ""

    def test_the_hint_ends_in_the_providers_own_sentence(self) -> None:
        graph = parse_call_graph(NAMED_GRAPH)
        assert build_priority_hint(graph, follow_up=PRIORITY_FOLLOW_UP).endswith(PRIORITY_FOLLOW_UP)
        neutral = build_priority_hint(graph)
        assert neutral.endswith(FOLLOW_UP)
        assert "decompile_function" not in neutral and "analyze_dataflow" not in neutral

    def test_no_function_is_no_hint(self) -> None:
        assert priority_hint([]) == ""


def test_a_hostile_graph_ten_times_larger_is_ranked_in_linear_time() -> None:
    import time

    def graph(n: int) -> CallGraph:
        edges = [(f"f{i}", f"f{i + 1}") for i in range(n)] + [(f"f{n}", "VirtualAllocEx")]
        return CallGraph.of_edges(edges)

    started = time.perf_counter()
    rank_suspicious_functions(graph(2_000))
    small = time.perf_counter() - started
    started = time.perf_counter()
    ranked = rank_suspicious_functions(graph(20_000), max_funcs=3)
    large = time.perf_counter() - started
    assert [f.name for f in ranked] == ["f20000", "f19999", "f19998"]
    assert large < max(small, 0.01) * 40


def test_catalogue_keys_are_normalized() -> None:
    # Every catalogue key must already be in normalized form (lowercase,
    # no decoration) so lookups are O(1) and self-consistent.
    for key in SENSITIVE_SINKS:
        assert key == _normalize_api(key), f"unnormalized catalogue key: {key}"
