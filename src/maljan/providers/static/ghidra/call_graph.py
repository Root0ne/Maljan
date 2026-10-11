"""Ghidra's call graph, turned into the neutral shape the sink ranking reads.

``GET /get_full_call_graph`` answers one ``CALLER -> CALLEE`` edge per line,
and Ghidra names a function it found no symbol for ``FUN_<address>``. The
ranking itself is the platform's (``maljan.analysis.sink_reachability``).
"""

from __future__ import annotations

import re

from maljan.analysis.sink_reachability import CallGraph

_FUN_ADDR_RE = re.compile(r"^FUN_0*([0-9a-fA-F]+)$")

# The sentence after Ghidra's priority-functions list: what to do with them,
# in its own tools' words.
PRIORITY_FOLLOW_UP = (
    "Use decompile_function / get_function_callees on these first. NOTE: "
    "reachable is NOT the same as data-connected — before asserting a "
    "'capability reached' claim, confirm the data path with analyze_dataflow "
    "(forward from the source, or backward from the sink argument) and "
    "classify the terminal (caller-supplied / decoded-config / fixed "
    "constant) to pick the right ATT&CK technique.\n"
)


def call_graph_from_text(text: str) -> CallGraph:
    """Ghidra's ``CALLER -> CALLEE`` edge lines as a :class:`CallGraph`.

    A line without the arrow is not an edge. A ``FUN_<address>`` name gives
    its function's address.
    """
    edges: list[tuple[str, str]] = []
    for line in text.splitlines():
        if " -> " not in line:
            continue
        caller, _, callee = line.partition(" -> ")
        edges.append((caller, callee))
    graph = CallGraph.of_edges(edges)
    names = set(graph.callees) | {callee for called in graph.callees.values() for callee in called}
    addresses = {
        name: f"0x{match.group(1)}" for name in names if (match := _FUN_ADDR_RE.match(name))
    }
    return CallGraph(callees=graph.callees, addresses=addresses)
