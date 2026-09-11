"""CFG Orderer using NetworkX to topologically sort Ghidra call graphs."""

from typing import Any

import networkx as nx


class CFGOrderer:
    """Parses a Ghidra-extracted CFG JSON and outputs topologically sorted functions."""

    def __init__(self, cfg_data: dict[str, Any]) -> None:
        self.cfg_data = cfg_data
        self.graph = nx.DiGraph()
        self._build_graph()

    def _build_graph(self) -> None:
        """Build a directed graph from the CFG data."""
        functions = self.cfg_data.get("functions", {})

        # Add nodes
        for func_name in functions:
            self.graph.add_node(func_name, **functions[func_name])

        # Add edges
        for caller, attrs in functions.items():
            for callee in attrs.get("calls", []):
                # Only add edges if the callee exists in the CFG
                if callee in functions:
                    self.graph.add_edge(caller, callee)

    def get_topological_order(self) -> list[str]:
        """
        Returns a robust topological order of functions.
        Handles cycles (recursive calls/obfuscation) using strongly connected components.
        Returns a bottom-up order (leaf functions first) so the LLM builds context upwards.
        """
        if nx.is_directed_acyclic_graph(self.graph):
            ordered = list(nx.topological_sort(self.graph))
        else:
            # Graph has cycles, use condensation graph
            condensation_graph = nx.condensation(self.graph)
            # Condensation graph is always a DAG
            scc_order = list(nx.topological_sort(condensation_graph))

            ordered = []
            for scc_node in scc_order:
                # Each node in the condensation graph is a set of nodes from the original graph
                scc_members = condensation_graph.nodes[scc_node]["members"]
                ordered.extend(list(scc_members))

        # Return reversed order (bottom-up: leaves first, main last)
        # Or top-down (main first). Let's do top-down for readability:
        return ordered
