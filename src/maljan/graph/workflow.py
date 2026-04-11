from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph

from maljan.graph.nodes import (
    dynamic_analyst_node,
    judge_node,
    negotiation_node,
    network_analyst_node,
    static_analyst_node,
)
from maljan.schemas.agent_states import MalwareState


def should_continue_negotiation(state: MalwareState) -> str:
    """
    Conditional router to determine if agents need more iteration rounds.
    If consensus is reached OR iteration >= 2, we route to judge.
    """
    iteration = state.get("iteration_count", 0)
    consensus = state.get("is_consensus", False)

    if consensus or iteration >= 2:
        return "judge"

    return "negotiation"


def build_graph() -> CompiledStateGraph:
    """Builds and compiles the Multi-Agent Malware Analysis workflow."""
    builder = StateGraph(MalwareState)

    # 1. Uzman Ajaları grafiğe düğüm (node) olarak ekle
    builder.add_node("static_analyst", static_analyst_node)
    builder.add_node("dynamic_analyst", dynamic_analyst_node)
    builder.add_node("network_analyst", network_analyst_node)

    # 2. Müzakere motoru ve Hakem düğümleri
    builder.add_node("negotiation", negotiation_node)
    builder.add_node("judge", judge_node)

    # 3. İşletme Sırası (Flow): Veri toplama ajanları sırayla çalışıp raporlarını çıkarır
    builder.add_edge(START, "static_analyst")
    builder.add_edge("static_analyst", "dynamic_analyst")
    builder.add_edge("dynamic_analyst", "network_analyst")

    # 4. Raporlar hazır olduğunda tartışma başlar
    builder.add_edge("network_analyst", "negotiation")

    # 5. Iterasyon kontrolü (Döngü)
    builder.add_conditional_edges(
        source="negotiation",
        path=should_continue_negotiation,
        path_map={
            "negotiation": "negotiation",  # Bir tur daha tartış
            "judge": "judge",  # Mahkeme karar versin
        },
    )

    # 6. Bitiş
    builder.add_edge("judge", END)

    return builder.compile()
