from maljan.graph.workflow import build_graph


def test_workflow_execution() -> None:
    """Verifies that the LangGraph state graph compiles and properly routes the mock nodes."""
    graph = build_graph()

    initial_state = {
        "file_hash": "sample_1",
        "file_name": "suspicious_payload.exe",
        "iteration_count": 0,
        "is_consensus": False,
        "discussion_history": [],
    }

    # Invoke the full state mechanism synchronously
    result = graph.invoke(initial_state)

    # Verify Layer 2: All Analyst logic was triggered and saved to state
    assert "obfuscation" in result["static_report"].lower()
    assert "registry" in result["dynamic_report"].lower()
    assert "https beaconing" in result["network_report"].lower()

    # Verify Layer 3: Negotiation loop triggered exactly 2 times
    assert result["iteration_count"] == 2

    # Verify Layer 4: Judge reached a decision
    assert result["final_decision"] == "Malware"
    assert "persistence" in result["judge_report"].lower()
