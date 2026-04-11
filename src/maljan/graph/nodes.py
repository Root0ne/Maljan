from typing import Any

from maljan.agents.dynamic_analyst import DynamicAnalyst
from maljan.agents.judge_agent import JudgeAgent
from maljan.agents.network_analyst import NetworkAnalyst
from maljan.agents.static_analyst import StaticAnalyst
from maljan.core.config import settings
from maljan.integrations.data_loaders import DataLoader
from maljan.integrations.llm_clients import get_expert_llm, get_judge_llm
from maljan.schemas.agent_states import AgentArgument, MalwareState
from maljan.schemas.stix_models import Bundle


def _is_mock_mode() -> bool:
    return not bool(settings.openai_api_key)


def static_analyst_node(state: MalwareState) -> dict[str, Any]:
    """Analyzes decompiled code and strings using modular StaticAnalyst."""
    if _is_mock_mode():
        return {"static_report": "MOCK: No obfuscation detected."}

    loader = DataLoader()
    data = loader.load_static_data(state["file_hash"])

    analyst = StaticAnalyst(llm=get_expert_llm(), name="StaticAnalyst")
    report = analyst.analyze(data)

    return {"static_report": report}


def dynamic_analyst_node(state: MalwareState) -> dict[str, Any]:
    """Analyzes behavior logs using modular DynamicAnalyst."""
    if _is_mock_mode():
        return {"dynamic_report": "MOCK: Dropped file in AppData, set Run registry key."}

    loader = DataLoader()
    data = loader.load_dynamic_data(state["file_hash"])

    analyst = DynamicAnalyst(llm=get_expert_llm(), name="DynamicAnalyst")
    report = analyst.analyze(data)

    return {"dynamic_report": report}


def network_analyst_node(state: MalwareState) -> dict[str, Any]:
    """Analyzes network flows using modular NetworkAnalyst."""
    if _is_mock_mode():
        return {"network_report": "MOCK: Periodic HTTPS beaconing to malicious IP."}

    loader = DataLoader()
    data = loader.load_network_data(state["file_hash"])

    analyst = NetworkAnalyst(llm=get_expert_llm(), name="NetworkAnalyst")
    report = analyst.analyze(data)

    return {"network_report": report}


def negotiation_node(state: MalwareState) -> dict[str, Any]:
    """Manages mediation between reports using modular JudgeAgent."""
    iteration = state.get("iteration_count", 0)

    if _is_mock_mode():
        return {
            "iteration_count": iteration + 1,
            "is_consensus": False,
            "discussion_history": [
                AgentArgument(
                    agent_name="Network", finding="Found HTTPS beacon", confidence_score=0.9
                )
            ],
        }

    judge = JudgeAgent(llm=get_expert_llm(), name="Mediator")
    argument = judge.mediate(
        static=state.get("static_report") or "",
        dynamic=state.get("dynamic_report") or "",
        network=state.get("network_report") or "",
        history=state.get("discussion_history") or [],
    )

    # In a production system, JudgeAgent could detect 'consensus' based on findings
    return {
        "iteration_count": iteration + 1,
        "is_consensus": False,
        "discussion_history": [argument],
    }


def judge_node(state: MalwareState) -> dict[str, Any]:
    """Final decision maker returning Structured STIX 2.1 Output using modular JudgeAgent."""
    if _is_mock_mode():
        return {
            "final_decision": "Malware",
            "judge_report": "MOCK: Evaluated persistence.",
            "stix_output": {},
        }

    judge = JudgeAgent(llm=get_judge_llm(), name="ChiefJudge")

    reports: dict[str, str] = {
        "static": state.get("static_report") or "",
        "dynamic": state.get("dynamic_report") or "",
        "network": state.get("network_report") or "",
    }

    bundle = judge.give_verdict(reports=reports, history=state.get("discussion_history") or [])

    stix_output = {}
    if isinstance(bundle, Bundle):
        stix_output = bundle.model_dump()

    return {
        "final_decision": "Malware",
        "judge_report": "Analyzed negotiation history and expert reports.",
        "stix_output": stix_output,
    }
