"""Generic node factories for the LangGraph pipeline.

Instead of one hardcoded function per agent, we use a factory that
creates a node function for ANY registered agent. Adding a new agent
to the registry automatically makes it available as a graph node.
"""

from __future__ import annotations

from typing import Any

from maljan.agents.judge_agent import JudgeAgent
from maljan.core.container import ServiceContainer
from maljan.core.exceptions import AnalystError, LLMError
from maljan.core.logger import logger
from maljan.pipeline.state import AgentArgument, AnalysisState
from maljan.schemas.stix_models import Bundle


def make_analyst_node(
    agent_name: str,
    container: ServiceContainer,
) -> Any:
    """Factory: creates a LangGraph node function for the given agent.

    The returned function reads data via the container's loader,
    runs the agent's safe_analyze(), and writes to state["reports"][agent_name].
    """

    def node_fn(state: AnalysisState) -> dict[str, Any]:
        if container.is_mock:
            return {"reports": {agent_name: f"MOCK: {agent_name} analysis complete."}}

        try:
            data = container.loader.load(state["file_hash"], agent_name)
            agent = container.agent_registry.create(agent_name, container.get_expert_llm())
            report = agent.safe_analyze(data)
            return {"reports": {agent_name: report}}
        except (AnalystError, LLMError) as e:
            logger.error(f"{agent_name} analysis failed: {e}")
            return {"reports": {agent_name: f"[ERROR] {agent_name} analysis failed: {e}"}}

    node_fn.__name__ = f"{agent_name}_analyst_node"
    node_fn.__doc__ = f"Auto-generated analysis node for '{agent_name}' agent."
    return node_fn


def make_negotiation_node(container: ServiceContainer) -> Any:
    """Factory: creates the mediator negotiation node."""

    def node_fn(state: AnalysisState) -> dict[str, Any]:
        iteration = state.get("iteration_count", 0)
        agent_names = container.agent_registry.list_agents()

        # Use revised reports if available, otherwise originals
        revised = state.get("revised_reports") or {}
        original = state.get("reports") or {}
        active_reports = {
            name: revised.get(name) or original.get(name, "") for name in agent_names
        }

        if container.is_mock:
            is_consensus = iteration >= 1
            return {
                "iteration_count": iteration + 1,
                "is_consensus": is_consensus,
                "discussion_history": [
                    AgentArgument(
                        agent_name="Mediator",
                        finding=(
                            "MOCK: All experts agree. CONFIDENCE: 0.95"
                            if is_consensus
                            else "MOCK: Contradictions found. CONFIDENCE: 0.4"
                        ),
                        confidence_score=0.95 if is_consensus else 0.4,
                    )
                ],
            }

        try:
            judge = JudgeAgent(llm=container.get_expert_llm(), name="Mediator")
            argument, is_consensus = judge.mediate(
                static=active_reports.get("static", ""),
                dynamic=active_reports.get("dynamic", ""),
                network=active_reports.get("network", ""),
                history=state.get("discussion_history") or [],
            )
            return {
                "iteration_count": iteration + 1,
                "is_consensus": is_consensus,
                "discussion_history": [argument],
            }
        except (AnalystError, LLMError) as e:
            logger.error(f"Negotiation failed: {e}")
            return {
                "iteration_count": iteration + 1,
                "is_consensus": False,
                "discussion_history": [
                    AgentArgument(
                        agent_name="Mediator",
                        finding=f"[ERROR] Mediation failed: {e}",
                        confidence_score=0.0,
                    )
                ],
            }

    node_fn.__name__ = "negotiation_node"
    return node_fn


def make_revision_node(container: ServiceContainer) -> Any:
    """Factory: creates the revision node where all agents revise their reports."""

    def node_fn(state: AnalysisState) -> dict[str, Any]:
        agent_names = container.agent_registry.list_agents()

        # Get latest mediator feedback
        history = state.get("discussion_history") or []
        mediator_feedback = ""
        for arg in reversed(history):
            if arg.agent_name == "Mediator":
                mediator_feedback = arg.finding
                break

        original_reports = state.get("reports") or {}

        if container.is_mock:
            return {
                "revised_reports": {
                    name: f"MOCK REVISED: {name} analysis updated."
                    for name in agent_names
                }
            }

        revised: dict[str, str] = {}

        for name in agent_names:
            try:
                data = container.loader.load(state["file_hash"], name)
                agent = container.agent_registry.create(
                    name, container.get_expert_llm()
                )
                own_report = original_reports.get(name, "")
                peer_reports = {
                    k: v for k, v in original_reports.items() if k != name
                }
                revised[name] = agent.safe_revise(
                    original_data=data,
                    own_report=own_report,
                    peer_reports=peer_reports,
                    mediator_feedback=mediator_feedback,
                )
            except (AnalystError, LLMError) as e:
                logger.error(f"{name} revision failed: {e}")
                revised[name] = original_reports.get(name, "")

        return {"revised_reports": revised}

    node_fn.__name__ = "revision_node"
    return node_fn


def make_judge_node(container: ServiceContainer) -> Any:
    """Factory: creates the final judge verdict node."""

    def node_fn(state: AnalysisState) -> dict[str, Any]:
        if container.is_mock:
            return {
                "final_decision": "Malware",
                "judge_report": "MOCK: Evaluated all indicators.",
                "stix_output": {},
            }

        try:
            judge = JudgeAgent(llm=container.get_judge_llm(), name="ChiefJudge")

            revised = state.get("revised_reports") or {}
            original = state.get("reports") or {}
            reports = {
                name: revised.get(name) or original.get(name, "")
                for name in container.agent_registry.list_agents()
            }

            bundle = judge.give_verdict(
                reports=reports,
                history=state.get("discussion_history") or [],
            )

            stix_output = {}
            if isinstance(bundle, Bundle):
                stix_output = bundle.model_dump()

            decision = "Suspicious"
            for obj in bundle.objects:
                if hasattr(obj, "type") and obj.type == "malware":
                    decision = "Malware"
                    break

            return {
                "final_decision": decision,
                "judge_report": "Analyzed negotiation history and expert reports.",
                "stix_output": stix_output,
            }
        except (AnalystError, LLMError) as e:
            logger.error(f"Judge verdict failed: {e}")
            return {
                "final_decision": "Suspicious",
                "judge_report": f"[ERROR] Judge failed: {e}",
                "stix_output": {},
            }

    node_fn.__name__ = "judge_node"
    return node_fn
