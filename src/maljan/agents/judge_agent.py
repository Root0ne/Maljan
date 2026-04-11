from langchain_core.prompts import ChatPromptTemplate

from maljan.agents.base_agent import BaseAnalyst
from maljan.schemas.agent_states import AgentArgument
from maljan.schemas.stix_models import Bundle


class JudgeAgent(BaseAnalyst):
    """The chief controller responsible for mediation and final verdict."""

    def analyze(self, data: str) -> str:
        """Generic analysis implementation for Judge."""
        self.logger.info("Executing generic judge analysis...")
        return f"Judge analysis of data: {data[:50]}..."

    def mediate(
        self, static: str, dynamic: str, network: str, history: list[AgentArgument]
    ) -> AgentArgument:
        """Finds contradictions between reports and submits a new argument to the state."""
        self.logger.info("Mediating expert reports for contradictions...")

        prompt = ChatPromptTemplate.from_messages(
            [
                (
                    "system",
                    "You are the Lead Cyber Security Mediator. Your task is to compare "
                    "Static, Dynamic, and Network reports. Look for contradictions. "
                    "Example: Static says 'no network code', "
                    "but Network says 'HTTPS traffic found'. "
                    "Challenge the agents to resolve these gaps.",
                ),
                (
                    "human",
                    "Static Analysis: {static}\n\n"
                    "Dynamic Analysis: {dynamic}\n\n"
                    "Network Analysis: {network}\n\n"
                    "Previous Discussion: {history}",
                ),
            ]
        )

        response = (prompt | self.llm).invoke(
            {"static": static, "dynamic": dynamic, "network": network, "history": str(history)}
        )

        return AgentArgument(
            agent_name="Mediator", finding=str(response.content), confidence_score=0.8
        )

    def give_verdict(self, reports: dict[str, str], history: list[AgentArgument]) -> Bundle:
        """Final judge decision returning a structured STIX 2.1 Bundle with MITRE mapping."""
        self.logger.info("Formulating final malware verdict with MITRE ATT&CK mapping...")

        prompt = ChatPromptTemplate.from_messages(
            [
                (
                    "system",
                    "You are the Chief Malware Judge. Based on expert reports and "
                    "discussion history, provide a final verdict. "
                    "You MUST map findings to MITRE ATT&CK techniques in the STIX Bundle "
                    "using AttackPattern objects.",
                ),
                (
                    "human",
                    "Expert Reports: {reports}\n\n"
                    "Negotiation History: {history}\n\n"
                    "Generate a comprehensive STIX 2.1 Bundle.",
                ),
            ]
        )

        # Structured output binding for STIX
        llm_stix = self.llm.with_structured_output(Bundle)
        result = (prompt | llm_stix).invoke({"reports": str(reports), "history": str(history)})

        if isinstance(result, Bundle):
            return result

        # Fallback to empty bundle if LLM fails
        return Bundle(objects=[])
