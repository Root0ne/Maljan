from langchain_core.prompts import ChatPromptTemplate

from maljan.agents.base_agent import BaseAnalyst
from maljan.pipeline.state import AgentArgument
from maljan.schemas.stix_models import Bundle


class JudgeAgent(BaseAnalyst):
    """The chief controller responsible for mediation, consensus detection, and final verdict."""

    # Threshold: if average confidence across agents exceeds this, declare consensus
    CONSENSUS_THRESHOLD = 0.85

    def analyze(self, data: str) -> str:
        """Generic analysis implementation for Judge."""
        self.logger.info("Executing generic judge analysis...")
        return f"Judge analysis of data: {data[:50]}..."

    def revise(
        self,
        original_data: str,
        own_report: str,
        peer_reports: dict[str, str],
        mediator_feedback: str,
    ) -> str:
        """Judge does not revise - delegates to mediate/verdict instead."""
        return own_report

    def mediate(
        self, static: str, dynamic: str, network: str, history: list[AgentArgument]
    ) -> tuple[AgentArgument, bool]:
        """Finds contradictions between reports and determines if consensus is reached.

        Returns:
            A tuple of (AgentArgument with findings, bool indicating consensus).
        """
        self.logger.info("Mediating expert reports for contradictions...")

        prompt = ChatPromptTemplate.from_messages(
            [
                (
                    "system",
                    "You are the Lead Cyber Security Mediator. Your task is to compare "
                    "Static, Dynamic, and Network reports. Look for contradictions. "
                    "Example: Static says 'no network code', "
                    "but Network says 'HTTPS traffic found'. "
                    "Challenge the agents to resolve these gaps.\n\n"
                    "At the end of your analysis, rate your confidence that the agents "
                    "are in agreement on a scale from 0.0 to 1.0. If there are no "
                    "remaining contradictions, give a high score (0.9+). "
                    "End your response with exactly: CONFIDENCE: <score>",
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

        content = str(response.content)
        confidence = self._extract_confidence(content)
        is_consensus = confidence >= self.CONSENSUS_THRESHOLD

        if is_consensus:
            self.logger.info(f"Consensus reached with confidence {confidence:.2f}")
        else:
            self.logger.info(f"No consensus yet (confidence: {confidence:.2f})")

        argument = AgentArgument(
            agent_name="Mediator", finding=content, confidence_score=confidence
        )

        return argument, is_consensus

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
        self.logger.warning("LLM did not return a valid Bundle, falling back to empty.")
        return Bundle(objects=[])

    def _extract_confidence(self, text: str) -> float:
        """Extracts the CONFIDENCE: <score> value from the mediator's response."""
        try:
            for line in reversed(text.strip().splitlines()):
                if "CONFIDENCE:" in line.upper():
                    score_str = line.upper().split("CONFIDENCE:")[-1].strip()
                    return max(0.0, min(1.0, float(score_str)))
        except (ValueError, IndexError):
            self.logger.warning("Could not extract confidence score, defaulting to 0.5")
        return 0.5
