from langchain_core.prompts import ChatPromptTemplate

from maljan.agents.base_agent import BaseAnalyst


class NetworkAnalyst(BaseAnalyst):
    """Specialized agent for evaluating network connectivity logs (Zeek/PCAP)."""

    def analyze(self, data: str) -> str:
        """Translates network flows into a C2 connectivity profile."""
        self.logger.info("Executing network flow analysis...")

        prompt = ChatPromptTemplate.from_messages(
            [
                (
                    "system",
                    "You are an expert Network Analyst. Focus on MITRE ATT&CK "
                    "techniques such as T1071 (Application Layer Protocol) "
                    "and T1571 (Non-Standard Port).",
                ),
                (
                    "human",
                    "Analyze DNS queries, HTTPS SSL flows, and potential C2 beacons "
                    "in this Zeek/pcap network data:\n{data}",
                ),
            ]
        )

        response = (prompt | self.llm).invoke({"data": data})
        return str(response.content)
