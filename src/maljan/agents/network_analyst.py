from langchain_core.prompts import ChatPromptTemplate

from maljan.agents.base_agent import BaseAnalyst
from maljan.agents.registry import register_agent


@register_agent("network")
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

    def revise(
        self,
        original_data: str,
        own_report: str,
        peer_reports: dict[str, str],
        mediator_feedback: str,
    ) -> str:
        """Revise network analysis based on static/dynamic findings and mediator feedback."""
        self.logger.info("Revising network analysis based on peer feedback...")

        prompt = ChatPromptTemplate.from_messages(
            [
                (
                    "system",
                    "You are an expert Network Analyst participating in a collaborative "
                    "multi-agent malware analysis. The mediator has identified contradictions "
                    "between your report and other experts. Review the peer reports and mediator "
                    "feedback, then revise your analysis. If the Static Analyst found hardcoded "
                    "C2 URLs or the Dynamic Analyst found HTTP API calls, correlate these with "
                    "your network traffic findings. "
                    "Focus on MITRE ATT&CK: T1071, T1571.",
                ),
                (
                    "human",
                    "YOUR ORIGINAL REPORT:\n{own_report}\n\n"
                    "STATIC ANALYST REPORT:\n{static_report}\n\n"
                    "DYNAMIC ANALYST REPORT:\n{dynamic_report}\n\n"
                    "MEDIATOR CONTRADICTIONS:\n{mediator_feedback}\n\n"
                    "ORIGINAL RAW DATA:\n{data}\n\n"
                    "Revise your analysis addressing the contradictions above.",
                ),
            ]
        )

        response = (prompt | self.llm).invoke(
            {
                "own_report": own_report,
                "static_report": peer_reports.get("static", "N/A"),
                "dynamic_report": peer_reports.get("dynamic", "N/A"),
                "mediator_feedback": mediator_feedback,
                "data": original_data,
            }
        )
        return str(response.content)
