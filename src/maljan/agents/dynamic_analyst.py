from langchain_core.prompts import ChatPromptTemplate

from maljan.agents.base_agent import BaseAnalyst
from maljan.agents.registry import register_agent


@register_agent("dynamic")
class DynamicAnalyst(BaseAnalyst):
    """Specialized agent for evaluating Sandbox behavioral logs."""

    def analyze(self, data: str) -> str:
        """Translates sandbox JSON logs into a behavioral malware profile."""
        self.logger.info("Executing dynamic behavior analysis...")

        prompt = ChatPromptTemplate.from_messages(
            [
                (
                    "system",
                    "You are an expert Dynamic Analyst. Focus on MITRE ATT&CK "
                    "techniques such as T1547 (Boot or Logon Autostart Execution) "
                    "and T1055 (Process Injection).",
                ),
                (
                    "human",
                    "Analyze registry persistence, process injection, and file/folder drops "
                    "in this sandbox behavior data:\n{data}",
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
        """Revise dynamic analysis based on static/network findings and mediator feedback."""
        self.logger.info("Revising dynamic analysis based on peer feedback...")

        prompt = ChatPromptTemplate.from_messages(
            [
                (
                    "system",
                    "You are an expert Dynamic Analyst participating in a collaborative "
                    "multi-agent malware analysis. The mediator has identified contradictions "
                    "between your report and other experts. Review the peer reports and mediator "
                    "feedback, then revise your analysis. If the Static Analyst found suspicious "
                    "API imports or the Network Analyst found C2 beacons that correlate with "
                    "behaviors in the sandbox, update your findings accordingly. "
                    "Focus on MITRE ATT&CK: T1547, T1055.",
                ),
                (
                    "human",
                    "YOUR ORIGINAL REPORT:\n{own_report}\n\n"
                    "STATIC ANALYST REPORT:\n{static_report}\n\n"
                    "NETWORK ANALYST REPORT:\n{network_report}\n\n"
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
                "network_report": peer_reports.get("network", "N/A"),
                "mediator_feedback": mediator_feedback,
                "data": original_data,
            }
        )
        return str(response.content)
