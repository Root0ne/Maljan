from langchain_core.prompts import ChatPromptTemplate

from maljan.agents.base_agent import BaseAnalyst
from maljan.agents.registry import register_agent


@register_agent("static")
class StaticAnalyst(BaseAnalyst):
    """Specialized agent for evaluating decompiled code and strings."""

    def analyze(self, data: str) -> str:
        """Translates disassembler output into a focused malware analysis report."""
        self.logger.info("Executing static evaluation...")

        prompt = ChatPromptTemplate.from_messages(
            [
                (
                    "system",
                    "You are an expert Static Malware Analyst. Your goal is to identify "
                    "MITRE ATT&CK techniques such as T1027 (Obfuscated Files/Information) "
                    "and T1106 (Native API).",
                ),
                (
                    "human",
                    "Analyze the following Ghidra/Radare2 static output for obfuscation, "
                    "suspicious API imports, and hardcoded C2 patterns:\n{data}",
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
        """Revise static analysis based on dynamic/network findings and mediator feedback."""
        self.logger.info("Revising static analysis based on peer feedback...")

        prompt = ChatPromptTemplate.from_messages(
            [
                (
                    "system",
                    "You are an expert Static Malware Analyst participating in a collaborative "
                    "multi-agent malware analysis. The mediator has identified contradictions "
                    "between your report and other experts. Review the peer reports and mediator "
                    "feedback, then revise your analysis. If the Dynamic Analyst found persistence "
                    "mechanisms or the Network Analyst found C2 traffic that your static analysis "
                    "missed, look for corroborating evidence in the original data. "
                    "Focus on MITRE ATT&CK: T1027, T1106.",
                ),
                (
                    "human",
                    "YOUR ORIGINAL REPORT:\n{own_report}\n\n"
                    "DYNAMIC ANALYST REPORT:\n{dynamic_report}\n\n"
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
                "dynamic_report": peer_reports.get("dynamic", "N/A"),
                "network_report": peer_reports.get("network", "N/A"),
                "mediator_feedback": mediator_feedback,
                "data": original_data,
            }
        )
        return str(response.content)
