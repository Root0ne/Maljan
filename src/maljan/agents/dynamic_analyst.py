from langchain_core.prompts import ChatPromptTemplate

from maljan.agents.base_agent import BaseAnalyst


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
