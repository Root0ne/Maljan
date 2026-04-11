from langchain_core.prompts import ChatPromptTemplate

from maljan.agents.base_agent import BaseAnalyst


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
