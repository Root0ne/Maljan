"""Static Analyst agent — evaluates decompiled code and binary strings.

Phase 1b: Overrides analyze_isr() and revise_isr() to extract structured
ClaimEvidence objects via a structured-output prompt. Each claim cites a
concrete artifact reference (function name, string offset, API call).
"""

from __future__ import annotations

import re

from langchain_core.prompts import ChatPromptTemplate

from maljan.agents.base_agent import BaseAnalyst
from maljan.agents.registry import register_agent
from maljan.schemas.isr_models import AgentISR, ClaimEvidence

# Structured ISR system prompt shared by analyze and revise
_ISR_SYSTEM = (
    "You are an expert Static Malware Analyst with 15 years of reverse engineering experience. "
    "Analyze binary files (e.g. PE, ELF) utilizing Ghidra through your available tools. "
    "You can decompile functions, find cross-references, extract strings, and more. "
    "For EVERY claim you make, you MUST cite a concrete artifact: a function name, "
    "string offset (.data+0xNN), API import, or hex pattern. "
    "Focus on MITRE ATT&CK: T1027 (Obfuscation), T1106 (Native API), "
    "T1055 (Process Injection), T1140 (Deobfuscation).\n\n"
    "=== TOOL USAGE WORKFLOW ===\n"
    "Follow this reverse engineering sequence:\n"
    "0. Call `list_instances` to discover running Ghidra instances. Then call\n"
    "   `connect_instance(project=<name>)` to attach to one. This step is CRITICAL:\n"
    "   without it only management tools are available, NOT analysis tools.\n"
    "   After connecting, call `load_tool_group(group='all')` to ensure all 225\n"
    "   analysis tools (decompile, xrefs, strings, etc.) are loaded.\n"
    "1. Call `import_file(file_path=<path>)` to load the binary into Ghidra.\n"
    "2. Call `list_functions` to get an overview of all functions.\n"
    "3. Call `list_imports` to identify suspicious API imports (VirtualAlloc, CreateRemoteThread, etc.).\n"
    "4. Call `list_exports` to check exported symbols.\n"
    "5. Call `list_strings` to find hardcoded C2 URLs, registry paths, or encoded data.\n"
    "6. For suspicious functions: call `decompile_function(name=<func>)` to read the C pseudocode.\n"
    "7. Call `get_xrefs_to(address=<addr>)` to trace how a suspicious API is called.\n"
    "8. Call `list_segments` or `list_namespaces` if you need memory layout context.\n\n"
    "IMPORTANT:\n"
    "- Step 0 (connect + load_tool_group) MUST happen before any analysis tool call.\n"
    "- Focus decompilation on 5-10 most suspicious functions, not every function.\n"
    "- Large binaries may have 1000+ functions. Prioritize entry point, main, "
    "and functions referencing crypto/network/process APIs.\n"
    "- Avoid calling `debugger_*` tools unless specifically doing dynamic debugging.\n"
    "- Summarize assembly patterns instead of dumping raw hex."
)


@register_agent("static")
class StaticAnalyst(BaseAnalyst):
    """Specialized agent for evaluating decompiled code and strings via Ghidra MCP."""

    # ------------------------------------------------------------------
    # MCP Tool Interface
    # ------------------------------------------------------------------

    def _initialize_mcp_client(self) -> None:
        if getattr(self, "tools", None):
            return

        import asyncio
        import os

        from mcp import StdioServerParameters

        from maljan.agents.mcp_client import MCPLangChainToolkit
        from maljan.core.config import settings

        if not settings.mcp.ghidra.enabled:
            self.logger.info("Ghidra MCP is disabled in config.")
            return

        command = settings.mcp.ghidra.command
        args = settings.mcp.ghidra.args

        env = os.environ.copy()
        env["PYTHONIOENCODING"] = "utf-8"
        if settings.mcp.ghidra.env:
            env.update(settings.mcp.ghidra.env)

        server_params = StdioServerParameters(command=command, args=args, env=env)

        # Build output guardrail: use FunctionSummarizer if available,
        # otherwise MCPLangChainToolkit falls back to simple truncation.
        output_guardrail = None
        if settings.preprocessing.use_function_summarizer:
            from maljan.core.container import ServiceContainer

            container = ServiceContainer(config=settings)
            summarizer = container.get_function_summarizer()
            if summarizer is not None:
                output_guardrail = summarizer.summarize_chunk
                self.logger.info("Ghidra output guardrail: FunctionSummarizer enabled.")

        max_chars = settings.preprocessing.max_tool_output_chars

        toolkit = MCPLangChainToolkit(
            server_params,
            output_guardrail=output_guardrail,
            max_output_chars=max_chars,
        )

        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop is not None and loop.is_running():
            import nest_asyncio

            nest_asyncio.apply()
            loop.run_until_complete(toolkit.initialize())
        else:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(toolkit.initialize())

        self.toolkit = toolkit
        # Filter out debugger_* tools — not needed for static analysis.
        # Reduces tool count from ~29 to ~7 (management + import tools only),
        # which prevents large tool schema from causing LLM timeouts.
        all_tools = toolkit.get_tools()
        self.tools = [t for t in all_tools if not t.name.startswith("debugger_")]
        self.logger.info(
            "Initialized Ghidra MCP tools: %d/%d (debugger_* excluded): %s",
            len(self.tools),
            len(all_tools),
            [t.name for t in self.tools],
        )

    # ------------------------------------------------------------------
    # Text interface (backward compatible)
    # ------------------------------------------------------------------

    def analyze(self, data: str) -> str:
        """Translates binary file paths or raw disassembly into a focused malware analysis report."""
        self.logger.info("Executing static evaluation...")

        self._initialize_mcp_client()

        # Treat `data` as a file path or hash if it's short, else raw disassembly
        target_info = (
            f"Target File: {data}" if len(data.strip()) < 512 else f"Static output:\n{data}"
        )

        prompt_messages = [
            ("system", _ISR_SYSTEM),
            (
                "human",
                "Analyze the following target for obfuscation, "
                "suspicious API imports, and hardcoded C2 patterns. "
                "Use your tools to deeply analyze the binary if it's a file path.\n"
                f"{target_info}",
            ),
        ]

        return self.execute_tool_loop(prompt_messages)

    def revise(
        self,
        original_data: str,
        own_report: str,
        peer_reports: dict[str, str],
        mediator_feedback: str,
    ) -> str:
        """Revise static analysis based on peer findings and mediator feedback."""
        self.logger.info("Revising static analysis based on peer feedback...")

        peer_section = (
            "\n\n".join(
                f"{name.upper()} ANALYST REPORT:\n{report}" for name, report in peer_reports.items()
            )
            or "No peer reports available."
        )

        prompt = ChatPromptTemplate.from_messages(
            [
                (
                    "system",
                    "You are an expert Static Malware Analyst participating in a collaborative "
                    "multi-agent malware analysis. The mediator has identified contradictions "
                    "between your report and other experts. Review the peer reports and mediator "
                    "feedback, then revise your analysis. Look for corroborating evidence "
                    "in the original data for any findings raised by peers. "
                    "Focus on MITRE ATT&CK: T1027, T1106.",
                ),
                (
                    "human",
                    "YOUR ORIGINAL REPORT:\n{own_report}\n\n"
                    "PEER ANALYST REPORTS:\n{peer_section}\n\n"
                    "MEDIATOR CONTRADICTIONS:\n{mediator_feedback}\n\n"
                    "ORIGINAL RAW DATA:\n{data}\n\n"
                    "Revise your analysis addressing the contradictions above.",
                ),
            ]
        )

        response = (prompt | self.llm).invoke(
            {
                "own_report": own_report,
                "peer_section": peer_section,
                "mediator_feedback": mediator_feedback,
                "data": original_data,
            }
        )
        return str(response.content)

    # ------------------------------------------------------------------
    # ISR interface (Phase 1b — structured claim extraction)
    # ------------------------------------------------------------------

    def analyze_isr(self, data: str) -> AgentISR:
        """Return a structured AgentISR with evidence-backed claims."""
        self.logger.info("Executing static ISR analysis...")

        self._initialize_mcp_client()

        target_info = (
            f"Target File: {data}" if len(data.strip()) < 512 else f"Static output:\n{data}"
        )

        prompt_messages = [
            ("system", _ISR_SYSTEM),
            (
                "human",
                "Analyze the target binary and return a structured list of findings.\n"
                "You may use tools to gather more information (decompile, xrefs, etc.).\n"
                "For each finding state: the claim, the exact artifact "
                "reference (e.g. 'API import: VirtualAllocEx', 'string at .data+0x20: /bin/sh'), "
                "your confidence (0.0-1.0), and the MITRE ATT&CK technique ID if applicable.\n\n"
                "Format each finding as:\n"
                "CLAIM: <claim text>\n"
                "EVIDENCE: <artifact reference>\n"
                "CONFIDENCE: <float>\n"
                "TECHNIQUE: <T-ID or NONE>\n"
                "---\n\n"
                f"{target_info}",
            ),
        ]

        content = self.execute_tool_loop(prompt_messages)
        claims = _parse_claim_blocks(content)

        if not claims:
            # Fallback to text extraction if parsing fails
            return self._text_to_isr(content, revision_round=0)

        return AgentISR(
            agent_id=self.name,
            domain="static",
            claims=claims,
            dissent_items=[],
            revision_round=0,
        )

    def revise_isr(
        self,
        original_data: str,
        own_report: str,
        peer_reports: dict[str, str],
        mediator_feedback: str,
        revision_round: int = 1,
    ) -> tuple[str, AgentISR]:
        """Return (revised_text, AgentISR) with dissent_items populated."""
        self.logger.info("Executing static ISR revision (round %d)...", revision_round)

        peer_isr_summaries = (
            "\n\n".join(
                f"{name.upper()} REPORT:\n{report}" for name, report in peer_reports.items()
            )
            or "No peer reports available."
        )

        prompt = ChatPromptTemplate.from_messages(
            [
                (
                    "system",
                    _ISR_SYSTEM + "\n\n"
                    "You are in a negotiation round. You MUST:\n"
                    "1. List any peer claims you still DISPUTE in a DISPUTES section.\n"
                    "2. Revise your own claims based on new evidence.\n"
                    "3. If you have NO disputes, write 'DISPUTES: NONE' to signal convergence.",
                ),
                (
                    "human",
                    "YOUR ORIGINAL REPORT:\n{own_report}\n\n"
                    "PEER REPORTS:\n{peer_section}\n\n"
                    "MEDIATOR FEEDBACK:\n{mediator_feedback}\n\n"
                    "RAW DATA:\n{data}\n\n"
                    "Format your response as structured claims (CLAIM/EVIDENCE/CONFIDENCE/TECHNIQUE)\n"
                    "followed by a DISPUTES section listing peer claims you reject.\n"
                    "Example:\n"
                    "CLAIM: ...\nEVIDENCE: ...\nCONFIDENCE: 0.8\nTECHNIQUE: T1055\n---\n"
                    "DISPUTES:\n- Dynamic analyst claims no injection but PCAP shows it.\n",
                ),
            ]
        )

        response = (prompt | self.llm).invoke(
            {
                "own_report": own_report,
                "peer_section": peer_isr_summaries,
                "mediator_feedback": mediator_feedback,
                "data": original_data,
            }
        )
        content = str(response.content)

        claims = _parse_claim_blocks(content)
        dissent = _parse_disputes(content)

        if not claims:
            return content, self._text_to_isr(content, revision_round=revision_round)

        isr = AgentISR(
            agent_id=self.name,
            domain="static",
            claims=claims,
            dissent_items=dissent,
            revision_round=revision_round,
        )
        return content, isr


# ------------------------------------------------------------------
# Shared parsing helpers (module-level, reused by other analysts)
# ------------------------------------------------------------------


def _parse_claim_blocks(text: str) -> list[ClaimEvidence]:
    """Parse structured CLAIM/EVIDENCE/CONFIDENCE/TECHNIQUE blocks from LLM output."""
    claims: list[ClaimEvidence] = []
    # Split on the --- separator
    blocks = re.split(r"-{3,}", text)
    for block in blocks:
        block = block.strip()
        if not block or "CLAIM:" not in block:
            continue
        claim_match = re.search(r"CLAIM:\s*(.+?)(?=\nEVIDENCE:|\Z)", block, re.DOTALL)
        evidence_match = re.search(r"EVIDENCE:\s*(.+?)(?=\nCONFIDENCE:|\Z)", block, re.DOTALL)
        confidence_match = re.search(r"CONFIDENCE:\s*([\d.]+)", block)
        technique_match = re.search(r"TECHNIQUE:\s*(T\d{4}(?:\.\d{3})?|NONE)", block)

        if not (claim_match and evidence_match and confidence_match):
            continue

        try:
            confidence = max(0.0, min(1.0, float(confidence_match.group(1))))
        except ValueError:
            confidence = 0.5

        technique_raw = technique_match.group(1) if technique_match else "NONE"
        technique_id = None if technique_raw == "NONE" else technique_raw

        claims.append(
            ClaimEvidence(
                claim=claim_match.group(1).strip()[:300],
                evidence_ref=evidence_match.group(1).strip()[:200],
                confidence=confidence,
                technique_id=technique_id,
            )
        )
    return claims


def _parse_disputes(text: str) -> list[str]:
    """Extract dispute items from the DISPUTES section of a revision response."""
    disputes: list[str] = []
    disputes_match = re.search(r"DISPUTES:(.*?)(?:\Z)", text, re.DOTALL | re.IGNORECASE)
    if not disputes_match:
        return disputes
    disputes_section = disputes_match.group(1).strip()
    if disputes_section.upper() in ("NONE", "NONE.", ""):
        return disputes
    for line in disputes_section.splitlines():
        line = line.strip().lstrip("-•* ")
        if line:
            disputes.append(line)
    return disputes
