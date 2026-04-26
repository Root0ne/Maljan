"""Network Analyst agent — evaluates network flows (Zeek/PCAP/DNS logs).

Phase 1b: Overrides analyze_isr() and revise_isr() to extract structured
ClaimEvidence objects. Focuses on C2 beaconing patterns, DGA domains,
TLS certificate anomalies, and protocol tunneling.
"""

from __future__ import annotations

from langchain_core.prompts import ChatPromptTemplate

from maljan.agents.base_agent import BaseAnalyst
from maljan.agents.registry import register_agent
from maljan.agents.static_analyst import _parse_claim_blocks, _parse_disputes
from maljan.schemas.isr_models import AgentISR

_ISR_SYSTEM = (
    "You are an expert Network Security Analyst with deep knowledge of malware C2 communication. "
    "Analyze DNS queries, HTTP/HTTPS flows, SSL certificates, and PCAP captures for "
    "beaconing patterns, DGA domains, tunneling, and exfiltration channels. "
    "For EVERY claim, cite a concrete artifact: 'DNS query: abc.evil.com', "
    "'PCAP frame 42: src=10.0.0.5 dst=185.220.x.x:443', 'TLS SNI: suspicious.tld'. "
    "Focus on MITRE ATT&CK: T1071 (Application Layer Protocol), T1571 (Non-Standard Port), "
    "T1048 (Exfiltration), T1568 (Dynamic Resolution)."
)


@register_agent("network")
class NetworkAnalyst(BaseAnalyst):
    """Specialized agent for evaluating network connectivity logs (Zeek/PCAP)."""

    # ------------------------------------------------------------------
    # MCP Tool Interface
    # ------------------------------------------------------------------

    def _initialize_mcp_client(self) -> None:
        if getattr(self, "tools", None):
            return

        import asyncio
        import os
        import sys

        from mcp import StdioServerParameters

        from maljan.agents.mcp_client import MCPLangChainToolkit

        project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
        server_script = os.path.join(project_root, "network-mcp", "server.py")

        server_params = StdioServerParameters(
            command=sys.executable,
            args=[server_script],
            env=os.environ.copy(),
            cwd=os.path.join(project_root, "network-mcp"),
        )

        toolkit = MCPLangChainToolkit(server_params)

        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

        if loop.is_running():
            import nest_asyncio

            nest_asyncio.apply()
            loop.run_until_complete(toolkit.initialize())
        else:
            loop.run_until_complete(toolkit.initialize())

        self.toolkit = toolkit
        self.tools = toolkit.get_tools()
        self.logger.info("Initialized Network MCP toolkit with %d tools", len(self.tools))

    # ------------------------------------------------------------------
    # Text interface (backward compatible)
    # ------------------------------------------------------------------

    def analyze(self, data: str) -> str:
        """Translates network flows into a C2 connectivity profile."""
        self.logger.info("Executing network flow analysis...")
        self._initialize_mcp_client()

        target_info = (
            f"Target PCAP: {data}" if len(data.strip()) < 512 else f"Network output:\n{data}"
        )

        prompt_messages = [
            ("system", _ISR_SYSTEM),
            (
                "human",
                "Analyze DNS queries, HTTPS SSL flows, and potential C2 beacons "
                "in this Zeek/pcap network data:\n"
                f"{target_info}\n\n"
                "You may use tools to extract more information from the PCAP.",
            ),
        ]

        content = self.execute_tool_loop(prompt_messages)
        return str(content)

    def revise(
        self,
        original_data: str,
        own_report: str,
        peer_reports: dict[str, str],
        mediator_feedback: str,
    ) -> str:
        """Revise network analysis based on peer findings and mediator feedback."""
        self.logger.info("Revising network analysis based on peer feedback...")
        self._initialize_mcp_client()

        peer_section = (
            "\n\n".join(
                f"{name.upper()} ANALYST REPORT:\n{report}" for name, report in peer_reports.items()
            )
            or "No peer reports available."
        )

        prompt_messages = [
            (
                "system",
                "You are an expert Network Analyst participating in a collaborative "
                "multi-agent malware analysis. The mediator has identified contradictions "
                "between your report and other experts. Review the peer reports and mediator "
                "feedback, then revise your analysis. Correlate network traffic with any "
                "hardcoded C2 URLs or HTTP API calls raised by peers. "
                "Focus on MITRE ATT&CK: T1071, T1571.",
            ),
            (
                "human",
                "YOUR ORIGINAL REPORT:\n{own_report}\n\n"
                "PEER ANALYST REPORTS:\n{peer_section}\n\n"
                "MEDIATOR CONTRADICTIONS:\n{mediator_feedback}\n\n"
                "ORIGINAL RAW DATA:\n{data}\n\n"
                "Revise your analysis addressing the contradictions above. Use tools if necessary.",
            ),
        ]

        # Use invoke since revision might not need tools unless they want to re-query
        # but to be safe, we allow tool usage
        prompt = ChatPromptTemplate.from_messages(prompt_messages)
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
    # ISR interface (Phase 1b)
    # ------------------------------------------------------------------

    def analyze_isr(self, data: str) -> AgentISR:
        """Return a structured AgentISR with evidence-backed network claims."""
        self.logger.info("Executing network ISR analysis...")
        self._initialize_mcp_client()

        target_info = (
            f"Target PCAP: {data}" if len(data.strip()) < 512 else f"Network output:\n{data}"
        )

        prompt_messages = [
            ("system", _ISR_SYSTEM),
            (
                "human",
                "Analyze the network data and return a structured list of findings.\n"
                "You may use tools to gather more information (extract DNS, HTTP, summaries, etc.).\n"
                "For each finding state: the claim, the exact artifact reference "
                "(e.g. 'PCAP frame 10: dst=185.220.101.5:443', 'DNS query: rnd7x.evil.com'), "
                "your confidence (0.0-1.0), and the MITRE ATT&CK technique ID.\n\n"
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
            return self._text_to_isr(content, revision_round=0)

        return AgentISR(
            agent_id=self.name,
            domain="network",
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
        self.logger.info("Executing network ISR revision (round %d)...", revision_round)

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
                    "CLAIM: ...\nEVIDENCE: ...\nCONFIDENCE: 0.8\nTECHNIQUE: T1071\n---\n"
                    "DISPUTES:\n- Static analyst says no C2 strings but PCAP shows beaconing.\n",
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
            domain="network",
            claims=claims,
            dissent_items=dissent,
            revision_round=revision_round,
        )
        return content, isr
