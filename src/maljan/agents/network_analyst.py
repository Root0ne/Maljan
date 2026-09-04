"""Network Analyst agent — evaluates network flows (Zeek/PCAP/DNS logs).

Phase 1b: Overrides analyze_isr() and revise_isr() to extract structured
ClaimEvidence objects. Focuses on C2 beaconing patterns, DGA domains,
TLS certificate anomalies, and protocol tunneling.

Data Flow:
  - Fixture mode: Receives pre-parsed Zeek JSON text from NetworkParser.
    Analysis is LLM-only (text-based reasoning on parsed tables).
  - Sandbox mode: Receives PCAP file path from the CAPEv2 sandbox.
    Analysis uses Network MCP tools (read_pcap_summary, extract_dns,
    extract_http) for deep traffic inspection, falling back to text
    analysis if MCP initialization fails.

PCAP detection heuristic:
  If the input data looks like a file path ending in .pcap/.pcapng,
  the agent treats it as a PCAP reference and uses MCP tools.
  Otherwise, it falls back to LLM-only text analysis.
"""

from __future__ import annotations

import os
import re

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

# Regex to detect PCAP file paths in the input data.
# Captures both bare paths and quoted paths (single/double).
_PCAP_PATH_RE = re.compile(
    r"""
    (?:["']?)            # optional opening quote
    (?P<path>[\w/\\:.-]+\.pcapn?g?)
    (?:["']?)            # optional closing quote
    (?=$|[\s,;)"'])     # boundary
    """,
    re.IGNORECASE | re.VERBOSE,
)


def _detect_pcap_path(data: str) -> str | None:
    """Extract a PCAP file path from the input data if present."""
    for match in _PCAP_PATH_RE.finditer(data):
        candidate = match.group("path")
        if any(sep in candidate for sep in (os.sep, "/", "\\", ":")):
            return candidate
    return None


@register_agent("network")
class NetworkAnalyst(BaseAnalyst):
    """Specialized agent for evaluating network connectivity logs (Zeek/PCAP)."""

    # ------------------------------------------------------------------
    # MCP Tool Interface
    # ------------------------------------------------------------------

    def _initialize_mcp_client(self) -> None:
        """Attach every tool server bound to the ``network`` role.

        With default settings that is exactly ``mcp.servers["network"]`` — the
        same ``network-mcp`` sidecar, the same command, cwd and environment
        this method used to spell out inline — so the tool names are
        unchanged, and ``tests/servers/test_builtin_tool_sets.py`` says so.
        An operator who adds a second network server gets both.
        """
        if getattr(self, "tools", None):
            return
        registry = self._server_registry()
        if registry is None:
            return
        tools, reasons = registry.tools_for("network", self._job_key())
        self.tools = tools
        self.degradation_reasons = reasons
        self.logger.info("Network tool servers: %d tools attached.", len(self.tools))

    # ``_try_initialize_mcp`` used to live here. It now lives on ``BaseAnalyst``
    # unchanged in behaviour and name, because the dynamic analyst needed the
    # same graceful degradation and had been hard-failing every run without it.

    # ------------------------------------------------------------------
    # Text interface (backward compatible)
    # ------------------------------------------------------------------

    def analyze(self, data: str) -> str:
        """Translates network flows into a C2 connectivity profile."""
        self.logger.info("Executing network flow analysis...")

        pcap_path = _detect_pcap_path(data)

        if pcap_path:
            # PCAP mode: use MCP tools for deep analysis
            self.logger.info("PCAP path detected: %s — using MCP tools.", pcap_path)
            mcp_ready = self._try_initialize_mcp()

            if mcp_ready:
                prompt_messages = [
                    ("system", _ISR_SYSTEM),
                    (
                        "human",
                        "A PCAP capture file is available for analysis.\n\n"
                        f"PCAP file path: {pcap_path}\n\n"
                        "Use the available tools to:\n"
                        "1. read_pcap_summary — get packet overview\n"
                        "2. extract_dns — extract all DNS queries\n"
                        "3. extract_http — extract HTTP request headers\n\n"
                        "Then analyze the results for C2 beaconing, DGA domains, "
                        "data exfiltration, and protocol tunneling.",
                    ),
                ]
                content = self.execute_tool_loop(prompt_messages)
                return str(content)
            else:
                self.logger.warning("MCP unavailable, falling back to text analysis of PCAP ref.")

        # Text mode: LLM-only analysis on pre-parsed data
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
                "Identify beaconing patterns, suspicious domains, and exfiltration channels.",
            ),
        ]

        # Try MCP for text mode too (agent might extract useful patterns)
        mcp_ready = self._try_initialize_mcp()
        if mcp_ready:
            content = self.execute_tool_loop(prompt_messages)
        else:
            from langchain_core.prompts import ChatPromptTemplate as CPT

            prompt = CPT.from_messages(prompt_messages)
            response = (prompt | self.llm).invoke({})
            content = str(response.content)

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
                "Revise your analysis addressing the contradictions above.",
            ),
        ]

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

        pcap_path = _detect_pcap_path(data)

        if pcap_path:
            self.logger.info("PCAP path detected for ISR: %s", pcap_path)
            mcp_ready = self._try_initialize_mcp()

            if mcp_ready:
                # The structured CAPE flows (``data``) are the PRIMARY evidence —
                # they already carry DNS/HTTP/TCP/UDP/hosts with ASN/country +
                # VirusTotal permalinks (network_extractor). The raw PCAP is an
                # OPTIONAL deep-dive: on a constrained local model an unbounded
                # read_pcap_summary loop over-ran the 330s analyst budget and
                # aborted, so we hand the analyst the structured evidence up front
                # and cap the PCAP peek (react_agent_max_steps_overrides.network).
                prompt_messages = [
                    ("system", _ISR_SYSTEM),
                    (
                        "human",
                        "Analyze the network activity below and return a structured "
                        "list of findings.\n\n"
                        "PRIMARY EVIDENCE — structured CAPE network flows (DNS / HTTP / "
                        "TCP / UDP / contacted hosts, annotated with ASN/country and "
                        "VirusTotal permalinks):\n"
                        f"{data}\n\n"
                        f"A raw packet capture is ALSO available at: {pcap_path}\n"
                        "You MAY make at most one or two PCAP tool calls "
                        "(read_pcap_summary / extract_dns / extract_http) to confirm "
                        "packet-level beaconing or tunnelling — but base your findings "
                        "primarily on the structured flows above and do NOT block on the "
                        "PCAP.\n\n"
                        "For each finding state: the claim, the exact artifact reference "
                        "(e.g. 'TCP dst=185.220.101.5:443', 'DNS query: rnd7x.evil.com'), "
                        "your confidence (0.0-1.0), and the MITRE ATT&CK technique ID.\n\n"
                        "Format each finding as:\n"
                        "CLAIM: <claim text>\n"
                        "EVIDENCE: <artifact reference>\n"
                        "CONFIDENCE: <float>\n"
                        "TECHNIQUE: <T-ID or NONE>\n"
                        "---\n",
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

        # Fallback: text-based ISR analysis
        target_info = (
            f"Target PCAP: {data}" if len(data.strip()) < 512 else f"Network output:\n{data}"
        )

        prompt_messages = [
            ("system", _ISR_SYSTEM),
            (
                "human",
                "Analyze the network data and return a structured list of findings.\n"
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

        # Try MCP for text mode
        mcp_ready = self._try_initialize_mcp()
        if mcp_ready:
            content = self.execute_tool_loop(prompt_messages)
        else:
            prompt = ChatPromptTemplate.from_messages(prompt_messages)
            response = (prompt | self.llm).invoke({})
            content = str(response.content)

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
