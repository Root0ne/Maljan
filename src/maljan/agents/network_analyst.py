"""Network Analyst agent — evaluates network flows (Zeek/PCAP/DNS logs).

Overrides analyze_isr() and revise_isr() to extract structured
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
from collections.abc import Sequence
from typing import Any

from maljan.agents.base_agent import BaseAnalyst, prompt_to_messages, revision_messages
from maljan.agents.prompt_fragments import (
    CLAIM_FORMAT_FRAGMENT,
    FINDINGS_BLOCK_FRAGMENT,
    format_fragment,
    tool_names,
    tools_statement,
)
from maljan.agents.registry import register_agent
from maljan.agents.static_analyst import _parse_disputes
from maljan.schemas.isr_models import AgentISR

# The platform-independent head of the network system prompt. Traffic looks the
# same from every guest, but what reached the wire does not, so the sample's
# format fragment is appended by ``composition.builtin_prompt``.
_NET_HEAD = (
    "You are an expert Network Security Analyst with deep knowledge of malware C2 communication. "
    "Analyze DNS queries, HTTP/HTTPS flows, SSL certificates, and PCAP captures for "
    "beaconing patterns, DGA domains, tunneling, and exfiltration channels. "
    "For EVERY claim, cite a concrete artifact: 'DNS query: abc.evil.com', "
    "'PCAP frame 42: src=10.0.0.5 dst=185.220.x.x:443', 'TLS SNI: suspicious.tld'. "
    "Focus on MITRE ATT&CK: T1071 (Application Layer Protocol), T1571 (Non-Standard Port), "
    "T1048 (Exfiltration), T1568 (Dynamic Resolution).\n\n"
)

# The optional structured channel, appended last for the same reason the other
# analysts append theirs: the assembly order is a contract, and this is the
# last thing the analyst reads before it answers.
_NET_TAIL = FINDINGS_BLOCK_FRAGMENT


def assemble_network_prompt(
    fragment: str, tools: Sequence[Any], *, for_a_clone: bool = False
) -> str:
    """HEAD, the sample's format fragment, the sentence about ``tools``, then TAIL."""
    statement = "\n\n" + tools_statement(tools) if not for_a_clone else ""
    return _NET_HEAD + fragment + statement + _NET_TAIL


def _network_prompt(tools: Sequence[Any] = ()) -> str:
    """The neutral network prompt, for an analyst built outside a container.

    A running job sends the container's resolved prompt for the tools the
    request carries (``composition.builtin_prompt`` and
    ``BaseAnalyst._system_prompt``).
    """
    return assemble_network_prompt(format_fragment("unknown", "unknown"), tools)


# Back-compat: the neutral assembly with no tools.
_ISR_SYSTEM = _network_prompt()

# The packet tools the PCAP turns walk through, in the order they are named.
_PCAP_TOOLS: tuple[tuple[str, str], ...] = (
    ("read_pcap_summary", "get packet overview"),
    ("extract_dns", "extract all DNS queries"),
    ("extract_http", "extract HTTP request headers"),
)


# What a PCAP turn says when its request carries none of the packet tools.
NO_PACKET_TOOL_LINE = (
    "No packet tool is in your tool list, so base your findings on the structured flows above."
)
OTHER_TOOLS_THEN_ANALYZE = "Use the tools in your tool list where they help, then analyze"


def _pcap_tools_in(tools: Sequence[Any]) -> list[tuple[str, str]]:
    """The packet tools of ``_PCAP_TOOLS`` the request actually carries."""
    offered = tool_names(tools)
    return [(name, what) for name, what in _PCAP_TOOLS if name in offered]


# The text revision path's own system prompt. It is not ``_ISR_SYSTEM`` plus a
# suffix — it is a different prompt, and it was inline in ``revise`` until the
# revision framing moved to ``BaseAnalyst``. Byte-for-byte unchanged.
_NETWORK_REVISE_SYSTEM = (
    "You are an expert Network Analyst participating in a collaborative "
    "multi-agent malware analysis. The mediator has identified contradictions "
    "between your report and other experts. Review the peer reports and mediator "
    "feedback, then revise your analysis. Correlate network traffic with any "
    "hardcoded C2 URLs or HTTP API calls raised by peers. "
    "Focus on MITRE ATT&CK: T1071, T1571."
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
        unchanged, and ``tests/unit/servers/test_builtin_tool_sets.py`` says so.
        An operator who adds a second network server gets both.
        """
        if getattr(self, "tools", None):
            return
        registry = self._server_registry()
        if registry is None:
            return
        # ``_attach_registry_tools`` records its own degradation reasons on the
        # analyst, so nothing here may reassign ``degradation_reasons`` — doing
        # so would erase the reason for the very server that failed to attach.
        self.tools = self._attach_registry_tools("network")
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
                packet_tools = _pcap_tools_in(self.tools)
                steps = (
                    "Use the available tools to:\n"
                    + "".join(
                        f"{i}. {name} — {what}\n" for i, (name, what) in enumerate(packet_tools, 1)
                    )
                    + "\nThen analyze"
                    if packet_tools
                    else OTHER_TOOLS_THEN_ANALYZE
                )
                prompt_messages = [
                    ("system", self._system_prompt(_network_prompt)),
                    (
                        "human",
                        "A PCAP capture file is available for analysis.\n\n"
                        f"PCAP file path: {pcap_path}\n\n"
                        f"{steps} the results for C2 beaconing, DGA domains, "
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

        # Try MCP for text mode too (agent might extract useful patterns).
        # Attached before the prompt is built: the prompt says what the
        # request carries, and it carries what this call attached.
        mcp_ready = self._try_initialize_mcp()
        prompt_messages = [
            ("system", self._system_prompt(_network_prompt)),
            (
                "human",
                "Analyze DNS queries, HTTPS SSL flows, and potential C2 beacons "
                "in this Zeek/pcap network data:\n"
                f"{target_info}\n\n"
                "Identify beaconing patterns, suspicious domains, and exfiltration channels.",
            ),
        ]

        if mcp_ready:
            content = self.execute_tool_loop(prompt_messages)
        else:
            # Messages, not a template: the resolved system prompt carries a
            # literal JSON example and a template would read its braces as
            # variables.
            content = self._capture_findings(
                self.ask_the_model(
                    self.frame_messages(prompt_to_messages(prompt_messages)), what="analysis"
                )
            )

        return str(content)

    def revise(
        self,
        original_data: str,
        own_report: str,
        peer_reports: dict[str, str],
        mediator_feedback: str,
    ) -> str:
        """Revise network analysis based on peer findings and mediator feedback.

        The framing moved to ``BaseAnalyst.revision_messages`` so a custom
        analyst sends the same one. The messages that reach the model are
        identical, which is what ``tests/unit/agents/test_revision_prompt_golden.py``
        compares against a fixture captured before the move; the
        ``ChatPromptTemplate`` round trip is gone with it, because the template
        only ever substituted these same four values and could not survive a
        brace inside one of them.
        """
        self.logger.info("Revising network analysis based on peer feedback...")

        messages = revision_messages(
            _NETWORK_REVISE_SYSTEM,
            original_data,
            own_report,
            peer_reports,
            mediator_feedback,
            isr=False,
        )
        return self.ask_the_model(
            self.frame_messages(prompt_to_messages(messages)), what="revision"
        )

    # ------------------------------------------------------------------
    # ISR interface
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
                # and ask for a short PCAP peek in the prompt below; the loop
                # itself has no step limit unless an operator sets one.
                packet_tools = _pcap_tools_in(self.tools)
                peek = (
                    "You MAY make at most one or two PCAP tool calls "
                    f"({' / '.join(name for name, _what in packet_tools)}) to confirm "
                    "packet-level beaconing or tunnelling — but base your findings "
                    "primarily on the structured flows above and do NOT block on the "
                    "PCAP.\n\n"
                    if packet_tools
                    else NO_PACKET_TOOL_LINE + "\n\n"
                )
                prompt_messages = [
                    ("system", self._system_prompt(_network_prompt)),
                    (
                        "human",
                        "Analyze the network activity below and return a structured "
                        "list of findings.\n\n"
                        "PRIMARY EVIDENCE — structured CAPE network flows (DNS / HTTP / "
                        "TCP / UDP / contacted hosts, annotated with ASN/country and "
                        "VirusTotal permalinks):\n"
                        f"{data}\n\n"
                        f"A raw packet capture is ALSO available at: {pcap_path}\n"
                        f"{peek}"
                        "For each finding state: the claim, the exact artifact reference "
                        "(e.g. 'TCP dst=185.220.101.5:443', 'DNS query: rnd7x.evil.com'), "
                        "your confidence (0.0-1.0), and the MITRE ATT&CK technique ID.\n\n"
                        f"{CLAIM_FORMAT_FRAGMENT}",
                    ),
                ]
                content = self.execute_tool_loop(prompt_messages)
                claims = self._read_claims(content)

                if not claims:
                    return self._text_to_isr(content, revision_round=0)

                return self._parsed_isr(claims, content, "network")

        # Fallback: text-based ISR analysis
        target_info = (
            f"Target PCAP: {data}" if len(data.strip()) < 512 else f"Network output:\n{data}"
        )

        # Try MCP for text mode, before the prompt that says what it attached.
        mcp_ready = self._try_initialize_mcp()
        prompt_messages = [
            ("system", self._system_prompt(_network_prompt)),
            (
                "human",
                "Analyze the network data and return a structured list of findings.\n"
                "For each finding state: the claim, the exact artifact reference "
                "(e.g. 'PCAP frame 10: dst=185.220.101.5:443', 'DNS query: rnd7x.evil.com'), "
                "your confidence (0.0-1.0), and the MITRE ATT&CK technique ID.\n\n"
                f"{CLAIM_FORMAT_FRAGMENT}\n"
                f"{target_info}",
            ),
        ]

        if mcp_ready:
            content = self.execute_tool_loop(prompt_messages)
        else:
            # Messages, not a template: the resolved system prompt carries a
            # literal JSON example and a template would read its braces as
            # variables.
            content = self._capture_findings(
                self.ask_the_model(
                    self.frame_messages(prompt_to_messages(prompt_messages)), what="analysis"
                )
            )

        claims = self._read_claims(content)

        if not claims:
            return self._text_to_isr(content, revision_round=0)

        return self._parsed_isr(claims, content, "network")

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

        messages = revision_messages(
            # A revision is one tools-free call: the prompt says so.
            self._system_prompt(_network_prompt, tools=()),
            original_data,
            own_report,
            peer_reports,
            mediator_feedback,
            isr=True,
            revision_round=revision_round,
        )
        # Through the findings capture like every other answer: the resolved
        # system prompt ends with the findings-block instruction, so a model
        # that obeys it puts a JSON fence into the revised report, and nothing
        # downstream of here — the claim parser, the transcript, the Composer —
        # should ever see it.
        content = self._capture_findings(
            self.ask_the_model(self.frame_messages(prompt_to_messages(messages)), what="revision")
        )

        claims = self._read_claims(content, revision_round)
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
