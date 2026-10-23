"""Network Analyst agent — evaluates network flows (packet captures, DNS logs).

Overrides analyze_isr() and revise_isr() to extract structured
ClaimEvidence objects. Focuses on C2 beaconing patterns, DGA domains,
TLS certificate anomalies, and protocol tunneling.

Data Flow:
  - Fixture mode: Receives pre-parsed network log text from NetworkParser.
    Analysis is LLM-only (text-based reasoning on parsed tables).
  - Sandbox mode: Receives a packet capture's path from the job's sandbox.
    Analysis uses the capture tools its tool servers declare (by kind:
    a packet overview, DNS queries, HTTP requests) for deep traffic
    inspection, falling back to text analysis if MCP initialization fails.

PCAP detection heuristic:
  If the input data looks like a file path ending in .pcap/.pcapng,
  the agent treats it as a PCAP reference and uses MCP tools.
  Otherwise, it falls back to LLM-only text analysis.
"""

from __future__ import annotations

import contextlib
import re
from collections.abc import Sequence
from typing import Any

from maljan.agents.base_agent import BaseAnalyst, prompt_to_messages, revision_messages
from maljan.agents.prompt_fragments import (
    CLAIM_FORMAT_FRAGMENT,
    FINDINGS_BLOCK_FRAGMENT,
    format_fragment,
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

# The kinds of capture tool the PCAP turns walk through, in the order they
# are named, with what each is for (``builtin_declarations.CONSUMER_KINDS``
# ``network_analyst._PCAP_TOOLS``). A tool is offered in the line by the kind
# it declares, under the name the request offers it by, whichever server
# serves it.
_PCAP_STEPS: tuple[tuple[str, str], ...] = (
    ("packet_overview", "get packet overview"),
    ("dns", "extract all DNS queries"),
    ("http", "extract HTTP request headers"),
)


# What a PCAP turn says when its request carries none of the packet tools.
NO_PACKET_TOOL_LINE = (
    "No packet tool is in your tool list, so base your findings on the structured flows above."
)
# What it says instead when the request carries tools that declare no kind:
# any of them may read the capture, and the model, not this line, decides.
UNDECLARED_TOOLS_LINE = (
    "Your tool list holds tools that declare no kind; you MAY use any of them that reads the "
    "capture to check the flows above at packet level, but base your findings primarily on "
    "the structured flows above and do NOT block on the PCAP."
)


def _undeclared_tools_in(tools: Sequence[Any]) -> bool:
    """Whether the request carries a tool from a declaring source that declares nothing for it.

    Such a tool may read a capture: nothing says it does not. A tool with no
    source at all (a team ``ask_`` tool) is not one.
    """
    from maljan.agents.prompt_fragments import offered
    from maljan.agents.tool_pinning import declared_facts_of, declared_source_of
    from maljan.core.undeclared_tools import declares_a_kind

    return any(
        declared_source_of(tool) is not None and not declares_a_kind(declared_facts_of(tool))
        for tool in offered(tools)
    )


def _pcap_tools_in(tools: Sequence[Any]) -> list[tuple[str, str]]:
    """The capture tools the request carries, one per kind of ``_PCAP_STEPS``, by declared kind."""
    from maljan.agents.prompt_fragments import offered
    from maljan.agents.tool_pinning import declared_facts_of

    kinds = {kind for kind, _what in _PCAP_STEPS}
    named: dict[str, str] = {}
    for tool in offered(tools):
        facts = declared_facts_of(tool)
        kind = getattr(facts, "kind", "")
        if kind in kinds and kind not in named:
            named[kind] = str(getattr(tool, "name", ""))
    return [(named[kind], what) for kind, what in _PCAP_STEPS if kind in named]


# The annotations the platform's enrichment writes on a flow's host, by the
# field it writes them under (``enrichment.orchestrator``, the network
# extractor), and the words the line names each by, in order.
_ANNOTATIONS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("ASN", ("asn",)),
    ("country", ("geo", "country")),
    ("reputation", ("reputation",)),
)
_FIELD = re.compile(r'"([a-z_]{2,20})"\s*:')


def _annotations_in(data: str) -> list[str]:
    """The annotation words for what the flows actually carry, read once over ``data``.

    A JSON flow block names them by field; the platform's own flow text
    (``parsers.network_parser``) by its ASN/country column and its reputation
    paragraph.
    """
    from maljan.parsers.network_parser import ASN_COUNTRY_COLUMN, REPUTATION_HEADING

    text = str(data or "")
    present = set(_FIELD.findall(text))
    if ASN_COUNTRY_COLUMN in text:
        present.update({"asn", "country"})
    if REPUTATION_HEADING in text:
        present.add("reputation")
    return [word for word, fields in _ANNOTATIONS if present.intersection(fields)]


def primary_evidence_line(sandbox: Any, data: str = "") -> str:
    """The line that hands the analyst the structured flows, naming the job's sandbox or none.

    It says which annotations the flows carry (ASN, country, reputation) only
    where the flows in ``data`` carry them.
    """
    found = _annotations_in(data)
    place = [word for word in found if word in ("ASN", "country")]
    parts = (["/".join(place)] if place else []) + [w for w in found if w not in place]
    said = ", annotated with " + " and ".join(parts) if parts else ""
    return (
        f"PRIMARY EVIDENCE — {_flows_label(sandbox)} (DNS / HTTP / TCP / UDP / contacted "
        f"hosts{said}):\n"
    )


def _flows_label(sandbox: Any) -> str:
    """What the structured flows are called: the sandbox's declared display name, or neither."""
    name = ""
    with contextlib.suppress(Exception):
        name = str(sandbox.display_name()) if sandbox is not None else ""
    return (
        f"structured network flows from the job's sandbox ({name})"
        if name
        else ("structured sandbox network flows")
    )


def _capture_line(captures: Sequence[str]) -> str:
    """The sentence naming the job's packet capture(s), which the platform fetched.

    With one, the packet tools' capture argument is filled by the platform and
    no path is shown; with several, each is named by its job-relative name
    (``tools.staging.job_relative``, never a host path), since the model must
    choose.
    """
    if len(captures) == 1:
        return "A raw packet capture is ALSO available to the packet tools."
    from maljan.tools.staging import job_relative

    return "Raw packet captures are ALSO available: " + ", ".join(job_relative(c) for c in captures)


@register_agent("network")
class NetworkAnalyst(BaseAnalyst):
    """Specialized agent for evaluating network connectivity logs (packet captures, DNS)."""

    def _job_sandbox(self) -> Any:
        """The job's sandbox provider, ``None`` for an analyst built outside a container."""
        container = getattr(self, "_container", None)
        if container is None:
            return None
        try:
            return container.get_sandbox_provider()
        except Exception as exc:  # noqa: BLE001 — a prompt never fails over a provider lookup
            self.logger.debug("No sandbox provider for the flows' label (%s).", type(exc).__name__)
            return None

    # ------------------------------------------------------------------
    # MCP Tool Interface
    # ------------------------------------------------------------------

    def _initialize_mcp_client(self) -> None:
        """Attach every tool server bound to the ``network`` role.

        With default settings that is exactly ``mcp.servers["network"]`` — the
        same ``network-mcp`` sidecar, the same command, cwd and environment
        this method used to spell out inline — so the tool names are
        unchanged, and ``tests/unit/servers/test_builtin_tool_sets.py`` says so.
        An operator who adds a second network server gets both. Where a sandbox
        produced a report, ``sandbox_items`` is beside them.
        """
        if getattr(self, "tools", None):
            return
        registry = self._server_registry()
        if registry is None:
            return
        # The sandbox's own tools when the definition asks for them, or else
        # the one query over the sandbox report's items: the pack shows this
        # analyst what the sandbox recorded, and a claim cites an item by id.
        sandbox = self._definition_sandbox_tools() or self._sandbox_items_tool()
        # ``_attach_registry_tools`` records its own degradation reasons on the
        # analyst, so nothing here may reassign ``degradation_reasons`` — doing
        # so would erase the reason for the very server that failed to attach.
        # The sandbox's tools are the agent's own, listed after the servers'
        # as they always were: a server tool of the same name is offered as
        # ``<server>__<tool>`` and never shadows one of them.
        from maljan.providers.servers import settle_tool_notes

        self.tools = settle_tool_notes(
            [*self._attach_registry_tools("network", claimed=sandbox), *sandbox],
            getattr(getattr(self, "_container", None), "config", None),
        )
        self.logger.info("Network tool servers: %d tools attached.", len(self.tools))

    # ``_try_initialize_mcp`` used to live here. It now lives on ``BaseAnalyst``
    # unchanged in behaviour and name, because the dynamic analyst needed the
    # same graceful degradation and had been hard-failing every run without it.

    # ------------------------------------------------------------------
    # Text interface (the abstract contract; the ISR path is the one that runs)
    # ------------------------------------------------------------------

    def analyze(self, data: str) -> str:
        """The first report as text: the ISR analysis, written out."""
        return self.analyze_isr(data).to_text_summary()

    def revise(
        self,
        original_data: str,
        own_report: str,
        peer_reports: dict[str, str],
        mediator_feedback: str,
    ) -> str:
        """The revised report as text: the ISR revision's text."""
        return self.revise_isr(original_data, own_report, peer_reports, mediator_feedback)[0]

    # ------------------------------------------------------------------
    # ISR interface
    # ------------------------------------------------------------------

    def analyze_isr(self, data: str) -> AgentISR:
        """Return a structured AgentISR with evidence-backed network claims."""
        self.logger.info("Executing network ISR analysis...")

        # The packet capture is what the platform fetched for this job, never
        # a path the sample's own flow text happens to carry: a flow string is
        # sample-controlled, and a path in it is a path the sample chose.
        captures = tuple(getattr(self, "_captures", ()) or ())

        if captures:
            self.logger.info("%d packet capture(s) fetched for this job.", len(captures))
            mcp_ready = self._try_initialize_mcp()

            if mcp_ready:
                # The sandbox's structured flows (``data``) are the PRIMARY
                # evidence — they already carry DNS/HTTP/TCP/UDP/hosts with
                # whatever the enrichment added (network_extractor). The raw PCAP
                # is an OPTIONAL deep-dive: on a constrained local model an
                # unbounded packet-overview loop over-ran the 330s analyst budget and
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
                    else (
                        UNDECLARED_TOOLS_LINE
                        if _undeclared_tools_in(self.tools)
                        else NO_PACKET_TOOL_LINE
                    )
                    + "\n\n"
                )
                prompt_messages = [
                    ("system", self._system_prompt(_network_prompt)),
                    (
                        "human",
                        "Analyze the network activity below and return a structured "
                        "list of findings.\n\n"
                        + primary_evidence_line(self._job_sandbox(), data)
                        + f"{data}\n\n"
                        f"{_capture_line(captures)}\n"
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
            # A revision is one tools-free call unless it may read a function
            # the ledger never listed: the prompt says which.
            self._system_prompt(_network_prompt, tools=self.revision_tools()),
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
        content = self._capture_findings(self.revision_answer(prompt_to_messages(messages)))

        claims = self._read_claims(content, revision_round)
        dissent = _parse_disputes(content)

        if not claims:
            # The lenient reading keeps the disputes the answer wrote: a
            # revision's dissent is what it says, whichever reader read it.
            lenient = self._text_to_isr(content, revision_round=revision_round)
            lenient.dissent_items = dissent
            return content, lenient

        isr = AgentISR(
            agent_id=self.name,
            domain="network",
            claims=claims,
            dissent_items=dissent,
            revision_round=revision_round,
        )
        self._with_claims_read(isr)
        return content, isr
