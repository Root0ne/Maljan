"""Dynamic Analyst agent — evaluates sandbox behavioral logs (CAPEv2/Cuckoo).

Overrides analyze_isr() and revise_isr() to extract structured
ClaimEvidence objects. Focuses on API call sequences, process injection
chains, and persistence mechanisms observable from sandbox JSON output.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from langchain_core.prompts import ChatPromptTemplate

from maljan.agents.base_agent import BaseAnalyst, prompt_to_messages
from maljan.agents.prompt_fragments import (
    CLAIM_FORMAT_FRAGMENT,
    FINDINGS_BLOCK_FRAGMENT,
    PROVIDER_FAMILY,
    format_fragment,
    stamp_source,
    tool_families,
    tools_statement,
)
from maljan.agents.registry import register_agent
from maljan.agents.static_analyst import _parse_claim_blocks, _parse_disputes
from maljan.providers.sandbox.cape2 import CAPE2SandboxProvider
from maljan.schemas.isr_models import AgentISR

# The provider- and platform-independent head of the dynamic system prompt: it
# names the sandbox report shape (CAPEv2/Cuckoo JSON) this analyst reads, but
# no tool and no operating system. The tool-usage workflow is the sandbox
# provider's fragment and the artefacts to look for are the sample's format
# fragment; ``composition.builtin_prompt`` assembles all three.
_DYN_HEAD = (
    "You are an expert Dynamic Malware Analyst with deep knowledge of sandbox behavior. "
    "Analyze the call sequences, process trees, file and configuration changes, "
    "and persistence mechanisms in the sandbox JSON report. "
    "For EVERY claim, cite a concrete artifact from the report: the call and where it "
    "was made, the process and its pid, the exact path or key that was written. "
    "Focus on MITRE ATT&CK: T1547 (Autostart), T1055 (Process Injection), "
    "T1059 (Command Execution).\n\n"
)

# The optional structured channel, appended after the provider fragment so it
# is the last thing the analyst reads before it answers. The assembly order is
# the contract the tool-server and agent-composition layers build prompts from.
_DYN_TAIL = FINDINGS_BLOCK_FRAGMENT


def assemble_dynamic_prompt(
    fragment: str,
    tools: Sequence[Any],
    *,
    provider_fragment: str = "",
    provider_label: str = "",
    provider_expected: bool = False,
    for_a_clone: bool = False,
) -> str:
    """The dynamic system prompt, true of the tool list ``tools``.

    HEAD, the sample's format fragment, the sandbox's own tool workflow when
    that sandbox's tools are in the list, the sentence about tools, then TAIL.
    The CAPE workflow names ``submit_file``, ``get_task_report`` and the rest;
    it used to be sent whatever the sandbox was, so an analyst on the mock
    sandbox with only the report tools was walked through calls to a server
    it did not have.
    """
    if for_a_clone:
        # What a clone is seeded with: no sandbox workflow and no sentence
        # about tools, both of which it gets for its own list when resolved.
        return _DYN_HEAD + fragment + _DYN_TAIL
    middle = "\n\n".join(
        part
        for part in sandbox_provider_parts(
            tools,
            provider_fragment=provider_fragment,
            provider_label=provider_label,
            provider_expected=provider_expected,
        )
        if part
    )
    return _DYN_HEAD + fragment + "\n\n" + middle + _DYN_TAIL


def sandbox_provider_parts(
    tools: Sequence[Any],
    *,
    provider_fragment: str = "",
    provider_label: str = "",
    provider_expected: bool = False,
) -> tuple[str, str]:
    """``(the sandbox's tool workflow or "", the sentence about tools)`` for ``tools``.

    The workflow only when the sandbox's own tools are in the list (or
    expected). Shared by the built-in assembly and an operator's prompt on the
    dynamic role.
    """
    attached = provider_expected or PROVIDER_FAMILY in tool_families(tools)
    workflow = provider_fragment.strip() if attached else ""
    statement = tools_statement(
        tools,
        provider_label=provider_label or "the sandbox's own tool server",
        provider_expected=attached,
    )
    return workflow, statement


def _dynamic_prompt(tools: Sequence[Any] = ()) -> str:
    """The neutral dynamic prompt, for an analyst built outside a container.

    Against CAPEv2's workflow, the sandbox this project has always measured
    the dynamic analyst on, and only when the tools it walks through are in
    the list. A running job sends the container's resolved prompt for the
    tools the request carries; see ``composition.builtin_prompt`` and
    ``BaseAnalyst._system_prompt``.
    """
    return assemble_dynamic_prompt(
        format_fragment("unknown", "unknown"),
        tools,
        provider_fragment=CAPE2SandboxProvider.CAPE_PROMPT_FRAGMENT,
        provider_label="the CAPEv2 tool server",
    )


# Back-compat: the neutral assembly with no tools, which is what an analyst
# built outside a container and never given any sends.
_ISR_SYSTEM = _dynamic_prompt()


@register_agent("dynamic")
class DynamicAnalyst(BaseAnalyst):
    """Specialized agent for evaluating Sandbox behavioral logs."""

    # ------------------------------------------------------------------
    # MCP Tool Interface
    # ------------------------------------------------------------------

    def _sandbox_provider(self) -> Any:
        container = getattr(self, "_container", None)
        if container is not None:
            return container.get_sandbox_provider()
        from maljan.core.config import get_settings
        from maljan.providers.registry import get_sandbox_provider

        return get_sandbox_provider(get_settings())

    def _static_capabilities(self) -> Any:
        # Read by BaseAnalyst._try_initialize_mcp. Every sandbox degrades: the
        # report JSON in ``data`` is evidence on its own, so an unreachable
        # tool server costs depth, not the analyst.
        return self._sandbox_provider().capabilities

    def _initialize_mcp_client(self) -> None:
        if getattr(self, "tools", None):
            return
        provider = self._sandbox_provider()
        sandbox_tools: list[Any] = []
        if provider.capabilities.provides_tools:
            sandbox_tools = stamp_source(provider.dynamic_tools(), PROVIDER_FAMILY)
            self.toolkit = getattr(provider, "_toolkit", None)
        else:
            self.logger.info("Sandbox provider '%s' exposes no tools.", provider.id)
        self.tools = [
            *sandbox_tools,
            *self._definition_sandbox_tools(),
            *self._attach_registry_tools("dynamic"),
        ]

    # ------------------------------------------------------------------
    # Text interface (backward compatible)
    # ------------------------------------------------------------------

    def analyze(self, data: str) -> str:
        """Translates sandbox JSON logs into a behavioral malware profile."""
        self.logger.info("Executing dynamic behavior analysis...")

        # Graceful: the CAPE MCP endpoint is a port-forward to a separate VM
        # and is routinely unreachable. The sandbox JSON in ``data`` is
        # evidence on its own, so a missing toolkit costs depth, not the
        # analyst. See ``BaseAnalyst._try_initialize_mcp``.
        self._try_initialize_mcp()

        # Treat `data` as task_id if it's numeric/short
        task_info = f"Task ID: {data}" if data.strip().isdigit() else f"Sandbox data:\n{data}"

        prompt_messages = [
            ("system", self._system_prompt(_dynamic_prompt)),
            (
                "human",
                "Analyze registry persistence, process injection, and file/folder drops "
                "in this sandbox behavior data."
                + (" You may use tools to gather more information.\n" if self.tools else "\n")
                + f"{task_info}",
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
        """Revise dynamic analysis based on peer findings and mediator feedback."""
        self.logger.info("Revising dynamic analysis based on peer feedback...")

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
                    "You are an expert Dynamic Analyst participating in a collaborative "
                    "multi-agent malware analysis. The mediator has identified contradictions "
                    "between your report and other experts. Review the peer reports and mediator "
                    "feedback, then revise your analysis. Correlate sandbox behaviors with "
                    "any API imports or network indicators raised by peers. "
                    "Focus on MITRE ATT&CK: T1547, T1055.",
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

        return self.ask_the_model(
            prompt.format_messages(
                own_report=own_report,
                peer_section=peer_section,
                mediator_feedback=mediator_feedback,
                data=original_data,
            ),
            what="revision",
        )

    # ------------------------------------------------------------------
    # ISR interface
    # ------------------------------------------------------------------

    def analyze_isr(self, data: str) -> AgentISR:
        """Return a structured AgentISR with evidence-backed behavioral claims."""
        self.logger.info("Executing dynamic ISR analysis...")

        # Graceful: the CAPE MCP endpoint is a port-forward to a separate VM
        # and is routinely unreachable. The sandbox JSON in ``data`` is
        # evidence on its own, so a missing toolkit costs depth, not the
        # analyst. See ``BaseAnalyst._try_initialize_mcp``.
        self._try_initialize_mcp()

        # Treat `data` as task_id if it's numeric/short
        task_info = f"Task ID: {data}" if data.strip().isdigit() else f"Sandbox data:\n{data}"

        prompt_messages = [
            ("system", self._system_prompt(_dynamic_prompt)),
            (
                "human",
                "Analyze the sandbox behavioral data and return a structured list of findings.\n"
                + (
                    "You may use tools to gather more information about the task.\n"
                    if self.tools
                    else ""
                )
                + "For each finding state: the claim, the exact artifact reference "
                "(e.g. 'API call: WriteProcessMemory PID=832', 'RegSetValue: HKLM\\Run\\malware'), "
                "your confidence (0.0-1.0), and the MITRE ATT&CK technique ID.\n\n"
                f"{CLAIM_FORMAT_FRAGMENT}\n"
                f"{task_info}",
            ),
        ]

        content = self.execute_tool_loop(prompt_messages)
        claims = _parse_claim_blocks(content)

        if not claims:
            return self._text_to_isr(content, revision_round=0)

        return self._parsed_isr(claims, content, "dynamic")

    def revise_isr(
        self,
        original_data: str,
        own_report: str,
        peer_reports: dict[str, str],
        mediator_feedback: str,
        revision_round: int = 1,
    ) -> tuple[str, AgentISR]:
        """Return (revised_text, AgentISR) with dissent_items populated."""
        self.logger.info("Executing dynamic ISR revision (round %d)...", revision_round)

        peer_isr_summaries = (
            "\n\n".join(
                f"{name.upper()} REPORT:\n{report}" for name, report in peer_reports.items()
            )
            or "No peer reports available."
        )

        # Built as messages rather than through a template: the resolved system
        # prompt carries a literal JSON example (the findings block), and a
        # ``ChatPromptTemplate`` reads every ``{...}`` in it as a variable.
        messages = prompt_to_messages(
            [
                (
                    "system",
                    # A revision is one tools-free call: the prompt says so.
                    self._system_prompt(_dynamic_prompt, tools=()) + "\n\n"
                    "You are in a negotiation round. You MUST:\n"
                    "1. List any peer claims you still DISPUTE in a DISPUTES section.\n"
                    "2. Revise your own claims based on new evidence.\n"
                    "3. If you have NO disputes, write 'DISPUTES: NONE' to signal convergence.",
                ),
                (
                    "human",
                    f"YOUR ORIGINAL REPORT:\n{own_report}\n\n"
                    f"PEER REPORTS:\n{peer_isr_summaries}\n\n"
                    f"MEDIATOR FEEDBACK:\n{mediator_feedback}\n\n"
                    f"RAW DATA:\n{original_data}\n\n"
                    "Format your response as structured claims "
                    "(CLAIM/EVIDENCE/CONFIDENCE/TECHNIQUE)\n"
                    "followed by a DISPUTES section listing peer claims you reject.\n"
                    "Example:\n"
                    "CLAIM: ...\nEVIDENCE: ...\nCONFIDENCE: 0.8\nTECHNIQUE: T1055\n---\n"
                    "DISPUTES:\n- Static analyst claims no API injection but I see "
                    "WriteProcessMemory.\n",
                ),
            ]
        )

        # Through the findings capture like every other answer: the resolved
        # system prompt ends with the findings-block instruction, so a model
        # that obeys it puts a JSON fence into the revised report, and nothing
        # downstream of here — the claim parser, the transcript, the Composer —
        # should ever see it.
        content = self._capture_findings(
            self.ask_the_model(self.frame_messages(messages), what="revision")
        )

        claims = _parse_claim_blocks(content)
        dissent = _parse_disputes(content)

        if not claims:
            return content, self._text_to_isr(content, revision_round=revision_round)

        isr = AgentISR(
            agent_id=self.name,
            domain="dynamic",
            claims=claims,
            dissent_items=dissent,
            revision_round=revision_round,
        )
        return content, isr
