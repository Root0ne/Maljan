"""Dynamic Analyst agent — evaluates sandbox behavioral logs (CAPEv2/Cuckoo).

Phase 1b: Overrides analyze_isr() and revise_isr() to extract structured
ClaimEvidence objects. Focuses on API call sequences, process injection
chains, and persistence mechanisms observable from sandbox JSON output.
"""

from __future__ import annotations

from typing import Any

from langchain_core.prompts import ChatPromptTemplate

from maljan.agents.base_agent import BaseAnalyst
from maljan.agents.registry import register_agent
from maljan.agents.static_analyst import _parse_claim_blocks, _parse_disputes
from maljan.providers.sandbox.cape2 import CAPE2SandboxProvider
from maljan.schemas.isr_models import AgentISR

# The provider-independent head of the dynamic system prompt: it names the
# sandbox report shape (CAPEv2/Cuckoo JSON) this analyst was measured on, but
# no tool — the tool-usage workflow is the sandbox provider's fragment,
# appended below. A golden test pins the assembled result byte for byte
# against the prompt this project measured its evaluation on.
_DYN_HEAD = (
    "You are an expert Dynamic Malware Analyst with deep knowledge of sandbox behavior. "
    "Analyze API call sequences, registry operations, process injection chains, "
    "and persistence mechanisms from CAPEv2/Cuckoo JSON reports. "
    "For EVERY claim, cite a concrete artifact: 'API call: X at address Y', "
    "'Registry key: HKLM\\...\\Run', 'Process spawned: cmd.exe PID 1234'. "
    "Focus on MITRE ATT&CK: T1547 (Autostart), T1055 (Process Injection), "
    "T1059 (Command Execution), T1112 (Registry Modification).\n\n"
)

# Empty today. Declared because the assembly order is the contract sub-projects
# B and C build agent prompts from, and an implicit empty tail is a trap.
_DYN_TAIL = ""

# Back-compat: several modules and tests import this name. It is the default
# evaluation profile's assembled prompt — CAPEv2, the sandbox this project has
# always measured the dynamic analyst against — not whatever ``sandbox.provider``
# happens to be configured on a given box (that one field defaults to "mock").
# Every run's actual tool attachment goes through the *configured* provider
# instead (see ``_sandbox_provider`` below); only this frozen constant is
# pinned to CAPE2, exactly as the literal it replaces always was.
_ISR_SYSTEM = _DYN_HEAD + CAPE2SandboxProvider.CAPE_PROMPT_FRAGMENT + _DYN_TAIL


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
        if not provider.capabilities.provides_tools:
            self.logger.info("Sandbox provider '%s' exposes no tools.", provider.id)
            return
        self.tools = provider.dynamic_tools()
        self.toolkit = getattr(provider, "_toolkit", None)

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
            ("system", _ISR_SYSTEM),
            (
                "human",
                "Analyze registry persistence, process injection, and file/folder drops "
                "in this sandbox behavior data. You may use tools to gather more information.\n"
                f"{task_info}",
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
            ("system", _ISR_SYSTEM),
            (
                "human",
                "Analyze the sandbox behavioral data and return a structured list of findings.\n"
                "You may use tools to gather more information about the task.\n"
                "For each finding state: the claim, the exact artifact reference "
                "(e.g. 'API call: WriteProcessMemory PID=832', 'RegSetValue: HKLM\\Run\\malware'), "
                "your confidence (0.0-1.0), and the MITRE ATT&CK technique ID.\n\n"
                "Format each finding as:\n"
                "CLAIM: <claim text>\n"
                "EVIDENCE: <artifact reference>\n"
                "CONFIDENCE: <float>\n"
                "TECHNIQUE: <T-ID or NONE>\n"
                "---\n\n"
                f"{task_info}",
            ),
        ]

        content = self.execute_tool_loop(prompt_messages)
        claims = _parse_claim_blocks(content)

        if not claims:
            return self._text_to_isr(content, revision_round=0)

        return AgentISR(
            agent_id=self.name,
            domain="dynamic",
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
        self.logger.info("Executing dynamic ISR revision (round %d)...", revision_round)

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
                    "DISPUTES:\n- Static analyst claims no API injection but I see WriteProcessMemory.\n",
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
            domain="dynamic",
            claims=claims,
            dissent_items=dissent,
            revision_round=revision_round,
        )
        return content, isr
