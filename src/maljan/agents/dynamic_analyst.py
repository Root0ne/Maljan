"""Dynamic Analyst agent — evaluates sandbox behavioral logs (CAPEv2/Cuckoo).

Phase 1b: Overrides analyze_isr() and revise_isr() to extract structured
ClaimEvidence objects. Focuses on API call sequences, process injection
chains, and persistence mechanisms observable from sandbox JSON output.
"""

from __future__ import annotations

from langchain_core.prompts import ChatPromptTemplate

from maljan.agents.base_agent import BaseAnalyst
from maljan.agents.registry import register_agent
from maljan.agents.static_analyst import _parse_claim_blocks, _parse_disputes
from maljan.schemas.isr_models import AgentISR

_ISR_SYSTEM = (
    "You are an expert Dynamic Malware Analyst with deep knowledge of sandbox behavior. "
    "Analyze API call sequences, registry operations, process injection chains, "
    "and persistence mechanisms from CAPEv2/Cuckoo JSON reports. "
    "For EVERY claim, cite a concrete artifact: 'API call: X at address Y', "
    "'Registry key: HKLM\\...\\Run', 'Process spawned: cmd.exe PID 1234'. "
    "Focus on MITRE ATT&CK: T1547 (Autostart), T1055 (Process Injection), "
    "T1059 (Command Execution), T1112 (Registry Modification).\n\n"
    "=== TOOL USAGE WORKFLOW ===\n"
    "Follow this sequence when given a file path or hash:\n"
    "1. Call `get_cuckoo_status` to verify the sandbox is online.\n"
    "2. Call `search_task(hash_value=<sha256>)` to check if this sample was already analyzed.\n"
    "3. If no existing task: call `submit_file(file_path=<path>)` to submit for analysis.\n"
    "4. After submission, POLL with `get_task_status(task_id=<id>)` until status is 'reported'.\n"
    "5. Once reported: call `get_task_report(task_id=<id>, format='lean')` for a summarized report.\n"
    "6. Call `get_task_iocs(task_id=<id>)` for IOCs (domains, IPs, mutexes).\n"
    "7. Optionally call `get_task_config(task_id=<id>)` for extracted malware configs.\n\n"
    "IMPORTANT: Always use format='lean' for reports to avoid context overflow. "
    "The lean format filters 50MB reports down to key findings.\n"
    "If given a Task ID directly, skip to step 5."
)


@register_agent("dynamic")
class DynamicAnalyst(BaseAnalyst):
    """Specialized agent for evaluating Sandbox behavioral logs."""

    # ------------------------------------------------------------------
    # MCP Tool Interface
    # ------------------------------------------------------------------

    def _initialize_mcp_client(self) -> None:
        if getattr(self, "tools", None):
            return

        import os

        from mcp import StdioServerParameters

        from maljan.agents.mcp_client import MCPLangChainToolkit
        from maljan.core.config import get_settings

        cfg = get_settings()

        if not cfg.mcp.cape.enabled:
            self.logger.info("CAPEv2 MCP is disabled in config.")
            return

        transport = (getattr(cfg.mcp.cape, "transport", "stdio") or "stdio").lower()

        if transport in ("http", "streamable-http", "sse"):
            # Remote CAPE MCP server (e.g. cape_mcp_wrapper.py running on a
            # separate Ubuntu VM with --transport streamable-http). There is no
            # local subprocess to launch; connect over HTTP.
            url = cfg.mcp.cape.url
            if not url:
                self.logger.warning(
                    "CAPE MCP transport=%s but mcp.cape.url is empty; skipping MCP init.",
                    transport,
                )
                return
            headers: dict[str, str] = {}
            token = getattr(cfg.mcp.cape, "auth_token", "")
            if token:
                headers["Authorization"] = f"Bearer {token}"
            self.logger.info("Initializing CAPEv2 MCP over %s: %s", transport, url)
            toolkit = MCPLangChainToolkit(transport=transport, http_url=url, http_headers=headers)
        else:
            command = cfg.mcp.cape.command
            args = cfg.mcp.cape.args

            env = os.environ.copy()
            if cfg.mcp.cape.env:
                env.update(cfg.mcp.cape.env)

            from maljan.core.paths import get_project_root, resolve_mcp_args

            project_root = str(get_project_root())
            args = resolve_mcp_args(args)
            server_params = StdioServerParameters(
                command=command, args=args, env=env, cwd=project_root
            )

            toolkit = MCPLangChainToolkit(server_params)

        # Init the MCP toolkit on the shared agent loop so its session/transport
        # is bound to the SAME loop the ReAct tool calls later run on. Running it
        # on a throwaway ``new_event_loop()`` (LangGraph runs sync nodes in a
        # worker thread with no running loop) bound the toolkit to a different
        # loop, so the first CAPE MCP tool call raised "<Event> is bound to a
        # different event loop" (see static_analyst._run_async for the full
        # rationale). Always called from the sync analyze path, never from within
        # the agent loop, so blocking on the result cannot deadlock.
        from maljan.agents.base_agent import _run_coro_blocking

        _run_coro_blocking(toolkit.initialize(), hard_timeout=120.0, label="cape-mcp-init")

        self.toolkit = toolkit
        # Essential CAPE tool list is config-driven: agents do not need to be
        # rebuilt when the operator adds/removes a tool name. ``cape.tools`` is
        # a list of allow-listed tool names; an empty list means "use the
        # built-in default essentials".
        configured = list(getattr(cfg.mcp.cape, "tools", []) or [])
        essential_set: set[str] = (
            set(configured)
            if configured
            else {
                "get_cuckoo_status",
                "search_task",
                "extended_search",
                "submit_file",
                "submit_static",
                "get_task_status",
                "get_task_report",
                "get_task_iocs",
                "get_task_config",
                "list_tasks",
                "view_task",
                "get_latest_tasks",
                "verify_auth",
            }
        )
        all_tools = toolkit.get_tools()
        self.tools = [t for t in all_tools if t.name in essential_set]
        self.logger.info(
            "Initialized CAPEv2 MCP tools: %d/%d (essential only): %s",
            len(self.tools),
            len(all_tools),
            [t.name for t in self.tools],
        )

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
