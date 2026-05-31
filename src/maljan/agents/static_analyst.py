"""Static Analyst agent — evaluates decompiled code and binary strings.

Phase 1b: Overrides analyze_isr() and revise_isr() to extract structured
ClaimEvidence objects via a structured-output prompt. Each claim cites a
concrete artifact reference (function name, string offset, API call).
"""

from __future__ import annotations

import os
import re
from typing import Any

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
    "Follow this reverse engineering sequence. Prefer the malware-specific\n"
    "analyzers first — they return pre-digested triage signals in one call,\n"
    "which is far cheaper than walking every function manually:\n"
    "1. Call `load_program(file=<path>)` to load the binary into Ghidra.\n"
    "   The file path is the absolute path on the server filesystem.\n"
    "2. Call `get_current_program_info` to verify the program loaded correctly.\n"
    "3. Call `detect_malware_behaviors` for a fast behavior-category summary.\n"
    "4. Call `analyze_api_call_chains` for suspicious API sequences with threat\n"
    "   classifications.\n"
    "5. Call `find_anti_analysis_techniques` to surface packing/anti-debug/VM\n"
    "   evasion patterns.\n"
    "6. Call `extract_iocs_with_context` to pull URLs, IPs, registry keys, and\n"
    "   filesystem paths with the calling function context.\n"
    "7. Call `list_imports` to confirm suspicious API imports raised above.\n"
    "8. Call `list_strings` for any encoded/hardcoded artefacts the IOC pass\n"
    "   missed.\n"
    "9. For the 3–5 most suspicious functions: `decompile_function(address=<addr>)`\n"
    "   then `get_xrefs_to(address=<addr>)` to confirm call-sites.\n\n"
    "IMPORTANT:\n"
    "- Step 1 (load_program) MUST happen before any analysis tool call.\n"
    "- Always prefer the high-level malware analyzers (steps 3–6) before\n"
    "  decompiling individual functions — they are much cheaper.\n"
    "- Focus decompilation on 3-5 most suspicious functions, not every function.\n"
    "- Large binaries may have 1000+ functions. Prioritize entry point, main,\n"
    "  and functions referencing crypto/network/process APIs.\n"
    "- Summarize assembly patterns instead of dumping raw hex."
)


@register_agent("static")
class StaticAnalyst(BaseAnalyst):
    """Specialized agent for evaluating decompiled code and strings via Ghidra MCP."""

    # ------------------------------------------------------------------
    # MCP Tool Interface
    # ------------------------------------------------------------------

    # Allowlist of Ghidra MCP tools exposed to the ReAct agent.
    #
    # Rationale: Ghidra MCP advertises ~225 tools, of which ~165 reach our
    # client. Past runs loaded 123 tools after a denylist filter, but each
    # ReAct step then carries that entire catalogue in the prompt — for a
    # 9B-parameter local model with a 32k context window this is the single
    # largest contributor to per-step latency (3–5 minutes per round). The
    # allowlist below covers everything a static malware analyst actually
    # needs (load + enumerate + decompile + xrefs + malware-specific
    # detectors) and nothing else, cutting the catalog ~5x.
    _GHIDRA_ALLOWED_TOOLS: frozenset[str] = frozenset(
        {
            # Program lifecycle (load_program MUST run first).
            "load_program",
            "get_current_program_info",
            # Pre-digested high-value analyzers — give the LLM curated
            # triage signals in one tool call instead of forcing it to
            # walk the function graph by hand.
            "detect_malware_behaviors",
            "analyze_api_call_chains",
            "find_anti_analysis_techniques",
            "extract_iocs_with_context",
            # Compact enumeration tools the model uses to corroborate
            # behavior calls without exploding the prompt.
            "list_imports",
            "list_strings",
            "list_segments",
            "get_entry_points",
            # Targeted deep-dive when the analyzers point at a function.
            "decompile_function",
            "get_xrefs_to",
        }
    )
    # 31 → 12 (audit 2026-05-17, A-01). The dropped tools were redundant
    # call-graph traversals and function-listing variants that bloated
    # the prompt and pushed each ReAct round into the 180-600 s range.

    def _filter_ghidra_tools(self, tools: list[Any]) -> list[Any]:
        """Keep only allowlisted read-only analysis tools.

        Cuts catalogue size ~5x so each ReAct step has a small enough tool
        manifest for local 7-9B models to iterate at reasonable speed.
        """
        kept: list[Any] = []
        for tool in tools:
            name = getattr(tool, "name", "").lower()
            if name in self._GHIDRA_ALLOWED_TOOLS:
                kept.append(tool)
        self.logger.info(
            "Ghidra MCP: kept %d/%d tools via static-analyst allowlist.",
            len(kept),
            len(tools),
        )
        return kept

    def _initialize_mcp_client(self) -> None:
        if getattr(self, "tools", None):
            return

        from maljan.core.config import get_settings

        cfg = get_settings()

        if not cfg.mcp.ghidra.enabled:
            self.logger.info("Ghidra MCP is disabled in config.")
            return

        # Build output guardrail: use FunctionSummarizer if available
        output_guardrail = None
        if cfg.preprocessing.use_function_summarizer:
            from maljan.core.container import ServiceContainer

            container = ServiceContainer(config=cfg)
            summarizer = container.get_function_summarizer()
            if summarizer is not None:
                output_guardrail = summarizer.summarize_chunk
                self.logger.info("Ghidra output guardrail: FunctionSummarizer enabled.")

        max_chars = cfg.preprocessing.max_tool_output_chars

        # ------------------------------------------------------------------
        # HTTP transport (headless Docker server)
        # ------------------------------------------------------------------
        if cfg.mcp.ghidra.transport == "http":
            from maljan.agents.ghidra_http_client import GhidraHTTPClient

            client = GhidraHTTPClient(
                base_url=cfg.mcp.ghidra.url,
                auth_token=cfg.mcp.ghidra.auth_token,
                output_guardrail=output_guardrail,
                max_output_chars=max_chars,
            )

            self._run_async(client.initialize())
            self.toolkit = client
            all_tools = client.get_tools()
            self.tools = self._filter_ghidra_tools(list(all_tools))
            self.logger.info(
                "Initialized Ghidra HTTP tools: %d/%d (after allowlist).",
                len(self.tools),
                len(all_tools),
            )
            return

        # ------------------------------------------------------------------
        # stdio transport (legacy local subprocess)
        # ------------------------------------------------------------------
        from mcp import StdioServerParameters

        from maljan.agents.mcp_client import MCPLangChainToolkit
        from maljan.core.paths import resolve_mcp_args

        command = cfg.mcp.ghidra.command
        args = cfg.mcp.ghidra.args

        env = os.environ.copy()
        env["PYTHONIOENCODING"] = "utf-8"
        if cfg.mcp.ghidra.env:
            env.update(cfg.mcp.ghidra.env)

        args = resolve_mcp_args(args)
        server_params = StdioServerParameters(command=command, args=args, env=env)

        toolkit = MCPLangChainToolkit(
            server_params,
            output_guardrail=output_guardrail,
            max_output_chars=max_chars,
        )

        self._run_async(toolkit.initialize())
        self.toolkit = toolkit  # type: ignore[assignment]
        all_tools = toolkit.get_tools()
        self.tools = self._filter_ghidra_tools(list(all_tools))
        self.logger.info(
            "Initialized Ghidra MCP tools: %d/%d (after allowlist).",
            len(self.tools),
            len(all_tools),
        )

    def _run_async(self, coro: Any) -> None:
        """Run an async coroutine from a sync context, handling nested loops."""
        import asyncio

        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop is not None and loop.is_running():
            import nest_asyncio

            nest_asyncio.apply()
            loop.run_until_complete(coro)
        else:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(coro)

    def _compute_sink_priority_hint(self, file_path: str) -> str:
        """Maltracker-style pre-pass: rank functions reachable to sensitive sinks.

        Loads + auto-analyses the binary on the Ghidra MCP server, pulls the
        full call graph, and renders a "priority functions" hint pointing the
        ReAct loop at the malicious core first. Deterministic and fail-safe:
        any error (or a stripped binary with no named sink APIs) returns an
        empty string and the analyst proceeds with its normal behaviour.
        """
        from maljan.core.config import get_settings

        cfg = get_settings()
        if not cfg.preprocessing.use_sink_reachability:
            return ""
        if cfg.mcp.ghidra.transport != "http":
            return ""  # the pre-pass speaks the headless REST API directly

        try:
            import httpx

            from maljan.analysis.sink_reachability import build_priority_hint

            base = cfg.mcp.ghidra.url.rstrip("/")
            token = cfg.mcp.ghidra.auth_token
            headers = {"Authorization": f"Bearer {token}"} if token else {}
            with httpx.Client(timeout=120.0, headers=headers) as http:
                http.post(f"{base}/load_program", json={"file": file_path}).raise_for_status()
                http.post(f"{base}/run_analysis", json={}).raise_for_status()
                resp = http.get(
                    f"{base}/get_full_call_graph",
                    params={"format": "json", "limit": 20000},
                )
                resp.raise_for_status()
                graph_text = resp.text

            hint = build_priority_hint(
                graph_text, max_funcs=cfg.preprocessing.sink_reachability_max_funcs
            )
            if hint:
                self.logger.info(
                    "Sink-reachability pre-pass: priority-functions hint built "
                    "(%d chars) for '%s'.",
                    len(hint),
                    file_path,
                )
            else:
                self.logger.info(
                    "Sink-reachability pre-pass: no named sink APIs reachable "
                    "(stripped/static binary?) — no hint emitted."
                )
            return hint
        except Exception as exc:  # fail-safe: never break analysis over a hint
            self.logger.warning(
                "Sink-reachability pre-pass failed (%s: %s); continuing without hint.",
                type(exc).__name__,
                exc,
            )
            return ""

    # ------------------------------------------------------------------
    # Text interface (backward compatible)
    # ------------------------------------------------------------------

    def analyze(self, data: str) -> str:
        """Translates binary file paths or raw disassembly into a focused malware analysis report."""
        self.logger.info("Executing static evaluation...")

        self._initialize_mcp_client()

        # Phase 4: If data looks like a file path and exists, use PELoader
        # for structural PE analysis instead of passing raw path to LLM.
        target_info: str
        if len(data.strip()) < 512 and os.path.exists(data.strip()):
            try:
                from maljan.loaders.pe_loader import PELoader

                loader = PELoader(data.strip())
                target_info = loader.to_markdown()
                self.logger.info("PELoader parsed static data for '%s'.", data.strip())
            except Exception as exc:
                self.logger.warning(
                    "PELoader failed for '%s': %s. Falling back to raw path.", data.strip(), exc
                )
                target_info = f"Target File: {data}"
        elif len(data.strip()) < 512:
            target_info = f"Target File: {data}"
        else:
            target_info = f"Static output:\n{data}"

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

        # PIPE-ANA-01 (audit 2026-05-19): when the supplied target *looks*
        # like a filename but doesn't exist on disk (e.g. a sandbox sent
        # the task_id instead of the artefact path), short-circuit
        # to a zero-claim ISR rather than paying for an LLM round that
        # ends with ``load_program: File not found``. ANA-MARK-01 already
        # neutralises the placeholder text path; this is the equivalent
        # cheap guard at the *structured* entry point.
        stripped = data.strip()
        looks_like_filename = (
            len(stripped) < 512
            and "\n" not in stripped
            and stripped.endswith(
                (".exe", ".dll", ".elf", ".so", ".apk", ".dex", ".sys", ".bin", ".dat")
            )
        )
        if looks_like_filename and not os.path.exists(stripped):
            self.logger.error(
                "Static analyst received a non-existent path '%s'. Skipping LLM "
                "round and emitting an empty ISR — downstream CONF-INFL-01 cap "
                "will mark this run as degraded.",
                stripped,
            )
            return AgentISR(
                agent_id=self.name,
                domain="static",
                claims=[],
                dissent_items=[],
                revision_round=0,
            )

        target_info = (
            f"Target File: {data}" if len(data.strip()) < 512 else f"Static output:\n{data}"
        )

        # Wave 6 (2026-05-28, GHIDRA-DELIVERY-01): make the load_program
        # path *explicit* in the human turn instead of leaving the LLM to
        # infer it from the JSON. The path is injected upstream in
        # ``nodes.py:_augment_static_chunks_with_path`` as
        # ``analysis_file_path`` on the chunk JSON. When present we hoist
        # it to a separate "Load using" line so the model can't miss it,
        # even on a degraded local 8-9B run.
        load_hint = _extract_load_hint(data)

        # Maltracker-style sink-reachability triage: when we have a
        # container-visible path, run a deterministic call-graph pre-pass and
        # hoist the resulting priority-function list above the target so the
        # ReAct loop decompiles the malicious core first. Fail-safe: empty
        # string when disabled, unavailable, or the binary has no named sinks.
        sink_hint = ""
        analysis_path = _extract_analysis_path(data)
        if analysis_path:
            sink_hint = self._compute_sink_priority_hint(analysis_path)

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
                f"{sink_hint}{load_hint}{target_info}",
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


def _extract_load_hint(data: str) -> str:
    """Return a one-line ``load_program`` hint when the chunk carries a path.

    Wave 6 GHIDRA-DELIVERY-01. The analyst-node wrapper splices the
    container-visible sample path into the chunk JSON as
    ``analysis_file_path``. We hoist that to a dedicated line at the top
    of the human turn so the LLM doesn't have to discover it inside the
    larger ``target`` block. Returns an empty string when the chunk
    isn't JSON (the legacy raw-bytes path) or when no path is present,
    keeping the prompt verbatim with the pre-Wave-6 behaviour.
    """
    import json as _json

    stripped = data.strip()
    if not stripped or not stripped.startswith("{"):
        return ""
    try:
        parsed = _json.loads(stripped)
    except (_json.JSONDecodeError, ValueError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    path = parsed.get("analysis_file_path")
    if not isinstance(path, str) or not path:
        return ""
    return (
        f'LOAD THIS BINARY FIRST: call ``load_program(file="{path}")``.\n'
        "All subsequent analysis tools operate on the program loaded by "
        "that call. Do not invent a path — use the one above verbatim.\n\n"
    )


def _extract_analysis_path(data: str) -> str | None:
    """Return the ``analysis_file_path`` from a chunk JSON, or None.

    Mirrors ``_extract_load_hint``'s parse but exposes the raw container path
    so the sink-reachability pre-pass can drive Ghidra directly. Best-effort:
    non-JSON or pathless chunks return None.
    """
    import json as _json

    stripped = data.strip()
    if not stripped or not stripped.startswith("{"):
        return None
    try:
        parsed = _json.loads(stripped)
    except (_json.JSONDecodeError, ValueError):
        return None
    if not isinstance(parsed, dict):
        return None
    path = parsed.get("analysis_file_path")
    return path if isinstance(path, str) and path else None


# CRLF-tolerant separator that requires the dashes to occupy their own line.
_BLOCK_SPLIT_RE = re.compile(r"(?:^|\r?\n)\s*-{3,}\s*(?:\r?\n|$)", flags=re.MULTILINE)
_CLAIM_RE = re.compile(r"CLAIM:\s*(.+?)(?=\s*\n\s*EVIDENCE:|\Z)", flags=re.DOTALL)
_EVIDENCE_RE = re.compile(r"EVIDENCE:\s*(.+?)(?=\s*\n\s*CONFIDENCE:|\Z)", flags=re.DOTALL)
_CONFIDENCE_RE = re.compile(r"CONFIDENCE:\s*([\d.]+)")
_TECHNIQUE_RE = re.compile(r"TECHNIQUE:\s*(T\d{4}(?:\.\d{3})?|NONE)", flags=re.IGNORECASE)

# DISPUTES section runs until end-of-string OR the next ALL-CAPS markdown-style
# header (e.g. ``\nSUMMARY:`` or ``\nFINAL VERDICT:``). The previous greedy
# pattern silently absorbed whatever followed.
_DISPUTES_RE = re.compile(
    r"DISPUTES:\s*(.*?)(?=\r?\n[A-Z][A-Z_ ]{2,}:|\Z)",
    flags=re.DOTALL | re.IGNORECASE,
)


def _parse_claim_blocks(text: str) -> list[ClaimEvidence]:
    """Parse structured CLAIM/EVIDENCE/CONFIDENCE/TECHNIQUE blocks from LLM output.

    Tolerates CRLF line endings and varying amounts of whitespace.
    """
    claims: list[ClaimEvidence] = []
    blocks = _BLOCK_SPLIT_RE.split(text)
    for block in blocks:
        block = block.strip()
        if not block or "CLAIM:" not in block:
            continue
        claim_match = _CLAIM_RE.search(block)
        evidence_match = _EVIDENCE_RE.search(block)
        confidence_match = _CONFIDENCE_RE.search(block)
        technique_match = _TECHNIQUE_RE.search(block)

        if not (claim_match and evidence_match and confidence_match):
            continue

        try:
            confidence = max(0.0, min(1.0, float(confidence_match.group(1))))
        except ValueError:
            confidence = 0.5

        technique_raw = technique_match.group(1).upper() if technique_match else "NONE"
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
    """Extract dispute items from the DISPUTES section of a revision response.

    Stops at the next ALL-CAPS header (e.g. ``SUMMARY:``) so trailing
    sections do not get absorbed as dispute items.
    """
    disputes: list[str] = []
    match = _DISPUTES_RE.search(text)
    if not match:
        return disputes
    section = match.group(1).strip()
    if section.upper().rstrip(".") in {"", "NONE"}:
        return disputes
    for line in section.splitlines():
        cleaned = line.strip().lstrip("-*• ")
        if cleaned:
            disputes.append(cleaned)
    return disputes
