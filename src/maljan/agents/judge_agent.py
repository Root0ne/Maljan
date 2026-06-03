"""Chief Judge and Mediator agent.

JudgeAgent is NOT an expert analyst — it does not inherit from BaseAnalyst.
It has two distinct responsibilities:
  1. mediate(): Find contradictions between expert reports during the
     negotiation loop, using structured output for reliable confidence scoring.
  2. give_verdict(): Produce the final STIX 2.1 Bundle after negotiation ends.

Phase 1b additions:
  - mediate() and give_verdict() optionally accept isr_reports to include
    structured ISR summaries alongside the plain-text reports. This gives
    the judge access to per-claim confidence scores and dissent signals.

Phase 4.2 additions:
  - give_verdict() optionally accepts an ATTCKValidator instance.
  - Before generating the STIX Bundle, all TTP IDs in isr_reports are
    validated against the authoritative ATT&CK dataset. A TTPValidationSummary
    is injected into the prompt so the LLM can self-correct hallucinated TTPs.
  - Graceful degradation: if no validator is provided (e.g., cache not built),
    verdict generation continues without validation — no crash.

Phase 4.3 additions:
  - give_verdict() optionally accepts a CascadeSummary from TTPCascadeEngine.
  - A three-layer cascade block is injected into the prompt, ranking TTPs by
    cross-layer weighted confidence so the LLM prioritizes corroborated findings.

Phase 7.2 additions (STIX Confidence Intervals):
  - System prompt now instructs the LLM to produce ConfidenceAnnotatedRelationship
    objects instead of plain Relationship objects for all TTP mappings.
  - Each relationship must be populated with:
      x_maljan_confidence: float [0.0, 1.0] — derived from cascade score or
          agent mean_confidence when cascade is unavailable.
      x_maljan_evidence_basis: controlled vocab — "static", "dynamic",
          "network", "static+dynamic", "all", etc.
      x_maljan_contributing_agents: list of agent_ids that found the evidence.
      x_maljan_technique_id: MITRE ATT&CK technique ID if applicable.
  - _build_confidence_instruction() builds cascade-aware evidence basis hints
    from the CascadeSummary so the LLM can ground confidence values rather
    than infer them.
Phase 7.1 additions (Dynamic Schema Pruning):
  - give_verdict() infers malware category (ransomware/RAT/dropper/worm/
    infostealer/unknown) from ISR reports using keyword-weighted scoring.
  - A schema pruning hint block is injected into the system prompt, guiding
    the LLM to produce only STIX object types relevant to the detected
    category. This implements the CTI-GEN (IEEE CSR 2025) methodology.
  - _build_schema_hint() handles inference + block generation.
  - Graceful degradation: UNKNOWN category returns empty string (no pruning);
    any inference error silently skips pruning.
"""

from __future__ import annotations

import asyncio
import uuid
from typing import TYPE_CHECKING, Any

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.prompts import ChatPromptTemplate

from maljan.analysis.schema_pruner import get_pruned_schema_hint
from maljan.analysis.semantic_category import infer_category
from maljan.core.config import get_settings
from maljan.core.logger import logger
from maljan.pipeline.mediation_models import MediatorVerdict
from maljan.pipeline.state import AgentArgument
from maljan.schemas.isr_models import AgentISR
from maljan.schemas.stix_models import Bundle

if TYPE_CHECKING:
    from maljan.analysis.ttp_cascade import CascadeSummary
    from maljan.memory.long_term_memory import MemoryStore

# Consensus threshold: mediator confidence must reach this to stop negotiation early
CONSENSUS_THRESHOLD = 0.85


class JudgeAgent:
    """Chief controller responsible for mediation, consensus detection, and final verdict.

    Usage:
        judge = JudgeAgent(llm=some_llm)
        argument, is_consensus = judge.mediate(reports, history)
        bundle = judge.give_verdict(reports, history, attck_validator=validator)
    """

    def __init__(self, llm: BaseChatModel, category_backend: str = "keyword") -> None:
        self.llm = llm
        self.logger = logger.getChild("judge")
        # Backend for the §7.1 schema-pruning category inference. Default
        # "keyword" keeps the deterministic substring path (zero behaviour
        # change); "semantic"/"hybrid" route through the embedding classifier.
        self.category_backend = category_backend

    async def _initialize_mcp_client(self) -> None:
        if getattr(self, "tools", None):
            return

        import os
        import sys

        from mcp import StdioServerParameters

        from maljan.agents.mcp_client import MCPLangChainToolkit
        from maljan.core.paths import get_project_root

        project_root = get_project_root()
        server_script = str(project_root / "threatintel-mcp" / "server.py")

        server_params = StdioServerParameters(
            command=sys.executable,
            args=[server_script],
            env=os.environ.copy(),
            cwd=str(project_root / "threatintel-mcp"),
        )

        toolkit = MCPLangChainToolkit(server_params)
        await toolkit.initialize()

        self.toolkit = toolkit
        self.tools = toolkit.get_tools()
        self.logger.info("Initialized ThreatIntel MCP tools: %s", [t.name for t in self.tools])

    async def execute_tool_loop(self, prompt_messages: list) -> str:
        """Execute a tool-calling ReAct loop for the agent."""
        import asyncio

        from langchain_core.messages import BaseMessage, HumanMessage, SystemMessage
        from langgraph.prebuilt import create_react_agent

        messages_pre: list[BaseMessage] = []
        for role, content in prompt_messages:
            if role == "system":
                messages_pre.append(SystemMessage(content=content))
            elif role == "human":
                messages_pre.append(HumanMessage(content=content))

        if not getattr(self, "tools", None):
            self.logger.warning("No tools initialized. Falling back to standard LLM invoke.")
            # Wave 5 HANG-01 (2026-05-28): wrap the no-tools ainvoke in the
            # same hard timeout used by the tools path so a stalled / queued
            # llama-server cannot freeze the judge node.
            no_tools_timeout = get_settings().react_agent_timeout_overrides.get(
                "judge", get_settings().react_agent_timeout
            )
            response = await asyncio.wait_for(
                self.llm.ainvoke(messages_pre),
                timeout=float(no_tools_timeout),
            )
            return str(response.content)

        self.logger.info("JudgeAgent starting ReAct agent loop with %d tools...", len(self.tools))

        agent_executor = create_react_agent(self.llm, self.tools)

        messages = messages_pre

        timeout = get_settings().react_agent_timeout
        self.logger.info(
            "JudgeAgent invoking ReAct (timeout=%ds, tools=%d)...",
            timeout,
            len(self.tools),
        )
        try:
            result = await asyncio.wait_for(
                agent_executor.ainvoke(
                    {"messages": messages},
                    {"recursion_limit": get_settings().react_agent_max_steps},
                ),
                timeout=timeout,
            )
            msg_count = len(result.get("messages", []))
            self.logger.info("JudgeAgent ReAct loop completed: %d messages.", msg_count)
            return str(result["messages"][-1].content)
        except TimeoutError:
            self.logger.error("JudgeAgent ReAct timed out after %ds.", timeout)
            raise

    @staticmethod
    def _has_explicit_dissent(isr_reports: dict[str, AgentISR] | None) -> bool:
        """Check if any agent has registered explicit dissent against peer findings.

        When all dissent_items are empty, agents fundamentally agree on the
        evidence — the mediator only needs to confirm consensus, not run
        ThreatIntel tools to resolve disputes.
        """
        if not isr_reports:
            return True  # conservative: no ISR data means we can't tell
        return any(
            bool(isr.dissent_items) for isr in isr_reports.values() if isinstance(isr, AgentISR)
        )

    async def mediate(
        self,
        reports: dict[str, str],
        history: list[AgentArgument],
        isr_reports: dict[str, AgentISR] | None = None,
    ) -> tuple[AgentArgument, bool]:
        """Find contradictions between expert reports and determine consensus.

        Accepts a generic dict of agent reports so any number of agents can
        participate without requiring changes to this method's signature.

        Fast path: when no explicit dissent is present in the ISRs, the mediator
        skips the expensive ReAct tool loop and uses a single LLM call to
        produce the structured verdict. ThreatIntel tools are only invoked when
        agents actually disagree on specific indicators.

        Args:
            reports: Mapping of agent name to their latest report text.
            history: Accumulated negotiation arguments from prior rounds.
            isr_reports: Optional structured ISR objects. When provided, their
                summaries are appended to give the judge per-claim confidence
                scores and explicit dissent signals.

        Returns:
            Tuple of (AgentArgument with mediator findings, bool indicating consensus).
        """
        self.logger.info("Mediating %d expert reports for contradictions...", len(reports))
        needs_tools = self._has_explicit_dissent(isr_reports)

        # Build a human-readable summary of all reports
        reports_text = "\n\n".join(
            f"--- {name.upper()} ANALYST ---\n{report}" for name, report in reports.items()
        )

        # Append ISR summaries when available — gives judge access to per-claim
        # confidence scores and explicit dissent signals from each agent.
        if isr_reports:
            isr_block = "\n\n".join(
                f"[ISR] {isr.to_text_summary()}"
                for isr in isr_reports.values()
                if isr.claims  # skip empty ISRs
            )
            if isr_block:
                reports_text = f"{reports_text}\n\n=== STRUCTURED CLAIMS (ISR) ===\n{isr_block}"

        # Audit 2026-05-17 (MED-01): the mediator is NOT allowed to state a
        # verdict or describe the sample as "clean". Its only job is to
        # surface explicit contradictions between agents and quantify how
        # aligned they are. The downstream judge LLM owns the verdict
        # decision — earlier prompt wording let "CLEAN / NO THREAT DETECTED"
        # prose leak into the judge prompt and bias the verdict toward
        # benign even when YARA had a hit.
        prompt_messages = [
            (
                "system",
                "You are the Lead Cyber Security Mediator. Your ONLY task is to "
                "compare expert analyst reports and emit:\n"
                "  1. A list of EXPLICIT contradictions between agents "
                "(one bullet per contradiction).\n"
                "  2. A single agreement_confidence in [0.0, 1.0] for how "
                "aligned the agents are — NOT the maliciousness of the sample.\n\n"
                "HARD RULES:\n"
                "- DO NOT emit a verdict. Never write 'Malware', 'Benign', "
                "'Suspicious', 'CLEAN', 'NO THREAT', or any synonym.\n"
                "- DO NOT recommend re-running pipelines or filling data gaps.\n"
                "- When an analyst has failed/empty output, write 'no input "
                "from <agent>' and EXCLUDE that analyst from the contradiction "
                "count. DO NOT treat absence of input as confirmation of "
                "cleanliness.\n"
                "- agreement_confidence reflects ONLY agent alignment, NOT how "
                "suspicious the sample looks. Two analysts unanimously saying "
                "nothing is still high alignment (1.0).\n"
                "- The downstream Judge alone decides Malware/Benign/Suspicious. "
                + (
                    "You have Threat Intelligence tools to verify disputed "
                    "IPs/domains/hashes — use them only to resolve contradictions.\n"
                    if needs_tools
                    else "No Threat Intelligence tools are needed for this run.\n"
                ),
            ),
            (
                "human",
                f"Expert Reports:\n{reports_text}\n\nPrevious Discussion:\n{history}\n\n"
                "List the contradictions and give a single agreement_confidence "
                "score. Do not state a verdict.",
            ),
        ]

        if needs_tools:
            self.logger.info("Mediator: explicit dissent detected — running ReAct tool loop.")
            await self._initialize_mcp_client()
            reasoning_text = await self.execute_tool_loop(prompt_messages)
        else:
            self.logger.info("Mediator: no dissent — fast path (single LLM call).")
            # Pass already-formatted content as BaseMessage list to avoid
            # ChatPromptTemplate interpreting literal { } inside report text
            # (e.g. JSON snippets) as template variables.
            from langchain_core.messages import BaseMessage, HumanMessage, SystemMessage

            direct_messages: list[BaseMessage] = []
            for role, content in prompt_messages:
                if role == "system":
                    direct_messages.append(SystemMessage(content=content))
                elif role == "human":
                    direct_messages.append(HumanMessage(content=content))
            try:
                response = await asyncio.wait_for(
                    self.llm.ainvoke(direct_messages),
                    timeout=float(get_settings().react_agent_timeout),
                )
            except TimeoutError:
                self.logger.error("Mediator fast-path timed out. Falling back to tool loop.")
                await self._initialize_mcp_client()
                reasoning_text = await self.execute_tool_loop(prompt_messages)
            else:
                reasoning_text = str(response.content)

        # Now extract the final structured output from the detailed reasoning.
        # IMPORTANT: reasoning_text may contain curly braces from LLM output
        # (e.g. JSON, {type}), so we use a template variable instead of f-string.
        extract_prompt = ChatPromptTemplate.from_messages(
            [
                (
                    "system",
                    "Extract the final structured verdict from the mediator's reasoning log.\n"
                    "You MUST produce a structured response with:\n"
                    "- contradictions: list of specific contradictions found\n"
                    "- resolution_summary: what was resolved and what remains\n"
                    "- confidence: float 0.0-1.0 (0.9+ means experts agree, no contradictions)",
                ),
                (
                    "human",
                    "{reasoning_log}",
                ),
            ]
        )

        # Structured output extraction with bounded retry; if every attempt
        # still fails, fall back to the regex-based extractor so the
        # negotiation loop can keep running.
        verdict = await self._extract_mediator_verdict(extract_prompt, reasoning_text)

        is_consensus = verdict.confidence >= CONSENSUS_THRESHOLD
        log_msg = "Consensus reached" if is_consensus else "No consensus yet"
        self.logger.info("%s (confidence=%.2f)", log_msg, verdict.confidence)

        finding = (
            f"{verdict.resolution_summary}\n\n"
            f"Contradictions: {'; '.join(verdict.contradictions) or 'None'}\n"
            f"Confidence: {verdict.confidence:.2f}"
        )
        argument = AgentArgument(
            agent_name="Mediator",
            finding=finding,
            confidence_score=verdict.confidence,
        )
        return argument, is_consensus

    async def give_verdict(
        self,
        reports: dict[str, str],
        history: list[AgentArgument],
        isr_reports: dict[str, AgentISR] | None = None,
        attck_validator: object | None = None,
        cascade_summary: CascadeSummary | None = None,
        memory_store: MemoryStore | None = None,
        evidence_corpus: set[str] | None = None,
        current_sample_id: str | None = None,
        cti_block: dict[str, Any] | None = None,
    ) -> Bundle:
        """Final judge decision returning a structured STIX 2.1 Bundle.

        Phase 4.2: When `attck_validator` is provided, all TTP IDs in
        `isr_reports` are validated against the ATT&CK dataset BEFORE the
        LLM call. The validation summary is injected into the prompt as a
        grounding block so the LLM can self-correct hallucinated IDs.

        Phase 4.3: When `cascade_summary` (CascadeSummary) is provided, a
        three-layer confidence ranking block is injected into the prompt so
        the LLM prioritizes corroborated (multi-layer) TTPs over single-layer
        evidence.

        Phase 5: When `memory_store` (MemoryStore protocol) is provided, the
        top-k most similar past analysis cases are retrieved and injected as
        few-shot context before the verdict LLM call.

        Triage CTI: When ``cti_block`` (the flat ``report["cti"]`` dict
        synthesised by ``TriageClient``) is provided, a compact summary of
        the deterministic CTI evidence (family, MITRE TTPs, C2, extracted
        secrets, dropped files, etc.) is injected into the prompt. The LLM
        is instructed to weigh it as ground-truth evidence, especially
        when analyst claims are sparse or conflict.

        Args:
            reports: Final expert reports (revised where applicable).
            history: Full negotiation history.
            isr_reports: Optional structured ISR objects for richer context.
            attck_validator: Optional ATTCKValidator instance.
            cascade_summary: Optional CascadeSummary from TTPCascadeEngine.
            memory_store: Optional MemoryStore for long-term case retrieval.
            cti_block: Optional flat CTI dict from the sandbox client
                (currently TriageClient's ``report["cti"]``).

        Returns:
            A valid STIX 2.1 Bundle with MITRE ATT&CK TTP mappings.
        """
        self.logger.info("Formulating final malware verdict with MITRE ATT&CK mapping...")

        # Build compact reports to avoid context bloat.
        # Full reports can exceed 15K tokens; we truncate each to ~500 chars
        # and only keep ISR claims + cascade summary.
        report_parts: list[str] = []
        for name, report in reports.items():
            truncated = report[:500] + "..." if len(report) > 500 else report
            report_parts.append(f"--- {name.upper()} ANALYST ---\n{truncated}")
        reports_text = "\n\n".join(report_parts)

        # Include ISR summaries (compact)
        if isr_reports:
            isr_block = "\n".join(
                f"[{name}] domain={isr.domain} | "
                f"claims={len(isr.claims)} | "
                f"mean_conf={isr.mean_confidence:.2f}"
                for name, isr in isr_reports.items()
                if isr.claims
            )
            if isr_block:
                reports_text += f"\n\n=== ISR SUMMARIES ===\n{isr_block}"

        # Phase 4.3: Three-layer TTP cascade block (compact)
        cascade_block = self._build_cascade_block(cascade_summary)
        if cascade_block:
            # Cascade blocks can be huge; keep only first 800 chars
            reports_text = f"{reports_text}\n\nCASCADE:\n{cascade_block[:800]}"

        # Phase 7.1: Schema hint (compact)
        schema_hint = self._build_schema_hint(reports, isr_reports)
        if schema_hint:
            reports_text = f"{reports_text}\n\n{schema_hint[:400]}"

        # Phase 5: Long-term memory — inject top-K similar past cases as
        # weighted priors. The block is bounded (~1.2 KB worst case for
        # top_k=3) and degrades gracefully to an empty string when the store
        # is empty or retrieval fails.
        memory_block = self._build_memory_context(
            isr_reports, memory_store, current_sample_id=current_sample_id
        )
        if memory_block:
            reports_text = f"{reports_text}\n\n{memory_block}"

        # Sandbox CTI block — deterministic evidence from the sandbox layer
        # (currently the TriageClient ``report["cti"]`` shape). Empty when
        # the active sandbox client does not synthesise CTI (mock / cape2).
        cti_text = _build_cti_block(cti_block)
        if cti_text:
            reports_text = f"{reports_text}\n\n{cti_text}"

        verdict_system = (
            "You are the Chief Malware Judge. Based on the expert reports below, "
            "provide a final verdict: Malware, Benign, or Suspicious.\n\n"
            "RULES:\n"
            "- Map findings to MITRE ATT&CK using AttackPattern objects (valid IDs: T#### or T####.###).\n"
            "- Omit technique ID if unsure.\n"
            "- On every Relationship, set x_maljan_confidence (0.0-1.0), "
            "x_maljan_evidence_basis (static|dynamic|network|all|unknown), "
            "and x_maljan_contributing_agents list.\n"
            "- ALL STIX object IDs MUST be ``<type>--<random uuid4>`` "
            "(spec-compliant 8-4-4-4-12 hex). NEVER reuse example UUIDs from "
            "the schema description. NEVER use ``<type>--T####`` (non-UUID).\n"
            "- DO NOT emit Indicator objects whose pattern values are inferred, "
            "hypothetical, or example. Every Indicator's pattern value MUST "
            "appear verbatim in the deterministic evidence (static strings, "
            "sandbox observations, or network IOCs). When in doubt, emit zero "
            "Indicators — the deterministic renderer will fill them in.\n"
            "- When a SANDBOX_CTI block is present, treat it as ground-truth "
            "deterministic evidence: families it lists MUST be reflected in "
            "the Bundle (Malware SDO), C2 entries become Indicator + "
            "Infrastructure SDOs, extracted credentials / mutexes / keys "
            "become Indicator objects with kind=other. Use it to corroborate "
            "or override sparse analyst claims.\n"
            "- Return ONLY a valid JSON STIX 2.1 Bundle. No markdown wrappers."
        )

        prompt = ChatPromptTemplate.from_messages(
            [
                ("system", verdict_system),
                (
                    "human",
                    "Expert Reports:\n{reports}\n\n"
                    "Negotiation History:\n{history}\n\n"
                    "Return a JSON STIX 2.1 Bundle.",
                ),
            ]
        )

        # Resolve the judge-specific timeout via the same override mechanism
        # the analyst agents use. ``react_agent_timeout_overrides`` ships
        # with ``{"static": 600, "judge": 300}`` so local Qwen3.6-35B has
        # enough headroom for the verdict round (the 2026-05-23 E2E run hit
        # the previous hardcoded 180s ceiling). Falls back to the global
        # ``react_agent_timeout`` when no override is configured.
        _settings = get_settings()
        _overrides = getattr(_settings, "react_agent_timeout_overrides", {}) or {}
        timeout = float(_overrides.get("judge", _settings.react_agent_timeout))
        self.logger.info("JudgeAgent invoking verdict LLM (timeout=%ds)...", timeout)
        try:
            result_text = await asyncio.wait_for(
                (prompt | self.llm).ainvoke(
                    {"reports": reports_text, "history": str(history)[:800]}
                ),
                timeout=timeout,
            )
        except TimeoutError:
            self.logger.error("JudgeAgent verdict timed out after %ds.", timeout)
            return self._fallback_bundle_from_text("[TIMEOUT]", reports, isr_reports)

        # Extract JSON from markdown code blocks or raw text
        raw = str(getattr(result_text, "content", result_text))

        from maljan.utils.json_cleaner import safe_parse_json

        data = safe_parse_json(raw)
        if data is None:
            self.logger.warning(
                "LLM did not return valid JSON. Attempting text-based fallback Bundle."
            )
            bundle = self._fallback_bundle_from_text(raw, reports, isr_reports)
            return bundle

        if not isinstance(data, dict):
            self.logger.warning(
                "LLM returned JSON that is not a dict (type=%s). Falling back to text.",
                type(data).__name__,
            )
            bundle = self._fallback_bundle_from_text(raw, reports, isr_reports)
            return bundle

        try:
            # Filter out hallucinated / invalid technique IDs
            data = self._filter_invalid_technique_ids(data)
            # Audit 2026-05-17: rewrite placeholder/non-UUID STIX IDs
            # (J-01), drop indicators whose pattern value isn't in the
            # deterministic evidence (J-02), and back-fill
            # ``attack-pattern.external_references`` (REP-01).
            from maljan.agents.judge_postprocess import postprocess_judge_bundle

            # Wave 9 (2026-05-29): when a cascade summary is available,
            # derive the set of TIDs that survived the cascade and pass it
            # to REP-02 so orphan attack-patterns (TTPs the LLM emitted
            # but the deterministic pipeline rejected) are dropped from
            # the bundle before validation.
            valid_tids: frozenset[str] | None = None
            if cascade_summary is not None:
                valid_tids = frozenset(
                    r.technique_id for r in cascade_summary.results if r.technique_id
                )
            data = postprocess_judge_bundle(
                data,
                evidence_corpus=evidence_corpus,
                valid_technique_ids=valid_tids,
            )
            return Bundle.model_validate(data)
        except Exception as e:
            self.logger.warning(
                "LLM did not return a valid Bundle: %s. Attempting text-based fallback.", e
            )
            bundle = self._fallback_bundle_from_text(raw, reports, isr_reports)
            return bundle

    async def _extract_mediator_verdict(
        self,
        extract_prompt: ChatPromptTemplate,
        reasoning_text: str,
        max_attempts: int = 3,
        base_delay: float = 0.5,
    ) -> MediatorVerdict:
        """Run ``with_structured_output`` with bounded exponential-backoff retry.

        ``with_structured_output`` itself may raise for providers that don't
        support the structured-output path — we build the wrapper inside the
        loop so a provider-level failure also routes through the fallback.

        PORTABLE-RESPONSE-FORMAT-01 (audit 2026-05-19): check the provider
        capability table before attempting ``with_structured_output``.
        Ollama (and any future provider that lacks tool-calling) is routed
        directly to the text fallback so we don't pay 3 retry rounds for a
        feature that will never work. The capability table lives in
        ``maljan.llm.registry``.
        """
        # Sniff the active provider name; the fallback is harmless if we
        # can't determine it.
        try:
            from maljan.core.container import ServiceContainer  # noqa: F401 (typing only)
            from maljan.llm.registry import provider_capabilities

            cfg = getattr(self, "_config", None)
            provider_name = (
                cfg.llm.provider
                if cfg is not None
                else getattr(self.llm, "_llm_type", "openai") or "openai"
            )
            caps = provider_capabilities(str(provider_name))
        except Exception:
            caps = {"supports_structured_output": True}

        if not caps.get("supports_structured_output", True):
            self.logger.info(
                "Provider lacks structured-output support; using text fallback "
                "for mediator verdict extraction."
            )
            return self._fallback_mediate(reasoning_text)

        last_exc: Exception | None = None
        for attempt in range(1, max_attempts + 1):
            try:
                llm_structured = self.llm.with_structured_output(MediatorVerdict)
                result = await (extract_prompt | llm_structured).ainvoke(
                    {"reasoning_log": reasoning_text}
                )
                if isinstance(result, MediatorVerdict):
                    return result
                raise ValueError(
                    f"Structured output produced unexpected type: {type(result).__name__}"
                )
            except Exception as exc:
                last_exc = exc
                self.logger.warning(
                    "Structured mediator output failed (attempt %d/%d): %s",
                    attempt,
                    max_attempts,
                    exc,
                )
                if attempt < max_attempts:
                    await asyncio.sleep(base_delay * (2 ** (attempt - 1)))

        self.logger.error(
            "Structured mediator output exhausted retries (%d). Falling back to text extraction. "
            "Last error: %s",
            max_attempts,
            last_exc,
        )
        return self._fallback_mediate(reasoning_text)

    # ------------------------------------------------------------------
    # Verdict keyword detection (used by the text fallback path)
    # ------------------------------------------------------------------

    @staticmethod
    def _verdict_from_text(text: str) -> str:
        """Token-level verdict extraction.

        The previous implementation searched for ``"malware"`` and
        ``"benign"`` as substrings, which let phrases like *"not malware"*
        or *"likely not benign"* flip the result. We now tokenise into
        word-shape segments and ignore negation neighbours.
        """
        import re

        tokens = re.findall(r"[a-z]+", text.lower())
        if not tokens:
            return "Suspicious"

        negators = {"not", "no", "non", "neither", "without", "isn't"}
        for i, tok in enumerate(tokens):
            if tok == "malware":
                prev = tokens[i - 1] if i > 0 else ""
                if prev not in negators and prev != "non":
                    return "Malware"
        for i, tok in enumerate(tokens):
            if tok in {"benign", "clean"} or tok.startswith("non-malicious"):
                prev = tokens[i - 1] if i > 0 else ""
                if prev not in negators:
                    return "Benign"
        return "Suspicious"

    def _filter_invalid_technique_ids(self, data: dict[str, Any]) -> dict[str, Any]:
        """Remove objects with invalid / hallucinated technique IDs from the Bundle data.

        Valid MITRE ATT&CK technique IDs match the pattern T#### or T####.###
        (e.g. T1055, T1055.001). Anything else (T0000, T123, T12345, etc.) is
        treated as hallucinated and the object is removed.

        Audit 2026-05-19 FILT-COVERAGE-01: the previous implementation only
        inspected the Maljan-custom ``x_maljan_technique_id`` field. STIX-
        standard technique IDs surface in ``external_references[*].external_id``
        and (for LLM-emitted SDOs) the ``name`` field, so we now check those
        as well. ``_INVALID_TIDS`` is reused so curated placeholders such as
        ``T0000`` get filtered even though they match the regex.
        """
        import re

        _VALID_TID_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
        _CURATED_PLACEHOLDERS = frozenset({"T0000", "T0000.000", "T9999", "T1234"})

        def _technique_id_is_bad(tid: str) -> bool:
            if not tid:
                return False
            if tid in _CURATED_PLACEHOLDERS:
                return True
            return not bool(_VALID_TID_RE.match(tid))

        def _extract_ids_from(obj: dict[str, Any]) -> list[str]:
            candidates: list[str] = []
            tid = obj.get("x_maljan_technique_id")
            if isinstance(tid, str):
                candidates.append(tid)
            for ref in obj.get("external_references") or []:
                if isinstance(ref, dict):
                    ext_id = ref.get("external_id")
                    src = (ref.get("source_name") or "").lower()
                    # Only enforce on MITRE-tagged refs; Sigma rule IDs etc.
                    # would otherwise fail the T#### regex.
                    if isinstance(ext_id, str) and src in {"mitre-attack", "mitre attack"}:
                        candidates.append(ext_id)
            # AttackPattern SDOs whose ``name`` is itself a T#### string
            # (the SIG-T0000-01 leak path) — only check ``name`` for
            # attack-pattern objects.
            if obj.get("type") == "attack-pattern":
                name = obj.get("name")
                if isinstance(name, str) and name.startswith("T") and len(name) <= 12:
                    candidates.append(name)
            return candidates

        objects = data.get("objects", [])
        filtered: list[dict[str, Any]] = []
        removed = 0
        for obj in objects:
            offending = [tid for tid in _extract_ids_from(obj) if _technique_id_is_bad(tid)]
            if offending:
                removed += 1
                self.logger.warning(
                    "Removing STIX object %s with invalid technique ID(s) %s.",
                    obj.get("id", "unknown"),
                    offending,
                )
                continue
            filtered.append(obj)
        if removed:
            self.logger.info("Filtered %d objects with invalid technique IDs.", removed)
            data["objects"] = filtered
        return data

    def _fallback_bundle_from_text(
        self,
        text: str,
        reports: dict[str, str],
        isr_reports: dict[str, AgentISR] | None = None,
    ) -> Bundle:
        """Build a minimal STIX Bundle when the LLM fails to produce valid JSON.

        Extracts the verdict from the text response and creates a minimal Bundle
        with an Identity, Malware, and Report object so the pipeline never
        returns an empty Bundle.
        """
        from maljan.schemas.stix_models import Bundle

        decision = self._verdict_from_text(text)

        self.logger.info(
            "Fallback Bundle: extracted verdict='%s' from text response (%d chars).",
            decision,
            len(text),
        )

        # Gather any valid technique IDs from the raw text and ISR claims
        import re

        _VALID_TID_RE = re.compile(r"\b(T\d{4}(?:\.\d{3})?)\b")
        tids = set(_VALID_TID_RE.findall(text))
        if isr_reports:
            for isr in isr_reports.values():
                for claim in isr.claims:
                    if claim.technique_id and _VALID_TID_RE.match(claim.technique_id):
                        tids.add(claim.technique_id)

        malware_id = f"malware--{uuid.uuid4()}"
        # Don't bake the raw fallback text (which may contain ``[TIMEOUT]``
        # or other internal markers) into the malware SDO description —
        # downstream cross-layer aggregation can upgrade the verdict in
        # ``report_node`` and the user-visible description should reflect
        # the final verdict, not the intermediate fallback. The judge
        # rationale is preserved in ``x_maljan_fallback_reasoning`` for
        # debug consumers.
        text_snippet = (text[:2000] if text else "No structured output available.").replace(
            "\n", " "
        )
        objects: list[dict[str, Any]] = [
            {
                "type": "malware",
                "id": malware_id,
                "name": "analyzed-sample",
                "malware_types": ["unknown"],
                "is_family": False,
                "description": (
                    f"Verdict: {decision} (judge fallback; subject to cross-layer review)"
                ),
                "x_maljan_fallback_reasoning": text_snippet,
            },
        ]

        for tid in sorted(tids):
            attack_id = f"attack-pattern--{uuid.uuid4()}"
            objects.append(
                {
                    "type": "attack-pattern",
                    "id": attack_id,
                    "name": tid,
                    "external_references": [
                        {
                            "source_name": "mitre-attack",
                            "external_id": tid,
                            "url": f"https://attack.mitre.org/techniques/{tid}",
                        }
                    ],
                }
            )
            objects.append(
                {
                    "type": "relationship",
                    "id": f"relationship--{uuid.uuid4()}",
                    "relationship_type": "uses",
                    "source_ref": malware_id,
                    "target_ref": attack_id,
                    "x_maljan_confidence": 0.5,
                    "x_maljan_evidence_basis": "unknown",
                    "x_maljan_contributing_agents": [],
                    "x_maljan_technique_id": tid,
                }
            )

        return Bundle.model_validate({"objects": objects})

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _build_validation_block(
        self,
        isr_reports: dict[str, AgentISR] | None,
        attck_validator: object | None,
    ) -> str:
        """Run ATT&CK TTP validation and return a prompt-ready block.

        Returns an empty string if validation cannot be run (no validator,
        no isr_reports, or any runtime error — always degrades gracefully).
        """
        if not attck_validator or not isr_reports:
            return ""

        # Runtime duck-type check — avoids circular import at module level
        if not hasattr(attck_validator, "validate_isr_reports"):
            self.logger.warning(
                "attck_validator does not implement validate_isr_reports(). Skipping."
            )
            return ""

        try:
            summary = attck_validator.validate_isr_reports(isr_reports)  # type: ignore[union-attr]
            if summary.total_claims == 0:
                return ""
            block = str(summary.to_prompt_block())
            self.logger.info(
                "ATT&CK validation: %d/%d valid, %d hallucinated, %d low-alignment.",
                summary.valid_ids,
                summary.total_claims,
                summary.invalid_ids,
                summary.low_alignment,
            )
            return block
        except Exception as exc:
            self.logger.warning("ATT&CK TTP validation failed (%s). Proceeding without it.", exc)
            return ""

    def _build_cascade_block(self, cascade_summary: CascadeSummary | None) -> str:
        """Return a prompt-ready three-layer TTP cascade block.

        Returns an empty string if no summary is provided or if it contains
        no results. Always degrades gracefully on any error.
        """
        if cascade_summary is None:
            return ""

        if not hasattr(cascade_summary, "to_prompt_block"):
            self.logger.warning("cascade_summary does not implement to_prompt_block(). Skipping.")
            return ""

        try:
            if not getattr(cascade_summary, "total_techniques", 0):
                return ""
            block = cascade_summary.to_prompt_block()  # type: ignore[union-attr]
            self.logger.info(
                "TTP cascade: %d techniques, %d corroborated, %d consensus.",
                getattr(cascade_summary, "total_techniques", 0),
                getattr(cascade_summary, "corroborated_count", 0),
                getattr(cascade_summary, "consensus_count", 0),
            )
            return block
        except Exception as exc:
            self.logger.warning("TTP cascade block failed (%s). Proceeding without it.", exc)
            return ""

    def _build_confidence_instruction(self, cascade_summary: CascadeSummary | None) -> str:
        """Build cascade-derived x_maljan_confidence hint block for the verdict prompt.

        When a CascadeSummary is available, the top techniques' weighted
        confidence scores and contributing layers are extracted and rendered as
        a reference table. The LLM uses this to populate x_maljan_confidence
        and x_maljan_evidence_basis fields accurately rather than guessing.

        Returns an empty string when cascade is unavailable or has no results.
        Always degrades gracefully.
        """
        if cascade_summary is None:
            return ""

        try:
            top = cascade_summary.top_techniques(n=10)
            if not top:
                return ""

            lines = [
                "CONFIDENCE REFERENCE TABLE (use these values for x_maljan_confidence):",
                "Technique ID | Weighted Confidence | Layers | Evidence Basis",
                "-" * 70,
            ]
            for r in top:
                layers = r.contributing_layers
                # Map layer set → evidence_basis controlled vocab
                if set(layers) == {"static", "dynamic", "network"}:
                    basis = "all"
                elif len(layers) == 2:  # noqa: PLR2004
                    basis = "+".join(sorted(layers))
                elif len(layers) == 1:
                    basis = layers[0]
                else:
                    basis = "unknown"

                lines.append(
                    f"{r.technique_id:<14} | {r.weighted_confidence:.3f}              "
                    f"| {', '.join(layers):<22} | {basis}"
                )

            return "\n".join(lines)
        except Exception as exc:
            self.logger.warning("_build_confidence_instruction failed (%s). Skipping.", exc)
            return ""

    def _build_schema_hint(
        self,
        reports: dict[str, str],
        isr_reports: dict[str, AgentISR] | None,
    ) -> str:
        """Infer malware category and return a STIX schema pruning hint block.

        Phase 7.1 (Dynamic Schema Pruning): Runs keyword-weighted inference
        over the combined analyst reports and ISR claims to detect the malware
        behavioral category (ransomware, RAT, dropper, worm, infostealer).

        When a specific category is detected, returns a prompt block guiding
        the LLM to focus on the STIX object types most relevant to that
        category, implementing the CTI-GEN schema-pruning methodology.

        Returns an empty string when category is UNKNOWN (no pruning) or on
        any inference error. Always degrades gracefully.

        Args:
            reports:     Final expert reports.
            isr_reports: Structured ISR objects (optional but improves signal).

        Returns:
            Prompt-ready schema pruning block, or empty string.
        """
        try:
            category = infer_category(reports, isr_reports, backend=self.category_backend)
            hint = get_pruned_schema_hint(category)
            if hint:
                self.logger.info(
                    "Schema pruning: inferred category '%s' (backend=%s).",
                    category.value,
                    self.category_backend,
                )
            else:
                self.logger.debug("Schema pruning: category UNKNOWN, no pruning applied.")
            return hint
        except Exception as exc:
            self.logger.warning("_build_schema_hint failed (%s). Skipping schema pruning.", exc)
            return ""

    def _fallback_mediate(
        self,
        reasoning_text: str,
    ) -> MediatorVerdict:
        """Plain-text fallback when structured output is unavailable.

        Extracts confidence from the reasoning text using regex and returns
        a minimal MediatorVerdict.
        """
        confidence = self._extract_confidence_from_text(reasoning_text)
        return MediatorVerdict(
            contradictions=[],
            resolution_summary=reasoning_text[:500],
            confidence=confidence,
        )

    @staticmethod
    def _extract_confidence_from_text(text: str) -> float:
        """Last-resort regex extraction for providers that ignore structured output."""
        for line in reversed(text.strip().splitlines()):
            if "confidence" in line.lower():
                parts = line.replace(":", " ").split()
                for part in reversed(parts):
                    try:
                        return max(0.0, min(1.0, float(part)))
                    except ValueError:
                        continue
        return 0.5

    @staticmethod
    def _build_memory_context(
        isr_reports: dict | None,
        memory_store: MemoryStore | None,
        current_sample_id: str | None = None,
    ) -> str:
        """Retrieve similar past cases and format them as a few-shot prompt block.

        Phase 5 implementation. Queries the MemoryStore with a summary of the
        current ISR claims. The retrieved cases are formatted as a structured
        context block to help the judge leverage historical analysis patterns.

        The judge is explicitly instructed to treat retrieved cases as weighted
        priors — not to copy technique IDs blindly, but to corroborate them with
        current evidence. This prevents retrieval hallucination (assuming a past
        case's TTPs must apply to the current sample).

        Args:
            isr_reports: Current ISR reports (used to build the search query).
            memory_store: MemoryStore-protocol object, or None to skip.

        Returns:
            Formatted prompt block string, or "" when store is None/empty or
            no similar cases are found.
        """
        if memory_store is None or not isr_reports:
            return ""

        # Build search query from all current ISR claims
        query_parts: list[str] = []
        for isr in isr_reports.values():
            for claim in isr.claims:
                query_parts.append(claim.claim)
                if claim.evidence_ref:
                    query_parts.append(claim.evidence_ref)
                if claim.technique_id:
                    query_parts.append(claim.technique_id)
        query = " ".join(query_parts)

        if not query.strip():
            return ""

        try:
            # Audit 2026-05-17 LTM-01: never retrieve the current
            # sample's own past run as a "weighted prior". Newer
            # QdrantStore.retrieve accepts ``exclude_sample_id``; older
            # MemoryStore implementations (InMemoryStore in tests) may
            # not — fall back to the unfiltered call in that case.
            try:
                cases = memory_store.retrieve(
                    query,
                    top_k=3,
                    exclude_sample_id=current_sample_id,
                )
            except TypeError:
                cases = memory_store.retrieve(query, top_k=3)
                if current_sample_id:
                    cases = [c for c in cases if c.sample_id != current_sample_id]
        except Exception:  # noqa: BLE001
            # Never let retrieval failure block verdict generation
            return ""

        if not cases:
            return ""

        total = len(cases)
        lines: list[str] = [
            "=== LONG-TERM MEMORY: Similar Past Case(s) ===",
            "Use these historical analyses as WEIGHTED PRIORS for TTP selection.",
            "Do NOT copy technique IDs blindly — corroborate with current evidence.",
            "",
        ]

        for idx, case in enumerate(cases, 1):
            ttps = ", ".join(case.technique_ids) if case.technique_ids else "none"
            summary = (
                (case.summary_text[:200] + "...")
                if len(case.summary_text) > 200
                else case.summary_text
            )
            lines.append(
                f"[{idx}/{total}] sample_id: {case.sample_id} (category: {case.malware_category})"
            )
            lines.append(f"  Past techniques: {ttps}")
            lines.append(f"  Behavioral summary: {summary}")

        lines.append("=== END LONG-TERM MEMORY ===")
        return "\n".join(lines)


def _build_cti_block(cti: dict[str, Any] | None) -> str:
    """Render the flat sandbox CTI dict into a compact prompt section.

    Returns ``""`` when ``cti`` is None / empty / contains no signal so the
    judge prompt stays small for runs that did not go through a CTI-aware
    sandbox (mock / CAPEv2 / Triage with empty observations).

    Lists are truncated to keep the prompt bounded — full data still lives
    on ``report["cti"]`` for downstream consumers.
    """
    if not isinstance(cti, dict) or not cti:
        return ""

    def _head(items: Any, n: int = 8) -> list[Any]:
        if not isinstance(items, list):
            return []
        return items[:n]

    family = _head(cti.get("family"))
    ttp = _head(cti.get("ttp"), n=12)
    tags = _head(cti.get("tags"))
    c2 = cti.get("c2") or {}
    c2_urls = _head(c2.get("urls"), n=5)
    c2_doms = _head(c2.get("domains"), n=8)
    c2_ips = _head(c2.get("ips"), n=8)
    mutexes = _head(cti.get("mutexes"), n=4)
    keys = _head(cti.get("keys"), n=3)
    creds = _head(cti.get("credentials"), n=3)
    dropped = _head(cti.get("dropped_files"), n=5)
    dropper_urls = _head(cti.get("dropper_urls"), n=3)
    ransom = _head(cti.get("ransom_notes"), n=2)
    net = cti.get("network") or {}
    net_doms = _head(net.get("domains"), n=8)
    net_ips = _head(net.get("ips"), n=8)
    net_urls = _head(net.get("http_urls"), n=5)
    sni = _head(net.get("tls_sni"), n=4)
    ja3 = _head(net.get("tls_ja3"), n=3)
    ja3s = _head(net.get("tls_ja3s"), n=3)
    indicators = _head(cti.get("indicators"), n=5)
    yara_rules = _head(cti.get("yara_rules"), n=5)
    score = cti.get("score")

    # Skip the block entirely when nothing CTI-worthy survived the synth.
    if not any(
        (
            family,
            ttp,
            tags,
            c2_urls,
            c2_doms,
            c2_ips,
            mutexes,
            keys,
            creds,
            dropped,
            dropper_urls,
            ransom,
            net_doms,
            net_ips,
            net_urls,
            sni,
            ja3,
            indicators,
            yara_rules,
            score is not None,
        )
    ):
        return ""

    lines: list[str] = ["=== SANDBOX_CTI (deterministic, treat as ground-truth) ==="]
    if score is not None:
        lines.append(f"sandbox_score: {score}/10")
    if family:
        lines.append(f"family: {family}")
    if ttp:
        lines.append(f"mitre_ttp: {ttp}")
    if tags:
        lines.append(f"tags: {tags}")
    if c2_urls or c2_doms or c2_ips:
        lines.append("c2:")
        if c2_urls:
            lines.append(f"  urls: {c2_urls}")
        if c2_doms:
            lines.append(f"  domains: {c2_doms}")
        if c2_ips:
            lines.append(f"  ips: {c2_ips}")
    if mutexes:
        lines.append(f"mutexes: {mutexes}")
    if keys:
        lines.append(f"extracted_keys ({len(keys)}): {keys}")
    if creds:
        lines.append(f"credentials_count: {len(creds)}")
    if dropped:
        dropped_short = [
            {"name": d.get("name"), "sha256": (d.get("sha256") or "")[:16] + "..."}
            for d in dropped
            if isinstance(d, dict)
        ]
        lines.append(f"dropped_files: {dropped_short}")
    if dropper_urls:
        lines.append(f"dropper_urls: {dropper_urls}")
    if ransom:
        lines.append(f"ransom_notes: {len(ransom)} extracted")
    if net_doms or net_ips or net_urls:
        lines.append("network_iocs:")
        if net_doms:
            lines.append(f"  domains: {net_doms}")
        if net_ips:
            lines.append(f"  ips: {net_ips}")
        if net_urls:
            lines.append(f"  urls: {net_urls}")
    if sni:
        lines.append(f"tls_sni: {sni}")
    if ja3:
        lines.append(f"tls_ja3: {ja3}")
    if ja3s:
        lines.append(f"tls_ja3s: {ja3s}")
    if indicators:
        ind_short = [i.get("ioc", "") for i in indicators if isinstance(i, dict) and i.get("ioc")]
        if ind_short:
            lines.append(f"sandbox_indicators: {ind_short}")
    if yara_rules:
        lines.append(f"yara_rules: {yara_rules}")
    lines.append("=== END SANDBOX_CTI ===")
    return "\n".join(lines)
