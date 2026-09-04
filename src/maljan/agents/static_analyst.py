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
from maljan.providers.base import StaticJobContext
from maljan.schemas.isr_models import AgentISR, ClaimEvidence

# The provider-independent head of the static system prompt. Everything that
# names a tool lives in the provider's fragment, so attaching radare2 or capa
# changes the middle and nothing else. A golden test pins the assembled result
# byte for byte against the prompt this project measured its evaluation on.
_ISR_HEAD = (
    "You are an expert Static Malware Analyst with 15 years of reverse engineering experience. "
)

# Empty today. Declared because the assembly order is the contract sub-projects
# B and C build agent prompts from, and an implicit empty tail is a trap.
_ISR_TAIL = ""


def _static_prompt(provider: Any | None = None) -> str:
    """Assemble the static system prompt for ``provider`` (the configured one by default)."""
    if provider is None:
        from maljan.core.config import get_settings
        from maljan.providers.registry import get_static_provider

        provider = get_static_provider(get_settings())
    return _ISR_HEAD + provider.prompt_fragment() + _ISR_TAIL


# Back-compat: several modules and tests import this name. It is the default
# profile's assembled prompt, which is what it always was.
_ISR_SYSTEM = _static_prompt()


# BUG-07 (2026-06-23 live-UI audit): the deterministic raw-data slot.
_STATIC_RAW_PLACEHOLDER_RE = re.compile(r"^\s*no\s+\w+\s+data\s+available\b", re.IGNORECASE)


def _reframe_static_raw_data(data: str, has_tools: bool) -> str:
    """Rephrase the 'No static data available' file-loader placeholder.

    BUG-07: for a freshly uploaded sample there is no pre-extracted
    ``data/samples/static/<sha>.json`` fixture, so
    ``FileBasedLoader.load(sha, "static")`` returns the literal placeholder
    "No static data available for sample <sha>." When that text lands in the
    revision prompt's RAW DATA slot, the small reasoning model treats it as
    authoritative and OVERWRITES its good live-Ghidra analysis with a defeatist
    "static analysis could not be performed" claim — even though its tool calls
    returned real ``get_current_program_info`` / ``detect_malware_behaviors``
    data. When the analyst has live Ghidra tools we swap the misleading
    placeholder for an explicit instruction to rely on the tool-derived ORIGINAL
    REPORT. Fail-safe: returns ``data`` unchanged for real data, or when the
    analyst has no tools (then the placeholder genuinely means "no evidence").
    """
    if not has_tools or not data:
        return data
    if _STATIC_RAW_PLACEHOLDER_RE.match(data.strip()):
        return (
            "No pre-extracted static fixture is available for this sample. This is "
            "EXPECTED for a freshly analysed binary and does NOT mean static analysis "
            "is impossible — your live Ghidra tool findings in YOUR ORIGINAL REPORT "
            "above are the authoritative static evidence. Revise from those findings; "
            "do NOT claim the binary data is missing or that analysis could not be performed."
        )
    return data


# Moved to maljan.providers.static.ghidra in the provider layer (2026-09-03).
# Re-exported so the modules and tests that import them from here keep working;
# removed in the last task of the provider plan.
from maljan.providers.static.ghidra import (  # noqa: E402
    GHIDRA_ALLOWED_TOOLS as _GHIDRA_ALLOWED_TOOLS_MODULE,
)
from maljan.providers.static.ghidra import GhidraStaticProvider  # noqa: E402


class _LegacyGhidraJob:
    """Live job view for the deprecated per-analyst delegations below.

    ``nodes.py`` still mutates ``_analysis_file_path`` / ``_sample_categories``
    on the agent instance itself (Task 10 moves this to a real
    ``StaticJobContext`` passed through ``open()``); wrapping the agent instead
    of snapshotting its attributes keeps the classic late-binding behaviour
    that ``tests/unit/test_load_program_pinning.py`` pins — a tool wrapped
    before a later path reassignment must still read the reassigned value at
    call time.
    """

    def __init__(self, agent: StaticAnalyst) -> None:
        self._agent = agent

    @property
    def mirror_sample_path(self) -> str | None:
        return getattr(self._agent, "_analysis_file_path", None)

    @property
    def capability_categories(self) -> Any:
        return getattr(self._agent, "_sample_categories", None)


@register_agent("static")
class StaticAnalyst(BaseAnalyst):
    """Specialized agent for evaluating decompiled code and strings via the configured static provider."""

    # ------------------------------------------------------------------
    # MCP Tool Interface
    # ------------------------------------------------------------------

    # Moved to maljan.providers.static.ghidra in the provider layer (2026-09-03).
    _GHIDRA_ALLOWED_TOOLS: frozenset[str] = _GHIDRA_ALLOWED_TOOLS_MODULE

    # Container-visible path of the current sample, assigned per-run by the
    # pipeline (nodes.py) alongside ``_sample_categories``. Read at CALL time
    # by the load_program wrapper (late binding — the agent is cached across
    # samples and tools may be selected before the pipeline sets the path).
    _analysis_file_path: str | None = None

    def _resolve_ghidra_provider(self) -> GhidraStaticProvider:
        """The provider that now owns this logic, for the four delegations below.

        Prefers the job's container-cached provider when it actually is
        Ghidra; otherwise builds a standalone instance from today's settings,
        which is what keeps a bare analyst — ``tests/unit/test_load_program_pinning.py``
        constructs one with ``StaticAnalyst.__new__`` — working. ``memory`` is
        never read by any of the four delegated methods, so the fallback does
        not need a real one. Reads ``static.ghidra`` directly: the transitional
        ``mcp``-namespaced mirror this shim used to prefer is gone (Task 12).
        """
        from maljan.core.config import MemoryConfig, get_settings

        container = getattr(self, "_container", None)
        provider = container.get_static_provider() if container is not None else None
        if not isinstance(provider, GhidraStaticProvider):
            cfg = get_settings()
            provider = GhidraStaticProvider(cfg.static.ghidra, cfg.preprocessing, MemoryConfig())
        provider._job = _LegacyGhidraJob(self)  # type: ignore[assignment]
        return provider

    def _ghidra_tool_mode(self) -> str:
        """Deprecated: the mode logic now lives on ``GhidraStaticProvider._tool_mode``."""
        return self._resolve_ghidra_provider()._tool_mode()

    def _select_ghidra_tools(
        self, tools: list[Any], categories: set[str] | None = None
    ) -> list[Any]:
        """Deprecated: the selection logic now lives on ``GhidraStaticProvider.select_tools``."""
        return self._resolve_ghidra_provider().select_tools(tools, categories)

    def _pin_load_program_path(self, tools: list[Any]) -> list[Any]:
        """Deprecated: the pinning logic now lives on ``GhidraStaticProvider``."""
        return self._resolve_ghidra_provider()._pin_load_program_path(tools)

    def _wrap_load_program(self, tool: Any) -> Any:
        """Deprecated: the wrapping logic now lives on ``GhidraStaticProvider``."""
        return self._resolve_ghidra_provider()._wrap_load_program(tool)

    def _refine_tools_for_sample(self, host_path: str | None) -> None:
        """In dynamic mode, narrow ``self.tools`` to the sample's relevant tools.

        Cheaply derives capability categories from the PE import classification
        (no Ghidra call) and re-selects from the full pool. No-op unless dynamic
        mode is active and the full pool was captured. Fail-safe.
        """
        if self._ghidra_tool_mode() != "dynamic":
            return
        pool = getattr(self, "_all_ghidra_tools", None)
        if not pool or not host_path:
            return
        try:
            from maljan.analysis.import_capability_layer import _imports_by_category
            from maljan.extractors.pe_extractor import build_static_analysis

            static = build_static_analysis(sample_path=host_path)
            categories = set(_imports_by_category(static).keys()) if static else set()
            self.tools = self._select_ghidra_tools(pool, categories)
        except Exception as e:  # noqa: BLE001
            self.logger.warning("Dynamic tool selection failed (%s); keeping current set.", e)

    def _provider(self) -> Any:
        """The static provider for this run: the container's, or one built ad hoc."""
        container = getattr(self, "_container", None)
        if container is not None:
            return container.get_static_provider()
        from maljan.core.config import get_settings
        from maljan.providers.registry import get_static_provider

        return get_static_provider(get_settings())

    def _initialize_mcp_client(self) -> None:
        """Attach the configured static provider's tools. Idempotent per sample.

        Everything this used to do — transports, clients, guardrails, the shared
        agent loop — moved into ``GhidraStaticProvider.open``. What is left is
        the analyst's half of the contract: ask, and narrow.
        """
        provider = self._provider()
        if not provider.capabilities.provides_tools:
            self.logger.info("Static provider '%s' exposes no tools.", provider.id)
            self.tools = []
            return
        provider.open(self._job_context())
        pool = provider.get_tools()
        self._all_ghidra_tools = pool  # kept: the report and tests read this name
        # No ``self.toolkit`` assignment here: the provider holds its own client
        # privately and closes it itself (``ServiceContainer.aclose`` calls
        # ``get_static_provider().close()``), so there is nothing for this
        # analyst's ``close_tools()`` to release on the static path.
        self.tools = provider.select_tools(pool, getattr(self, "_sample_categories", None))
        self.logger.info(
            "Static provider '%s': %d/%d tools attached.", provider.id, len(self.tools), len(pool)
        )

    def _job_context(self) -> StaticJobContext:
        from maljan.core.config import get_settings

        cfg = get_settings()
        guardrail = None
        if cfg.preprocessing.use_function_summarizer:
            # Reuse the container that owns this agent. Constructing a fresh
            # one here rebuilt the 2651-rule Sigma layer, the YARA layer and a
            # new set of LLM clients — and this runs once per chunk, so a run
            # with ten static chunks built ten of them and dropped them all.
            container = getattr(self, "_container", None)
            if container is not None:
                summarizer = container.get_function_summarizer()
                if summarizer is not None:
                    guardrail = summarizer.summarize_chunk
        return StaticJobContext(
            host_sample_path=getattr(self, "_host_sample_path", None),
            mirror_sample_path=getattr(self, "_analysis_file_path", None),
            capability_categories=frozenset(getattr(self, "_sample_categories", None) or ()),
            output_guardrail=guardrail,
            max_output_chars=cfg.preprocessing.max_tool_output_chars,
            truncation_ledger=getattr(self, "truncation_ledger", None),
        )

    def _static_capabilities(self) -> Any:
        """The provider's degrade policy: Ghidra's is loud, others may differ."""
        return self._provider().capabilities

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
        # Ghidra-specific by construction: this pre-pass drives the headless
        # Ghidra REST API directly (load_program / call graph), not a
        # capability any other static provider could satisfy. Generalising it
        # behind a capability flag is sub-project C's, not this one's.
        if cfg.static.ghidra.transport != "http":
            return ""  # the pre-pass speaks the headless REST API directly

        try:
            import httpx

            from maljan.analysis.sink_reachability import build_priority_hint

            base = cfg.static.ghidra.url.rstrip("/")
            token = cfg.static.ghidra.auth_token
            headers = {"Authorization": f"Bearer {token}"} if token else {}
            from maljan.analysis.ghidra_program import (
                SWITCH_PARAM,
                SWITCH_PATH,
                program_name_from_load,
            )

            with httpx.Client(timeout=120.0, headers=headers) as http:
                loaded = http.post(f"{base}/load_program", json={"file": file_path})
                loaded.raise_for_status()
                # Loading is not looking. `load_program` sets Ghidra's current
                # program only when nothing is current yet, so from the second
                # sample of a container's lifetime onwards this pre-pass was
                # building its hint from the *first* binary — measured
                # 2026-08-10 as byte-identical call graphs across samples that
                # shared nothing. The switch is what makes the next two calls
                # describe the file we were asked about.
                name = program_name_from_load(loaded.text)
                if not name:
                    # A failed load answers **200** with
                    # {"error": "Failed to load program from: ..."}, so
                    # raise_for_status sees nothing wrong. Carrying on would
                    # analyse and describe whichever program is still current —
                    # a hint about a different binary, handed to the analyst as
                    # guidance for this one. Measured 2026-08-10: once the
                    # server began refusing loads, 66 consecutive samples
                    # produced a call graph of identical length.
                    #
                    # No hint is better than a wrong hint; the analyst's
                    # documented fallback is to proceed without one.
                    self.logger.warning(
                        "Sink-reachability pre-pass: load_program did not yield a program "
                        "for '%s' (%s) — skipping the hint rather than describing whichever "
                        "binary is still loaded.",
                        file_path,
                        " ".join(loaded.text.split())[:200],
                    )
                    return ""
                http.post(f"{base}{SWITCH_PATH}", params={SWITCH_PARAM: name}, json={})
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

    def _compute_function_hash_hint(self, file_path: str, sample_hash: str) -> str:
        """Pre-pass: surface known-family code reuse via exact opcode-hash match.

        Computes per-function normalized-opcode hashes for the binary, asks the
        FunctionHashStore which known samples share them, and renders an
        "attribution prior" hint. Deterministic and fail-safe: any error (or an
        empty corpus / no overlap) returns an empty string and the analyst
        proceeds normally. ``get_bulk_function_hashes`` is deliberately NOT in
        the model allowlist — it is driven here from Python so the small local
        model never carries that tool in its prompt.
        """
        from maljan.core.config import get_settings

        cfg = get_settings()
        if not cfg.preprocessing.use_function_hash_attribution:
            return ""
        if not self._provider().capabilities.provides_function_hashes:
            return ""  # this static provider cannot produce function hashes
        if cfg.memory.backend != "qdrant":
            return ""  # the function-hash store needs the Qdrant backend

        try:
            from maljan.analysis.function_hash_attribution import (
                aggregate_matches,
                build_attribution_hint,
            )
            from maljan.memory.function_hash_store import FunctionHashStore

            functions = self._provider().function_hashes(
                StaticJobContext(mirror_sample_path=file_path)
            )
            if not functions:
                return ""

            store = FunctionHashStore(
                url=cfg.memory.qdrant_url,
                collection=cfg.memory.qdrant_function_hash_collection,
                api_key=(
                    cfg.memory.qdrant_api_key.get_secret_value()
                    if cfg.memory.qdrant_api_key
                    else None
                ),
            )
            matches = store.match(
                [fh for _name, fh in functions],
                exclude_sample_id=sample_hash or None,
            )
            results = aggregate_matches(
                matches, max_families=cfg.preprocessing.function_hash_max_matches
            )
            hint = build_attribution_hint(results)
            if hint:
                self.logger.info(
                    "Function-hash pre-pass: %d family prior(s) from %d shared "
                    "function(s) for '%s'.",
                    len(results),
                    sum(r.shared_functions for r in results),
                    file_path,
                )
            else:
                self.logger.info(
                    "Function-hash pre-pass: no known-family overlap (new sample "
                    "or empty corpus) — no prior emitted."
                )
            return hint
        except Exception as exc:  # fail-safe: never break analysis over a hint
            self.logger.warning(
                "Function-hash pre-pass failed (%s: %s); continuing without prior.",
                type(exc).__name__,
                exc,
            )
            return ""

    def _compute_family_rag_hint(self, file_path: str) -> str:
        """Pre-pass: retrieve candidate families by static-feature similarity.

        Builds a deterministic static-feature profile of the sample and retrieves
        the nearest family fingerprints from the vendored KB, rendering them as
        CANDIDATE evidence for the LLM to weigh. LLM-centric — retrieval surfaces
        candidates; the analyst decides attribution. Generalises to UNSEEN samples
        (unlike the exact-match function-hash prior). Fail-safe: gated OFF by
        default, returns '' when the catalog/profile is absent or empty.
        """
        from maljan.core.config import get_settings

        cfg = get_settings()
        if not cfg.preprocessing.use_family_feature_rag:
            return ""
        try:
            from maljan.analysis.family_feature_rag import (
                build_rag_hint,
                build_sample_profile_text,
                retrieve_candidates,
            )
            from maljan.extractors.pe_extractor import build_static_analysis
            from maljan.memory.family_fingerprint_index import load_family_index

            static = build_static_analysis(sample_path=file_path)
            if static is None:
                return ""
            profile = build_sample_profile_text(static)
            if not profile:
                return ""
            index = load_family_index(cfg.preprocessing.family_fingerprint_catalog_path)
            if index is None:
                return ""  # catalog absent — already logged once at load
            candidates = retrieve_candidates(
                profile,
                index,
                top_k=cfg.preprocessing.family_rag_top_k,
                min_score=cfg.preprocessing.family_rag_min_score,
            )
            hint = build_rag_hint(candidates)
            if hint:
                self.logger.info(
                    "Family-RAG pre-pass: %d candidate(s) for '%s' (top=%s).",
                    len(candidates),
                    file_path,
                    f"{candidates[0].family}~{candidates[0].score:.2f}" if candidates else "-",
                )
            else:
                self.logger.info("Family-RAG pre-pass: no family above the similarity floor.")
            return hint
        except Exception as exc:  # fail-safe: never break analysis over a hint
            self.logger.warning(
                "Family-RAG pre-pass failed (%s: %s); continuing without candidates.",
                type(exc).__name__,
                exc,
            )
            return ""

    def _compute_attck_case_hint(self, file_path: str) -> str:
        """Pre-pass: surface ATT&CK techniques recurring in similar prior cases (§4 U2).

        Builds the same deterministic static-feature profile as the family RAG and
        retrieves the behaviourally-similar prior cases mined from our own long-term
        memory; their attributed technique_ids are aggregated into ranked CANDIDATE
        techniques for the LLM to corroborate. LLM-centric — retrieval surfaces
        prior-art TTPs; the analyst decides which apply. Fail-safe: gated OFF by
        default, returns '' when the corpus/profile is absent or empty.
        """
        from maljan.core.config import get_settings

        cfg = get_settings()
        if not cfg.preprocessing.use_attck_case_rag:
            return ""
        try:
            from maljan.analysis.attck_case_rag import (
                build_attck_case_hint,
                retrieve_techniques,
            )
            from maljan.analysis.family_feature_rag import build_sample_profile_text
            from maljan.extractors.pe_extractor import build_static_analysis
            from maljan.memory.attck_case_index import load_attck_case_index

            static = build_static_analysis(sample_path=file_path)
            if static is None:
                return ""
            profile = build_sample_profile_text(static)
            if not profile:
                return ""
            index = load_attck_case_index(cfg.preprocessing.attck_case_corpus_path)
            if index is None:
                return ""  # corpus absent — already logged once at load
            candidates = retrieve_techniques(
                profile,
                index,
                top_k=cfg.preprocessing.attck_case_rag_top_k,
                min_score=cfg.preprocessing.attck_case_rag_min_score,
                max_techniques=cfg.preprocessing.attck_case_rag_max_techniques,
            )
            hint = build_attck_case_hint(candidates)
            if hint:
                self.logger.info(
                    "ATT&CK-case-RAG pre-pass: %d candidate technique(s) for '%s' (top=%s).",
                    len(candidates),
                    file_path,
                    f"{candidates[0].technique_id}~{candidates[0].score:.2f}"
                    if candidates
                    else "-",
                )
            else:
                self.logger.info("ATT&CK-case-RAG pre-pass: no technique above the floor.")
            return hint
        except Exception as exc:  # fail-safe: never break analysis over a hint
            self.logger.warning(
                "ATT&CK-case-RAG pre-pass failed (%s: %s); continuing without candidates.",
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

        # 2026-07 round 3: dynamic-mode tool narrowing when data is a file path.
        if len(data.strip()) < 512 and os.path.exists(data.strip()):
            self._refine_tools_for_sample(data.strip())

        prompt_messages = [
            ("system", _static_prompt(self._provider())),
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
                # BUG-07: don't let the "No static data available" placeholder
                # talk the model out of its live-Ghidra ORIGINAL REPORT.
                "data": _reframe_static_raw_data(original_data, bool(self.tools)),
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
        attr_hint = ""
        rag_hint = ""
        attck_hint = ""
        analysis_path = _extract_analysis_path(data)
        if analysis_path:
            sink_hint = self._compute_sink_priority_hint(analysis_path)
            # Function-hash attribution prior: exact opcode-hash matches against
            # previously analysed samples. Hoisted ABOVE the sink hint so a known
            # family link frames the whole analysis. Fail-safe and corpus-gated.
            attr_hint = self._compute_function_hash_hint(
                analysis_path, _extract_sample_hash(data) or ""
            )
        # Family-feature RAG: retrieve candidate families by static-feature
        # similarity (LLM-centric — the analyst decides). Generalises to UNSEEN
        # samples where the exact-match function-hash prior is silent. Reads the
        # raw bytes on the HOST (pe_extractor), so it needs the host path, not the
        # container path Ghidra uses. Fail-safe and gated OFF by default.
        host_path = _extract_host_path(data)
        if host_path:
            rag_hint = self._compute_family_rag_hint(host_path)
            # ATT&CK case-prior RAG (§4 U2): cross-sample TTP grounding mined from our
            # own long-term memory. Same host profile as the family RAG, different KB
            # (prior cases -> recurring techniques). Fail-safe and gated OFF by default.
            attck_hint = self._compute_attck_case_hint(host_path)
        # 2026-07 round 3: in dynamic mode, narrow the Ghidra tool manifest to the
        # tools relevant to THIS sample's capability categories before the ReAct
        # loop (all tools stay reachable; only the relevant subset is shown).
        self._refine_tools_for_sample(host_path)

        prompt_messages = [
            ("system", _static_prompt(self._provider())),
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
                f"{rag_hint}{attck_hint}{attr_hint}{sink_hint}{load_hint}{target_info}",
            ),
        ]

        content = self.execute_tool_loop(prompt_messages)
        parsed = _parse_claim_blocks(content)
        # BUG-07: a defeatist "could not be performed / missing binary data"
        # claim parses as a well-formed block but is not a real finding — drop it
        # so static collapses to a zero-claim (degraded) ISR rather than a fake
        # high-confidence one.
        claims = self._drop_meta_claims(parsed)

        if parsed and not claims:
            self.logger.info(
                "%s: all initial claims were meta-claims; emitting zero-claim ISR.",
                self.name,
            )
            return AgentISR(
                agent_id=self.name,
                domain="static",
                claims=[],
                dissent_items=[],
                revision_round=0,
            )

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
                # BUG-07: don't let the "No static data available" placeholder
                # talk the model out of its live-Ghidra ORIGINAL REPORT.
                "data": _reframe_static_raw_data(original_data, bool(self.tools)),
            }
        )
        content = str(response.content)

        parsed = _parse_claim_blocks(content)
        # BUG-07: drop defeatist meta-claims ("could not be performed / missing
        # binary data") that parse as well-formed blocks; a no-real-finding
        # revision must collapse to a zero-claim ISR so the run is honestly
        # marked degraded instead of crediting a fake high-confidence claim.
        claims = self._drop_meta_claims(parsed)
        dissent = _parse_disputes(content)

        if parsed and not claims:
            self.logger.info(
                "%s: all revision claims were meta-claims; emitting zero-claim ISR.",
                self.name,
            )
            return content, AgentISR(
                agent_id=self.name,
                domain="static",
                claims=[],
                dissent_items=dissent,
                revision_round=revision_round,
            )

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


def _extract_host_path(data: str) -> str | None:
    """Return the ``host_sample_path`` from a chunk JSON, or None.

    The host-readable raw-binary path (spliced in by
    ``nodes._augment_static_chunks_with_path``) — distinct from the
    container-visible ``analysis_file_path`` Ghidra uses. Needed by the
    static-feature family classifier, which reads the bytes on the host.
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
    path = parsed.get("host_sample_path")
    return path if isinstance(path, str) and path else None


def _extract_sample_hash(data: str) -> str | None:
    """Return the sample's full sha256 from a chunk JSON, or None.

    The static chunk carries ``{sha256, md5, name, size, ...}``; the full
    ``sha256`` equals the pipeline ``file_hash`` used as the LTM/function-hash
    ``sample_id``, so a re-analysis can exclude its own prior matches. Falls
    back to the short ``sample_hash`` fingerprint. Best-effort: None on any miss.
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
    for key in ("sha256", "sample_hash"):
        val = parsed.get(key)
        if isinstance(val, str) and val:
            return val
    return None


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
