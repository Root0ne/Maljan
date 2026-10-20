"""Static Analyst agent — evaluates decompiled code and binary strings.

Overrides analyze_isr() and revise_isr() to extract structured
ClaimEvidence objects via a structured-output prompt. Each claim cites a
concrete artifact reference (function name, string offset, API call).
"""

from __future__ import annotations

import os
import re
from collections.abc import Sequence
from typing import Any

from maljan.agents.base_agent import (
    BaseAnalyst,
    prompt_to_messages,
    read_claim_blocks,
    strip_tool_call_scaffolding,
)
from maljan.agents.prompt_fragments import (
    CLAIM_FORMAT_FRAGMENT,
    FINDINGS_BLOCK_FRAGMENT,
    PROVIDER_FAMILY,
    REPUTATION_LOOKUP_FRAGMENT,
    has_decompiler,
    has_xrefs,
    offered,
    provider_source,
    resolve_attached,
    stamp_source,
    tool_families,
    tool_names,
    tools_statement,
)
from maljan.agents.registry import register_agent
from maljan.providers.base import (
    StaticJobContext,
    absent_provider_fragment,
    holding_the_discipline,
)
from maljan.schemas.isr_models import AgentISR, ClaimEvidence

# The provider- and platform-independent head of the static system prompt.
# Everything that names a tool lives in the provider's fragment and everything
# that names an operating system lives in the sample's format fragment, so
# attaching radare2 or handing it an APK changes the middle and nothing else.
_ISR_HEAD = (
    "You are an expert Static Malware Analyst with 15 years of reverse engineering experience. "
)

# What a claim is for. A live run produced 39 claims of which most were the
# sample's own metadata at confidence 1.00 -- "the binary has a sha256 hash of
# ...", "mime type consistent" -- which the judge then weighed as evidence of
# something. Those facts belong in the artifacts block, which exists for them.
_CLAIMS_BEAR_ON_THE_VERDICT = (
    "\n\nClaims state findings that bear on the verdict. File metadata — hashes, size, "
    "mime type, machine type, timestamps — goes in the artifacts block, not in claims."
)

# The optional structured channel, appended after the provider fragment so it
# is the last thing the analyst reads before it answers. The assembly order is
# the contract the tool-server and agent-composition layers build prompts from.
_ISR_TAIL = FINDINGS_BLOCK_FRAGMENT + _CLAIMS_BEAR_ON_THE_VERDICT + REPUTATION_LOOKUP_FRAGMENT


def assemble_static_prompt(
    provider: Any,
    fragment: str,
    tools: Sequence[Any],
    *,
    provider_expected: bool = False,
    for_a_clone: bool = False,
) -> str:
    """The static system prompt for ``provider``, true of the tool list ``tools``.

    HEAD, the sample's format fragment, the provider's fragment, the sentence
    about the tools, then TAIL. The provider's fragment walks the model through
    the provider's own tools, so it is the prompt only when those tools are in
    the list (or, for a prompt resolved before the analyst attaches them,
    ``provider_expected``); otherwise the provider says what it is and that it
    is not attached; either way its tool-independent guidance is there. The
    sentence about tools is built from ``tools`` alone.

    ``for_a_clone`` leaves out both the provider's fragment and the sentence:
    the text a clone is seeded with, which is resolved with its own provider
    and its own tool list.
    """
    if for_a_clone:
        return _ISR_HEAD + fragment + _ISR_TAIL
    body, statement = static_provider_parts(provider, tools, provider_expected=provider_expected)
    return _ISR_HEAD + fragment + "\n\n" + body + "\n\n" + statement + _ISR_TAIL


def static_provider_parts(
    provider: Any, tools: Sequence[Any], *, provider_expected: bool = False
) -> tuple[str, str]:
    """``(the provider's text, the sentence about tools)`` for a request carrying ``tools``.

    The provider's text is its whole fragment when its tools are in the list
    (or expected), and otherwise its guidance with the sentence saying it is
    not attached; a provider that offers no tools always sends its fragment.
    The built-in assembly and an operator's prompt on a static provider both
    take these two parts, so the provider says the same thing under either.
    """
    attached = provider_expected or PROVIDER_FAMILY in tool_families(tools)
    label = str(getattr(provider, "label", "") or getattr(provider, "id", "") or "static")
    offers_tools = bool(getattr(getattr(provider, "capabilities", None), "provides_tools", True))
    # A provider that offers no tools (``none``, capa/YARA) has nothing to be
    # absent: its fragment describes it whatever the list holds.
    if attached or not offers_tools:
        body = str(provider.prompt_fragment())
    elif hasattr(provider, "absent_fragment"):
        body = str(provider.absent_fragment())
    else:
        guidance = getattr(provider, "guidance_fragment", None)
        body = (
            absent_provider_fragment(label, str(guidance()))
            if callable(guidance)
            else absent_provider_fragment(label)
        )
    statement = tools_statement(
        tools,
        provider_label=f"the {label} static provider",
        provider_expected=attached,
    )
    # Every static analyst is held to the verification discipline, whatever
    # its provider wrote: a provider that writes its whole fragment itself
    # gets it after that fragment.
    # A part of the provider's declared workflow that names another server's
    # tool reads as that server's being attached or not.
    return resolve_attached(holding_the_discipline(body), tools).rstrip(), statement


def _static_prompt(provider: Any | None = None, tools: Sequence[Any] = ()) -> str:
    """The neutral static system prompt for ``provider`` (the configured one by default).

    Neutral because it carries the format fragment for a sample nothing has
    identified. A running job does not use this: the container resolves the
    agent's prompt with the job's own format (``composition.builtin_prompt``)
    and ``BaseAnalyst._system_prompt`` builds it for the tools the request
    carries. This is the fallback for an analyst built outside a container.
    """
    if provider is None:
        from maljan.core.config import get_settings
        from maljan.providers.registry import get_static_provider

        provider = get_static_provider(get_settings())
    from maljan.agents.prompt_fragments import format_fragment

    return assemble_static_prompt(provider, format_fragment("unknown", "unknown"), tools)


# Back-compat: several modules and tests import this name. It is the default
# profile's neutral assembly; a running job sends the container's resolved
# prompt instead (``composition.builtin_prompt`` and
# ``BaseAnalyst._system_prompt``).
_ISR_SYSTEM = _static_prompt()


# The deterministic raw-data slot.
_STATIC_RAW_PLACEHOLDER_RE = re.compile(r"^\s*no\s+\w+\s+data\s+available\b", re.IGNORECASE)


def _reframe_static_raw_data(data: str, has_tools: bool) -> str:
    """Rephrase the 'No static data available' file-loader placeholder.

    For a freshly uploaded sample there is no pre-extracted
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
            "is impossible — the tool findings in YOUR ORIGINAL REPORT "
            "above are the authoritative static evidence. Revise from those findings; "
            "do NOT claim the binary data is missing or that analysis could not be performed."
        )
    return data


@register_agent("static")
class StaticAnalyst(BaseAnalyst):
    """Specialized agent for evaluating decompiled code and strings via the configured static provider."""

    # ------------------------------------------------------------------
    # MCP Tool Interface
    # ------------------------------------------------------------------

    # Container-visible path of the current sample, assigned per-run by the
    # pipeline (nodes.py). Read at CALL time by the load_program wrapper (late
    # binding — the agent is cached across samples and tools may be attached
    # before the pipeline sets the path).
    _analysis_file_path: str | None = None

    def _provider(self) -> Any:
        """The static provider for *this agent*: its own, the container's, or an ad hoc one.

        A definition may name a static provider (a clone of ``static`` on
        radare2), in which case that is the one this analyst reads; the
        container caches one object per id, so two static analysts on two
        providers are two providers and not one with two opinions. Without a
        resolution — a bare analyst in a test or a script — this is exactly the
        globally configured provider it always was.
        """
        container = getattr(self, "_container", None)
        resolved = getattr(self, "_resolved", None)
        if container is not None:
            if resolved is not None:
                return container.get_static_provider(resolved.static_provider_id)
            return container.get_static_provider()
        from maljan.core.config import get_settings
        from maljan.providers.registry import get_static_provider

        return get_static_provider(get_settings())

    def _initialize_mcp_client(self) -> None:
        """Attach the configured static provider's tools. Idempotent per sample.

        Everything this used to do — transports, clients, guardrails, the shared
        agent loop — moved into ``GhidraStaticProvider.open``. What is left is
        the analyst's half of the contract: ask.
        """
        provider = self._provider()
        if not provider.capabilities.provides_tools:
            self.logger.info("Static provider '%s' exposes no tools.", provider.id)
            self.tools = self._attach_registry_tools("static")
            return
        try:
            provider.open(self._job_context())
        except Exception as exc:
            if provider.capabilities.degrade_on_failure:
                self._record_provider_degradation(provider, exc)
            raise
        # Marked as the provider's, so the prompt names them as such rather
        # than inferring it from the absence of a server key.
        pool = stamp_source(
            provider.get_tools(), PROVIDER_FAMILY, declared=provider_source(provider)
        )
        # A tool the provider withholds is said where it is withheld.
        from maljan.providers.base import record_provider_withheld

        own = list(getattr(self, "degradation_reasons", None) or [])
        record_provider_withheld(provider, self._server_registry(), own)
        if own:
            self.degradation_reasons = own
        # No ``self.toolkit`` assignment here: the provider holds its own client
        # privately and closes it itself (``ServiceContainer.aclose`` calls
        # ``get_static_provider().close()``), so there is nothing for this
        # analyst's ``close_tools()`` to release on the static path.
        # The provider's tools are the agent's own: a server tool of the same
        # name is offered as ``<server>__<tool>`` beside them, never in their
        # place.
        self.tools = [
            *pool,
            *self._attach_registry_tools(
                "static",
                exclude=str(getattr(provider, "server_name", "")),
                claimed=pool,
                claimed_by=f"provider:{provider.id}",
            ),
        ]
        self.logger.info("Static provider '%s': %d tools attached.", provider.id, len(self.tools))

    def _record_provider_degradation(self, provider: Any, exc: BaseException) -> None:
        """Say in the run summary that a degrading provider did not attach, and why.

        A degrading provider's failed attach used to reach the log alone: the
        run went on without the provider's tools and the summary did not say
        so. The reason is the published form of the failure — its kind and its
        remedy, never its message, which may name host paths — and goes on the
        job's registry list, which the run summary reads, once.
        """
        from maljan.pipeline.events import describe_exception

        reason = f"static provider '{provider.id}' unavailable: {describe_exception(exc)}"
        if reason not in self.degradation_reasons:
            self.degradation_reasons = [*self.degradation_reasons, reason]
        registry = self._server_registry()
        reasons = getattr(registry, "degradation_reasons", None)
        if isinstance(reasons, list) and reason not in reasons:
            reasons.append(reason)

    def _fallback_prompt(self, tools: Sequence[Any]) -> str:
        """The prompt of an analyst built outside a container, for ``tools``."""
        return _static_prompt(self._provider(), tools)

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
            job_key=str(getattr(self, "_job_id", "") or ""),
            host_sample_path=getattr(self, "_host_sample_path", None),
            mirror_sample_path=getattr(self, "_analysis_file_path", None),
            output_guardrail=guardrail,
            max_output_chars=cfg.preprocessing.max_tool_output_chars,
            truncation_ledger=getattr(self, "truncation_ledger", None),
            context_budget=self._context_budget(),
        )

    def _static_capabilities(self) -> Any:
        """The provider's degrade policy: Ghidra's is loud, others may differ."""
        return self._provider().capabilities

    def _compute_sink_priority_hint(self, file_path: str) -> str:
        """Open the sample on this agent's provider, then rank functions reachable to sinks.

        The pre-pass every analyst on a static provider runs
        (``providers.base.prepare_sample``), on *this agent's* provider,
        whatever the globally configured one is. The open is the provider's
        (``open_sample``) on the agent's pinned mirror when one is pinned, else
        the chunk's path: a sample the provider knows it cannot open raises
        :class:`SampleNotOpened` before the loop starts. The ranking is the
        provider's call graph's, where it gives one, and fail-safe: any error
        in it, or a stripped binary with no named sink APIs, returns an empty
        string.
        """
        from maljan.providers.base import prepare_sample

        path = getattr(self, "_analysis_file_path", None) or file_path
        return prepare_sample(self._provider(), path, self.logger)

    def _sample_open(self) -> Any:
        """What this agent's provider declares opens a sample (its ``sample_open``), or ``None``.

        Read from the provider's declaration (``core.declared_reading``), so
        the load line names whichever tool the provider's block declares.
        """
        try:
            from maljan.core.declared_reading import declarations

            held = declarations().source(self._provider().declaration_source)
        except Exception as exc:  # noqa: BLE001 — no declaration, no tool named
            self.logger.debug("no sample-open declaration to read (%s)", type(exc).__name__)
            return None
        return getattr(held, "sample_open", None) if held is not None else None

    def _compute_function_hash_hint(self, file_path: str, sample_hash: str) -> str:
        """Pre-pass: surface known-family code reuse via exact opcode-hash match.

        Computes per-function normalized-opcode hashes for the binary, asks the
        configured memory backend's function-hash store which known samples
        share them, and renders an
        "attribution prior" hint. Deterministic and fail-safe: any error (or an
        empty corpus / no overlap) returns an empty string and the analyst
        proceeds normally. ``get_bulk_function_hashes`` is deliberately NOT in
        the model allowlist — it is driven here from Python so the small local
        model never carries that tool in its prompt.
        """
        from maljan.core.config import get_settings

        cfg = get_settings()
        from maljan.providers.base import preprocessing_of

        pre = preprocessing_of(self._provider())
        if not pre.use_function_hash_attribution:
            return ""
        if not self._provider().capabilities.provides_function_hashes:
            return ""  # this static provider cannot produce function hashes

        try:
            from maljan.analysis.function_hash_attribution import (
                aggregate_matches,
                build_attribution_hint,
            )
            from maljan.memory.store_factory import leased_function_hash_store

            # Held for the read: a settings change meanwhile closes this store
            # only once the read has let go of it.
            with leased_function_hash_store(cfg) as store:
                if store is None:
                    return ""  # the configured memory backend keeps no function hashes

                functions = self._provider().function_hashes(
                    StaticJobContext(mirror_sample_path=file_path)
                )
                if not functions:
                    unread = getattr(functions, "unavailable", "")
                    if unread:
                        self.logger.warning(
                            "Function-hash pre-pass: no hashes could be read (%s); "
                            "continuing without prior.",
                            unread,
                        )
                    return ""

                from maljan.memory.long_term_memory import match_functions, memory_owner_of

                matches = match_functions(
                    store,
                    [fh for _name, fh in functions],
                    exclude_sample_id=sample_hash or None,
                    owner=memory_owner_of(getattr(self, "_container", None)),
                )
            results = aggregate_matches(matches, max_families=pre.function_hash_max_matches)
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
    # ISR interface (structured claim extraction)
    # ------------------------------------------------------------------

    def analyze_isr(self, data: str) -> AgentISR:
        """Return a structured AgentISR with evidence-backed claims."""
        self.logger.info("Executing static ISR analysis...")

        self._try_initialize_mcp()

        # When the supplied target *looks*
        # like a filename but doesn't exist on disk (e.g. a sandbox sent
        # the task_id instead of the artefact path), short-circuit
        # to a zero-claim ISR rather than paying for an LLM round that
        # ends with ``load_program: File not found``. The meta-claim guard already
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
                "round and emitting an empty ISR — the downstream confidence "
                "cap will mark this run as degraded.",
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

        # Make the load_program
        # path *explicit* in the human turn instead of leaving the LLM to
        # infer it from the JSON. The path is injected upstream in
        # ``nodes.py:_augment_static_chunks_with_path`` as
        # ``analysis_file_path`` on the chunk JSON. When present we hoist
        # it to a separate "Load using" line so the model can't miss it,
        # even on a degraded local 8-9B run.
        # The provider's own declaration, else a declaration an operator-bound
        # server's offered open tool carries (``sample_open.mark_open_tool``).
        from maljan.providers.sample_open import declared_open

        load_hint = _extract_load_hint(
            data, tool_names(self.tools), self._sample_open() or declared_open(self.tools)
        )

        # Maltracker-style sink-reachability triage: when we have a
        # container-visible path, run a deterministic call-graph pre-pass and
        # hoist the resulting priority-function list above the target so the
        # ReAct loop decompiles the malicious core first. Fail-safe: empty
        # string when disabled, unavailable, or the binary has no named sinks.
        sink_hint = ""
        attr_hint = ""
        rag_hint = ""
        analysis_path = _extract_analysis_path(data)
        if analysis_path:
            # The provider opens the sample where its session needs it, then
            # ranks the functions its call graph shows reaching sinks.
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
        host_path = getattr(self, "_host_sample_path", None)
        if host_path:
            rag_hint = self._compute_family_rag_hint(host_path)
        prompt_messages = [
            ("system", self._system_prompt(self._fallback_prompt)),
            (
                "human",
                "Analyze the target binary and return a structured list of findings.\n"
                f"{_tool_use_line(self.tools)}"
                "For each finding state: the claim, the exact artifact "
                "reference (e.g. 'API import: VirtualAllocEx', 'string at .data+0x20: /bin/sh'), "
                "your confidence (0.0-1.0), and the MITRE ATT&CK technique ID if applicable.\n\n"
                f"{CLAIM_FORMAT_FRAGMENT}\n"
                f"{rag_hint}{attr_hint}{sink_hint}{load_hint}{target_info}",
            ),
        ]

        content = self.execute_tool_loop(prompt_messages)
        parsed = self._read_claims(content)
        # A defeatist "could not be performed / missing binary data"
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
            # No block the strict parser reads: the lenient reading, which
            # keeps an answer with no claim as prose and says so.
            return self._text_to_isr(content, revision_round=0)

        return self._parsed_isr(claims, content, "static")

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

        # Built as messages rather than through a template: the resolved system
        # prompt carries a literal JSON example (the findings block), and a
        # ``ChatPromptTemplate`` reads every ``{...}`` in it as a variable.
        messages = prompt_to_messages(
            [
                (
                    "system",
                    # A revision is one tools-free call unless it may read a
                    # function the ledger never listed: the prompt says which.
                    self._system_prompt(self._fallback_prompt, tools=self.revision_tools()) + "\n\n"
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
                    # Don't let the "No static data available" placeholder
                    # talk the model out of its live-Ghidra ORIGINAL REPORT.
                    "RAW DATA:\n"
                    f"{_reframe_static_raw_data(original_data, bool(self.tools))}\n\n"
                    "Format your response as structured claims "
                    "(CLAIM/EVIDENCE/CONFIDENCE/TECHNIQUE)\n"
                    "followed by a DISPUTES section listing peer claims you reject.\n"
                    "Example:\n"
                    "CLAIM: ...\nEVIDENCE: ...\nCONFIDENCE: 0.8\nTECHNIQUE: T1055\n---\n"
                    "DISPUTES:\n- Dynamic analyst claims no injection but PCAP shows it.\n",
                ),
            ]
        )

        # Through the findings capture like every other answer: the resolved
        # system prompt ends with the findings-block instruction, so a model
        # that obeys it puts a JSON fence into the revised report, and nothing
        # downstream of here — the claim parser, the transcript, the Composer —
        # should ever see it.
        content = self._capture_findings(self.revision_answer(messages))

        parsed = self._read_claims(content, revision_round)
        # Drop defeatist meta-claims ("could not be performed / missing
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
            # The lenient reading keeps the disputes the answer wrote: a
            # revision's dissent is what it says, whichever reader read it.
            lenient = self._text_to_isr(content, revision_round=revision_round)
            lenient.dissent_items = dissent
            return content, lenient

        isr = AgentISR(
            agent_id=self.name,
            domain="static",
            claims=claims,
            dissent_items=dissent,
            revision_round=revision_round,
        )
        self._with_claims_read(isr)
        return content, isr


# ------------------------------------------------------------------
# Shared parsing helpers (module-level, reused by other analysts)
# ------------------------------------------------------------------


def _tool_use_line(tools: Sequence[Any]) -> str:
    """The human turn's line about tools, true of the list the request carries.

    A decompile-and-xrefs example is a promise only a decompiler keeps: a live
    run on the ``none`` provider was told it could decompile while no tool in
    its list could. With no tools at all the turn says nothing about them; the
    system prompt already says there are none.
    """
    if not offered(tools):
        return ""
    examples = [
        what
        for what, present in (("decompile", has_decompiler(tools)), ("xrefs", has_xrefs(tools)))
        if present
    ]
    if examples:
        return f"You may use tools to gather more information ({', '.join(examples)}, etc.).\n"
    return "You may use the tools in your tool list to gather more information.\n"


def _extract_load_hint(data: str, offered: frozenset[str], sample_open: Any = None) -> str:
    """Return a one-line sample-path hint when the chunk carries a path.

    The analyst-node wrapper splices the
    container-visible sample path into the chunk JSON as
    ``analysis_file_path``. We hoist that to a dedicated line at the top
    of the human turn so the LLM doesn't have to discover it inside the
    larger ``target`` block. Returns an empty string when the chunk
    isn't JSON (the legacy raw-bytes path) or when no path is present,
    keeping the prompt verbatim with the pre-Wave-6 behaviour.

    ``offered`` is the tool names the request carries. ``sample_open`` is
    what the provider's declaration says opens a sample (``open_tool`` and its
    ``path_argument``): the load line names that tool and argument only when
    the tool is among those offered; without one the line gives the path and
    names no tool, so a provider that opens no sample is not told to call one.
    """
    from maljan.loaders.binary_chunker import head_object

    parsed = head_object(data)
    if parsed is None:
        return ""
    path = parsed.get("analysis_file_path")
    if not isinstance(path, str) or not path:
        return ""
    tool = str(getattr(sample_open, "open_tool", "") or "")
    argument = str(getattr(sample_open, "path_argument", "") or "")
    if tool and argument and tool in offered:
        from maljan.providers.sample_open import load_line

        return load_line(tool, argument, path)
    if offered:
        return f"Sample path (use exactly this string wherever a tool asks for a file): {path}\n\n"
    return f"Sample path: {path}\n\n"


def _extract_analysis_path(data: str) -> str | None:
    """Return the ``analysis_file_path`` from a chunk JSON, or None.

    Mirrors ``_extract_load_hint``'s parse but exposes the raw container path
    so the sink-reachability pre-pass can hand it to the provider. Best-effort:
    non-JSON or pathless chunks return None.
    """
    from maljan.loaders.binary_chunker import head_object

    parsed = head_object(data)
    if parsed is None:
        return None
    path = parsed.get("analysis_file_path")
    return path if isinstance(path, str) and path else None


def _extract_sample_hash(data: str) -> str | None:
    """Return the sample's full sha256 from a chunk JSON, or None.

    The static chunk carries ``{sha256, md5, name, size, ...}``; the full
    ``sha256`` equals the pipeline ``file_hash`` used as the LTM/function-hash
    ``sample_id``, so a re-analysis can exclude its own prior matches. Falls
    back to the short ``sample_hash`` fingerprint. Best-effort: None on any miss.
    """
    from maljan.loaders.binary_chunker import head_object

    parsed = head_object(data)
    if parsed is None:
        return None
    for key in ("sha256", "sample_hash"):
        val = parsed.get(key)
        if isinstance(val, str) and val:
            return val
    return None


def _parse_claim_blocks(text: str) -> list[ClaimEvidence]:
    """The claims the static, dynamic and network analysts read out of ``text``.

    The one claim reader (``base_agent.read_claim_blocks``) in its stricter
    reading, which wants an EVIDENCE line on every claim. The caller that
    turns these into an ISR goes through ``BaseAnalyst._read_claims``, which
    records any claim the answer began and the reader did not read.
    """
    return read_claim_blocks(text, require_evidence=True).claims


def _parse_disputes(text: str) -> list[str]:
    """Extract dispute items from the DISPUTES section of a revision response.

    The section is the one the claim reader stops at
    (``claim_headings.disputes_section``): it opens at its label alone and
    runs to the next all-capitals section label (e.g. ``SUMMARY:``), so
    trailing sections do not get absorbed as dispute items and every dispute
    line, bulleted or not, is one.
    """
    from maljan.agents.claim_headings import disputes_section

    disputes: list[str] = []
    found = disputes_section(text)
    if found is None:
        return disputes
    # Stripped over the whole section before it is split: a tool-call block
    # spans several lines, so a per-line check would never see one and every
    # line of it would become its own dispute item.
    section = strip_tool_call_scaffolding(found).strip()
    if section.upper().rstrip(".") in {"", "NONE"}:
        return disputes
    for line in section.splitlines():
        cleaned = line.strip().lstrip("-*• ")
        # A bullet whose whole content was scaffolding is left as an empty
        # marker by the strip above, and an empty dispute is not a dispute.
        if cleaned:
            disputes.append(cleaned)
    return disputes
