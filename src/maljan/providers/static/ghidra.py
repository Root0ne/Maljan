"""Ghidra MCP static analysis — moved out of the static analyst.

The tool allow-list, the tool-selection modes, the load_program path pin and
the http/stdio attach path are all the static analyst's own code
(``StaticAnalyst``, pre-2026-09), transplanted here unchanged. The analyst's
``_initialize_mcp_client`` now calls this provider instead of driving its own
copy.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from langchain_core.tools import BaseTool

from maljan.core.logger import logger
from maljan.core.settings_overrides import redact_url
from maljan.providers.base import (
    MirrorSpec,
    ProviderProbe,
    StaticCapabilities,
    StaticJobContext,
    StaticProvider,
)
from maljan.providers.registry import register_static_provider
from maljan.providers.static.ghidra_tool_selector import select_relevant_ghidra_tools

if TYPE_CHECKING:
    from maljan.core.config import MCPServerConfig, MemoryConfig, PreprocessingConfig, Settings


# The tool-facing body of the static system prompt: verbatim lines 23-85 of
# the old ``_ISR_SYSTEM`` in the analyst, moved rather than retyped so a
# golden test can pin the assembled prompt byte for byte. ``_ISR_HEAD`` in
# the analyst supplies the provider-independent opening line this fragment
# completes.
GHIDRA_PROMPT_FRAGMENT: str = (
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
    "=== ADVANCED TOOLS (reach for these when the triage signals call for them) ===\n"
    "- API names resolved by hash (a hashing loop, sparse imports): call\n"
    "  `emulate_hash_batch` to brute-force the obfuscated API names.\n"
    "- Suspected encryption / ransomware: `detect_crypto_constants`.\n"
    "- Trace a key, config value, or decoded buffer through a function:\n"
    "  `analyze_dataflow(address=<addr>, direction=backward|forward)`.\n"
    "- Run a small hash / decode routine to see its output: `emulate_function`.\n"
    "- Packed binary with few functions: `find_code_gaps` to surface missed code.\n"
    "- Record `get_function_hash` on the core malicious function for attribution.\n\n"
    "=== VERIFICATION DISCIPLINE (suppresses confidently-wrong attribution) ===\n"
    "- A SPECIFIC claim (a named algorithm like RC4/djb2/ROR13, a constant or XOR\n"
    "  key, or a hash-resolved API) may reach CONFIDENCE >= 0.8 only if you\n"
    "  FALSIFY it first: `emulate_function` with a known input vs the expected\n"
    "  output, OR `analyze_dataflow(direction=backward)` to confirm its origin.\n"
    "  If you cannot run the check (non-leaf, syscall/heap side effects), cap\n"
    "  CONFIDENCE at 0.7.\n"
    "- `emulate_hash_batch`: read the FULL `matches` list. If more than one API\n"
    "  name collides, do NOT blindly take `best_match` — disambiguate via the\n"
    "  likely source DLL, or emit CONFIDENCE <= 0.5.\n"
    "- A claim is High (>= 0.8) only with >= 2 independent evidence loci (e.g. an\n"
    "  import AND its call-site). A single locus caps at 0.7. Reconcile any\n"
    "  contradictory signals before emitting.\n"
    "- Dynamic API resolution (LoadLibrary + GetProcAddress) is by itself the\n"
    "  ORDINARY Windows idiom for optional/delay-loaded DLLs — it is NOT evidence\n"
    "  of packing or obfuscation (T1027) on its own. Only claim T1027 when you\n"
    "  observe a REAL obfuscation mechanism: a hashing/decrypt loop over API\n"
    "  names, a high-entropy/packed section, an unpacking stub, or a sparse\n"
    "  import table that hides the real APIs. A rich, fully-named import table\n"
    "  (dozens of imports across several DLLs) argues AGAINST packing. Do not\n"
    "  inflate a plain LoadLibrary/GetProcAddress pair into an obfuscation claim.\n\n"
    "IMPORTANT:\n"
    "- Step 1 (load_program) MUST happen before any analysis tool call.\n"
    "- Always prefer the high-level malware analyzers (steps 3–6) before\n"
    "  decompiling individual functions — they are much cheaper.\n"
    "- Focus decompilation on 3-5 most suspicious functions, not every function.\n"
    "- Large binaries may have 1000+ functions. Prioritize entry point, main,\n"
    "  and functions referencing crypto/network/process APIs.\n"
    "- Summarize assembly patterns instead of dumping raw hex."
)


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
GHIDRA_ALLOWED_TOOLS: frozenset[str] = frozenset(
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
        # 2026-05-31: high-value malware analyzers surfaced by the
        # ghidra-mcp v5.6.0 audit (we were using 12/165 tools). These
        # close the evasion / crypto / dynamic-emulation gaps.
        "emulate_hash_batch",  # resolve API-hash obfuscation (ROR13/CRC32/djb2/FNV)
        "emulate_function",  # run a hash/crypto/deobfuscation routine in isolation
        "detect_crypto_constants",  # AES/RC4/etc. constants (ransomware/packing)
        "analyze_dataflow",  # PCode taint: trace keys / C2 config / decode chains
        "get_function_hash",  # normalized opcode hash for family attribution
        "search_byte_patterns",  # masked in-binary signature hunt
        "find_code_gaps",  # surface missed functions in packed/obfuscated code
        "analyze_function_complete",  # one-call comprehensive function analysis
    }
)
# 31 → 12 (audit 2026-05-17, A-01). The dropped tools were redundant
# call-graph traversals and function-listing variants that bloated
# the prompt and pushed each ReAct round into the 180-600 s range.
# 2026-05-31: 12 → 20 — added 8 high-value malware analyzers (emulate /
# crypto / dataflow / code-gap). The sink-reachability pre-pass focuses
# the loop, offsetting the larger tool manifest.


@register_static_provider("ghidra")
class GhidraStaticProvider(StaticProvider):
    """Ghidra MCP, as the static analyst has always driven it.

    Every line of the attach path — the http/stdio branch, the shared-loop
    ``_run_async``, the load_program pin, the three tool-selection modes — is
    this file's, moved out of ``StaticAnalyst`` unchanged. What is new is only
    the seam: the analyst now asks a provider for tools instead of knowing how
    to build them.

    ``degrade_on_failure`` is False on purpose. Ghidra IS the static evidence;
    a toolless static run produces a confident-looking report grounded in
    nothing, which is why this analyst has always failed loudly while dynamic
    and network degrade.
    """

    def __init__(
        self,
        cfg: MCPServerConfig,
        preprocessing: PreprocessingConfig,
        memory: MemoryConfig,
        container_samples_path: str = "/data/samples",
    ) -> None:
        self._cfg = cfg
        self._pre = preprocessing
        self._memory = memory
        self._container_samples_path = container_samples_path
        self._job = StaticJobContext()
        self._toolkit: Any = None
        self._all_tools: list[Any] = []
        self.tools: list[Any] = []

    @classmethod
    def from_settings(cls, cfg: Settings) -> GhidraStaticProvider:
        return cls(cfg.static.ghidra, cfg.preprocessing, cfg.memory)

    @property
    def capabilities(self) -> StaticCapabilities:
        # function hashes come from the headless REST API, so only the http
        # transport can produce them — the same condition nodes.py used to spell
        # out as ``mcp.ghidra.transport == "http"``.
        http = self._cfg.transport == "http"
        return StaticCapabilities(
            provides_tools=True,
            provides_evidence=False,
            provides_function_hashes=http,
            needs_sample_mirror=True,
            supports_tool_curation=True,
            degrade_on_failure=False,
        )

    def prompt_fragment(self) -> str:
        return GHIDRA_PROMPT_FRAGMENT

    def open(self, job: StaticJobContext) -> None:
        """Attach to Ghidra for ``job``. Idempotent, per the base contract.

        The expected repeat call is for the *same* sample: a multi-chunk
        static run calls ``analyze_isr`` once per chunk on one cached agent,
        ``ServiceContainer`` hands back the same memoized provider instance
        each time, and the analyst re-derives an equal ``StaticJobContext``
        per chunk. Before this guard, every one of those calls rebuilt the
        transport from scratch — a fresh ``GhidraHTTPClient.initialize()``
        round trip (up to the 120s hard cap) on http, a fresh subprocess on
        stdio — and the previous client was only dereferenced, never closed:
        N-1 leaked clients or subprocesses per N-chunk sample, for the life
        of the worker. A call whose job compares equal to the one already
        attached now returns immediately instead.

        A call with a job that differs from the one already attached — which
        the current per-job container lifecycle never produces, since each
        job gets its own provider instance — closes the stale toolkit first
        and attaches fresh for the new job, rather than leaking the old one
        silently or refusing the new attach outright.
        """
        if self._toolkit is not None:
            if job == self._job:
                return
            logger.warning(
                "Ghidra provider re-opened for a job different from the one "
                "already attached; closing the stale toolkit before re-attaching."
            )
            self._close_toolkit()
        self._job = job
        if not self._cfg.enabled:
            logger.info("Ghidra MCP is disabled in config.")
            return

        output_guardrail = job.output_guardrail
        max_chars = job.max_output_chars

        # ------------------------------------------------------------------
        # HTTP transport (headless Docker server)
        # ------------------------------------------------------------------
        if self._cfg.transport == "http":
            from maljan.agents.ghidra_http_client import GhidraHTTPClient

            client = GhidraHTTPClient(
                base_url=self._cfg.url,
                auth_token=self._cfg.auth_token,
                output_guardrail=output_guardrail,
                max_output_chars=max_chars,
                truncation_ledger=job.truncation_ledger,
            )

            self._run_async(client.initialize())
            self._toolkit = client
            all_tools = list(client.get_tools())
            self._all_tools = all_tools  # full pool; kept reachable
            self.tools = self.select_tools(all_tools)
            logger.info(
                "Initialized Ghidra HTTP tools: %d/%d (mode=%s).",
                len(self.tools),
                len(all_tools),
                self._tool_mode(),
            )
            return

        # ------------------------------------------------------------------
        # stdio transport (legacy local subprocess)
        # ------------------------------------------------------------------
        from mcp import StdioServerParameters

        from maljan.agents.mcp_client import MCPLangChainToolkit
        from maljan.agents.subprocess_env import child_env
        from maljan.core.paths import resolve_mcp_args

        command = self._cfg.command
        args = self._cfg.args

        env = child_env(self._cfg.env)
        env.setdefault("PYTHONIOENCODING", "utf-8")

        args = resolve_mcp_args(args)
        server_params = StdioServerParameters(command=command, args=args, env=env)

        toolkit = MCPLangChainToolkit(
            server_params,
            output_guardrail=output_guardrail,
            max_output_chars=max_chars,
            truncation_ledger=job.truncation_ledger,
        )

        self._run_async(toolkit.initialize())
        self._toolkit = toolkit  # type: ignore[assignment]
        all_tools = list(toolkit.get_tools())
        self._all_tools = all_tools  # full pool; kept reachable
        self.tools = self.select_tools(all_tools)
        logger.info(
            "Initialized Ghidra MCP tools: %d/%d (mode=%s).",
            len(self.tools),
            len(all_tools),
            self._tool_mode(),
        )

    def _run_async(self, coro: Any) -> None:
        """Run an MCP-client init coroutine on the *shared agent loop*.

        The Ghidra HTTP client builds its long-lived ``httpx.AsyncClient`` inside
        ``initialize()`` (via ``_get_http``); httpx binds that client's
        connection pool — and the asyncio primitives behind it — to whichever
        loop first creates it. The ReAct tool calls later run on the
        process-wide agent loop (``base_agent._get_agent_loop``), so the old
        implementation here — which ran init on a throwaway ``new_event_loop()``
        (LangGraph runs sync nodes in a worker thread with no running loop) —
        bound the client to a *different* loop than the ReAct. The first chunk's
        tool call then raised ``<asyncio.locks.Event ...> is bound to a different
        event loop`` and that chunk was lost on every run (and, under the CLI's
        ``asyncio.run``, the whole static analyst). Submitting init to the same
        shared loop the ReAct uses keeps client creation and use on one loop.

        Only ever called from a synchronous setup path (``analyze`` /
        ``analyze_isr``) on the main/worker thread — never from within the agent
        loop itself — so blocking on the result cannot deadlock.
        """
        from maljan.agents.base_agent import _run_coro_blocking

        _run_coro_blocking(coro, hard_timeout=120.0, label="ghidra-mcp-init")

    def get_tools(self) -> list[BaseTool]:
        return self._all_tools

    def select_tools(self, tools: list[Any], categories: set[str] | None = None) -> list[Any]:
        """Pick the tool manifest to expose to the model per the configured mode.

        - ``curated`` — the fixed ~20-tool allowlist (fastest, narrowest).
        - ``dynamic`` — CORE triage set + tools relevant to the sample's
          capability ``categories`` (~30-40). All tools stay reachable; only the
          relevant subset is shown (2026-07 round 3, tool-RAG). Without
          categories (init time) it falls back to the curated allowlist.
        - ``all`` — every tool the server offers (measured 5-6x slower + noisier).
        """
        mode = self._tool_mode()
        if mode == "all":
            logger.info("Ghidra MCP [all]: exposing all %d tools.", len(tools))
            return self._pin_load_program_path(list(tools))

        # Fall back to categories set by the pipeline (nodes.py) when the caller
        # didn't pass any — this is the reliable path (state["sample_path"]).
        if categories is None:
            job_categories = self._job.capability_categories
            categories = None if job_categories is None else set(job_categories)

        if mode == "dynamic" and categories is not None:
            selected = select_relevant_ghidra_tools(tools, categories)
            logger.info(
                "Ghidra MCP [dynamic]: selected %d/%d tools for categories %s.",
                len(selected),
                len(tools),
                sorted(categories) or "{}",
            )
            return self._pin_load_program_path(selected)

        # curated (or dynamic before a sample is known)
        kept = [t for t in tools if getattr(t, "name", "").lower() in GHIDRA_ALLOWED_TOOLS]
        logger.info(
            "Ghidra MCP [%s]: kept %d/%d tools via curated allowlist.",
            mode,
            len(kept),
            len(tools),
        )
        return self._pin_load_program_path(kept)

    def _tool_mode(self) -> str:
        """Resolve the effective tool-selection mode from config (back-compat)."""
        if getattr(self._cfg, "use_all_tools", False):
            return "all"
        return str(getattr(self._cfg, "tool_selection", "dynamic"))

    def _pin_load_program_path(self, tools: list[Any]) -> list[Any]:
        """Wrap ``load_program`` so a hallucinated ``file`` arg is overridden.

        Ghidra-path fix (2026-07-12, job 60df48cb): on a fresh sample whose
        chunk lacked ``analysis_file_path`` the LLM invented
        ``/home/user/data/bin.<sha>`` and load_program failed with
        "File not found" even though the mirror to ``/data/samples/`` had
        succeeded. The wrapper deterministically substitutes the known
        container path (``self._job.mirror_sample_path``, set per-sample by
        nodes.py) whenever the model supplies a different one. Fail-safe:
        any wrapping error keeps the original tool.
        """
        out: list[Any] = []
        for tool in tools:
            if getattr(tool, "name", "") == "load_program":
                try:
                    tool = self._wrap_load_program(tool)
                except Exception as e:  # noqa: BLE001
                    logger.warning("load_program pin skipped: %s", e)
            out.append(tool)
        return out

    def _wrap_load_program(self, tool: Any) -> Any:
        """Rebuild the load_program StructuredTool with a path-pinning coroutine.

        A fresh tool is built rather than mutating ``tool.coroutine`` in
        place — the original lives in the shared ``_all_tools`` pool
        and the HTTP client's tool list; in-place mutation would leak the
        wrapper across selections.
        """
        from langchain_core.tools import StructuredTool

        inner = getattr(tool, "coroutine", None)
        if inner is None:
            return tool  # sync/stdio tool variant — leave untouched

        provider = self

        async def pinned_load_program(**kwargs: Any) -> str:
            pinned = getattr(provider._job, "mirror_sample_path", None)
            if isinstance(pinned, str) and pinned and kwargs.get("file") != pinned:
                logger.warning(
                    "load_program: overriding model-supplied path %r with known container path %r.",
                    kwargs.get("file"),
                    pinned,
                )
                kwargs["file"] = pinned
            return str(await inner(**kwargs))

        return StructuredTool.from_function(
            func=None,
            coroutine=pinned_load_program,
            name=tool.name,
            description=tool.description,
            args_schema=tool.args_schema,
        )

    def mirror_spec(self) -> MirrorSpec:
        return MirrorSpec(work_subdir=".work", container_prefix=self._container_samples_path)

    def function_hashes(self, job: StaticJobContext) -> list[tuple[str, str]]:
        """Two lines of delegation: the pre-pass itself already lives in analysis/."""
        from maljan.analysis.function_hash_attribution import fetch_bulk_function_hashes

        if not self.capabilities.provides_function_hashes or not job.mirror_sample_path:
            return []
        return fetch_bulk_function_hashes(
            base_url=self._cfg.url,
            auth_token=self._cfg.auth_token,
            file_path=job.mirror_sample_path,
            min_instructions=self._pre.function_hash_min_instructions,
        )

    async def probe(self) -> ProviderProbe:
        """The headless server's own health endpoint, with the configured token."""
        import time

        import httpx

        t0 = time.perf_counter()
        headers = (
            {"Authorization": f"Bearer {self._cfg.auth_token}"} if self._cfg.auth_token else {}
        )
        url = f"{self._cfg.url.rstrip('/')}/check_connection"
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(url, headers=headers)
        except httpx.HTTPError as exc:
            return ProviderProbe(
                ok=False,
                detail=redact_url(f"{type(exc).__name__}: {exc}"),
                latency_ms=int((time.perf_counter() - t0) * 1000),
            )
        return ProviderProbe(
            ok=response.status_code < 400,
            detail=f"HTTP {response.status_code}",
            latency_ms=int((time.perf_counter() - t0) * 1000),
        )

    def _close_toolkit(self) -> None:
        """Release whatever client or subprocess is currently attached, if any.

        The one release path, shared by ``close()`` (job-end teardown) and
        ``open()`` (mid-life re-attach for a job that differs from the one
        already open) — so there is never a point where two toolkits are
        live at once, and never a point where releasing one is written twice.
        Teardown that can throw is teardown nobody calls, so every failure
        here is a warning.
        """
        from maljan.agents.base_agent import _run_coro_blocking

        toolkit, self._toolkit = self._toolkit, None
        self._all_tools = []
        if toolkit is None:
            return
        closer = getattr(toolkit, "cleanup", None) or getattr(toolkit, "aclose", None)
        if closer is None:
            return
        try:
            _run_coro_blocking(closer(), hard_timeout=20.0, label="ghidra-close")
        except Exception as exc:  # noqa: BLE001 - teardown never propagates
            logger.warning("Ghidra provider teardown failed (non-fatal): %s", exc)

    def close(self) -> None:
        self._close_toolkit()
