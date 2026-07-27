"""Hierarchical application configuration.

Uses nested Pydantic models so that each subsystem (LLM, negotiation, etc.)
has its own isolated config namespace. Environment variables are flattened
with double-underscore separators (e.g. LLM__PROVIDER=anthropic).

Heterogeneous Model Ensemble (Phase 8 / Master Plan Section 4):
  Agents can now be assigned different LLM providers/models via
  LLMConfig.agents dict. Example env vars:

    LLM__AGENTS__STATIC__PROVIDER=anthropic
    LLM__AGENTS__STATIC__MODEL=claude-3-5-sonnet-20241022
    LLM__AGENTS__DYNAMIC__PROVIDER=openai
    LLM__AGENTS__DYNAMIC__MODEL=gpt-4o
    LLM__AGENTS__NETWORK__PROVIDER=ollama
    LLM__AGENTS__NETWORK__MODEL=llama3.1:8b

  Agents without an explicit entry fall back to the global expert LLM
  (backward-compatible: existing configs require no changes).
"""

from typing import Any, Literal

from pydantic import BaseModel, Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

# ---------------------------------------------------------------------------
# Per-provider LLM configs
# ---------------------------------------------------------------------------


class OpenAIConfig(BaseModel):
    """OpenAI-specific model selection.

    base_url can be overridden to use OpenAI-compatible APIs such as
    Kimi AI (Moonshot), DeepSeek, or Azure OpenAI.
    """

    api_key: SecretStr | None = None
    base_url: str | None = None
    expert_model: str = "gpt-4o-mini"
    judge_model: str = "gpt-4o"
    # Sampler repetition penalty forwarded to OpenAI-compatible local servers
    # (llama.cpp / ik_llama.cpp) via extra_body. 1.0 = no-op. Values around
    # 1.15 break the small reasoning model out of the catastrophic ATT&CK
    # ID-recall loops observed in live runs. Only applied when base_url is
    # set, so vanilla OpenAI (which would 400 on the param) stays untouched.
    repetition_penalty: float = 1.0
    # Disable a local reasoning model's chain-of-thought (Qwen3 ``<think>``)
    # by forwarding ``chat_template_kwargs.enable_thinking=false`` via extra_body.
    # On constrained hosts the reasoning model otherwise spends the whole decode
    # budget inside ``<think>`` (which the server strips into reasoning_content,
    # leaving an empty answer + frequent timeouts). Off by default; only applied
    # when base_url is set, so vanilla OpenAI stays untouched.
    disable_thinking: bool = False


class AnthropicConfig(BaseModel):
    """Anthropic-specific model selection."""

    api_key: SecretStr | None = None
    expert_model: str = "claude-sonnet-4-20250514"
    judge_model: str = "claude-sonnet-4-20250514"


class OllamaConfig(BaseModel):
    """Ollama (local) model selection."""

    base_url: str = "http://localhost:11434"
    expert_model: str = "qwen3.5:9b"
    judge_model: str = "qwen3.5:9b"
    keep_alive: str = "30m"
    num_ctx: int = 32768


class GeminiConfig(BaseModel):
    api_key: SecretStr | None = None
    expert_model: str = "gemini-2.5-pro"
    judge_model: str = "gemini-2.5-pro"


class AgentLLMConfig(BaseModel):
    """Per-agent LLM override for heterogeneous model ensemble.

    When populated for a specific agent name, ServiceContainer will build a
    dedicated LLM instance for that agent instead of reusing the global expert
    LLM. This breaks the single-model echo chamber by ensuring each expert
    uses a different model family.

    Attributes:
        provider:    LLM provider name ("openai", "anthropic", "ollama").
                     Overrides the global LLMConfig.provider for this agent.
        model:       Model identifier (e.g. "gpt-4o", "claude-3-5-sonnet",
                     "llama3.1:8b"). Required when provider is set.
        temperature: Optional temperature override. Defaults to 0.1 when None.
    """

    provider: str
    model: str
    temperature: float | None = None


class LLMConfig(BaseModel):
    """Top-level LLM configuration grouping provider selection and per-provider settings.

    agents: Optional per-agent LLM overrides for heterogeneous ensemble.
    Empty dict means all agents share the global expert LLM (default behavior).
    """

    provider: str = "openai"
    openai: OpenAIConfig = Field(default_factory=OpenAIConfig)
    anthropic: AnthropicConfig = Field(default_factory=AnthropicConfig)
    ollama: OllamaConfig = Field(default_factory=OllamaConfig)
    gemini: GeminiConfig = Field(default_factory=GeminiConfig)
    # Per-agent overrides: {"static": AgentLLMConfig(...), "dynamic": ...}
    agents: dict[str, AgentLLMConfig] = Field(default_factory=dict)

    # Hard output cap for the judge verdict generation (max_tokens). The judge
    # otherwise has no output bound — only the 600 s wall-clock timeout — so a
    # degenerate/rambling decode on the slow local model burns the full budget
    # and falls back to an empty bundle (the §1.7.1 ablation measured this:
    # without focus the judge hit the 600 s timeout 6/17 vs 1/17). A verdict
    # STIX bundle is small (observed obj<=13, ~2-4k tokens); 8192 leaves wide
    # headroom for legitimate output yet bounds a runaway decode to ~205 s at
    # ~40 tok/s, well under the timeout. This is a worst-case-latency/robustness
    # guard (in the spirit of the §3.3 degenerate-loop damper), not a quality
    # fix — focus comes from the §7.1 hint. Set 0 to disable (unbounded).
    judge_max_tokens: int = 8192

    # Wave 7 THROUGHPUT-01 (2026-05-28): when True, analysts run in parallel —
    # correct for hosted multi-slot LLMs. When False (the DEFAULT since
    # 2026-07-13), the pipeline runs analysts sequentially so a single-slot
    # local llama-server gives each analyst exclusive slot use for its
    # per-agent timeout budget instead of letting them choke each other in the
    # request queue. Set ``LLM__PARALLEL_ANALYSTS=true`` only for a hosted
    # multi-slot API with real per-request isolation.
    #
    # 2026-07-13 ROOT-CAUSE (supersedes the "SWA re-prefill" misdiagnosis in
    # findings-log): the served Qwen3.6-35B-A3B is a HYBRID Gated-DeltaNet
    # (recurrent) + attention MoE — NOT a sliding-window model. On a single
    # llama-server slot, "parallel" analysts interleave their requests and each
    # one CLOBBERS the others' per-slot recurrent DeltaNet state; llama.cpp /
    # ik_llama cannot restore the recurrent context checkpoint (open bug
    # ik_llama#1762 / ggml-org#20225), so every ReAct step then does a FULL
    # prompt re-processing → minutes/turn → the revision round hit
    # request_timeout (900s) and runs took ~41 min. Sequential (False) gives
    # each analyst exclusive slot use, so its recurrent state survives across
    # its own ReAct steps → only new tokens are processed → no re-prefill, no
    # timeout. MEASURED on sample 11e77149 + CAPE: parallel 2480s (revision
    # timed out) → sequential 743s (3.3×, zero timeouts).
    #
    # Honoured in BOTH phases: the initial fan-out (pipeline/builder.py —
    # parallel edges vs a sequential chain) AND the revision node
    # (pipeline/nodes.py — concurrent asyncio.gather vs a sequential await
    # loop). The default flipped True→False (2026-07-13) so a run WITHOUT a
    # local .env (CI, fresh clone, deploy) is safe by default — otherwise
    # parallel + the restored deep static budget = the exact uncapped
    # re-prefill the old caps once masked. Do NOT re-enable on a single-slot
    # hybrid-model deployment.
    parallel_analysts: bool = False

    # View-decomposition pilot (findings-log §3.6). 0 = off (today's single
    # monolithic analyst call). N > 0 splits the analyst's text-evidence into N
    # focused sub-prompts run concurrently and merged, each capped at
    # ``expert_max_tokens // N`` so the total generation budget matches the
    # monolithic arm (the equal-budget control §3.2 lacked). Text path only;
    # the tool-using Ghidra/CAPE ReAct loop is unaffected. Stays off until the
    # §3.6 eval justifies it. Set ``LLM__VIEW_DECOMPOSITION_VIEWS=2`` to pilot.
    view_decomposition_views: int = 0

    # Per-call output budget for the analyst LLM. Used to size the equal-budget
    # split when ``view_decomposition_views > 0`` (0 = provider/server default,
    # i.e. UNBOUNDED on llama-server).
    #
    # 2026-07-26 audit (Ö3) — raised 0 -> 8192. The analyst path was the only
    # unbounded LLM call in the system (judge 8192, narrative 1500, composer 900
    # are all capped). MEASURED on a 36 KB sample: after the depth restore the
    # static analyst gathered 19 tool observations, and the forced-synthesis
    # salvage that digests them ran **19+ minutes** against its 25-minute wall
    # clock (the same sample synthesised in 118 s before the depth restore). An
    # unbounded budget also gives the §3.3 degenerate-repetition failure mode a
    # full 25 minutes to burn. 8192 matches ``judge_max_tokens`` and is far above
    # any legitimate analyst answer (~2-4k tokens observed), so it bounds the
    # tail without truncating real output. Set 0 to restore unbounded.
    expert_max_tokens: int = 8192

    # View-decomposition strategy when ``view_decomposition_views >= 2``
    # (findings-log §4 Item 3, LAMD). "facet" = horizontal, AppPoet-style
    # independent facets over the same evidence (the §3.6 default). "tier" =
    # LAMD-style vertical reasoning — facts -> behaviour -> ATT&CK semantics,
    # each tier sequentially consuming the previous tier's findings (canonical
    # N=3). Both strategies share the equal-budget ``expert_max_tokens // N``
    # split and the tools-free text path. Ignored when decomposition is off.
    view_decomposition_mode: Literal["facet", "tier"] = "facet"

    @property
    def expert_model(self) -> str:
        """Returns the expert model name for the currently selected provider."""
        provider_cfg: dict[str, BaseModel] = {
            "openai": self.openai,
            "anthropic": self.anthropic,
            "ollama": self.ollama,
            "gemini": self.gemini,
        }
        cfg = provider_cfg.get(self.provider, self.openai)
        return cfg.expert_model  # type: ignore[attr-defined, no-any-return]

    @property
    def judge_model(self) -> str:
        """Returns the judge model name for the currently selected provider."""
        provider_cfg: dict[str, BaseModel] = {
            "openai": self.openai,
            "anthropic": self.anthropic,
            "ollama": self.ollama,
            "gemini": self.gemini,
        }
        cfg = provider_cfg.get(self.provider, self.openai)
        return cfg.judge_model  # type: ignore[attr-defined, no-any-return]


# ---------------------------------------------------------------------------
# Negotiation engine config
# ---------------------------------------------------------------------------


class NegotiationConfig(BaseModel):
    """Controls the multi-agent negotiation loop.

    max_iterations is a safety ceiling, NOT the expected round count.
    The primary exit condition is Adaptive Termination (rolling std on
    confidence_history). The hard limit exists only to prevent runaway
    loops when adaptive convergence fails.
    """

    max_iterations: int = 5
    consensus_threshold: float = 0.85


class ChunkingConfig(BaseModel):
    """Controls binary/text chunking behaviour for large input data.

    The chunker splits oversized analyst inputs into overlapping windows
    so each chunk fits within the LLM context. Agents summarize each chunk
    independently and merge the summaries before ISR construction.
    """

    # Maximum tokens per chunk sent to the LLM.
    #
    # 2026-07-11 — raised 6000 -> 20000 after the GPU/context upgrade. The old
    # 6000 was sized for the pre-GPU ~32K-context era; against a real PE it
    # split the decompiled static text into 27 chunks, and since the static
    # analyst's per-chunk ReAct loop re-runs ``load_program`` + Ghidra auto-
    # analysis on EVERY chunk (see static_analyst._ISR_SYSTEM step 1), each of
    # the 27 chunks burned its full 1200s budget — jobs never finished (live
    # job 95d88f7e/task 10, 2026-07-11: chunk 1/27 alone hit the hard cap).
    # llama-server now serves 128K (``-c 131072``); budgeting ~80K for the
    # static loop's 40 tool observations (max_tool_output_chars=8000 each), ~4K
    # system and ~8K generation leaves ~36K headroom, so 20K/chunk is safe and
    # collapses that same PE to ~8 chunks. Override via
    # ``CHUNKING__MAX_TOKENS_PER_CHUNK``.
    max_tokens_per_chunk: int = 20000

    # Overlap between consecutive chunks (in tokens) to preserve context
    overlap_tokens: int = 200

    # If True, skip chunking for data smaller than max_tokens_per_chunk
    skip_if_fits: bool = True


class MemoryConfig(BaseModel):
    """Phase 5 Long-Term Memory configuration.

    Controls which backend is used to store and retrieve past analysis
    cases for few-shot context injection in JudgeAgent.give_verdict().

    backend:            "memory" (default) uses InMemoryStore — no external
                        dependencies. "qdrant" uses QdrantStore which requires
                        a running Qdrant instance and the qdrant-client package.
    qdrant_url:         Qdrant server URL (only used when backend="qdrant").
    qdrant_collection:  Qdrant collection name for Maljan cases.
    top_k:              Maximum number of similar cases to inject into the
                        judge prompt. Higher values provide more context but
                        increase prompt length.
    """

    backend: str = "qdrant"  # "memory" | "qdrant"
    qdrant_url: str = "http://localhost:6333"
    # v2 collection name — created with fastembed/BGE 384-dim vectors. Operators
    # upgrading from the pre-fastembed era (which used 512-dim hash vectors in
    # a collection named ``maljan_cases``) should either point at this fresh
    # name or delete the old collection explicitly.
    qdrant_collection: str = "maljan_cases_v2"
    top_k: int = 3
    # Function-hash attribution tier (deterministic, exact opcode-hash match).
    # A separate Qdrant collection stores per-function normalized-opcode hashes
    # keyed to the malware family, so a new sample sharing functions with a
    # known one yields a high-precision family link. Independent of the
    # semantic ``qdrant_collection`` above (which does fuzzy prose retrieval).
    qdrant_function_hash_collection: str = "maljan_function_hashes_v1"


class SandboxConfig(BaseModel):
    """Sandbox backend configuration.

    Controls which backend is used for dynamic sample analysis. The sandbox
    client is exposed via ServiceContainer.get_sandbox_client() and can be
    passed to FileDataLoader.load_from_sandbox().

    backend:
        "mock"  (default) — MockSandboxClient loads fixture JSON files from
                the samples directory. Requires no network access or external
                services. Safe for CI, tests, and local development.
        "cape2" — CAPEv2Client submits samples to a live CAPEv2 instance via
                its REST API. Requires httpx and a running CAPEv2 server.
                Recommended for production / private samples.

    cape2_base_url, cape2_api_token, cape2_timeout_seconds,
    cape2_poll_interval_seconds:
        CAPEv2 endpoint, optional bearer token, completion timeout and poll
        interval. Token can be empty for unauthenticated local instances.
    """

    backend: str = "mock"  # "mock" | "cape2"
    cape2_base_url: str = "http://localhost:8000"
    cape2_api_token: SecretStr = SecretStr("")
    cape2_timeout_seconds: int = 300
    cape2_poll_interval_seconds: int = 10


class AnalysisConfig(BaseModel):
    """Analysis layer configuration.

    Controls deterministic analysis layer settings (YARA, Sigma).

    sigma_rules_dir:
        Directory containing Sigma rule YAML files. Loaded recursively.
        Set to a non-existent path to disable Sigma layer (graceful degradation).
    """

    sigma_rules_dir: str = "data/sigma_rules"


class PreprocessingConfig(BaseModel):
    """Optional preprocessing pipeline configuration.

    Controls the FunctionSummarizer — a lightweight pre-summarization
    step that reduces token cost for large binary analysis inputs.

    use_function_summarizer:
        Set to True to enable chunk pre-summarization. Off by default.
    summarizer_provider:
        LLM provider for the summarizer (prefer a small local model).
    summarizer_model:
        Model identifier for the summarizer LLM.
    summarizer_max_words:
        Maximum words in each chunk summary.
    max_tool_output_chars:
        Maximum character length for MCP tool outputs. When a tool
        returns text exceeding this limit, the output is either
        summarized (if FunctionSummarizer is enabled) or truncated.
    """

    use_function_summarizer: bool = False
    summarizer_provider: str = "ollama"
    summarizer_model: str = "llama3.2:3b"
    summarizer_max_words: int = 150
    # 2026-07-13 — restored 3000 -> 6000 (was 8000 before the 2026-07-11 cut).
    # The cut to 3000 blamed "SWA re-prefill", a MISDIAGNOSIS: the served model
    # is a hybrid Gated-DeltaNet (recurrent) MoE, not sliding-window, and the
    # real re-prefill cause was parallel analysts clobbering the single slot's
    # recurrent state (fixed by parallel_analysts=False; see LLMConfig). With
    # sequential analysts each ReAct step reuses the prior context, so richer
    # observations no longer inflate re-prefill cost. 6000 chars (~1500 tokens)
    # per Ghidra observation lets a full priority function's pseudo-C survive
    # untruncated. NOT 8000: there is no in-loop context pruning, so at the
    # restored static max_steps=40 the worst-case accumulation is ~40*1500 tool
    # tokens + 20k chunk + ~12k system/gen ~= 90-95k — a safe ~36k under
    # n_ctx=131072. 8000 would push the peak to ~112k, and crossing 131072
    # triggers a silent server context-shift that drops the earliest tokens (the
    # load_program framing) — catastrophic and invisible. Override via
    # ``PREPROCESSING__MAX_TOOL_OUTPUT_CHARS``.
    max_tool_output_chars: int = 6000

    # Sink-reachability triage (Maltracker-inspired). When enabled, the static
    # analyst runs a deterministic pre-pass over the Ghidra call graph to find
    # the functions that reach security-sensitive sink APIs and injects a
    # "priority functions" hint into its prompt, focusing decompilation on the
    # malicious core. Fail-safe: any error or a stripped binary yields no hint.
    use_sink_reachability: bool = True
    sink_reachability_max_funcs: int = 12

    # TraceRAG-style function-level retrieval for the static analyst (§4 Item 2).
    # 0 = off (linear chunking — every function chunk fed to the LLM). N > 0: for
    # large binaries, retrieve the top-N function chunks per behavior query (see
    # function_index.BEHAVIOR_QUERIES) and feed only their union, focusing the
    # analyst on the malicious core. Engages only when the static chunk count
    # exceeds ``static_function_rag_min_chunks`` (small binaries keep the full
    # path). Fail-safe: retrieval that matches nothing falls back to all chunks.
    static_function_rag_top_k: int = 0
    static_function_rag_min_chunks: int = 6

    # LAMD-style inline foundational-tier consistency gate (§4 Item 4). When
    # True, the analyst safe_* wrappers drop claims whose cited artifact /
    # technique does not appear in the source evidence text — catching
    # hallucinated claims at parse time, complementing the post-hoc, structural
    # fp_linter. Off by default (today's behaviour: every parsed claim kept).
    # Fail-safe: any gate error leaves the ISR untouched.
    use_claim_consistency_gate: bool = False

    # Function-hash attribution tier. When enabled, the static analyst runs a
    # deterministic pre-pass that computes per-function normalized-opcode hashes
    # (Ghidra ``get_bulk_function_hashes``) and queries the function-hash store
    # for exact matches against past samples, injecting a high-precision
    # "attribution prior" hint. The judge node mirrors this write-side, upserting
    # the current sample's hashes under its inferred family so the corpus grows.
    # Functions with fewer than ``function_hash_min_instructions`` instructions
    # are ignored — tiny thunks/stubs collide across unrelated binaries and would
    # otherwise produce false family links. Fail-safe and http-transport only.
    use_function_hash_attribution: bool = True
    function_hash_min_instructions: int = 8
    function_hash_max_matches: int = 8

    # Family-feature RAG (§4 dataset-survey workstream — LLM-centric attribution).
    # When enabled AND a vendored fingerprint catalog exists at
    # ``family_fingerprint_catalog_path``, the static analyst gets a deterministic
    # static-feature PROFILE of the sample matched against an offline-built family
    # fingerprint KB (from MABEL / a raw-binary corpus); the top-k nearest families
    # are injected as CANDIDATE evidence and the LLM decides the attribution. This
    # fills the static-only gap (no sandbox CTI / sandbox sig to name a family) while
    # staying LLM-centric: retrieval only surfaces candidates — it never predicts.
    # No trained model and no heavy deps (reuses the fastembed BGE-384 embedder
    # already loaded for LTM). OFF by default: absent a catalog it degrades to a
    # no-op (fail-safe). Build the catalog with scripts/build_family_feature_kb.py.
    use_family_feature_rag: bool = False
    family_fingerprint_catalog_path: str = "data/family_fingerprints_v1.json"
    family_rag_top_k: int = 5
    family_rag_min_score: float = 0.3

    # Windows API behaviour map — the data-driven replacement for the 51-entry
    # ``pe_extractor._SUSPICIOUS_IMPORTS`` table. ~680 API names across 13
    # behaviour categories, with a per-category tier deciding which of them
    # actually count as *suspicious* (categorising RegOpenKeyExA is useful;
    # flagging it is not). ON by default and fail-safe in both directions: a
    # missing or malformed catalog logs once and falls back to the built-in
    # table, so the worst case is the behaviour we shipped before it existed.
    # Build it with scripts/build_api_capability_db.py.
    use_api_behaviour_map: bool = True
    api_behaviour_map_path: str = "data/api_behaviour_map_v1.json"

    # Deterministic API→ATT&CK mapping, computed from the same resolved-import
    # set as the behaviour map above (one parse, two projections). This is what
    # gives a sandbox-unreachable run real technique coverage: without it the
    # import layer emits at most three techniques, all hand-coded.
    # Every claim is capped below the YARA floor (0.70) so it corroborates other
    # layers without solo-driving a verdict, and each technique declares a
    # ``min_apis`` so a single ubiquitous import cannot promote itself to a
    # finding. ON by default; absent the catalog the layer keeps its previous
    # three-technique behaviour.
    use_api_attck_map: bool = True
    api_attck_map_path: str = "data/api_attck_map_v1.json"

    # ATT&CK case-prior RAG (§4 U2 — LLM-centric, cross-sample TTP grounding).
    # The per-sample function RAG retrieves over THIS sample's own functions only;
    # this fills the cross-sample gap. When enabled AND a vendored case corpus exists
    # at ``attck_case_corpus_path``, the static analyst's sample profile retrieves the
    # behaviourally-similar prior cases mined from our OWN long-term memory (Qdrant
    # StoredCase: summary_text + attributed technique_ids), and their technique_ids are
    # aggregated into a ranked ATT&CK CANDIDATE list injected as evidence — the LLM
    # decides which TTPs apply. Raises static-only TTP precision without a second
    # statistical brain (nothing trained; adding a case is a new corpus row). Reuses
    # the fastembed BGE-384 embedder already loaded for LTM — zero new deps. OFF by
    # default: absent a corpus it degrades to a no-op (fail-safe). Build the corpus
    # with scripts/build_attck_case_kb.py.
    use_attck_case_rag: bool = False
    attck_case_corpus_path: str = "data/attck_case_corpus_v1.json"
    attck_case_rag_top_k: int = 5
    attck_case_rag_min_score: float = 0.35
    attck_case_rag_max_techniques: int = 8

    # Deterministic ATT&CK technique-ID correction. When enabled, the judge node
    # runs a pre-cascade pass that re-grounds each LLM analyst claim's technique_id
    # against the in-memory TF-IDF ATT&CK index: invalid IDs are replaced with the
    # top evidence-derived suggestion, and valid-but-poorly-aligned IDs are swapped
    # only when a strictly better-aligned suggestion exists. This removes the small
    # model's loop-prone ID-recall sub-task from the critical path; the model just
    # describes behaviour and the index assigns the ID. Layer-0 deterministic
    # sources (yara/sigma) are skipped — their IDs are rule-authoritative. Fail-safe.
    use_attck_autocorrect: bool = True
    attck_autocorrect_min_alignment: float = 0.08
    # Whether to also swap VALID-but-low-alignment technique IDs (not just fix
    # invalid ones). The TRAM2 ablation (findings-log §1.5.2) found this path
    # damages ~38% of already-correct IDs while recovering only ~21% of wrong
    # ones, and the two cannot be separated by the alignment gate — net negative.
    # Default False: autocorrect only fixes invalid/hallucinated IDs, which is a
    # provably zero-regression operation. Enable only for offline experiments.
    attck_autocorrect_swap_valid: bool = False
    # ATT&CK index backend for technique-ID grounding (§1.5). One of:
    #   "tfidf"    keyword bag-of-words (clean alignment gate, weaker ranking)
    #   "semantic" dense BGE-384 embeddings (better ranking, poor gate)
    #   "hybrid"   semantic ranking + TF-IDF gate — best of both (DEFAULT, §1.5.1)
    # The TRAM2 comparison (tests/evaluation/eval_technique_mapping.py) showed the
    # hybrid dominates both pure backends: it matches semantic's ranking (+6pp
    # top-3 over TF-IDF) AND gives the cleanest alignment gate (correct-vs-wrong
    # separation +0.108 vs TF-IDF +0.068 vs semantic +0.020). Its gate is TF-IDF,
    # so the existing 0.08 threshold applies. fastembed is already loaded in
    # production for long-term memory, so the marginal cost is one catalog embed
    # at startup. Set to "tfidf" to skip embeddings entirely (air-gapped/minimal).
    attck_index_backend: str = "hybrid"
    # Semantic threshold is intentionally 0.0: the eval showed absolute semantic
    # scores do not separate correct from wrong, so the absolute low-alignment
    # gate is disabled for that backend (it still fixes invalid IDs and applies
    # strictly-better relative swaps, which need no absolute threshold).
    attck_autocorrect_min_alignment_semantic: float = 0.0

    # Backend for malware-category inference (drives the §7.1 STIX schema-pruning
    # hint). Default "keyword" = the deterministic substring classifier
    # (schema_pruner.infer_malware_category) — zero-dependency and, critically,
    # it *abstains* (UNKNOWN -> no hint) rather than guessing, which is the safe
    # failure mode for an advisory hint.
    #
    # The category-inference eval (tests/evaluation/eval_category_inference.py,
    # 101 ATT&CK families labelled by self-declared type) measured:
    #   * keyword:               full 0.792 acc / behavioral 0.327 (abstains 38%)
    #   * semantic (zero-shot):  full 0.376 / behavioral 0.168  (NOT recommended —
    #                            averaged technique prototypes are too blurry)
    #   * hybrid (kw->semantic): full 0.812 / behavioral 0.386  (small lift; no
    #                            new data, fastembed already loaded for memory)
    # The strongest variant (keyword -> *few-shot* fallback: full 0.832 /
    # behavioral 0.525) needs a labelled prototype corpus (e.g. LTM stored cases)
    # and is therefore not a config-only switch. Keyword stays the default
    # because on realistic analyst text (which names the category, ~the "full"
    # regime) it is competitive AND safe-abstaining; the hint is advisory anyway,
    # so the marginal category-accuracy gain has limited end-to-end effect.
    # Set to "hybrid" to recover keyword's abstentions via the semantic fallback.
    category_inference_backend: str = "keyword"  # "keyword" | "semantic" | "hybrid"


# ---------------------------------------------------------------------------
# MCP (Model Context Protocol) Integration
# ---------------------------------------------------------------------------


class MCPServerConfig(BaseModel):
    """Configuration for a single MCP server connection.

    Supports two transports:
      - "stdio": local subprocess (default). Uses command + args.
      - "http": remote HTTP REST API. Uses url + auth_token.
    """

    enabled: bool = False
    transport: str = "stdio"  # "stdio" | "http"
    # stdio transport settings
    command: str = ""
    args: list[str] = Field(default_factory=list)
    env: dict[str, str] = Field(default_factory=dict)
    # http transport settings
    url: str = ""
    auth_token: str = ""
    # 2026-07 round 3: how many Ghidra MCP tools the static analyst exposes to the
    # model (MCP__GHIDRA__TOOL_SELECTION):
    #   "curated" — fixed ~20-tool allowlist (fastest, narrowest).
    #   "dynamic" — CORE triage set + tools relevant to the sample's capability
    #               categories (~30-40 tools). All ~165 stay reachable; only the
    #               relevant subset is shown per run. RECOMMENDED DEFAULT.
    #   "all"     — every tool the server offers (~165). Maximum coverage but a
    #               large per-step prompt; measured 5-6x slower + noisier locally.
    tool_selection: Literal["curated", "dynamic", "all"] = "dynamic"
    # Back-compat: MCP__GHIDRA__USE_ALL_TOOLS=true still forces "all".
    use_all_tools: bool = False


class MCPConfig(BaseModel):
    """MCP integration configurations for external tools."""

    ghidra: MCPServerConfig = Field(default_factory=MCPServerConfig)
    cape: MCPServerConfig = Field(default_factory=MCPServerConfig)


# ---------------------------------------------------------------------------
# Reporting (Faz 2+)
# ---------------------------------------------------------------------------


class ReportingConfig(BaseModel):
    """Comprehensive malware report generation settings.

    The pipeline's ``report_node`` reads these flags:

    - ``enabled``: when False the graph keeps the legacy ``judge → END`` edge
      and downstream consumers receive only ``judge_report`` / ``stix_output``.
    - ``include_extended_stix``: emit the extended Bundle (Identity / Note /
      Report SDOs). Disable to halve serialization cost when consumers only
      need the minimal judge bundle.
    - ``narrative_max_tokens``: hard cap for the NarrativeAgent LLM round
      (Faz 3). Keeps tail latency predictable.
    - ``auto_generate_detection_rules``: template-based YARA/Sigma/Suricata
      generation (Faz 4).
    - ``enrichment_async``: enqueue a threat-intel enrichment ARQ job after
      verdict instead of blocking the pipeline (Faz 6).
    """

    enabled: bool = True
    include_extended_stix: bool = True
    narrative_max_tokens: int = 1500
    auto_generate_detection_rules: bool = True
    enrichment_async: bool = True

    # --- Report-reshaping (professional-report front-matter + Composer) ---
    # Front-matter identity for the report cover / TLP banner.
    publisher: str = "Maljan"
    product_type: str = "Malware Analysis Report"
    author_team: str = "Maljan Multi-Agent Pipeline"
    report_number_prefix: str = "MJN"
    default_tlp: Literal["CLEAR", "GREEN", "AMBER", "AMBER_STRICT", "RED"] = "CLEAR"
    # Section-wise Report Composer (Phase 4). When False, the pipeline keeps the
    # legacy single-round NarrativeAgent. Bounded per-section prompts + hard
    # per-section timeout keep the local SWA model from stalling.
    composer_enabled: bool = True
    composer_section_max_tokens: int = 900
    composer_per_section_timeout: int = 120
    # Server-side HTML→PDF export (Phase 6).
    html_export_enabled: bool = True


# ---------------------------------------------------------------------------
# Root Settings
# ---------------------------------------------------------------------------


def _find_env_file() -> str:
    """Walk up from this file to find the project root .env.

    Supports launching from any subdirectory (apps/api, apps/web, etc.)
    without requiring the caller to set CWD to the project root.
    """
    from pathlib import Path

    current = Path(__file__).resolve().parent
    for _ in range(6):  # max 6 levels up
        candidate = current / ".env"
        if candidate.exists():
            return str(candidate)
        current = current.parent
    return ".env"  # fallback: let pydantic-settings handle the miss gracefully


class Settings(BaseSettings):
    """Root configuration - reads from .env and environment variables.

    Nested models use double-underscore env var separators:
        LLM__PROVIDER=anthropic
        LLM__OPENAI__API_KEY=sk-...
        NEGOTIATION__MAX_ITERATIONS=3
    """

    model_config = SettingsConfigDict(
        env_file=_find_env_file(),
        env_file_encoding="utf-8",
        env_nested_delimiter="__",
        extra="ignore",
    )

    # Sub-configs
    llm: LLMConfig = Field(default_factory=LLMConfig)
    negotiation: NegotiationConfig = Field(default_factory=NegotiationConfig)
    chunking: ChunkingConfig = Field(default_factory=ChunkingConfig)
    memory: MemoryConfig = Field(default_factory=MemoryConfig)
    sandbox: SandboxConfig = Field(default_factory=SandboxConfig)
    analysis: AnalysisConfig = Field(default_factory=AnalysisConfig)
    preprocessing: PreprocessingConfig = Field(default_factory=PreprocessingConfig)
    mcp: MCPConfig = Field(default_factory=MCPConfig)
    reporting: ReportingConfig = Field(default_factory=ReportingConfig)

    # Token overflow protection (128K is conservative for Gemini 1M+ context)
    max_token_limit: int = 128_000

    # ReAct agent execution limits
    react_agent_timeout: int = 180  # seconds before agent loop times out
    react_agent_max_steps: int = 10  # max LangGraph recursion steps
    # PERF-STATIC-ANALYST-LATENCY-01 (audit 2026-05-19) — tool-call budget.
    # When an analyst's ReAct loop exceeds this many cumulative tool calls
    # we log a WARNING. Not a hard limit (LangGraph's recursion_limit is
    # the structural cap); this is the early signal that an analyst is
    # spinning unproductively on tool calls. Set via env
    # ``REACT_AGENT_TOOL_CALL_BUDGET``.
    react_agent_tool_call_budget: int = 20

    # Per-agent timeout overrides. The default ``react_agent_timeout`` is
    # tuned for the network/dynamic analysts (~1-3 tool calls). The
    # static analyst attaches the Ghidra MCP server with many tools, so
    # we give it more headroom by default. The judge agent also needs a
    # larger budget on local models (Qwen3.6-35B on llama.cpp took 180+s
    # to formulate the final verdict in the 2026-05-23 E2E run, hitting
    # the previous ``max(timeout, 120)`` ceiling and triggering the
    # fallback path). Override via env, e.g.
    # ``REACT_AGENT_TIMEOUT_OVERRIDES__static=600``.
    react_agent_timeout_overrides: dict[str, int] = Field(
        default_factory=lambda: {
            # Wave 7.5 THROUGHPUT-02 (2026-05-28): the static analyst runs a
            # full ReAct loop against Ghidra MCP (load_program → auto-
            # analyze → behaviour scan → decompile). On the local 35B Qwen
            # at ~4.6 tok/s output the previous 600s ceiling fired
            # *during* Ghidra auto-analysis (live trace job 3450f9cd
            # 2026-05-28 — Ghidra logged ``Loaded program`` for the target
            # before the budget expired). 1200s covers a cold-cache cycle
            # end-to-end while still leaving headroom under the arq
            # 3600s job timeout once we add dynamic (600s) + network
            # (300s) + negotiation + judge. Reduce to 600s for hosted
            # multi-slot APIs.
            #
            # 2026-07-13 — restored 300 -> 1500 (per *chunk*). The 2026-07-11 cut
            # to 300 blamed "SWA re-prefill" (a MISDIAGNOSIS — see
            # max_tool_output_chars / parallel_analysts): the 1200s blow-ups were
            # parallel analysts clobbering the single slot's recurrent state, now
            # fixed by the sequential topology. This per-chunk wall-clock is the
            # BINDING constraint on depth — the restored static max_steps=40 is
            # inert unless the timeout moves with it (at ~15-20s/step, 300s fits
            # only ~15-20 steps). 40 steps ~= 600-800s when a rich chunk uses them
            # all; 1500 (hard cap timeout+30 = 1530s) is generous headroom so the
            # net never fires on a *progressing* chunk ("a timeout is a bug").
            # safe_analyze_isr_chunked still tolerates a genuinely wedged chunk.
            # Override via ``REACT_AGENT_TIMEOUT_OVERRIDES__static=1500``.
            "static": 1500,
            # Judge budget bumped 300 → 600 for the same reason — the
            # final-verdict LLM call on Qwen 35B repeatedly bottlenecked
            # at 180-300s in the 2026-05-28 sequential live runs.
            "judge": 600,
            # Wave 5 HANG-01 (2026-05-28): single-slot llama-server serialises
            # all three analyst LLM calls — when the static analyst holds the
            # slot for ~600s the dynamic / network analysts spend most of
            # their budget queueing. Bump them so they don't time out before
            # the LLM ever sees their request.
            "dynamic": 600,
            "network": 300,
        }
    )

    # Per-agent ReAct recursion-step overrides. The default
    # ``react_agent_max_steps`` (10) suits the network/dynamic analysts (0-3
    # tool calls), but the static analyst runs a full Ghidra MCP ReAct loop
    # (load_program -> list functions -> decompile -> imports/strings) that
    # needs far more than ~4 tool calls. With only 10 recursion steps it was
    # cut off mid-analysis and LangGraph returned the "Sorry, need more steps
    # to process this request." stop message instead of real claims (live job
    # 3be3ba0e, 2026-06-23: ReAct "completed" in 17.3s after just 4 tool calls,
    # hitting the step cap while its 1200s *time* budget was barely touched —
    # the per-agent timeout override added earlier missed the parallel step
    # cap). Override via env, e.g. ``REACT_AGENT_MAX_STEPS_OVERRIDES__static=40``.
    # ``network`` is capped LOW: with a real CAPE PCAP the analyst can enter a
    # read_pcap_summary/extract_* tool loop whose large per-packet output is slow
    # to prefill+decode on a constrained local model, over-running the 330s
    # analyst budget (live task 8, 2026-07-11). The structured flows are handed
    # to it up front (see network_analyst.analyze_isr), so a tight cap keeps the
    # optional PCAP peek from starving synthesis. ~6 steps ≈ 2-3 tool calls.
    # 2026-07-13 — static RESTORED 8 -> 40 (its original designed depth). The
    # 2026-07-11 cuts (40 -> 12 -> 8) blamed "SWA re-prefill": every step
    # re-prefilling ~58k tokens of growing Ghidra context, so late steps cost
    # 50-90s and chunks blew their cap. That was a MISDIAGNOSIS — the model is a
    # hybrid Gated-DeltaNet (recurrent) MoE, and the re-prefill was actually
    # parallel analysts clobbering the single slot's recurrent state, now fixed
    # by parallel_analysts=False (+ the revision node serialised; see LLMConfig).
    # With sequential analysts each step reuses the prior context (only new
    # tokens processed), so a deep loop is cheap again. 40 (~20 tool calls) is
    # the full Ghidra pass (load_program -> auto-analyze -> enumerate -> decompile
    # the sink-reachability priority functions -> xrefs -> strings -> imports ->
    # malware-specific tools). MEASURED (E2E 2026-07-13, sample 11e77149): static
    # did 19 tool calls -> 7 claims (vs 3 calls at cap=8), zero re-prefill, 120.9s
    # < 1500s. The small local model tends to keep tool-calling to the cap rather
    # than self-terminating, so the forced-synthesis salvage still fires — but now
    # it synthesises DEEP (19-call) evidence, not shallow (3-call). Depth is the
    # win; the salvage is the conclusion mechanism, not a bug. Raising the cap
    # further mostly adds tool calls + salvage time (diminishing returns).
    # MUST move with the static timeout (1500) — the per-chunk wall-clock is the
    # binding constraint. Context-safe: 40 steps * ~1500 tok (max_tool_output_
    # chars=6000) ~= 90-95k peak, ~36k under n_ctx=131072. Override via
    # ``REACT_AGENT_MAX_STEPS_OVERRIDES__static=40``.
    react_agent_max_steps_overrides: dict[str, int] = Field(
        default_factory=lambda: {
            "static": 40,
            "network": 6,
        }
    )

    # LangChain / LangSmith Tracing
    # Enable with: LANGCHAIN_TRACING_V2=true, LANGCHAIN_API_KEY=ls_xxx
    # ServiceContainer reads these and sets the OS env vars LangChain expects.
    langchain_tracing_v2: bool = False
    langchain_api_key: SecretStr | None = None
    langchain_project: str = "maljan"

    # Flat shortcut env vars (backward compatibility with existing .env files)
    openai_api_key: SecretStr | None = None
    anthropic_api_key: SecretStr | None = None
    google_api_key: SecretStr | None = None

    def model_post_init(self, __context: object) -> None:
        """Merge flat env vars into nested config for backward compatibility."""
        if self.openai_api_key and not self.llm.openai.api_key:
            self.llm.openai.api_key = self.openai_api_key
        if self.anthropic_api_key and not self.llm.anthropic.api_key:
            self.llm.anthropic.api_key = self.anthropic_api_key
        if self.google_api_key and not self.llm.gemini.api_key:
            self.llm.gemini.api_key = self.google_api_key


# ---------------------------------------------------------------------------
# Lazy access pattern
# ---------------------------------------------------------------------------
#
# A previous version instantiated ``settings = Settings()`` at import time.
# This caused two problems:
#   1. ``monkeypatch.setenv(...)`` inside test fixtures could not override
#      values because the singleton was already built.
#   2. Validation errors broke the import of ``maljan.core.config`` itself,
#      hiding the real failure behind an opaque ``ImportError``.
#
# The replacement is a memoised factory ``get_settings()``. Existing callers
# that import the legacy ``settings`` symbol still work — it is now a thin
# lazy proxy that constructs the Settings object on first attribute access.

_settings_instance: "Settings | None" = None


def get_settings() -> Settings:
    """Return the process-wide Settings singleton (lazy)."""
    global _settings_instance
    if _settings_instance is None:
        _settings_instance = Settings()
    return _settings_instance


def reset_settings_cache() -> None:
    """Drop the cached Settings instance (intended for tests)."""
    global _settings_instance
    _settings_instance = None


class _LazySettingsProxy:
    """Attribute-forwarding proxy that builds Settings on first access."""

    __slots__ = ()

    def __getattr__(self, name: str) -> Any:
        return getattr(get_settings(), name)

    def __setattr__(self, name: str, value: Any) -> None:
        setattr(get_settings(), name, value)

    def __repr__(self) -> str:
        return f"<LazySettingsProxy {get_settings()!r}>"


# Public lazy handle used by legacy imports such as
# ``from maljan.core.config import settings``.
settings: Any = _LazySettingsProxy()
