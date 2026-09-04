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

import copy
from typing import Annotated, Any, Literal, cast

from pydantic import BaseModel, Field, SecretStr, model_validator
from pydantic.fields import FieldInfo
from pydantic_settings import BaseSettings, PydanticBaseSettingsSource, SettingsConfigDict

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
    repetition_penalty: Annotated[float, Field(ge=0)] = 1.0
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
    num_ctx: Annotated[int, Field(ge=1)] = 32768


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


class FrontierArm(BaseModel):
    """One comparison endpoint.

    Was a single endpoint until 2026-08-14, when a second provider made a
    **parameter-size series** reachable instead of a single bigger model. That
    is a different and much stronger answer to P8: `arXiv:2606.18166` claims
    parameter count is the only significant predictor of ATT&CK-classification
    F1 (rho=0.85), and one comparison model can only agree or disagree with that
    on a single point, whereas a series can test the trend on our own task.

    ``max_spend_usd`` is a **hard** ceiling checked before every call, and the
    per-million-token rates are what make it enforceable. Leaving the rates at
    zero disables the arm rather than making it free — a meter that cannot price
    a call cannot refuse one. Set them from the provider's published pricing.
    """

    base_url: str | None = None
    api_key: SecretStr | None = None
    model: str = ""
    # Deliberately small. Raising it should be a decision, not a default.
    max_spend_usd: Annotated[float, Field(ge=0)] = 25.0
    input_usd_per_mtok: Annotated[float, Field(ge=0)] = 0.0
    output_usd_per_mtok: Annotated[float, Field(ge=0)] = 0.0

    # Set True only when the endpoint genuinely bills nothing (e.g. an
    # OpenRouter ``:free`` model). It is an explicit acknowledgement, not a
    # convenience: without it, zero pricing *disables* the arm, because a meter
    # that cannot price a call can never refuse one. Declaring free_tier says
    # "there is nothing to refuse", which is a different and checkable claim.
    # Token counts are still recorded — the paper reports cost in tokens
    # regardless of what the invoice says.
    free_tier: bool = False

    # Reasoning models (the frontier candidates are) emit a separate reasoning
    # stream that the provider returns outside ``content``. It still consumes
    # generation budget: a one-line answer measured 285 output tokens, most of
    # them reasoning. For an equal-budget comparison that is a real confound, so
    # the decision is recorded here rather than left implicit:
    #
    #   the cap is on TOTAL output tokens, reasoning included, and the harness
    #   reports the reasoning/content split so a reader can see how much of the
    #   frontier arm's budget went to thinking.
    #
    # Capping content only would hand the frontier arm more compute for the same
    # nominal budget; hiding the split would make the comparison unreadable.
    # (Note: OpenRouter's ``reasoning.exclude`` does NOT suppress generation — it
    # stops returning the stream separately, and the text then leaks into
    # ``content`` and exhausts the cap. Measured 2026-08-10. Leave it unset.)
    count_reasoning_tokens: bool = True

    # Throttling is a property of the endpoint, so it is configured per arm
    # rather than assumed by the harness. Measured 2026-08-14 on NVIDIA NIM:
    # two calls four seconds apart succeed and the next six return HTTP 429.
    # The first attempt at B8 recorded throttles as failures and reported n=9
    # with a wrong point estimate, so a paced client with backoff is now part of
    # the arm's definition and not something each harness reinvents.
    min_interval_s: Annotated[float, Field(ge=0)] = 0.0
    max_retries: Annotated[int, Field(ge=0)] = 6

    # Provenance for the parameter-size analysis, which is the whole reason
    # more than one arm exists. Recorded here so the correlation in the paper is
    # computed from configuration rather than from a number remembered while
    # writing, and so an arm cannot enter the series without declaring its size.
    total_params_b: Annotated[float, Field(ge=0)] = 0.0
    active_params_b: Annotated[float, Field(ge=0)] = 0.0
    quantisation: str = ""


class FrontierConfig(FrontierArm):
    """The frontier comparison arms (findings-log E.8, queue items B8 / C6).

    **Evaluation only.** Nothing in the analysis pipeline reads this; only the
    eval harnesses do, through ``maljan.core.frontier``. The arms exist to close
    pitfall **P8** — every LLM result in this work is one model on one machine,
    and a single-model finding cannot be read as a property of the architecture.

    Inherits the endpoint fields so the original single-endpoint configuration
    keeps working unchanged (``LLM__FRONTIER__MODEL`` and friends still describe
    one arm, the one B8 ran). Additional arms go in ``arms`` and are addressed by
    name: ``LLM__FRONTIER__ARMS__GLM__MODEL=...``.
    """

    enabled: bool = False
    arms: dict[str, FrontierArm] = Field(default_factory=dict)


class LLMConfig(BaseModel):
    """Top-level LLM configuration grouping provider selection and per-provider settings.

    agents: Optional per-agent LLM overrides for heterogeneous ensemble.
    Empty dict means all agents share the global expert LLM (default behavior).
    """

    provider: Literal["openai", "anthropic", "ollama", "gemini"] = "openai"
    openai: OpenAIConfig = Field(default_factory=OpenAIConfig)
    anthropic: AnthropicConfig = Field(default_factory=AnthropicConfig)
    ollama: OllamaConfig = Field(default_factory=OllamaConfig)
    gemini: GeminiConfig = Field(default_factory=GeminiConfig)
    # Evaluation-only comparison endpoint; see FrontierConfig.
    frontier: FrontierConfig = Field(default_factory=FrontierConfig)
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
    judge_max_tokens: Annotated[int, Field(ge=0)] = 8192

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
    view_decomposition_views: Annotated[int, Field(ge=0)] = 0

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
    expert_max_tokens: Annotated[int, Field(ge=0)] = 8192

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

    max_iterations: Annotated[int, Field(ge=1)] = 5
    consensus_threshold: Annotated[float, Field(ge=0, le=1)] = 0.85


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
    max_tokens_per_chunk: Annotated[int, Field(ge=1)] = 20000

    # Overlap between consecutive chunks (in tokens) to preserve context
    overlap_tokens: Annotated[int, Field(ge=0)] = 200

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

    backend: Literal["memory", "qdrant"] = "qdrant"
    qdrant_url: str = "http://localhost:6333"
    # v2 collection name — created with fastembed/BGE 384-dim vectors. Operators
    # upgrading from the pre-fastembed era (which used 512-dim hash vectors in
    # a collection named ``maljan_cases``) should either point at this fresh
    # name or delete the old collection explicitly.
    qdrant_collection: str = "maljan_cases_v2"
    top_k: Annotated[int, Field(ge=1)] = 3
    # Function-hash attribution tier (deterministic, exact opcode-hash match).
    # A separate Qdrant collection stores per-function normalized-opcode hashes
    # keyed to the malware family, so a new sample sharing functions with a
    # known one yields a high-precision family link. Independent of the
    # semantic ``qdrant_collection`` above (which does fuzzy prose retrieval).
    qdrant_function_hash_collection: str = "maljan_function_hashes_v1"
    # Sent with every Qdrant request when the server enforces one (compose
    # does, via QDRANT__SERVICE__API_KEY). Empty means no authentication,
    # which is fine for a loopback-only server.
    qdrant_api_key: SecretStr | None = None


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
    summarizer_provider: Literal["openai", "anthropic", "ollama", "gemini"] = "ollama"
    summarizer_model: str = "llama3.2:3b"
    summarizer_max_words: Annotated[int, Field(ge=1)] = 150
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
    max_tool_output_chars: Annotated[int, Field(ge=1)] = 6000

    # Sink-reachability triage (Maltracker-inspired). When enabled, the static
    # analyst runs a deterministic pre-pass over the Ghidra call graph to find
    # the functions that reach security-sensitive sink APIs and injects a
    # "priority functions" hint into its prompt, focusing decompilation on the
    # malicious core. Fail-safe: any error or a stripped binary yields no hint.
    use_sink_reachability: bool = True
    sink_reachability_max_funcs: Annotated[int, Field(ge=1)] = 12

    # TraceRAG-style function-level retrieval for the static analyst (§4 Item 2).
    # 0 = off (linear chunking — every function chunk fed to the LLM). N > 0: for
    # large binaries, retrieve the top-N function chunks per behavior query (see
    # function_index.BEHAVIOR_QUERIES) and feed only their union, focusing the
    # analyst on the malicious core. Engages only when the static chunk count
    # exceeds ``static_function_rag_min_chunks`` (small binaries keep the full
    # path). Fail-safe: retrieval that matches nothing falls back to all chunks.
    static_function_rag_top_k: Annotated[int, Field(ge=0)] = 0
    static_function_rag_min_chunks: Annotated[int, Field(ge=1)] = 6

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
    function_hash_min_instructions: Annotated[int, Field(ge=1)] = 8
    function_hash_max_matches: Annotated[int, Field(ge=1)] = 8

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
    #
    # Evidence so far: the retrieval layer beats chance on a leakage-free split
    # (recall@5 0.199 vs 0.032 random, family_rag_retrieval.json) but the end-to-end
    # A/B found no gain (f1 +0.003 at n=19, family_rag_ab.json) — hence still off.
    #
    # The default path is the 21-family bootstrap catalog, NOT the larger vendored ones
    # (family_fingerprints_rat_v1.json: 278 families; ..._mabel_v1.json: 318). That is
    # deliberate but easy to misread as an oversight: the A/B above ran on MABEL, so the
    # bigger catalog is the one already shown not to help. Point this at a larger catalog
    # only together with a re-run of eval_family_rag_retrieval.py — note that eval needs
    # data/samples/extracted/<Family>/{a0,a1}/, which is not vendored.
    use_family_feature_rag: bool = False
    family_fingerprint_catalog_path: str = "data/family_fingerprints_v1.json"
    family_rag_top_k: Annotated[int, Field(ge=1)] = 5
    family_rag_min_score: Annotated[float, Field(ge=0, le=1)] = 0.3

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

    # Offensive-tool / commodity-RAT byte markers (Cobalt Strike, Mimikatz,
    # Sliver, AsyncRAT, ...). The only source of a malware family name on a run
    # with no sandbox: FamilyAttribution otherwise draws it solely from CAPE's
    # cti.family[], so a static-only report knew its verdict but not what it was
    # looking at. Emits on the existing cascade domain "yara" so it inherits
    # that weight and cannot manufacture cross-layer corroboration with the
    # real YARA layer. Every entry needs two distinct markers to fire — one is
    # enough to flag an EDR agent or the defenders' own tooling.
    use_tool_artifacts: bool = True
    tool_artifacts_path: str = "data/tool_artifacts_v1.json"

    # Packer / protector signatures, replacing four hardcoded section-name
    # checks. Ranks its evidence: a section name is strong, an entry point in
    # an unexpected section is strong, a string is weak — "UPX!" appears in
    # every scanner's own signature table, this repo's included.
    # Note the coupling to the T1027 over-claim cap in capability_matrix: that
    # cap fires when static evidence does NOT support an obfuscation claim, so
    # a detector that fires more often makes the cap fire less often. The
    # confidence floor there is what stops a better detector from producing
    # *more* hallucinated T1027.
    use_packer_signatures: bool = True
    packer_signatures_path: str = "data/packer_signatures_v1.json"

    # Compiler / language fingerprints, replacing six literal byte checks.
    # Feeds two consumers that previously got nothing: platform inference for
    # otherwise-unknown blobs (an "unknown" platform silently drops every
    # platform-specific YARA and Sigma rule), and the static analyst's prompt,
    # which never saw what the sample was written in.
    use_language_signatures: bool = True
    language_signatures_path: str = "data/language_signatures_v1.json"

    # ATT&CK case-prior RAG (§4 U2 — LLM-centric, cross-sample TTP grounding).
    # The per-sample function RAG retrieves over THIS sample's own functions only;
    # this fills the cross-sample gap. When enabled AND a vendored case corpus exists
    # at ``attck_case_corpus_path``, the static analyst's sample profile retrieves the
    # behaviourally-similar prior cases mined from our OWN long-term memory (Qdrant
    # StoredCase: summary_text + attributed technique_ids), and their technique_ids are
    # aggregated into a ranked ATT&CK CANDIDATE list injected as evidence — the LLM
    # decides which TTPs apply. Raises static-only TTP precision without a second
    # statistical brain (nothing trained; adding a case is a new corpus row). Reuses
    # the fastembed BGE-384 embedder already loaded for LTM — zero new deps. Build the
    # corpus with scripts/build_attck_case_kb.py.
    #
    # STAYS OFF — measured, not merely undeployed (tests/evaluation/eval_attck_case_rag.py,
    # attck_case_rag_retrieval.json, 2026-08-08). The index itself works; the *query*
    # does not reach it:
    #
    #   corpus-native query (leave-one-out, near-duplicates suppressed)
    #       retrieval F1 0.620   vs frequency-prior 0.424   vs random 0.078
    #   production query (build_sample_profile_text over 15 labelled samples)
    #       retrieval F1 0.111   vs frequency-prior 0.123
    #
    # So with the query production actually sends, the candidate list is no better than
    # printing the eight most common techniques in the corpus and never looking at the
    # sample. The cause is a vocabulary mismatch, not a tuning problem: the corpus
    # renders capa rule sentences and lowercase API names ("allocate RW memory";
    # "closehandle"), the runtime profile renders import-category counts and CamelCase
    # ("capabilities: execution x5"; "GetProcAddress"). The only text the two share is
    # the boilerplate, which is why every query lands at 0.78-0.90 similarity regardless
    # of content. A variant querying with only the lowercased import segment was tried
    # and did not close the gap (F1 0.090).
    #
    # Enabling it anyway would be worse than a no-op: an LLM shown a technique list that
    # tracks corpus frequency rather than this sample would read it as corroboration.
    # Re-open this when the corpus is rebuilt in build_sample_profile_text's vocabulary
    # (or the query in capa's) — the eval script re-runs in ~2 min and answers it.
    use_attck_case_rag: bool = False
    attck_case_corpus_path: str = "data/attck_case_corpus_v1.json"
    attck_case_rag_top_k: Annotated[int, Field(ge=1)] = 5
    # NOTE: this floor is inert at present — every one of the 15 production-style queries
    # scored 0.78-0.90 against the corpus, so nothing is ever filtered. It is kept (rather
    # than raised to a value that would appear to work) because the scores do not separate
    # good matches from bad ones, exactly as measured for the semantic ATT&CK gate above;
    # a threshold picked to make the numbers look decisive would only hide that.
    attck_case_rag_min_score: Annotated[float, Field(ge=0, le=1)] = 0.35
    attck_case_rag_max_techniques: Annotated[int, Field(ge=1)] = 8

    # Deterministic ATT&CK technique-ID correction. When enabled, the judge node
    # runs a pre-cascade pass that re-grounds each LLM analyst claim's technique_id
    # against the in-memory TF-IDF ATT&CK index: invalid IDs are replaced with the
    # top evidence-derived suggestion, and valid-but-poorly-aligned IDs are swapped
    # only when a strictly better-aligned suggestion exists. This removes the small
    # model's loop-prone ID-recall sub-task from the critical path; the model just
    # describes behaviour and the index assigns the ID. Layer-0 deterministic
    # sources (yara/sigma) are skipped — their IDs are rule-authoritative. Fail-safe.
    use_attck_autocorrect: bool = True
    attck_autocorrect_min_alignment: Annotated[float, Field(ge=0, le=1)] = 0.08
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
    attck_index_backend: Literal["tfidf", "semantic", "hybrid"] = "hybrid"
    # Semantic threshold is intentionally 0.0: the eval showed absolute semantic
    # scores do not separate correct from wrong, so the absolute low-alignment
    # gate is disabled for that backend (it still fixes invalid IDs and applies
    # strictly-better relative swaps, which need no absolute threshold).
    attck_autocorrect_min_alignment_semantic: Annotated[float, Field(ge=0, le=1)] = 0.0

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
    category_inference_backend: Literal["keyword", "semantic", "hybrid"] = "keyword"


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
    transport: Literal["stdio", "http", "streamable-http", "sse"] = "stdio"
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
# Static-analysis provider settings
# ---------------------------------------------------------------------------


class StaticR2Config(MCPServerConfig):
    """radare2 MCP server, plus where the sample has to be for r2 to read it.

    ``mirror_dir`` is the host directory the worker copies the sample into when
    the provider declares ``needs_sample_mirror``; it defaults to the same
    ``.work`` subdirectory the Ghidra mirror already uses, because a co-located
    r2mcp reads the host path directly.
    """

    binary_path: str = "r2mcp"
    mirror_dir: str = "data/samples/.work"


class StaticCapaConfig(BaseModel):
    """flare-capa rule sources and its execution budget."""

    rules_dir: str = "data/capa-rules"
    signatures_dir: str = "data/capa-signatures"
    timeout_seconds: Annotated[int, Field(ge=1)] = 300
    backend: Literal["auto", "vivisect", "pefile", "binja"] = "auto"


class StaticYaraConfig(BaseModel):
    """Rule directory for the evidence-only YARA pass of the capa_yara provider.

    The deterministic YARA *layer* (``analysis/yara_layer.py``) keeps its own
    vendored corpus; this is the operator's own rule directory, scanned only by
    the capa_yara static provider.
    """

    rules_dir: str = "data/yara_rules"
    timeout_seconds: Annotated[int, Field(ge=1)] = 60


class StaticConfig(BaseModel):
    """Which static-analysis tool the static analyst attaches, and its settings.

    ``provider`` is the single switch; every block below is the configuration of
    one provider and is inert unless that provider is selected. ``ghidra`` is
    the default and is byte-for-byte the configuration that used to live at
    ``mcp.ghidra``.
    """

    provider: Literal["ghidra", "r2", "capa_yara", "generic_mcp", "none"] = "ghidra"
    ghidra: MCPServerConfig = Field(default_factory=MCPServerConfig)
    r2: StaticR2Config = Field(default_factory=StaticR2Config)
    capa: StaticCapaConfig = Field(default_factory=StaticCapaConfig)
    yara: StaticYaraConfig = Field(default_factory=StaticYaraConfig)
    generic: MCPServerConfig = Field(default_factory=MCPServerConfig)


# ---------------------------------------------------------------------------
# Sandbox provider settings
# ---------------------------------------------------------------------------


class SandboxCape2Config(BaseModel):
    """CAPEv2 REST endpoint plus the optional CAPE MCP server beside it."""

    base_url: str = "http://localhost:8000"
    api_token: SecretStr = SecretStr("")
    timeout_seconds: Annotated[int, Field(ge=1)] = 300
    poll_interval_seconds: Annotated[int, Field(ge=1)] = 10
    mcp: MCPServerConfig = Field(default_factory=MCPServerConfig)


class SandboxTriageConfig(BaseModel):
    """Hatching Triage cloud API.

    ``profile`` names a Triage VM profile; empty means the account default.
    ``timeout_seconds`` is generous because a Triage run queues behind other
    tenants' work.
    """

    base_url: str = "https://tria.ge/api/v0"
    api_token: SecretStr = SecretStr("")
    profile: str = ""
    timeout_seconds: Annotated[int, Field(ge=1)] = 900
    poll_interval_seconds: Annotated[int, Field(ge=1)] = 15
    fetch_pcap: bool = True


class SandboxUploadConfig(BaseModel):
    """Limits for operator-uploaded sandbox reports (no detonation of our own)."""

    max_report_bytes: Annotated[int, Field(ge=1)] = 67_108_864  # 64 MiB
    allowed_formats: list[str] = Field(default_factory=lambda: ["cape2", "cuckoo", "triage"])


class SandboxConfig(BaseModel):
    """Which sandbox produces the dynamic evidence, and how to reach it.

    provider:
        "mock"   (default) — fixture JSON from the samples directory, no network.
        "cape2"  — a live CAPEv2 instance over its REST API.
        "upload" — no detonation: an operator-uploaded report is attached to the job.
        "triage" — Hatching Triage cloud sandbox.

    The legacy flat names (``SANDBOX__BACKEND``, ``SANDBOX__CAPE2_BASE_URL``, …)
    keep working through the alias table on ``Settings``.
    """

    provider: Literal["mock", "cape2", "upload", "triage"] = "mock"
    cape2: SandboxCape2Config = Field(default_factory=SandboxCape2Config)
    triage: SandboxTriageConfig = Field(default_factory=SandboxTriageConfig)
    upload: SandboxUploadConfig = Field(default_factory=SandboxUploadConfig)

    @model_validator(mode="before")
    @classmethod
    def _alias_flat_keys(cls, data: Any) -> Any:
        """Accept ``SandboxConfig(backend=..., cape2_base_url=...)`` directly.

        The table on ``Settings`` covers values arriving through the environment;
        this covers direct construction, which tests and the container do.
        """
        if not isinstance(data, dict):
            return data
        return _alias_within(data, _SANDBOX_LOCAL_ALIASES)


# ---------------------------------------------------------------------------
# Legacy key aliases
# ---------------------------------------------------------------------------
#
# The provider layer moved four groups of settings. Every legacy name keeps
# working: the table below is applied to the assembled input before validation,
# and only where the new key is absent, so a `.env` written for the old shape
# and one written for the new shape both produce the same Settings. One warning
# per process names the file to edit; nothing is removed in this release.

SETTINGS_ALIASES: tuple[tuple[str, str], ...] = (
    ("mcp.ghidra", "static.ghidra"),
    ("mcp.cape", "sandbox.cape2.mcp"),
    ("sandbox.backend", "sandbox.provider"),
    ("sandbox.cape2_base_url", "sandbox.cape2.base_url"),
    ("sandbox.cape2_api_token", "sandbox.cape2.api_token"),
    ("sandbox.cape2_timeout_seconds", "sandbox.cape2.timeout_seconds"),
    ("sandbox.cape2_poll_interval_seconds", "sandbox.cape2.poll_interval_seconds"),
)

# The subset that a bare ``SandboxConfig(...)`` can carry (paths relative to it).
_SANDBOX_LOCAL_ALIASES: tuple[tuple[str, str], ...] = (
    ("backend", "provider"),
    ("cape2_base_url", "cape2.base_url"),
    ("cape2_api_token", "cape2.api_token"),
    ("cape2_timeout_seconds", "cape2.timeout_seconds"),
    ("cape2_poll_interval_seconds", "cape2.poll_interval_seconds"),
)

_ALIAS_WARNED = False


def _dig(data: dict[str, Any], path: str) -> tuple[dict[str, Any] | None, str]:
    """Return (owning mapping, last segment) for ``path``, or (None, ...) if absent."""
    cursor: Any = data
    parts = path.split(".")
    for part in parts[:-1]:
        if not isinstance(cursor, dict) or part not in cursor:
            return None, parts[-1]
        cursor = cursor[part]
    return (cursor if isinstance(cursor, dict) else None), parts[-1]


def _ensure(data: dict[str, Any], path: str) -> tuple[dict[str, Any], str]:
    """Return (owning mapping, last segment) for ``path``, creating dicts as needed."""
    cursor = data
    parts = path.split(".")
    for part in parts[:-1]:
        nxt = cursor.get(part)
        if not isinstance(nxt, dict):
            nxt = {}
            cursor[part] = nxt
        cursor = nxt
    return cursor, parts[-1]


def _alias_within(data: dict[str, Any], table: tuple[tuple[str, str], ...]) -> dict[str, Any]:
    """Move every legacy path in ``table`` onto its new path, new key wins.

    Sub-mappings are merged key by key (``mcp.ghidra`` -> ``static.ghidra``
    keeps a ``static.ghidra.url`` that was set explicitly), scalars are moved
    only when the target is absent. The legacy key is removed either way so the
    model never sees an unknown field.

    ``data`` is deep-copied before anything is popped from it: a shallow copy
    would still share the nested per-key dicts with the caller, so popping a
    legacy leaf out of one of them (e.g. ``sandbox.backend``) would mutate the
    caller's own mapping too — this is the plain-dict-in, plain-dict-out
    contract ``apply_settings_aliases`` documents.
    """
    out = copy.deepcopy(data)
    used: list[str] = []
    for old, new in table:
        src_owner, src_key = _dig(out, old)
        if src_owner is None or src_key not in src_owner:
            continue
        value = src_owner.pop(src_key)
        used.append(old)
        dst_owner, dst_key = _ensure(out, new)
        if isinstance(value, dict):
            target = dst_owner.get(dst_key)
            merged = dict(value)
            if isinstance(target, dict):
                merged.update(target)  # explicit new keys win
            dst_owner[dst_key] = merged
        elif dst_key not in dst_owner:
            dst_owner[dst_key] = value
    if used:
        _warn_once(used)
    return out


def _warn_once(paths: list[str]) -> None:
    global _ALIAS_WARNED
    if _ALIAS_WARNED:
        return
    _ALIAS_WARNED = True
    from maljan.core.logger import logger

    logger.warning(
        "Reading legacy setting name(s) %s; they now live under static.* / sandbox.* "
        "(MCP__GHIDRA__* -> STATIC__GHIDRA__*, MCP__CAPE__* -> SANDBOX__CAPE2__MCP__*, "
        "SANDBOX__BACKEND -> SANDBOX__PROVIDER, SANDBOX__CAPE2_* -> SANDBOX__CAPE2__*). "
        "The old names keep working; update .env when convenient.",
        ", ".join(sorted(paths)),
    )


def apply_settings_aliases(data: dict[str, Any]) -> dict[str, Any]:
    """Public, pure form of the alias pass — used by the validator and by tests."""
    return _alias_within(data, SETTINGS_ALIASES)


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
    """

    enabled: bool = True
    include_extended_stix: bool = True
    narrative_max_tokens: Annotated[int, Field(ge=1)] = 1500
    auto_generate_detection_rules: bool = True

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
    composer_section_max_tokens: Annotated[int, Field(ge=1)] = 900
    composer_per_section_timeout: Annotated[int, Field(ge=1)] = 120
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
    static: StaticConfig = Field(default_factory=StaticConfig)
    sandbox: SandboxConfig = Field(default_factory=SandboxConfig)
    analysis: AnalysisConfig = Field(default_factory=AnalysisConfig)
    preprocessing: PreprocessingConfig = Field(default_factory=PreprocessingConfig)
    # Transitional mirror of static.ghidra / sandbox.cape2.mcp. Every reader
    # moves to the provider in tasks 9-12; MCPConfig itself goes in Task 23.
    mcp: MCPConfig = Field(default_factory=MCPConfig)
    reporting: ReportingConfig = Field(default_factory=ReportingConfig)

    @classmethod
    def _alias_legacy_keys(cls, data: Any) -> Any:
        """Translate the pre-provider setting names, then mirror back for readers.

        Called from ``settings_customise_sources`` against each assembled
        source in turn (init kwargs, environment nested by the ``__``
        delimiter, dotenv, file secrets) — the probe test in
        ``tests/unit/core/test_settings_aliases.py`` proved that a
        ``model_validator(mode="before")`` here is compiled into the
        pydantic-core schema by reference at class-definition time, so a
        test that monkeypatches this classmethod afterwards never observes
        the call; the source pre-pass calls ``cls._alias_legacy_keys``
        through ordinary attribute lookup on every construction instead,
        which a monkeypatch does reach. See the plan's Task 2 Step 5.
        """
        if not isinstance(data, dict):
            return data
        out = apply_settings_aliases(data)
        # Keep the deprecated mirror in step with the new home so a module that
        # has not been migrated yet reads the operator's real value.
        static_ghidra = (
            (out.get("static") or {}).get("ghidra") if isinstance(out.get("static"), dict) else None
        )
        if isinstance(static_ghidra, dict):
            mcp = out.setdefault("mcp", {})
            if isinstance(mcp, dict) and not isinstance(mcp.get("ghidra"), dict):
                mcp["ghidra"] = dict(static_ghidra)
        cape_mcp = (
            ((out.get("sandbox") or {}).get("cape2") or {}).get("mcp")
            if isinstance(out.get("sandbox"), dict)
            else None
        )
        if isinstance(cape_mcp, dict):
            mcp = out.setdefault("mcp", {})
            if isinstance(mcp, dict) and not isinstance(mcp.get("cape"), dict):
                mcp["cape"] = dict(cape_mcp)
        return out

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        """Alias legacy names inside each source, before they are merged.

        The merge is a deep dict update, so aliasing per source is equivalent to
        aliasing the merged mapping as long as a source never contributes half
        of an aliased sub-mapping — and a source is one file or one environment,
        so it cannot.
        """

        class _Aliased(PydanticBaseSettingsSource):
            def __init__(self, inner: PydanticBaseSettingsSource) -> None:
                super().__init__(settings_cls)
                self._inner = inner

            def get_field_value(self, field: FieldInfo, field_name: str) -> tuple[Any, str, bool]:
                return self._inner.get_field_value(field, field_name)

            def __call__(self) -> dict[str, Any]:
                data = self._inner()
                # An empty source has nothing to alias; skip the call so the
                # (harmless) no-op does not show up as a call on a source that
                # never carried a legacy name — e.g. init kwargs when the
                # settings are built from the environment alone.
                if not data:
                    return data
                return cast("dict[str, Any]", cls._alias_legacy_keys(data))

        return (
            _Aliased(init_settings),
            _Aliased(env_settings),
            _Aliased(dotenv_settings),
            _Aliased(file_secret_settings),
        )

    # Token overflow protection (128K is conservative for Gemini 1M+ context)
    max_token_limit: Annotated[int, Field(ge=1)] = 128_000

    # ReAct agent execution limits
    react_agent_timeout: Annotated[int, Field(ge=1)] = 180  # seconds before agent loop times out
    react_agent_max_steps: Annotated[int, Field(ge=1)] = 10  # max LangGraph recursion steps
    # PERF-STATIC-ANALYST-LATENCY-01 (audit 2026-05-19) — tool-call budget.
    # When an analyst's ReAct loop exceeds this many cumulative tool calls
    # we log a WARNING. Not a hard limit (LangGraph's recursion_limit is
    # the structural cap); this is the early signal that an analyst is
    # spinning unproductively on tool calls. Set via env
    # ``REACT_AGENT_TOOL_CALL_BUDGET``.
    react_agent_tool_call_budget: Annotated[int, Field(ge=1)] = 20

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
        # Transitional: the readers that still say ``mcp.ghidra`` (static
        # analyst, pipeline nodes, worker mirror) must see the provider's
        # configuration until Task 12 moves them.
        if self.mcp.ghidra == MCPServerConfig():
            self.mcp.ghidra = self.static.ghidra.model_copy(deep=True)
        if self.mcp.cape == MCPServerConfig():
            self.mcp.cape = self.sandbox.cape2.mcp.model_copy(deep=True)


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


def install_settings(instance: Settings) -> None:
    """Make ``instance`` the process-wide singleton every ``get_settings()`` caller sees.

    The arq worker (``max_jobs = 1``) calls this once per job with the Settings
    it built from the environment plus the UI-managed overrides. Agents,
    pipeline nodes and extractors read ``get_settings()`` rather than an
    injected config, so without this a UI override would reach the container
    and nothing below it.
    """
    global _settings_instance
    _settings_instance = instance


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
