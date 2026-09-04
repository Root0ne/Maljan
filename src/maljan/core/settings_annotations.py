"""What each setting means, in words a person can act on.

Titles and descriptions were seeded from the comments in ``.env.example`` by
``scripts/seed_settings_annotations.py`` and then edited. Groups come from
the key prefix (``group_for``); an entry may override its group. ``applies``
defaults to ``next_job`` for every core setting. ``probe`` names the
connection test in apps/api/app/services/settings_probes.py that exercises
the field.
"""

from __future__ import annotations

from typing import Literal, NotRequired, TypedDict


class Annotation(TypedDict):
    title: str
    description: str
    applies: NotRequired[Literal["next_job", "live", "restart"]]
    probe: NotRequired[str]
    group: NotRequired[str]
    applies_when: NotRequired[dict[str, list[str]]]  # key -> values that reveal this entry
    order: NotRequired[int]  # within the group; default 0
    choices_from: NotRequired[
        Literal["static_providers", "sandbox_providers", "mcp_servers", "agent_roles"]
    ]
    editor: NotRequired[Literal["server_map", "rest_sandbox"]]


GROUP_ORDER: list[tuple[str, str]] = [
    ("llm", "LLM & model"),
    ("providers", "Providers"),
    ("frontier", "Frontier arms"),
    ("static", "Static analysis provider"),
    ("sandbox", "Sandbox provider"),
    ("mcp", "Tool servers (MCP)"),
    ("memory", "Memory / LTM (Qdrant)"),
    ("analysis", "Analysis layers"),
    ("negotiation", "Negotiation"),
    ("chunking", "Chunking"),
    ("reporting", "Reporting"),
    ("agents", "Agent timeouts and budgets"),
    ("tracing", "Tracing"),
    ("enrichment", "Enrichment / threat intelligence"),
    ("api", "API"),
    ("system", "System (read-only)"),
]

_PREFIX_GROUPS: list[tuple[str, str]] = [
    ("llm.frontier", "frontier"),
    ("llm.openai", "providers"),
    ("llm.anthropic", "providers"),
    ("llm.gemini", "providers"),
    ("llm.ollama", "providers"),
    ("llm", "llm"),
    ("negotiation", "negotiation"),
    ("chunking", "chunking"),
    ("memory", "memory"),
    ("sandbox", "sandbox"),
    ("analysis", "analysis"),
    ("preprocessing", "analysis"),
    ("static", "static"),
    ("mcp", "mcp"),
    ("reporting", "reporting"),
    ("react_agent", "agents"),
    ("max_token_limit", "agents"),
    ("langchain", "tracing"),
    ("openai_api_key", "providers"),
    ("anthropic_api_key", "providers"),
    ("google_api_key", "providers"),
]


def group_for(path: str) -> str:
    for prefix, group in _PREFIX_GROUPS:
        if path == prefix or path.startswith(prefix + ".") or path.startswith(prefix + "_"):
            return group
    return "agents"


ANNOTATIONS: dict[str, Annotation] = {
    "analysis.sigma_rules_dir": {
        "title": "Sigma rules directory",
        "description": (
            "Directory of Sigma rule YAML files, loaded recursively for the "
            "deterministic Sigma detection layer. Pointing this at a non-existent path "
            "disables the layer gracefully instead of failing."
        ),
    },
    "anthropic_api_key": {
        "title": "Anthropic API key (shortcut)",
        "description": (
            "Flat-key convenience shortcut for Anthropic credentials, auto-promoted "
            "into llm.anthropic.api_key on startup if that nested field is not already "
            "set."
        ),
    },
    "chunking.max_tokens_per_chunk": {
        "title": "Max tokens per chunk",
        "description": (
            "Maximum tokens per chunk when splitting oversized analyst input for the "
            "LLM. Raise it on a larger-context model to produce fewer, richer chunks; "
            "lowering it produces more, smaller chunks."
        ),
    },
    "chunking.overlap_tokens": {
        "title": "Chunk overlap (tokens)",
        "description": (
            "Token overlap between consecutive chunks, preserving context across a "
            "chunk boundary so evidence spanning two chunks is not lost."
        ),
    },
    "chunking.skip_if_fits": {
        "title": "Skip chunking if it fits",
        "description": (
            "When true, input smaller than max_tokens_per_chunk is sent as a single "
            "chunk instead of always being split. Set false to force chunking even on "
            "small input — useful for testing the chunked code path."
        ),
    },
    "google_api_key": {
        "title": "Google API key (shortcut)",
        "description": (
            "Flat-key convenience shortcut for Google Gemini credentials, auto-promoted "
            "into llm.gemini.api_key on startup if that nested field is not already "
            "set."
        ),
    },
    "langchain_api_key": {
        "title": "LangSmith API key",
        "description": (
            "LangSmith API key used to authenticate tracing uploads when "
            "langchain_tracing_v2 is enabled."
        ),
    },
    "langchain_project": {
        "title": "LangSmith project",
        "description": (
            "LangSmith project name that traces are grouped under when "
            "langchain_tracing_v2 is enabled."
        ),
    },
    "langchain_tracing_v2": {
        "title": "LangChain tracing enabled",
        "description": (
            "Enables LangSmith/LangChain tracing. When true, every LLM call, "
            "negotiation round, ISR construction and TTP validation is traced to the "
            "configured LangChain project."
        ),
    },
    "llm.agents": {
        "title": "Per-agent LLM overrides",
        "description": (
            "Per-agent LLM overrides for the heterogeneous model ensemble "
            "(LLM__AGENTS__<AGENT>__PROVIDER/MODEL/TEMPERATURE), letting different "
            "analysts (static, dynamic, network) run on different providers/models "
            "instead of sharing one global expert LLM. Empty by default, meaning every "
            "agent uses the global expert LLM."
        ),
    },
    "llm.anthropic.api_key": {
        "title": "Anthropic API key",
        "description": (
            "Bearer credential for the Anthropic API. Required whenever llm.provider is anthropic."
        ),
    },
    "llm.anthropic.expert_model": {
        "title": "Anthropic expert model",
        "description": (
            "Model used for analyst LLM calls when llm.provider is anthropic, e.g. "
            "claude-sonnet-4-20250514."
        ),
    },
    "llm.anthropic.judge_model": {
        "title": "Anthropic judge model",
        "description": ("Model used for the judge verdict call when llm.provider is anthropic."),
    },
    "llm.expert_max_tokens": {
        "title": "Analyst max output tokens",
        "description": (
            "Per-call output-token budget for the analyst LLM. 0 means unbounded "
            "(provider/server default); a nonzero value both caps a runaway decode and "
            "sizes the split budget when view_decomposition_views is set."
        ),
    },
    "llm.frontier.active_params_b": {
        "title": "Frontier active parameters (B)",
        "description": (
            "Active (non-MoE-sparse) parameter count (billions) of the model behind "
            "this frontier arm, recorded for the same parameter-size analysis as "
            "total_params_b."
        ),
    },
    "llm.frontier.api_key": {
        "title": "Frontier API key",
        "description": (
            "Bearer credential for the single frontier comparison endpoint. Evaluation "
            "only; never read by the production pipeline."
        ),
    },
    "llm.frontier.arms": {
        "title": "Frontier arms",
        "description": (
            "Named additional frontier comparison endpoints "
            "(LLM__FRONTIER__ARMS__<NAME>__...), each with its own model, pricing and "
            "spend ceiling, used to test a parameter-size series rather than a single "
            "comparison point. Evaluation only."
        ),
    },
    "llm.frontier.base_url": {
        "title": "Frontier base URL",
        "description": (
            "Base URL of the single frontier comparison endpoint. Evaluation only — "
            "nothing in the analysis pipeline reads this; only the eval harnesses in "
            "maljan.core.frontier use it to run the paper's model-diversity comparison."
        ),
    },
    "llm.frontier.count_reasoning_tokens": {
        "title": "Frontier count reasoning tokens",
        "description": (
            "When true, this frontier arm's output-token cap counts reasoning tokens as "
            "well as the final answer, keeping the compute comparison against other "
            "arms fair. Some providers do not actually suppress reasoning generation "
            "when this is off, so leaving it on is recommended."
        ),
    },
    "llm.frontier.enabled": {
        "title": "Frontier arms enabled",
        "description": (
            "Turns on the frontier comparison arms for evaluation harnesses. Has no "
            "effect on the production analysis pipeline, which never reads this config."
        ),
    },
    "llm.frontier.free_tier": {
        "title": "Frontier free tier",
        "description": (
            "Explicit acknowledgement that this frontier arm genuinely bills nothing "
            "(e.g. an OpenRouter :free model), so zero pricing does not disable it. "
            "Token counts are still recorded regardless."
        ),
    },
    "llm.frontier.input_usd_per_mtok": {
        "title": "Frontier input price (USD/Mtok)",
        "description": (
            "Price per million input tokens for this frontier arm, used to enforce "
            "max_spend_usd. Leaving this at zero disables the arm rather than making it "
            "free, unless free_tier is explicitly set."
        ),
    },
    "llm.frontier.max_retries": {
        "title": "Frontier max retries",
        "description": (
            "Maximum retry attempts with backoff when this frontier arm's endpoint "
            "returns a throttling or transient error."
        ),
    },
    "llm.frontier.max_spend_usd": {
        "title": "Frontier max spend (USD)",
        "description": (
            "Hard USD ceiling for this frontier arm, checked before every call. "
            "Deliberately small by default — raising it should be a deliberate "
            "decision, not an accidental default."
        ),
    },
    "llm.frontier.min_interval_s": {
        "title": "Frontier min call interval (s)",
        "description": (
            "Minimum seconds between consecutive calls to this frontier arm's endpoint, "
            "used to stay under provider rate limits observed during evaluation."
        ),
    },
    "llm.frontier.model": {
        "title": "Frontier model",
        "description": (
            "Model identifier for the single frontier comparison arm (the one the B8 "
            "evaluation originally ran). Additional arms are configured under "
            "llm.frontier.arms."
        ),
    },
    "llm.frontier.output_usd_per_mtok": {
        "title": "Frontier output price (USD/Mtok)",
        "description": (
            "Price per million output tokens for this frontier arm, used to enforce "
            "max_spend_usd. Leaving this at zero disables the arm rather than making it "
            "free, unless free_tier is explicitly set."
        ),
    },
    "llm.frontier.quantisation": {
        "title": "Frontier quantisation",
        "description": (
            "Free-text quantisation label for the model behind this frontier arm (e.g. "
            "Q4_K_M), recorded as provenance for the parameter-size analysis."
        ),
    },
    "llm.frontier.total_params_b": {
        "title": "Frontier total parameters (B)",
        "description": (
            "Total parameter count (billions) of the model behind this frontier arm, "
            "recorded for the parameter-size-vs-F1 correlation analysis in the paper. "
            "Purely descriptive metadata — does not affect behaviour."
        ),
    },
    "llm.gemini.api_key": {
        "title": "Gemini API key",
        "description": (
            "Bearer credential (Google AI API key) for Gemini. Required whenever "
            "llm.provider is gemini."
        ),
    },
    "llm.gemini.expert_model": {
        "title": "Gemini expert model",
        "description": ("Gemini model used for analyst LLM calls, e.g. gemini-2.5-pro."),
    },
    "llm.gemini.judge_model": {
        "title": "Gemini judge model",
        "description": ("Gemini model used for the judge verdict call."),
    },
    "llm.judge_max_tokens": {
        "title": "Judge max output tokens",
        "description": (
            "Hard output-token cap for the judge's final verdict generation. Bounds a "
            "rambling or degenerate decode on a slow local model to a predictable "
            "wall-clock cost instead of relying only on the timeout; set to 0 for "
            "unbounded."
        ),
    },
    "llm.ollama.base_url": {
        "title": "Ollama base URL",
        "description": (
            "Base URL of the local Ollama server used when llm.provider is ollama, e.g. "
            "http://localhost:11434."
        ),
    },
    "llm.ollama.expert_model": {
        "title": "Ollama expert model",
        "description": ("Ollama model tag used for analyst LLM calls, e.g. qwen3.5:9b."),
    },
    "llm.ollama.judge_model": {
        "title": "Ollama judge model",
        "description": ("Ollama model tag used for the judge verdict call."),
    },
    "llm.ollama.keep_alive": {
        "title": "Ollama keep-alive",
        "description": (
            "How long Ollama keeps the model loaded in memory after the last request "
            "(an Ollama duration string, e.g. 30m). Longer values avoid reload latency "
            "between calls at the cost of holding GPU/RAM."
        ),
    },
    "llm.ollama.num_ctx": {
        "title": "Ollama context size",
        "description": (
            "Context window size (tokens) requested from the Ollama model. Must be "
            "large enough for the chunked prompt plus generation budget, or the server "
            "silently truncates the oldest context."
        ),
    },
    "llm.openai.api_key": {
        "title": "OpenAI API key",
        "description": (
            "Bearer credential for api.openai.com or any OpenAI-compatible endpoint set "
            "via base_url. Required whenever llm.provider is openai and the endpoint "
            "enforces auth."
        ),
        "probe": "llm",
    },
    "llm.openai.base_url": {
        "title": "OpenAI base URL",
        "description": (
            "Overrides the OpenAI API endpoint to target an OpenAI-compatible server "
            "instead of api.openai.com — a local llama.cpp/ik_llama.cpp server, Kimi "
            "(Moonshot), DeepSeek, or Azure OpenAI. Leave empty to use OpenAI's own "
            "endpoint."
        ),
        "probe": "llm",
    },
    "llm.openai.disable_thinking": {
        "title": "OpenAI disable thinking",
        "description": (
            "When true and base_url points at a local OpenAI-compatible server, "
            "forwards chat_template_kwargs.enable_thinking=false to suppress a "
            "reasoning model's (e.g. Qwen3) hidden chain-of-thought. Needed on "
            "constrained local hosts, where thinking otherwise consumes the whole "
            "output budget; has no effect on vanilla OpenAI."
        ),
    },
    "llm.openai.expert_model": {
        "title": "OpenAI expert model",
        "description": (
            "Model name used for the analyst (expert) LLM calls when llm.provider is "
            "openai, e.g. gpt-4o-mini or a local model name served behind base_url."
        ),
        "probe": "llm",
    },
    "llm.openai.judge_model": {
        "title": "OpenAI judge model",
        "description": (
            "Model name used for the final verdict (judge) LLM call when llm.provider "
            "is openai. Can differ from expert_model to reserve a stronger model for "
            "the verdict."
        ),
        "probe": "llm",
    },
    "llm.openai.repetition_penalty": {
        "title": "OpenAI repetition penalty",
        "description": (
            "Repetition penalty forwarded to local OpenAI-compatible servers "
            "(llama.cpp/ik_llama.cpp) via extra_body when base_url is set; ignored "
            "against api.openai.com. 1.0 is a no-op — values around 1.15 stop a small "
            "local reasoning model from looping on ATT&CK ID recall."
        ),
    },
    "llm.parallel_analysts": {
        "title": "Run analysts in parallel",
        "description": (
            "When true, the static/dynamic/network analysts run concurrently — correct "
            "only for a hosted, multi-slot LLM API. When false (the default), they run "
            "one at a time, which is required for a single-slot local llama.cpp/Ollama "
            "server where parallel requests would clobber each other's KV/recurrent "
            "state and cause timeouts."
        ),
    },
    "llm.provider": {
        "title": "Provider",
        "description": (
            "Selects which LLM backend serves both the expert and judge roles: openai, "
            "anthropic, ollama, or gemini. Switching providers routes every LLM call in "
            "the pipeline to that provider's endpoint and picks up its model settings "
            "below."
        ),
        "probe": "llm",
    },
    "llm.view_decomposition_mode": {
        "title": "View-decomposition mode",
        "description": (
            "Strategy used when view_decomposition_views is 2 or more: facet runs "
            "independent horizontal facets over the same evidence; tier runs a vertical "
            "facts -> behaviour -> ATT&CK-semantics pipeline where each tier consumes "
            "the previous tier's findings."
        ),
    },
    "llm.view_decomposition_views": {
        "title": "View-decomposition views",
        "description": (
            "Number of focused sub-prompts to split the analyst's text evidence into, "
            "each run concurrently and merged (0 disables the pilot and keeps today's "
            "single monolithic analyst call). Text path only; the Ghidra/CAPE "
            "tool-using ReAct loop is unaffected."
        ),
    },
    "max_token_limit": {
        "title": "Max token limit",
        "description": (
            "Global token-count ceiling used to truncate prompts before they overflow "
            "the LLM's context window. Conservative by default for smaller-context "
            "models; raise it when running on a large-context model such as Gemini."
        ),
    },
    "memory.backend": {
        "title": "Memory backend",
        "description": (
            "Long-term-memory store used for past-case retrieval. qdrant persists cases "
            "in a real Qdrant instance; memory keeps them in an in-process, ephemeral "
            "store with no external dependency."
        ),
    },
    "memory.qdrant_collection": {
        "title": "Qdrant case collection",
        "description": (
            "Qdrant collection name storing semantic case embeddings for few-shot "
            "retrieval into the judge prompt. Bump this when migrating to a new "
            "embedding scheme (e.g. a dimension change) rather than reusing an "
            "incompatible old collection."
        ),
        "probe": "qdrant",
    },
    "memory.qdrant_function_hash_collection": {
        "title": "Qdrant function-hash collection",
        "description": (
            "Separate Qdrant collection storing per-function normalized-opcode hashes "
            "for the exact-match function-hash attribution tier, independent of the "
            "fuzzy semantic case collection above."
        ),
    },
    "memory.qdrant_url": {
        "title": "Qdrant URL",
        "description": (
            "URL of the Qdrant server backing long-term memory when memory.backend is qdrant."
        ),
        "probe": "qdrant",
    },
    "memory.qdrant_api_key": {
        "title": "Qdrant API key",
        "description": (
            "API key sent with every Qdrant request when the server enforces one (compose "
            "does); empty means no authentication, which is fine for a loopback-only server."
        ),
    },
    "memory.top_k": {
        "title": "Memory top-K",
        "description": (
            "Maximum number of similar past cases injected into the judge's prompt. "
            "Higher values give more context but lengthen the prompt."
        ),
    },
    "negotiation.consensus_threshold": {
        "title": "Consensus threshold",
        "description": (
            "Confidence threshold (0.0-1.0) at which the mediator accepts early "
            "consensus and ends the negotiation loop before max_iterations is reached."
        ),
    },
    "negotiation.max_iterations": {
        "title": "Max negotiation rounds",
        "description": (
            "Hard ceiling on negotiation rounds between agents. Not the expected round "
            "count — the primary exit is adaptive termination on the rolling standard "
            "deviation of confidence history; this ceiling only stops a runaway loop "
            "when that convergence fails."
        ),
    },
    "openai_api_key": {
        "title": "OpenAI API key (shortcut)",
        "description": (
            "Flat-key convenience shortcut for OpenAI credentials. Auto-promoted into "
            "llm.openai.api_key on startup if that nested field is not already set, so "
            "existing setups using the flat env var keep working."
        ),
    },
    "preprocessing.api_attck_map_path": {
        "title": "API-to-ATT&CK map path",
        "description": (
            "Path to the API-to-ATT&CK mapping catalog JSON used when use_api_attck_map is enabled."
        ),
    },
    "preprocessing.api_behaviour_map_path": {
        "title": "API behaviour map path",
        "description": (
            "Path to the API-behaviour-map catalog JSON used when use_api_behaviour_map "
            "is enabled. Build it with scripts/build_api_capability_db.py."
        ),
    },
    "preprocessing.attck_autocorrect_min_alignment": {
        "title": "ATT&CK autocorrect min alignment",
        "description": (
            "Minimum alignment score required before the ATT&CK autocorrect pass "
            "accepts a suggested technique-ID replacement (TF-IDF backend gate)."
        ),
    },
    "preprocessing.attck_autocorrect_min_alignment_semantic": {
        "title": "ATT&CK autocorrect min alignment (semantic)",
        "description": (
            "Minimum alignment score for the semantic ATT&CK index backend's "
            "low-alignment gate. Intentionally 0.0 (disabled) because evaluation showed "
            "absolute semantic scores do not separate correct from wrong matches; "
            "invalid-ID fixes and relative swaps still apply without it."
        ),
    },
    "preprocessing.attck_autocorrect_swap_valid": {
        "title": "ATT&CK autocorrect swap valid IDs",
        "description": (
            "When true, autocorrect also swaps a VALID-but-poorly-aligned technique ID, "
            "not just an invalid one. Off by default — an evaluation found this path "
            "damages about 38% of already-correct IDs while recovering only about 21% "
            "of wrong ones."
        ),
    },
    "preprocessing.attck_case_corpus_path": {
        "title": "ATT&CK case corpus path",
        "description": (
            "Path to the ATT&CK case-prior corpus JSON used when use_attck_case_rag is "
            "enabled. Build it with scripts/build_attck_case_kb.py against a populated "
            "Qdrant long-term-memory store."
        ),
    },
    "preprocessing.attck_case_rag_max_techniques": {
        "title": "ATT&CK case-RAG max techniques",
        "description": (
            "Maximum number of technique IDs surfaced in the ATT&CK case-prior candidate list."
        ),
    },
    "preprocessing.attck_case_rag_min_score": {
        "title": "ATT&CK case-RAG min score",
        "description": (
            "Minimum similarity score for a case-prior RAG match to be kept. Currently "
            "inert in practice — measured production queries all score 0.78-0.90 "
            "regardless of content, so nothing is filtered — but kept rather than "
            "raised to a value that would appear to work."
        ),
    },
    "preprocessing.attck_case_rag_top_k": {
        "title": "ATT&CK case-RAG top-K",
        "description": ("Number of prior cases retrieved per query for ATT&CK case-prior RAG."),
    },
    "preprocessing.attck_index_backend": {
        "title": "ATT&CK index backend",
        "description": (
            "Backend for the ATT&CK technique index used for grounding and autocorrect: "
            "tfidf (keyword bag-of-words, clean alignment gate), semantic (dense "
            "embeddings, better ranking but a poor gate), or hybrid (semantic ranking "
            "with a TF-IDF gate — the default and best-performing option in "
            "evaluation)."
        ),
    },
    "preprocessing.category_inference_backend": {
        "title": "Category-inference backend",
        "description": (
            "Backend for malware-category inference, which drives an advisory STIX "
            "schema-pruning hint. keyword is the deterministic substring classifier "
            "that abstains rather than guesses (the safe default); hybrid falls back to "
            "a semantic classifier to recover some of keyword's abstentions at a small "
            "accuracy gain."
        ),
    },
    "preprocessing.family_fingerprint_catalog_path": {
        "title": "Family-fingerprint catalog path",
        "description": (
            "Path to the vendored family-fingerprint catalog used by family-feature "
            "RAG. Different catalogs trade off size against disjointness from the eval "
            "set; build one with scripts/build_family_feature_kb.py."
        ),
    },
    "preprocessing.family_rag_min_score": {
        "title": "Family-RAG min score",
        "description": (
            "Minimum similarity score for a family-feature RAG match to be surfaced as "
            "candidate evidence."
        ),
    },
    "preprocessing.family_rag_top_k": {
        "title": "Family-RAG top-K",
        "description": (
            "Number of nearest families surfaced as candidate evidence by family-feature RAG."
        ),
    },
    "preprocessing.function_hash_max_matches": {
        "title": "Function-hash max matches",
        "description": (
            "Maximum number of matching past samples surfaced by function-hash attribution."
        ),
    },
    "preprocessing.function_hash_min_instructions": {
        "title": "Function-hash min instructions",
        "description": (
            "Minimum instruction count for a function to be included in function-hash "
            "attribution. Smaller functions (thunks/stubs) are ignored because they "
            "collide across unrelated binaries and would produce false family links."
        ),
    },
    "preprocessing.language_signatures_path": {
        "title": "Language signatures catalog path",
        "description": (
            "Path to the compiler/language fingerprint catalog JSON used when "
            "use_language_signatures is enabled."
        ),
    },
    "preprocessing.max_tool_output_chars": {
        "title": "Max tool output characters",
        "description": (
            "Maximum characters kept from an MCP tool's output (e.g. a Ghidra "
            "decompile). Longer output is summarized (if the function summarizer is "
            "enabled) or truncated; raising it risks pushing the accumulated ReAct "
            "context past the model's window."
        ),
    },
    "preprocessing.packer_signatures_path": {
        "title": "Packer signatures catalog path",
        "description": (
            "Path to the packer/protector signature catalog JSON used when "
            "use_packer_signatures is enabled."
        ),
    },
    "preprocessing.sink_reachability_max_funcs": {
        "title": "Sink-reachability max functions",
        "description": (
            "Maximum number of priority functions surfaced by the sink-reachability hint."
        ),
    },
    "preprocessing.static_function_rag_min_chunks": {
        "title": "Static function-RAG min chunks",
        "description": (
            "Minimum static chunk count before function-level retrieval engages; "
            "binaries with fewer chunks always take the full linear-chunking path."
        ),
    },
    "preprocessing.static_function_rag_top_k": {
        "title": "Static function-RAG top-K",
        "description": (
            "Number of top function chunks retrieved per behaviour query for large "
            "binaries when function-level retrieval is engaged (0 disables retrieval "
            "and feeds every chunk linearly). Focuses the static analyst on the "
            "malicious core instead of the whole binary."
        ),
    },
    "preprocessing.summarizer_max_words": {
        "title": "Summarizer max words",
        "description": (
            "Maximum words allowed in each chunk's generated summary when the function "
            "summarizer is enabled."
        ),
    },
    "preprocessing.summarizer_model": {
        "title": "Summarizer model",
        "description": ("Model identifier for the summarizer LLM, e.g. a small Ollama model tag."),
    },
    "preprocessing.summarizer_provider": {
        "title": "Summarizer provider",
        "description": (
            "LLM provider used for the function summarizer when use_function_summarizer "
            "is enabled. Prefer a small, cheap local model since this runs as a "
            "pre-pass, not the main analysis."
        ),
    },
    "preprocessing.tool_artifacts_path": {
        "title": "Tool-artifacts catalog path",
        "description": (
            "Path to the offensive-tool/commodity-RAT marker catalog JSON used when "
            "use_tool_artifacts is enabled."
        ),
    },
    "preprocessing.use_api_attck_map": {
        "title": "Use API-to-ATT&CK map",
        "description": (
            "Enables deterministic API-to-ATT&CK-technique mapping computed from the "
            "sample's resolved imports, the main source of technique coverage on a "
            "sandbox-unreachable run. On by default; each claim is capped below the "
            "YARA floor so it corroborates other layers without solo-driving a verdict."
        ),
    },
    "preprocessing.use_api_behaviour_map": {
        "title": "Use API behaviour map",
        "description": (
            "Enables the data-driven Windows-API behaviour catalog (~680 API names "
            "across 13 behaviour categories) in place of the small hardcoded "
            "suspicious-imports table. On by default and fail-safe: a missing or "
            "malformed catalog falls back to the built-in table."
        ),
    },
    "preprocessing.use_attck_autocorrect": {
        "title": "Use ATT&CK autocorrect",
        "description": (
            "Enables a deterministic pre-cascade pass that re-grounds each LLM analyst "
            "claim's technique ID against the in-memory ATT&CK index, replacing invalid "
            "IDs with the top evidence-derived suggestion. Rule-based (yara/sigma) "
            "claims are skipped since their IDs are already authoritative. On by "
            "default."
        ),
    },
    "preprocessing.use_attck_case_rag": {
        "title": "Use ATT&CK case-prior RAG",
        "description": (
            "Enables cross-sample ATT&CK case-prior retrieval: the sample's profile is "
            "matched against behaviourally-similar prior cases from long-term memory, "
            "and their technique IDs are aggregated into a ranked candidate list for "
            "the LLM. Stays off by default — measured evaluation found the production "
            "query text does not actually reach the corpus effectively (retrieval F1 "
            "0.111 vs a 0.123 frequency-prior baseline), so enabling it would look like "
            "corroboration without being one."
        ),
    },
    "preprocessing.use_claim_consistency_gate": {
        "title": "Use claim-consistency gate",
        "description": (
            "When true, the analyst's claim parser drops any claim whose cited artifact "
            "or technique does not actually appear in the source evidence text, "
            "catching hallucinated claims at parse time. Off by default; any gate error "
            "leaves the ISR untouched."
        ),
    },
    "preprocessing.use_family_feature_rag": {
        "title": "Use family-feature RAG",
        "description": (
            "Enables static-feature family-fingerprint retrieval: a deterministic "
            "profile of the sample is matched against an offline-built family "
            "fingerprint catalog, and the nearest families are injected as candidate "
            "evidence for the LLM to decide on. Off by default — an end-to-end A/B "
            "found no measurable gain (f1 +0.003, n=19), and it degrades to a no-op if "
            "the catalog file is missing."
        ),
    },
    "preprocessing.use_function_hash_attribution": {
        "title": "Use function-hash attribution",
        "description": (
            "Enables a deterministic pre-pass that computes per-function "
            "normalized-opcode hashes and matches them against past samples in the "
            "function-hash store, injecting a high-precision family-attribution hint. "
            "The judge also writes the current sample's hashes back to grow the corpus."
        ),
    },
    "preprocessing.use_function_summarizer": {
        "title": "Use function summarizer",
        "description": (
            "Enables a small/local LLM pre-summarization pass over large function lists "
            "or decompiled blocks before they reach the expensive expert LLM. Off by "
            "default — it adds latency and only pays off on huge inputs."
        ),
    },
    "preprocessing.use_language_signatures": {
        "title": "Use language signatures",
        "description": (
            "Enables compiler/language fingerprint detection, feeding platform "
            "inference for otherwise-unknown binaries and the static analyst's prompt "
            "with what the sample was written in. On by default."
        ),
    },
    "preprocessing.use_packer_signatures": {
        "title": "Use packer signatures",
        "description": (
            "Enables the ranked packer/protector signature catalog (section names, "
            "entry-point placement, strings) in place of four hardcoded section-name "
            "checks. On by default."
        ),
    },
    "preprocessing.use_sink_reachability": {
        "title": "Use sink-reachability triage",
        "description": (
            "Enables a deterministic pre-pass over the Ghidra call graph that finds "
            "functions reaching security-sensitive sink APIs and injects a 'priority "
            "functions' hint, focusing the static analyst's decompilation on the likely "
            "malicious core. Fails safe to no hint on error or a stripped binary."
        ),
    },
    "preprocessing.use_tool_artifacts": {
        "title": "Use tool-artifact markers",
        "description": (
            "Enables detection of offensive-tool / commodity-RAT byte markers (Cobalt "
            "Strike, Mimikatz, Sliver, AsyncRAT, and similar), the only source of a "
            "malware family name on a static-only run with no sandbox. Each entry "
            "requires two distinct markers to fire, so a single coincidental string "
            "cannot trigger it."
        ),
    },
    "react_agent_max_steps": {
        "title": "ReAct agent default max steps",
        "description": (
            "Default maximum LangGraph recursion steps for a ReAct agent loop, tuned "
            "for the network/dynamic analysts' small tool-call count. Per-agent "
            "overrides live in react_agent_max_steps_overrides."
        ),
    },
    "react_agent_max_steps_overrides": {
        "title": "ReAct agent max-steps overrides",
        "description": (
            "Per-agent LangGraph recursion-step overrides, keyed by agent name, "
            "overriding react_agent_max_steps for agents whose tool-call depth differs "
            "from the default — the static analyst needs many more steps for its Ghidra "
            "pass, while network is capped low to keep an optional PCAP tool loop from "
            "starving synthesis."
        ),
    },
    "react_agent_timeout": {
        "title": "ReAct agent default timeout (s)",
        "description": (
            "Default wall-clock timeout in seconds for a ReAct agent loop (analyst or "
            "judge) before it is forced to stop, tuned for the network/dynamic "
            "analysts. Per-agent overrides live in react_agent_timeout_overrides."
        ),
    },
    "react_agent_timeout_overrides": {
        "title": "ReAct agent timeout overrides",
        "description": (
            "Per-agent timeout overrides (in seconds), keyed by agent name (e.g. "
            "static, dynamic, network, judge), overriding react_agent_timeout for "
            "agents whose workload needs a different budget — the static analyst's "
            "Ghidra ReAct loop in particular needs far more time than the default."
        ),
    },
    "react_agent_tool_call_budget": {
        "title": "ReAct agent tool-call budget",
        "description": (
            "Soft ceiling on cumulative tool calls in a ReAct loop; exceeding it logs a "
            "warning rather than stopping the agent, as an early signal that it is "
            "spinning unproductively."
        ),
    },
    "reporting.author_team": {
        "title": "Author team",
        "description": ("Author/team name shown on the report cover."),
    },
    "reporting.auto_generate_detection_rules": {
        "title": "Auto-generate detection rules",
        "description": (
            "Enables template-based YARA/Sigma/Suricata detection-rule generation as "
            "part of the report."
        ),
    },
    "reporting.composer_enabled": {
        "title": "Report composer enabled",
        "description": (
            "When true, reports are built section-by-section by the bounded, "
            "per-section Report Composer instead of the legacy single-round "
            "NarrativeAgent. Bounded prompts and a per-section timeout keep a slow "
            "local model from stalling the whole report."
        ),
    },
    "reporting.composer_per_section_timeout": {
        "title": "Composer per-section timeout (s)",
        "description": (
            "Wall-clock timeout in seconds for each report section's LLM call when "
            "composer_enabled is true."
        ),
    },
    "reporting.composer_section_max_tokens": {
        "title": "Composer section max tokens",
        "description": ("Output-token cap per report section when composer_enabled is true."),
    },
    "reporting.default_tlp": {
        "title": "Default TLP marking",
        "description": (
            "Default Traffic Light Protocol marking shown on the report cover and TLP "
            "banner, controlling how the report may be shared onward."
        ),
    },
    "reporting.enabled": {
        "title": "Reporting enabled",
        "description": (
            "When false, the pipeline keeps the legacy judge -> END edge and skips "
            "report generation entirely; downstream consumers only get judge_report and "
            "stix_output."
        ),
    },
    "reporting.html_export_enabled": {
        "title": "HTML export enabled",
        "description": ("Enables server-side HTML-to-PDF export of the generated report."),
    },
    "reporting.include_extended_stix": {
        "title": "Include extended STIX bundle",
        "description": (
            "Emits the extended STIX bundle (Identity/Note/Report SDOs) alongside the "
            "minimal judge bundle. Disable to roughly halve serialization cost when "
            "consumers only need the minimal bundle."
        ),
    },
    "reporting.narrative_max_tokens": {
        "title": "Narrative max tokens",
        "description": (
            "Hard output-token cap for the NarrativeAgent's LLM round, keeping "
            "report-generation tail latency predictable."
        ),
    },
    "reporting.product_type": {
        "title": "Product type",
        "description": (
            "Product-type label shown on the report cover, e.g. 'Malware Analysis Report'."
        ),
    },
    "reporting.publisher": {
        "title": "Publisher",
        "description": ("Publisher name shown on the report cover / front matter."),
    },
    "reporting.report_number_prefix": {
        "title": "Report number prefix",
        "description": (
            "Prefix used when generating the report's reference number, e.g. MJN-2026-0001."
        ),
    },
}


def mcp_server_annotations(
    prefix: str,
    label: str,
    *,
    probe: str | None = None,
    applies_when: dict[str, list[str]] | None = None,
    order: int = 0,
    provider_owned: bool = False,
) -> dict[str, Annotation]:
    """The fourteen leaves of an ``MCPServerConfig`` block, described for ``label``.

    Every MCP server in the settings has the same nine transport/tool-selection
    knobs, plus five sub-project-B fields (``cwd``, ``env_allow``, ``tools``,
    ``agents``, ``label``); writing them out six times invites drift between
    blocks that must behave identically. The per-field wording is fixed, the
    server's name is the only variable.

    ``provider_owned`` marks a block whose ``tools``/``agents``/``label`` a
    static or sandbox provider (Ghidra, radare2, the CAPE MCP sidecar)
    computes for itself and ignores if set: those three leaves get
    ``applies_when`` pinned to the block's own governing key with an empty
    allowed list, which the settings tab can never satisfy, so they are never
    shown. ``cwd`` and ``env_allow`` stay visible under the block's ordinary
    ``applies_when`` — a stdio launch of that server still reads them.
    """
    common: Annotation = {"title": "", "description": ""}
    del common  # documented shape; each entry below is built explicitly

    def ann(title: str, description: str, *, with_probe: bool = False) -> Annotation:
        a: Annotation = {"title": title, "description": description, "order": order}
        if applies_when is not None:
            a["applies_when"] = applies_when
        if with_probe and probe:
            a["probe"] = probe
        return a

    never_shown: dict[str, list[str]] = {key: [] for key in (applies_when or {})}

    def owned_ann(title: str, description: str) -> Annotation:
        a: Annotation = {"title": title, "description": description, "order": order}
        if never_shown:
            a["applies_when"] = never_shown
        return a

    entries: dict[str, Annotation] = {
        f"{prefix}.enabled": ann(
            f"{label} enabled",
            f"Turns on the {label} integration. When off the analyst runs on the "
            "evidence it already has and exposes no tools from this server.",
            with_probe=True,
        ),
        f"{prefix}.transport": ann(
            f"{label} transport",
            "How the server is reached: stdio launches a local subprocess "
            "(command/args/env); http, streamable-http and sse connect to a "
            "running server (url/auth_token).",
        ),
        f"{prefix}.command": ann(
            f"{label} command",
            "Executable launched for the stdio transport, e.g. python or r2mcp.",
        ),
        f"{prefix}.args": ann(
            f"{label} args",
            "Command-line arguments for the stdio subprocess. Relative paths are "
            "resolved against the project root.",
        ),
        f"{prefix}.env": ann(
            f"{label} environment",
            "Extra environment variables for the stdio subprocess. The child gets "
            "these plus a fixed base set, and no credentials of its own.",
        ),
        f"{prefix}.url": ann(
            f"{label} URL",
            "Address of the server for the http transports, e.g. http://localhost:8089.",
            with_probe=True,
        ),
        f"{prefix}.auth_token": ann(
            f"{label} auth token",
            "Bearer token sent to the server over the http transports. Leave "
            "empty when the server does not enforce one.",
            with_probe=True,
        ),
        f"{prefix}.tool_selection": ann(
            f"{label} tool selection",
            "How many of the server's tools the analyst sees per run: curated is "
            "a fixed allow-list (fastest, narrowest); dynamic shows a core triage "
            "set plus the tools relevant to the sample's inferred capabilities; "
            "all exposes every tool, which is measurably slower and noisier.",
        ),
        f"{prefix}.use_all_tools": ann(
            f"{label} force all tools",
            "Back-compat flag: when true, forces tool selection to all regardless "
            "of its own value.",
        ),
        f"{prefix}.cwd": ann(
            f"{label} working directory",
            "Working directory for the stdio subprocess; empty means the repository root.",
        ),
        f"{prefix}.env_allow": ann(
            f"{label} inherited environment names",
            "Names copied out of the API process's own environment into the "
            "stdio subprocess — the only way a credential reaches this sidecar, "
            "since the environment field above is visible in the UI.",
        ),
    }

    if provider_owned:
        entries[f"{prefix}.tools"] = owned_ann(
            f"{label} tool allow-list",
            f"Ignored: {label} is a provider-owned server and computes its own tool exposure.",
        )
        entries[f"{prefix}.agents"] = owned_ann(
            f"{label} receiving analysts",
            f"Ignored: {label} is a provider-owned server and routes to its "
            "provider's own analyst, not a configurable list.",
        )
        entries[f"{prefix}.label"] = owned_ann(
            f"{label} display name",
            f"Ignored: {label} is a provider-owned server; its display name "
            "comes from the provider, not this field.",
        )
    else:
        entries[f"{prefix}.tools"] = ann(
            f"{label} tool allow-list",
            "Allow-list of tool names exposed to the model. Empty exposes "
            "nothing until tools are ticked from the server's probe; null "
            "exposes every tool the server advertises.",
        )
        entries[f"{prefix}.agents"] = ann(
            f"{label} receiving analysts",
            "Which analysts (static, dynamic, network, judge) receive this "
            "server's tools. Empty means none.",
        )
        entries[f"{prefix}.label"] = ann(
            f"{label} display name",
            "Display name shown in the tool-server registry; empty uses the server's key.",
        )

    return entries


_STATIC_GHIDRA = {"core.static.provider": ["ghidra"]}
_STATIC_R2 = {"core.static.provider": ["r2"]}
_STATIC_CAPA_YARA = {"core.static.provider": ["capa_yara"]}
_STATIC_GENERIC = {"core.static.provider": ["generic_mcp"]}
_SANDBOX_CAPE2 = {"core.sandbox.provider": ["cape2"]}
_SANDBOX_TRIAGE = {"core.sandbox.provider": ["triage"]}
_SANDBOX_UPLOAD = {"core.sandbox.provider": ["upload"]}
_SANDBOX_REST = {"core.sandbox.provider": ["rest"]}
_SANDBOX_REST_GENERIC = {
    "core.sandbox.provider": ["rest"],
    "core.sandbox.rest.report.format": ["generic"],
}


ANNOTATIONS.update(
    {
        "static.provider": {
            "title": "Static analysis provider",
            "description": (
                "Which tool produces the static evidence. ghidra runs the Ghidra MCP "
                "server (today's default and the profile the evaluation was measured "
                "on); r2 runs radare2 over its MCP server; capa_yara runs capa and "
                "YARA with no tool server and hands the analyst evidence rather than "
                "tools; generic_mcp attaches any MCP server you configure; none "
                "leaves the static analyst with no tools at all."
            ),
            "order": -1,
            "choices_from": "static_providers",
        },
        "sandbox.provider": {
            "title": "Sandbox provider",
            "description": (
                "Which sandbox produces the dynamic evidence. mock loads fixture "
                "reports from the samples directory with no network access; cape2 "
                "submits to a live CAPEv2 instance; upload runs no detonation and "
                "uses the report attached to the job; triage submits to the Hatching "
                "Triage cloud sandbox; rest drives any HTTP sandbox from the "
                "endpoints and JSONPaths you describe."
            ),
            "order": -1,
            "choices_from": "sandbox_providers",
        },
        "static.r2.binary_path": {
            "title": "radare2 MCP binary",
            "description": (
                "Executable that serves the radare2 MCP tools, looked up on PATH "
                "when it is a bare name. The provider's connection test reports "
                "clearly when it is missing."
            ),
            "applies_when": _STATIC_R2,
            "probe": "r2",
        },
        "static.r2.mirror_dir": {
            "title": "radare2 sample directory",
            "description": (
                "Host directory the sample is copied into so radare2 can open it by "
                "path. Defaults to the same private .work directory the Ghidra "
                "mirror uses."
            ),
            "applies_when": _STATIC_R2,
        },
        "static.capa.rules_dir": {
            "title": "capa rules directory",
            "description": (
                "Directory of flare-capa rules. Missing or empty lowers the "
                "provider to no evidence with a warning rather than failing a run."
            ),
            "applies_when": _STATIC_CAPA_YARA,
            "probe": "capa_yara",
        },
        "static.capa.signatures_dir": {
            "title": "capa signatures directory",
            "description": (
                "Directory of capa's library-identification signatures, used to keep "
                "statically linked library code out of the results."
            ),
            "applies_when": _STATIC_CAPA_YARA,
            "probe": "capa_yara",
        },
        "static.capa.timeout_seconds": {
            "title": "capa timeout (s)",
            "description": (
                "Wall-clock budget for one capa run. A sample that exceeds it "
                "contributes no capa evidence and the run continues."
            ),
            "applies_when": _STATIC_CAPA_YARA,
        },
        "static.capa.backend": {
            "title": "capa backend",
            "description": (
                "Analysis engine capa uses: auto picks per file type, vivisect is "
                "the portable default, pefile is header-only and fast, binja needs a "
                "local Binary Ninja installation."
            ),
            "applies_when": _STATIC_CAPA_YARA,
        },
        "static.yara.rules_dir": {
            "title": "YARA rules directory (static provider)",
            "description": (
                "Your own YARA rules, scanned by the capa_yara static provider. The "
                "deterministic YARA detection layer keeps its own vendored corpus "
                "and is unaffected by this."
            ),
            "applies_when": _STATIC_CAPA_YARA,
            "probe": "capa_yara",
        },
        "static.yara.timeout_seconds": {
            "title": "YARA timeout (s)",
            "description": "Wall-clock budget for one YARA scan of the sample.",
            "applies_when": _STATIC_CAPA_YARA,
        },
        "sandbox.cape2.base_url": {
            "title": "CAPEv2 base URL",
            "description": (
                "Base URL of the CAPEv2 REST API. CAPEv2 is not part of this "
                "repository — it runs on its own Linux host with KVM and registered "
                "guest images; point this at that host's apiv2 address."
            ),
            "applies_when": _SANDBOX_CAPE2,
            "probe": "cape2",
        },
        "sandbox.cape2.api_token": {
            "title": "CAPEv2 API token",
            "description": (
                "Bearer token for the CAPEv2 REST API. Can be left empty for an "
                "unauthenticated local instance."
            ),
            "applies_when": _SANDBOX_CAPE2,
            "probe": "cape2",
        },
        "sandbox.cape2.timeout_seconds": {
            "title": "CAPEv2 timeout (s)",
            "description": (
                "Maximum seconds to wait for a CAPEv2 detonation and report before "
                "giving up. Real detonation takes minutes, so the default is set "
                "well above the poll interval."
            ),
            "applies_when": _SANDBOX_CAPE2,
        },
        "sandbox.cape2.poll_interval_seconds": {
            "title": "CAPEv2 poll interval (s)",
            "description": "Seconds between polls of the CAPEv2 API while a task runs.",
            "applies_when": _SANDBOX_CAPE2,
        },
        "sandbox.triage.base_url": {
            "title": "Triage API base URL",
            "description": (
                "Hatching Triage cloud API root. Use https://private.tria.ge/api/v0 "
                "for a private instance."
            ),
            "applies_when": _SANDBOX_TRIAGE,
            "probe": "triage",
        },
        "sandbox.triage.api_token": {
            "title": "Triage API token",
            "description": (
                "Bearer token from your Triage account. Samples leave this host when "
                "this provider is selected."
            ),
            "applies_when": _SANDBOX_TRIAGE,
            "probe": "triage",
        },
        "sandbox.triage.profile": {
            "title": "Triage VM profile",
            "description": (
                "Name of the Triage analysis profile to request. Empty means the "
                "account's default profile."
            ),
            "applies_when": _SANDBOX_TRIAGE,
        },
        "sandbox.triage.timeout_seconds": {
            "title": "Triage timeout (s)",
            "description": (
                "Maximum seconds to wait for a Triage analysis to reach the reported "
                "state, queueing behind other tenants included."
            ),
            "applies_when": _SANDBOX_TRIAGE,
        },
        "sandbox.triage.poll_interval_seconds": {
            "title": "Triage poll interval (s)",
            "description": (
                "Initial seconds between status polls. The provider backs off by "
                "1.5x up to a minute and honours a Retry-After header."
            ),
            "applies_when": _SANDBOX_TRIAGE,
        },
        "sandbox.triage.fetch_pcap": {
            "title": "Fetch the Triage capture",
            "description": (
                "Download each task's PCAP so the network analyst can inspect the "
                "packets rather than only the structured indicators."
            ),
            "applies_when": _SANDBOX_TRIAGE,
        },
        "sandbox.upload.max_report_bytes": {
            "title": "Uploaded report size limit (bytes)",
            "description": (
                "Reports larger than this are rejected while streaming, before "
                "anything is stored. A gzipped upload is checked again after "
                "inflation."
            ),
            "applies_when": _SANDBOX_UPLOAD,
        },
        "sandbox.upload.allowed_formats": {
            "title": "Accepted report formats",
            "description": (
                "Formats the sniffer may accept for an uploaded report: cape2, "
                "cuckoo, triage. A file that sniffs as anything else is refused."
            ),
            "applies_when": _SANDBOX_UPLOAD,
        },
    }
)

ANNOTATIONS.update(
    mcp_server_annotations(
        "static.ghidra",
        "Ghidra MCP",
        probe="ghidra",
        applies_when=_STATIC_GHIDRA,
        provider_owned=True,
    )
)
ANNOTATIONS.update(
    mcp_server_annotations(
        "static.r2", "radare2 MCP", probe="r2", applies_when=_STATIC_R2, provider_owned=True
    )
)
ANNOTATIONS.update(
    mcp_server_annotations(
        "sandbox.cape2.mcp", "CAPE MCP", applies_when=_SANDBOX_CAPE2, provider_owned=True
    )
)

ANNOTATIONS.update(
    {
        "mcp.servers": {
            "title": "Tool servers",
            "description": (
                "Every MCP server Maljan can attach, keyed by a short name. Each "
                "entry says how to reach the server, which of its tools the model "
                "may call, and which analysts receive them. A newly added server "
                "exposes nothing until its tools are ticked."
            ),
            "group": "mcp",
            "editor": "server_map",
            "order": -1,
        },
        "static.generic.server": {
            "title": "Custom MCP server",
            "description": (
                "Which entry of the tool-server registry the generic_mcp static "
                "provider drives. Empty leaves that provider with nothing to attach."
            ),
            "applies_when": _STATIC_GENERIC,
            "choices_from": "mcp_servers",
        },
    }
)


def _rest(title: str, description: str, *, generic_only: bool = False) -> Annotation:
    """One ``sandbox.rest.*`` leaf: gated on the provider, drawn by one editor.

    ``generic_only`` adds the second gate the mapping leaves need — the
    catalog's ``applies_when`` is a conjunction of key/value sets, so two keys
    in one dict is exactly "the REST provider AND the generic report format".
    """
    return {
        "title": title,
        "description": description,
        "applies_when": _SANDBOX_REST_GENERIC if generic_only else _SANDBOX_REST,
        "editor": "rest_sandbox",
    }


ANNOTATIONS.update(
    {
        "sandbox.rest.base_url": _rest(
            "Sandbox API base URL",
            "Root of the sandbox's HTTP API; every path below is appended to it.",
        ),
        "sandbox.rest.auth.header": _rest(
            "Auth header", "Header carrying the credential, e.g. Authorization or X-API-Key."
        ),
        "sandbox.rest.auth.scheme": _rest(
            "Auth scheme",
            "Prefix written before the token, e.g. Bearer. Empty sends the token alone.",
        ),
        "sandbox.rest.auth.token": _rest(
            "Sandbox API token", "Credential sent in the configured header. Stored encrypted."
        ),
        "sandbox.rest.submit.method": _rest(
            "Submit method", "HTTP method for the submission, POST or PUT."
        ),
        "sandbox.rest.submit.path": _rest(
            "Submit path", "Path the sample is uploaded to, appended to the base URL."
        ),
        "sandbox.rest.submit.file_field": _rest(
            "Submit file field", "Name of the multipart field carrying the sample bytes."
        ),
        "sandbox.rest.submit.extra_fields": _rest(
            "Submit extra fields",
            "Additional multipart fields sent with the sample, as name/value pairs.",
        ),
        "sandbox.rest.submit.task_id_path": _rest(
            "Task id path",
            "JSONPath selecting the task identifier out of the submit response, e.g. $.id.",
        ),
        "sandbox.rest.status.path": _rest(
            "Status path", "Poll path; {task_id} is replaced by the submitted task's id."
        ),
        "sandbox.rest.status.state_path": _rest(
            "Status field path", "JSONPath selecting the state value out of the status response."
        ),
        "sandbox.rest.status.done_values": _rest(
            "Completed states",
            "State values that mean the run finished, compared case-insensitively.",
        ),
        "sandbox.rest.status.failed_values": _rest(
            "Failed states", "State values that mean the run failed and must not be polled further."
        ),
        "sandbox.rest.report.path": _rest(
            "Report path", "Path the finished report is fetched from; {task_id} is substituted."
        ),
        "sandbox.rest.report.format": _rest(
            "Report format",
            "Shape of the fetched report. cape2, cuckoo and triage reuse the mappers the "
            "report-upload provider already uses; generic maps the response with the "
            "JSONPaths below.",
        ),
        "sandbox.rest.report.pcap_path": _rest(
            "PCAP path", "Optional capture path; empty means this sandbox publishes no PCAP."
        ),
        "sandbox.rest.mapping.target_sha256": _rest(
            "Mapping: sample hash", "JSONPath to the detonated sample's SHA-256.", generic_only=True
        ),
        "sandbox.rest.mapping.processes": _rest(
            "Mapping: processes",
            "JSONPath to the process rows; each match supplies pid, ppid, name and command_line.",
            generic_only=True,
        ),
        "sandbox.rest.mapping.calls": _rest(
            "Mapping: API calls",
            "JSONPath to the API-call rows; each match supplies pid, api, args and timestamp.",
            generic_only=True,
        ),
        "sandbox.rest.mapping.signatures": _rest(
            "Mapping: signatures",
            "JSONPath to the signature hits; each match supplies name, description, "
            "severity and ttps.",
            generic_only=True,
        ),
        "sandbox.rest.mapping.dns": _rest(
            "Mapping: DNS",
            "JSONPath to the DNS rows; each match supplies request, type and answers.",
            generic_only=True,
        ),
        "sandbox.rest.mapping.http": _rest(
            "Mapping: HTTP", "JSONPath to the HTTP request rows.", generic_only=True
        ),
        "sandbox.rest.mapping.tcp": _rest(
            "Mapping: TCP",
            "JSONPath to the TCP flows; each match supplies dst and dport.",
            generic_only=True,
        ),
        "sandbox.rest.mapping.udp": _rest(
            "Mapping: UDP",
            "JSONPath to the UDP flows; each match supplies dst and dport.",
            generic_only=True,
        ),
        "sandbox.rest.mapping.hosts": _rest(
            "Mapping: hosts",
            "JSONPath to the contacted hosts, one string per match.",
            generic_only=True,
        ),
        "sandbox.rest.mapping.domains": _rest(
            "Mapping: domains",
            "JSONPath to the resolved domains, one string per match.",
            generic_only=True,
        ),
        "sandbox.rest.mapping.dropped_files": _rest(
            "Mapping: dropped files",
            "JSONPath to the dropped files; each match supplies name, sha256 and size.",
            generic_only=True,
        ),
        "sandbox.rest.mapping.registry": _rest(
            "Mapping: registry",
            "JSONPath to the touched registry paths, one string per match.",
            generic_only=True,
        ),
        "sandbox.rest.mapping.field_names": _rest(
            "Mapping: field renames",
            "Per-row field renames, keyed 'channel.field', e.g. processes.command_line -> cmdline.",
            generic_only=True,
        ),
        "sandbox.rest.timeout_seconds": _rest(
            "Sandbox timeout (s)", "How long a detonation may take before the run is abandoned."
        ),
        "sandbox.rest.poll_interval_seconds": _rest(
            "Poll interval (s)", "Delay between status checks; backs off to 60 s under pressure."
        ),
        "sandbox.rest.verify_tls": _rest(
            "Verify TLS",
            "Check the sandbox's certificate. Turning this off is reported in the "
            "connection test's detail.",
        ),
    }
)
