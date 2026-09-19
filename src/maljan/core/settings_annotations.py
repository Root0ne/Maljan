"""What each setting means, in words a person can act on.

Titles and descriptions were first drafted from the comments of the former
root ``.env.example`` and then edited; a new leaf's title and description are
written by hand here. Groups come from the key prefix (``group_for``); an entry
may override its group. ``applies``
defaults to ``next_job`` for every core setting. ``probe`` names the
connection test in apps/api/app/services/settings_probes.py that exercises
the field.

``GROUP_ORDER`` names and orders the groups; ``GROUP_DESCRIPTIONS`` gives each
one the sentence the console prints under its heading. Inside a group,
``subgroup`` puts an entry under a heading of its own and ``advanced`` folds it
into the group's closed "Advanced" disclosure.
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
        Literal["static_providers", "sandbox_providers", "mcp_servers", "agent_roles", "profiles"]
    ]
    editor: NotRequired[Literal["server_map", "rest_sandbox", "agent_definitions", "stages"]]
    subgroup: NotRequired[str]  # heading inside the group; absent = top of the group
    advanced: NotRequired[bool]  # folded into the group's closed "Advanced" disclosure


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
    ("agents", "Agents"),
    ("events", "Live events"),
    ("tracing", "Tracing"),
    ("enrichment", "Enrichment / threat intelligence"),
    ("api", "API"),
    ("system", "Deployment (read-only)"),
]

GROUP_DESCRIPTIONS: dict[str, str] = {
    "llm": "Which language model backend the analysts and the judge call, and the per-call limits.",
    "providers": (
        "Credentials, endpoints and model names for each LLM vendor; only the selected "
        "provider is used."
    ),
    "frontier": (
        "Evaluation-only comparison endpoints and their cost accounting; nothing in the "
        "analysis pipeline reads them."
    ),
    "static": "The static analysis provider behind the static analyst and its connection details.",
    "sandbox": "Where samples are detonated, or which uploaded report stands in for a detonation.",
    "mcp": "Tool servers the agents may call, with the tools each one is allowed to expose.",
    "memory": (
        "Long-term memory of past analyses: the backend, the collections and how many "
        "neighbours are recalled."
    ),
    "analysis": (
        "Deterministic pre-analysis layers: feature switches, reference data files and "
        "their thresholds."
    ),
    "negotiation": "How many rounds the analysts negotiate and when consensus is reached.",
    "chunking": "How large inputs are split before they reach a model.",
    "reporting": "What the final report contains and the metadata stamped on it.",
    "agents": "The analysts Maljan can run, the profile that selects them, and the ReAct limits.",
    "events": (
        "The live conversation the console draws a running analysis from, and how long the "
        "record of one is kept against the job."
    ),
    "tracing": "LangSmith tracing of every model call.",
    "enrichment": "Threat-intelligence lookups for the indicators a report names.",
    "api": "Request limits and login protection of the HTTP API; changes take effect immediately.",
    "system": "Set in the process environment when the service starts; changed by redeploying.",
}

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
    ("triage", "analysis"),
    ("validation", "analysis"),
    ("events", "events"),
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
    "anthropic_api_key": {
        "title": "Anthropic API key (shortcut)",
        "description": (
            "Flat-key convenience shortcut for Anthropic credentials, auto-promoted "
            "into llm.anthropic.api_key on startup if that nested field is not already "
            "set."
        ),
        "advanced": True,
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
        "advanced": True,
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
            "(LLM__AGENTS__<AGENT>__PROVIDER/MODEL/TEMPERATURE/BASE_URL), letting different "
            "analysts (static, dynamic, network) run on different providers/models "
            "instead of sharing one global expert LLM. Empty by default, meaning every "
            "agent uses the global expert LLM. The judge reads this map too; an entry "
            "that sets only provider and model runs at the per-agent default "
            "temperature of 0.1, not the judge role's 0.0, so set temperature "
            "explicitly to keep the verdict call deterministic. A per-agent base URL "
            "applies to openai and ollama entries only and lets different agents use "
            "different local servers, while the provider's API key stays shared. "
            "Ordinarily edited from "
            "the Agents page; this raw view is for bulk edits."
        ),
        "probe": "llm",
        "advanced": True,
    },
    "llm.anthropic.api_key": {
        "title": "Anthropic API key",
        "description": (
            "Bearer credential for the Anthropic API. Required whenever llm.provider is anthropic."
        ),
        "probe": "llm",
        "subgroup": "Anthropic",
    },
    "llm.anthropic.expert_model": {
        "title": "Anthropic expert model",
        "description": (
            "Model used for analyst LLM calls when llm.provider is anthropic, e.g. "
            "claude-sonnet-4-20250514."
        ),
        "probe": "llm",
        "subgroup": "Anthropic",
    },
    "llm.anthropic.judge_model": {
        "title": "Anthropic judge model",
        "description": ("Model used for the judge verdict call when llm.provider is anthropic."),
        "probe": "llm",
        "subgroup": "Anthropic",
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
        "advanced": True,
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
            "Named additional frontier comparison endpoints, each with its own model, "
            "pricing and spend ceiling, used to test a parameter-size series rather than "
            "a single comparison point. Each arm's API key is stored encrypted on its own "
            "and shown here masked. Evaluation only."
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
        "advanced": True,
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
        "advanced": True,
    },
    "llm.frontier.input_usd_per_mtok": {
        "title": "Frontier input price (USD/Mtok)",
        "description": (
            "Price per million input tokens for this frontier arm, used to enforce "
            "max_spend_usd. Leaving this at zero disables the arm rather than making it "
            "free, unless free_tier is explicitly set."
        ),
        "advanced": True,
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
            "Model identifier for the single frontier comparison arm used by the "
            "original evaluation. Additional arms are configured under "
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
        "advanced": True,
    },
    "llm.frontier.quantisation": {
        "title": "Frontier quantisation",
        "description": (
            "Free-text quantisation label for the model behind this frontier arm (e.g. "
            "Q4_K_M), recorded as provenance for the parameter-size analysis."
        ),
        "advanced": True,
    },
    "llm.frontier.total_params_b": {
        "title": "Frontier total parameters (B)",
        "description": (
            "Total parameter count (billions) of the model behind this frontier arm, "
            "recorded for the parameter-size-vs-F1 correlation analysis in the paper. "
            "Purely descriptive metadata — does not affect behaviour."
        ),
        "advanced": True,
    },
    "llm.gemini.api_key": {
        "title": "Gemini API key",
        "description": (
            "Bearer credential (Google AI API key) for Gemini. Required whenever "
            "llm.provider is gemini."
        ),
        "probe": "llm",
        "subgroup": "Google Gemini",
    },
    "llm.gemini.expert_model": {
        "title": "Gemini expert model",
        "description": ("Gemini model used for analyst LLM calls, e.g. gemini-2.5-pro."),
        "probe": "llm",
        "subgroup": "Google Gemini",
    },
    "llm.gemini.judge_model": {
        "title": "Gemini judge model",
        "description": ("Gemini model used for the judge verdict call."),
        "probe": "llm",
        "subgroup": "Google Gemini",
    },
    "llm.require_probe": {
        "title": "Require a passing model probe",
        "description": (
            "Refuse a job whose agents name a model no probe has reached at the "
            "endpoint they would use. The probe result is stored against that "
            "endpoint and model, so changing either asks for it again. Turn this "
            "off for an air-gapped batch run, where the endpoint is known good "
            "and nobody is at the console to press the button."
        ),
        "probe": "llm",
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
        "probe": "llm",
        "subgroup": "Ollama",
    },
    "llm.ollama.expert_model": {
        "title": "Ollama expert model",
        "description": ("Ollama model tag used for analyst LLM calls, e.g. qwen3.5:9b."),
        "probe": "llm",
        "subgroup": "Ollama",
    },
    "llm.ollama.judge_model": {
        "title": "Ollama judge model",
        "description": ("Ollama model tag used for the judge verdict call."),
        "probe": "llm",
        "subgroup": "Ollama",
    },
    "llm.ollama.disable_thinking": {
        "title": "Ollama disable thinking",
        "description": (
            "When true, sends think=false to Ollama so a reasoning model spends its "
            "output budget on the answer instead of on its own chain of thought. "
            "Leave it off for models that do not reason: Ollama refuses the field "
            "for a model that does not support it."
        ),
        "probe": "llm",
        "subgroup": "Ollama",
        "advanced": True,
    },
    "llm.ollama.keep_alive": {
        "title": "Ollama keep-alive",
        "description": (
            "How long Ollama keeps the model loaded in memory after the last request "
            "(an Ollama duration string, e.g. 30m). Longer values avoid reload latency "
            "between calls at the cost of holding GPU/RAM."
        ),
        "subgroup": "Ollama",
        "advanced": True,
    },
    "llm.ollama.num_ctx": {
        "title": "Ollama context size",
        "description": (
            "Context window size (tokens) requested from the Ollama model. Must be "
            "large enough for the chunked prompt plus generation budget, or the server "
            "silently truncates the oldest context."
        ),
        "subgroup": "Ollama",
    },
    "llm.openai.context_size": {
        "title": "Context window (tokens)",
        "description": (
            "Context window the server behind the base URL was started with, in tokens. "
            "0 leaves it unknown. It sizes the salvage conversation a ReAct loop is "
            "asked to synthesise from when it runs out of steps."
        ),
        "subgroup": "OpenAI",
        "advanced": True,
    },
    "llm.openai.api_key": {
        "title": "OpenAI API key",
        "description": (
            "Bearer credential for api.openai.com or any OpenAI-compatible endpoint set "
            "via base_url. Required whenever llm.provider is openai and the endpoint "
            "enforces auth."
        ),
        "probe": "llm",
        "subgroup": "OpenAI",
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
        "subgroup": "OpenAI",
    },
    "llm.openai.compat": {
        "title": "OpenAI endpoint dialect",
        "description": (
            "Which dialect the endpoint behind base_url speaks. llama_cpp sends the "
            "llama.cpp-only request extras (repetition penalty, the n_predict echo of "
            "the output cap, chat_template_kwargs); standard sends OpenAI-standard "
            "fields only, which is what a hosted OpenAI-compatible API accepts — it "
            "returns 400 Unsupported parameter otherwise. auto reads the base URL "
            "host: loopback, link-local and private addresses are treated as a local "
            "llama.cpp server, everything else as a hosted API."
        ),
        "probe": "llm",
        "subgroup": "OpenAI",
        "advanced": True,
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
        "probe": "llm",
        "subgroup": "OpenAI",
        "advanced": True,
    },
    "llm.openai.expert_model": {
        "title": "OpenAI expert model",
        "description": (
            "Model name used for the analyst (expert) LLM calls when llm.provider is "
            "openai, e.g. gpt-4o-mini or a local model name served behind base_url."
        ),
        "probe": "llm",
        "subgroup": "OpenAI",
    },
    "llm.openai.judge_model": {
        "title": "OpenAI judge model",
        "description": (
            "Model name used for the final verdict (judge) LLM call when llm.provider "
            "is openai. Can differ from expert_model to reserve a stronger model for "
            "the verdict."
        ),
        "probe": "llm",
        "subgroup": "OpenAI",
    },
    "llm.openai.repetition_penalty": {
        "title": "OpenAI repetition penalty",
        "description": (
            "Repetition penalty forwarded to local OpenAI-compatible servers "
            "(llama.cpp/ik_llama.cpp) via extra_body when base_url is set; ignored "
            "against api.openai.com. 1.0 is a no-op — values around 1.15 stop a small "
            "local reasoning model from looping on ATT&CK ID recall."
        ),
        "subgroup": "OpenAI",
        "advanced": True,
    },
    "llm.parallel_analysts": {
        "title": "Run analysts in parallel",
        "description": (
            "The run mode a team gets when it is still written as a plain list of "
            "analysts rather than as stages: true runs them concurrently, which is "
            "correct only for a hosted, multi-slot LLM API, and false (the default) "
            "runs them one at a time, which is required for a single-slot local "
            "llama.cpp/Ollama server where parallel requests would clobber each "
            "other's KV/recurrent state and cause timeouts. A team written as stages "
            "sets this per analysis stage and ignores this key."
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
        "subgroup": "View decomposition",
    },
    "llm.view_decomposition_views": {
        "title": "View-decomposition views",
        "description": (
            "Number of focused sub-prompts to split the analyst's text evidence into, "
            "each run concurrently and merged (0 disables the pilot and keeps today's "
            "single monolithic analyst call). Text path only; the Ghidra/CAPE "
            "tool-using ReAct loop is unaffected."
        ),
        "subgroup": "View decomposition",
    },
    "max_token_limit": {
        "title": "Max token limit",
        "description": (
            "Global token-count ceiling used to truncate prompts before they overflow "
            "the LLM's context window. Conservative by default for smaller-context "
            "models; raise it when running on a large-context model such as Gemini."
        ),
        "subgroup": "Limits",
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
        "advanced": True,
    },
    "preprocessing.api_attck_map_path": {
        "title": "API-to-ATT&CK map path",
        "description": (
            "Path to the API-to-ATT&CK mapping catalog JSON used when use_api_attck_map is enabled."
        ),
        "subgroup": "Reference data",
    },
    "preprocessing.attck_index_backend": {
        "title": "ATT&CK index backend",
        "description": (
            "Backend for the ATT&CK technique index the knowledge tools rank against: "
            "tfidf (keyword bag-of-words, clean alignment gate), semantic (dense "
            "embeddings, better ranking but a poor gate), or hybrid (semantic ranking "
            "with a TF-IDF gate — the default and best-performing option in "
            "evaluation)."
        ),
        "subgroup": "Thresholds and limits",
    },
    "preprocessing.family_fingerprint_catalog_path": {
        "title": "Family-fingerprint catalog path",
        "description": (
            "Path to the vendored family-fingerprint catalog used by family-feature "
            "RAG. Different catalogs trade off size against disjointness from the eval "
            "set; build one with scripts/knowledge/build_family_feature_kb.py."
        ),
        "subgroup": "Reference data",
    },
    "preprocessing.family_rag_min_score": {
        "title": "Family-RAG min score",
        "description": (
            "Minimum similarity score for a family-feature RAG match to be surfaced as "
            "candidate evidence."
        ),
        "subgroup": "Thresholds and limits",
        "advanced": True,
    },
    "preprocessing.family_rag_top_k": {
        "title": "Family-RAG top-K",
        "description": (
            "Number of nearest families surfaced as candidate evidence by family-feature RAG."
        ),
        "subgroup": "Thresholds and limits",
    },
    "preprocessing.function_hash_max_matches": {
        "title": "Function-hash max matches",
        "description": (
            "Maximum number of matching past samples surfaced by function-hash attribution."
        ),
        "subgroup": "Thresholds and limits",
        "advanced": True,
    },
    "preprocessing.function_hash_min_instructions": {
        "title": "Function-hash min instructions",
        "description": (
            "Minimum instruction count for a function to be included in function-hash "
            "attribution. Smaller functions (thunks/stubs) are ignored because they "
            "collide across unrelated binaries and would produce false family links."
        ),
        "subgroup": "Thresholds and limits",
        "advanced": True,
    },
    "preprocessing.language_signatures_path": {
        "title": "Language signatures catalog path",
        "description": (
            "Path to the compiler/language fingerprint catalog JSON used when "
            "use_language_signatures is enabled."
        ),
        "subgroup": "Reference data",
    },
    "preprocessing.max_tool_output_chars": {
        "title": "Max tool output characters",
        "description": (
            "Maximum characters kept from an MCP tool's output (e.g. a Ghidra "
            "decompile). Longer output is summarized (if the function summarizer is "
            "enabled) or truncated; raising it risks pushing the accumulated ReAct "
            "context past the model's window."
        ),
        "subgroup": "Thresholds and limits",
    },
    "preprocessing.packer_signatures_path": {
        "title": "Packer signatures catalog path",
        "description": (
            "Path to the packer/protector signature catalog JSON used when "
            "use_packer_signatures is enabled."
        ),
        "subgroup": "Reference data",
    },
    "preprocessing.sink_reachability_max_funcs": {
        "title": "Sink-reachability max functions",
        "description": (
            "Maximum number of priority functions surfaced by the sink-reachability hint."
        ),
        "subgroup": "Thresholds and limits",
        "advanced": True,
    },
    "preprocessing.static_function_rag_min_chunks": {
        "title": "Static function-RAG min chunks",
        "description": (
            "Minimum static chunk count before function-level retrieval engages; "
            "binaries with fewer chunks always take the full linear-chunking path."
        ),
        "subgroup": "Thresholds and limits",
        "advanced": True,
    },
    "preprocessing.static_function_rag_top_k": {
        "title": "Static function-RAG top-K",
        "description": (
            "Number of top function chunks retrieved per behaviour query for large "
            "binaries when function-level retrieval is engaged (0 disables retrieval "
            "and feeds every chunk linearly). Focuses the static analyst on the "
            "malicious core instead of the whole binary."
        ),
        "subgroup": "Thresholds and limits",
        "advanced": True,
    },
    "preprocessing.summarizer_max_words": {
        "title": "Summarizer max words",
        "description": (
            "Maximum words allowed in each chunk's generated summary when the function "
            "summarizer is enabled."
        ),
        "subgroup": "Function summarizer",
    },
    "preprocessing.summarizer_model": {
        "title": "Summarizer model",
        "description": ("Model identifier for the summarizer LLM, e.g. a small Ollama model tag."),
        "subgroup": "Function summarizer",
    },
    "preprocessing.summarizer_provider": {
        "title": "Summarizer provider",
        "description": (
            "LLM provider used for the function summarizer when use_function_summarizer "
            "is enabled. Prefer a small, cheap local model since this runs as a "
            "pre-pass, not the main analysis."
        ),
        "subgroup": "Function summarizer",
    },
    "preprocessing.use_api_attck_map": {
        "title": "Use API-to-ATT&CK map",
        "description": (
            "Enables deterministic API-to-ATT&CK-technique mapping computed from the "
            "sample's resolved imports, the main source of technique coverage on a "
            "sandbox-unreachable run. On by default. Each row carries the catalog's "
            "own modest confidence and names the imports behind it, so an analyst "
            "reading it can check the reasoning rather than take the number."
        ),
        "subgroup": "Feature switches",
    },
    "preprocessing.use_claim_consistency_gate": {
        "title": "Use claim-consistency gate",
        "description": (
            "When true, the analyst's claim parser drops any claim whose cited artifact "
            "or technique does not actually appear in the source evidence text, "
            "catching hallucinated claims at parse time. Off by default; any gate error "
            "leaves the ISR untouched."
        ),
        "subgroup": "Feature switches",
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
        "subgroup": "Feature switches",
    },
    "preprocessing.use_function_hash_attribution": {
        "title": "Use function-hash attribution",
        "description": (
            "Enables a deterministic pre-pass that computes per-function "
            "normalized-opcode hashes and matches them against past samples in the "
            "function-hash store, injecting a high-precision family-attribution hint. "
            "The judge also writes the current sample's hashes back to grow the corpus."
        ),
        "subgroup": "Feature switches",
    },
    "preprocessing.use_function_summarizer": {
        "title": "Use function summarizer",
        "description": (
            "Enables a small/local LLM pre-summarization pass over large function lists "
            "or decompiled blocks before they reach the expensive expert LLM. Off by "
            "default — it adds latency and only pays off on huge inputs."
        ),
        "subgroup": "Feature switches",
    },
    "preprocessing.use_language_signatures": {
        "title": "Use language signatures",
        "description": (
            "Enables compiler/language fingerprint detection, feeding platform "
            "inference for otherwise-unknown binaries and the static analyst's prompt "
            "with what the sample was written in. On by default."
        ),
        "subgroup": "Feature switches",
    },
    "preprocessing.use_packer_signatures": {
        "title": "Use packer signatures",
        "description": (
            "Enables the ranked packer/protector signature catalog (section names, "
            "entry-point placement, strings) in place of four hardcoded section-name "
            "checks. On by default."
        ),
        "subgroup": "Feature switches",
    },
    "preprocessing.use_sink_reachability": {
        "title": "Use sink-reachability triage",
        "description": (
            "Enables a deterministic pre-pass over the Ghidra call graph that finds "
            "functions reaching security-sensitive sink APIs and injects a 'priority "
            "functions' hint, focusing the static analyst's decompilation on the likely "
            "malicious core. Fails safe to no hint on error or a stripped binary."
        ),
        "subgroup": "Feature switches",
    },
    "triage.enabled": {
        "title": "Run the triage pack",
        "description": (
            "Before any analyst starts, the pipeline runs the deterministic tools "
            "over the sample (identification, hashes, signature, format facts, "
            "strings, IoCs, YARA, capa, Sigma, catalogue lookups, the sandbox "
            "summary, one reputation lookup) and writes each result to the "
            "evidence ledger as facts of the run. Off leaves the stage in every "
            "team and makes it decline with that reason."
        ),
        "subgroup": "Triage pack",
    },
    "triage.strings_head": {
        "title": "Triage strings head",
        "description": (
            "How many printable runs of at least six characters the triage pack "
            "records from the sample. The full string table stays reachable by "
            "tool call; this bounds the one open-ended entry in the pack."
        ),
        "subgroup": "Triage pack",
    },
    "triage.reputation": {
        "title": "Triage reputation lookup",
        "description": (
            "'auto' asks the enabled reputation server once for the sample hash: "
            "VirusTotal's own server when it is enabled, else the threat-intel "
            "sidecar. 'off' records a skipped entry instead. The call goes through "
            "the tool server like any agent's call and is recorded under that "
            "server."
        ),
        "subgroup": "Triage pack",
    },
    "triage.budget_seconds": {
        "title": "Triage pack budget (seconds)",
        "description": (
            "How long the whole triage pack may take. capa and YARA carry their own "
            "budgets; this one is checked between steps, and a step that would start "
            "after it is spent is recorded as not run rather than started."
        ),
        "subgroup": "Triage pack",
    },
    "events.stream_deltas": {
        "title": "Stream partial answers",
        "description": (
            "Publish an agent's text while its loop is still running, so the "
            "conversation fills in as the agent works instead of arriving whole "
            "at the end. What is published is one model turn's text as the loop "
            "produces it, not a token at a time. Off leaves every finished "
            "message exactly as it is."
        ),
        "applies": "next_job",
    },
    "events.retention_days": {
        "title": "Keep the live feed for (days)",
        "description": (
            "How long a finished run's moment-by-moment feed stays on the job "
            "before the worker's nightly sweep removes it. The transcript, the "
            "agent findings and the evidence ledger are kept by the report and "
            "the job and are not touched by this."
        ),
        "applies": "live",
    },
    "validation.alignment_gate": {
        "title": "Technique alignment gate",
        "description": (
            "Whether an analyst's technique claims are ranked against the ATT&CK index "
            "as a check ('auto') or not at all ('off'). 'auto' runs the check only when "
            "this worker has already built the index; the result is a violation the "
            "analyst answers once and a ranking the judge and the report see. No id is "
            "ever replaced."
        ),
        "subgroup": "Technique check",
    },
    "validation.alignment_gate_build": {
        "title": "Build the ATT&CK index for the gate",
        "description": (
            "Lets the first run that needs the alignment gate build the ATT&CK index in "
            "the background, once per worker; that run skips the gate and the runs after "
            "it have it. Off leaves the gate to workers that built the index for another "
            "reason. The build takes seconds and hundreds of megabytes."
        ),
        "subgroup": "Technique check",
    },
    "validation.alignment_threshold": {
        "title": "Alignment gate threshold",
        "description": (
            "The TF-IDF gate score below which a claimed technique may be questioned. "
            "The paper's gate. It questions nothing on its own: the ranking also has to "
            "disagree with the claim by the alignment margin."
        ),
        "subgroup": "Technique check",
    },
    "validation.alignment_margin": {
        "title": "Alignment gate margin",
        "description": (
            "How far a candidate technique from the sample's own ATT&CK domain, and from "
            "another tactic than the claimed id, must beat the claimed id's gate score "
            "before the claim is questioned. The index scores correct ids near zero, so "
            "without a margin nearly every claim is questioned and every batch costs a "
            "model turn."
        ),
        "subgroup": "Technique check",
    },
    "validation.weak_alignment": {
        "title": "Question weakly aligned techniques",
        "description": (
            "Whether the alignment ranking may question an analyst's technique id, at the "
            "cost of one correction turn per batch. Off: the ranking is recorded on the "
            "claim and shown to the judge, and nothing is asked again. No id is ever "
            "replaced either way."
        ),
        "subgroup": "Technique check",
    },
    "react_agent_max_steps": {
        "title": "ReAct agent default max steps",
        "description": (
            "Default maximum LangGraph recursion steps for a ReAct agent loop, tuned "
            "for the network/dynamic analysts' small tool-call count. Per-agent "
            "overrides live in react_agent_max_steps_overrides."
        ),
        "subgroup": "Limits",
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
        "subgroup": "Limits",
        "advanced": True,
    },
    "react_agent_timeout": {
        "title": "ReAct agent default timeout (s)",
        "description": (
            "Default wall-clock timeout in seconds for a ReAct agent loop (analyst or "
            "judge) before it is forced to stop, tuned for the network/dynamic "
            "analysts. Per-agent overrides live in react_agent_timeout_overrides."
        ),
        "subgroup": "Limits",
    },
    "react_agent_timeout_overrides": {
        "title": "ReAct agent timeout overrides",
        "description": (
            "Per-agent timeout overrides (in seconds), keyed by agent name (e.g. "
            "static, dynamic, network, judge), overriding react_agent_timeout for "
            "agents whose workload needs a different budget — the static analyst's "
            "Ghidra ReAct loop in particular needs far more time than the default."
        ),
        "subgroup": "Limits",
        "advanced": True,
    },
    "react_agent_tool_call_budget": {
        "title": "ReAct agent tool-call budget",
        "description": (
            "Soft ceiling on cumulative tool calls in a ReAct loop; exceeding it logs a "
            "warning rather than stopping the agent, as an early signal that it is "
            "spinning unproductively."
        ),
        "subgroup": "Limits",
    },
    "reporting.author_team": {
        "title": "Author team",
        "description": ("Author/team name shown on the report cover."),
        "subgroup": "Document metadata",
    },
    "reporting.auto_generate_detection_rules": {
        "title": "Auto-generate detection rules",
        "description": (
            "Enables template-based YARA/Sigma/Suricata detection-rule generation as "
            "part of the report."
        ),
        "subgroup": "Report content",
    },
    "reporting.composer_enabled": {
        "title": "Report composer enabled",
        "description": (
            "When true, reports are built section-by-section by the bounded, "
            "per-section Report Composer instead of the legacy single-round "
            "NarrativeAgent. Bounded prompts and a per-section timeout keep a slow "
            "local model from stalling the whole report."
        ),
        "subgroup": "Report content",
    },
    "reporting.composer_per_section_timeout": {
        "title": "Composer per-section timeout (s)",
        "description": (
            "Wall-clock timeout in seconds for each report section's LLM call when "
            "composer_enabled is true."
        ),
        "subgroup": "Report content",
    },
    "reporting.composer_section_max_tokens": {
        "title": "Composer section max tokens",
        "description": ("Output-token cap per report section when composer_enabled is true."),
        "subgroup": "Report content",
    },
    "reporting.default_tlp": {
        "title": "Default TLP marking",
        "description": (
            "Default Traffic Light Protocol marking shown on the report cover and TLP "
            "banner, controlling how the report may be shared onward."
        ),
        "subgroup": "Document metadata",
    },
    "reporting.enabled": {
        "title": "Reporting enabled",
        "description": (
            "When false, the pipeline keeps the legacy judge -> END edge and skips "
            "report generation entirely; downstream consumers only get judge_report and "
            "stix_output."
        ),
        "subgroup": "Report content",
    },
    "reporting.evidence_budget_bytes": {
        "title": "Evidence budget per agent (bytes)",
        "description": (
            "How many bytes of tool output one agent may keep in the evidence ledger. "
            "Entries past the budget still record the call and its outcome but carry no "
            "output, and the report states how many were trimmed. Zero disables the "
            "budget and keeps every output."
        ),
        "subgroup": "Report content",
        "advanced": True,
    },
    "reporting.html_export_enabled": {
        "title": "HTML export enabled",
        "description": ("Enables server-side HTML-to-PDF export of the generated report."),
        "subgroup": "Report content",
    },
    "reporting.include_extended_stix": {
        "title": "Include extended STIX bundle",
        "description": (
            "Emits the extended STIX bundle (Identity/Note/Report SDOs) alongside the "
            "minimal judge bundle. Disable to roughly halve serialization cost when "
            "consumers only need the minimal bundle."
        ),
        "subgroup": "Report content",
    },
    "reporting.narrative_max_tokens": {
        "title": "Narrative max tokens",
        "description": (
            "Hard output-token cap for the NarrativeAgent's LLM round, keeping "
            "report-generation tail latency predictable."
        ),
        "subgroup": "Report content",
    },
    "reporting.upstream_findings_max_chars": {
        "title": "Upstream findings budget",
        "description": (
            "How many characters of the upstream stages' findings a stage is given "
            "in its prompt, when its 'inject upstream' setting asks for them. Past "
            "this the block is cut and says so, so a long pipeline cannot spend a "
            "late stage's whole context on a summary of the stages before it."
        ),
        "subgroup": "Report content",
    },
    "reporting.product_type": {
        "title": "Product type",
        "description": (
            "Product-type label shown on the report cover, e.g. 'Malware Analysis Report'."
        ),
        "subgroup": "Document metadata",
    },
    "reporting.publisher": {
        "title": "Publisher",
        "description": ("Publisher name shown on the report cover / front matter."),
        "subgroup": "Document metadata",
    },
    "reporting.report_number_prefix": {
        "title": "Report number prefix",
        "description": (
            "Prefix used when generating the report's reference number, e.g. MJN-2026-0001."
        ),
        "subgroup": "Document metadata",
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
    knobs, plus five tool-server fields (``cwd``, ``env_allow``, ``tools``,
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

    def ann(
        title: str,
        description: str,
        *,
        with_probe: bool = False,
        subgroup: str | None = None,
        advanced: bool = False,
    ) -> Annotation:
        a: Annotation = {"title": title, "description": description, "order": order}
        if applies_when is not None:
            a["applies_when"] = applies_when
        if with_probe and probe:
            a["probe"] = probe
        if subgroup is not None:
            a["subgroup"] = subgroup
        if advanced:
            a["advanced"] = True
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
            subgroup="Connection",
        ),
        f"{prefix}.transport": ann(
            f"{label} transport",
            "How the server is reached: stdio launches a local subprocess "
            "(command/args/env); http, streamable-http and sse connect to a "
            "running server (url/auth_token).",
            subgroup="Connection",
        ),
        f"{prefix}.command": ann(
            f"{label} command",
            "Executable launched for the stdio transport, e.g. python or r2mcp.",
            subgroup="Connection",
        ),
        f"{prefix}.args": ann(
            f"{label} args",
            "Command-line arguments for the stdio subprocess. Relative paths are "
            "resolved against the project root.",
            subgroup="Connection",
        ),
        f"{prefix}.env": ann(
            f"{label} environment",
            "Extra environment variables for the stdio subprocess. The child gets "
            "these plus a fixed base set, and no credentials of its own.",
            advanced=True,
        ),
        f"{prefix}.url": ann(
            f"{label} URL",
            "Address of the server for the http transports, e.g. http://localhost:8089.",
            with_probe=True,
            subgroup="Connection",
        ),
        f"{prefix}.auth_token": ann(
            f"{label} auth token",
            "Bearer token sent to the server over the http transports. Leave "
            "empty when the server does not enforce one.",
            with_probe=True,
            subgroup="Connection",
        ),
        f"{prefix}.cwd": ann(
            f"{label} working directory",
            "Working directory for the stdio subprocess; empty means the repository root.",
            subgroup="Connection",
        ),
        f"{prefix}.env_allow": ann(
            f"{label} inherited environment names",
            "Names copied out of the API process's own environment into the "
            "stdio subprocess — the only way a credential reaches this sidecar, "
            "since the environment field above is visible in the UI.",
            advanced=True,
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
            "subgroup": "Connection",
        },
        "static.r2.mirror_dir": {
            "title": "radare2 sample directory",
            "description": (
                "Host directory the sample is copied into so radare2 can open it by "
                "path, hardened the way every mirror is: owner-only, and removed when "
                "the job ends. It may not be hidden. radare2 rejects any path with a "
                "'/.' segment, so a sample under one makes every r2 tool call answer "
                "'Failed to open file.'"
            ),
            "applies_when": _STATIC_R2,
            "subgroup": "Connection",
        },
        "static.capa.rules_dir": {
            "title": "capa rules directory",
            "description": (
                "Directory of flare-capa rules. Missing or empty lowers the "
                "provider to no evidence with a warning rather than failing a run."
            ),
            "applies_when": _STATIC_CAPA_YARA,
            "probe": "capa_yara",
            "subgroup": "Rules",
        },
        "static.capa.signatures_dir": {
            "title": "capa signatures directory",
            "description": (
                "Directory of capa's library-identification signatures, used to keep "
                "statically linked library code out of the results."
            ),
            "applies_when": _STATIC_CAPA_YARA,
            "probe": "capa_yara",
            "subgroup": "Rules",
        },
        "static.capa.timeout_seconds": {
            "title": "capa timeout (s)",
            "description": (
                "Wall-clock budget for one capa run. A sample that exceeds it "
                "contributes no capa evidence and the run continues."
            ),
            "applies_when": _STATIC_CAPA_YARA,
            "subgroup": "Rules",
        },
        "static.capa.backend": {
            "title": "capa backend",
            "description": (
                "Analysis engine capa uses: auto picks per file type, vivisect is "
                "the portable default, pefile is header-only and fast, binja needs a "
                "local Binary Ninja installation."
            ),
            "applies_when": _STATIC_CAPA_YARA,
            "subgroup": "Rules",
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
            "subgroup": "Rules",
        },
        "static.yara.timeout_seconds": {
            "title": "YARA timeout (s)",
            "description": "Wall-clock budget for one YARA scan of the sample.",
            "applies_when": _STATIC_CAPA_YARA,
            "subgroup": "Rules",
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
        "sandbox.cape2.package_by_format": {
            "title": "CAPEv2 package per format",
            "description": (
                "Which CAPE analysis package each file type is detonated with, as "
                "name/value pairs keyed by the detected type: apk, elf, pdf, ooxml, "
                "ole2, dex, jar, script and so on. Use * for the fallback. A format "
                "with no entry is submitted without a package, so CAPE picks one."
            ),
            "applies_when": _SANDBOX_CAPE2,
        },
        "sandbox.cape2.submit_options": {
            "title": "CAPEv2 submit options",
            "description": (
                "Extra form fields sent verbatim with every submission, as "
                "name/value pairs: machine, tags, options, timeout and anything "
                "else tasks/create/file accepts."
            ),
            "applies_when": _SANDBOX_CAPE2,
            "advanced": True,
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
        "sandbox.triage.profile_by_format": {
            "title": "Triage profile per format",
            "description": (
                "Which Triage VM profile each file type is analysed on, as "
                "name/value pairs keyed by the detected type (apk, elf, macho and "
                "so on). Use * for the fallback; a format with no entry falls back "
                "to the profile above."
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
        "agents.profile": {
            "title": "Active profile",
            "description": (
                "Which profile a job runs unless it names one of its own. A "
                "profile is an ordered set of analysts; 'default' is the "
                "three-analyst architecture this project was measured on."
            ),
            "group": "agents",
            "choices_from": "profiles",
            "order": -1,
        },
        "agents.profiles": {
            # Not "Teams": the console's page for this leaf is already called
            # Teams, and the two headings sat on top of each other. The
            # agents leaf beside it is "Agent definitions" for the same reason.
            "title": "Team definitions",
            "description": (
                "Named teams, each an ordered list of stages: an analysis stage "
                "runs the agents it names, a debate stage argues over the "
                "analysis upstream of it, the verdict stage runs the judge and "
                "the report stage builds the report. A stage may depend on "
                "earlier stages, read their findings, and carry a condition "
                "that decides whether it runs at all. 'default' and "
                "'measurement' are read-only apart from their debate options "
                "and their built-in tool switches; clone one to change it."
            ),
            "group": "agents",
            "editor": "stages",
            "order": -1,
        },
        "agents.delegation_depth": {
            "title": "Delegation depth",
            "description": (
                "How far one agent's ask of another may nest. A stage's agent "
                "asking a specialist is depth 1; that specialist asking another "
                "is depth 2; an ask that would go deeper is refused with a "
                "message the model reads. It bounds the nesting, never how many "
                "times an agent may ask."
            ),
            "group": "agents",
        },
        "agents.delegation_steps": {
            "title": "Steps one ask gets",
            "description": (
                "How many graph steps a delegated agent may spend answering one "
                "ask — about five tool rounds and an answer at the default. It is "
                "the ask's own budget, not a share of the caller's: a callee that "
                "inherited what its caller had left ran out before it had made a "
                "tool call. The caller's own step budget is not reduced by what "
                "its specialists spend; its wall clock is."
            ),
            "group": "agents",
        },
        "agents.delegation_timeout_seconds": {
            "title": "Seconds one ask gets",
            "description": (
                "How long a delegated agent may take over one ask. An ask is also "
                "bounded by the time its caller has left, so the caller's own "
                "stage timeout is what decides how many asks fit in one loop."
            ),
            "group": "agents",
        },
        "agents.definitions": {
            "title": "Agent definitions",
            "description": (
                "Every agent Maljan can run, keyed by a short name: its role, "
                "its prompt, the tool servers it receives, the static "
                "provider it reads and the step and time budget one of its "
                "loops gets. The built-ins are read-only apart from their "
                "enabled switch; clone one to change it."
            ),
            "group": "agents",
            "editor": "agent_definitions",
            "order": -1,
        },
    }
)


def _rest(
    title: str, description: str, *, generic_only: bool = False, probe: str | None = None
) -> Annotation:
    """One ``sandbox.rest.*`` leaf: gated on the provider, drawn by one editor.

    ``generic_only`` adds the second gate the mapping leaves need — the
    catalog's ``applies_when`` is a conjunction of key/value sets, so two keys
    in one dict is exactly "the REST provider AND the generic report format".
    ``probe`` names the connection test the group header's button runs; only
    one leaf per group needs it.
    """
    annotation: Annotation = {
        "title": title,
        "description": description,
        "applies_when": _SANDBOX_REST_GENERIC if generic_only else _SANDBOX_REST,
        "editor": "rest_sandbox",
    }
    if probe is not None:
        annotation["probe"] = probe
    return annotation


ANNOTATIONS.update(
    {
        "sandbox.rest.base_url": _rest(
            "Sandbox API base URL",
            "Root of the sandbox's HTTP API; every path below is appended to it.",
            probe="rest",
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
        "sandbox.rest.submit.submit_fields": _rest(
            "Submit fields",
            "Further multipart fields sent verbatim with the sample, as name/value pairs.",
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
        "sandbox.rest.mapping.channels": _rest(
            "Mapping: open channels",
            "Extra channels this schema has no field for, as name/JSONPath pairs; "
            "namespace the name by platform, e.g. android.permissions.",
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
