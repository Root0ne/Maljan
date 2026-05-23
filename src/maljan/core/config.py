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

from typing import Any

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

    # Maximum tokens per chunk sent to the LLM
    max_tokens_per_chunk: int = 6000

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
        "triage" — TriageClient submits to Recorded Future Sandbox (tria.ge).
                Public-cloud submissions on the free Researcher tier are
                world-visible and cannot be deleted; use only with samples
                whose public exposure is already acceptable (corpus samples,
                published-IOC samples). Intended for academic / research-paper
                reproducibility — every submission yields a citeable
                tria.ge/<sample_id> URL.

    cape2_base_url, cape2_api_token, cape2_timeout_seconds,
    cape2_poll_interval_seconds:
        CAPEv2 endpoint, optional bearer token, completion timeout and poll
        interval. Token can be empty for unauthenticated local instances.

    triage_api_token, triage_base_url, triage_timeout_seconds,
    triage_poll_interval_seconds:
        Triage API token (https://tria.ge/account -> API access), API base
        URL (default https://api.tria.ge — leave the trailing /v0 off, the
        client appends it), submission-to-report timeout and poll interval.
    """

    backend: str = "mock"  # "mock" | "cape2" | "triage"
    cape2_base_url: str = "http://localhost:8000"
    cape2_api_token: SecretStr = SecretStr("")
    cape2_timeout_seconds: int = 300
    cape2_poll_interval_seconds: int = 10
    triage_api_token: SecretStr = SecretStr("")
    triage_base_url: str = "https://api.tria.ge"
    triage_timeout_seconds: int = 1800
    triage_poll_interval_seconds: int = 15
    # Research-paper defaults: every submission embeds an explicit OS-tag
    # profile derived from the file extension, so behavioral analysis is
    # guaranteed even on Researcher-tier accounts that have no saved
    # profiles (where ``auto: true`` would fall back to static-only).
    # Override per-account by setting ``triage_force_os_tag`` to a tag from
    # ``GET /v0/resources`` (e.g. ``os:windows10-2004-x64``); leave empty to
    # use the built-in extension -> OS mapping.
    triage_force_os_tag: str = ""
    # Behavioral analysis timeout per task (seconds, Triage hard cap 3600).
    triage_behavioral_timeout: int = 120
    # Behavioral network mode: internet | drop | tor.
    triage_network_mode: str = "internet"
    # Optional VPN geolocation tag (see GET /v0/geolocations). Empty = default.
    triage_geolocation: str = ""
    # Optional password for encrypted archives. Common for malware
    # distribution (e.g. "infected"-locked .zip / .rar).
    triage_archive_password: str = ""
    # Comma-separated experiment-metadata tags embedded in every
    # submission (e.g. "experiment:rq2,batch:7"). Surfaces in Triage's
    # report and lets the paper correlate runs by tag.
    triage_user_tags: str = ""
    # Set to True for the old static -> POST /profile {auto:true} flow.
    # Only useful when the account has saved profiles via the web UI; the
    # default embedded-profile path covers the typical research case.
    triage_interactive: bool = False
    triage_auto_profile: bool = False
    # Pull the decrypted PCAPNG file for each behavioral task and persist it
    # under data/triage_pcaps/<task>/. Off by default — PCAPs are large
    # (often tens of MB) and only network-deep analyses need them.
    triage_fetch_pcapng: bool = False
    triage_pcap_dir: str = "data/triage_pcaps"
    # Download dropped/dumped binaries from each behavioral task — payload
    # bytes themselves, not just sha256/path. Persisted under
    # data/triage_dumps/<sample_id>/<sha256_prefix>_<name>. Off by default
    # (can be many tens of MB per sample).
    triage_fetch_dumps: bool = False
    triage_dumps_dir: str = "data/triage_dumps"
    # Pull the raw kernel-monitor JSON log for each behavioral task. Off
    # by default. Persisted under data/triage_logs/<sample>/<task>.onemon.json.
    triage_fetch_onemon: bool = False
    triage_onemon_dir: str = "data/triage_logs"


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
    max_tool_output_chars: int = 8000


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
    # we give it more headroom by default. Override via env, e.g.
    # ``REACT_AGENT_TIMEOUT_OVERRIDES__static=600``.
    react_agent_timeout_overrides: dict[str, int] = Field(default_factory=lambda: {"static": 600})

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
