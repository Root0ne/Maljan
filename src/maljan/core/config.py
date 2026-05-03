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

from pydantic import BaseModel, Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

# ---------------------------------------------------------------------------
# Per-provider LLM configs
# ---------------------------------------------------------------------------


class OpenAIConfig(BaseModel):
    """OpenAI-specific model selection."""

    api_key: str | None = None
    expert_model: str = "gpt-4o-mini"
    judge_model: str = "gpt-4o"


class AnthropicConfig(BaseModel):
    """Anthropic-specific model selection."""

    api_key: str | None = None
    expert_model: str = "claude-sonnet-4-20250514"
    judge_model: str = "claude-sonnet-4-20250514"


class OllamaConfig(BaseModel):
    """Ollama (local) model selection."""

    base_url: str = "http://localhost:11434"
    expert_model: str = "qwen2.5-coder:7b"
    judge_model: str = "llama3.1:70b"


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

    max_iterations: int = 20
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

    backend: str = "memory"  # "memory" | "qdrant"
    qdrant_url: str = "http://localhost:6333"
    qdrant_collection: str = "maljan_cases"
    top_k: int = 3


class SandboxConfig(BaseModel):
    """Phase 6 CAPEv2 Sandbox configuration.

    Controls which backend is used for dynamic sample analysis. The sandbox
    client is exposed via ServiceContainer.get_sandbox_client() and can be
    passed to FileDataLoader.load_from_sandbox().

    backend:
        "mock"  (default) — MockSandboxClient loads fixture JSON files from
                the samples directory. Requires no network access or external
                services. Safe for CI, tests, and local development.
        "cape2" — CAPEv2Client submits samples to a live CAPEv2 instance
                via its REST API. Requires httpx and a running CAPEv2 server.

    cape2_base_url:
        Base URL of the CAPEv2 REST API (only used when backend="cape2").
    cape2_api_token:
        CAPEv2 authentication token. Leave empty for unauthenticated
        local instances.
    cape2_timeout_seconds:
        Maximum seconds to wait for a task to reach 'reported' status.
    cape2_poll_interval_seconds:
        Seconds between status poll requests during task completion wait.
    """

    backend: str = "mock"  # "mock" | "cape2" | "triage"
    cape2_base_url: str = "http://localhost:8000"
    cape2_api_token: str = ""
    cape2_timeout_seconds: int = 300
    cape2_poll_interval_seconds: int = 10
    # Hatching Triage sandbox (SaaS, free tier)
    triage_api_token: str = ""
    triage_base_url: str = "https://api.tria.ge"
    triage_timeout_seconds: int = 300
    triage_poll_interval_seconds: int = 15


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
    """Configuration for a single MCP server connection."""

    enabled: bool = False
    command: str = ""
    args: list[str] = Field(default_factory=list)
    env: dict[str, str] = Field(default_factory=dict)


class MCPConfig(BaseModel):
    """MCP integration configurations for external tools."""

    ghidra: MCPServerConfig = Field(default_factory=MCPServerConfig)
    cape: MCPServerConfig = Field(default_factory=MCPServerConfig)


# ---------------------------------------------------------------------------
# Root Settings
# ---------------------------------------------------------------------------


class Settings(BaseSettings):
    """Root configuration - reads from .env and environment variables.

    Nested models use double-underscore env var separators:
        LLM__PROVIDER=anthropic
        LLM__OPENAI__API_KEY=sk-...
        NEGOTIATION__MAX_ITERATIONS=3
    """

    model_config = SettingsConfigDict(
        env_file=".env",
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

    # Token overflow protection (128K is conservative for Gemini 1M+ context)
    max_token_limit: int = 128_000

    # ReAct agent execution limits
    react_agent_timeout: int = 600  # seconds before agent loop times out
    react_agent_max_steps: int = 50  # max LangGraph recursion steps

    # LangChain / LangSmith Tracing
    # Enable with: LANGCHAIN_TRACING_V2=true, LANGCHAIN_API_KEY=ls_xxx
    # ServiceContainer reads these and sets the OS env vars LangChain expects.
    langchain_tracing_v2: bool = False
    langchain_api_key: str | None = None
    langchain_project: str = "maljan"

    # Flat shortcut env vars (backward compatibility with existing .env files)
    openai_api_key: str | None = None
    anthropic_api_key: str | None = None
    google_api_key: SecretStr | None = None

    def model_post_init(self, __context: object) -> None:
        """Merge flat env vars into nested config for backward compatibility."""
        if self.openai_api_key and not self.llm.openai.api_key:
            self.llm.openai.api_key = self.openai_api_key
        if self.anthropic_api_key and not self.llm.anthropic.api_key:
            self.llm.anthropic.api_key = self.anthropic_api_key
        if self.google_api_key and not self.llm.gemini.api_key:
            self.llm.gemini.api_key = self.google_api_key


settings = Settings()
