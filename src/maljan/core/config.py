"""Hierarchical application configuration.

Uses nested Pydantic models so that each subsystem (LLM, negotiation, etc.)
has its own isolated config namespace. Environment variables are flattened
with double-underscore separators (e.g. LLM__PROVIDER=anthropic).

Heterogeneous Model Ensemble:
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

import contextvars
import logging
import re
import sys
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Annotated, Any, Literal

from pydantic import (
    BaseModel,
    Field,
    SecretStr,
    SerializerFunctionWrapHandler,
    field_validator,
    model_serializer,
    model_validator,
)
from pydantic_settings import BaseSettings, PydanticBaseSettingsSource, SettingsConfigDict

from maljan.agents.prompts import (
    ANDROID_STATIC_PROMPT,
    LEAD_PROMPT,
    REVERSER_PROMPT,
    TRIAGE_PROMPT,
)
from maljan.core import virustotal

# The stdlib logger rather than ``maljan.core.logger``: this module is imported
# by almost everything, including the logging setup itself, and it has exactly
# one thing to say — a stored value it had to fall back from.
logger = logging.getLogger(__name__)

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
    # Which dialect the endpoint behind ``base_url`` speaks. The three extras
    # above (the sampler penalty, the ``n_predict`` echo of the output cap and
    # ``chat_template_kwargs``) are llama.cpp's, not OpenAI's, and sending them
    # to a hosted OpenAI-compatible API is a 400 on the first request — a live
    # run against integrate.api.nvidia.com died on
    # ``Unsupported parameter(s): n_predict`` before a single analyst ran.
    # A custom base URL is not the same fact as a llama.cpp server, so it is
    # asked here instead of inferred from one. ``auto`` reads the host: a
    # loopback, link-local or private address is a local server, anything else
    # is a hosted API that gets standard fields only.
    compat: Literal["auto", "llama_cpp", "standard"] = "auto"
    # The context window the server behind ``base_url`` was started with, in
    # tokens. Zero means it is not known, which is the honest default: an
    # OpenAI-compatible endpoint does not report it and guessing one is worse
    # than saying so. What reads it is the forced-synthesis budget, which fits
    # the salvage conversation to a fraction of the window rather than to a
    # fixed number of characters chosen for one deployment.
    context_size: Annotated[int, Field(ge=0)] = 0


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
    # Ollama's own ``think`` switch, the counterpart of the OpenAI-compatible
    # ``disable_thinking`` above. A reasoning model served by Ollama spends its
    # output budget in the thinking channel and answers with an empty string;
    # turning this on spends it on the answer. Off by default, because a model
    # that cannot think is not told to stop — Ollama answers a ``think`` it
    # does not understand with an error, and most tags are not reasoning
    # models.
    disable_thinking: bool = False


class GeminiConfig(BaseModel):
    api_key: SecretStr | None = None
    expert_model: str = "gemini-2.5-pro"
    judge_model: str = "gemini-2.5-pro"


class ModelChoice(BaseModel):
    """One model an agent may call: provider, model, and where it is served.

    The shape a per-agent override has always had, named on its own so the
    models an agent falls back to are written exactly the way its first model
    is. ``temperature`` left at ``None`` takes the entry's own, and ``0.1``
    when neither sets one.

    Attributes:
        provider:    LLM provider name ("openai", "anthropic", "ollama", "gemini").
        model:       Model identifier (e.g. "gpt-4o", "claude-3-5-sonnet",
                     "llama3.1:8b").
        temperature: Optional temperature override.
        base_url:    Optional per-agent endpoint, so two agents can sit on two
                     different OpenAI-compatible servers (llama.cpp /
                     ik_llama.cpp) or two different Ollama servers instead of
                     sharing the single global one. Only meaningful for the
                     "openai" and "ollama" providers; the credential stays
                     global, so an "openai" entry pointing at its own endpoint
                     still authenticates with llm.openai.api_key.
    """

    provider: str
    model: str
    temperature: float | None = None
    base_url: str | None = None

    @model_validator(mode="after")
    def _base_url_belongs_to_an_endpoint_provider(self) -> "ModelChoice":
        """Reject a per-agent endpoint the provider has nowhere to send.

        Anthropic and Gemini are vendor APIs here, with no per-agent endpoint
        to override, so a base_url set against them would be silently dropped
        at build time. Saying so is the only useful answer.
        """
        if self.base_url is not None and not self.base_url.strip():
            self.base_url = None
        if self.base_url and self.provider not in ("openai", "ollama"):
            raise ValueError(
                f"base_url is only supported for the 'openai' and 'ollama' providers, "
                f"not '{self.provider}'; those providers have no per-agent endpoint."
            )
        return self

    def same_call(self, other: "ModelChoice") -> bool:
        """Whether two choices would send a call to the same model at the same place."""
        return (self.provider, self.model, self.base_url or None) == (
            other.provider,
            other.model,
            other.base_url or None,
        )


class AgentLLMConfig(ModelChoice):
    """Per-agent LLM override for heterogeneous model ensemble.

    When populated for a specific agent name, ServiceContainer will build a
    dedicated LLM instance for that agent instead of reusing the global expert
    LLM. This breaks the single-model echo chamber by ensuring each expert
    uses a different model family.

    ``fallbacks`` is the rest of the agent's ordered model list: the models
    tried, in order, when the one before them fails *as a provider* — a
    connection error, a timeout, an HTTP 5xx, a model the server does not
    have, a refusal the provider reports as an error. Never on what a model
    said: an answer the platform's validation rejects goes back to the model
    that wrote it, because asking another model instead would be the platform
    choosing a different answer. Empty keeps the single-model form, which is
    every entry written before the list existed.
    """

    fallbacks: list[ModelChoice] = Field(default_factory=list)

    @model_validator(mode="after")
    def _each_model_once(self) -> "AgentLLMConfig":
        """A model named twice in one list would only be asked twice."""
        seen: list[ModelChoice] = [self]
        for choice in self.fallbacks:
            if any(choice.same_call(earlier) for earlier in seen):
                raise ValueError(
                    f"fallback {choice.provider}/{choice.model} is already in this agent's "
                    "model list; name each model once."
                )
            seen.append(choice)
        return self

    def chain(self) -> list[ModelChoice]:
        """The agent's models in the order they are tried, first model first."""
        return [self, *self.fallbacks]


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
    # An earlier harness recorded throttles as failures and reported n=9
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
    """The frontier comparison arms.

    **Evaluation only.** Nothing in the analysis pipeline reads this; only the
    eval harnesses do, through ``maljan.core.frontier``. The arms exist to close
    pitfall **P8** — every LLM result in this work is one model on one machine,
    and a single-model finding cannot be read as a property of the architecture.

    Inherits the endpoint fields so the original single-endpoint configuration
    keeps working unchanged (``LLM__FRONTIER__MODEL`` and friends still describe
    one arm). Additional arms go in ``arms`` and are addressed by
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
    # How much of an agent's loop budget one model on its fallback list may
    # spend on a turn before it is treated as stalled and the next model is
    # asked (``maljan.llm.fallback``). A share of the loop rather than a fixed
    # number of seconds, because the loop budget is what would otherwise
    # cancel the stall first: at a half, a first model that stops answering
    # leaves the other half of the loop to the model that stays for it.
    fallback_turn_share: Annotated[float, Field(gt=0.0, lt=1.0)] = 0.5

    # Whether a job is refused when an agent names a model no probe has
    # reached. A model name is the one part of a definition nothing validates
    # until the run gets to that agent: a typo in it, or an endpoint that no
    # longer serves it, fails minutes into an analysis with a sample already
    # uploaded and a queue slot spent. The settings probe already answers the
    # question; this makes the answer a precondition rather than a courtesy.
    # Turned off for an air-gapped batch run, where the endpoint is known good
    # and there is nobody at a console to press the button.
    require_probe: bool = True

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

    # When True, analysts run in parallel —
    # correct for hosted multi-slot LLMs. When False (the default), the
    # pipeline runs analysts sequentially so a single-slot
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
    # Raised 0 -> 8192. The analyst path was the only
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
    # llama-server now serves 128K (``-c 131072``); budgeting ~60K for the
    # static loop's 40 tool observations, ~4K system and ~8K generation leaves
    # ~56K headroom, so 20K/chunk is safe and collapses that same PE to ~8
    # chunks. That 60K no longer has to be budgeted by hand: a tool answer is
    # measured against what the window has left at the moment of the call
    # (``max_tool_output_chars`` below), and the chunk sitting in the
    # conversation is part of what it is measured against. Override via
    # ``CHUNKING__MAX_TOKENS_PER_CHUNK``.
    max_tokens_per_chunk: Annotated[int, Field(ge=1)] = 20000

    # Overlap between consecutive chunks (in tokens) to preserve context
    overlap_tokens: Annotated[int, Field(ge=0)] = 200

    # If True, skip chunking for data smaller than max_tokens_per_chunk
    skip_if_fits: bool = True


class MemoryConfig(BaseModel):
    """Long-Term Memory configuration.

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
        Maximum character length for MCP tool outputs. Zero — the default —
        derives it per call from the context window the served model was
        found to have; a positive value is an explicit operator cap.
    """

    use_function_summarizer: bool = False
    summarizer_provider: Literal["openai", "anthropic", "ollama", "gemini"] = "ollama"
    summarizer_model: str = "llama3.2:3b"
    summarizer_max_words: Annotated[int, Field(ge=1)] = 150
    # Zero means "derive it", and zero is the default.
    #
    # The number this replaces was 6,000 characters, and every argument for it
    # was an argument about one deployment: at the static analyst's 40 steps,
    # 40 observations of ~1,500 tokens plus a 20k chunk plus ~12k of system and
    # generation came to ~90-95k, a safe margin under the 131,072 that server
    # was started with. Every part of that is a fact about one model. On a
    # model served with 32,768 tokens the same constant does not fit; on one
    # with a million it throws information away for nothing.
    #
    # Derived, the cap is worked out at the moment of the call from the window
    # the served model was found to have, less what the conversation already
    # holds and the room kept back for the model's own reply, converted at a
    # measured characters-per-token figure, times the share one answer may
    # take. The whole arithmetic, its numbers and where each came from are in
    # ``maljan.llm.context_window``; the window itself is learned from the
    # server's own metadata endpoint, from a vendored table, or from a stated
    # fallback, and the run summary says which.
    #
    # A positive value is the operator saying the number themselves, and it
    # behaves exactly as this setting always did: that cap, on every answer,
    # whatever the window. Override via ``PREPROCESSING__MAX_TOOL_OUTPUT_CHARS``.
    max_tool_output_chars: Annotated[int, Field(ge=0)] = 0

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
    # no-op (fail-safe). Build the catalog with scripts/knowledge/build_family_feature_kb.py.
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

    # Deterministic API→ATT&CK mapping, computed from the same resolved-import
    # set as the behaviour map above (one parse, two projections). It fills
    # ``StaticAnalysis.api_technique_hits``: one row per *rule* with the exact
    # imports that evidenced it, which an analyst reads and decides about. Two
    # rules may name one technique by two mechanisms, and each carries its own
    # ``rule`` label so the two rows are not read as a duplicate.
    # Each row carries the catalog's own confidence, deliberately modest — a
    # resolved import merely being present is weak — and each technique declares
    # a ``min_apis`` so one ubiquitous import cannot produce a row on its own.
    # ON by default; absent the catalog the audit trail is simply empty.
    use_api_attck_map: bool = True
    api_attck_map_path: str = "data/api_attck_map_v1.json"

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

    # ATT&CK index backend for technique-ID grounding (§1.5). One of:
    #   "tfidf"    keyword bag-of-words (clean alignment gate, weaker ranking)
    #   "semantic" dense BGE-384 embeddings (better ranking, poor gate)
    #   "hybrid"   semantic ranking + TF-IDF gate — best of both (DEFAULT, §1.5.1)
    # The TRAM2 comparison showed the hybrid dominates both pure backends: it
    # matches semantic's ranking (+6pp
    # top-3 over TF-IDF) AND gives the cleanest alignment gate (correct-vs-wrong
    # separation +0.108 vs TF-IDF +0.068 vs semantic +0.020). Its gate is TF-IDF,
    # ``tools.knowledge.resolve_technique`` returns both numbers per candidate
    # and says which one is safe to threshold on. fastembed is already loaded in
    # production for long-term memory, so the marginal cost is one catalog embed
    # at startup. Set to "tfidf" to skip embeddings entirely (air-gapped/minimal).
    attck_index_backend: Literal["tfidf", "semantic", "hybrid"] = "hybrid"


# ---------------------------------------------------------------------------
# MCP (Model Context Protocol) Integration
# ---------------------------------------------------------------------------

# The role a definition plays in the fixed skeleton. ``generic`` and ``lead``
# are the roles with no class of their own: both run as ``ConfigurableAnalyst``
# and are nothing but their prompt and their tools. ``lead`` is the one whose
# tools are, first of all, other agents: it plans, delegates and weighs, and
# naming that as a role is what lets the console, the transcript and a report
# say which agent led. ``report`` is the one role that is only a prompt
# template: the reporter definition picks the LLM and the prompt the narrative
# and composer steps run with, and the report stage is a deterministic build
# around them rather than an agent loop.
AnalystRole = Literal["static", "dynamic", "network", "judge", "generic", "lead", "report"]
# The roles that are a prompt rather than a class, and therefore need one.
PROMPT_ROLES: tuple[str, ...] = ("generic", "lead")

# Why a provider reference is refused, in one sentence both the settings model
# and the API's definition editor raise, so the two never word it differently.
# A built-in role opens the provider its class knows about; a definition that
# is only a prompt is the one that has to say which one it wants.
PROVIDER_REFERENCE_RULE = (
    f"provider tool references are only valid on {' and '.join(PROMPT_ROLES)} "
    "definitions; built-in roles open their provider themselves"
)

# Deprecated. ``MCPServerConfig.agents`` used to be a Literal of the four
# built-in roles; an operator can now bind a server to any definition key, so
# the field is a plain ``str`` validated against the definition map in
# ``Settings``. The name stays because the tool-server modules import it, and
# it stays a type so an annotation using it still type-checks.
AgentRole = str

# A server key is a slug: lowercase, starts with a letter, at most 32 chars.
# It is a path segment in the probe URL and a prefix in a renamed tool name,
# so it is validated in the model rather than only in the API.
SERVER_KEY_PATTERN = r"^[a-z][a-z0-9_-]{0,31}$"
# The one value in ``ProfileDefinition.exclude_servers`` that is not a key.
# It cannot collide with one: the key pattern above admits no ``*``.
ALL_SERVERS = "*"
BUILTIN_SERVER_KEYS: tuple[str, ...] = (
    "analysis",
    "knowledge",
    "network",
    "threatintel",
    virustotal.SERVER_KEY,
)
# The built-in servers that answer "who is this sample": VirusTotal's own
# server and the REST sidecar that reads VirusTotal and AbuseIPDB. Named as a
# set rather than found by scanning prose, because what decides whether the
# question has been asked is which server a ledger entry came from, and a
# sentence that happens to contain the word "reputation" is not an answer.
REPUTATION_SERVER_KEYS: tuple[str, ...] = (virustotal.SERVER_KEY, "threatintel")
RESERVED_SERVER_KEYS: tuple[str, ...] = (
    "analysis",
    "knowledge",
    "network",
    "threatintel",
    virustotal.SERVER_KEY,
    "ghidra",
    "cape",
)


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
    auth_token: SecretStr = SecretStr("")
    # Working directory for the stdio child; empty means the repository root.
    cwd: str = ""
    # Names copied out of the API process's own environment into the child.
    # The only way a credential reaches a sidecar: ``env`` below is a visible
    # setting, so a token written there would be readable in the UI.
    env_allow: list[str] = Field(default_factory=list)
    # Allow-list. ``None`` exposes every tool the server advertises (what the
    # built-ins do today); ``[]`` exposes nothing, which is what a freshly
    # added custom server does until the operator ticks tools from its probe.
    tools: list[str] | None = None
    # Which agents receive this server's tools. Definition keys — the four
    # built-in roles are simply the four built-in keys — validated against
    # ``agents.definitions`` in ``Settings``.
    agents: list[str] = Field(default_factory=list)
    # Display name; empty means "use the key".
    label: str = ""

    @model_validator(mode="after")
    def _refuse_the_composed_names(self) -> "MCPServerConfig":
        """A name the spawn composes is not a name a stored row may carry.

        ``MALJAN_STAGING_JOB`` says which job's directory a sidecar writes and
        reads in, and it is composed per job when the server is started. A
        stored mapping is applied to the child's environment on top of
        everything else, so one naming this would point that server at another
        job's bytes for every job it is attached to. There is nothing an
        operator could correctly write here, so the value is refused where it
        is entered rather than ignored where it is used.
        """
        from maljan.tools.staging import STAGING_JOB_ENV

        for name in (STAGING_JOB_ENV,):
            if name in self.env or name in self.env_allow:
                raise ValueError(
                    f"{name} is composed per job when this server is started and cannot be "
                    f"set here; remove it from env and env_allow"
                )
        return self


# The names a built-in sidecar is always started with, whatever a stored
# registry row says. They are the two facts a sidecar cannot work out for
# itself: which directories it may read a path argument in, and where a
# delivered sample lands and for how long. A child that loses
# ``MALJAN_SAMPLE_ROOTS`` refuses every tool call on the run's own sample;
# one that loses ``MALJAN_STAGING_DIR`` writes its uploads somewhere the rest
# of the deployment does not look, and one that loses
# ``MALJAN_STAGING_TTL_HOURS`` silently keeps live malware on disk for the
# default day instead of the hours the deployment chose. ``knowledge`` is the
# process where the ATT&CK index is actually built, so one that loses
# ``MALJAN_INDEX_RETRY_SECONDS`` keeps re-attempting a fifty-megabyte download
# every fifteen minutes on a deployment that set the interval to zero to stop
# exactly that.
#
# Everything else a built-in ships with is a default an operator may take
# away. ``threatintel``'s ``VIRUSTOTAL_API_KEY`` and ``ABUSEIPDB_API_KEY`` are
# the deployment's own credentials: clearing that list is how an operator stops
# a sample being looked up, and it stays cleared.
REQUIRED_ENV_ALLOW: dict[str, tuple[str, ...]] = {
    "analysis": ("MALJAN_STAGING_DIR", "MALJAN_STAGING_TTL_HOURS", "MALJAN_SAMPLE_ROOTS"),
    "network": ("MALJAN_STAGING_DIR", "MALJAN_SAMPLE_ROOTS"),
    "knowledge": ("MALJAN_INDEX_RETRY_SECONDS",),
}


def _builtin_servers() -> dict[str, MCPServerConfig]:
    """The servers a deployment starts with, as settings rather than constants.

    ``analysis`` and ``knowledge`` are the tool sidecars: every static-analysis
    capability the pipeline used to run in-process, and every reference lookup
    it used to consult from one stage, offered to an agent as a tool. An
    operator turns one off by flipping ``enabled`` rather than by editing code.
    ``analysis``
    sees environment variables of its own — ``MALJAN_STAGING_DIR`` and
    ``MALJAN_STAGING_TTL_HOURS``, which say where its ``put_sample`` uploads
    land and how long they are kept, and ``knowledge`` sees
    ``MALJAN_INDEX_RETRY_SECONDS``, which is how long it believes a failed
    ATT&CK index build. Both file-reading sidecars also see
    ``MALJAN_SAMPLE_ROOTS``: the directories they may read a path argument in,
    on top of the staging directory. The worker exports the mirror it copies
    a sample into; without it a sidecar reads only what it staged itself.

    The two tool sidecars carry ``agents=[]`` on purpose. They are bound by the
    ``ToolRef``s in ``_builtin_definitions()`` and by nothing else, so a clone
    of the static definition with the ``analysis`` reference removed really
    does run without the analysis tools. Binding them by role as well would
    make the definition's tool list decorative.

    Byte-for-byte the launch parameters ``NetworkAnalyst._initialize_mcp_client``
    and ``JudgeAgent._initialize_mcp_client`` used before the sidecars became
    settings:
    ``sys.executable`` running ``<dir>/server.py`` with ``<dir>`` as cwd, the
    threat-intel one alone allowed to see the two intel keys. ``tools=None``
    keeps the whole manifest, which is what those agents did, and what
    ``tests/fixtures/golden/mcp_tools/*.json`` pins.

    ``virustotal`` is the one entry that is neither a sidecar of this repo nor
    a local process: it is VirusTotal's own server, reached over HTTP with an
    agent token, and the one built-in that ships disabled and with a narrowed
    tool list.
    """
    return {
        "analysis": MCPServerConfig(
            enabled=True,
            transport="stdio",
            command=sys.executable,
            args=["services/analysis-mcp/server.py"],
            cwd="services/analysis-mcp",
            env_allow=[
                "MALJAN_STAGING_DIR",
                "MALJAN_STAGING_TTL_HOURS",
                "MALJAN_SAMPLE_ROOTS",
            ],
            agents=[],
            label="Analysis MCP",
        ),
        "knowledge": MCPServerConfig(
            enabled=True,
            transport="stdio",
            command=sys.executable,
            args=["services/knowledge-mcp/server.py"],
            cwd="services/knowledge-mcp",
            env_allow=["MALJAN_INDEX_RETRY_SECONDS"],
            agents=[],
            label="Knowledge MCP",
        ),
        "network": MCPServerConfig(
            enabled=True,
            transport="stdio",
            command=sys.executable,
            args=["services/network-mcp/server.py"],
            cwd="services/network-mcp",
            env_allow=["MALJAN_STAGING_DIR", "MALJAN_SAMPLE_ROOTS"],
            agents=["network"],
            label="Network MCP",
        ),
        "threatintel": MCPServerConfig(
            enabled=True,
            transport="stdio",
            command=sys.executable,
            args=["services/threatintel-mcp/server.py"],
            cwd="services/threatintel-mcp",
            env_allow=["VIRUSTOTAL_API_KEY", "ABUSEIPDB_API_KEY"],
            agents=["judge"],
            label="Threat intel MCP",
        ),
        # VirusTotal's own MCP server, reached over its streamable-HTTP
        # endpoint. Off until an operator registers an agent token, because
        # there is nothing to seed a credential with and a server that dials
        # out on every run without one would only ever contribute a failure.
        #
        # ``tools`` is the one built-in that ships a narrowed list. Every
        # lookup is read-only; the submit tools upload the sample to
        # VirusTotal, so they stay unticked until the operator says otherwise.
        # ``agents=[]`` for the reason the tool sidecars carry it: the
        # definitions in ``_builtin_definitions()`` reference this server by
        # name, and a role binding on top would make those lists decorative.
        virustotal.SERVER_KEY: MCPServerConfig(
            enabled=False,
            transport="streamable-http",
            url=virustotal.MCP_ENDPOINT,
            tools=list(virustotal.LOOKUP_TOOLS),
            agents=[],
            label=virustotal.SERVER_LABEL,
        ),
    }


def builtin_env_allow(key: str, configured: Iterable[str]) -> list[str]:
    """The names a built-in's child may read: the required ones, then the stored ones.

    Some of a built-in sidecar's environment belongs to the code that ships
    with it rather than to a stored setting. ``analysis`` and ``network``
    refuse a path argument that lands outside the directories
    ``MALJAN_SAMPLE_ROOTS`` names, so a child that cannot read that variable
    refuses the very sample its run is about — with the error a real escape
    attempt gets, in the ledger and in front of the model.

    The registry is stored as a single row holding every server, written whole
    whenever an operator saves anything in it: a token, a server of their own,
    a built-in switched off. Each save therefore pins the built-ins' launch
    parameters as they stood that day, and re-seeding only the *missing* keys
    left a name added to a sidecar afterwards reaching fresh installs alone.
    ``REQUIRED_ENV_ALLOW`` is what a stored row cannot take away.

    It is a floor, not the whole shipped list. Every other default is the
    operator's to remove — a ``threatintel`` whose ``env_allow`` an admin has
    emptied keeps its API keys out of the child on load, on save, in the
    editor's view and in the connection test. Stored names are kept, after the
    required ones, so a name an admin added still reaches the child. A key with
    nothing required of it — every server an operator added, and a built-in
    that takes no path — is left exactly as stored.
    """
    return list(dict.fromkeys([*REQUIRED_ENV_ALLOW.get(key, ()), *configured]))


class MCPBreakerConfig(BaseModel):
    """A tool server that keeps failing is rested; a slow one is not piled onto.

    ``failures_to_open`` calls in a row the server did not answer — a timeout,
    a refused connection, the server's process gone, or a call that did not
    finish within its caller's budget — open the server's breaker for
    ``cooldown_seconds``. A call in that time is answered by the platform with
    an authored tool error naming the server, that it is resting and when it
    will be tried again; after it, one call is let through and a success
    closes the breaker. A tool that answers with its own error has answered and
    never counts.

    ``max_concurrent_calls`` is how many calls one server may have in flight
    for one job at once, so parallel analysts queue rather than pile onto one
    slow sidecar. ``0`` leaves the calls uncapped.

    ``call_timeout_seconds`` is how long a call may go unanswered before it is
    a timeout, which the breaker counts.
    """

    failures_to_open: Annotated[int, Field(ge=1)] = 3
    cooldown_seconds: Annotated[float, Field(ge=0.0)] = 60.0
    max_concurrent_calls: Annotated[int, Field(ge=0)] = 4
    # The budget every tool call gets at least before it counts as a server
    # that did not answer (a tool whose server declares a longer budget gets
    # that, and thirty seconds of grace are added either way). Zero derives
    # it from the longest tool budget the deployment configures — capa's.
    call_timeout_seconds: Annotated[float, Field(ge=0.0)] = 0.0


class MCPConfig(BaseModel):
    """The operator-visible registry of tool servers.

    ``ghidra`` and ``cape`` used to live here as a transitional mirror of
    ``static.ghidra`` / ``sandbox.cape2.mcp`` for readers that had not yet
    moved onto the provider layer; every reader has since moved, and
    ``servers`` now holds a real ``dict[str, MCPServerConfig]`` for
    operator-configured MCP tools that are not one of the built-in providers.
    """

    # The operator-visible registry of tool servers, keyed by slug. Built-in
    # entries are re-seeded on load, so "delete" in the UI means enabled=False
    # for them and a real removal for a custom key.
    servers: dict[str, MCPServerConfig] = Field(default_factory=_builtin_servers)
    # How a job treats a tool server that keeps failing at the transport, and
    # how many calls it may have in flight at once. Per job and per server;
    # see ``maljan.providers.server_guard``.
    breaker: MCPBreakerConfig = Field(default_factory=lambda: MCPBreakerConfig())

    @model_validator(mode="after")
    def _reseed_builtins(self) -> "MCPConfig":
        """A built-in key that is absent comes back; one that is present is kept.

        An operator who disables ``threatintel`` stores ``enabled=False`` and
        keeps every other field they set. An override written before a built-in
        existed simply gains it. Neither can end with a run silently missing a
        sidecar the pipeline assumes.

        A stored ``env_allow`` is kept as it is, except that the names in
        ``REQUIRED_ENV_ALLOW`` come back — see ``builtin_env_allow``.
        """
        for key, default in _builtin_servers().items():
            stored = self.servers.setdefault(key, default)
            if stored is not default:
                stored.env_allow = builtin_env_allow(key, stored.env_allow)
        return self


# ---------------------------------------------------------------------------
# Agent composition
# ---------------------------------------------------------------------------

# A definition key is a slug, exactly like a server key: it names a graph node
# (``f"{key}_analyst"``), a path segment in the probe URL, and a key in
# ``llm.agents``. Sharing the pattern rather than re-declaring it keeps the two
# maps' rules from drifting apart.
AGENT_KEY_PATTERN = SERVER_KEY_PATTERN
JUDGE_AGENT_KEY = "judge"
# The narrative/composer step, as a definition. It exists so the report has an
# LLM entry and a prompt of its own instead of borrowing the judge's, and so a
# report stage names an agent like every other stage does.
REPORTER_AGENT_KEY = "reporter"
BUILTIN_AGENTS: tuple[str, ...] = ("static", "dynamic", "network", "judge", "reporter")


# The generic agents the seeded ``mobile`` and ``deep_static`` teams are built
# from. Kept apart from ``BUILTIN_AGENTS``, which names the roles that have a
# class behind them: a generic agent is a definition, a prompt and a tool list,
# and the whole point of seeding these is that a team of one's own is written
# the same way. They are seeded and locked like any other built-in definition.
#
# Derived from the seeds rather than written out beside them. A second
# hand-kept copy of the same three names is a copy that goes stale the first
# time a fourth is added.
def seeded_generic_agents() -> tuple[str, ...]:
    """The seeded definitions that are a prompt rather than a class."""
    return tuple(key for key, d in _builtin_definitions().items() if d.role in PROMPT_ROLES)


BUILTIN_PROFILES: tuple[str, ...] = ("default", "measurement", "mobile", "deep_static", "team_lead")

# What an agent may be handed as its input text. ``sample.path`` is the
# container-visible path its tools load the sample from; ``sample.chunks`` the
# parsed sample profile; the ``sandbox.*`` entries are slices of the job's
# sandbox report, ``sandbox.full`` being the whole document. Empty on a
# definition means the role's historical default, spelled out in
# ``container.load_data_for_agent``.
DATA_SOURCES: tuple[str, ...] = (
    "sample.path",
    "sample.chunks",
    "sandbox.target",
    "sandbox.behavior",
    "sandbox.network",
    "sandbox.full",
)

# ``container.load_data_for_agent`` documents what an empty list means per
# role; it is deliberately not restated as a constant here, because the empty
# case runs the loader's own historical branch and a second copy of it would be
# a second answer to the same question.

_AGENT_KEY_RE = re.compile(AGENT_KEY_PATTERN)
_KEY_RULE = (
    "an agent name is lowercase, starts with a letter, and is at most 32 "
    "characters of letters, digits, '-' or '_'"
)


class ToolRef(BaseModel):
    """One tool source an agent definition asks for by name.

    ``kind="mcp"`` names an entry of ``mcp.servers``; ``name=None`` means that
    server's whole allow-listed set, and a name means one tool of it.
    ``kind="provider"`` means "the tools of this agent's static provider" and
    carries nothing else — the provider is already chosen by
    ``AgentDefinition.static_provider``, so naming it twice could disagree.

    ``kind="sandbox"`` is the one in-process tool source: the job's sandbox
    report, read through ``providers.sandbox_tools``. It carries nothing else
    for the same reason a provider reference does not — there is exactly one
    report per job and naming it twice could disagree.

    ``kind="agent"`` names another definition. Bound to an agent, it appears in
    that agent's toolbox as ``ask_<agent>``: a tool that hands the named agent a
    task, runs it under the same job, and returns its answer. It is a tool and
    nothing more, so the ask, the answer and everything the callee did on the
    way are in the ledger, the budget and the transcript like any other call
    (``agents.delegation``).
    """

    kind: Literal["mcp", "provider", "sandbox", "agent"]
    server: str | None = None
    name: str | None = None
    agent: str | None = None

    @model_serializer(mode="wrap")
    def _agent_only_when_named(self, handler: SerializerFunctionWrapHandler) -> Any:
        """Dump ``agent`` only on an agent reference.

        Every stored definition, every export and every pinned dump was
        written before the field existed; a reference of any other kind dumps
        exactly as it always did, so none of them reads as changed.
        """
        dumped = handler(self)
        if isinstance(dumped, dict) and self.kind != "agent":
            dumped.pop("agent", None)
        return dumped

    @model_validator(mode="after")
    def _shape_matches_the_kind(self) -> "ToolRef":
        if self.kind == "mcp":
            if not self.server:
                raise ValueError("an mcp tool reference needs a server")
            if self.agent is not None:
                raise ValueError("an mcp tool reference names no agent")
        elif self.kind == "agent":
            if not self.agent:
                raise ValueError("an agent tool reference needs an agent")
            if self.server is not None or self.name is not None:
                raise ValueError("an agent tool reference names no server and no tool")
        elif self.server is not None or self.name is not None or self.agent is not None:
            raise ValueError(f"a {self.kind} tool reference names no server, tool or agent")
        return self


def _without_the_empty_builtin_tool_list(entry: dict[str, Any]) -> dict[str, Any]:
    """Drop a stored built-in's ``tools: []`` so the seed's tool list applies.

    Every built-in definition used to seed an empty tool list, so that is what
    an operator database written before the tool sidecars existed holds — for
    a built-in the operator never edited as much as once. Left alone, the
    stored ``[]`` would win the merge below, the identity check would then see
    a definition that does not match its seed, and loading those settings would
    raise "built in; clone it to change it" over an edit nobody made. Worse, if
    the check were relaxed instead, the run would quietly go on with the four
    analysts holding no tools at all.

    This is ``MCPConfig._reseed_builtins`` for the definition map: an empty
    list is indistinguishable from "not set", so it is treated as not set. An
    operator who genuinely wants a tool-free run has the ``measurement``
    profile, which withholds the servers without touching the definitions.
    """
    if entry.get("tools") == []:
        return {k: v for k, v in entry.items() if k != "tools"}
    return entry


def _a_whole_number(value: Any) -> Any:
    """``value`` as the integer it names, or ``value`` itself.

    An environment variable and a JSON import both bring a number in as a
    string, and a bound that runs before pydantic's coercion has to read one
    the way pydantic would. Anything that is not a whole number comes back
    unchanged, so the caller still refuses it.
    """
    if isinstance(value, str):
        try:
            return int(value.strip())
        except ValueError:
            return value
    return value


def _is_a_budget(value: Any) -> bool:
    """Whether ``value`` is a step or time budget a definition may carry.

    A whole number of at least one. ``True`` is an ``int`` to Python and is not
    a budget to anybody, so it is refused by name.
    """
    return isinstance(value, int) and not isinstance(value, bool) and value >= 1


class AgentDefinition(BaseModel):
    """One agent, as configuration rather than as a class.

    ``prompt=None`` on a built-in role means the built-in prompt assembled from
    the agent's own providers (see ``agents.composition.builtin_prompt``), which
    is what keeps a clone honest: change the provider, keep the prompt null,
    and the middle of the prompt changes with it.

    The LLM is *not* here. It lives at ``llm.agents.<key>.*`` and nowhere else;
    two copies of one setting drift.
    """

    role: AnalystRole
    label: str = ""
    prompt: str | None = None
    tools: list[ToolRef] = Field(default_factory=list)
    static_provider: str | None = None
    enabled: bool = True
    # Which slices of the job this agent is handed as its input text. Empty
    # means the role's historical default, which is what every definition
    # written before stages existed relies on: the data an agent read used to
    # be a switch on its role, so a clone of the static analyst could not be
    # pointed at the sandbox behaviour log without also becoming a dynamic
    # analyst. Naming the sources makes that a two-word edit.
    data_sources: list[str] = Field(default_factory=list)
    # How long one loop of this agent may run and how many steps it may take.
    # ``None`` means the deployment-wide ``react_agent_timeout`` /
    # ``react_agent_max_steps``, by way of the deprecated per-agent override
    # maps. A budget is a property of the agent, not of the deployment: an
    # operator who clones the lead gets a definition that asks six specialists
    # and, without this, the default ten steps to do it in — the clone starves
    # and nothing in the card they edited said why.
    max_steps: Annotated[int, Field(ge=1)] | None = None
    timeout_seconds: Annotated[int, Field(ge=1)] | None = None

    @model_validator(mode="after")
    def _data_sources_are_known(self) -> "AgentDefinition":
        seen: set[str] = set()
        for source in self.data_sources:
            if source not in DATA_SOURCES:
                known = ", ".join(DATA_SOURCES)
                raise ValueError(f"unknown data source {source!r}. Available: {known}")
            if source in seen:
                raise ValueError(f"data source {source!r} is listed twice")
            seen.add(source)
        return self


class DebateOptions(BaseModel):
    """How hard one debate stage argues before it hands over.

    These were three global settings, which meant a profile with two debates
    had to run both of them the same way. They are per stage now; a stage that
    sets none inherits the global values it was seeded from, so an operator who
    never opens a stage card sees the behaviour they had.
    """

    max_rounds: Annotated[int, Field(ge=1)] = 3
    consensus_threshold: Annotated[float, Field(ge=0, le=1)] = 0.8
    sycophancy_check: bool = True


class StageDefinition(BaseModel):
    """One step of a team, in the order and on the condition an operator sets.

    A human analysis team is a sequence of dependent steps — triage, then
    static, then dynamic if it is worth detonating, then reversing, then the
    network and threat-intel pass, then correlation, then the report — and each
    step reads what the ones before it produced. A flat list of analysts could
    express none of that: every member saw the same input, ran at the same
    point, and ran always.

    ``kind`` says what the stage *is*, which is what the builder turns into
    nodes. ``when`` says whether it runs at all (see ``pipeline.conditions``);
    a stage whose condition is false is still part of the graph and still
    records a result, so the topology is a property of the configuration alone
    and never of the sample.

    A ``triage`` stage names no agent. It is the pipeline itself running the
    deterministic tools over the sample and writing each result to the
    evidence ledger before any analyst starts (``pipeline.triage_pack``), so
    the facts a model may or may not ask for exist either way.
    """

    key: Annotated[str, Field(pattern=SERVER_KEY_PATTERN)]
    label: str = ""
    kind: Literal["triage", "analysis", "debate", "verdict", "report"] = "analysis"
    agents: list[str] = Field(default_factory=list)
    depends_on: list[str] = Field(default_factory=list)
    when: str = ""
    mode: Literal["parallel", "sequential"] = "sequential"
    inject_upstream: Literal["none", "findings", "full"] = "findings"
    debate: DebateOptions | None = None
    builtin_tools: bool = True

    @model_validator(mode="after")
    def _condition_parses(self) -> "StageDefinition":
        problem = stage_condition_problem(self.key, self.when)
        if problem:
            raise ValueError(problem)
        return self


def stage_condition_problem(key: str, when: str) -> str:
    """Why stage ``key`` cannot carry ``when``, or an empty string when it can.

    The one sentence both the stage model and the team lint report, so the
    refusal on save and the finding in the editor are the same words.
    """
    from maljan.pipeline.conditions import validate_condition

    problems = validate_condition(when)
    return f"stage {key!r}: {problems[0]}" if problems else ""


@dataclass(frozen=True)
class TeamProblem:
    """One thing the settings model refuses about a team, and where it sits.

    ``stage`` and ``field`` locate it on the stage card it concerns; both are
    ``None`` for a rule about the team as a whole. ``message`` is the exact
    sentence the model raises, so a refusal on save and a finding in the
    editor cannot say different things.
    """

    message: str
    stage: str | None = None
    field: str | None = None
    code: str = ""

    def __post_init__(self) -> None:
        if self.code not in TEAM_RULE_CODES:
            raise ValueError(f"team rule code {self.code!r} is not declared in TEAM_RULE_CODES")


# Every code a team rule in this module reports. ``TeamProblem`` refuses one
# that is not here, and the lint's parity test requires a refused team for
# each, so a rule added to ``stage_list_problems`` or ``stage_member_problems``
# cannot reach save without also being proven to reach the editor.
TEAM_RULE_CODES: frozenset[str] = frozenset(
    {
        "no_stages",
        "duplicate_key",
        "self_dependency",
        "dangling_dependency",
        "later_dependency",
        "agent_in_two_stages",
        "no_agents",
        "triage_agents",
        "triage_key",
        "debate_upstream",
        "debate_handover",
        "verdict_count",
        "report_count",
        "report_not_last",
        "unknown_agent",
        "agent_role",
        "disabled_agent",
        "verdict_judge",
        "report_reporter",
        "debate_agents",
    }
)


# The stage that runs the deterministic tools before any analyst. One key
# everywhere, because the migration that gives stored profiles the stage and
# the seeds that ship with it have to agree on what to skip when it is there.
TRIAGE_STAGE_KEY = "triage_pack"


def triage_stage() -> StageDefinition:
    """The deterministic first step of a team, written once.

    No agents and no upstream: it runs the tools in ``src/maljan/tools`` over
    the sample and records what they said, and everything after it reads the
    ledger it wrote. It carries no condition of its own because the facts it
    establishes are the ones a condition further down is written against.
    """
    return StageDefinition(
        key=TRIAGE_STAGE_KEY,
        label="Triage pack",
        kind="triage",
        inject_upstream="none",
    )


def stages_from_analysts(
    analysts: list[str],
    *,
    parallel: bool = False,
    max_rounds: int = 3,
    consensus_threshold: float = 0.8,
    triage: bool = True,
) -> list[StageDefinition]:
    """The stage form of a profile that was written as a list of analysts.

    This is the whole of the compatibility story: every profile in every
    operator database predates stages, and the pipeline they describe is one
    analysis stage, one debate, one verdict and one report. Written once here
    so the settings model, the alembic migration and the tests cannot each
    invent a slightly different translation.

    ``triage`` puts the deterministic triage pack in front of the four. It is
    on for every team but the measurement baseline, whose whole purpose is to
    show what the models do with nothing established for them.
    """
    head = [triage_stage()] if triage else []
    return [
        *head,
        StageDefinition(
            key="analysis",
            label="Analysis",
            kind="analysis",
            agents=list(analysts),
            mode="parallel" if parallel else "sequential",
            inject_upstream="none",
        ),
        StageDefinition(
            key="debate",
            label="Debate",
            kind="debate",
            depends_on=["analysis"],
            inject_upstream="none",
            debate=DebateOptions(
                max_rounds=max_rounds,
                consensus_threshold=consensus_threshold,
            ),
        ),
        StageDefinition(
            key="verdict",
            label="Verdict",
            kind="verdict",
            agents=[JUDGE_AGENT_KEY],
            depends_on=["debate"],
            inject_upstream="none",
        ),
        StageDefinition(
            key="report",
            label="Report",
            kind="report",
            agents=[REPORTER_AGENT_KEY],
            depends_on=["verdict"],
            inject_upstream="none",
        ),
    ]


# What re-derivation is allowed to overwrite, and therefore the only two
# fields a derived stage list may differ from the plain conversion in: the
# analysis stage's run mode comes from ``llm.parallel_analysts`` and the debate
# stage's options from the negotiation settings. Everything else about a stage
# is the operator's.
_DERIVED_FIELDS: tuple[str, ...] = ("mode", "debate")


def _is_a_fixed_node_name(key: str) -> bool:
    """Whether ``key`` would collide with a node the graph names itself.

    A triage stage's node is its key; the judge, the report, the debate's two
    nodes, every ``<agent>_analyst`` and every ``<stage>__join`` are names the
    builder issues, and a stage that took one would break the build instead
    of being refused at save time.
    """
    from maljan.pipeline.topology import (
        JOIN_SUFFIX,
        JUDGE_NODE,
        NEGOTIATION_NODE,
        REPORT_NODE,
        REVISION_NODE,
    )

    return (
        key in (JUDGE_NODE, REPORT_NODE, NEGOTIATION_NODE, REVISION_NODE)
        or key.endswith("_analyst")
        or key.endswith(JOIN_SUFFIX)
        or key.endswith(f"__{NEGOTIATION_NODE}")
        or key.endswith(f"__{REVISION_NODE}")
    )


def has_triage_stage(stages: list["StageDefinition"]) -> bool:
    """Whether a team runs the triage pack. Read off the kind, never the key."""
    return any(stage.kind == "triage" for stage in stages)


def stages_are_derived(analysts: list[str], stages: list["StageDefinition"]) -> bool:
    """Whether ``stages`` is still the plain conversion of ``analysts``.

    With or without the triage pack in front: whether a team runs the pack is
    the one thing about a derived team that is not read from the two global
    keys, so the check accepts both forms and re-derivation keeps whichever
    the document had.

    The ``derived_from_analysts`` marker travels in the stored document, so it
    arrives over the wire from an import, a script's PATCH, or a hand-edited
    export. Trusting it on its own means a team with the marker and four stages
    an operator wrote by hand has those stages silently replaced on the next
    load. The marker says "nobody has touched these"; this is what checks it.

    The two fields re-derivation itself sets cannot take part in the check: the
    stored ones were written from whatever the globals said at the time, and
    disagreeing with today's globals is the very thing re-derivation is for. A
    document that keeps the marker and changes *only* a debate stage's options
    is therefore still overwritten — the console clears the marker on every
    stage edit, so that combination only arises from an export edited by hand.
    """
    if not analysts:
        return False
    expected = stages_from_analysts(list(analysts), triage=has_triage_stage(stages))
    if len(expected) != len(stages):
        return False
    for want, have in zip(expected, stages, strict=True):
        left = want.model_dump(exclude=set(_DERIVED_FIELDS))
        right = have.model_dump(exclude=set(_DERIVED_FIELDS))
        if left != right:
            return False
    return True


def analysts_become_stages(data: Any) -> Any:
    """A profile document written as a list of analysts, read as the four stages.

    ``ProfileDefinition`` applies it before it validates, and the team lint
    applies it before it reads, so both see the stages a stored analyst list
    stands for.
    """
    if not isinstance(data, dict):
        return data
    if data.get("stages"):
        return data
    analysts = data.get("analysts")
    if not analysts:
        return data
    return {
        **data,
        "stages": [s.model_dump() for s in stages_from_analysts(list(analysts))],
        "derived_from_analysts": True,
    }


class ProfileDefinition(BaseModel):
    """A team, as ordered dependent stages.

    The three ``exclude``/override fields are what make a tool-free baseline
    possible without cloning every definition: a profile says which servers its
    members may not reach, whether the in-process sandbox tools are withheld,
    and which static provider to force. ``resolve_agent`` applies them, so the
    same definition runs with tools under one profile and without them under
    another — and the two can never drift apart, because there is only one
    definition.

    ``static_provider=None`` means "leave each definition's own choice alone";
    a value overrides it for every member of the profile.

    ``exclude_servers`` holds server keys, or the single entry ``"*"`` meaning
    every server there is — including whatever an operator adds later, which
    is the only form a tool-free baseline can safely take.

    ``analysts`` is what a profile used to be and is kept so a stored document
    still loads, still exports, and can still be read back by the migration's
    downgrade. A profile that carries it and no ``stages`` is converted below.
    """

    label: str = ""
    stages: list[StageDefinition] = Field(default_factory=list)
    analysts: list[str] = Field(default_factory=list)
    exclude_servers: list[str] = Field(default_factory=list)
    exclude_sandbox_tools: bool = False
    static_provider: str | None = None
    # True when ``stages`` was derived from ``analysts`` rather than written.
    # ``Settings`` re-derives those stages once the whole document is loaded,
    # because the conversion needs ``llm.parallel_analysts`` and the
    # negotiation settings and a profile cannot see either from in here.
    #
    # Stored rather than dropped, because the alembic revision that writes
    # stages into an operator's database sets it: without it, a team the
    # operator never opened would freeze whatever those two global keys said
    # on migration day, and an operator who later moved from a hosted API back
    # to the single-slot local model would keep running analysts in parallel.
    # The console clears it on any stage edit — from that point the stages are
    # the operator's, not a derivation of the analyst list.
    derived_from_analysts: bool = False

    @model_validator(mode="before")
    @classmethod
    def _analysts_become_stages(cls, data: Any) -> Any:
        """A profile written as a list of analysts is read as the four stages."""
        return analysts_become_stages(data)

    @model_validator(mode="after")
    def _stages_are_a_pipeline(self) -> "ProfileDefinition":
        """Everything about the stage list that needs only the stage list."""
        if not self.stages:
            raise ValueError("a profile needs at least one stage")

        # The marker is a stored field, so it arrives from an import, a
        # script's PATCH or a hand-edited export as readily as from the
        # migration that sets it. A team whose stages are no longer the plain
        # conversion of its analyst list has been written, whatever the
        # document claims, and re-deriving it would throw that writing away.
        if self.derived_from_analysts and not stages_are_derived(self.analysts, self.stages):
            self.derived_from_analysts = False

        problems = stage_list_problems(self.stages)
        if problems:
            raise ValueError(problems[0].message)
        return self

    def entry_node_count(self, stage: "StageDefinition") -> int:
        """How many graph nodes a dependency of ``stage`` has to point at."""
        return _entry_node_count(stage)

    def debate_handover_error(self, stage: "StageDefinition") -> str:
        """Why ``stage`` cannot hand over, or an empty string when it can."""
        return _debate_handover_error(self.stages, stage)

    def _reachable(self, key: str) -> set[str]:
        """Every stage ``key`` transitively depends on."""
        return _upstream_of(self.stages, key)

    def stage(self, key: str) -> StageDefinition | None:
        for candidate in self.stages:
            if candidate.key == key:
                return candidate
        return None

    @property
    def analysis_agents(self) -> list[str]:
        """Every agent of every analysis stage, in stage order.

        What ``analysts`` used to mean, computed rather than stored, so the
        roster the worker announces and the roster the graph runs cannot
        disagree once a profile is edited as stages.
        """
        out: list[str] = []
        for stage in self.stages:
            if stage.kind == "analysis":
                out.extend(stage.agents)
        return out


def _entry_node_count(stage: StageDefinition) -> int:
    """How many graph nodes a dependency of ``stage`` has to point at.

    One for every stage but a parallel analysis stage, which starts at all
    of its agents at once. ``pipeline.topology`` derives the same number
    from the same rule; it is restated here because the check below has to
    run before a graph is ever built.
    """
    if stage.kind == "analysis" and stage.mode == "parallel":
        return len(stage.agents)
    return 1


def _debate_handover_error(stages: list[StageDefinition], stage: StageDefinition) -> str:
    """Why debate ``stage`` cannot hand over, or an empty string when it can.

    A debate leaves through a conditional edge, and a conditional edge has
    exactly one destination per branch. A debate that feeds two stages — or
    one parallel analysis stage with two agents, which is two nodes — has
    no single destination for the branch that stops arguing.

    This is checked when the team is saved rather than only when the graph
    is built. The builder still refuses it, but by then the sample has been
    uploaded and detonated and every job under that team fails; an operator
    has to be told while they are still editing.
    """
    return _handover_message(stage, [c for c in stages if stage.key in c.depends_on])


def _handover_message(stage: StageDefinition, fed_by: list[StageDefinition]) -> str:
    """The hand-over refusal for debate ``stage`` feeding ``fed_by``, or ``""``."""
    heads = sum(_entry_node_count(candidate) for candidate in fed_by)
    fed = [candidate.key for candidate in fed_by]
    if heads <= 1:
        return ""
    return (
        f"stage {stage.key!r} is a debate that hands over to {heads} nodes "
        f"({', '.join(fed)}); a debate hands over to exactly one stage, and not "
        "to a parallel analysis stage with more than one agent"
    )


def _upstream_of(stages: list[StageDefinition], key: str) -> set[str]:
    """Every stage ``key`` transitively depends on."""
    by_key = {s.key: s for s in stages}
    out: set[str] = set()
    pending = list(by_key[key].depends_on) if key in by_key else []
    while pending:
        current = pending.pop()
        if current in out or current not in by_key:
            continue
        out.add(current)
        pending.extend(by_key[current].depends_on)
    return out


def _dependents_by_key(stages: list[StageDefinition]) -> dict[str, list[StageDefinition]]:
    """Each key's dependents in stage order, each listed once however often it names the key."""
    out: dict[str, list[StageDefinition]] = {}
    for candidate in stages:
        for key in dict.fromkeys(candidate.depends_on):
            out.setdefault(key, []).append(candidate)
    return out


def _keys_after_an_analysis(stages: list[StageDefinition]) -> set[str]:
    """Every key with an analysis stage among what it transitively depends on.

    ``_upstream_of`` asked once per stage, answered for all of them in one
    breadth-first pass from the analysis stages along the reversed edges, so a
    team of any size costs its stages plus its edges. The edges are read the
    way ``_upstream_of`` reads them: a repeated key's dependencies are the
    last declaration's, and a key counts as analysis if any stage keyed so is.
    """
    by_key = {s.key: s for s in stages}
    reverse: dict[str, list[str]] = {}
    for key, stage in by_key.items():
        for dependency in stage.depends_on:
            if dependency in by_key:
                reverse.setdefault(dependency, []).append(key)
    reached: set[str] = set()
    pending = [
        dependent
        for key in {s.key for s in stages if s.kind == "analysis"}
        for dependent in reverse.get(key, [])
    ]
    while pending:
        current = pending.pop()
        if current in reached:
            continue
        reached.add(current)
        pending.extend(reverse.get(current, []))
    return reached


def stage_list_problems(stages: list[StageDefinition]) -> list[TeamProblem]:
    """Everything the settings model refuses about a stage list on its own.

    ``ProfileDefinition`` raises the first of these; the team lint reports
    all of them. One list in one order, so the refusal on save is always the
    first finding the editor shows and never a sentence it did not.
    """
    problems: list[TeamProblem] = []
    if not stages:
        return [TeamProblem("a profile needs at least one stage", code="no_stages")]

    seen: set[str] = set()
    for stage in stages:
        if stage.key in seen:
            problems.append(
                TeamProblem(
                    f"stage {stage.key!r} is declared twice", stage.key, "key", "duplicate_key"
                )
            )
        seen.add(stage.key)

    # ``depends_on`` may only name a stage declared earlier. That is a
    # stronger rule than "no cycles" and a much kinder one: it makes the
    # written order the run order, so a reader of the profile card reads
    # the pipeline top to bottom, and it makes a cycle unrepresentable
    # rather than merely detectable.
    earlier: set[str] = set()
    for stage in stages:
        for dependency in stage.depends_on:
            if dependency == stage.key:
                message, code = f"stage {stage.key!r} depends on itself", "self_dependency"
            elif dependency not in seen:
                message = f"stage {stage.key!r} depends on unknown stage {dependency!r}"
                code = "dangling_dependency"
            elif dependency not in earlier:
                message = (
                    f"stage {stage.key!r} depends on {dependency!r}, which is declared "
                    "after it; a stage may only depend on an earlier stage"
                )
                code = "later_dependency"
            else:
                continue
            problems.append(TeamProblem(message, stage.key, "depends_on", code))
        earlier.add(stage.key)

    # Only analysis stages: an agent's node is named after the agent
    # (``<agent>_analyst``), so two analysis stages naming one agent would
    # collide in the graph. The verdict and report nodes are named after
    # the stage kind, and the judge that runs the verdict is *expected* to
    # be named again wherever the operator went wrong — reporting that as
    # a name collision would hide the real error, which is the role.
    agent_owner: dict[str, str] = {}
    for stage in stages:
        if stage.kind != "analysis":
            continue
        for agent in stage.agents:
            previous = agent_owner.get(agent)
            if previous is not None:
                problems.append(
                    TeamProblem(
                        f"{agent!r} is in stage {previous!r} and again in {stage.key!r}; "
                        "an agent belongs to one stage",
                        stage.key,
                        "agents",
                        "agent_in_two_stages",
                    )
                )
            else:
                agent_owner[agent] = stage.key

    after_analysis = _keys_after_an_analysis(stages)
    for stage in stages:
        if stage.kind == "analysis" and not stage.agents:
            problems.append(
                TeamProblem(
                    f"stage {stage.key!r} is an analysis stage with no agent",
                    stage.key,
                    "agents",
                    "no_agents",
                )
            )
        if stage.kind == "triage" and stage.agents:
            problems.append(
                TeamProblem(
                    f"stage {stage.key!r} is a triage stage and names an agent; the "
                    "pipeline runs it",
                    stage.key,
                    "agents",
                    "triage_agents",
                )
            )
        if stage.kind == "triage" and _is_a_fixed_node_name(stage.key):
            problems.append(
                TeamProblem(
                    f"stage {stage.key!r} is a triage stage keyed like a graph node the "
                    "pipeline names itself; choose another key",
                    stage.key,
                    "key",
                    "triage_key",
                )
            )
        if stage.kind == "debate":
            if stage.key not in after_analysis:
                problems.append(
                    TeamProblem(
                        f"stage {stage.key!r} debates nothing: it needs an analysis stage "
                        "upstream of it",
                        stage.key,
                        "depends_on",
                        "debate_upstream",
                    )
                )

    dependents = _dependents_by_key(stages)
    for stage in stages:
        if stage.kind != "debate":
            continue
        handover = _handover_message(stage, dependents.get(stage.key, []))
        if handover:
            problems.append(TeamProblem(handover, stage.key, "depends_on", "debate_handover"))

    verdicts = [s.key for s in stages if s.kind == "verdict"]
    if len(verdicts) != 1:
        found = ", ".join(verdicts) or "none"
        problems.append(
            TeamProblem(
                f"a profile needs exactly one verdict stage; found {found}",
                verdicts[1] if len(verdicts) > 1 else None,
                "kind" if len(verdicts) > 1 else None,
                "verdict_count",
            )
        )
    reports = [s.key for s in stages if s.kind == "report"]
    if len(reports) > 1:
        problems.append(
            TeamProblem(
                f"a profile has at most one report stage; found {', '.join(reports)}",
                reports[1],
                "kind",
                "report_count",
            )
        )
    if reports and stages[-1].kind != "report":
        problems.append(
            TeamProblem(
                "the report stage is the last stage of a profile",
                reports[0],
                "kind",
                "report_not_last",
            )
        )
    return problems


def _builtin_definitions() -> dict[str, AgentDefinition]:
    """The agents the pipeline has always had, as settings.

    The prompt and the static provider stay neutral — a null prompt and a null
    provider are what "the built-in behaviour" *means*. The tool lists are not
    neutral any more: every analysis capability the pipeline used to run
    in-process is now a tool, and an agent that is not given the tools cannot
    reach any of it. Each definition therefore names the sidecars its role
    actually reads, and ``measurement`` below is the profile that takes them
    all away again.

    ``dynamic`` gets ``ToolRef(kind="sandbox")`` rather than a server: the
    job's sandbox report is already in this process, so the tools over it are
    closures, not a transport.

    The judge and the reporter are here so that their LLM and their tool
    servers have the same editing surface as the analysts. Neither can be an
    analyst: a profile names them from its verdict and report stages.
    """
    return {
        "static": AgentDefinition(
            role="static",
            label="Static analyst",
            tools=[
                ToolRef(kind="mcp", server="analysis"),
                ToolRef(kind="mcp", server="knowledge"),
                ToolRef(kind="mcp", server=virustotal.SERVER_KEY),
            ],
        ),
        "dynamic": AgentDefinition(
            role="dynamic",
            label="Dynamic analyst",
            tools=[ToolRef(kind="sandbox"), ToolRef(kind="mcp", server="knowledge")],
        ),
        "network": AgentDefinition(
            role="network",
            label="Network analyst",
            tools=[
                ToolRef(kind="mcp", server="network"),
                ToolRef(kind="mcp", server="knowledge"),
                ToolRef(kind="mcp", server=virustotal.SERVER_KEY),
            ],
        ),
        JUDGE_AGENT_KEY: AgentDefinition(
            role="judge",
            label="Judge",
            tools=[
                ToolRef(kind="mcp", server="knowledge"),
                ToolRef(kind="mcp", server=virustotal.SERVER_KEY),
            ],
        ),
        REPORTER_AGENT_KEY: AgentDefinition(
            role="report",
            label="Reporter",
            tools=[],
        ),
        # The generic agents the seeded teams below are built from. A generic
        # agent is a definition and a prompt: it has no class of its own, so
        # what it does is entirely what its prompt says and which tools it is
        # given. Seeded rather than left as an example in the documentation,
        # because a team an operator can only run after transcribing three
        # prompts is a team nobody runs.
        "triage": AgentDefinition(
            role="generic",
            label="Triage",
            prompt=TRIAGE_PROMPT,
            tools=[
                ToolRef(kind="mcp", server="analysis"),
                ToolRef(kind="mcp", server="knowledge"),
                ToolRef(kind="mcp", server=virustotal.SERVER_KEY),
            ],
        ),
        "android_static": AgentDefinition(
            role="generic",
            label="Android static analyst",
            prompt=ANDROID_STATIC_PROMPT,
            tools=[
                ToolRef(kind="mcp", server="analysis"),
                ToolRef(kind="mcp", server="knowledge"),
                ToolRef(kind="mcp", server=virustotal.SERVER_KEY),
            ],
        ),
        "reverser": AgentDefinition(
            role="generic",
            label="Reverser",
            prompt=REVERSER_PROMPT,
            tools=[
                ToolRef(kind="provider"),
                ToolRef(kind="mcp", server="knowledge"),
                ToolRef(kind="mcp", server=virustotal.SERVER_KEY),
            ],
        ),
        # The lead analyst: its tools are the other analysts. It asks the
        # three the paper measured, the reverser for a function-level answer
        # and the triage agent for a second reading of the pack, and keeps
        # the knowledge server so it can check a technique id a specialist
        # cited before it repeats it.
        "lead": AgentDefinition(
            role="lead",
            label="Lead analyst",
            prompt=LEAD_PROMPT,
            # A lead spends its steps on asks and on reading what comes back,
            # and each ask is two of them — the turn that calls the tool and
            # the node that runs it. Six asks and the turns to weigh them is
            # forty, and at the default 300 s per ask 1800 s fits those six
            # with the lead's own turns around them; that is the number
            # ``delegation._asks_that_fit`` computes and the number the
            # ``ask_<key>`` tool's description gives the model. The
            # specialists' own budgets are their own and do not come out of
            # these.
            max_steps=40,
            timeout_seconds=1800,
            tools=[
                ToolRef(kind="agent", agent="static"),
                ToolRef(kind="agent", agent="dynamic"),
                ToolRef(kind="agent", agent="network"),
                ToolRef(kind="agent", agent="reverser"),
                ToolRef(kind="agent", agent="triage"),
                ToolRef(kind="mcp", server="knowledge"),
            ],
        ),
    }


def _builtin_profiles() -> dict[str, ProfileDefinition]:
    """The paper's architecture, named — written as the stages it always was.

    Four stages, because that is what the pipeline does: the analysts, the
    debate they hold, the verdict a judge draws from it and the report built
    from the verdict. The seeds are written as the analyst list they always
    were and converted by ``ProfileDefinition`` like any other stored profile,
    which is what keeps ``llm.parallel_analysts`` and the negotiation settings
    in charge of a profile nobody has opened: an operator who raises the round
    limit still raises it for the default profile.

    ``measurement`` is the same three analysts with every tool server taken
    away, every static provider forced to ``none`` and no triage pack in front
    of them: the honest baseline for "what does the ensemble contribute on its
    own". It is a profile rather than
    three cloned definitions because a clone would have to be kept in step with
    its original by hand, and the first time someone edited one and not the
    other the baseline would silently stop being the same agents.

    Its exclusion is ``["*"]`` rather than the four built-in keys. A fixed list
    would still hand the baseline any server an operator added afterwards, and
    the built-in identity check would refuse the edit that repaired it — so a
    profile whose whole purpose is a measurement claim would quietly stop being
    tool-free and could not be fixed in place.
    """
    paper_analysts = ["static", "dynamic", "network"]
    return {
        "default": ProfileDefinition(label="Default", analysts=list(paper_analysts)),
        # Written out without the triage pack, and still marked derived so the
        # two global keys keep applying to it: the baseline measures what the
        # ensemble does with nothing established for it, and a pack of facts
        # in every prompt would be the opposite of that.
        "measurement": ProfileDefinition(
            label="Measurement baseline",
            analysts=list(paper_analysts),
            stages=stages_from_analysts(list(paper_analysts), triage=False),
            derived_from_analysts=True,
            exclude_servers=[ALL_SERVERS],
            exclude_sandbox_tools=True,
            static_provider="none",
        ),
        "mobile": ProfileDefinition(label="Mobile", stages=_mobile_stages()),
        "deep_static": ProfileDefinition(label="Deep static", stages=_deep_static_stages()),
        "team_lead": ProfileDefinition(label="Team lead", stages=_team_lead_stages()),
    }


def _triage_stage() -> StageDefinition:
    """The first analyst of every seeded team that has one, written once.

    Triage reads nothing upstream because nothing upstream has concluded
    anything: the pack before it is facts, not findings, and this is the step
    that decides what the rest of the team should look at. A stage that was
    handed conclusions would be deciding under their influence.
    """
    return StageDefinition(
        key="triage",
        label="Triage",
        kind="analysis",
        agents=["triage"],
        inject_upstream="none",
    )


def _mobile_stages() -> list[StageDefinition]:
    """A team for a mobile sample: triage, the Android pass, detonation, verdict.

    The Android stage carries a condition rather than a platform check inside
    an agent, which is the whole point of a staged team — on a PE the stage is
    still in the graph, still declines, and still says why, so the console can
    show an operator that the team was applied and what it chose not to do.

    The dynamic stage is the built-in one: whichever sandbox is configured has
    already been asked for the options this sample's format needs, so nothing
    about detonating an APK belongs in the team definition.
    """
    return [
        triage_stage(),
        _triage_stage(),
        StageDefinition(
            key="android_static",
            label="Android static",
            kind="analysis",
            agents=["android_static"],
            depends_on=["triage"],
            when='file_type in ("apk", "dex")',
            inject_upstream="findings",
        ),
        StageDefinition(
            key="dynamic",
            label="Detonation",
            kind="analysis",
            agents=["dynamic"],
            depends_on=["android_static"],
            when="has_sandbox_report",
            inject_upstream="findings",
        ),
        StageDefinition(
            key="debate",
            label="Debate",
            kind="debate",
            depends_on=["dynamic"],
            inject_upstream="none",
        ),
        StageDefinition(
            key="verdict",
            label="Verdict",
            kind="verdict",
            agents=[JUDGE_AGENT_KEY],
            depends_on=["debate"],
            inject_upstream="none",
        ),
        StageDefinition(
            key="report",
            label="Report",
            kind="report",
            agents=[REPORTER_AGENT_KEY],
            depends_on=["verdict"],
            inject_upstream="none",
        ),
    ]


def _deep_static_stages() -> list[StageDefinition]:
    """A team that reads the code: triage, static, reversing, network.

    The reversing stage is the one that makes this team worth having. It runs
    after the static stage and is handed its findings, so its prompt can ask
    for each of them to be confirmed or refuted at function level rather than
    for another pass over the same imports. It takes the tools of whichever
    static provider is configured — Ghidra, r2 or neither — because a team
    should not have to name the decompiler an operator happens to run.
    """
    return [
        triage_stage(),
        _triage_stage(),
        StageDefinition(
            key="static",
            label="Static",
            kind="analysis",
            agents=["static"],
            depends_on=["triage"],
            inject_upstream="findings",
        ),
        StageDefinition(
            key="reversing",
            label="Reversing",
            kind="analysis",
            agents=["reverser"],
            depends_on=["static"],
            inject_upstream="findings",
        ),
        StageDefinition(
            key="network",
            label="Network",
            kind="analysis",
            agents=["network"],
            depends_on=["reversing"],
            when="has_pcap or has_sandbox_report",
            inject_upstream="findings",
        ),
        StageDefinition(
            key="debate",
            label="Debate",
            kind="debate",
            depends_on=["network"],
            inject_upstream="none",
        ),
        StageDefinition(
            key="verdict",
            label="Verdict",
            kind="verdict",
            agents=[JUDGE_AGENT_KEY],
            depends_on=["debate"],
            inject_upstream="none",
        ),
        StageDefinition(
            key="report",
            label="Report",
            kind="report",
            agents=[REPORTER_AGENT_KEY],
            depends_on=["verdict"],
            inject_upstream="none",
        ),
    ]


def _team_lead_stages() -> list[StageDefinition]:
    """A team led by one agent: the pack, the lead, the verdict.

    The lead is the only analyst the stage list names. The specialists it
    asks are its tools, not stages: which of them run, in what order and how
    often is the lead's decision on this sample, which is the point of having
    a lead rather than a fixed sequence. What they did is still in the ledger
    under their own keys, and the verdict reads the lead's report with their
    evidence cited in it.

    No debate stage, and that is the whole difference from the other seeded
    teams. A debate is agents arguing with each other, and this team has one
    analyst: the stage would hand the lead its own report, ask it to revise
    against nobody, and cost a second full loop — with the asks that loop
    makes — for a round that cannot change a position. The lead's own asks
    are where the disagreement happens here; a specialist that contradicts
    the lead does it in the answer the lead reads, not in a round afterwards.
    """
    return [
        triage_stage(),
        StageDefinition(
            key="lead",
            label="Lead",
            kind="analysis",
            agents=["lead"],
            inject_upstream="none",
        ),
        StageDefinition(
            key="verdict",
            label="Verdict",
            kind="verdict",
            agents=[JUDGE_AGENT_KEY],
            depends_on=["lead"],
            inject_upstream="none",
        ),
        StageDefinition(
            key="report",
            label="Report",
            kind="report",
            agents=[REPORTER_AGENT_KEY],
            depends_on=["verdict"],
            inject_upstream="none",
        ),
    ]


def agent_reference_problems(
    key: str, definition: AgentDefinition, definitions: Mapping[str, AgentDefinition]
) -> list[str]:
    """Everything wrong with ``definition``'s agent references, as sentences.

    Shared by the settings model and the API's definition editor so the two
    refuse the same things in the same words. A reference to an agent that is
    not there, to the definition itself, to the judge or the reporter, and a
    reference on the judge or the reporter are all refused here; whether the
    named agent is enabled is a runtime question, answered by the ask itself,
    because a built-in profile may keep a disabled member while another
    profile runs.
    """
    problems: list[str] = []
    refs = [ref for ref in definition.tools if ref.kind == "agent"]
    if refs and definition.role in ("judge", "report"):
        problems.append(f"a {definition.role} definition cannot ask other agents")
    seen: set[str] = set()
    for ref in refs:
        callee = str(ref.agent)
        if callee in seen:
            problems.append(f"agent {callee!r} is referenced twice")
            continue
        seen.add(callee)
        if callee == key:
            problems.append("an agent cannot ask itself")
            continue
        target = definitions.get(callee)
        if target is None:
            available = ", ".join(sorted(definitions)) or "(none)"
            problems.append(f"unknown agent {callee!r} in a tool reference. Available: {available}")
            continue
        if target.role in ("judge", "report"):
            problems.append(f"{callee!r} has role {target.role!r} and cannot be asked")
    return problems


def convert_builtin_profile_document(name: str, entry: Any) -> Any:
    """A stored built-in profile, read with the pack choice its seed made.

    ``ProfileDefinition`` converts a bare analyst list with the triage pack
    in front, because every team gets the pack unless it says otherwise. The
    one seeded team that says otherwise is the measurement baseline, and it
    cannot say so from inside a document that carries no stages. So a stored
    built-in without stages is converted here, by name, with the choice its
    seed made — and the identity check then compares like with like.

    A stored built-in that carries derived stages is brought to the same
    choice: a ``default`` written before the pack existed holds four stages
    and the mark, and re-deriving it with the pack is what its seed would
    have produced. Only a plain derivation is touched; stages someone wrote
    are left as written for the identity check to judge.
    """
    if not isinstance(entry, dict):
        return entry
    seed = _builtin_profiles().get(name)
    analysts = entry.get("analysts")
    if seed is None or not isinstance(analysts, list) or not analysts:
        return entry
    wanted = has_triage_stage(seed.stages)
    stored = entry.get("stages")
    if stored:
        if not entry.get("derived_from_analysts"):
            return entry
        try:
            typed = [StageDefinition.model_validate(stage) for stage in stored]
        except ValueError:
            return entry
        if has_triage_stage(typed) == wanted or not stages_are_derived(list(analysts), typed):
            return entry
    return {
        **entry,
        "stages": [
            stage.model_dump() for stage in stages_from_analysts(list(analysts), triage=wanted)
        ],
        "derived_from_analysts": True,
    }


def _profile_stage_identity(stages: Any) -> Any:
    """A built-in profile's stages with the two editable fields taken out.

    Used only by the identity check: ``debate`` options and ``builtin_tools``
    are what an operator may tune on a seeded profile, so they are removed from
    both sides of the comparison rather than compared and forgiven afterwards.
    """
    if not isinstance(stages, list):
        return stages
    return [
        {k: v for k, v in stage.items() if k not in ("debate", "builtin_tools")}
        if isinstance(stage, dict)
        else stage
        for stage in stages
    ]


class AgentsConfig(BaseModel):
    """The agent definitions, the profiles, and which profile is active.

    ``delegation_depth`` bounds how far one ask may nest: a stage's agent asking
    a specialist is depth 1, that specialist asking another is depth 2, and an
    ask that would go deeper is refused with a tool error the model reads. It
    bounds the nesting, never the number of asks.

    ``delegation_steps`` and ``delegation_timeout_seconds`` are what one ask
    gets. They are the delegation's own budget, not a share of the caller's:
    a callee derived from what its caller had left ran out of steps before it
    had made a tool call — the live proof watched a static specialist die at a
    recursion limit of five, and every later ask refused with "0 s and 3 steps
    remain". An ask is bounded by the caller's remaining wall clock and by
    nothing else, because the wall clock is the one thing the two really
    share: the ask runs inside the caller's own timeout.
    """

    profile: str = "default"
    profiles: dict[str, ProfileDefinition] = Field(default_factory=_builtin_profiles)
    definitions: dict[str, AgentDefinition] = Field(default_factory=_builtin_definitions)
    delegation_depth: Annotated[int, Field(ge=1)] = 2
    # Twelve steps is about five tool rounds and an answer — what a specialist
    # needs to open the sample, look at two or three things and write a claim.
    delegation_steps: Annotated[int, Field(ge=2)] = 12
    # Five minutes per ask on a local model: a specialist with tools spends
    # most of it waiting for its own tool calls, and a lead with a long stage
    # timeout can still make several asks inside one loop.
    delegation_timeout_seconds: Annotated[int, Field(ge=1)] = 300

    @model_validator(mode="before")
    @classmethod
    def _drop_a_budget_the_field_would_refuse(cls, data: Any) -> Any:
        """A stored budget outside the field's bound is read as absent.

        The two deprecated override maps are plain ``dict[str, int]`` and
        accept a zero or a negative through the settings PATCH, so a store
        written before a budget belonged to a definition can hold one; the
        migration that moves them leaves such a value where it is, and an
        operator can still write one into the map by hand. Refusing the whole
        document over it would take the API and the worker down for every
        settings read — a build that raises is a deployment that cannot serve
        — so the agent falls back to the deployment's budget and the reason
        is logged once, where the fallback happens.
        """
        if not isinstance(data, dict):
            return data
        definitions = data.get("definitions")
        if not isinstance(definitions, dict):
            return data
        cleaned: dict[Any, Any] = {}
        for key, entry in definitions.items():
            if not isinstance(entry, dict):
                cleaned[key] = entry
                continue
            kept = dict(entry)
            for field in ("max_steps", "timeout_seconds"):
                if field in kept and kept[field] is not None and not _is_a_budget(kept[field]):
                    logger.warning(
                        "Agent %r has a stored %s of %r, which is not a whole number of at "
                        "least one; the deployment's own budget is used instead.",
                        key,
                        field,
                        kept[field],
                    )
                    kept[field] = None
            cleaned[key] = kept
        return {**data, "definitions": cleaned}

    @model_validator(mode="before")
    @classmethod
    def _merge_builtin_definition_defaults(cls, data: Any) -> Any:
        """Fill in the seed's values for whatever a built-in override left out.

        An operator overriding ``network`` to flip ``enabled`` writes
        ``{"role": "network", "enabled": False}``, not a full copy of the
        seed. Without this, the fields they did not mention would take
        ``AgentDefinition``'s own bare defaults (``label=""`` and so on)
        instead of the seed's, and the identity check below — which must
        compare every field but ``enabled`` — would see a mismatch on
        ``label`` alone and refuse an edit the operator never made. Merging
        here, before typed validation, is what lets that check compare
        without also having to guess which fields were "really" sent.
        """
        if not isinstance(data, dict):
            return data
        definitions = data.get("definitions")
        if not isinstance(definitions, dict):
            return data
        seeds = _builtin_definitions()
        merged = {}
        for key, entry in definitions.items():
            seed = seeds.get(key)
            if seed is not None and isinstance(entry, dict):
                entry = _without_the_empty_builtin_tool_list(entry)
                merged[key] = {**seed.model_dump(), **entry}
            else:
                merged[key] = entry
        return {**data, "definitions": merged}

    @model_validator(mode="before")
    @classmethod
    def _convert_builtin_profile_lists(cls, data: Any) -> Any:
        """Read a stored built-in profile's analyst list with its seed's shape.

        See ``convert_builtin_profile_document``: the measurement baseline is
        the seeded team without the triage pack, and a document that still
        holds only its analyst list has to be converted the way its seed was
        or the identity check below refuses a team nobody edited.
        """
        if not isinstance(data, dict):
            return data
        profiles = data.get("profiles")
        if not isinstance(profiles, dict):
            return data
        converted = {
            name: convert_builtin_profile_document(str(name), entry)
            for name, entry in profiles.items()
        }
        return {**data, "profiles": converted}

    @model_validator(mode="before")
    @classmethod
    def _rename_keys_a_seed_has_taken(cls, data: Any) -> Any:
        """Move an operator's own agent or team off a key that is now built in.

        Runs before anything else, because the identity check below refuses a
        stored built-in that does not match its seed and it refuses it on every
        construction — including the one the worker makes at boot. A key that
        was legal when it was saved must not become a service that will not
        start. See ``core.agent_key_migration``; ``Settings`` runs the same
        pass over the whole document so the references outside this model are
        rewritten too, and running it twice changes nothing.

        Declared below the merge above deliberately: pydantic runs ``before``
        validators in reverse declaration order, and the rename has to see the
        stored entry as the operator wrote it. Merged first, an operator's own
        `reverser` would be renamed carrying the seed's tools and label.
        """
        from maljan.core.agent_key_migration import rename_colliding_agent_keys

        if not isinstance(data, dict):
            return data
        renamed, _ = rename_colliding_agent_keys({"agents": data})
        return renamed["agents"]

    @model_validator(mode="after")
    def _seed_and_check(self) -> "AgentsConfig":
        """Re-seed the built-ins, then apply every rule that needs only this model.

        Seeding is ``MCPConfig._reseed_builtins`` again: a stored map holds only
        what the operator added or disabled, so a missing built-in comes back
        and a present one is kept. What "kept" may differ by is the next rule.
        """
        for key, default_definition in _builtin_definitions().items():
            self.definitions.setdefault(key, default_definition)
        for key, default_profile in _builtin_profiles().items():
            self.profiles.setdefault(key, default_profile)

        for key in self.definitions:
            if not _AGENT_KEY_RE.match(str(key)):
                raise ValueError(f"{key!r}: {_KEY_RULE}")
        for key in self.profiles:
            if not _AGENT_KEY_RE.match(str(key)):
                raise ValueError(f"{key!r}: {_KEY_RULE}")

        # A built-in is compared field by field against its seed. ``enabled``
        # is the one field excluded, and only for an analyst — that is the
        # operator's one lever — not for the judge, which the skeleton always
        # runs. Every other field, ``label`` included, must match the seed
        # exactly; a field the operator did not mention already reads as the
        # seed's own value, courtesy of ``_merge_builtin_definition_defaults``.
        for key, seed in _builtin_definitions().items():
            current = self.definitions[key].model_dump()
            expected = seed.model_dump()
            if key != "judge":
                current.pop("enabled", None)
                expected.pop("enabled", None)
            if current != expected:
                raise ValueError(f"{key!r} is built in; clone it to change it")
        for key in _builtin_profiles():
            if builtin_profile_changed(key, self.profiles[key]):
                raise ValueError(builtin_profile_message(key))

        for key, definition in self.definitions.items():
            # Spec §3.1: one judge, and it cannot be cloned. A second judge
            # definition is inert — no profile may name it — so the operator
            # would get a card that can never run anything.
            if definition.role == "judge" and key != JUDGE_AGENT_KEY:
                raise ValueError(f"{key!r}: only the built-in judge may have role judge")
            if definition.role == "report" and key != REPORTER_AGENT_KEY:
                raise ValueError(f"{key!r}: only the built-in reporter may have role report")
            if definition.role in PROMPT_ROLES and not (definition.prompt or "").strip():
                raise ValueError(f"{key!r}: a {definition.role} agent needs a prompt")
            has_provider_ref = any(ref.kind == "provider" for ref in definition.tools)
            if has_provider_ref and definition.role not in PROMPT_ROLES:
                raise ValueError(f"{key!r}: {PROVIDER_REFERENCE_RULE}")
            for problem in agent_reference_problems(key, definition, self.definitions):
                raise ValueError(f"{key!r}: {problem}")

        for name, profile in self.profiles.items():
            self._check_profile_members(name, profile)

        if self.profile not in self.profiles:
            available = ", ".join(sorted(self.profiles))
            raise ValueError(f"unknown profile {self.profile!r}. Available: {available}")
        return self

    def _check_profile_members(self, name: str, profile: ProfileDefinition) -> None:
        """Every rule about a profile's stages that needs the definition map.

        ``ProfileDefinition`` can check the shape of a pipeline but not who is
        in it: it cannot see the definitions. See ``stage_member_problems``.
        """
        exempt = name in BUILTIN_PROFILES and name != self.profile
        problems = stage_member_problems(name, profile.stages, self.definitions, exempt=exempt)
        if problems:
            raise ValueError(problems[0].message)


def _definition_field(definition: Any, field: str, default: Any = None) -> Any:
    """One field of a definition that may be a model or its stored dict."""
    if isinstance(definition, dict):
        return definition.get(field, default)
    return getattr(definition, field, default)


def stage_member_problems(
    name: str,
    stages: list[StageDefinition],
    definitions: Mapping[str, Any],
    *,
    exempt: bool = False,
) -> list[TeamProblem]:
    """Everything the settings model refuses about who is in a team's stages.

    ``definitions`` maps agent keys to ``AgentDefinition`` or to its stored
    dict, so the settings model, the API's save path and the team lint read
    the same rules off whichever form they hold.

    ``exempt`` lifts the enabled check. A built-in profile is exempt only
    while it is not the active profile: disabling a member of ``default`` is
    harmless as long as some other profile is actually running, but the moment
    ``default`` itself is selected the disabled member would be asked to run. A
    custom profile has no such exemption — its author chose every member,
    active or not.
    """
    problems: list[TeamProblem] = []

    def refuse(stage: StageDefinition, text: str, code: str) -> None:
        problems.append(
            TeamProblem(f"profile {name!r}, stage {stage.key!r}: {text}", stage.key, "agents", code)
        )

    for stage in stages:
        for agent in stage.agents:
            member = definitions.get(agent)
            if member is None:
                refuse(stage, f"unknown agent {agent!r}", "unknown_agent")
                continue
            role = _definition_field(member, "role")
            if stage.kind == "analysis" and role in ("judge", "report"):
                refuse(stage, f"{agent!r} has role {role!r} and cannot be an analyst", "agent_role")
            if not exempt and _definition_field(member, "enabled", True) is False:
                refuse(stage, f"{agent!r} is disabled", "disabled_agent")
        if stage.kind == "verdict":
            if len(stage.agents) != 1:
                refuse(stage, "a verdict stage names exactly one judge", "verdict_judge")
            else:
                judge = definitions.get(stage.agents[0])
                if judge is None or _definition_field(judge, "role") != "judge":
                    refuse(stage, f"{stage.agents[0]!r} is not a judge definition", "verdict_judge")
        if stage.kind == "report" and stage.agents != [REPORTER_AGENT_KEY]:
            refuse(stage, f"a report stage is run by {REPORTER_AGENT_KEY!r}", "report_reporter")
        if stage.kind == "debate" and stage.agents:
            refuse(
                stage,
                "a debate stage names no agent; it argues over the analysis stages upstream of it",
                "debate_agents",
            )
    return problems


def builtin_profile_message(name: str) -> str:
    """The refusal for an edit to a built-in team beyond what it allows."""
    return f"{name!r} is built in; clone it to change it"


def builtin_profile_changed(name: str, profile: ProfileDefinition) -> bool:
    """Whether ``profile`` differs from built-in team ``name`` beyond what it allows.

    False for a name that is not built in. Shared by the settings model, the
    API's save path and the team lint.
    """
    seed = _builtin_profiles().get(name)
    if seed is None:
        return False
    current_profile = profile.model_dump()
    expected_profile = seed.model_dump()
    # ``exclude_servers`` is the one field an operator may edit on a
    # built-in profile. It names servers, and the set of servers is
    # the operator's own: a baseline that has to withhold a server
    # added this morning would otherwise be unrepairable, because
    # every edit to it is refused as tampering with a built-in.
    #
    # ``analysts`` is inert once a profile carries stages — the model
    # reads the stages and nothing else — so a document that dropped
    # the deprecated copy is the same built-in profile.
    #
    # ``derived_from_analysts`` is bookkeeping, not a setting: a built-in
    # whose stages were written out by the migration and one that was
    # derived on load are the same built-in team.
    for field in ("exclude_servers", "analysts", "derived_from_analysts"):
        current_profile.pop(field, None)
        expected_profile.pop(field, None)
    # The stages of a built-in are the paper's architecture and stay
    # fixed, with two exceptions an operator legitimately needs: how
    # hard the debate argues, and whether a stage gets the built-in
    # tool servers. Everything else about a stage — its kind, its
    # agents, what it depends on, when it runs — is the architecture
    # itself, and editing it means cloning the profile.
    current_profile["stages"] = _profile_stage_identity(current_profile.get("stages"))
    expected_profile["stages"] = _profile_stage_identity(expected_profile.get("stages"))
    return current_profile != expected_profile


# ---------------------------------------------------------------------------
# Static-analysis provider settings
# ---------------------------------------------------------------------------


class StaticR2Config(MCPServerConfig):
    """radare2 MCP server, plus where the sample has to be for r2 to read it.

    ``mirror_dir`` names the ``samples_dir`` subdirectory the worker copies the
    sample into for r2 to open; only its last segment is used, and the copy
    keeps the same hardening every mirror gets (0o700 directory, 0o600 file,
    removed when the job ends) — see
    ``apps/api/app/worker/sample_files.work_dir()``.

    **It may not be hidden.** radare2 rejects a path carrying a ``/.`` segment,
    so an r2mcp handed a sample under ``.work`` answers "Failed to open file."
    to every tool call and the run analyses nothing — BUG 10, live on
    2026-09-07, where the default *was* ``.work``. Reproduced against a live
    r2mcp with one PE: it opens from ``data/samples/<sha>.exe`` and from
    ``data/samples/r2work/<sha>.exe``, and fails from
    ``data/samples/.work/<sha>.exe``, with ``-g none`` too. Hence the default
    below and the validator: an operator who points this back at a hidden
    directory is told why, rather than getting a provider that silently reads
    nothing.
    """

    binary_path: str = "r2mcp"
    mirror_dir: str = "data/samples/r2-work"

    @field_validator("mirror_dir")
    @classmethod
    def _no_hidden_segment(cls, value: str) -> str:
        hidden = [
            part
            for part in PurePosixPath(value.replace("\\", "/")).parts
            if part.startswith(".") and part not in (".", "..")
        ]
        if hidden:
            raise ValueError(
                f"radare2 cannot open a sample under a hidden directory, and "
                f"{value!r} contains {', '.join(repr(h) for h in hidden)}: r2 rejects any "
                f"path with a '/.' segment, so every tool call would answer "
                f"'Failed to open file.'. Use an unhidden directory such as "
                f"'data/samples/r2-work'."
            )
        # Only the last segment is honoured — the mirror is always a
        # subdirectory of the worker's ``samples_dir`` — so a value whose last
        # segment names a directory itself or its parent is not a mirror
        # location at all. ``..`` is the one that matters: it slipped through
        # the check above (which excludes it as "not hidden") and resolved
        # *outside* ``samples_dir``, into a directory the worker would then
        # chmod 0o700 and sweep stale files from. ``''`` and ``'.'`` used to
        # fall back to the hidden default, which is BUG 10 again.
        last = PurePosixPath(value.replace("\\", "/")).name
        if last in ("", ".", ".."):
            raise ValueError(
                f"{value!r} does not name a mirror directory: only its last segment is "
                f"used, and that segment is {last!r}, which means the samples directory "
                f"itself or its parent. Use a subdirectory name such as "
                f"'data/samples/r2-work'."
            )
        return value


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


class StaticGenericConfig(BaseModel):
    """Which entry of ``mcp.servers`` the ``generic_mcp`` static provider drives.

    This provider used to carry its own copy of an ``MCPServerConfig``.
    One server can now serve several analysts, so the configuration lives in
    ``mcp.servers`` and this is only the name of the one the static provider
    owns. Empty means the provider has nothing to attach, and its probe says
    exactly that rather than failing obscurely.
    """

    server: str = ""


class StaticConfig(BaseModel):
    """Which static-analysis tool the static analyst attaches, and its settings.

    ``provider`` is the single switch; every block below is the configuration of
    one provider and is inert unless that provider is selected. ``ghidra`` is
    the default.
    """

    provider: Literal["ghidra", "r2", "capa_yara", "generic_mcp", "none"] = "ghidra"
    ghidra: MCPServerConfig = Field(default_factory=MCPServerConfig)
    r2: StaticR2Config = Field(default_factory=StaticR2Config)
    capa: StaticCapaConfig = Field(default_factory=StaticCapaConfig)
    yara: StaticYaraConfig = Field(default_factory=StaticYaraConfig)
    generic: StaticGenericConfig = Field(default_factory=StaticGenericConfig)


# ---------------------------------------------------------------------------
# Sandbox provider settings
# ---------------------------------------------------------------------------


class SandboxCape2Config(BaseModel):
    """CAPEv2 REST endpoint plus the optional CAPE MCP server beside it.

    ``package_by_format`` routes a sample to the CAPE analysis package its
    format needs — an APK detonated with the ``exe`` package produces nothing.
    Keys are the file types ``sample_identity`` detects (``apk``, ``elf``,
    ``pdf``, ``ooxml``, ...); ``"*"`` is the fallback for every other format,
    and no entry at all leaves the package unset so CAPE picks for itself.
    ``submit_options`` is sent verbatim as extra form fields on every
    submission, for the CAPE settings this model does not name.
    """

    base_url: str = "http://localhost:8000"
    api_token: SecretStr = SecretStr("")
    timeout_seconds: Annotated[int, Field(ge=1)] = 300
    poll_interval_seconds: Annotated[int, Field(ge=1)] = 10
    submit_options: dict[str, str] = Field(default_factory=dict)
    package_by_format: dict[str, str] = Field(default_factory=dict)
    mcp: MCPServerConfig = Field(default_factory=MCPServerConfig)


class SandboxTriageConfig(BaseModel):
    """Hatching Triage cloud API.

    ``profile`` names a Triage VM profile and is the ``"*"`` fallback; empty
    means the account default. ``profile_by_format`` overrides it per detected
    file type, so an APK reaches an Android profile rather than the Windows
    one every other sample uses. ``timeout_seconds`` is generous because a
    Triage run queues behind other tenants' work.
    """

    base_url: str = "https://tria.ge/api/v0"
    api_token: SecretStr = SecretStr("")
    profile: str = ""
    profile_by_format: dict[str, str] = Field(default_factory=dict)
    timeout_seconds: Annotated[int, Field(ge=1)] = 900
    poll_interval_seconds: Annotated[int, Field(ge=1)] = 15
    fetch_pcap: bool = True


class SandboxUploadConfig(BaseModel):
    """Limits for operator-uploaded sandbox reports (no detonation of our own)."""

    max_report_bytes: Annotated[int, Field(ge=1)] = 67_108_864  # 64 MiB
    allowed_formats: list[str] = Field(default_factory=lambda: ["cape2", "cuckoo", "triage"])


class RestAuthConfig(BaseModel):
    """How the credential is presented to the sandbox's API."""

    header: str = "Authorization"
    scheme: str = "Bearer"  # empty sends the token as the raw header value
    token: SecretStr = SecretStr("")


class RestSubmitConfig(BaseModel):
    """The multipart submission and where the task id is read from its answer."""

    method: Literal["POST", "PUT"] = "POST"
    path: str = "/samples"
    file_field: str = "file"
    extra_fields: dict[str, str] = Field(default_factory=dict)
    # Sent verbatim beside ``extra_fields``. The two are separate so an
    # operator can keep the fields the sandbox always needs apart from the
    # per-format ones they are still tuning.
    submit_fields: dict[str, str] = Field(default_factory=dict)
    task_id_path: str = "$.id"


class RestStatusConfig(BaseModel):
    """The poll endpoint and the two terminal state sets."""

    path: str = "/samples/{task_id}"
    state_path: str = "$.status"
    done_values: list[str] = Field(default_factory=lambda: ["reported", "completed", "finished"])
    failed_values: list[str] = Field(default_factory=lambda: ["failed", "error"])


class RestReportConfig(BaseModel):
    """Where the report is, what shape it is in, and the optional capture."""

    path: str = "/samples/{task_id}/report"
    format: Literal["cape2", "cuckoo", "triage", "generic"] = "generic"
    pcap_path: str = ""


class RestMappingConfig(BaseModel):
    """RFC 9535 JSONPaths selecting each consumer channel out of a report.

    Read only when ``report.format`` is ``generic``. An empty path is not a
    mistake: it says the sandbox does not publish that channel, and the
    provider lists it in ``SandboxReport.unavailable`` so a rendered report
    never reads like a clean sample by omission.
    """

    target_sha256: str = "$.target.sha256"
    processes: str = ""  # each match: {pid, ppid, name, command_line}
    calls: str = ""  # each match: {pid, api, args, timestamp}
    signatures: str = ""  # each match: {name, description, severity, ttps}
    dns: str = ""  # each match: {request, type, answers[]}
    http: str = ""
    tcp: str = ""  # each match: {dst, dport}
    udp: str = ""
    hosts: str = ""  # each match: a string
    domains: str = ""
    dropped_files: str = ""  # each match: {name, sha256, size}
    registry: str = ""  # each match: a string
    # "<channel>.<consumer field>" -> the field name this sandbox uses,
    # e.g. {"processes.command_line": "cmdline"}.
    field_names: dict[str, str] = Field(default_factory=dict)
    # Channels this schema has no field for: "<name>" -> JSONPath, landing in
    # SandboxReport.channels under that name. Namespace the name by platform,
    # e.g. {"android.permissions": "$.apk.permissions[*]"}.
    channels: dict[str, str] = Field(default_factory=dict)


class SandboxRestConfig(BaseModel):
    """Any HTTP sandbox, described rather than coded."""

    base_url: str = ""
    auth: RestAuthConfig = Field(default_factory=RestAuthConfig)
    submit: RestSubmitConfig = Field(default_factory=RestSubmitConfig)
    status: RestStatusConfig = Field(default_factory=RestStatusConfig)
    report: RestReportConfig = Field(default_factory=RestReportConfig)
    mapping: RestMappingConfig = Field(default_factory=RestMappingConfig)
    timeout_seconds: Annotated[int, Field(ge=1)] = 900
    poll_interval_seconds: Annotated[int, Field(ge=1)] = 15
    verify_tls: bool = True


class SandboxConfig(BaseModel):
    """Which sandbox produces the dynamic evidence, and how to reach it.

    provider:
        "mock"   (default) — fixture JSON from the samples directory, no network.
        "cape2"  — a live CAPEv2 instance over its REST API.
        "upload" — no detonation: an operator-uploaded report is attached to the job.
        "triage" — Hatching Triage cloud sandbox.
        "rest"   — any HTTP sandbox, described by sandbox.rest.*
    """

    provider: Literal["mock", "cape2", "upload", "triage", "rest"] = "mock"
    cape2: SandboxCape2Config = Field(default_factory=SandboxCape2Config)
    triage: SandboxTriageConfig = Field(default_factory=SandboxTriageConfig)
    upload: SandboxUploadConfig = Field(default_factory=SandboxUploadConfig)
    rest: SandboxRestConfig = Field(default_factory=SandboxRestConfig)


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------


class ReportingConfig(BaseModel):
    """Comprehensive malware report generation settings.

    The pipeline's ``report_node`` reads these flags:

    - ``enabled``: when False the graph keeps the legacy ``judge → END`` edge
      and downstream consumers receive only ``judge_report`` / ``stix_output``.
    - ``include_extended_stix``: emit the extended Bundle (Identity / Note /
      Report SDOs). Disable to halve serialization cost when consumers only
      need the minimal judge bundle.
    - ``narrative_max_tokens``: hard cap for the NarrativeAgent LLM round.
      Keeps tail latency predictable.
    - ``auto_generate_detection_rules``: template-based YARA/Sigma/Suricata
      generation.
    """

    enabled: bool = True
    include_extended_stix: bool = True
    narrative_max_tokens: Annotated[int, Field(ge=1)] = 1500
    # How much of the upstream stages' findings a stage is handed. A pipeline
    # of six stages would otherwise put the whole run into every prompt after
    # the second one, and the last stage would spend its context on a summary
    # of a summary instead of on the sample.
    #
    # The third copy of the six thousand the tool-output cap used to be, and it
    # is the one that stays. The two it is not: the guardrail's number bounded
    # a prompt and is now derived from the served window; the evidence ledger's
    # bounded a *record* silently and is gone, because a stored prefix that
    # does not say it is one cannot be cited. This bounds a prompt, like the
    # first, and it announces itself — the block a stage reads ends in
    # "[upstream findings truncated]" — and nothing is lost, because the whole
    # findings stay in the run state, the transcript and the report. What it
    # shares with the first is being a constant where the served window is
    # knowable, and deriving it belongs with that cap rather than bolted on
    # here.
    upstream_findings_max_chars: Annotated[int, Field(ge=0)] = 6000
    auto_generate_detection_rules: bool = True

    # --- Report-reshaping (professional-report front-matter + Composer) ---
    # Front-matter identity for the report cover / TLP banner.
    publisher: str = "Maljan"
    product_type: str = "Malware Analysis Report"
    author_team: str = "Maljan Multi-Agent Pipeline"
    report_number_prefix: str = "MJN"
    default_tlp: Literal["CLEAR", "GREEN", "AMBER", "AMBER_STRICT", "RED"] = "CLEAR"
    # Section-wise Report Composer. When False, the pipeline keeps the
    # legacy single-round NarrativeAgent. Bounded per-section prompts + hard
    # per-section timeout keep the local SWA model from stalling.
    composer_enabled: bool = True
    composer_section_max_tokens: Annotated[int, Field(ge=1)] = 900
    composer_per_section_timeout: Annotated[int, Field(ge=1)] = 120
    # Server-side HTML→PDF export.
    html_export_enabled: bool = True

    # How many bytes of tool output one agent may keep in the evidence ledger.
    # Past it an entry still records the call — tool, arguments, outcome,
    # timing — and drops the output, and the report says how many entries it
    # is not showing. Half a megabyte holds a full Ghidra loop's decompilation
    # and stays well inside what a JSONB column tolerates.
    #
    # This used to be argued against answers of at most 6,000 characters, and
    # that number is gone: a tool answer is now measured against what the
    # served window has left. The arithmetic that replaces it is the one
    # property the derivation has — the answers of one conversation sum to
    # less than the room it began with — so one loop can put at most
    # ``(window - reply reserve) * 3`` characters through this budget. Half a
    # megabyte therefore holds a loop's whole tool output up to a window of
    # about 183,000 tokens, which covers every deployment this platform has
    # been run on. Above that it begins to bind, and what it does then is what
    # it has always done: the call is recorded, the output is not, and the
    # report says how many entries it is not showing. A deployment on a very
    # large window that wants the whole of it kept raises this, and pays for it
    # in a JSONB column rather than in the model's context.
    evidence_budget_bytes: Annotated[int, Field(ge=0)] = 524288

    # How much of a run's tool output is kept in memory, for the length of the
    # job, so a grounding check can ask what the run SAW rather than what the
    # ledger kept. The budget above blanks an entry after the model has already
    # read it, and a check that searched only what survived told a judge its
    # own C2 "appears nowhere in the evidence". This corpus is never written to
    # the graph state, never persisted and dropped when the job ends. Past it
    # the corpus reports itself incomplete, and an absence measured against an
    # incomplete corpus is advisory rather than a reason to drop anything.
    #
    # Sixteen megabytes, and the number is a measurement rather than a round
    # one. A ceiling only bounds what it says it bounds if the text is not
    # copied: at 400 answers of 6 000 characters the corpus holds 2.07 MB for
    # 2.40 MB of text and one grounding check allocates 0.01 MB on top of it,
    # so the process cost is the ceiling and not four times it.
    #
    # What that measurement was read against has changed. An answer used to be
    # at most 6 000 characters, so 16 MB was about 2 700 of them; a tool answer
    # is now measured against what the served window has left, and one loop can
    # put at most ``(window - reply reserve) * 3`` characters through it. On the
    # 32,768-token window this deployment serves that is 74 KB a loop, so a team
    # of six spends under half a megabyte; at 131,072 it is 369 KB a loop and
    # the six come to 2.2 MB; at a million it is 3.0 MB a loop and the ceiling
    # holds five and a half of them, so a six-agent team on a window that size
    # reaches it — and so does a static analyst taking a loop per chunk, which
    # is how a run has more loops than it has agents.
    #
    # This is deliberately **not** scaled with the window. The window is the
    # model's; this is the worker's RAM, on a machine that also runs the model,
    # and answering a bigger window by holding a proportionally bigger corpus
    # is how a 30 GB laptop runs out of memory mid-analysis. What happens when
    # it binds is unchanged and is said out loud: the corpus reports itself
    # incomplete, the run summary carries how many answers it could not hold
    # and from which tools, and an absence measured against an incomplete
    # corpus is advisory rather than a reason to drop anything. A deployment
    # with the memory to spare raises this setting.
    evidence_corpus_bytes: Annotated[int, Field(ge=0)] = 16777216


class TriageConfig(BaseModel):
    """The triage pack: the deterministic tools the pipeline runs before any analyst.

    ``enabled`` off leaves the stage in every team and makes it decline with
    that reason, so a run without the pack still says it had none.
    ``strings_head`` bounds the one open-ended tool in the pack; the rest read
    fixed structures or scan with their own budgets. ``reputation`` is the one
    network call the pack makes: ``auto`` asks whichever reputation server is
    enabled and not withheld by the team, once, for the sample hash, and
    ``off`` records that it did not. ``budget_seconds`` bounds the pack as a
    whole, checked between steps.
    """

    enabled: bool = True
    strings_head: Annotated[int, Field(ge=1)] = 300
    reputation: Literal["auto", "off"] = "auto"
    # The whole pack's wall clock. capa has its own subprocess budget and yara
    # its own, and nothing else in the pack did; a step that would start after
    # this many seconds is recorded as not run instead.
    budget_seconds: Annotated[int, Field(ge=1)] = 1200
    # What running FLOSS beside capa must leave of the host's available memory
    # (MiB). The pack runs the two together only when what is available, less
    # capa's measured peak and FLOSS's own address-space bound, stays at or
    # above this — and when the worker's own memory limit, where it has one,
    # holds both. 10,240 is the machine rule this project runs its models
    # under: ten gigabytes free before heavy work. 0 checks only that both fit.
    memory_floor_mb: Annotated[int, Field(ge=0)] = 10240


class EventsConfig(BaseModel):
    """The live conversation feed: what it carries, and how long it is kept.

    The events themselves are not optional — the console is drawn from them
    and a run that published none would be a spinner again. What is settable
    is the one channel that costs something per model turn rather than per
    step, and how long the record of a finished run stays on the job.

    ``stream_deltas`` publishes an agent's partial text while its loop is
    still running. It is on because a thirty-minute analyst that says nothing
    until it is done is the complaint this whole feed exists to answer; a
    deployment whose browsers are on a thin link can turn it off and still see
    every finished message.

    ``retention_days`` bounds ``job_events``. The transcript and the evidence
    ledger of a finished run are kept by the report and the job and are not
    touched by this; what ages out is the moment-by-moment feed, which is what
    a reader wants while a run is fresh and nobody reads a month later.
    """

    stream_deltas: bool = True
    retention_days: Annotated[int, Field(ge=1)] = 30


class ValidationConfig(BaseModel):
    """The technique check's one heuristic part, and when it is allowed to run.

    Validity, platform consistency and corroboration are exact and always on.
    The alignment gate ranks a claim's text against the ATT&CK index, and the
    index costs seconds and hundreds of megabytes to build. ``auto`` runs the
    gate only when this worker already built the index; ``alignment_gate_build``
    lets the first run that needs it build it once, in a thread, for the runs
    after. The ranking it produces is recorded on the claim and shown to the
    judge whenever the gate runs.

    Whether that ranking may also *question* a claim is ``weak_alignment``, and
    it is off. The index scores a correct id near zero often enough that the
    check questioned 81 of 92 claims in one audited run, each one costing a
    full model turn; it stays off until it clears the bar the recorded fixture
    sets. With it on, a claim is questioned when its id scores under
    ``alignment_threshold`` — the paper's gate — and an in-scope candidate from
    another tactic beats that score by ``alignment_margin``.

    ``index_retry_seconds`` is how long a failed index build is believed before
    another is attempted. A worker used to remember one network blip for its
    whole life, so every later job in it ran without the index; 0 restores that.
    """

    alignment_gate: Literal["auto", "off"] = "auto"
    alignment_gate_build: bool = False
    index_retry_seconds: Annotated[int, Field(ge=0)] = 900
    alignment_threshold: Annotated[float, Field(ge=0.0, le=1.0)] = 0.05
    alignment_margin: Annotated[float, Field(ge=0.0, le=1.0)] = 0.20
    weak_alignment: bool = False


# ---------------------------------------------------------------------------
# Root Settings
# ---------------------------------------------------------------------------


# Flipped around ``Settings(**overrides)`` by ``build_settings`` (see
# ``maljan.core.settings_overrides``) to mean "init kwargs and field defaults
# only -- no environment, no .env, no secrets directory". Bare ``Settings()``
# never touches this flag, so it stays environment- and dotenv-capable, which
# is the documented library behaviour. A ContextVar rather than an init kwarg because
# pydantic-settings validates unknown keyword arguments against the model's
# fields and rejects one that is not a declared field.
STORE_ONLY: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "maljan_settings_store_only", default=False
)


def _find_env_file() -> str:
    """Walk up from this file to find the project root .env.

    Supports launching from any subdirectory (apps/api, apps/web, etc.)
    without requiring the caller to set CWD to the project root.

    Bare-path only: this is consulted by the bare ``Settings()`` constructor
    (env- and dotenv-capable, library behaviour). The application's own
    construction path -- ``build_settings`` -- sets ``STORE_ONLY`` instead,
    which drops the dotenv source outright regardless of what this function
    returns.
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
    preprocessing: PreprocessingConfig = Field(default_factory=PreprocessingConfig)
    # See ``MCPConfig``'s own docstring; the transitional ``static.ghidra`` /
    # ``sandbox.cape2.mcp`` mirror that used to live here for not-yet-migrated
    # readers is gone.
    mcp: MCPConfig = Field(default_factory=MCPConfig)
    reporting: ReportingConfig = Field(default_factory=ReportingConfig)
    triage: TriageConfig = Field(default_factory=TriageConfig)
    validation: ValidationConfig = Field(default_factory=ValidationConfig)
    # The live conversation feed the console is drawn from.
    events: EventsConfig = Field(default_factory=EventsConfig)
    # Which analysts exist, in what order, and what each one gets. The
    # ``default`` profile is the architecture this project measured itself on.
    agents: AgentsConfig = Field(default_factory=AgentsConfig)

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        """Pick which sources a construction reads.

        When ``STORE_ONLY`` is set (``build_settings``, the application's
        construction path), only the init-kwargs source is returned: no
        environment, no dotenv file, no secrets directory. Bare ``Settings()``
        never sets the flag, so it keeps all four sources — that is the
        documented library behaviour.
        """
        if STORE_ONLY.get():
            return (init_settings,)
        return (init_settings, env_settings, dotenv_settings, file_secret_settings)

    # Token overflow protection (128K is conservative for Gemini 1M+ context)
    max_token_limit: Annotated[int, Field(ge=1)] = 128_000

    # ReAct agent execution limits
    react_agent_timeout: Annotated[int, Field(ge=1)] = 180  # seconds before agent loop times out
    react_agent_max_steps: Annotated[int, Field(ge=1)] = 10  # max LangGraph recursion steps
    # Tool-call budget.
    # When an analyst's ReAct loop exceeds this many cumulative tool calls
    # we log a WARNING. Not a hard limit (LangGraph's recursion_limit is
    # the structural cap); this is the early signal that an analyst is
    # spinning unproductively on tool calls. Set via env
    # ``REACT_AGENT_TOOL_CALL_BUDGET``.
    react_agent_tool_call_budget: Annotated[int, Field(ge=1)] = 20

    # Deprecated: a budget belongs to the agent that spends it, so
    # ``agents.definitions.<key>.timeout_seconds`` is where one is set now and
    # a definition's own value wins. This map is still read until the release
    # after the next promotion to main, so a deployment that set a budget here
    # keeps it.
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
            # The static analyst runs a
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
            # A single-slot llama-server serialises
            # all three analyst LLM calls — when the static analyst holds the
            # slot for ~600s the dynamic / network analysts spend most of
            # their budget queueing. Bump them so they don't time out before
            # the LLM ever sees their request.
            "dynamic": 600,
            "network": 300,
        }
    )

    # Deprecated, as ``react_agent_timeout_overrides`` is: set a step budget on
    # the agent's own definition (``agents.definitions.<key>.max_steps``),
    # which wins over this map. Read until the release after the next promotion
    # to main, so a deployment that set one here keeps it.
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

    @field_validator(
        "react_agent_timeout_overrides", "react_agent_max_steps_overrides", mode="before"
    )
    @classmethod
    def _drop_a_budget_the_maps_cannot_hold(cls, value: Any) -> Any:
        """The ``ge=1`` the definition's own budget fields carry, on the maps too.

        ``dict[str, int]`` accepts a zero, a negative and a boolean through the
        settings PATCH, and a loop given one of those does not run at all. The
        entry is dropped and the reason logged rather than refused: a build
        that raises is a deployment that cannot serve, and every one of these
        maps is read on the path that starts every loop. What is dropped falls
        through to the deployment's own budget, which is what the reader did
        with it anyway — the difference is that the store no longer holds a
        number nothing will ever use, and the operator is told.

        **Before** the coercion, because that is where the shapes that raise
        are. Run after it, this saw an ``int`` or nothing at all: a ``2.5``, a
        ``"lots"`` and a nested dict never reached it and made the settings
        build raise, which is the outcome it exists to prevent. What a
        deployment legitimately writes still arrives — an environment variable
        is a string, so a ``"40"`` that names a whole number is kept and
        handed on for pydantic to coerce as it always did.
        """
        if not isinstance(value, dict):
            return value
        kept: dict[Any, Any] = {}
        for agent, budget in value.items():
            if _is_a_budget(_a_whole_number(budget)):
                kept[agent] = budget
                continue
            logger.warning(
                "Agent %r has a per-agent budget of %r in a deprecated override map, which "
                "is not a whole number of at least one; it is ignored and the deployment's "
                "own budget is used.",
                agent,
                budget,
            )
        return kept

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

    @model_validator(mode="before")
    @classmethod
    def _rename_agent_keys_a_seed_has_taken(cls, data: Any) -> Any:
        """The same rename as ``AgentsConfig``, over the whole document.

        ``AgentsConfig`` can only reach the references inside itself. An agent
        key appears three more times outside it — as a key of ``llm.agents``,
        in each MCP server's ``agents`` binding, and in the two
        ``react_*_overrides`` maps — and leaving any of them pointing at the
        old name would silently drop a per-agent model choice or a timeout the
        operator set. Both passes are idempotent, so the nested one finds
        nothing left to do.
        """
        from maljan.core.agent_key_migration import rename_colliding_agent_keys

        renamed, _ = rename_colliding_agent_keys(data)
        return renamed

    @model_validator(mode="after")
    def _validate_agent_composition(self) -> "Settings":
        """The agent rules that need more than ``AgentsConfig`` to check.

        Three references leave the model that owns them: a ``ToolRef`` names a
        server in ``mcp.servers``, a definition may name a static provider in
        the provider registry, and a server names the agents it is bound to.
        Checking them here rather than in ``AgentsConfig`` is what lets a single
        PATCH that adds a server *and* an agent that uses it validate as one
        unit instead of failing on whichever half pydantic built first.
        """
        from maljan.providers.registry import static_provider_ids

        provider_ids = set(static_provider_ids())
        for key, definition in self.agents.definitions.items():
            if definition.static_provider is not None:
                if definition.static_provider not in provider_ids:
                    available = ", ".join(sorted(provider_ids))
                    raise ValueError(
                        f"{key!r}: unknown static provider "
                        f"{definition.static_provider!r}. Available: {available}"
                    )
            for ref in definition.tools:
                if ref.kind != "mcp":
                    continue
                server = self.mcp.servers.get(str(ref.server))
                if server is None:
                    raise ValueError(f"{key!r} references unknown mcp server {ref.server!r}")
                # ``tools=None`` is "every tool this server advertises", which
                # is only knowable from a live handshake. A name against such a
                # server is checked at resolution and a miss degrades there;
                # refusing it here would make a built-in sidecar unreferenceable.
                if ref.name is not None and server.tools is not None:
                    if ref.name not in server.tools:
                        raise ValueError(
                            f"{key!r}: {ref.name!r} is not allowed on server {ref.server!r}"
                        )

        self._rederive_converted_profiles()

        known = set(self.agents.definitions)
        for name, server in self.mcp.servers.items():
            for agent in server.agents:
                if agent not in known:
                    available = ", ".join(sorted(known))
                    raise ValueError(
                        f"server {name!r} is bound to unknown agent {agent!r}. "
                        f"Available: {available}"
                    )
        return self

    def _rederive_converted_profiles(self) -> None:
        """Give a converted profile the global values it is supposed to inherit.

        ``ProfileDefinition`` turns a stored list of analysts into four stages,
        but it cannot see ``llm.parallel_analysts`` or the negotiation settings
        from inside itself, so it converts with the model defaults and marks the
        profile. This is where those two global keys are applied — the promise
        that a profile nobody has opened yet runs exactly as it ran before.
        """
        for profile in self.agents.profiles.values():
            if not profile.derived_from_analysts:
                continue
            profile.stages = stages_from_analysts(
                list(profile.analysts),
                parallel=bool(self.llm.parallel_analysts),
                max_rounds=self.negotiation.max_iterations,
                consensus_threshold=self.negotiation.consensus_threshold,
                triage=has_triage_stage(profile.stages),
            )


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
    it built from the UI-managed overrides plus model defaults (``build_settings``,
    store-only). Agents,
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
