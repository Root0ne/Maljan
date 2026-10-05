# LLM providers

Maljan's agents call language models through one of four provider backends.
Which one a deployment uses is a setting, not code: `core.llm.provider` picks
the backend, and each backend has its own credentials, endpoint and model
names. Every setting on these pages is edited under **Settings → Configuration
→ Models**, or walked through by the **Connect a language model** setup guide.

<div class="grid cards" markdown>

-   :material-api:{ .lg .middle } __OpenAI-compatible__

    ---

    OpenAI's API, DeepSeek, and any hosted OpenAI-compatible endpoint, with a
    dialect switch for what each accepts.

    [:octicons-arrow-right-24: OpenAI-compatible](openai-compatible.md)

-   :material-server-outline:{ .lg .middle } __Local llama.cpp__

    ---

    A llama.cpp or ik_llama.cpp server on this machine or network, through the
    same OpenAI-compatible provider.

    [:octicons-arrow-right-24: Local llama.cpp](llama-cpp.md)

-   :material-alpha-a-box-outline:{ .lg .middle } __Anthropic__

    ---

    Anthropic's Messages API with an API key.

    [:octicons-arrow-right-24: Anthropic](anthropic.md)

-   :material-star-four-points-outline:{ .lg .middle } __Gemini__

    ---

    Google's Gemini API with an API key.

    [:octicons-arrow-right-24: Gemini](gemini.md)

-   :material-laptop:{ .lg .middle } __Ollama__

    ---

    A local or networked Ollama host.

    [:octicons-arrow-right-24: Ollama](ollama.md)

</div>

## At a glance

| Provider | `core.llm.provider` | Credential | Endpoint | Per-agent endpoint |
| :-- | :-- | :-- | :-- | :-- |
| [OpenAI-compatible](openai-compatible.md) | `openai` | `llm.openai.api_key` | `llm.openai.base_url`; unset means api.openai.com | yes |
| [Local llama.cpp](llama-cpp.md) | `openai` | `llm.openai.api_key`, if the server asks for one | `llm.openai.base_url` | yes |
| [Anthropic](anthropic.md) | `anthropic` | `llm.anthropic.api_key` | the vendor API | no |
| [Gemini](gemini.md) | `gemini` | `llm.gemini.api_key` | the vendor API | no |
| [Ollama](ollama.md) | `ollama` | none | `llm.ollama.base_url` | yes |

## Analyst and judge models

Each backend has two model names: `expert_model`, which the analysts use, and
`judge_model`, which the judge uses. The analysts run at temperature 0.1 and the
judge at 0.0 unless an agent's own entry says otherwise. A job can switch the
backend for itself with `llm_provider` in its config; see [Running an
analysis](../usage/running-an-analysis.md#what-a-job-may-choose-for-itself).

## Per-agent models and fallbacks

`llm.agents` holds one optional entry per agent key — provider, model,
temperature and, for `openai` and `ollama`, a base URL — so the analysts and the
judge need not share one model, or one server. It is ordinarily edited from the
Agents page, one agent at a time.

```json
{
  "static": {
    "provider": "openai",
    "model": "qwen3.6-35b-a3b",
    "base_url": "http://127.0.0.1:8080/v1",
    "fallbacks": [
      {"provider": "ollama", "model": "gemma4:12b"}
    ]
  }
}
```

An entry may name the models the agent falls back to, in order. The next model
is asked **only when the one before failed as a provider** — a refused or
dropped connection, a timeout, an HTTP 5xx, 408 or 429, a model the server does
not have, a refused credential — and never because of what a model said. Which
model answered is recorded on every turn. The full rule is in [Per-agent model
overrides](../configuration.md#per-agent-model-overrides).

!!! note "The credential stays global"

    A per-agent `openai` entry with its own endpoint still authenticates with
    `llm.openai.api_key`, and Anthropic and Gemini entries take no base URL at
    all: one set against them is rejected on save.

## A model is probed before a job may name it

With `llm.require_probe` on (the default), a job is refused while any model its
team names has not answered a connection test. The probe asks for one short
answer at the endpoint and on the model the run will use, through each
provider's own completion API. See [A model is probed before a job may name
it](../configuration.md#a-model-is-probed-before-a-job-may-name-it).

## Behaviour common to every provider

- **Request timeout.** Every provider's client is built with an 1800 s request
  timeout until the model's pace is measured; after that each request is sized
  for its own output cap. See [A call waits as long as its answer takes at the
  model's pace](../configuration.md#a-call-waits-as-long-as-its-answer-takes-at-the-models-pace).
- **Every tool call is answered.** No request sends a tool call without its
  reply, in each provider's own message shape, because every provider's API
  refuses a history with a call left unanswered.
- **The context window is learned, not guessed.** The window a model is served
  with decides how much of a tool answer it may read and how large its output
  cap is. It is taken from a setting, a metadata endpoint or a vendored table,
  and a run that could learn none says so. See [How much of a tool answer a
  model sees](../configuration.md#how-much-of-a-tool-answer-a-model-sees).
- **A spend ceiling, when you want one.** `core.llm.max_spend_usd_per_job`
  bounds what one job may spend on its models, priced from
  `core.llm.model_prices`. It is empty by default. See [Loops have no default
  limit](../configuration.md#loops-have-no-default-limit).
