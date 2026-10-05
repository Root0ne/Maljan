# OpenAI-compatible

The `openai` provider calls an OpenAI-compatible chat API through LangChain's
`ChatOpenAI`. With no `base_url` it calls api.openai.com; with one, it calls
whatever serves that address — DeepSeek, another hosted OpenAI-compatible API,
or a server on your own machine (see [Local llama.cpp](llama-cpp.md)).

## Settings

| Setting | Default | Notes |
| :-- | :-- | :-- |
| `core.llm.provider` | `openai` | The shipped backend. |
| `core.llm.openai.api_key` | — | Stored encrypted. Every `openai` model authenticates with it, per-agent entries included. |
| `core.llm.openai.base_url` | unset | Unset means api.openai.com. |
| `core.llm.openai.expert_model` | `gpt-4o-mini` | The analysts' model. |
| `core.llm.openai.judge_model` | `gpt-4o` | The judge's model. |
| `core.llm.openai.compat` | `auto` | Which dialect the endpoint speaks (below). |
| `core.llm.openai.reasoning_effort` | empty | Sent as `reasoning_effort` exactly as written; empty sends nothing. |
| `core.llm.openai.disable_thinking` | `false` | Turns a reasoning model's thinking off: `chat_template_kwargs.enable_thinking=false` for llama.cpp, `thinking.type: disabled` under `deepseek`. |
| `core.llm.openai.context_size` | `0` | The window the endpoint serves, when it cannot be learned from the endpoint; 0 means unknown. |

Every `llm.openai` setting is global: it applies to every model built on the
`openai` provider, per-agent entries and fallbacks at their own endpoints
included.

## Which dialect the endpoint speaks

`compat` exists because llama.cpp and the hosted APIs disagree about what a
request body may contain. llama.cpp reads three fields of its own — a
repetition penalty, an `n_predict` echo of the output cap, and
`chat_template_kwargs.enable_thinking` — and a hosted API answers all three
with `400 Unsupported parameter`.

| Value | What is sent |
| --- | --- |
| `auto` (default) | `llama_cpp` when the base URL host is loopback, link-local, `.local` or a private address; `standard` otherwise |
| `llama_cpp` | the three extras, whatever the host — for a local server reached through a public name |
| `standard` | OpenAI-standard fields only — for a hosted API, or a local vLLM that validates its body |
| `deepseek` | DeepSeek's API: the output cap as `max_tokens` as well, and `disable_thinking` as `thinking.type: disabled`; none of the llama.cpp extras |

An endpoint that rejects one of the extras anyway is retried once without them,
recorded for the rest of the process, and named in a warning that says to set
this value explicitly.

## DeepSeek

=== "Settings"

    ```
    core.llm.provider                 = openai
    core.llm.openai.base_url          = <DeepSeek's API base URL>
    core.llm.openai.api_key           = <your key>
    core.llm.openai.compat            = deepseek
    core.llm.openai.expert_model      = <a DeepSeek model>
    core.llm.openai.judge_model       = <a DeepSeek model>
    core.llm.openai.reasoning_effort  = high
    ```

=== "Why `deepseek` is set, not guessed"

    Under `auto` a DeepSeek base URL is a hosted API like any other, so no
    output cap reaches it: OpenAI's clients send the cap as
    `max_completion_tokens`, which DeepSeek's chat completions ignore, and
    DeepSeek reads `max_tokens`. `deepseek` is also the only value under which
    `disable_thinking` reaches it.

Under `deepseek`, a thinking model's `reasoning_content` is kept exactly as
returned and sent back on its turn on every later request that carries tools,
which DeepSeek's API requires. DeepSeek takes `low`, `high` and `max` as
`reasoning_effort`; empty leaves its own default. The complete behaviour is in
[Which dialect an OpenAI-compatible endpoint
speaks](../configuration.md#which-dialect-an-openai-compatible-endpoint-speaks)
and [Reasoning effort](../configuration.md#reasoning-effort).

!!! tip "Price the models before a paid run"

    `core.llm.max_spend_usd_per_job` bounds what one job may spend, priced from
    `core.llm.model_prices`, keyed by the model name the provider serves. Both
    are empty by default, so no job has a ceiling until you set one.

## OpenAI's own API

With `base_url` unset, requests go to api.openai.com and never carry the
llama.cpp extras in any mode. OpenAI's reasoning models take `minimal` to `high`
as `reasoning_effort`. A model the client sends to the Responses API (a `codex`
or `pro` model, or a request with `reasoning`, `include`, `text`, `truncation`
or `context_management` set) has its tool replies written as
`function_call_output` items, the shape that API requires.

## Structured output

Against OpenAI's own API, structured output is used where a caller asks for it.
Against any custom `base_url` it is not: a local OpenAI-compatible server is a
different animal, and the plain text path does the same job without the risk
of a call that hangs for its whole timeout.

## Mixing endpoints

Because `compat` is global, a run that mixes a hosted DeepSeek entry with a
local llama.cpp entry on the same `openai` provider sends DeepSeek's fields to
both. Keep the local entries on another provider (`ollama`) or run them under
`llama_cpp` in a separate configuration.
