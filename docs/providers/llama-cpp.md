# Local llama.cpp

A llama.cpp server — or a fork such as ik_llama.cpp — is reached through the
[OpenAI-compatible](openai-compatible.md) provider, pointed at the server's
`/v1` address. It is how the [Benchmark](../benchmark/index.md)'s local model,
Qwen3.6-35B-A3B on ik_llama.cpp, was served.

## Settings

=== "Worker on the host"

    ```
    core.llm.provider             = openai
    core.llm.openai.base_url      = http://127.0.0.1:8080/v1
    core.llm.openai.expert_model  = <the model name the server serves>
    core.llm.openai.judge_model   = <the model name the server serves>
    core.llm.openai.compat        = auto
    ```

=== "Worker in the compose stack"

    ```
    core.llm.provider             = openai
    core.llm.openai.base_url      = http://host.docker.internal:8080/v1
    core.llm.openai.expert_model  = <the model name the server serves>
    core.llm.openai.judge_model   = <the model name the server serves>
    core.llm.openai.compat        = auto
    ```

`api_key` is needed only if the server was started with one. Under `compat =
auto`, a loopback, link-local, `.local` or private host is taken to be
llama.cpp; a local server reached through a public name needs `compat =
llama_cpp` set explicitly.

## What a llama.cpp endpoint is sent

| Setting | Sent as | Default |
| :-- | :-- | :-- |
| `core.llm.openai.repetition_penalty` | `repetition_penalty` | `1.0` (no effect). Around 1.15 breaks a small reasoning model out of ATT&CK id-recall loops. |
| The request's output cap | `n_predict` as well as the standard field | always, because llama.cpp ignores `max_completion_tokens` |
| `core.llm.openai.disable_thinking` | `chat_template_kwargs.enable_thinking=false` | `false` |
| `core.llm.openai.dry_multiplier`, `dry_base`, `dry_allowed_length`, `dry_penalty_last_n` | the DRY sampler's fields, each only when set | unset |

The DRY sampler penalises a token that extends a sequence already repeated in
the context.

!!! tip "On a constrained host, consider `disable_thinking`"

    A reasoning model can spend its whole decode budget inside its thinking,
    which the server strips into `reasoning_content`, leaving an empty answer.

## What is learned from the server

- **The context window.** `GET /props` reports the window the server was
  started with, and that window sizes how much of a tool answer a model may
  read and its output caps. `core.llm.openai.context_size` states it instead
  for a server that does not report it.
- **The slots.** `/props` also reports how many requests the server serves at
  once. Under `core.llm.parallel_analysts = auto`, a local server with one slot
  runs the analysts one after another, because concurrent analysts on a
  single-slot server clobber each other's per-slot state and every step
  re-processes its prompt. More than one slot runs them in parallel.
- **Its own timings.** The prompt and generation rates llama.cpp reports on
  every answer are recorded, and the call deadlines are sized from them.

Structured output is never attempted against a custom `base_url`: a local
server handles it badly, and the plain text path does the same job.

## Two servers, two agents

A per-agent entry can name its own `base_url`, so two agents can sit on two
different local servers while `core.llm.openai.base_url` stays the fallback
for everything that sets none. The llama.cpp extras and the structured-output
decision follow the endpoint the agent will actually call. See [Per-agent
models and fallbacks](index.md#per-agent-models-and-fallbacks).

## The server the measurements used

For the record, the local model server behind this repository's measurements
ran ik_llama.cpp on loopback port 8080 as:

```bash
llama-server -m Qwen3.6-35B-A3B-IQ3_K_R4.gguf -c 131072 -t 16 -fa on \
  -ctk q8_0 -ctv q8_0 -ngl 999 \
  -ot 'blk\.([1-3][0-9])\.ffn_(up|gate|down)_exps=CPU' \
  --context-shift on --jinja
```

Host-specific helpers — a launcher, a memory guard — live outside the
repository; see [Development](../development.md#repository-layout).
