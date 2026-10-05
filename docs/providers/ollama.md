# Ollama

The `ollama` provider calls an Ollama host through LangChain's `ChatOllama`. It
is the simplest way to run a model on a machine of your own.

## Settings

| Setting | Default | Notes |
| :-- | :-- | :-- |
| `core.llm.provider` | `openai` | Set to `ollama`. |
| `core.llm.ollama.base_url` | `http://localhost:11434` | The Ollama host. From inside the compose network, use an address the containers can reach. |
| `core.llm.ollama.expert_model` | `qwen3.5:9b` | The analysts' model tag. |
| `core.llm.ollama.judge_model` | `qwen3.5:9b` | The judge's model tag. |
| `core.llm.ollama.num_ctx` | `32768` | The context size sent with every call. |
| `core.llm.ollama.keep_alive` | `30m` | How long Ollama keeps the model loaded. |
| `core.llm.ollama.disable_thinking` | `false` | Sends Ollama's `think: false`. |

No credential is involved.

## A smaller model, when the machine has less memory

For a machine that cannot hold the default model, `gemma4:12b` behind Ollama is
a documented option:

```
core.llm.provider                   = ollama
core.llm.ollama.expert_model        = gemma4:12b
core.llm.ollama.judge_model         = gemma4:12b
core.llm.ollama.disable_thinking    = true
core.llm.ollama.num_ctx             = 32768
```

!!! warning "`disable_thinking` is not optional for a reasoning model"

    A reasoning model served by Ollama spends its output budget in the thinking
    channel and answers with an empty string. At the default the connection
    test reports that the model *answered nothing*, and with
    `core.llm.require_probe` on every job is refused until the setting is
    turned on. It is off by default because Ollama refuses `think` for a model
    that has no thinking mode.

What was measured with it is in the [Quick
start](../getting-started.md#a-smaller-model-when-the-machine-has-less-memory).

## How it behaves

- **Output caps reach the model.** The cap other providers take as
  `max_tokens` is sent as Ollama's `num_predict`.
- **No structured output.** Most Ollama-served models do not honour structured
  output cleanly, so the pipeline asks for JSON in the prompt instead.
- **One request at a time.** Under `core.llm.parallel_analysts = auto`, a model
  served by Ollama is taken to serve one request at a time, so the analysts run
  one after another.
- **Per-agent hosts.** A per-agent `base_url` wins over the global one, so two
  agents can be served by two different Ollama hosts.
- **Timeouts.** The client's 1800 s timeout bounds the silence between two
  pieces of a streamed answer, and every request is also held to a whole-call
  deadline sized for its answer.
- **The window.** `num_ctx` is one half of the served window; the other is what
  the weights hold, read from Ollama's `/api/show`, and the smaller of the two
  is used.

The probe for this provider asks through `/api/generate`, with `num_ctx` and
`keep_alive` in the body, the two fields that decide which instance Ollama
keeps loaded.
