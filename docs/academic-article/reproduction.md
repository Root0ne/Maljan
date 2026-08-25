# Serving configuration, verbatim

Supplement to *What a language model adds to deterministic malware analysis, and what it takes to measure it*.
Section 2.4 of the paper names the model, the engine and the host in two tables and
states the two serving details that decide whether an arm reproduces. This is the
part a reproducer runs.

## The local server

```
llama-server -m Qwen3.6-35B-A3B-IQ3_K_R4.gguf \
  -c 131072 -t 16 -fa on -ctk q8_0 -ctv q8_0 -ngl 999 \
  -ot "blk\.([1-3][0-9])\.ffn_(up|gate|down)_exps=CPU" \
  --context-shift on --jinja --host 0.0.0.0 --port 8080
```

Restarting the server between arms changes no decoding parameter and is therefore
measurement-neutral. Long paired runs restart it anyway, because its resident set
grows and does not come back (Table 1 of the paper).

## The output cap has to be sent twice

`ChatOpenAI(max_tokens=N)` reaches the wire as `max_completion_tokens`, which
`ik_llama.cpp` does not read, so the cap must also travel in `extra_body`. Measured
on this host, 48 requested yields 2,805 generated with the renamed field alone and 48
with both. This is M7 of the paper's Section 3.8, in the form a reproducer meets it.

The same server truncates silently: it returns `finish_reason: "stop"` at the cap and
never `"length"`, so telemetry that detects truncation by finish reason reports zero
however often the cap binds.

## The rate-limited tier

The frontier arm ran on a free tier allowing 50 requests per day at 20 per minute.
The first attempt exhausted it mid-flight, 16 of its calls returning HTTP 429. One
call per sample over a 97-sample cohort is two days at that rate, and a full-pipeline
arm at roughly 20 model requests per analysis is not reachable on that tier at all,
which is why the frontier comparison runs on fixtures at n=25.
