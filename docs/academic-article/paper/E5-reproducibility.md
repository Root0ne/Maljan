# Reproducibility Appendix

*Draft for the paper. This is the full answer to pitfall P9 (model ambiguity), and it includes the
things that would stop a reader reproducing this work — quotas, retention windows, memory ceilings —
because those are what we actually hit.*

## 1. The model, exactly

| | |
|---|---|
| model | `Qwen/Qwen3.6-35B-A3B`, quantised **IQ3_K_R4** by Unsloth |
| GGUF sha256 | `d0de70ef…c4ea` — computed locally **and** matching the HuggingFace etag |
| HF revision | `cfd350fd…1f0d` |
| retrieved | 2026-05-11 |
| imatrix calibration dataset | **named in §2.0** |
| architecture | hybrid recurrent (SSM keys + `full_attention_interval=4`), confirmed from the GGUF metadata |

Naming the imatrix dataset matters: most papers reporting a quantisation level cannot say which
calibration produced it, and two IQ3 quants of the same model are not the same artifact.

## 2. The engine, and an honest note about how we know

Engine: `ik_llama.cpp`, commit **`eb570eb96689c235933b813693ca28ab9d3d26de`**
(*"MTP: Avoid per step SSM copy (#1778)"*).

**The binary could not identify itself.** `llama-server --version` prints `version: 0 (unknown)`,
because the build tree was never a git checkout. The commit was recovered from a depth-1 clone
vendored elsewhere in the project and then *proved* to describe the build: identical 837-file source
lists, and with line endings normalised **exactly one file differs — the generated
`common/build-info.cpp`**.

We report the reconstruction rather than presenting the identifier as though it had been recorded.
The transferable lesson is the one we learned the hard way: **build provenance must be captured at
build time.** A retracted first version of this row concluded the commit was unrecoverable; it was
recovered only because a vendored copy happened to exist.

### Serving command

```
llama-server -m Qwen3.6-35B-A3B-IQ3_K_R4.gguf \
  -c 131072 -t 16 -fa on -ctk q8_0 -ctv q8_0 -ngl 999 \
  -ot "blk\.([1-3][0-9])\.ffn_(up|gate|down)_exps=CPU" \
  --context-shift on --jinja --host 0.0.0.0 --port 8080
```

Two caveats a reader needs. The context is served at **131,072 — half the model's native 262,144**.
And the launch command documented in the repository at one point specified `--n-cpu-moe 36` while
the service actually ran 30 blocks on CPU; the command above is what ran.

## 3. Hardware, and the ceiling it imposes

Single host: RTX 5060, 31 GiB RAM, 16 threads. Three measured properties that shape what can be
reproduced here:

* **`llama-server` grows with cumulative requests and does not plateau** — 10.4 GB fresh, 14.8 GB
  after a single full analyst pass. A long paired run must restart it between arms; at temperature 0
  this is measurement-neutral.
* **Serving at 64k instead of 131k does not lower the peak** (14.6 vs 14.8 GB) — the baseline is
  CPU-resident expert weights, and the growth follows the context a pass actually consumes.
* **Generation rate varies from 162 to 20 tokens/s across requests.** On this hybrid recurrent
  architecture, llama.cpp writes and erases a **63 MiB recurrent-state checkpoint every few hundred
  tokens** at ~39k tokens of context. Long-context calls are therefore not slow in proportion —
  they fall off a cliff.

The Ghidra container is capped at **6 GB** (`mem_limit`). Its JVM `-Xmx4g` bounds the heap only;
the database is memory-mapped and measured RSS reached 5.15 GB against that nominal 4 GB cap. Two
host lock-ups preceded this limit being added.

## 4. Data

| artifact | what it is | committed |
|---|---|---|
| `temporal_manifest.json` | 210 dated samples, 7 cohorts, 27 families, **metadata only — no binaries** | yes |
| `dynamic_cohort_n100.json` | the n=100 dynamic cohort: Windows PE only, stratified by year, **seed 20260810**, digest recorded | yes |
| `cape_task_ledger_n100.json` | sha256 → CAPE task id for all 100 submissions | yes |
| `sink_hint_frequency.json` | per-sample hint measurement, n=100 attempted | yes |
| `cape_baseline.json` | per-sample CAPE-only scores | yes |
| `consensus_ablation.json`, `frontier_probe.json`, … | per-sample arms for every ablation | yes |
| CAPE reports | ~7 MB each, ~660 MB total | **no** — see §5 |

Ground truth resolves a MalwareBazaar family signature to an in-repo MITRE `uses` fixture through an
explicit alias map plus a CamelCase-split fallback. It is **uncurated at technique level**, which
Threats to Validity treats as a construct-validity limit rather than a footnote.

**Per-sample outputs are stored for every study in this paper.** This is a policy adopted after it
cost us a result: an earlier study's per-sample outputs were not retained, and when a defect was
later found that could have affected it, the question could not be asked. That study is withdrawn.

## 5. The sandbox, and three things that will block a reader

CAPE 2.5 at a private address, reachable only from one network.

1. **One analysis machine** (`win10`, x64), no Linux VM. Only Windows PE can be analysed dynamically
   whatever the code's stated scope, which is why the cohort is Windows-only. An ELF submitted there
   joins the 10,348 tasks that are never scheduled.
2. **Reports are retained for days, not indefinitely.** Sampled across the full task-id range, **18
   of 18** older tasks return `"Reports directory does not exist"`; a report from four days earlier
   survived. The local archive of fetched reports is therefore **the only copy**, and "submit the
   same samples" is not a reproduction recipe on its own.
3. **The instance rate-limits, and its throttle response is byte-identical to its auth refusal** —
   `{"error": true, "message": ""}` in both cases. A harness that reads that string as a capability
   verdict will mis-classify a throttle as a missing permission; we did, briefly. Re-call a tool that
   worked minutes earlier to tell them apart.

Timing, for planning: a new Windows submission is scheduled in **~1 second** and completes in
**~5.5 minutes**; the 10,348-task backlog is never scheduled and does not queue ahead of new work.
An n=100 cohort is roughly 9 hours of sandbox time.

## 6. The frontier endpoint

OpenRouter, `nvidia/nemotron-3-super-120b-a12b:free`, temperature 0, 2,400-token output cap.

**The free tier allows 50 requests per day** (`X-RateLimit-Limit: 50`,
`limit_source: openrouter_free_tier_daily`), resetting daily. This is why the frontier arm is n=9
rather than n=25: the run exhausted the quota mid-flight, 9 calls landing and 16 returning HTTP 429.
A cohort-scale frontier arm is a **two-day run or a paid one**. The spend meter is enforced as a
precondition on every call rather than reconciled afterwards, and projections price output at the
full cap because a degenerate decode produces exactly that.

## 7. Reproducing each result

All harnesses are committed under `tests/evaluation/` and are checkpointed and resumable — several
of the runs in this paper were interrupted by the memory guard and resumed without loss.

| result | harness | services needed |
|---|---|---|
| consensus ablation (§1) | `eval_consensus_ablation.py` | llama-server |
| frontier arm (§2) | `eval_frontier_probe.py` | network only |
| CAPE baseline (§0) | `eval_cape_baseline.py` | **none** — reads the local report archive |
| sink-hint frequency (§4) | `eval_sink_hint_frequency.py` | Ghidra |
| sink-hint ablation (§7) | `eval_sink_hint_ablation.py` | llama-server + Ghidra |
| opcode-hash attribution (§3) | `eval_function_hash_attribution.py` | Ghidra + Qdrant |

Two harness properties are deliberate and worth copying. Every sweep **restarts the server it
depends on between samples**, because a read timeout leaves the Ghidra JVM mid-analysis and every
subsequent load is refused — a whole window of samples was lost to this before it was understood.
And every sweep reports **how many distinct outputs the N inputs produced**, because that one line
is the cheapest detector for the stale-state defects described in Threats to Validity.
