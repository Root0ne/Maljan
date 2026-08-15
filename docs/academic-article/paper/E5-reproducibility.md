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

**The working set does not fit alongside an interactive session, and that is a reproducibility fact
rather than an operational one.** Model server ~16 GB, analysis worker ~8 GB, disassembly container
up to 6 GB: on a 31 GiB host this leaves nothing for a desktop. When we ran a paired study without
that headroom, the swap file was exhausted, the model server had **2.3 GB of its own address space
paged out**, and one arm then exceeded a 594-second budget on a 16,000-character prompt. A model
generating from disk-backed pages is a different instrument from one generating from RAM, and the
timings it produces are not comparable to the rest of the table.

Two consequences for anyone reproducing this work:

* **Give the run the machine.** Long paired studies here are run against an otherwise-idle host. This
  is not a performance recommendation; arms measured under memory pressure are not commensurable with
  arms that were not.
* **Record the host state per arm, not per study.** Our harnesses capture `MemAvailable`, `SwapFree`
  and the model server's resident-versus-swapped split at both ends of every arm, and the scoring
  script excludes arms whose host was degraded. This screen can only be applied forward: for arms
  already collected without it, the state is gone and the honest label is `unattributable`. That is
  the label our own halted ablation carries.
* **Start the model server in its own cgroup, not the harness's.** This one cost us three
  interrupted runs before we read the kernel log carefully enough:

  ```
  task_memcg=/user.slice/.../snap.code.code-*.scope, task=llama-server
  Out of memory: Killed process (llama-server) oom_score_adj:1000
  snap.code.code-*.scope: Failed with result 'oom-kill'
  ```

  The harness had launched the server as a child process, so it inherited the cgroup of whatever
  started the harness — an editor's integrated terminal — and its ~16 GB was accounted to the
  editor's scope. We had already made the server the kernel's preferred victim, and that was the
  wrong level: choosing *which process* dies cannot change *whose accounting it dies inside*.
  Launching it as a transient unit with an explicit `MemoryMax` puts the measurement's memory where
  it belongs and lets the server hit a limit of its own before the host has to arbitrate.

## 4. Data

| artifact | what it is | committed |
|---|---|---|
| `temporal_manifest.json` | 210 dated samples, 7 cohorts, 27 families, **metadata only — no binaries** | yes |
| `dynamic_cohort_n100.json` | the n=100 dynamic cohort: Windows PE only, stratified by year, **seed 20260810**, digest recorded | yes |
| `cape_task_ledger_n100.json` | sha256 → CAPE task id for all 100 submissions | yes |
| `sink_hint_frequency.json` | per-sample hint measurement, n=100 attempted | yes |
| `cape_baseline.json` | per-sample CAPE-only scores | yes |
| `consensus_ablation.json`, `frontier_probe*.json`, … | per-sample arms for every ablation, one file per arm and configuration | yes |
| `parameter_size_series.json` | the size series with each arm's **measured** reasoning share and why it was included or excluded | yes |
| `judge_contribution_{uncapped,capped}.json` | the judge study in both output-cap conditions, per call, with the branch each failed call took | yes |
| `fallback_bundle_content_{uncapped,capped}.json` | per-call technique sets on the fallback path against the cascade set each would have received | yes |
| `outbound_parameter_probe.json` | which parameters the local server acts on, measured | yes |
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

## 6. The comparison endpoints, and one parameter that decides everything

Three endpoints, and a reader reproducing any of them needs the configuration axis before the
model names, because it is worth more F1 than any of them.

| arm | endpoint | model | reasoning | n |
|---|---|---|---|---|
| local baseline | `ik_llama.cpp`, this host | Qwen3.6-35B-A3B (IQ3_K_R4) | off | 25 |
| frontier | OpenRouter | `nvidia/nemotron-3-super-120b-a12b:free` | **on — not controllable** | 25 ×2 |
| same weights, hosted | DashScope International | `qwen3.6-35b-a3b` | off | 25 |
| same weights, hosted | DashScope International | `qwen3.6-35b-a3b` | on | 25 |
| larger, hosted | DashScope International | `qwen3.6-plus` | off / on | 25 each |

**`enable_thinking` is honoured on DashScope and ignored on OpenRouter.** Not rejected — accepted,
recorded in the result file, and not acted on: the re-run requesting it returned a **56.2%**
reasoning share against **56.5%** without it. On DashScope the same request produces **0.0%**. This
is the single most important line in this appendix for anyone comparing arms, because the flag is
worth 0.34–0.45 F1 on the two models where it can be set, and an arm can therefore be labelled
matched while running the opposite configuration. `eval_parameter_size_series.py` selects arms on
the **measured** reasoning share for exactly this reason and refuses to correlate when fewer than
three configuration-matched arms span three parameter counts — which, on these endpoints, is
always.

**The local server's output cap must be sent twice.** `ChatOpenAI(max_tokens=N)` reaches the wire as
`max_completion_tokens`, which `ik_llama.cpp` does not read; the cap must also travel in
`extra_body` as `max_tokens` and `n_predict`. Measured on this host: {{cap_requested}} requested, **{{cap_ignored_tokens}}
generated** with the renamed field alone, **{{cap_honoured_tokens}}** with both. A reader who omits this will find the
verdict model decoding to the context limit, which is what happened here for as long as the cap had
existed. `probe_outbound_parameters.py` re-checks this and the other outbound parameters against a
running server; it is the regression witness, and it is cheap enough to run before any measurement
campaign.

Note also that this server **truncates silently**: at the cap it returns `finish_reason: "stop"`,
never `"length"`, and carries no `stopped_limit` field. Telemetry that detects truncation by finish
reason will report zero however often the cap binds; compare the generated-token count against the
cap that was requested instead.

### The original frontier arm

OpenRouter, `nvidia/nemotron-3-super-120b-a12b:free`, temperature 0, 2,400-token output cap.

**The free tier allows 50 requests per day** (`X-RateLimit-Limit: 50`,
`limit_source: openrouter_free_tier_daily`), resetting daily, with a 20-requests-per-minute cap
that applies whether or not credit has been purchased. The **first** attempt at this arm exhausted
the daily quota mid-flight — 9 calls landing and 16 returning HTTP 429 — and the n=9 estimate it
produced was not merely imprecise but pointed the wrong way (§2). The arm reported above is the
completed **n=25** run, taken from a fresh quota: 25 of 25 parsed, 0 refusals, $0 charged against
the $25 ceiling.

The quota is stated here because it governs what a cohort-scale frontier arm costs in wall-clock
rather than in dollars: one call per sample over a 97-sample cohort is two days at 50 requests per
day, and a full-pipeline arm — roughly 20 model requests per analysis — is not reachable on the
free tier at all. The spend meter is enforced as a precondition on every call rather than reconciled
afterwards, and projections price output at the full cap because a degenerate decode produces
exactly that.

## 7. Reproducing each result

All harnesses are committed under `tests/evaluation/` and are checkpointed and resumable — several
of the runs in this paper were interrupted by the memory guard and resumed without loss.

| result | harness | services needed |
|---|---|---|
| consensus ablation (§1) | `eval_consensus_ablation.py` | llama-server |
| frontier and hosted arms (§2) | `eval_frontier_probe.py --arm <name> [--no-thinking]` | network only |
| parameter-size series (§2) | `eval_parameter_size_series.py` | **none** — reads the arm files |
| CAPE baseline (§0) | `eval_cape_baseline.py` | **none** — reads the local report archive |
| sink-hint frequency (§4) | `eval_sink_hint_frequency.py` | Ghidra |
| sink-hint ablation (§7) | `eval_sink_hint_ablation.py` | llama-server + Ghidra |
| opcode-hash attribution (§3) | `eval_function_hash_attribution.py` | Ghidra + Qdrant |
| Layer-0 verdict arms (§5) | `eval_layer0_verdict.py`, checked by `verify_b3_mechanism.py` | llama-server; the check needs **none** |
| cascade weight sensitivity (§5) | `eval_weight_sensitivity_six.py` | **none** — reads the report archive |
| judge contribution (§5) | `eval_judge_contribution.py` | llama-server |
| fallback bundle content (§5) | `eval_fallback_bundle_content.py --checkpoint <run>` | **none** — reads the run above |
| outbound parameter check | `probe_outbound_parameters.py` | llama-server |
| every figure | `make_paper_figures.py` | **none** — reads the JSON the above emit |

Two of these exist only because a result could not be believed, and both are worth running before
the studies they check rather than after. `verify_b3_mechanism.py` recomputes each ablation arm's
cascade set from its seeded fixture and compares it against what the arm recorded — it is what
established that a published finding of ours had measured a post-processing step rather than a
model. `probe_outbound_parameters.py` asks whether the server acts on each parameter we send it,
by behaviour rather than by reading a response field, because a server that ignores a parameter
does not report having done so.

The judge-contribution study is run **twice, in two conditions**, and the pair is kept: once with
the output cap not reaching the server and once with it binding. The comparison between them is
what isolates what the model's unparsable output contributes to the analyst's bundle, and neither
run alone shows it. Preserved as `judge_contribution_uncapped.*` and `judge_contribution_capped.*`.

**Figures are generated from the same retained records as the text.** The script recomputes intervals
with the seeded bootstrap rather than reading them out of a summary, so a figure and a sentence
cannot drift apart without the script failing to reproduce one of them. This caught a live error: an
ROC computed by naive descending sort returned AUC 0.458 against the {{confidence_auc}} in our text, because 186
of 210 claims are tied at confidence 1.0 and tie handling decides the entire estimate. The text was
right and the first draft of the figure was wrong — which is the ordinary direction for this check to
fire, and the reason for wiring it this way.

Three harness properties are deliberate and worth copying. Every sweep **restarts the server it
depends on between samples**, because a read timeout leaves the Ghidra JVM mid-analysis and every
subsequent load is refused — a whole window of samples was lost to this before it was understood.
Every sweep reports **how many distinct outputs the N inputs produced**, because that one line is the
cheapest detector for the stale-state defects described in Threats to Validity. And every sweep
records the **host's memory state at both ends of each unit of work**, so that a failed unit can
afterwards be attributed to the pipeline or excluded as an artefact of the machine — a question that
cannot be reopened later, as §3 above describes.
