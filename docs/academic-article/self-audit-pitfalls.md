# Self-audit against *Chasing Shadows*' nine pitfalls

> **Why this exists.** Evertz et al., *Chasing Shadows: Pitfalls in LLM Security Research*,
> **NDSS 2026** (`arXiv:2512.09549`), surveyed **all 72** peer-reviewed LLM-security papers from
> leading Security and Software Engineering venues in 2023–2024. **Every one contains at least
> one of nine pitfalls**, and **only 15.7% of the present pitfalls were explicitly discussed.**
> The author list includes Daniel Arp, of *Dos and Don'ts of Machine Learning in Computer
> Security* — this is that critique's direct successor, and it is what a 2026 security reviewer
> is now primed to look for.
>
> Pitfall definitions below are quoted from the paper's living appendix at `llmpitfalls.org`.
> The 15.7% figure is the low bar this document exists to clear: not being free of pitfalls —
> nobody is — but **naming ours before a reviewer does**.
>
> Audited 2026-08-08. Verdicts are `CLEAR` / `PARTIAL` / `EXPOSED`, and `PARTIAL` means exactly
> that.

---

## Summary

| # | Pitfall | Verdict | One line |
|---|---|---|---|
| P1 | Data Poisoning | `CLEAR` | Nothing is trained; retrieval corpora are curated and their provenance is documented |
| P2 | Label Inaccuracy | `CLEAR` | Ground truth is MITRE-curated, and **LLM-as-a-judge was never used for scoring** |
| P3 | Data Leakage | `PARTIAL` | One instance found, disclosed and mitigated by us — but never systematically audited |
| P4 | Model Collapse | `CLEAR` | Explicitly rejected augmenting long-term memory with LLM-fabricated cases, with a cited rationale |
| P5 | Spurious Correlations | `PARTIAL` | Two found and published; no systematic perturbation testing |
| P6 | Context Truncation | `EXPOSED` → `PARTIAL` | Frequency measured 2026-08-14: the static ReAct loop hits its step budget on **82.1%** of arms, always at exactly 19 tool calls / 41 messages; a tool output is cut on 83.9%; evidence is chunked on 48.2%. Truncation is the normal regime, not an edge case. Performance impact still unmeasured — too few unaffected arms to compare |
| P7 | Prompt Sensitivity | `PARTIAL` | A structured prompt-variation study exists; production prompts are fixed and unvaried |
| P8 | Surrogate Fallacy | `EXPOSED` → `PARTIAL` | One model, one machine. Four claims **scoped 2026-08-09**. Frontier arm completed 2026-08-12 at n=25: paired ΔF1 **+0.003 [−0.077, +0.081]** — a 3.4× model does not separate. Remaining gap is **coverage** (fixtures, not the cohort) → C6 |
| P9 | Model Ambiguity | `PARTIAL` | Model **and engine both pinned 2026-08-09** (GGUF digest + HF revision + imatrix dataset; engine commit `eb570eb9`). Off `CLEAR` because the running binary reports `unknown` — the commit was recovered from a second copy of the sources, not from the artifact |

**Three actionable items** fall out: report truncation frequency (P6), scope the generalising
claims (P8), and pin the exact model and engine revisions (P9). None requires an experiment.

---

## P1 — Data Poisoning `CLEAR`

> *"A dataset used to train a model is collected from the internet without strategies to verify
> the integrity and safety of the data."*

**Nothing in Maljan is trained.** There is no classifier, no fine-tuning, no gradient step
anywhere in the decision path (§0, and the `SUPERSEDED` static-feature classifier in §4 was
rejected on exactly this principle).

The pitfall still partially transfers, because retrieval corpora are data whose integrity
matters. Ours and their provenance: the **MITRE ATT&CK STIX bundle** (official, auto-refreshed
every 30 days, hash-keyed embedding cache), **2,651 Sigma rules** (upstream project),
**30 YARA rules** (in-house), **MABEL-derived corpora**, and **MalwareBazaar** samples.

**What we already disclose:** the MABEL case corpus carries **capa's *static inference*** of
ATT&CK ids, "not authoritative ground truth" (§4). That corpus is now measured as no better
than a frequency prior and is disabled (§1.5.3), so the exposure is retired rather than merely
caveated.

**Residual:** no integrity verification of the Sigma corpus beyond trusting upstream. Worth one
sentence in the paper, not an experiment.

## P2 — Label Inaccuracy `CLEAR`

> *"LLMs are used to annotate data with certain labels via classification or LLM-as-a-judge
> procedures without further validation of correctness."*

**We never used LLM-as-a-judge for scoring**, which is the common form of this failure. **Still
true after the B layer, and worth re-checking rather than assuming** — the five harnesses added on
2026-08-09 all score in code: B1 compares technique-id sets against fixture ground truth, B2 scores
each claim's id against the same, B3/B4 diff bundles and read integrity counters, B5 diffs two runs
of a production function. No model judged any result. The one planned exception is **D1, the
readability assessment, which is LLM-based and for that reason does not enter the paper at all**
(see the queue). Every
evaluation harness scores deterministically: `TTPAccuracyMetrics` compares technique-id sets by
exact match; narrative quality is grounding precision / coverage recall / structural compliance
computed in code (§3.5); view decomposition scores invalid-id rate through the production
`ATTCKValidator` (§3.6). The scoring functions are themselves unit-tested
(`test_*_scoring.py`), so the instrument is checked independently of the result.

Ground truth is **MITRE-curated**: family-level ATT&CK `uses` relationships from the official
STIX data, for 700+ families. Not model-generated.

**Worth stating positively in the paper.** Given how prevalent LLM-as-judge has become, "no LLM
scored any result in this work" is a claim most papers cannot make.

## P3 — Data Leakage `PARTIAL`

> *"An LLM is trained or fine-tuned with data that is normally not available in practice or the
> training data is contaminated with possible test data."*

**We found one instance, disclosed it, and fixed it.** `data/family_fingerprints_v1.json` was
built **from the n=210 evaluation corpus**, and the findings log says so in the entry that
created it: *"this bootstrap catalog is built FROM the eval corpus, so it must NOT be used for a
leakage-free measurement of the RAG's effect — for that, rebuild from a DISJOINT source."* A
disjoint MABEL catalog (318 families) was then built for that purpose, and the leakage-free
retrieval eval was run on a held-out `a0`/`a1` archive split.

We also guard the circular-evaluation form: the ATT&CK index is built **from** ATT&CK
descriptions, so §1.5.1 scores it on TRAM2 and (2026-08-08) on AnnoCTR instead — *"scoring
against the ATT&CK descriptions themselves would be circular"*, stated in the harness docstring.

**Residual, and it is real:** the underlying LLM's training data is unknown to us. Qwen3.6 may
have seen MalwareBazaar samples, ATT&CK prose, or the very CTI reports our benchmarks draw
from. We cannot exclude it and have not probed for memorisation. The pitfall's own
recommendation — *"verify training cutoff dates, probe for memorization, and acknowledge
potential effects if leakage cannot be excluded"* — means the paper must **acknowledge** this.
Currently it does not.

## P4 — Model Collapse `CLEAR`

> *"An LLM is trained on data that is generated by other language models, risking an
> amplification of bias and degradation of data quality."*

Nothing is trained, so the direct form does not apply. The *retrieval* analogue does — a memory
corpus fed by model output would compound its own errors — and **we explicitly rejected it**.
§3.1 records the decision against augmenting the Qdrant long-term memory with LLM-fabricated
cases, citing Rollinson & Polatidis's finding that synthetic data reinforces existing structure
without adding predictive information. The long-term memory stores only *analysed real samples*.

**This is a strong row and should be said out loud**, since the temptation to bootstrap a
memory corpus with generated cases is obvious and we documented refusing it.

## P5 — Spurious Correlations `PARTIAL`

> *"The LLM adapts to unrelated artifacts from the problem space instead of generalizing onto
> the actual task."*

**Two found and published**, both by measurement rather than by inspection:

1. **§1.5.1** — TF-IDF matching a ransomware claim to a *crypto-algorithm* technique on the
   shared token "AES" rather than the impact technique. A lexical artifact, documented as the
   backend's characteristic failure mode.
2. **§1.5.3** — the case-prior RAG scoring every query 0.78–0.90 **regardless of content**,
   because query and corpus shared only their boilerplate. The retriever had adapted to
   template text, not to the sample.

The second is the more interesting: it was invisible to top-k accuracy and only appeared in the
**score distribution**, which is a generalisable diagnostic.

**A third instance, 2026-08-09 — and the diagnostic is the transferable part.** §3.8 found the
ISR **confidence** channel sitting at ~0.98 regardless of content, with one channel at exactly
1.000 throughout. That is the *same diagnostic* as instance 2, applied to a different score: look
at the **distribution**, not the top-line metric. Both channels looked healthy by their headline
number and were degenerate underneath.

Strictly this is not a spurious correlation — the model is not adapting to an artifact, it is
failing to vary at all — so it does not make P5 worse. It matters here because it is the second
time the **score-distribution check** caught something no accuracy metric would have, which
promotes that check from an anecdote to a method worth naming in the paper. *(The phenomenon
itself is published — `arXiv:2603.09309`, "discretization" — see §3.8. What is ours is the
diagnostic habit and the fact that a system was consuming the number.)*

**Residual:** no *systematic* robustness testing. The pitfall recommends controlled
perturbations; our only instance is the §1.10 weight-perturbation study, which perturbs our own
constants rather than the input. Input perturbation (packed vs unpacked, stripped vs symbolised,
renamed functions) is unrun and would be a real experiment. **The B1 follow-up — degrading the
evidence channels to locate `arXiv:2604.02460`'s crossover — is exactly such a perturbation and is
now queued**, so this row has a concrete path off `PARTIAL` for the first time.

## P6 — Context Truncation `EXPOSED` → `PARTIAL`

> *"The LLM's context size is not spacious enough for its intended task and the input needs to
> be truncated."*

**This is our weakest row, and it is weak in a way we can fix without an experiment.**

Truncation is everywhere in the design and is *deliberate*: `binary_chunker` splits large
binaries at function boundaries; `static_max_chars` bounds evidence per call; `max_steps` caps
the ReAct loop at 40; `judge_max_tokens` bounds the verdict at 8192; the schema-pruning hint is
truncated to 400 characters. §2.1 documents a 131,072-token context.

We also found a *consequence* of the budget without framing it as truncation: **§1.7.1** —
removing an advisory hint made the judge overrun a 600 s ceiling and fall back to an empty
bundle **6/17** times instead of 1/17. That is context/budget exhaustion changing the result,
measured.

**What is missing is exactly what the pitfall asks for:** *"report truncation frequency and
performance impacts."* We do not report how often a sample's evidence was truncated, how many
chunks were dropped, or what fraction of runs hit `max_steps`. The data exists in run logs and
`RunSummary`; nobody has counted it.

**Action:** add truncation counters to `RunSummary` and report the distribution. `[cheap]` once
runs exist — no new experiment, just instrumentation of runs we already do.

*Progress, 2026-08-11.* The counters exist (`core/truncation_ledger.py`, A3) and record every
guardrail decision including the pass-through, because a frequency needs its denominator.

*Measured, 2026-08-14 — the frequency this row was opened for.* Counted over the dynamic-vs-static
study's arms, which drive the full pipeline on real binaries. The denominator is **arms started**
(56) rather than arms completed (30), because an arm killed by the memory guard still exercised the
static analyst before it died, and using completions would flatter every rate:

| truncation site | arms affected | rate |
|---|---|---|
| static ReAct loop hit its step budget | 46/56 | **82.1%** |
| a tool's output exceeded the guardrail and was cut | 47/56 | **83.9%** |
| static evidence split into chunks | 27/56 | **48.2%** |
| forced-synthesis fallback then exceeded its hard cap | 10/56 | 17.9% |

**The step-budget row is not a distribution.** All 46 arms stopped at *exactly* 19 tool calls and
*exactly* 41 messages — the same boundary every time, which is `static max_steps = 40` binding on
message count. This is not a model failing to converge and occasionally running long; it is a
deterministic cap being reached on four arms in five, after which the analyst abandons its loop and
falls back to synthesising from whatever it had gathered.

Chunking is common but modest where it happens: 2 chunks on 10 arms, 3 on 9, 6 on 3, 11 on 5.

**What this changes about the paper.** Truncation is not an edge case in this system, it is the
normal operating regime, and every accuracy number in this work was produced under it. That belongs
next to the numbers rather than in an appendix.

**Verdict: `EXPOSED` → `PARTIAL`.** The pitfall asks for two things and we now have one. Frequency
is reported with its denominator. The *performance impact* is not: with 46 of 56 arms hitting the
same cap there is almost no unaffected control group to compare against, so we can say how often
the system runs truncated but not yet what it costs. Saying so is the point of the row.

One truncation site was found that no part of this audit had listed: the sink-reachability
pre-pass fetches the call graph with **`limit=20000` edges**, and a binary whose graph exceeds that
is silently cut before the hint is computed. Measured at **1 of 79** samples (§3.15) — low, but it
was zero in the sense that mattered: nobody was counting it. Two lessons for the P6 write-up. The
enumeration of truncation sites was itself incomplete, so the paper should say how the list was
built rather than presenting it as exhaustive; and the site was found by instrumenting a
measurement for a different question, which is the ordinary way such things surface.

## P7 — Prompt Sensitivity `PARTIAL`

> *"The prompt used to instruct the language models is fixed for all models and experiments or
> is not expressive enough for the given task."*

**Partially addressed, by accident of a different question.** §3.6 is a genuine prompt-structure
variation study — monolithic vs 2-view vs 4-view vs 3-tier, at **equal total generation budget**,
N≫1, with bootstrap CIs — and it found decomposition trades grounding for volume. §3.2/§3.4
found something sharper: the *decoding budget* inverted the ranking of the same prompt
structures, which is prompt sensitivity showing up as an instrument-validity failure.

External corroboration worth citing: `arXiv:2606.18166` found prompt strategy, chain-of-thought
and temperature were **not** statistically significant predictors of ATT&CK-classification F1,
while parameter size was (ρ=0.85, p=0.014).

**Residual:** production prompts are fixed and were never varied per model — because there is
one model (see P8). The pitfall's recommendation to "optimize prompts per model-task pair" only
bites once a second model exists.

## P8 — Surrogate Fallacy `EXPOSED`

> *"Findings from specific LLMs are often inappropriately generalized to other, often large and
> more capable models or even to entire classes of language models."*

**Known, stated as E.8 — and several claims were phrased more generally than the evidence
supports.** Every LLM result in this work is **Qwen3.6-35B-A3B (IQ3_K_R4) on one machine**.

Claims that needed scoping language, and what each one's evidence actually covers:

| claim | read as | evidence actually covers | scoped |
|---|---|---|---|
| §3.3 degenerate ID loop | "a small-model pathology" | one model, reproducible across two runs and two prompt structures; **the sampler half is a property of the *engine*, not the model** | ✅ 2026-08-09 |
| §3.5 narrative quality | "the LLM narrator's only edge is readability" | one model, 5 fixtures × 3 repeats; and "structural compliance" is a **format proxy, not readability** | ✅ 2026-08-09 |
| §1.7.1 hint → completion | an operational property | one model at ~40 tok/s under one 600 s ceiling — this one *was* already caveated; only the identifier was missing | ✅ 2026-08-09 |
| §1.5.2 autocorrect regression | a property of the correction policy | **not a model limit at all** — the harness is server-free; see below | ✅ 2026-08-09 |

**Correction to this audit's first pass (2026-08-09).** The row above originally read *"measured
on one index and one model's outputs"*. The second half is wrong: `eval_autocorrect_ablation.py`
runs **server-free** and the three input error modes are **injected at 100% each, rate-free** —
they are a simulation, not any model's observed error distribution. The real limits are (i) one
retrieval index, whose gate §1.5.1 shows varies by +0.062 to +0.168 across backends, and (ii) a
stated assumption that correct inputs dominate. Getting this wrong mattered in a specific way:
it would have attached a model caveat to the one result that does not need one, while leaving
the index dependency — the limit that actually binds — unstated. What survives unconditionally
is the structural claim: correct-but-weak and wrong-but-valid IDs are not separable by an
alignment score, so the valid→valid swap cannot be tuned safely at any error rate.

`arXiv:2606.18166` makes this sharper rather than softer: if **parameter size is the only
significant predictor** of performance on the nearest task, then single-model findings are
exactly the kind the pitfall warns about.

**Cross-model data, completed 2026-08-12 at full n — and it moved.** A second endpoint has run to
completion (§3.16): Nemotron-3-Super-120B-A12B against the local Qwen3.6-35B-A3B, same five
fixtures, same five repeats, same prompt, same 2400-token budget. Because both arms cover the same
sample the comparison is **paired**:

> **frontier − local = +0.0026**, 95% CI **[−0.0770, +0.0814]**, n=25.
> Frontier better on 12, worse on 13, tied on 0.

**The interim reading was wrong, and how it was wrong is the point.** At n=9 this arm scored
**0.5025** and read as a lead over the local model's 0.4136. Completing the sample moved the estimate
down by 0.086 — through the local mean and out the other side — and the direction across samples is a
coin flip. Nothing was learned between the two runs except the remaining 16 calls, which had been
truncated by a daily request quota rather than by anything about the samples. A difference read off
an underpowered arm is not a weak result; it is an unreliable one, and this audit had it in front of
it for a day.

What follows for the confound. It is **substantially narrowed**: at equal budget on this task, a 3.4×
parameter advantage produces no measurable separation, which is direct evidence *against* the
surrogate fallacy's usual worry — that a bigger model would have changed the conclusions. The scoped
claims stand as scoped, and the negatives now have a second model behind them.

What remains is **coverage, not power**. This is five synthetic fixtures, not the n=100 malware
cohort; C6 asks the same question against real samples, where evidence bundles are messier and longer
and the two models may diverge in ways five fixtures cannot show. The free tier caps at **50
requests/day**, so C6 is a two-day run or a $10 purchase — a scheduling fact for the reproducibility
appendix, since a reader reproducing it hits the same wall.

**Verdict: `PARTIAL`, and closer to `CLEAR` than at any earlier pass.** The write-up half is done —
all four claims carry their scope at the point of claim, `related-work.md` carries a section-level
scope statement, and the distinction between *negatives obtained under a favourable configuration*
(which travel) and *positives bounded by this model's speed* (which may not) is stated. The empirical
half is now **half done rather than absent**: a second model of 3.4× the size has been measured at
full n on the fixture suite and does not separate, so "these findings are an artefact of a small
quantised model" is no longer an open hypothesis — it is one the evidence points against.

It stays `PARTIAL` for a reason we can name precisely, which is the only kind worth keeping open:
the second model has been tested on **fixtures, not on the malware cohort**. C6 closes that. Until it
lands the honest statement remains the one in `related-work.md` — single-model findings are not
properties of an architecture — but the sentence now has a measured counterexample standing behind
it rather than a promise.

## P9 — Model Ambiguity `PARTIAL`

> *"The model details are insufficient for precise identification, preventing reproducibility
> (e.g., missing model ID, snapshot, commit ID, quantization level)."*

**Unusually strong for this literature.** We report the model family and architecture
(Qwen3.6-35B-A3B MoE, 35B total / ≈3B active), the **quantization level** (IQ3_K_R4), the
**serving engine** (ik_llama.cpp `llama-server`), the offload strategy (`--n-cpu-moe`, hybrid
CPU/GPU), the **context size** (`-c 131072`), decoding settings where they matter
(`enable_thinking=false`, `temperature=0` in the ablations), and the hardware (RTX 5060 8 GiB,
31 GiB RAM). §2.1 even records a sampler-behaviour quirk of this specific engine
(`repeat_penalty` honored, `repetition_penalty`/`frequency_penalty`/`presence_penalty` silently
ignored) — engine-level detail almost nobody reports.

**Resolved for the model, structurally unresolvable for the engine (2026-08-09, queue item A2).**
Full record in `findings-log.md` **§2.0**.

**Model — closed.** GGUF **sha256 `d0de70ef…c4ea`** (computed here *and* matching the HuggingFace
download etag, so the file is byte-identical to the published artifact), **HF revision
`cfd350fd…1f0d`**, retrieved 2026-05-11 20:39:17 UTC, `general.quantized_by = Unsloth` over base
`Qwen/Qwen3.6-35B-A3B` (Apache-2.0), `file_type 339`, and — unusually — the **imatrix calibration
dataset is named** (`unsloth_calibration_Qwen3.6-35B-A3B.txt`, 510 entries / 76 chunks).
Importance-matrix quantisation is a lossy transform whose result depends on its calibration text;
most papers reporting a quant level cannot say which imatrix produced it.

**Engine — closed, but not by the artifact.** `llama-server --version` prints `version: 0
(unknown)` and `build-info.cpp` holds `LLAMA_COMMIT = "unknown"`, because the build tree is not a
git checkout and CMake had no commit to record. The commit was recovered from a **second copy of
the same sources** — the depth-1 clone vendored at `external/ik_llama.cpp` — and *proved* to
describe the build: identical file lists of **837 sources**, and comparing them with CR stripped,
**exactly one file differs, `common/build-info.cpp`**, which is the generated file itself.

**Engine source commit: `eb570eb96689c235933b813693ca28ab9d3d26de`** (*"MTP: Avoid per step SSM
copy (#1778)"*, `github.com/ikawrakow/ik_llama.cpp`, on `origin/main`), binary sha256
`7737b2a9…542d`, built 2026-07-05 with `cc 15.2.0`.

**Verdict: `PARTIAL`.** Both halves are now identified to the byte, which is more than this
literature usually manages. What keeps it off `CLEAR` is not a missing field but the way the
field was obtained: the running binary could not name itself, and recovery depended on a second
copy existing by luck. **Build provenance must be captured at build time.** Reconstructing it
worked here; it is not a method to rely on, and the paper says so rather than presenting a clean
identifier as though it had been recorded properly.

*Correction, 2026-08-09:* this row first concluded the commit was **unrecoverable** and pinned the
engine by hashes alone. That was wrong — I searched the build tree and stopped, without checking
whether the sources existed elsewhere in the project. The vendored clone surfaced by accident,
from a pytest collection error. Also retracted: the "upstream anchor at PR #630" read off the
vendored `github-data` directory. The commit references **PR #1778**, so that directory is a stale
artifact and never was a version anchor.

**Action:** ~~record the model file digest and engine commit~~ — **done in §2.0**; emitting the
provenance block with every run is folded into **A3**.

---

## What this changes

Nothing in the results. Three things in the write-up, all cheap:

1. **P6** — instrument and report truncation frequency; the mechanism is designed-in and the
   data is already produced, only uncounted.
2. **P8** — ~~scope four claims to the evaluated model by exact identifier~~ **done 2026-08-09**;
   the architecture/model confound is now stated explicitly in `related-work.md` and stays open
   until C6.
3. **P9** — ~~pin the model digest and engine commit~~ **done 2026-08-09**, both. The engine
   commit (`eb570eb9`) had to be recovered from a second copy of the sources because the running
   binary reports `unknown`, and the paper says that rather than presenting the identifier as
   though it had been recorded properly. The transferable lesson: build provenance must be
   captured at build time.

And one thing to say out loud rather than assume a reviewer will notice: **P2 and P4 are clear
in a way most papers in this survey are not** — no LLM scored any result here, and augmenting
the memory corpus with generated cases was considered and refused with a citation. Against a
baseline where only 15.7% of present pitfalls are discussed at all, having a document like this
one is itself part of the answer.

---

## A tenth check this survey does not have, added 2026-08-09

All nine pitfalls concern the relationship between a paper's **claims** and its **experiments**.
Two failures this week sat a level below that — between the claim register and the **evidence
log** — and neither would have been caught by any of the nine:

1. **A claim was recorded as novel one hour after our own text called it a replication.** N9's
   findings-log entry described it as *"a replication of `arXiv:2604.02460` and `arXiv:2605.00914`
   in a new domain"*, while the ledger row said `OURS`. Catching that needed no literature search
   at all — only reading the two documents against each other.
2. **This audit mis-stated one of its own rows.** P8's first pass recorded §1.5.2's limitation as
   "one model's outputs" when that harness is **server-free** and its error modes are injected.
   Corrected the same day. The consequence was not cosmetic: it would have attached a model caveat
   to the one result that does not need one, while leaving the limit that actually binds — the
   retrieval index — unwritten.

**The check: before a claim register is trusted, diff it against the evidence log.** It costs
minutes, needs no external source, and here it caught two errors a literature search would have
missed — one of which had already been written down correctly and was then contradicted.

Worth a methods note in the paper, because it generalises: a project disciplined enough to keep
both a findings log *and* a claim ledger has, by that very fact, created the conditions for the
two to diverge.

---

## An eleventh check, added 2026-08-10 — count the distinct outputs

The nine pitfalls, and the tenth above, all assume the **instrument reports what it measured**.
Three defects found on a single day violated that assumption, and none of them would have been
caught by any of the eleven checks that existed that morning:

| | the instrument did this | while reporting |
|---|---|---|
| **M1** | sent `null` for every unset optional MCP argument | nothing — all 36 CAPE tools refused, silently |
| **M2** | left Ghidra's *current program* on the first binary ever loaded | `{"success": true, "program": "<the one you asked for>"}` |
| **M3** | answered a refused load with **HTTP 200** and an `error` body | a call graph, a hint, and function hashes — of another binary |

They share a shape worth naming: **a plausible wrong answer with no error anywhere**. Not a crash,
not a stack trace, not a degraded score — output that looks exactly like output. M2 is the sharpest
case: `load_program` returned success *with the correct program name in the response*, and the very
next call operated on a different program entirely.

**Why the test suite did not help.** All three survived **1,981 passing tests**. Not by accident:
M2 and M3 require a *second* case in one server lifetime, and a unit test writes one. A suite that
loads a single program, asserts on it, and tears down can never observe a context that fails to
switch. The green suite was not wrong; it was answering a different question.

**What did catch them, all three times, was arithmetic on the outputs:**

- a priority hint of **2,575 characters** appearing for two unrelated samples — and for a third in
  an earlier session;
- call graphs of **404,337 characters, 11,798 lines**, identical to the character, for binaries of
  241 KB and 139 KB;
- **66 consecutive samples** at exactly 75,426 characters.

**The check: before trusting a batch measurement, ask how many distinct outputs the N inputs
produced.** If N samples yield far fewer than N distinct values on any dimension that should vary —
output length, digest, element count — the instrument is repeating itself, and repetition is what a
stale-state bug looks like from outside. It costs one line of code, needs no ground truth, and it is
now reported alongside the result in §3.15 (**50 distinct call-graph sizes across 79 samples**).

**What it cost not to have this.** §3.14 withdraws the **n=210 temporal-drift study**: it drove the
full pipeline per sample against a long-lived shared Ghidra container that was never restarted,
which is precisely M2's precondition, and its per-sample outputs were not retained — so whether it
was affected cannot now be determined. A result that survived review, went into the ledger as
`OURS`, and is now unusable, because nobody asked how many distinct answers the samples gave.

The generalisable form, and the reason this belongs in the paper rather than in an issue tracker:
**an LLM pipeline is mostly other people's servers, and a server that answers is not the same as a
server that answered your question.** Every integration boundary here — MCP, Ghidra, the sandbox
REST API — turned out to have a way of saying yes while doing something else, and the pipeline's
own error handling was built for the failures that announce themselves.

### Counter-search on this check, 2026-08-11 — it is a refinement, not a discovery

The house rule is that a claim of novelty is a *searched absence*, so this one was searched before
it was written up. It does not survive intact:

* **The detector is a metamorphic relation.** "Distinct inputs should produce distinct outputs" is
  an ordinary MR, and metamorphic testing exists precisely to check programs whose correct output
  is unknown — see the ACM TOSEM survey on MR generation (`10.1145/3708521`). Nothing about the
  *idea* is new.
* **The inverse is already an eval-harness practice.** `arXiv:2603.05399` duplicates dataset items
  to check that identical inputs score consistently. Same instinct, opposite direction.
* **Output validity is already treated as a dimension separate from stability** — `arXiv:2603.15840`
  (Riasat), confirmed by reading the paper rather than a search snippet.

What survives is narrower and worth stating as such: **applying output cardinality as a reporting
norm on an evaluation batch that crosses third-party tool servers**, where the failure is a
successful-looking response rather than a wrong computation, together with three measured defect
classes at three different integration boundaries and the price of not having it (a withdrawn
n=210 study). That is a refinement with a concrete cost attached, not a new technique.

*One note on how this search went, because it is the same lesson one level up.* A search summary
asserted that a paper documented harness-level silent failures misattributed to the model and
resolved by auditing platform source code — which would have been close prior art. **Both candidate
papers were fetched and neither contained it.** The summary was a plausible synthesis, and citing
it would have put a fabricated source in the ledger. A search result that answers is not the same
as a source that said so.
