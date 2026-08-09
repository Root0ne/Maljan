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
| P6 | Context Truncation | `EXPOSED` | Truncation mechanisms everywhere, **frequency never reported** |
| P7 | Prompt Sensitivity | `PARTIAL` | A structured prompt-variation study exists; production prompts are fixed and unvaried |
| P8 | Surrogate Fallacy | `EXPOSED` → `PARTIAL` | One model, one machine. Four claims **scoped 2026-08-09**; the confound itself stands until the frontier arm (C6) runs |
| P9 | Model Ambiguity | `PARTIAL` | Model **fully pinned 2026-08-09** (digest + HF revision + imatrix dataset). The **engine commit is unrecoverable** — the build recorded `unknown`; pinned by binary and source hash instead |

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

**We never used LLM-as-a-judge for scoring**, which is the common form of this failure. Every
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

**Residual:** no *systematic* robustness testing. The pitfall recommends controlled
perturbations; our only instance is the §1.10 weight-perturbation study, which perturbs our own
constants rather than the input. Input perturbation (packed vs unpacked, stripped vs symbolised,
renamed functions) is unrun and would be a real experiment.

## P6 — Context Truncation `EXPOSED`

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

**Verdict after scoping: `PARTIAL`.** The write-up half is done — all four claims now carry their
scope at the point of claim, `related-work.md` carries a section-level scope statement, and the
distinction between *negatives obtained under a favourable configuration* (which travel) and
*positives bounded by this model's speed* (which may not) is stated. The **empirical** half is
not done and cannot be closed by writing: the architecture/model confound stands until the
frontier arm runs. That is queue item **C6**, funded and scheduled. Until it lands, the honest
statement is the one now in `related-work.md` — single-model findings are not properties of an
architecture.

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

**Engine — cannot be closed, and this is P9 happening to us.** `llama-server --version` prints
`version: 0 (unknown)` and `build-info.cpp` holds `LLAMA_COMMIT = "unknown"`, because the source
tree is not a git checkout and CMake had no commit to record. **The upstream commit is not
recoverable from the artifact.** Pinned instead: engine binary **sha256 `7737b2a9…542d`**, a
**content hash over the 837 compiled source files** (`5911b128…15b8`), the compiler
(`cc 15.2.0`), the build date (2026-07-05), and an upstream anchor — the vendored `github-data`
tops out at **PR #630**. A hash of the bytes actually built is arguably a *better* identifier
than a revision name; it is nonetheless weaker as a *reproduction* instruction, and the paper
says so rather than implying a commit was recorded.

**Verdict: `PARTIAL`, and it stays `PARTIAL` permanently for the engine.** The lesson is the
transferable part and belongs in the write-up: this project reports engine-level detail almost
nobody reports — and *still* lost the engine commit, to a `git clone` that was never a clone.
Build provenance has to be captured at build time; it cannot be reconstructed afterwards.

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
3. **P9** — ~~pin the model digest and engine commit~~ **done 2026-08-09** for the model; the
   engine commit turned out to be **unrecoverable** (the build recorded `unknown`), so it is
   pinned by binary and source-tree hash and the paper says so plainly. The transferable lesson:
   build provenance must be captured at build time — it cannot be reconstructed afterwards.

And one thing to say out loud rather than assume a reviewer will notice: **P2 and P4 are clear
in a way most papers in this survey are not** — no LLM scored any result here, and augmenting
the memory corpus with generated cases was considered and refused with a citation. Against a
baseline where only 15.7% of present pitfalls are discussed at all, having a document like this
one is itself part of the answer.
