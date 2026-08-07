# Maljan — Literature Review Brief (research intake)

> **Purpose.** This document is the input for a multi-model literature review. Part A and B
> state, without inflation, what the system actually is and what it can honestly claim. Part C
> contains self-contained research briefs to hand to independent research LLMs. Part D is the
> format their answers must come back in so four reports can be merged without losing
> provenance. Part E lists the gaps in **our own** evidence — the things a reviewer will attack
> first, independent of what the literature says.
>
> Companion: [findings-log.md](findings-log.md) is the primary evidence record (every claim
> below cites a § there). This brief never restates a result more strongly than that log does.
>
> Created 2026-08-08.

---

## Part 0 — Workflow

```
  this brief  ──►  N independent research LLMs (one brief at a time)
                        │
                        ▼
                 N reports in the Part D format
                        │
                        ▼
      merge + conflict resolution + citation verification  ──►  related-work matrix
                        │
                        ▼
      gap analysis  ──►  what Maljan already answers / what it must be extended to answer
                        │
                        ▼
      experiments (Part E backlog)  ──►  results  ──►  LaTeX paper
```

Two rules for the merge stage, stated up front because they decide the paper's credibility:

1. **Every citation returned by a research LLM is treated as unverified until resolved to a
   real DOI / arXiv ID / proceedings entry.** LLM-fabricated references are the single most
   likely way this paper gets desk-rejected. The Part D format forces a verifiable identifier
   per claim; anything without one is quarantined, not cited.
2. **A gap is only a gap if it survives all N reports.** A "nobody has done X" from one model is
   a hypothesis. If three independent models with different training cutoffs all fail to name
   prior work for X, that is evidence — still to be confirmed by a targeted manual search.

---

## Part A — What the system is

A local-first, multi-agent malware analysis pipeline that produces an **attributable analyst
report + spec-valid CTI**, not a binary label. Roughly 42k LOC Python (engine + API), 14.6k LOC
TypeScript (web), 35k LOC tests (2,227 passing unit tests), 10 offline evaluation harnesses.

### A.1 The architectural claim in one line

> **LLM proposes, deterministic layer disposes** — reasoning is delegated to a small local LLM
> over decompiled/behavioural evidence; every *decidable* sub-task (taxonomy lookup, corroboration,
> validity, false-positive filtering, spec conformance) is removed from the model and executed
> deterministically.

### A.2 Layers

| Layer | What runs there | Key modules |
|---|---|---|
| **Acquisition** | PE/ELF static extraction, CAPEv2 dynamic sandbox, PCAP/network, Triage CTI | `extractors/`, `loaders/` |
| **Layer-0 (deterministic detectors)** | YARA (30 rules), Sigma (2,651 rules), import-capability (778 APIs / 13 categories → 47 techniques / 353 API entries), LOLBin, network-DGA, tool-artifact | `analysis/{yara,sigma,import_capability,lolbin,tool_artifact}_layer.py` |
| **Deterministic pre-passes** | sink-reachability triage, function-hash attribution, function-level RAG, schema pruning | `analysis/sink_reachability.py`, `function_hash_attribution.py`, `memory/function_index.py` |
| **LLM analysts** | static (Ghidra MCP ReAct, 20-tool curated allowlist), dynamic, network — each emits a structured ISR (claim + evidence + confidence + technique) | `agents/{static,dynamic,network}_analyst.py` |
| **Adjudication** | multi-layer TTP cascade (weighted, cross-layer corroboration), judge/mediator negotiation to consensus, false-positive linter, ATT&CK ID re-grounding | `analysis/ttp_cascade.py`, `agents/judge_agent.py`, `qa/fp_linter.py`, `memory/attck_validator.py` |
| **Memory / retrieval** | hybrid ATT&CK index (697 techniques; semantic rank + TF-IDF gate), Qdrant long-term case memory, function-hash store (2,226 points), family-fingerprint + case-prior RAG (both off) | `memory/` |
| **Output** | Markdown/PDF report, STIX 2.1 bundle with deterministic integrity pass, MISP export, detection-rule synthesis, degraded-run honesty banner | `reporting/`, `agents/judge_postprocess.py` |
| **Deployment** | Qwen3.6-35B-A3B (MoE, ~3B active, IQ3_K_R4) on ik_llama.cpp with hybrid CPU/GPU offload, RTX 5060 8 GiB; FastAPI + arq + Postgres + Redis + MinIO + Qdrant + Ghidra MCP, all local | `docker/`, `apps/` |

### A.3 What is deliberately *not* in it

No trained classifier anywhere in the decision path. No cloud LLM. No Android/macOS support
(§1.8, scope decision driven by the sandbox's actual coverage). These are positioning choices
with recorded rationale, not omissions.

---

## Part B — Contribution map (with honest evidence status)

Status vocabulary is the findings-log's: `IMPLEMENTED` (in code, tested) / `EXPERIMENTAL`
(measured, note N) / `OBSERVED` (reproducible, not formally studied) / `NEGATIVE` (tested, does
not help) / `UNMEASURED` (shipped but no evidence — added here, and the honest label for several).

### B.1 Positioning

| # | Claim | Status | Evidence |
|---|---|---|---|
| **C0** | A taxonomy separating *LLM-as-analyst* from *LLM-as-tool-for-a-trained-detector*, and an argument that the former fits explainable-report + no-labelled-corpus + local-hardware settings | positioning | §0, §3.1 |

### B.2 Mechanism contributions

| # | Claim | Status | Evidence / gap |
|---|---|---|---|
| **C1** | Sink-reachability triage transferred cross-domain (NPM/JS learning-based → stripped binaries) as an LLM **prompt-steering** pre-pass, with graceful empty-hint degradation | `IMPLEMENTED` | §1.1; **no isolated ablation** |
| **C2** | Two-tier attribution: exact normalized-opcode-hash code-reuse (high precision) + semantic RAG (high recall), with an anti-FP instruction-count floor | `IMPLEMENTED` | §1.2; **UNMEASURED** |
| **C3** | Falsification-before-confidence: a specific claim may exceed 0.8 confidence only if actively falsified via emulation/dataflow; ≥2 independent evidence loci required | `IMPLEMENTED` | §1.3; **UNMEASURED** |
| **C4** | *"Use a tool ≠ expose it to the model"* — 20-tool curated allowlist for the model, remaining high-value tools driven deterministically from code | `IMPLEMENTED` + `EXPERIMENTAL` | §1.4, §2.2 (~201 schemas ≈ 22k tokens; small model degrades before that scale) |
| **C5** | **Describe-then-map**: the ID-recall sub-task is removed from the model entirely — the analyst describes behaviour, a deterministic retrieval index assigns the ATT&CK ID | `IMPLEMENTED` + measured | §1.5, §1.5.1, §1.5.2 — **the strongest contribution** |
| **C5a** | Ranking quality and gate quality are *separate axes* of a retrieval-based label assigner; composing per-axis winners (semantic rank + TF-IDF gate) beats either pure backend on both | `EXPERIMENTAL` N=4,913 | §1.5.1 (TRAM2): hybrid top-3 0.392 & gate +0.115 vs TF-IDF 0.329/+0.085, semantic 0.392/+0.019 |
| **C6** | Multi-layer TTP cascade: per-layer trust weights (yara .90 → network .20) × cross-layer corroboration multipliers, with deterministic Layer-0 pooled by max and LLM layers by mean | `IMPLEMENTED` | `ttp_cascade.py`; **UNMEASURED — see E.1, this is the biggest hole** |
| **C7** | Deterministic CTI integrity + calibrated honesty: STIX 2.1 referential-integrity pass, cascade-reconciled bundle, `DEGRADED RUN` banner, "not determined" instead of a fake 0.00-confidence family | `IMPLEMENTED` | §1.6; **UNMEASURED as a quality claim** |
| **C8** | Category-driven STIX schema pruning: an advisory prompt hint whose measured benefit is **completion under a time budget**, not mapping accuracy | `EXPERIMENTAL` n=17 paired | §1.7.1 — empty-fallback bundles 6/17 → 1/17 |

### B.3 Negative and methodological results (publishable as such)

| # | Result | Status | Evidence |
|---|---|---|---|
| **N1** | Single-run parsed-claim count is **not a valid measurement instrument** for LLM structured findings — three runs at different budgets inverted the ranking of the same arms | `NEGATIVE` | §3.4 |
| **N2** | At **equal total budget**, view decomposition trades grounding for volume (mono 7 claims/0.334 grounded → 4-view 18/0.142); tier reasoning is least grounded (0.070). The earlier "2× completeness" was a budget artifact and is retracted | `EXPERIMENTAL` n≈8–9/arm | §3.2 → §3.6 |
| **N3** | Zero-shot nearest-prototype category inference over averaged ATT&CK descriptions is worse than a hand-written keyword table (0.376 vs 0.792 full) — the dynamic win requires *few-shot* in-domain prototypes | `NEGATIVE` N=101 | §1.7 |
| **N4** | Auto-correcting *valid-but-weakly-aligned* technique IDs damages ~38% of correct IDs to recover ~21% of wrong ones, and the alignment gate cannot separate the two → restrict auto-correction to the provably-safe invalid→valid sub-operation | `NEGATIVE` → fix | §1.5.2 |
| **N5** | An LLM narrative does **not** beat a deterministic template on faithfulness+coverage (F1 delta −0.111, CI excludes 0); both are perfectly faithful (precision 1.0, zero hallucination). The LLM's only edge is structural readability (0.73 vs 0.00) | `EXPERIMENTAL` n=15 | §3.5 |
| **N6** | A case-prior RAG can have a **working retriever and a query that never reaches it**: corpus-native F1 0.620 vs frequency-prior 0.424, but production-query F1 0.111 vs prior 0.123. Mandatory control = the label-frequency prior at equal budget | `NEGATIVE` | §1.5.3 (2026-08-08) |
| **N7** | A reproducible small-model pathology: **degenerate technique-ID loop** on under-specified 600+ label recall; sampler penalties are necessary-but-insufficient (they convert a tight loop into a slow ID-enumeration ramble) | `OBSERVED` → fixed | §3.3 |
| **N8** | MTP / speculative decoding gives no throughput gain on this A3B MoE and regressed quality | `NEGATIVE` | §2.3 |

### B.4 Empirical systems results

| # | Result | Status | Evidence |
|---|---|---|---|
| **E1** | **7-year temporal-drift study, n=210** (30/cohort × 2020–2026, 27 families, real MalwareBazaar binaries, static-only, local 35B): earliest→latest F1 delta **−0.004**, all cohort CIs overlap → **no measurable concept drift**; hallucination ≤0.011 across every cohort | `EXPERIMENTAL` n=210 | §4 Item 5 — **the flagship empirical result** |
| **E2** | On a hybrid-offload MoE deployment, KV cache ≈10.85 KiB/token and **context length barely moves system RAM**; the RAM cost is the offloaded weights. A closed-form GGUF estimate over-predicted KV by ~4× | `EXPERIMENTAL` | §2.1 |
| **E3** | Whole-tool-catalogue exposure (~201 schemas) is infeasible for a ~3B-active model independently of context size | `EXPERIMENTAL` | §2.2 |

### B.5 Assets that are themselves contributions

- **10 offline evaluation harnesses** with bootstrap CIs, checkpoint/resume, and unit-tested
  scoring arithmetic (`eval_technique_mapping`, `eval_autocorrect_ablation`, `eval_category_inference`,
  `eval_hint_ablation`, `eval_narrative_quality`, `eval_view_decomposition`, `eval_temporal_drift`,
  `eval_function_rag`, `eval_family_rag_retrieval`, `eval_attck_case_rag`).
- **A vendored, reproducible drift manifest** (210 dated samples, metadata only) + family→ATT&CK
  ground-truth fixtures for 700+ families.
- **A nine-source dataset survey** with per-source verdicts against four use-axes (§4 `SURVEY`),
  whose central finding is that **no public source provides per-sample ATT&CK TTP labels** or a
  decompiled-code↔ATT&CK corpus.

---

## Part C — Research briefs

Hand these to the research LLMs **one at a time**. Each is self-contained: the model does not
need to know what Maljan is beyond what the brief says. Each asks the user's four questions
(state of the art → gaps → do we close them → how to extend) scoped to one theme.

**Preamble to paste before every brief:**

> You are performing a rigorous academic literature review for a systems-security paper. Cover
> 2022–2026 with emphasis on 2024–2026. Prioritise peer-reviewed venues (IEEE S&P, USENIX
> Security, CCS, NDSS, ACSAC, RAID, DIMVA, ISSTA, ICSE, FSE, MSR, EuroS&P, AsiaCCS, DFRWS,
> Computers & Security, TDSC, TIFS) and well-cited arXiv preprints. For **every** claim you
> make, give a verifiable identifier: DOI, arXiv ID, or full proceedings citation. If you are
> not certain a paper exists, say so explicitly rather than producing a plausible-looking
> citation — a fabricated reference is worse than an admitted gap. Distinguish clearly between
> "I found no work on this" and "no work exists". Answer in the output format given at the end.

---

### R1 — LLM agents for binary reverse engineering and malware analysis

**Scope.** Systems where an LLM reasons over *binaries* (disassembly, decompiled pseudo-C,
imports, sandbox traces) rather than over source code or Android manifests. Include tool-using /
agentic setups (ReAct, MCP, function calling) driving a reverse-engineering backend
(Ghidra/IDA/Binary Ninja/angr).

**Our position.** A small **local** open-weight model (~3B active MoE) drives Ghidra through a
deliberately curated 20-tool allowlist; high-value tools are invoked deterministically from code
rather than exposed to the model. We measured that exposing the full ~201-tool catalogue (≈22k
tokens of schema) is infeasible for a model this size.

**Answer these:**
1. What are the state-of-the-art LLM-agent systems for binary RE / malware analysis? Give an
   architecture-by-architecture comparison: what the LLM decides vs what is deterministic; local
   vs cloud model; tool interface; evaluation.
2. What is **missing** in this literature? Specifically: (a) is anything evaluated on *local,
   small, open-weight* models, or is the field GPT-4-class-only? (b) does anyone report tool-
   selection degradation as a function of catalogue size? (c) is there work on *which* RE
   sub-tasks should be delegated to a model vs executed deterministically?
3. Does the approach above address those gaps? Where does it fall short?
4. What would have to be built or measured to close the remaining gaps convincingly?

---

### R2 — LLM-based ATT&CK technique mapping and TTP extraction

**Scope.** Mapping evidence (report prose, behaviour, code) to MITRE ATT&CK technique IDs with
LLMs and/or retrieval. Include TRAM/TRAM2, rcATT and classical baselines, retrieval-based
mappers, and any work on hallucinated/invalid technique IDs.

**Our position.** We found a reproducible small-model pathology: asked to *recall* an ID from a
600+ label taxonomy, the model enters a degenerate loop emitting wrong IDs until the budget is
exhausted; sampler penalties only convert a tight loop into a slow enumeration ramble. Our fix
removes the recall sub-task from the model: the analyst **describes behaviour only**, and a
deterministic retrieval index assigns the ID ("describe-then-map"). We further measured that
*ranking* quality and *alignment-gate* quality are separate axes (semantic embeddings rank
better but their scores do not separate correct from wrong; TF-IDF ranks worse but gates
cleanly), and that composing the per-axis winners beats either pure backend on both
(N=4,913 TRAM2 pairs). We also measured that auto-correcting valid-but-weak IDs is net-negative
(damages 38% of correct IDs to recover 21% of wrong ones).

**Answer these:**
1. State of the art for automated ATT&CK technique mapping — LLM-based, retrieval-based, and
   supervised. What accuracy is reported, on what ground truth, and is it comparable across papers?
2. Gaps. Specifically: (a) does anyone separate *description* from *taxonomy assignment* as an
   architectural decision, or is the ID always generated by the model? (b) is the invalid /
   hallucinated technique-ID failure mode documented anywhere? (c) does anyone report retrieval
   *ranking* and *thresholding/gating* as distinct metrics? (d) is auto-correction of model-
   assigned IDs studied, including its regressions?
3. Do the results above fill those gaps? Which are genuinely novel and which are reinventions?
4. What further experiments would make the "describe-then-map" claim publishable at a top venue?

---

### R3 — Multi-agent LLM systems and structured consensus for security analysis

**Scope.** Multi-agent LLM architectures where agents with different evidence views negotiate,
debate, vote, or are adjudicated toward a decision. Include LLM-debate / multi-agent-debate
literature, judge/critic architectures, and any security-domain application.

**Our position.** Three domain analysts (static / dynamic / network) each emit structured
findings with evidence and confidence; a judge/mediator negotiates to a consensus threshold over
bounded revision rounds, and a deterministic cascade weights each finding by *which independent
evidence layers* corroborate it (rule-based layers weighted above model-based ones). We have
found and fixed a specific pathology: a revision round run on an analyst that had **no data**
echoed its peers' report back under its own domain label, which the corroboration counter then
read as independent confirmation — i.e. **multi-agent architectures can manufacture false
corroboration when an agent's evidence channel is empty**.

**Answer these:**
1. State of the art in multi-agent LLM debate/consensus, and specifically its use in security
   (malware, IR, CTI, vuln analysis). How is consensus operationalised and how is it evaluated?
2. Gaps. Specifically: (a) is there work quantifying whether multi-agent debate actually beats a
   single well-prompted agent at equal total token budget? (b) is *sycophancy / echo between
   agents* measured in security settings? (c) does anyone weight agent opinions by the
   independence or trustworthiness of the underlying evidence channel rather than by
   model-reported confidence? (d) is the "agent with no data still speaks" failure mode named
   anywhere?
3. Does the architecture above address them? What does it demonstrably not address?
4. What ablation would be required to show that the negotiation + cascade earns its cost?

---

### R4 — Grounding, hallucination control, and confidence calibration in LLM security analysis

**Scope.** Techniques that constrain an LLM's security claims to its evidence: grounding checks,
verification-before-assertion, self-consistency, abstention, calibration of small models.

**Our position.** Several layered mechanisms: a prompt-level *falsification-before-confidence*
protocol (a claim naming a specific algorithm/key may exceed 0.8 confidence only after active
falsification via emulation or backward dataflow; ≥2 independent evidence loci required for high
confidence), a parse-time claim-consistency gate, a post-hoc structural false-positive linter,
and a deterministic report layer that renders an explicit degraded-run banner rather than a
confident-looking verdict when evidence was thin. Measured hallucination on 210 real samples was
≤0.011 across all cohorts.

**Answer these:**
1. State of the art for grounding and hallucination control in LLM security analysis. What is
   actually measured, and how is "hallucination" defined in each case?
2. Gaps. Specifically: (a) is *tool-executed falsification as a precondition for high confidence*
   a known technique? (b) is there work on calibrating **small local** models for security
   assertions? (c) is honest degradation / abstention reporting studied as an output-quality
   property? (d) what hallucination rates are reported on real (not synthetic) malware corpora?
3. Does our stack address them? Which mechanism is genuinely novel vs standard practice under a
   different name?
4. How should the falsification-before-confidence protocol be evaluated to be a contribution
   rather than a design description?

---

### R5 — Retrieval-augmented generation for malware analysis and CTI

**Scope.** RAG applied to malware/CTI: retrieval over prior cases, over decompiled functions,
over CTI corpora, over ATT&CK. Include TraceRAG and any code-retrieval-for-RE work.

**Our position.** Multiple retrieval tiers, with **measured** outcomes in both directions:
per-sample function-level retrieval (recall 1.0 of the seeded malicious core at ~75% input-token
reduction); an exact opcode-hash tier for code reuse; and a cross-sample ATT&CK case-prior RAG
that we **measured and disabled** — its retriever is good in its own vocabulary (F1 0.620 vs a
0.424 frequency prior) but with the query production actually sends it scores 0.111 against the
prior's 0.123, because query and corpus share only boilerplate. Our dataset survey found **no
public corpus** pairing decompiled code with ATT&CK labels.

**Answer these:**
1. State of the art for RAG in malware analysis / CTI. What is retrieved, from what corpus, and
   what improvement is demonstrated?
2. Gaps. Specifically: (a) do these papers report a **retrieval-free baseline**, and in
   particular a label-frequency prior when the label distribution is skewed? (b) is query/corpus
   vocabulary mismatch identified as a failure mode? (c) are negative RAG results published at
   all in this area? (d) does a public decompiled-code↔ATT&CK corpus exist that we missed?
3. Does our work fill them — in particular, is "the retriever works but the query never reaches
   it, and the frequency prior wins" a novel, publishable negative result?
4. If we wanted the case-prior RAG to actually work, what does the literature suggest — and what
   corpus would have to be built?

---

### R6 — Evaluation methodology, benchmarks, and ground truth for LLM malware analysis

**Scope.** How this field measures itself: datasets, ground truth for TTPs, metrics, statistical
practice, concept-drift evaluation, reproducibility.

**Our position.** We ran a 7-year drift study (n=210 dated real binaries, 30/cohort, 27
families) and found **no measurable drift** (earliest→latest F1 delta −0.004, all CIs overlap).
We use family-level ATT&CK `uses` sets as per-sample ground truth and are explicit that this
imposes a structural recall ceiling, so only the *relative* delta is claimed. We also produced a
methodological negative result: a single-run parsed-claim count inverted the ranking of the same
arms across decoding budgets, i.e. it is not a valid instrument.

**Answer these:**
1. What benchmarks, datasets, and metrics does the LLM-for-malware field currently use? Which
   are actually comparable across papers?
2. Gaps. Specifically: (a) does a per-sample ATT&CK ground-truth corpus exist for Windows/Linux
   binaries, or does everyone fall back to family-level labels? (b) how many papers report
   confidence intervals, repeats, or equal-budget controls? (c) is temporal/concept drift
   evaluated for *LLM-based* (not trained-classifier) malware analysis? (d) are there known
   instrument-validity critiques of LLM evaluation in this domain?
3. Do our harnesses and the drift study address these? Where is our methodology still weak?
4. What would a *credible* benchmark for this task look like, and can we build or bootstrap it?

---

### R7 — Local, small, open-weight models for security analysis (deployment constraints)

**Scope.** On-premise / air-gapped / privacy-constrained deployment of LLMs for security work.
Quantisation, MoE offload, throughput/latency, and what capability is actually lost vs frontier
models.

**Our position.** Everything runs locally: a 35B-total/3B-active MoE at IQ3_K_R4 on a single
8 GiB consumer GPU with hybrid CPU offload, alongside Ghidra, a sandbox, and the full service
stack. Malware samples never leave the machine — which is a *requirement*, not an optimisation.
We measured KV-cache scaling (≈10.85 KiB/token; context length barely moves system RAM on a
hybrid-offload MoE — the cost is the offloaded weights) and recorded a negative result on
speculative decoding for this architecture.

**Answer these:**
1. What does the literature say about small/local LLMs for security analysis? Which tasks are
   reported to work at 7–35B open-weight scale and which are not?
2. Gaps. Specifically: (a) is there a systematic capability comparison for *malware analysis*
   between local open-weight and frontier models? (b) is the confidentiality argument (samples
   must not leave the premises) treated as a first-class design constraint anywhere? (c) are
   deployment economics (VRAM, offload, throughput) reported in security papers at all?
3. Does our deployment evidence address them?
4. What comparison would be needed — e.g. the same pipeline behind a frontier model — and what
   would that comparison legitimately prove?

---

### R8 — Automated CTI report generation and machine-readable output quality

**Scope.** LLM-generated analyst reports, STIX/MISP generation, detection-rule synthesis, and how
their *quality* is assessed.

**Our position.** The pipeline emits a Markdown/PDF analyst report, a STIX 2.1 bundle passed
through a deterministic referential-integrity + cascade-reconciliation pass, a MISP export, and
synthesised detection rules. We measured that an LLM narrative does **not** beat a deterministic
template on faithfulness+coverage (paired F1 delta −0.111, CI excluding 0; both perfectly
faithful) — its only edge is structural readability. We also found that an advisory
schema-pruning hint's real effect was **completion under a time budget** (empty-fallback bundles
6/17 → 1/17), a channel invisible to mapping-accuracy metrics.

**Answer these:**
1. State of the art in automated CTI report / STIX generation with LLMs, and how output quality
   is evaluated.
2. Gaps. Specifically: (a) is spec-validity / referential integrity of generated STIX ever
   checked? (b) is an LLM narrative compared against a *deterministic template* baseline
   anywhere? (c) is "honest degradation" (a report that declares its own evidence was thin)
   treated as a quality dimension? (d) is generation *completion* under an operational budget
   measured, or only accuracy?
3. Do our results fill them?
4. What would make the "deterministic template beats the LLM on faithfulness" result robust
   enough to publish as a caution to the field?

---

## Part D — Required output format (paste at the end of every brief)

```markdown
## 1. State of the art
For each system/paper (aim for 8–20):
- **[Short name]** — Authors, Venue, Year. `DOI or arXiv ID`
  - What it does (2 sentences)
  - LLM role: analyst / feature-summariser / data-generator / classifier / other
  - Model used: frontier-cloud / open-weight-local / both — and size
  - Evaluated on: dataset, N, ground truth
  - Headline result (as the paper states it, with the metric named)
  - Confidence that this paper exists as cited: HIGH / MEDIUM / LOW

## 2. Gaps in the literature
For each gap:
- **[Gap]** — one sentence
  - Evidence it is a gap: which surveys/papers explicitly call it future work, or which
    searches returned nothing
  - Severity: is this a gap the field cares about, or an unexplored corner nobody wants?
  - Confidence: HIGH / MEDIUM / LOW

## 3. Does the described approach close these gaps?
Per gap: CLOSED / PARTIALLY / NOT CLOSED — with a one-paragraph justification and, where
partial, the precise missing piece.

## 4. How to extend to close the remaining gaps
Ranked by (research value ÷ effort). For each: what to build or measure, what result would
constitute closing the gap, and what the likely counter-argument from a reviewer would be.

## 5. Verification notes
- Citations you are confident about: [list]
- Citations you are NOT confident about: [list]
- Questions you could not answer from your knowledge: [list]
```

---

## Part E — Gaps in *our own* evidence

These are independent of the literature. A reviewer will find them whether or not any related
work exists. Ordered by how badly they hurt the paper.

### E.1 The cascade — the core adjudication mechanism — has never been ablated `CRITICAL`

`ttp_cascade.py` is the concrete instantiation of "deterministic layer disposes": layer weights
(yara 0.90 … network 0.20), cross-layer corroboration multipliers (1.00 → 1.90), max-pooling for
rule-based layers vs mean for model-based ones. **None of it is measured.** The weights are
plausible and unjustified; there is no experiment showing that corroboration-weighted output
beats a flat union of the same claims. This is the most attackable part of the paper — the
central mechanism is the least evidenced one.

*Needed:* an ablation on the n=210 corpus — flat union vs cascade, and a weight-sensitivity
analysis showing the conclusion is not an artifact of the chosen constants.

### E.2 Multi-agent negotiation is unevaluated `CRITICAL`

The judge/mediator consensus loop is in the project's own framing ("structured consensus") and
there is no experiment showing it improves anything over a single judge pass. Its cost is
enormous (revision rounds dominate wall-clock). N1's warning applies to us: we must not claim it
works without an equal-budget comparison.

*Needed:* single-pass vs negotiated consensus at equal total token budget, scored on TTP F1 and
grounding, N≫1 with CIs.

### E.3 The entire empirical result is static-only `MAJOR`

The flagship n=210 study ran with `SANDBOX__BACKEND=mock`. The dynamic path (CAPEv2, now verified
working end-to-end) has **no measured result**, yet §4 argues "dynamic analysis is required to
lift recall". That is currently an argument, not a measurement — and it is exactly the claim a
dynamic-vs-static arm would settle.

*Needed:* a dynamic-enabled cohort (even n≈30) against the same ground truth, reported as a
paired delta against the static-only numbers.

### E.4 No baseline system comparison `MAJOR`

Nothing is compared against: CAPE's own signature output, a commercial sandbox's TTP list, or the
same pipeline driven by a frontier model. Without at least one, "our pipeline achieves F1 0.08"
has no referent — the number could be excellent or terrible for the task.

*Needed:* at minimum, CAPE-signature-derived TTPs as a zero-LLM baseline on the same samples;
ideally also one frontier-model arm to separate *architecture* from *model capability*.

### E.5 Layer-0 sources are individually unmeasured `MODERATE`

2,651 Sigma rules, 30 YARA rules, 778-API capability map — no per-source contribution analysis.
Which layers actually carry the corroboration signal? A leave-one-layer-out study is cheap
(deterministic, no LLM) and directly supports C6.

### E.6 The YARA corpus is thin `MODERATE`

30 in-house rules against 2,651 Sigma rules. If YARA carries the highest cascade weight (0.90),
30 rules is a narrow base for the layer trusted most. Flagged in the backlog as pending a licence
review.

### E.7 No human evaluation `MODERATE`

The report is the product, and no analyst has scored one. N5 measured faithfulness/coverage
mechanically; readability — the LLM narrator's *only* demonstrated edge — is exactly the
dimension that needs human judgement.

### E.8 Single model, single hardware `MINOR but must be stated`

Every LLM result is Qwen3.6-35B-A3B on one machine. Model-specific effects cannot be separated
from architectural ones. At least one second open-weight model on the key experiments would let
us say "architecture" instead of "this model".

---

## Part F — Candidate paper framings

Recording these now so the literature review can be read against a concrete target. Not a
decision.

| Framing | Core claim | Rests on | Risk |
|---|---|---|---|
| **F1 — System paper** | A local-first multi-agent architecture producing attributable CTI, with "LLM proposes, deterministic layer disposes" as the organising principle | C0, C4, C5, C6, C7 + E1/E2/E3 evidence | The unmeasured mechanisms (E.1, E.2) are load-bearing |
| **F2 — Describe-then-map** | Removing taxonomy recall from a small model and giving it to deterministic retrieval; ranking vs gating as separate axes; auto-correction's regression | C5, C5a, N4, N7 | Narrower, but the best-evidenced story we have today |
| **F3 — Negative-results / methodology paper** | How LLM-for-malware evaluation goes wrong: invalid instruments, budget artifacts, missing frequency-prior baselines, RAG that answers from its corpus, LLM narratives losing to templates | N1, N2, N3, N5, N6 + §1.5.3 | Venues for negative results are fewer; but this material is unusually strong and honest |
| **F4 — Empirical drift study** | LLM-based static malware analysis is temporally stable across 7 years where trained classifiers drift | E1 | Needs the trained-classifier comparison arm to land the contrast |

**Current honest read:** F2 and F3 are supported *today*. F1 is the ambition and needs E.1–E.4.
F4 needs a comparison arm. The literature review should be read primarily as a test of which of
these is actually novel.
