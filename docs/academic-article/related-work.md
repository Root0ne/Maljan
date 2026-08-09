# Related Work

> **Draft, 2026-08-08.** Written from [`research-briefs/novelty-ledger.md`](research-briefs/novelty-ledger.md);
> every citation was verified by fetching its record (see
> [`research-briefs/incoming/CITATION-AUDIT.claude-web.md`](research-briefs/incoming/CITATION-AUDIT.claude-web.md)).
> Numbered references match [`findings-log.md`](findings-log.md) §References.
>
> **Organising principle:** each subsection ends by stating plainly what this work does *not*
> claim. Four of our original contribution candidates are prior art, and a related-work section
> that hides that is the one a reviewer breaks.
>
> **Revised 2026-08-09 after the A4 counter-search.** Three claims this draft originally presented
> as ours — the rank-versus-gate separation, the auto-correction asymmetry, and the degenerate-loop
> mitigation — turned out to be domain instances of results already established in **IR score
> calibration**, **grammatical error correction** and **neural text degeneration**. None was
> refuted; each keeps a mechanism worth reporting. The sentences that claimed novelty have been
> rewritten rather than deleted, and where an earlier draft was wrong this file now says so in
> place. §5's temporal paragraph was also re-framed: its axis is *input era*, not
> training-recency, and the earlier text conflated them.

---

## 1. Mapping evidence to ATT&CK

Automated ATT&CK technique extraction has moved from supervised classifiers — TRAM, rcATT,
TTPDrill — through neural extractors such as EXTRACTOR, AttacKG and LADDER, to
retrieval-augmented generation. **TechniqueRAG** [7] pairs off-the-shelf retrievers with an
instruction-tuned re-ranker and fine-tunes only the generator, motivated by the field's data
scarcity: ATT&CK defines over 550 (sub-)techniques while roughly 10,000 annotated examples exist
publicly. Its hierarchical successor injects the tactic→technique taxonomy as an inductive bias,
filtering at tactic level first to cut the candidate space by 77.5% for a 3.8% F1 gain and a
62.4% latency reduction. **TTPrint** takes an orthogonal route, decomposing reports into atomic
behaviours and retaining only candidates supported by both localised evidence spans and the
MITRE definition.

Büchel et al.'s SoK [5] is the field's own assessment. Re-evaluating 40+ systems in a unified
setting, they report a performance ceiling existing approaches have not crossed, that existing
solutions are "largely incomparable" because they use custom ontologies and inaccessible
datasets, and — counterintuitively — that **traditional NLP approaches outperform modern
embedder-based and generative approaches in realistic settings**.

**Position.** Our describe-then-map design removes technique-ID recall from the model entirely:
the analyst describes behaviour and a deterministic index assigns the identifier. This is a
domain instantiation of **Infer-Retrieve-Rank** [6], which established the general program —
multi-step LM/retriever interaction that decouples inference from assignment over a
many-thousand-class label space — reaching state of the art on three benchmarks with tens of
labelled examples. Ours is stricter than [6] and than [7]: in both of those the language model
still ranks or selects among retrieved candidates, whereas here it never emits an identifier and
any correction is gated to the provably-safe invalid→valid case. **We do not claim the idea.**

What we contribute is a decomposition of the SoK's insight. [5] reports that embedders lose; we
measure *where*. Ranking quality and gate quality behave as separable axes here: dense embeddings
rank better while their scores barely separate a correct pick from a wrong one, and a lexical
index ranks worse while gating cleanly. Composing the per-axis winners beats either pure backend
on both, measured on TRAM2 (N=4,913) and replicated on the independently annotated AnnoCTR
corpus [15].

**The separation itself is not ours, and an earlier draft of this section claimed it was.**
Abdallah et al. [16] evaluate retrieval **confidence** — AUROC for predicting query success — as a
dimension explicitly distinct from retrieval effectiveness, find calibration "consistently weak
across model families", and conclude raw scores are "unreliable for downstream routing without
additional calibration". That is the general statement, over more retrievers than we test. What
remains ours is narrower and specific: the **inversion** — that in this task the *lexical* backend
is the better gate while the *semantic* one is the better ranker, so the two axes have different
winners and can be composed. We found that inversion neither asserted nor excluded elsewhere,
which is a weaker absence than the one we first claimed, and we say so.

We also report a result about correction policy. Auto-correcting *valid but weakly-aligned*
identifiers damages 38% of already-correct labels to recover 21% of wrong ones. **The asymmetry is
not a discovery**: grammatical error correction has studied over-correction for years and
evaluates with F0.5 precisely because a false correction costs more than a missed one [17], and
recent work targets the failure directly. Our contribution is the *mechanism* in this setting:
correct-but-weak and wrong-but-valid identifiers are **not separable by an alignment score**, so
the valid→valid swap cannot be safely tuned at any error rate — which is why the shipped policy is
restricted to the invalid→valid case, where zero regression holds by construction rather than by
tuning.

Finally, the failure that motivates removing identifier recall in the first place. Asked for an
ATT&CK identifier it does not know, the model enters a degenerate loop, proposing and re-proposing
wrong identifiers until the budget is gone. **The loop is not novel and neither is the inadequacy
of the obvious remedy:** neural text degeneration is a studied phenomenon with an established
account rooted in self-reinforcement and training-data repetition [18], and the limits of a
uniform repetition penalty are known — it damages tokens that legitimately recur. We reproduce
that here and can add one engine-level detail, that the server honours `repeat_penalty` while
silently ignoring three sibling parameters, which converts a tight loop into a slower enumeration
without fixing it.

What we can contribute is the **consequence**. The degeneration literature measures repetition
rate and text quality; here the budget is exhausted inside an operational deadline, the verdict
stage times out, and the analyst receives an **empty STIX bundle** — degeneration as a failure to
*deliver*, not a failure of prose. We measure that channel directly (§1.7.1: empty bundles 6/17
versus 1/17). Constrained decoding would also solve the original loop, and we say so; the point is
that the cheaper mitigation a practitioner reaches for first does not.

## 2. LLM agents over binaries

Agentic systems now drive reverse-engineering backends through tool interfaces, and the model
tier splits sharply by role. Fine-tuned binary specialists are overwhelmingly small and
open-weight — ReCopilot on Qwen2.5-Coder-7B, LLM4Decompile at 1.3–33B, Nova — while the
*tool-driving* agents use frontier models. **TTPDetect** [8] is the closest system to ours: it
identifies TTPs in **stripped malware binaries** using dense plus neural retrieval to narrow
analysis entry points, then a function-level agent with incremental context retrieval, reporting
93.25% precision and 93.81% recall at function level and 87.37% precision on real-world malware.

**Position.** We do not claim binary evidence as an input modality; [8] holds that ground. Two
differences remain and only one is currently defensible. First, [8] appears to demonstrate on a
cloud model while our pipeline runs on a ~3B-active local MoE — a deployment claim, addressed in
§4 rather than here. Second, [8] reasons at function level over decompiled code while we fuse
six deterministic detectors, three domain analysts and a corroboration cascade; that is a
different system, but "different" is not a contribution until the difference is measured.

The one gap we do occupy is tool-catalogue scale. Degradation of tool selection as the catalogue
grows is documented generally — LongFuncEval reports a 7–85% performance drop as the tool count
increases, and reducing an edge model's catalogue from 46 to 19 tools cuts execution time by up
to 70% — but has not been measured for a reverse-engineering catalogue, where schemas are large
and tools semantically overlap. Our finding that exposing ~201 Ghidra MCP tools (≈22k tokens of
schema) is infeasible at this model scale, motivating a curated 20-tool allowlist with
high-value tools invoked deterministically from code, is the domain instance. It is a single
feasibility point rather than a degradation curve, and we say so.

## 3. Multi-agent consensus

Multi-agent debate has become a standard pattern, including in security: PhishDebate assigns
four specialised agents to distinct views of a webpage under a moderator and judge, reporting
98.2% recall and improvements over single-agent and chain-of-thought baselines.

Two 2026 results change how such claims must be read. Tran and Kiela [11] hold the reasoning
token budget constant and find single agents consistently match or beat multi-agent systems on
multi-hop reasoning, supported by an information-theoretic argument from the Data Processing
Inequality: under a fixed budget with good context utilisation, decomposition introduces
communication bottlenecks that lose information. Bertalanič and Fortuna [10] reach the same
conclusion on 7–8B open-weight models, where debate consumed 2.1–3.4× more tokens for equal or
lower accuracy, and name three failure modes — **sycophantic conformity** (modal adoption up to
85.5%), contextual fragility, and consensus collapse discarding correct answers already present
in the generation pool.

**Position.** We do not claim that multi-agent analysis beats a single agent, and we report the
equal-budget comparison rather than assuming it. Both [10] and [11] scope their negative results
to *homogeneous* agents decomposing a *single* context, and both name the exception — degraded
or noisy context — which is the regime a 600-import binary plus a sandbox report plus network
capture occupies. Whether heterogeneous evidence-channel decomposition survives the control that
homogeneous debate fails is the question our ablation asks.

Our contribution here is a failure mode adjacent to [10]'s. Sycophantic conformity arises from
majority pressure among agents holding the same information. We observed a distinct mechanism:
an analyst whose **evidence channel was empty** paraphrased its peers, and because the echo
returned tagged with that analyst's own domain, the corroboration counter read it as independent
confirmation — promoting a single-source finding to *corroborated* and weighting it above the
source it was copied from. In a security pipeline the harm is not a wrong answer but a
**fabricated independent confirmation**.

Finally, weighting evidence by source reliability and discounting non-independent sources is
Dempster–Shafer theory, decades old. Our cascade is an instance of it with hand-chosen constants,
and we treat that as a limitation: measuring five perturbations of those constants — including
inverting the most- and least-trusted layers — changed the top-10 ranking on 10.6–27.5% of
samples and the corroborated set on **none**, because the corroboration decision is a function
of layer count alone.

## 4. Local deployment

Confidentiality-driven local deployment is established rather than novel. **REx86** [12]
fine-tunes eight open-weight models for x86 reverse engineering explicitly because
"cloud-hosted, closed-weight models pose privacy and security risks and cannot be used in
closed-network facilities", and validates with a 43-participant user study in which line-level
comprehension improved significantly (p=0.031) while the correct-solve rate rose from 31% to 53%
without reaching significance (p=0.189). The capability gap is quantified: the UK AI Security
Institute places open-weight cyber capability 4–7 months behind the closed frontier, narrowing
from 6–10 months, at roughly 45× lower cost per task.

**Position.** We inherit this constraint and cite it; we do not claim it. Our deployment
contribution is narrower and practitioner-facing: on a hybrid-offload MoE, KV cache costs
≈10.85 KiB/token and **context length barely moves system RAM** because the cost is the
offloaded weights — a closed-form estimate over-predicted KV by ~4× and was overturned by
measurement — and speculative decoding gave no throughput gain on this architecture. We found no
comparable deployment-economics reporting for a complete local security pipeline.

## 5. Evaluation practice

This work's methodological results belong to an established critique tradition rather than
preceding it. Arp et al.'s *Dos and Don'ts* identified ten pitfalls in ML-for-security;
**Chasing Shadows** [9] is its direct successor, surveying **all 72** peer-reviewed
LLM-security papers from 2023–2024 and finding that **every one** contains at least one of nine
pitfalls, with only 15.7% explicitly discussed. Broader benchmark audits reach the same place
from the construct-validity direction across 445 LLM benchmarks.

**Position.** Our instrument-validity finding — that a single-run parsed-claim count produced
contradictory rankings of the same arms across decoding budgets — is a **worked example** inside
[9]'s category, not a new observation, and we present it as such: the nuisance parameter
identified, the inversion measured. Likewise our narrative result. That template-based
generation favours faithfulness while neural generation favours fluency is textbook data-to-text;
what differs is the mechanism. In our paired comparison both arms were perfectly faithful — zero
hallucinated techniques, precision 1.0 — so the entire F1 deficit came from **coverage**, not
from hallucination. The LLM did not invent; it omitted.

Two evaluation results appear to be unoccupied. First, a case-prior retriever that is genuinely
good in its own vocabulary (F1 0.620 against a 0.424 label-frequency prior) but scores 0.111
against that prior's 0.123 when queried the way production queries it, because query and corpus
share only their boilerplate — dense retrieval being the standard remedy for vocabulary mismatch
makes this a failure of the remedy, visible only in the retriever's **score distribution** while
top-k accuracy stayed healthy. A published negative RAG result in malware analysis exists [13],
by a different mechanism — retrieved context diluting a signal-extraction task — and the
requirement to compare against a trivial label-only baseline is long established [14]. Second,
an advisory prompt hint whose measurable effect was **completion under an operational time
budget** rather than mapping accuracy, reducing empty fallback bundles from 6/17 to 1/17; we
found no work measuring generation completion as a channel through which prompt changes act.

Finally, temporal stability — and here the axis matters more than the result. There is a
substantial literature on **temporal generalisation** in language models, and its finding is
degradation: performance falls as evaluation moves away from the training period, and scale does
not close the gap [19]. That work varies the **distance between training time and test time**.
Our study varies something else. The model is **fixed**, and what changes is **the era of the
input binary** — which is concept drift in the malware-detection sense, applied to an LLM analyst,
rather than temporal misalignment of the model itself.

On that axis we find no LLM-based equivalent. Across 210 dated real binaries spanning 2020–2026 we
measure an earliest-to-latest F1 difference of −0.004, bounding drift at ≤0.040 F1 over seven
years at 95% confidence, with the study powered to detect δ ≥ 0.05. We state the bound rather than
claiming absence, and note that its width relative to an absolute F1 of 0.055–0.089 makes the
stability claim a coarse one. The prior from [19] runs the other way, which is what makes a null
worth reporting here — provided, as above, that the axis is named.

## Scope of every empirical statement above

Each of our results cited in this section was produced on **one model on one machine**:
Qwen3.6-35B-A3B at IQ3_K_R4 quantisation, served by ik_llama.cpp `llama-server` on a single
RTX 5060 / 31 GiB host, with the exact model revision, GGUF digest and engine commit recorded in
the reproducibility appendix. Where a statement concerns retrieval or the deterministic cascade
rather than generation, no model was involved at all and the binding limit is the index and the
corpus instead; those are marked at the point of claim.

We state this here rather than only in Threats to Validity because [9]'s **surrogate fallacy** is
the pitfall this work is most exposed to, and because the nearest external evidence sharpens it:
in an ATT&CK-classification study across models, **parameter size was the only statistically
significant predictor of F1** (ρ=0.85, p=0.014) while prompt strategy, chain-of-thought and
temperature were not. Single-model findings are therefore exactly the kind that should not be
read as properties of an architecture. Where a result is a *negative* obtained under a
configuration favourable to the alternative, it travels further than a positive; we say which is
which at each claim.

---

## Reference note

[5]–[14] are as numbered in `findings-log.md` §References. [15] is the AnnoCTR corpus
(Lange et al., LREC-COLING 2024, `arXiv:2404.07765`, CC-BY-SA 4.0), added here for the §1
replication. Systems named without a bracketed number — TRAM, rcATT, TTPDrill, EXTRACTOR,
AttacKG, LADDER, PhishDebate, LongFuncEval, ReCopilot, LLM4Decompile, Nova — are cited via the
verified sources that discuss them and **must be resolved to their own records before
submission**; see the citation audit for which were fetched directly and which were not.

**[16]–[19] were added on 2026-08-09 by the A4 adjacent-field counter-search, and their
verification status differs — deliberately recorded rather than smoothed over:**

| # | Source | Verified how |
|---|---|---|
| [16] | Abdallah, Holdcroft, Ali & Jatowt, *Are LLM-Based Retrievers Worth Their Cost?*, `arXiv:2604.03676` | **Abstract fetched and read.** The quoted claims are from it |
| [17] | Grammatical error correction's over-correction literature and the F0.5 convention | **Search results only.** Named, checkable candidates: *Leveraging What's Overfixed: Post-Correction via LLM Grammatical Error Overcorrection*; *Edit-Wise Preference Optimization for GEC* (COLING 2025). **Must be read in full and resolved to specific records before submission** |
| [18] | Neural text degeneration: Welleck et al., `arXiv:1908.04319`; *Repetition In Repetition Out*, `arXiv:2310.10226` (NeurIPS'23); *Rethinking Repetition Problems of LLMs in Code Generation*, `arXiv:2505.10402` | **Search results only.** Same requirement |
| [19] | Temporal generalisation: Lazaridou et al., *Mind the Gap* (NeurIPS'21); TemporalWiki `arXiv:2204.14211`; TARDIS `arXiv:2503.18693` | **Search results only.** Same requirement |

Acting on [17]–[19] now is conservative because each one *demotes* a claim of ours — the safe
direction. Citing them in a submitted paper on this basis would not be, and the standing rule from
the 2026-08-08 citation audit applies: a search summary is a lead, not a source. That audit exists
because one fabricated a claim.
