# Novelty ledger

> One row per contribution claim: what we assert, what prior work asserts, and the verdict.
> This is the product the literature review exists to produce; the per-theme reports are its
> working papers. Built 2026-08-08 from `incoming/R{2..8}.claude-web.md`, `R1.model-b.md` and
> the citation audit. Claim definitions live in
> [literature-review-brief.md](../literature-review-brief.md) Part B.
>
> **Verdicts.** `OURS` — no prior work found · `REFINEMENT` — prior work owns the idea, we
> narrow or sharpen it · `PRIOR ART` — already published, cite and stop claiming ·
> `UNMEASURED` — we cannot claim it either way until we measure it.
>
> **Every `OURS` is a searched negative, not a proof of absence.** Confidence is stated per row.

---

## Summary

| verdict | count | claims |
|---|---|---|
| `OURS` | **5** | C5a, N4, N7, C8, E1 |
| `REFINEMENT` | **6** | N1, N5, N6, C6(partly), C3, "false corroboration" |
| `PRIOR ART` | **4** | C5, binary→ATT&CK modality, local/confidentiality framing, honest degradation |
| `UNMEASURED` — cannot claim | **4** | C1, C2, C6, C7 |

**Read plainly:** the strongest surviving story is *negative results and measurement*, not
architecture. Four architectural claims cannot be defended because they were never measured, and
the two candidates we were building a framing on both fell to prior art in a single night.

---

## The ledger

### `OURS` — no prior work found

| # | Claim | Searched against | Confidence | Notes |
|---|---|---|---|---|
| **C5a** | Retrieval **ranking** and **alignment-gating** are separate axes; composing per-axis winners beats either pure backend (N=4,913 TRAM2) | TechniqueRAG `2505.11988`, H-TechniqueRAG `2604.14166`, Semantic Ranking `2403.17068`, TTPrint `2605.25836` — none reports a gate-separation metric | `MEDIUM` | The Büchel SoK (USENIX Sec '25) already publishes the *conclusion* that traditional NLP out-gates embedders; ours is the **mechanistic refinement**, and must be positioned as such |
| **N4** | Auto-correcting valid-but-weak technique IDs is net-negative: damages **38%** of correct IDs to recover **21%** of wrong ones, and the gate cannot separate them | LlmCorr `2402.13414` runs the opposite direction (LLM corrects an ML model); no ATT&CK system reports a correction-stage regression | `MEDIUM` | **Most transferable result we have.** Every retrieve-then-rerank system has an implicit override policy and none reports its cost |
| **N7** | Degenerate technique-ID loop in a small model; sampler penalties convert a tight loop into a slow enumeration ramble — necessary but insufficient | Constrained decoding is the standard remedy; TTPrint verifies post-hoc. Nobody documents budget exhaustion as the failure | `MEDIUM` | Reviewer will say *"constrained decoding solves this"*. True — the contribution is that the cheaper mitigation practitioners reach for first does not |
| **C8** | An advisory prompt hint's real effect is **completion under a time budget**, not mapping accuracy: empty bundles **6/17 → 1/17** | No CTI-generation work measures completion under an operational budget | `MEDIUM` | Strongest claim in R8. Caveat ships with it: operational, timeout-mediated, specific to a slow local model |
| **E1** | 7-year drift study, n=210 dated real binaries: earliest→latest F1 delta **−0.004**, all CIs overlap; hallucination ≤0.011 | Drift evaluation is standard for trained classifiers; no LLM-based malware-analysis equivalent found | `MEDIUM` | Needs an **equivalence bound** — overlapping CIs are not evidence of absence |

### `REFINEMENT` — prior work owns the idea; we narrow it

| # | Claim | Prior work | What is left to us |
|---|---|---|---|
| **N1** | Single-run parsed-claim count is an invalid instrument | **Chasing Shadows** `2512.09549` (NDSS'26, 72 papers, every one has ≥1 of nine pitfalls); **Arp et al.** `2010.09470`; construct-validity audits `2511.04703`, `2510.23191` | A **worked example**: the same arms ranked in contradictory orders across decoding budgets, nuisance parameter identified. Cite the tradition, publish the instance |
| **N5** | Deterministic template beats the LLM narrative on faithfulness+coverage (F1 delta −0.111, CI excludes 0) | Classic data-to-text: templates are faithful and stilted, neural output fluent and hallucination-prone | **The mechanism differs.** Both arms were perfectly faithful (precision 1.0, zero hallucinated techniques) — the loss was **coverage, not faithfulness**. Finer than the literature's claim |
| **N6** | Working retriever whose query never reaches it; a frequency prior wins | Negative RAG in malware analysis already published (`2605.03140`, SecDev '26); the baseline principle is textbook with a 2015 audit (`1503.06952`, up to 43% of published results fail to beat a label-only baseline); vocabulary mismatch is foundational IR | **Dense retrieval is the standard *remedy* for vocabulary mismatch and it failed here** — boilerplate dominated, all 15 queries scored 0.78–0.90 regardless of content, the 0.35 gate filtered nothing. The transferable artifact is the **score-distribution diagnostic** |
| **C3** | Falsification-before-confidence | **FAX** `2605.27879` — claim decomposition + cross-check against faithful tools, filtering unsupported claims, faithfulness 0.20→0.46 | FAX **filters**; we **cap** — a graded ceiling (>0.8 only after tool-executed falsification, else 0.7) plus a ≥2-evidence-loci rule. Also `2606.29490` reframes *why* it works: verbal confidence tracks commitment, not correctness. **But C3 is unmeasured — see below** |
| **C6** | Cascade weighting by independent evidence layers | **Dempster–Shafer** evidence theory, decades old, including correlation-based discounting of non-independent sources | Applying it to **LLM agents** where sensors mix rule engines and models. But the constants are ad-hoc where a formalism exists, which makes the unmeasured state worse |
| — | "Manufactured false corroboration" from a dataless analyst | **Sycophantic conformity** `2605.00914`, modal adoption up to 85.5% on 7–8B models | Our mechanism is an **empty evidence channel**, not majority pressure; the consequence is domain-specific — the echo returns under the silent agent's own domain tag and the corroboration counter reads it as independent confirmation |

### `PRIOR ART` — cite, do not claim

| Claim | Prior work | Note |
|---|---|---|
| **C5** describe-then-map: remove ID recall from the model, deterministic retrieval assigns it | **Infer-Retrieve-Rank** `arXiv:2401.12178` (Jan 2024) — general program decoupling LM inference from assignment over a many-thousand-class label space | Ours is stricter (the model never touches an ID; theirs re-ranks retrieved candidates). A domain instantiation with a design refinement — **cite prominently, position against, do not lead with** |
| **binary→ATT&CK input modality** | **TTPDetect** `arXiv:2602.06325` (Purdue, Feb 2026) — stripped binaries → ATT&CK, 93.25% function-level precision, deterministic retrieval pre-pass + LLM reasoner | The second framing candidate to fall. What remains is *local model* (an R7 point) and *multi-source cascade*, and the latter is unmeasured |
| **Local deployment / confidentiality as a hard constraint** | **REx86** `arXiv:2510.20975` (ACSAC 2025) — *"cloud-hosted, closed-weight models pose privacy and security risks and cannot be used in closed-network facilities"*; **AISI** quantifies the open-weight gap at 4–7 months with cost figures | A constraint we inherit. E2/E3/N8 systems measurements have no comparator and belong in an artifact appendix |
| **Honest degradation** | Abstention / selective prediction, mature, with 2026 LLM work offering provable coverage guarantees | Ours is abstention expressed as a property of a generated **deliverable**. One paragraph and a citation |

### `UNMEASURED` — cannot be claimed either way

| # | Claim | Why it cannot stand | Cost to fix |
|---|---|---|---|
| **C6** | Multi-layer cascade | Partly answered tonight: across five weight perturbations the top-10 ranking moved on 10.6–27.5% of samples and **the corroborated set moved on 0.0%**, because `is_corroborated` never consults the weights. So the constants are far less load-bearing than they look — which defends them against "arbitrary" and raises why they exist. The full ablation still needs the LLM | `[LLM]` |
| **C2** | Two-tier attribution (opcode-hash + semantic RAG) | **AsmRAG** `2604.23196` does semantic retrieval over assembly at 40,000 binaries, F1 95–96%, against EMBER and ResNeXt. An unmeasured two-tier design cannot be claimed against that | `[LLM]` partly, tier-contribution part `[cheap]` |
| **C3** | Falsification-before-confidence | FAX reports 0.20→0.46 with an ablation showing verification is essential. An unmeasured graded variant of a measured binary method is not a contribution | `[LLM]` |
| **C7** | Deterministic STIX integrity + reconciliation | eLLM-CTI already measures STIX *validity*; the OASIS validator exists. What is left is the **repair** pass, and "we repair bundles" is a design claim until measured | `[cheap]` once bundles exist |
| **C1** | Sink-reachability transferred JS→binary | No isolated ablation. R1 found no competing claim, so this may survive — but it has never been measured either | `[LLM]` |

---

## What the ledger implies for the paper

1. **Lead with measurement, not architecture.** Five `OURS` rows are all results about how
   things fail or how to measure them. Four architectural claims are unmeasured.
2. **Two framings died in one night.** Describe-then-map and the binary modality are both prior
   art. The roadmap's Part F must be rewritten around F3 (negative results / methodology) with
   F1 gated on E.1 and E.2.
3. **Three claims are one experiment away from surviving** — C6, C3 and C7. C7's is `[cheap]`.
4. **The adjacent-field rule paid for itself four times.** Infer-Retrieve-Rank (general ML),
   TTPDetect (binary analysis), Dempster–Shafer (sensor fusion), template-vs-neural (NLG). Every
   single one would have been missed by searching security terms alone.
5. **Every `OURS` is an absence.** Before any of the five reaches a submitted paper, it needs one
   targeted manual search from a different angle — ideally by someone who wants it to be false.
