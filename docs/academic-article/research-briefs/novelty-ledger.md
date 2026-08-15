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

**Revised 2026-08-09 twice: first after the adversarial counter-search (A4), then again after the
B-layer measurements (B1, B2).**

> **This table is the 2026-08-09 state and is kept for the record, not as the current ledger.**
> The live counts are in [`paper-roadmap.md`](../paper-roadmap.md) under *Where this stands*
> (revised 2026-08-11): **5 `OURS` · 10 `REFINEMENT` · 2 `PRIOR ART` (+1 adjacent) ·
> 0 `UNMEASURED` · 1 `WITHDRAWN`**. Annotated rather than rewritten, on the same principle the
> brief states: the change should stay visible.

| verdict | count | claims |
|---|---|---|
| `OURS` | **2** | C8, E1 |
| `REFINEMENT` | **11** | N1, N5, N6, C6(partly), C3, "false corroboration", C5a, N4, N7, **+ N9, N10** |
| `PRIOR ART` | **4** | C5, binary→ATT&CK modality, local/confidentiality framing, honest degradation |
| `UNMEASURED` — cannot claim | **3** → **0** | **all three have since been measured, and all three came back negative** — see below |

### The three `UNMEASURED` rows, resolved (2026-08-11 … 2026-08-14)

The row this ledger was most worried about — *"four architectural claims cannot be defended because
they were never measured"* — is closed. Not by defending them:

| claim | measurement | result |
|---|---|---|
| **C1** sink-reachability prompt steering | §3.18 | **negative** — the hint fires on 56.7% of samples and changes nothing the analyst receives |
| **C2** two-tier attribution | §3.12 (semantic), §3.17 (opcode-hash) | **negative on both tiers** — the retriever works at 6.3× chance and moves the pipeline +0.003 F1; the opcode tier fires on **0 of 18** samples after hashing 7,716 functions |
| **C7** deterministic STIX integrity + reconciliation | §3.10, then §3.27 | **premise measured** — 15 of 51 fresh bundles had objects removed across all four defect classes. The *repair-versus-reject* comparison is still not measured and is not claimed |
| **C6** the cascade *(listed as pending above)* | §3.27.1, §3.30 | **closed `NEGATIVE`** — the agreement flag cannot be moved by the cascade's own constants, and the technique set reaching the analyst is the cascade's, not the model's |

**The pattern is the finding.** Four independently-designed components, each defensible on paper,
each measured, each inert or near-inert once wired to real inputs. That is now the project's
most-replicated result and it is what the paper is about.

### M6 and M7, counter-searched 2026-08-15 — **both demoted before they were ever claimed**

Entered as pending on 2026-08-14 with the note *"prior work on confounded evaluation comparisons is
likely to exist; it must be looked for before the row is written."* It exists. Neither becomes an
`OURS` row.

| # | Claim | What owns it | What is left to us |
|---|---|---|---|
| **M6** | A parameter-size correlation that ranked a reasoning-configuration flag and recovered the published scaling ρ almost exactly (§3.34) | **`arXiv:2604.00025`** (*Brevity Constraints Reverse Performance Hierarchies in Language Models*) — **abstract fetched and verified**. An inference-time output-length constraint *reverses* model rankings by 28.4 points, and the authors frame it exactly as a methodological confound: universal evaluation protocols "mask" latent capability, so protocols must be scale-aware. Our reasoning flag consumes the answer budget, which makes our arm a brevity-constrained arm by another name — and their result is the stronger one, since a reversal beats a spurious correlation | **The selection rule, not the phenomenon.** Their remedy is to adapt the protocol per model. Ours is narrower and, we think, not stated there: match arms on the **measured** configuration rather than the requested one, because a provider can accept the parameter and ignore it (§3.32), which makes intent-based matching silently unsafe. That is a refinement of their methodological point, and it is how it must be written |
| **M7** | A documented output cap that never reached the server, because the client library renamed it to a key the server does not read (§3.35) | **Known in the implementations' own issue trackers.** `ggml-org/llama.cpp` issue **#8634** reports `max_tokens` not being respected on the non-chat endpoint, with generation continuing to the context limit — our failure with a different key on the chat endpoint. vLLM carries a parallel request (**#11976**) for a server-side cap. *Search-result level; the issues have not been read in full, so this is a demotion pending confirmation — the conservative direction* | **The consequence, not the incompatibility.** That OpenAI-compatible servers disagree about token-limit parameters is a known integration wart. What we add is what it costs downstream in a measurement setting: a documented safety property silently absent, a degenerate decode reaching 30,155 tokens, and half a study's calls diverted onto a bundle-construction path that skips the cascade entirely (§3.37) |

**Neither demotion weakens E6's actual claim, and both narrow it.** The chapter does not argue that
each mechanism is individually unknown; §6.5 claims the *setting* — an evaluation pipeline for
security research, where the artefact is a measurement that is wrong and looks right — and the
composition. But the M6 write-up as first drafted reads as though the phenomenon were ours, and it
is not. That has to be fixed in the text before submission, not left for a reviewer.

**Third time in two days that reading the source changed the answer.** The search summary for a
second paper (`arXiv:2607.28211`) reported it as framing scaling correlations as evaluation
artifacts. Fetching it shows the authors argue the opposite emphasis — that *data* properties
predict better than scale. It reports ρ falling 0.68 → 0.48 → 0.05 across benchmarks, which is
adjacent evidence that ρ(scale, performance) is protocol-dependent, and it is **not** a confound
claim. Cited at that strength or not at all.

### New rows from the B layer, 2026-08-09 — **both counter-searched the same day, both demoted**

They were entered as `OURS pending counter-search`. The counter-search ran within the hour, and
neither survived it. Recording the sequence rather than the endpoint, because the speed is the
point: **an unchecked `OURS` row survived about sixty minutes.**

| # | Claim | Adjacent field that owns it | What is left to us |
|---|---|---|---|
| **N10** | The self-reported confidence a cascade consumes is nearly a constant — AUC 0.550, all 210 claims in one bin, one channel at exactly 1.000 throughout | **Confidence elicitation.** `arXiv:2603.09309` (Dai & Wang, *Rescaling Confidence*) — **abstract fetched and verified** — reports verbalized confidence is *"heavily discretized, with more than 78% of responses concentrating on just three round-number values"*, across **six LLMs and three datasets**. The phenomenon has a published name — **discretization** — and their evidence is far broader than our one model and five fixtures. Also `arXiv:2306.13063` (Xiong et al.) on overconfidence | **The consequence, not the phenomenon.** Their subject is scale design and metacognition. Ours is a *system that consumes the number*: the cascade's gates are keyed to a value that turns out to be discretized to near-constancy, which is why its confidence-driven parts move nothing (converges with §1.10). Also possibly the **below-chance channel** (AUC 0.428 on `network`) — not seen in their abstract, but n=70 and weak |
| **N9** | Heterogeneous evidence-channel decomposition does not beat a single agent at equal token budget | **Ensemble learning.** *Deep Ensembles Work, But Are They Necessary?* (`arXiv:2202.06985`) finds ensembles perform about the same as a **larger single model under a fixed parameter budget**, i.e. diversity buys no more than capacity alone. Same shape: a committee of specialists does not beat one model at matched budget | **The substrate genuinely differs** and the demotion is weaker for it: theirs is *independently trained* models under a *parameter* budget; ours is *one* model prompted N ways under a *token* budget. What is left is the domain instance plus the **noise control** — corrupting one channel costs +0.061 F1 with a CI excluding zero, so the mediator reconciles rather than averages, which the ensemble framing does not address |

**And a self-inconsistency this exposed.** §3.7 already described N9 as *"a replication of
`arXiv:2604.02460` and `arXiv:2605.00914` in a new domain"* — and a replication is by definition
not `OURS`. The ledger row contradicted the findings-log entry written an hour earlier. The
ensemble literature adds a second, older precedent, but the row was mis-verdicted before that
search ran, by me, against my own text.

**Verification status.** N10's demotion is confirmed by fetching the abstract. N9's rests on
search results naming a real, checkable paper and is a **demotion pending full-text confirmation**
— the conservative direction, but it must be read before the paper cites it.

**C3 is now in trouble for a new reason.** It was `REFINEMENT` of FAX and `UNMEASURED`. B2 makes
the measurement question sharper: a falsification-graded confidence *cap* keyed to a value that is
0.98 for almost everything is a cap that almost never binds. **B5 now tests whether the cap does
anything given that its input does not** — a better question than the one it was queued for, and
one where either answer is publishable.

**Read plainly:** the strongest surviving story is *negative results and measurement*, not
architecture. Four architectural claims cannot be defended because they were never measured, and
the two candidates we were building a framing on both fell to prior art in a single night.

> **Corrected 2026-08-14.** The second clause no longer holds and the first is stronger for it. All
> four architectural claims *were* measured, between 2026-08-11 and 2026-08-14, and every one came
> back negative or near-inert (see the resolution table above). They are not undefended for want of
> evidence; they are refuted by it. The reading stands, with its reason replaced.

**And now a third thing.** Part F recommended the F2 remnant — **C5a + N4 + N7** — as the paper's
"sharpest chapter". A4 searched each of those three in the vocabulary of an adjacent field, and
**all three demoted to `REFINEMENT`**. None was refuted; each turned out to be a domain instance
of something a neighbouring field already knows. The refinements are real and worth publishing —
but the chapter can no longer be introduced as three novel findings, and **D3 must re-decide the
framing on that basis**.

### What A4 actually did

The ledger's own closing item said every `OURS` is *a searched absence, not a proof*, and asked
for one targeted search each **from a different angle, ideally by someone who wants it to be
false**. That is what this was. The searches deliberately used the adjacent field's vocabulary:
auto-correction → **grammatical error correction**; degenerate loop → **neural text
degeneration**; rank-vs-gate → **IR score calibration**; drift → **temporal generalization of
LMs**; hint-to-completion → **inference latency / prompt compression**.

**Evidence standard, stated because it varies by row.** Only `arXiv:2604.03676` was confirmed by
fetching the source (abstract). The GEC and degeneration findings come from search results
naming real, checkable papers, and are recorded here as *demotions pending full-text
confirmation* — the demotion is the safe direction, so acting on them now is conservative, but
**each must be read in full before the paper cites it**. That is the same rule the 2026-08-08
citation audit imposed after a search summary fabricated a claim.

---

## The ledger

### `OURS` — survived the counter-search

| # | Claim | Searched against | Confidence | Notes |
|---|---|---|---|---|
| **C8** | An advisory prompt hint's real effect is **completion under a time budget**, not mapping accuracy: empty bundles **6/17 → 1/17** | R8's CTI-generation sweep; **A4 adjacent field: inference latency / prompt compression** — `arXiv:2604.02985` (*Prompt Compression in the Wild*) measures latency, rate adherence and quality, and the wider literature optimises latency. None found measuring **completion rate under a hard wall-clock ceiling** as the channel a prompt change acts through | `MEDIUM` | Held. The distinction that survives the search: that field asks *how fast*, we ask *whether anything came out at all before the deadline*. Caveat ships with it — operational, timeout-mediated, specific to a slow local model (§1.7.1) |
| **E1** | 7-year drift study, n=210 dated real binaries: earliest→latest F1 delta **−0.004**, bound ≤0.040 F1 at 95% | Drift evaluation for trained classifiers; **A4 adjacent field: temporal generalization of LMs** — Lazaridou et al. *Mind the Gap* (NeurIPS'21), TemporalWiki `2204.14211`, TARDIS `2503.18693`, and a 2025 survey of temporal drift in LLMs | `MEDIUM` | Held **but must be reframed**, see below |

**E1's reframing, and it is not optional.** The temporal-LM literature is large and its finding is
*degradation*. But it varies the **gap between training time and test time**, holding the input
distribution's role implicit. Our study does the opposite: the model is **fixed**, and what varies
is **the era of the input binary**. Those are different axes, and E1 is the second one — closer to
concept drift in malware detection (TESSERACT/Pendlebury) applied to an LLM analyst than to
temporal misalignment. Two consequences: the paper may **no longer say temporal effects in LLMs
are unstudied** — it must cite this literature and distinguish the axis; and the field's prior of
degradation makes our null **more** interesting, not less, provided the axis is stated plainly.

### Demoted by the A4 counter-search, 2026-08-09

*Each was `OURS` with `MEDIUM` confidence. None was refuted — each was found to be a domain
instance of an adjacent field's established result. Pending full-text confirmation where noted.*

| # | Was | Adjacent field that owns it | What is left to us |
|---|---|---|---|
| **C5a** | `OURS` | **IR score calibration.** `arXiv:2604.03676` (*Are LLM-Based Retrievers Worth Their Cost?*, Abdallah, Holdcroft, Ali, Jatowt) — **confirmed by fetching the abstract** — evaluates **confidence (AUROC) for predicting query success** as a dimension distinct from retrieval effectiveness, finds *"confidence calibration is consistently weak across model families"*, and concludes raw scores are *"unreliable for downstream routing without additional calibration"* | **The separate-axes framing is no longer ours** — that is their contribution, stated generally, over more retrievers than we test. What may remain: the specific **inversion** we measure (the *lexical* backend gates better while the *semantic* one ranks better) and composing the per-axis winners as a design. I found no paper reporting that inversion — and no paper excluding it either, so this is a weaker absence than C5a previously claimed |
| **N4** | `OURS` | **Grammatical error correction.** Over-correction is a named, long-studied failure there, and **GEC evaluates with F0.5 precisely because a false correction costs more than a missed one** — the exact asymmetry our 38%-damaged / 21%-recovered result rediscovers. Recent work targets it directly (PoCO post-correction; edit-wise preference optimisation, COLING'25) | The **non-separability** finding: correct-but-weak and wrong-but-valid IDs cannot be told apart *by an alignment score*, so the valid→valid swap cannot be tuned safely at any error rate. Plus the provably-zero-regression restriction (a valid ID is never invalid). The *principle* is GEC's; the **mechanism and the security-domain instance** are ours. *Pending full-text confirmation* |
| **N7** | `OURS` | **Neural text degeneration.** Welleck et al., *Neural Text Degeneration with Unlikelihood Training* (`1908.04319`); *Repetition In Repetition Out* (`2310.10226`, NeurIPS'23); and *Rethinking Repetition Problems of LLMs in Code Generation* (`2505.10402`), which states plainly that a uniform repetition penalty is **detrimental** for frequent tokens. "Sampler penalties are necessary but insufficient" is that field's settled position | The **operational consequence** in a structured-output security pipeline: the ramble exhausts the budget, the judge times out, and the deliverable is an **empty bundle** — degeneration as a *delivery* failure rather than a text-quality one. Plus the engine-specific finding that ik_llama honors `repeat_penalty` and silently ignores three siblings. *Pending full-text confirmation* |

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

*Rewritten 2026-08-09 after A4, then again the same day after B1, B2 and their counter-searches.*

1. **Lead with measurement, not architecture.** Now the only option: **two** `OURS` rows remain
   (C8, E1), both measurement results, and three architectural claims are still unmeasured.
2. **Three framings have died.** Describe-then-map and the binary modality fell to prior art on
   08-08; the **F2 remnant** — the chapter Part F called the sharpest, built on C5a + N4 + N7 —
   demoted wholesale on 08-09. F1 was gated on B1 returning positive; **B1 returned negative**, so
   F1 is closed unless C3 reopens it.
3. **A `REFINEMENT` is still publishable, and this is the honest way to publish it.** Every demoted
   row keeps a real contribution: C5a the measured *inversion* between which backend ranks and
   which gates; N4 **non-separability by alignment score**; N7 degeneration as a **delivery**
   failure; N9 the **noise control** the ensemble framing does not address; N10 the fact that a
   *system consumes* the discretized number, which is a mechanism for §1.10 rather than a
   restatement of it. What changes is the introducing sentence — "we find" becomes "we confirm in
   a new domain, and add the mechanism".
4. **The adjacent-field rule has now paid for itself nine times.** Infer-Retrieve-Rank (general ML),
   TTPDetect (binary analysis), Dempster–Shafer (sensor fusion), template-vs-neural (NLG), GEC
   over-correction, neural text degeneration, IR score calibration, and now **confidence
   elicitation** and **ensemble learning**. Every one would have been missed by searching security
   terms alone. **It is the single highest-yield habit in this review**, and it should be described
   as a *method* in the paper rather than merely used.
5. **The rule's cost, which is the number worth reporting.** Across two passes it demoted **five of
   seven** rows that had been entered as ours — three of five at A4, then two of two the same day.
   The second pair survived **about sixty minutes**. That is not a story about carelessness; the
   rows were entered with evidence and a stated confidence. It is a measurement of how unreliable
   "we found no prior work" is when the search stays inside one field's vocabulary.
6. **One demotion was a self-inconsistency, not a discovery.** N9's own findings-log entry already
   called it a *replication*, which is by definition not `OURS`. The ledger row contradicted a text
   written an hour earlier. **A claim register needs to be checked against the evidence log, not
   only against the literature.**
7. **Two claims are one experiment away** — C3 (B5) and C7 (B4, running). C6 is partly answered by
   B3, also running.
8. **The two survivors are still absences.** C8 and E1 have had one counter-search each. Each needs
   a second by a different route before submission — and **E1's must use the *input-era* framing,
   not temporal misalignment**, or it will search the wrong field and come back falsely clean.
