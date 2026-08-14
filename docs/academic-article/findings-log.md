# Maljan — Academic Findings Log (paper seed)

> **Purpose.** A living, append-only record of the research-relevant findings,
> design contributions, empirical results, and literature positioning produced
> while building Maljan. This document feeds an eventual academic paper. Each
> entry is tagged with a **status** so claims are not overstated:
>
> - `IMPLEMENTED` — in the codebase, verified (tests/lint/types green).
> - `EXPERIMENTAL` — measured in a controlled probe (note the N / confounds).
> - `OBSERVED` — a reproducible phenomenon noted during runs, not yet formally studied.
> - `HYPOTHESIS` — proposed, not yet tested.
> - `NEGATIVE` — tested and found NOT to help (still publishable as a result).
>
> **Honesty rules for this log:** record confounds and sample sizes; keep negative
> results; do not inflate single-run probes into "studies"; cite the prior work each
> finding builds on or contradicts. Last updated: 2026-08-09.

---

## 0. Thesis and positioning

**Core framing — "LLM-as-analyst".** Maljan uses LLMs as *reasoning analysts* over
disassembled/decompiled binaries (via Ghidra MCP tool-use / ReAct), feeding a
deterministic adjudication layer (judge + false-positive linter + deterministic
pre/post-passes). This is distinct from the two dominant paradigms in the recent
LLM-for-malware literature:

| Paradigm | Role of the LLM | Examples | Transfer to Maljan |
|---|---|---|---|
| **LLM-as-analyst** (ours) | Reasons over binary evidence, proposes claims; a deterministic layer decides | Maljan; partially AppPoet [3]; MaLAware [4] | n/a |
| Learning-based detector + **LLM-as-data-generator** | LLM fabricates training data for a trained classifier | Rollinson & Polatidis [2] | NEGATIVE — no trained classifier in Maljan |
| Learning-based detector + **LLM-as-feature-summariser** | LLM describes features; a trained DNN decides | AppPoet's classifier half [3]; Maltracker [1] | PARTIAL — the prompt/semantic half transfers, the trained-classifier half does not |

**Contribution candidate C0 (positioning).** A taxonomy that separates
"LLM-as-analyst" pipelines from "LLM-as-tool-for-a-trained-detector" pipelines,
and an argument that the former is the right fit when (a) the goal is an
explainable, attributable *report* (not a binary label), and (b) deployment is on
constrained local hardware with no labelled training corpus. `OBSERVED` /
positioning.

---

## 1. System / design contributions

### 1.1 Sink-reachability triage as a deterministic pre-pass (Maltracker, cross-domain) — `IMPLEMENTED`
- **What.** Adapted Maltracker's [1] insight — *malicious behaviour concentrates in
  functions that can reach security-sensitive sink APIs through the call graph* —
  from its original NPM/JavaScript, learning-based setting to **binary reverse
  engineering** as a pure, deterministic pre-pass. Backward BFS from a curated
  sink catalogue over the Ghidra call graph ranks the functions nearest the
  malicious core; the ranking is injected as a "priority functions" prompt hint so
  a small local model spends its limited budget on the malicious core first.
- **Novelty vs [1].** (i) Cross-domain transfer (JS source → stripped binaries);
  (ii) used as a *prompt-steering pre-pass for an LLM agent* rather than as
  features for a trained classifier; (iii) graceful degradation: a stripped/static
  binary with no named sinks yields an empty hint (no false steering).
- **Verification-discipline coupling.** The hint explicitly warns that *reachable ≠
  data-connected*: before asserting a "capability reached" claim the analyst must
  confirm the data path with `analyze_dataflow`, then classify the terminal
  (caller-supplied / decoded-config / fixed-constant) to pick the correct ATT&CK
  technique. This closes a classic FP ("imports WinExec" ≠ "executes payload").
- **Artifacts.** `src/maljan/analysis/sink_reachability.py`;
  `tests/unit/analysis/test_sink_reachability.py` (18 tests).
- **Reference.** Maltracker, ISSTA 2024, DOI 10.1145/3650212.3680397 [1].

### 1.2 Function-hash attribution tier (deterministic code-reuse) — `IMPLEMENTED`
- **What.** A high-precision attribution tier orthogonal to semantic RAG: per-function
  *normalized-opcode hashes* (Ghidra `get_bulk_function_hashes`) are stored in a
  dedicated Qdrant collection keyed to the sample's attributed family. A new sample
  sharing an exact opcode hash with a known one yields a near-certain code-reuse
  link — a stronger signal than RAG-over-prose similarity. The corpus grows at
  judge time (write-side) and is queried as a pre-pass prompt prior (read-side).
- **Anti-FP control (important for the paper).** Functions below an
  instruction-count threshold (default 8) are excluded, because tiny thunks/stubs
  normalise to identical opcode hashes across unrelated binaries and would
  manufacture false family links. Confidence is a monotone, capped function of the
  count of distinct shared functions (saturates < 1.0: exact match is a *prior* to
  corroborate behaviourally, not proof).
- **Novelty.** A two-tier attribution design — (Tier A) exact opcode-hash code-reuse,
  (Tier B) semantic RAG — where the deterministic tier is higher-precision and the
  semantic tier higher-recall; both feed the judge and the report, both fail-safe
  and config-gated.
- **Artifacts.** `src/maljan/memory/function_hash_store.py`,
  `src/maljan/analysis/function_hash_attribution.py`,
  `tests/unit/analysis/test_function_hash_attribution.py` (18 tests).

### 1.3 Verification discipline for small-model attribution — `IMPLEMENTED`
- **What.** A prompt-level confidence-calibration protocol that suppresses
  confidently-wrong attribution (the most damaging FP class for an automated
  verdict):
  - A *specific* claim (named algorithm — RC4/djb2/ROR13 — a constant/XOR key, or a
    hash-resolved API) may reach CONFIDENCE ≥ 0.8 only if **actively falsified**
    first via `emulate_function` (known input vs expected output) or
    `analyze_dataflow(backward)`; otherwise capped at 0.7.
  - `emulate_hash_batch` collision caveat: read the full `matches` list; on multiple
    collisions do not take `best_match` blindly (cap ≤ 0.5).
  - High confidence (≥ 0.8) requires **≥ 2 independent evidence loci**; a single
    locus caps at 0.7.
- **Why it matters for the paper.** Falsification-before-confidence is a concrete,
  tool-grounded mechanism for calibrating a *small local* model whose raw
  confidence is otherwise uncalibrated.
- **Artifacts.** `_ISR_SYSTEM` in `src/maljan/agents/static_analyst.py`.

### 1.4 Curated tool allowlist for small-model tool-use — `IMPLEMENTED` / `OBSERVED`
- **What.** Ghidra MCP advertises ~225 tools (≈201 authoritative `@McpTool`
  endpoints in the Java service layer). Exposing all of them is **infeasible and
  undesirable** for a small local model — see §2.2. Maljan exposes a curated
  20-tool allowlist (lifecycle + malware analyzers + targeted deep-dive + emulation/
  crypto/dataflow) and drives the remaining high-value tools (e.g.
  `get_bulk_function_hashes`) **deterministically from Python**, never as model-facing
  tools.
- **Design principle (paper-worthy).** *"Use a tool ≠ expose it to the model."* For a
  weak model, expensive tool-routing should be done in code (deterministic pre/post
  passes), handing the model only focused results. This unifies §1.1, §1.2 and the
  view-decomposition idea (§3.2).

### 1.5 Deterministic ATT&CK technique-ID assignment (describe-then-map) — `IMPLEMENTED`
- **What.** The small model is the wrong instrument for *recalling* a numeric ID from a
  600+ technique taxonomy it has not memorised (it loops — §3.3). So the ID-recall
  sub-task is moved off the model: the analyst only **describes behaviour** (CLAIM +
  EVIDENCE), and a deterministic pre-cascade pass **re-grounds the technique ID** against
  an in-house TF-IDF index over the official MITRE ATT&CK Enterprise corpus
  (`correct_isr_reports`). Invalid IDs (well-formed but absent from the catalog) are
  replaced by the top evidence-derived suggestion; valid-but-poorly-aligned IDs are
  swapped only when a *strictly* better-aligned candidate exists; well-aligned and
  `NONE` IDs are left untouched. Layer-0 rule sources (YARA/Sigma) are skipped — their
  IDs are rule-authoritative. The correction runs before the cascade so it propagates to
  corroboration, the judge's grounding, the report, and the STIX bundle.
- **Why deterministic beats the model here.** The TF-IDF index cannot loop or
  hallucinate, draws from the full catalog, and is strictly superior for the
  *ID-existence/assignment* sub-task; the model keeps only what it is good at (describing
  behaviour). Its own failure mode is lexical (keyword, no synonyms), which is why
  assignment is **gated** (only override invalid or strictly-worse-aligned IDs), not blind.
- **Novelty / principle — corrected 2026-08-08.** The design is a concrete instance of
  "LLM proposes, deterministic layer disposes" applied to the *label-assignment* step
  itself: separate **description** (model) from **taxonomy mapping** (deterministic
  retrieval). The project already had this index but used it only *advisorily*; the
  change was making it **authoritative** for ID assignment. That remains an accurate
  description of the engineering — but it is **not a new idea**.
  `Infer-Retrieve-Rank` [6] (Jan 2024) publishes the general program: multi-step
  interactions between LMs and retrievers that decouple the LM's inference from direct
  assignment over a many-thousand-class label space, reaching SOTA on three benchmarks
  with tens of labelled examples and no finetuning. TechniqueRAG [7] and its hierarchical
  successor apply retrieve-then-rerank to ATT&CK specifically.
  **What is defensibly ours is narrower.** Ours is *stricter*: in Infer-Retrieve-Rank and
  TechniqueRAG the LM still ranks or selects among retrieved candidates, whereas here the
  model never emits an ID at all and any override is gated to the provably-safe
  invalid→valid case (§1.5.2). A domain instantiation with a design refinement — **cite [6]
  prominently and position against it; do not lead a paper with this.**
- **Artifacts.** `correct_isr_reports` in `src/maljan/memory/attck_validator.py` (over the
  TF-IDF `src/maljan/memory/attck_index.py`); wired in `src/maljan/pipeline/nodes.py`
  before cascade; `tests/unit/test_attck_memory.py` (6 correction tests). Config-gated
  (`use_attck_autocorrect`) and fail-safe.
- **Real-corpus validation (2026-06-01).** Probed against the live 697-technique bundle
  (ATT&CK v19.1): the §3.3 trigger — an invalid ID on `ptrace`/`prctl` anti-debug evidence
  — re-grounded to **T1055.008 "Ptrace System Calls"** (alignment 0.45); a well-aligned ID
  (0.21) and a `NONE` were left untouched. Real good-match alignments cluster at 0.20–0.45
  vs 0.0 for unrelated, so the `min_alignment=0.08` gate separates them cleanly. Caveat
  confirmed: TF-IDF is lexical — a C2-tagged ransomware claim swapped to a crypto-algorithm
  technique on shared "AES/encryption" tokens rather than the impact technique.

### 1.5.1 TF-IDF vs semantic vs hybrid technique mapping — `IMPLEMENTED`
- **Motivation.** The §1.5 TF-IDF lexical caveat suggested dense embeddings might map evidence
  to techniques better. The project already ships a BGE-384 embedder (`embeddings.py`,
  `fastembed`), so we added a drop-in `SemanticATTCKIndex` (same interface; embeds each
  technique's searchable text once) and measured before changing any default.
- **Method (honest test set).** TRAM2 `single_label` — human-labeled (sentence, technique_id)
  pairs from real threat reports — is **independent** of the ATT&CK descriptions the index is
  built from (scoring against those descriptions would be circular). Full set: **4,913 valid
  pairs**; real fastembed BGE confirmed (related 0.696 vs unrelated 0.568). Metrics: top-1/top-3
  accuracy, MRR, and a *gate separation* = mean alignment score of the chosen top-1 when correct
  minus when wrong (higher = the absolute threshold can better flag a wrong pick). Harness:
  `tests/evaluation/eval_technique_mapping.py`.
- **Result (N=4913).**

  | backend | top-1 | top-3 | MRR | gate separation |
  |---|---|---|---|---|
  | TF-IDF | 0.205 | 0.329 | 0.274 | +0.085 |
  | semantic | 0.230 | 0.392 | 0.319 | +0.019 |
  | **hybrid** | **0.230** | **0.392** | **0.319** | **+0.115** |

- **Finding.** The two pure methods are **complementary**: semantic *ranks* better (+6.3pp top-3,
  +4.4pp MRR) but its scores barely separate correct from wrong (gate +0.019 — everything sits
  near 0.7), while TF-IDF *gates* cleanly (scores ~0 for unrelated, gate +0.085) but ranks
  worse. The §1.5 autocorrect's low-alignment swap depends on a clean gate. The **hybrid**
  (`HybridATTCKIndex`: semantic `search()` for ranking + TF-IDF `validate_and_score()` for the
  gate) takes both strengths — it matches semantic's ranking *and* yields the **cleanest gate of
  all (+0.115)**, because semantic surfaces better candidates that TF-IDF then validates
  decisively (wrong picks score ~0.13). Absolute top-1 ≈ 0.20–0.23 reflects the known difficulty
  of zero-shot single-sentence → technique on TRAM2 (no fine-tuning, 697-way retrieval).
- **External replication on AnnoCTR (2026-08-08) — the claim now rests on two corpora.**
  The TRAM2 result had a specific vulnerability: its sentences are short and were annotated *for*
  technique classification, so a lexical gate has an easy job — the sentence often names the
  behaviour in ATT&CK's own words. If the gate separation were an artifact of that register
  rather than a property of the method, the claim would not survive real report prose.
  **AnnoCTR** [15] (Lange et al., LREC-COLING 2024, CC-BY-SA 4.0) is a different task by
  different annotators over different documents: expert *entity linking* in running threat-report
  prose, so the evidence text is whatever the analyst actually wrote around the mention.
  **3,289 technique-linked mentions** scored (48 labels dropped as absent from our ATT&CK
  bundle), metrics reused verbatim from `eval_technique_mapping._evaluate` — a replication that
  redefines its measure is not one.

  | backend | top-1 | top-3 | MRR | gate separation | *TRAM2 gate sep* |
  |---|---|---|---|---|---|
  | TF-IDF | 0.094 | 0.183 | 0.147 | **+0.135** | *+0.085* |
  | semantic | 0.123 | **0.214** | 0.176 | +0.062 | *+0.019* |
  | **hybrid** | 0.123 | **0.214** | 0.176 | **+0.168** | *+0.115* |

  **All three orderings replicate.** Semantic ranks better than TF-IDF (+3.1pp top-3); the gate
  ordering is hybrid > TF-IDF > semantic exactly as on TRAM2; and the hybrid wins both axes. The
  separations are uniformly *larger* here, which is consistent with the harder corpus spreading
  the scores rather than with the effect being register-bound.
  **Honest reading.** Absolute accuracy is much lower than on TRAM2 (top-1 0.09–0.12 vs
  0.21–0.23) because entity linking in unconstrained prose over a 697-technique space is a
  harder task than sentence classification — the numbers are not comparable across corpora and
  are not presented as such. What replicates is the **ordering**, which is the whole claim.
  Harness `tests/evaluation/eval_annoctr_mapping.py`; helpers unit-tested in
  `test_annoctr_mapping_scoring.py`; artifact `tests/evaluation/annoctr_mapping.json`. The
  corpus is fetched into a gitignored `data/external/`, never vendored.
- **Literature position (2026-08-08) — the conclusion is not ours; the decomposition is.**
  The Büchel SoK [5] (USENIX Security 2025) re-evaluated 40+ TTP-extraction systems in a unified
  setting and reports that *"traditional NLP approaches (possibly counterintuitively) outperform
  modern embedder-based and generative approaches in realistic settings."* That is a stronger,
  more general form of what this section found for the gating axis, published before it. Our
  result must be positioned as a **mechanistic refinement** of that insight, not as a discovery:
  the SoK says embedders lose; we say *why and where* — they rank better and gate worse, the two
  are separable axes, and composing the per-axis winners beats either. The review found no other
  work reporting ranking and gate quality as distinct metrics (`MEDIUM` confidence).
- **Decision.** Hybrid dominates both pure backends on both axes, so it is the **default**
  (`attck_index_backend = "hybrid"`); its TF-IDF gate keeps the existing 0.08 threshold valid.
  `fastembed` is already loaded in production (long-term memory), so the marginal cost is one
  catalog embed at startup. `tfidf` (no embeddings, air-gapped) and `semantic` remain opt-in.
- **Method note (paper-relevant).** Ranking accuracy and gate quality are *separate* axes for a
  retrieval-based label assigner; a method can win one and lose the other. Reporting both — and
  composing the winners per-axis into a hybrid — beat picking a single "best" index.

### 1.5.2 Autocorrect impact ablation — `IMPLEMENTED` (a regression found and fixed)
- **Motivation.** §1.5.1 measured retrieval quality in isolation. The decisive question is
  whether the autocorrect's full *decision policy* improves pipeline output — and at what cost.
- **Method.** TRAM2 (real evidence sentence + real label), production hybrid backend, server-free.
  The small model's three error modes are simulated at 100%/scenario (rate-free): a claim's raw
  technique_id is set to (a) an invalid ID, (b) a wrong-but-valid ID, or (c) the true label;
  OFF = raw passes through, ON = after `correct_isr_reports`. N=800.
- **Result.**

  | scenario (input) | acc OFF→ON | hallucination OFF→ON |
  |---|---|---|
  | invalid ID (T9999) | 0.000 → 0.193 | 1.000 → **0.000** |
  | wrong-valid ID | 0.000 → 0.207 | 0.000 → 0.000 |
  | **correct ID (regression)** | 1.000 → **0.619** | 0.000 → 0.000 |

- **Finding (the value of measuring end-to-end).** The invalid-ID fix is an unambiguous win
  (eliminates 100% of hallucinations, recovers ~19%). But the valid-ID *swap* path **damaged 38%
  of already-correct IDs**: short real evidence often has weak TF-IDF overlap with the correct
  technique, so a wrong candidate out-scores it. Correct-but-weak and wrong-valid IDs are **not
  separable** by the alignment gate, so the swap cannot be safely tuned — and since correct
  inputs dominate in any usable model, the swap path is **net-negative**. This regression is
  invisible to the §1.5.1 retrieval metric; only the end-to-end ablation surfaced it.
- **Fix (provably zero-regression).** Restrict the autocorrect to invalid-ID replacement
  (`attck_autocorrect_swap_valid = False`, default). A valid ID is never invalid, so correct IDs
  are untouched *by construction*. Re-measured: invalid-ID fix retained (hallucination 100%→0%,
  +19% recovery), **correct-ID regression eliminated (100%→100%)**; the wrong-valid recovery
  (+20.7pp) is sacrificed — acceptable, since a wrong-but-valid ID is a far milder error than a
  hallucinated one (still a real technique, sanity-checkable), and the §3.3 failure mode the
  feature targets is invalid/loop, not subtle valid swaps.
- **Takeaway (paper).** Isolated retrieval accuracy does not justify an auto-correction policy;
  the end-to-end ablation is what exposed a 38% regression. Auto-correction should be confined to
  the provably-safe sub-operation (invalid→valid), not extended to ambiguous valid→valid edits.
  Harness: `tests/evaluation/eval_autocorrect_ablation.py`.
- **Scope of the claim (P8, 2026-08-09).** This ablation is **server-free** — no LLM ran — so
  unlike §3.3/§3.5 the binding limit is *not* the model. It is two other things, and the
  self-audit's first pass mis-stated them. **(i) One index.** The 38% damage figure is a
  property of the **production hybrid backend's alignment gate** on TRAM2 evidence sentences:
  short real evidence often has weak lexical overlap with the correct technique, so a wrong
  candidate out-scores it. A different retriever, a different corpus, or a different gate
  threshold would move that number, and §1.5.1's own result — the three backends separate on
  gate quality by +0.062 to +0.168 — says they would move it a lot. **(ii) Simulated, not
  observed, error modes.** The three input scenarios are injected at 100% each and are
  deliberately rate-free; they are not this or any model's measured error distribution. The
  *directional* conclusion (the swap path is net-negative) therefore rests on one further
  assumption stated in the entry — that correct inputs dominate — which holds for any usable
  model but is an assumption, not a measurement. What survives unconditionally is the
  **structural** claim, and it is the transferable one: correct-but-weak and wrong-but-valid IDs
  are *not separable by an alignment score*, so a valid→valid swap cannot be tuned safely no
  matter what the error rates turn out to be. The invalid→valid restriction is zero-regression
  **by construction** (a valid ID is never invalid), which needs no empirical scope at all.

### 1.5.3 Case-prior retrieval as a technique-candidate source — `NEGATIVE` (the retriever works; the query never reaches it)
- **Motivation.** §4 U2 shipped an ATT&CK case-prior RAG: embed 1,733 ATT&CK-labelled prior
  cases, retrieve the behaviourally-nearest neighbours for the sample, aggregate their
  `technique_ids` into a ranked CANDIDATE list, hand it to the static analyst as evidence. It has
  been `use_attck_case_rag = False` since it landed, justified as "absent a corpus it degrades to
  a no-op" — a statement about deployment, not about whether it works. The one measurement that
  touched it (the U3 A/B, n=19) switched the **family** RAG on in the same arm and read out final
  technique F1, so it could not have detected this retriever's effect in either direction.
- **Method (the control is the finding).** The corpus is severely non-uniform: T1129 appears in
  71% of cases, T1027 in 67%, and there are only **77 distinct techniques** in total. A
  recommender that ignores the query entirely and returns the globally most frequent K therefore
  scores well *by construction*. So the comparison is not RAG-vs-nothing but **RAG vs a
  frequency prior at equal budget** (K = `attck_case_rag_max_techniques` = 8), with random
  selection from the 77 as a floor. Two query regimes, because they are not the same experiment:
  *native* (query = another case's own `summary_text` — the optimistic ceiling) and *runtime*
  (query = `build_sample_profile_text`, literally what production sends, scored against
  independent family-level ATT&CK ground truth for 15 labelled samples).
- **Leakage control.** 742 of the 1,733 cases (43%) share a **byte-identical** `summary_text`
  with another case, so plain leave-one-out hands 43% of queries their own twin — a retrieval
  problem nobody has in production. Reported with near-duplicate neighbours (cosine ≥ 0.99)
  suppressed; the naive figure (F1 0.697) is also in the artifact for contrast.
- **Result.**

  | regime | query | retrieval F1 | frequency prior | random |
  |---|---|---|---|---|
  | native (dedup) | corpus `summary_text` | **0.620** | 0.424 | 0.078 |
  | runtime (n=15) | `build_sample_profile_text` | **0.111** | **0.123** | — |

- **Finding.** The index is *not* the problem — given a query in its own vocabulary it beats the
  prior by +0.20 F1 with hit@1 = 0.90. But with the query production actually sends it is
  **indistinguishable from, and on F1 slightly below, printing the eight most common techniques
  in the corpus and never looking at the sample.** The cause is mechanical, not a tuning
  shortfall: the corpus renders capa rule sentences and lowercase API names ("allocate RW
  memory"; "closehandle"), while the runtime profile renders import-category counts and CamelCase
  ("capabilities: execution x5"; "GetProcAddress"). The only text the two share is the
  boilerplate — which is why **all 15 queries land at 0.78–0.90 similarity regardless of
  content**, and why `attck_case_rag_min_score = 0.35` is inert, filtering nothing. A variant
  querying with only the lowercased import segment (the one overlapping vocabulary) was tried and
  did **not** close the gap (F1 0.090).
- **Correction to the record.** The U2 entry's end-to-end verification — "an injection+network
  static profile retrieves T1055 / T1055.003 at 0.90" — read a number that carries no
  information: 0.90 is what *every* query scores here, correct or not. A single anecdotal
  retrieval at a plausible-looking similarity is not evidence when the score distribution has not
  been characterised. The pre-existing "vocabulary overlaps but does not perfectly match" caveat
  was directionally right and quantitatively far too generous.
- **Decision.** Stays OFF — now on evidence rather than on absence of a corpus. Enabling it would
  be **worse than a no-op**: an analyst shown a technique list that tracks corpus frequency rather
  than this sample reads it as corroboration, which is the same false-corroboration mechanism the
  dataless-revision fix had to remove elsewhere in the pipeline. Re-open when the corpus is
  rebuilt in `build_sample_profile_text`'s vocabulary (or the query in capa's); the harness
  re-runs in ~2 min and answers it.
- **Takeaway (paper).** Three transferable points. (i) For a retrieval component over a skewed
  label distribution, the mandatory baseline is the **label-frequency prior at equal budget** —
  against "no retrieval" this component looks strong, against the prior it is negative. (ii)
  **Retriever quality and query/corpus vocabulary parity are separable failure modes**, and the
  usual isolated-retrieval metric measures only the first; the ceiling-vs-runtime split is what
  localises the fault. (iii) A similarity floor tuned on scores that do not separate good matches
  from bad ones is decoration, not a gate — the same conclusion §1.5.1 reached for the semantic
  backend, reached independently here. Harness: `tests/evaluation/eval_attck_case_rag.py`;
  artifact: `tests/evaluation/attck_case_rag_retrieval.json`; the harness's own scoring
  arithmetic is unit-tested (`test_attck_case_rag_scoring.py`) because it decides a shipped
  default.

### 1.6 Deterministic STIX validity + honest reporting — `IMPLEMENTED`
- **What.** Two deterministic output-quality passes that harden the machine-readable (STIX 2.1
  bundle) and human-readable (Markdown report) artifacts, in the same "deterministic layer
  disposes" spirit as the analysis contributions above.
- **STIX integrity pass (`enforce_bundle_integrity`).** A single polymorphic pass (works on the
  judge's parsed-dict bundle and the renderer's pydantic SDOs) applied after every drop step in
  `judge_postprocess.py` AND at the end of `ExtendedSTIXRenderer.render()`. It (i) drops
  empty/whitespace-pattern Indicators (STIX 2.1 requires a usable pattern), (ii) deduplicates
  attack-patterns by technique ID and indicators by `(pattern_type, pattern)`, rewriting
  relationship refs to the survivor, (iii) drops relationships whose source/target no longer
  resolves and collapses duplicate relationships, and (iv) trims dangling `object_refs` on
  Report/Note SDOs. This closes a real referential-integrity gap: the prior `REP-02` swept only
  relationships pointing to dropped *attack-patterns*, so relationships to *indicators* dropped by
  the J-02 hallucination filter leaked through as dangling refs.
- **Honest reporting signals.** (i) A `family_grounded` flag (already computed by the attribution
  guardrail) is now *surfaced*: an evidence-ungrounded family is marked `(ungrounded — no
  YARA/deterministic corroboration)`, and a no-candidate family renders "not determined" instead of
  the misleading "unknown (confidence 0.00)". (ii) A `DEGRADED RUN` banner is rendered when the run
  had low/no analyst data, so a numerically high verdict/severity is not read as authoritative;
  `degradation_reasons` are listed.
- **Why it matters (paper).** Output validity and calibrated honesty are part of the "LLM proposes,
  deterministic layer disposes" contribution: the deterministic layer guarantees the emitted CTI is
  spec-valid and internally consistent, and the report never over-claims beyond the evidence it had.
- **Artifacts.** `enforce_bundle_integrity` in `src/maljan/agents/judge_postprocess.py` (applied in
  `stix_renderer.py`); `src/maljan/reporting/{models.py,builder.py,renderers/markdown.py}`;
  `src/maljan/pipeline/nodes.py`. Tests in `tests/unit/test_judge_postprocess.py` (integrity) and
  `tests/unit/reporting/test_renderers_markdown.py` (honesty signals).
- **Measured externally, and it found two defects our own checks could not (2026-08-08).**
  §1.6 described the integrity pass without ever grading its output, and the literature review
  narrowed the claim: eLLM-CTI already contributes a *STIX accuracy* metric, and the **OASIS
  `cti-stix-validator` has existed all along**. Our own §3.4 says to measure with someone else's
  instrument, so we did — and the instrument immediately failed us in two ways the integrity
  pass has no opinion about:
  1. **No `spec_version` on any object.** In STIX 2.1 it is *required* on every SDO (it moved
     off the bundle, where 2.0 put it). We emitted it nowhere, so strictly **every bundle this
     project produced was not identifiable as 2.1** — a conforming consumer falls back to 2.0
     semantics and the validator refuses the object outright.
  2. **`null` properties and empty arrays.** STIX forbids both as *present* properties; pydantic
     emits `"description": null` and `"malware_types": []` by default. **13 validator errors on
     a four-object probe bundle.**
  Both are fixed: `spec_version: Literal["2.1"]` on the SDO base, and a `_SpecConformantModel`
  base overriding the dump methods so the rule holds at every serialisation site rather than
  wherever someone remembered a flag. **A bundle built from the production models now validates
  clean — 0 errors, 0 referential warnings.** Pinned by `tests/unit/reporting/test_stix_spec_version.py`.
  **The point worth keeping is how they were found.** The integrity pass checks empty patterns,
  duplicate attack-patterns and dangling references, and had no opinion about either defect;
  the standard validator saw both in seconds. That is §3.4's own argument about measurement
  instruments, arriving at our own expense.
  **A methodological near-miss, recorded because it was close.** The validator's PyPI wheel
  **ships without the OASIS JSON schemas** and ignores `schema_dir` for the core-schema lookup,
  so it initially reported *every* bundle — including a textbook-valid one — as invalid. Had the
  harness not probed a known-good bundle first, this section would now contain a confident and
  entirely wrong finding. `eval_stix_integrity.py` therefore refuses to run until the instrument
  proves itself.
  **Still unmeasured:** how often the pass fires on real output, and what it recovers that
  rejection would discard. The four archived bundles available are pre-fix, and the defect
  classes the pass targets come from LLM generation, so this needs `[LLM]` runs.
- **CTI polish (wave 2).** Three further low-risk correctness passes: (i) the integrity pass also
  drops syntactically malformed STIX patterns (conservative bracket+comparator shape check — no
  grammar parser, no over-dropping); (ii) attack-pattern display names are back-filled from the
  already-loaded ATT&CK index for all ~700 techniques (not just a 14-entry curated table),
  fail-safe when the index isn't built; (iii) FP-prone `file:name` string-IOC indicators are typed
  `anomalous-activity` rather than `malicious-activity` so consumers can weight them below
  high-confidence hash/C2 IOCs.

### 1.7 Static keyword vs dynamic semantic category inference — `IMPLEMENTED` (knob shipped, default unchanged) / zero-shot variant `NEGATIVE`
- **Question.** The STIX schema-pruning hint is driven by `infer_malware_category` — a
  static, hand-maintained keyword table (substring scoring over the analyst text + ISR claims).
  Two honest doubts: (a) how reliable is a fixed keyword list, and how much of its accuracy is
  just the text *literally naming* the category; (b) can a dynamic embedding classifier do better,
  and is "dynamicizing" it even worthwhile?
- **Method (non-circular ground truth).** ATT&CK `malware` SDO descriptions are human-written CTI
  whose first sentence almost always declares the family's type ("EKANS is ransomware variant…",
  "cd00r is a backdoor…"). We label each family by that *declared type* (a targeted copular-noun
  parser — a different mechanism than the bag-of-keywords classifier under test) and then evaluate
  in two regimes: **full** (whole description) and **behavioral** (declaring sentence removed, so
  the classifier cannot echo the label). **101 families** pass the single-declared-type filter
  (RAT 41 / ransomware 33 / dropper 16 / infostealer 8 / worm 3 — worm/infostealer sparse in the
  ATT&CK corpus, so their per-class numbers are indicative). Builder
  `tests/evaluation/category_eval_data.py`; harness `tests/evaluation/eval_category_inference.py`
  (real BGE-384 confirmed). Methods: keyword; semantic **zero-shot** (prototypes = mean embedding
  of each category's seed-technique descriptions); semantic **few-shot** (leave-one-out: prototype
  = mean of the other 100 labelled descriptions); two hybrids (keyword → semantic fallback on
  abstain); majority-class floor.
- **Result (N=101, accuracy / macro-F1).**

  | method | full | behavioral | note |
  |---|---|---|---|
  | keyword (default) | 0.792 / 0.771 | 0.327 / 0.389 | abstains 5.9% full → **37.6% behavioral** |
  | semantic zero-shot | 0.376 / 0.306 | 0.168 / 0.154 | below keyword *and* near floor |
  | semantic few-shot (LOO) | **0.851** / 0.751 | **0.505** / 0.313 | best acc; never abstains; zeros sparse classes |
  | hybrid (kw→zero-shot) | 0.812 / **0.781** | 0.386 / 0.337 | small lift, no labelled data needed |
  | hybrid (kw→few-shot) | 0.832 / 0.775 | 0.525 / **0.448** | best balance; needs a labelled corpus |
  | majority floor | 0.406 / 0.115 | 0.406 / 0.115 | — |

- **Finding 1 (the doubt is correct, the failure mode is safe).** Keyword accuracy is *conditional
  on the surface naming the category*: 0.792 when the description names it, collapsing to 0.327
  when the naming sentence is removed — and crucially it **abstains 38%** of the time there rather
  than guessing. So a fixed keyword list is *not* always right, exactly as suspected; but its error
  is to fall silent (UNKNOWN → no hint), which is the correct failure mode for an advisory signal.
- **Finding 2 (`NEGATIVE`: zero-shot semantic does not work).** Prototypes averaged from ATT&CK
  technique descriptions are too blurry — BGE-small crams all malware-behaviour text into a narrow
  0.59–0.70 cosine band, margins are tiny, and the classifier underperforms the keyword table in
  both regimes (and barely beats the majority floor on behavioral). "Just embed the text and
  compare to technique prototypes" is not a viable replacement.
- **Finding 3 (dynamic helps only when *learned* from labelled prose).** Few-shot prototypes built
  from labelled malware descriptions beat keyword on raw accuracy in both regimes (full +5.9pp,
  behavioral +17.8pp). But they never abstain and collapse the sparse worm/infostealer classes to
  F1≈0 (macro-F1 0.313 behavioral), trading calibration for accuracy, and they require a labelled
  prototype corpus. The best **balance** is the keyword→few-shot hybrid: keyword stays
  authoritative where confident, the learned classifier fills its 38% abstentions — behavioral
  0.525/0.448 (+19.8pp acc, +5.9pp macro-F1), full 0.832 (+4.0pp).
- **Decision (keep the safe default; ship a measured, reversible knob).** `category_inference_backend`
  defaults to `"keyword"` — on realistic analyst text (which, like the *full* regime, names the
  category) keyword is competitive **and** safe-abstaining, and the hint is advisory + 400-char
  truncated, so an intermediate-signal gain has bounded end-to-end effect. `"semantic"` and
  `"hybrid"` are opt-in and **fail-safe to keyword** (BoW fallback / any error → keyword). The
  deployable hybrid (kw→zero-shot) needs no new data and gives a small realistic-regime lift; the
  stronger kw→few-shot variant needs a labelled prototype corpus — the natural source is the LTM
  `StoredCase.malware_category` history (cold-start degrades gracefully to keyword) — and is the
  documented upgrade path, not a config-only switch.
- **Method notes (paper-relevant).** (i) A keyword classifier's headline accuracy is an artifact of
  whether the input surface names the label; reporting both the *named* and *behavior-only* regimes
  exposes the dependence that a single number hides. (ii) Zero-shot nearest-prototype over averaged
  ATT&CK descriptions is a tempting but losing "dynamic" baseline — the win requires few-shot
  prototypes from in-domain labelled prose. (iii) This measures the *classifier*, not downstream
  STIX/judge quality; since the hint is advisory, the classifier delta is an **upper bound** on the
  end-to-end effect — quantifying the latter needs an LLM-in-the-loop hint-vs-no-hint ablation
  (server-dependent; deferred). Artifacts: `src/maljan/analysis/semantic_category.py`,
  `core/config.py` (`category_inference_backend`), `agents/judge_agent.py` + `core/container.py`
  wiring; `tests/unit/test_semantic_category.py`.

### 1.7.1 End-to-end hint ablation: the benefit is *completion*, not mapping accuracy — `IMPLEMENTED` / `OBSERVED`
- **What §1.7 deferred.** Whether the advisory schema-pruning hint actually improves the judge's
  final STIX bundle (not just the intermediate category). Ran the LLM-in-the-loop ablation against
  the live judge LLM (Qwen3.6-35B-A3B, **temp=0 — deterministic**, so any ON-vs-OFF difference is
  the hint's, not sampling noise). Each family is judged twice with identical inputs except the hint
  is forced empty in the OFF arm. Ground truth = the family's ATT&CK `uses` techniques; text = the
  family description. **17 paired families** had a hint (keyword non-UNKNOWN); 2 (wipers keyword
  can't name) were correctly excluded. Harness: `tests/evaluation/eval_hint_ablation.py`
  (checkpointed/resumable; the run was paused and resumed across a day with no loss).
- **Result (n=17 paired).**

  | metric | ON (hint) | OFF (no hint) | delta |
  |---|---|---|---|
  | empty/fallback bundles | **1 / 17** | **6 / 17** | the headline |
  | objects (mean) | 8.18 | 4.18 | +4.00 |
  | attack-patterns (mean) | 3.18 | 1.41 | +1.76 |
  | relationships (mean) | 3.59 | 1.59 | +2.00 |
  | TTP F1 exact (mean) | 0.032 | 0.003 | +0.029 |
  | TTP F1 parent (mean) | 0.126 | 0.051 | +0.075 |
  | precision (mean) | 0.093 | 0.015 | +0.078 |
  | hallucinated techniques | 0.0 | 0.0 | 0.0 |

  Paired TTP-F1(exact) mean delta **+0.029, 95% bootstrap CI [-0.001, +0.072]** (just crosses 0);
  sign test ON 4 / OFF 1 / 12 ties.
- **Finding (the real, somewhat unexpected effect).** The hint's measurable benefit is **not** better
  technique *selection* — the exact-F1 gain is small and its CI includes 0. The dominant, clear
  effect is **completion under the operational time budget**: without the hint the local model
  rambles past the 600 s judge timeout and falls back to an empty bundle **6×** as often (6/17 vs
  1/17), so ON yields roughly double the objects / attack-patterns / relationships and a modestly
  higher precision as a downstream consequence. The hint focuses and *bounds* generation so it
  finishes. (One sample inverted — ON timed out, OFF did not — so the asymmetry is strong but noisy.)
- **Honest scope of the claim.** This is an **operational, timeout-mediated** benefit specific to a
  slow local model under a fixed 600 s ceiling — not evidence of intrinsically better mapping. With a
  faster model or no timeout the OFF arm would more often complete and the gap would shrink. Absolute
  F1 is tiny by construction: GT is each family's *full-lifetime* ATT&CK set (24–55 techniques) vs a
  one-paragraph single verdict, so recall is floored; only the paired delta is meaningful.
- **Scope, pinned (P8, 2026-08-09).** The paragraph above already caveats the right thing — this
  is the one of the four claims that did — so this adds the identifier rather than the argument:
  **Qwen3.6-35B-A3B, IQ3_K_R4, ik_llama.cpp `llama-server`, temp=0, one machine, one 600 s judge
  ceiling** (full identity in §2.1), n=17 paired families. Two things are worth separating for the
  write-up. The **accuracy** claim is *negative and safely general*: the exact-F1 CI includes 0, so
  we assert no mapping benefit, and a negative under a favourable configuration is the easier
  direction to defend. The **completion** claim (6/17 → 1/17 empty bundles) is the positive one and
  is bounded by the model's generation speed against a fixed wall clock — it is a claim about *this
  model at ~40 tok/s under a 600 s ceiling*, and the C6 frontier arm is expected to shrink or erase
  it. That is not a weakness of the finding; it is the finding. The transferable statement is the
  takeaway already written below: an "advisory, low-impact" prompt addition can act through an
  unmeasured channel, so completion and bundle shape must be measured alongside F1.
- **Takeaways (paper + product).** (i) An "advisory, low-impact" prompt addition can have a
  first-order effect through an *unmeasured channel* (completion/latency), invisible to a pure
  mapping-quality metric — measure bundle shape and completion, not just F1. (ii) The
  category-driven STIX schema-pruning feature earns its place: disabling it ~halves bundle completeness and 6×'s the
  empty-fallback rate on this deployment. (iii) The §1.7 default (keyword) is reaffirmed — keyword
  supplies a hint ~94 % of the time on realistic text, so it already delivers this completion benefit;
  no backend change is warranted on this evidence. Artifacts: `tests/evaluation/eval_hint_ablation.py`,
  report `D:/tmp/hint_ablation.md`.
- **Mitigation shipped (follow-up).** The ablation incidentally exposed that the judge had **no
  output bound** — only the 600 s wall-clock — so a degenerate decode burns the whole budget before
  falling back to an empty bundle. Added `LLMConfig.judge_max_tokens` (default **8192**), wired in
  `container.get_judge_llm()`, bounding a runaway verdict to ~205 s at ~40 tok/s, well under the
  timeout. Verified non-truncating: MiniDuke and Emotet (obj=13/ap=4 uncapped) reproduce **obj=13,
  ap=4** capped — the bound has wide headroom over a real verdict bundle. This is a worst-case-latency
  guard (kin to the §3.3 damper), not a quality fix; focus still comes from the hint. `max_tokens` is
  a core OpenAI param ik_llama honors (unlike the silently-ignored `repetition_penalty`, §3.3). Full
  unit suite (1227) green; ruff/mypy clean.

### 1.8 OS-support scope: Windows + Linux only — `IMPLEMENTED` (deliberate narrowing)
- **Decision.** The pipeline officially supports **Windows and Linux** samples only. Driver: the
  dynamic sandbox (CAPEv2) produces reports for Windows (flagship, full API-hook/payload/config
  extraction) and Linux (supported); it has **no Android** support (Android dynamic analysis in the
  Cuckoo lineage was the separate, abandoned CuckooDroid) and only legacy/limited macOS. The earlier
  multi-platform taxonomy (macOS/Android/iOS/cloud/crossplatform) + Mobile ATT&CK frontend was
  speculative breadth with no end-to-end data source behind it.
- **What changed.** Backend: `reporting.models.Platform` Literal → `{windows, linux, unknown}`;
  `sample_identity._infer_platform` maps Mach-O/APK/IPA/jar and macOS/Android/iOS sandbox+MIME hints
  to `unknown`; `ttp_cascade._MITRE_PLATFORM_MAP` → Windows/Linux only and `MOBILE_ENTERPRISE_OVERLAP`
  (+ its android/ios fallback) removed; `fp_linter._PLATFORM_INCOMPATIBLE_TERMS`, `sigma._OS_PRODUCTS`,
  and `persistence._NON_WINDOWS_PLATFORMS` trimmed to Windows/Linux. Frontend: deleted
  `lib/mitre-mobile.ts`, collapsed the capabilities Mobile/Enterprise/ICS matrix selector to
  **Enterprise-only**, narrowed the `SamplePlatform` TS type.
- **Deliberately kept.** The Android *false-positive* denylists (`ANDROID_CLASS_REF_RE`,
  `_indicator_denylists`, the STIX-renderer noise filter) stay — they suppress garbage indicators when
  a sample *contains* Android-ish strings (NDK paths, JVM class refs); they are defensive FP hygiene,
  not OS support, and removing them would regress the §1.6/§1.9 indicator quality.
- **Consequence.** The previously-deferred "Android persistence (manifest/receiver) parser" backlog
  item is **dropped** — there is no Android data source in scope.
- **Verification.** `mypy` clean (99 source files); 1226 unit tests pass (platform tests updated:
  non-Win/Linux file types → `unknown`, obsolete android-gating test removed, fp-linter C3 cases
  re-pointed to Linux); web `tsc --noEmit` clean + ESLint 0 errors.
- **Follow-up — reject at the entry, not just relabel.** A later pass closed the last *live*
  remnant: `loaders/triage_client.py` still routed `.apk/.dex`→Android and `.dmg/.pkg/.app/.scpt`→
  macOS Triage profiles. Per an explicit scope decision we now **reject** non-Win/Linux samples
  rather than silently route them: a magic-byte-first detector
  (`sample_identity.unsupported_os_reason` — header magic for Mach-O/APK/IPA + an extension fallback
  for `.dex/.dmg/.pkg/.app/.scpt`) runs in `app.arun` **before** sandbox submission and raises the
  new `UnsupportedSampleError`; the worker's existing job-level handler surfaces it as a clean
  "failed: Unsupported sample OS …". The guard is deliberately conservative — only *definitely-foreign*
  files trip it, so an obscure/unknown Windows sample is never blocked — and backend-agnostic (covers
  Triage + CAPE + CLI). The Android FP denylists remain untouched (verified). The foreign-rule-drop
  tests (sigma/yara/cascade) were reframed to use a supported Win/Linux *sample* with a foreign
  *rule*, preserving every quality assertion without a non-Win/Linux sample platform. 1242 unit +
  report-pipeline tests pass; mypy/ruff clean.

### 1.9 Deterministic signal-quality hardening — `IMPLEMENTED`
- **Premise.** The deterministic extractors feed both the report and the LLM analysts, so a
  false positive or a miscalibrated confidence propagates and compounds. A four-part hardening
  wave raised signal quality across the extractor layer without adding speculative features.
- **(A) Network FP reduction + validation.** Drop reserved/private/link-local/broadcast IPs and
  RFC 6761 reserved / single-label domains from IOC emission (on both the CAPE and Triage-CTI
  paths); expand the benign CDN/infra allowlist; unify the DGA/benign suspicion scorer across
  sources; validate port (1–65535) and HTTP-status (100–599) ranges; lowercase + dedup URL hosts;
  fix HTTPS scheme inference (8443 / `encrypted` flag).
- **(B) Platform-aware persistence + dynamic FP reduction.** Gate the Windows registry/service/
  scheduled-task scanners on `sample_platform` (a Linux/Android sample is no longer flagged with
  Windows registry-run persistence — the critical FP); whitelist OS-normal injector processes
  (svchost/lsass/…); add XDG-autostart + systemd-timer Linux paths; harden the process tree
  (cycle detection, depth cap, duplicate-PID keep-first); drop read-only registry queries; require
  a cron-path write to corroborate a bare `crontab -e`.
- **(C) Anti-false-confidence calibration.** Drop zero-confidence + zero-evidence capability cells
  (they rendered as "verified" and seeded fabricated narrative); guard category inference against
  malformed ISR objects; fold suspicious network infrastructure into the LTM similar-samples query.
- **(D) Enrichment trust & freshness.** Pre-filter private/reserved IPs before paid reputation
  lookups; fix idempotency to retry *failed* (source-less) lookups; annotate VT reputation with
  `age_days` and treat >90-day data as stale; feed a verified-malicious reputation back into the
  heuristic `is_suspicious` flag; make the GeoIP DB path env-configurable.
- **Method note.** Findings came from a 3-agent code sweep; each was verified against the live
  code before implementation, and one ("word-boundary keyword matching" for category inference)
  was **rejected after testing** — it broke the keyword table's intentional stems
  (`keylog`→keylogger, `exfiltrat`→exfiltration), a reminder that an FP "fix" can destroy real
  signal. Net: deterministic FP↓ and calibration↑ with no valid-signal regression (verified by
  the existing + new extractor/enrichment test suites).

### 1.10 What the static Layer-0 sources contribute, and whether the cascade weights matter — `EXPERIMENTAL`
- **Motivation.** The TTP cascade is the concrete instantiation of "deterministic layer
  disposes", and neither half of it had been measured: not the sources feeding it, and not the
  eleven constants inside it (`LAYER_WEIGHTS` 0.90…0.20, cross-layer multipliers 1.00…1.90).
  The §3.1 review made this urgent rather than merely untidy — weighting evidence by source
  reliability and discounting non-independent sources is **Dempster–Shafer theory**, so "our
  constants are plausible" is not a defence when a principled formalism already exists.
- **Method.** Three of the six Layer-0 sources read only the sample bytes and its parsed PE, so
  they run with no LLM and no sandbox: `yara_layer`, `import_capability_layer`,
  `tool_artifact_layer`. Run over **209 real PE samples** (189 produced evidence), then the same
  ISR tuples fed to `TTPCascadeEngine` under five weight perturbations — flat 0.5, inverted
  yara↔network, compressed ×0.25 toward 0.5, stretched ×1.75, and yara demoted 0.90→0.45.
  Harness `tests/evaluation/eval_layer0_contribution.py`; pure helpers unit-tested in
  `test_layer0_contribution_scoring.py`; artifact `tests/evaluation/layer0_contribution.json`.
- **Result — source contribution.**

  | source | fires on | techniques emitted | unique to it |
  |---|---|---|---|
  | `yara_layer` | **89.5%** (187/209) | 812 | 79.8% |
  | `import_capability` | **52.6%** (110/209) | 694 | 76.5% |
  | `tool_artifact` | **2.4%** (5/209) | **5** | 80% (4 techniques) |

- **Result — corroboration ceiling.** 1,184 techniques were seen by exactly one domain and 163
  by two: **87.9% of techniques are single-source** before the sandbox is in play.
- **Result — weight sensitivity.** Across all five perturbations the top-10 ranking changed on
  **10.6–27.5%** of samples and the corroborated set changed on **0.0%**, every time.
- **Findings.** (i) **`tool_artifact` is effectively inert** — 5 techniques across 209 samples,
  and because it emits `domain="yara"` it cannot contribute an independent layer even when it
  fires. Reporting per *source* rather than per *domain* would have made three sources look like
  three layers; the two views differ by exactly one technique across the corpus, and only the
  domain view governs `is_corroborated`. (ii) **The weights are far less load-bearing than they
  look.** The 0.0% is structural, not a corpus artifact: `is_corroborated` is
  `len(contributing_layers) >= 2` and never consults `LAYER_WEIGHTS`, so the label the report
  displays most prominently is independent of all five constants — and inverting the most- and
  least-trusted layers leaves the ranking identical on ~72% of samples. This defends the
  constants against "arbitrary" and simultaneously raises why they exist at all.
- **Honest scope.** Three of six layers. Sigma (2,651 rules), LOLBin and network-DGA consume a
  sandbox report and are `[CAPE]`-gated; they are also the layers weighted *below* yara, so
  their absence does not flatter the result. This is a **static** Layer-0 ablation and is named
  that way. The full cascade ablation (flat union vs cascade, end-to-end) still needs the LLM.
- **Incidental.** The eval's own unit tests found a defect in it: a whitespace-only
  `technique_id` survived the `NONE` filter and entered the sets as an empty-string "technique"
  that would then appear corroborated across every source that also had one.

---

## 2. Empirical systems findings (local deployment)

Hardware: RTX 5060 (8 GiB VRAM), 31 GiB system RAM, Windows 11 + WSL2/Docker.
Model: Qwen3.6-35B-A3B (MoE, 35B total / ≈3B active), IQ3_K_R4 quant, served by
ik_llama.cpp `llama-server` with hybrid CPU/GPU offload.

### 2.0 Model and engine provenance — `IMPLEMENTED` (P9), recorded 2026-08-09

> **Why this section exists.** *Chasing Shadows*' pitfall **P9 (Model Ambiguity)** asks for
> details sufficient for precise identification: model ID, snapshot, commit, quantization. §2.1
> below reports a **sampler behaviour of this specific engine build** as a finding, and that
> finding is not reproducible without the identifiers here. This is also the reproducibility
> appendix's source of truth (queue item E5).

**Model — fully pinned.**

| field | value |
|---|---|
| file | `models/Qwen3.6-35B-A3B-IQ3_K_R4.gguf`, 15,340,250,080 bytes |
| **sha256** | `d0de70ef693eb2af1a3803d4fb2c93cf375db19b0a5e0fb2cae79c1678cbc4ea` |
| **HF revision** | `cfd350fde08a91e4017d22db422e9ad1eac71f0d` |
| retrieved | **2026-05-11 20:39:17 UTC** |
| `general.architecture` | `qwen35moe` |
| `general.quantized_by` | **Unsloth** (`general.repo_url = https://huggingface.co/unsloth`) |
| base model | `https://huggingface.co/Qwen/Qwen3.6-35B-A3B`, Apache-2.0 |
| `general.file_type` / `quantization_version` | `339` / `2` |
| **imatrix** | `Qwen3.6-35B-A3B-GGUF/imatrix_unsloth.gguf`, dataset `unsloth_calibration_Qwen3.6-35B-A3B.txt`, 510 entries / 76 chunks |
| tokenizer | GPT-2 BPE, `pre = qwen35`, 248,320 tokens, `add_bos_token = false` |

The sha256 was computed here **and** matches the HuggingFace download etag independently, so the
file is byte-identical to the published artifact. The calibration dataset being *named* is worth
noting: importance-matrix quantisation is a lossy transform whose result depends on its
calibration text, and most work reporting a quant level does not say which imatrix produced it.

**Engine — commit recovered, but not from the running binary.** The artifact itself is mute:

```
$ llama-server --version
version: 0 (unknown)
$ cat ~/maljan-llm-build/ik_llama.cpp/common/build-info.cpp
int LLAMA_BUILD_NUMBER = 0;
char const *LLAMA_COMMIT = "unknown";
```

The build tree at `~/maljan-llm-build/ik_llama.cpp` **is not a git checkout** — no `.git`, only a
`.gitignore` and `.gitmodules` left behind — so CMake's build-info step had no commit to record.
The commit was recovered from a **second** copy of the same sources, the shallow clone vendored in
this repository at `external/ik_llama.cpp`, and then *proved* to describe the build tree:

| field | value |
|---|---|
| **engine source commit** | **`eb570eb96689c235933b813693ca28ab9d3d26de`** |
| commit subject / date | *"MTP: Avoid per step SSM copy (#1778)"*, 2026-05-11T18:15:55+03:00 |
| upstream | `https://github.com/ikawrakow/ik_llama.cpp`, reachable on `origin/main` (clone is depth 1) |
| **engine binary sha256** | `7737b2a90e33e2afc364801df13d33d506864a3390d6d61b92a11a029450542d` |
| binary built | 2026-07-05 22:02 +03 |
| compiler | `cc (Ubuntu 15.2.0-16ubuntu1) 15.2.0`, target `x86_64-linux-gnu` |
| build-tree source hash | `5911b1281d4774bcf89ae1d3b657a7888e48e97da0610d2149374fe8fc2c15b8` (837 files, `LC_ALL=C sort`ed, build dirs excluded) |

**How the correspondence was established, since it is the part a reader has to trust.** Both trees
were enumerated with the same recipe — `*.c/cpp/h/hpp/cu/cuh/metal` plus `CMakeLists.txt`, build
directories pruned — giving **identical file lists of 837 sources**. Comparing them file by file
with CR stripped, **exactly one file differs: `common/build-info.cpp`**, which is generated at
build time and is precisely the file that holds `unknown` in the copy and `eb570eb` in the clone.
Every other source byte is the same. So the Linux CUDA binary that produced every LLM result in
this work was compiled from commit `eb570eb9`.

Two details are worth keeping rather than smoothing over. First, the vendored clone's own
generated build-info reads `LLAMA_COMPILER = "MSVC 19.44.35225.0"`, `LLAMA_BUILD_TARGET = "x64"` —
i.e. the *same source* was also built once on Windows; the serving binary is the Linux CUDA one in
the table above. Second, the trees differ in line endings throughout (`git diff --stat` on the
clone reports 1,967 files changed with **737,043 insertions and 737,043 deletions** — equal counts,
the signature of CRLF↔LF, not of edited code), which is why the naive content hashes disagree and
the normalised comparison is the one that means anything.

**The reproducibility lesson survives, in a narrower and more accurate form.** The running binary
could not identify itself. Recovering its provenance required a second copy of the sources to exist
by luck, plus a byte-level proof that the two correspond. Had `external/ik_llama.cpp` not been
vendored, or had it drifted, the engine behind §2.1's sampler finding would genuinely have been
unrecoverable. **Build provenance must be captured at build time**; reconstructing it afterwards
worked here and is not a method anyone should rely on.

**Serving configuration**, from the systemd unit (`~/.config/systemd/user/maljan-llama.service`):

```
llama-server -m Qwen3.6-35B-A3B-IQ3_K_R4.gguf -c 131072 -t 16 -fa on \
  -ctk q8_0 -ctv q8_0 -ngl 999 \
  -ot "blk\.([1-3][0-9])\.ffn_(up|gate|down)_exps=CPU" \
  --context-shift on --jinja --alias qwen3.6-35b-a3b --host 0.0.0.0 --port 8080
```

**Two things this dump settled that are not bookkeeping:**

1. **The architecture is hybrid recurrent/attention, and the GGUF proves it.** `ssm.conv_kernel=4`,
   `ssm.state_size=128`, `ssm.group_count=16`, `ssm.time_step_rank=32`, `ssm.inner_size=4096`,
   alongside `full_attention_interval=4` — i.e. full attention every fourth of 40 blocks, linear
   recurrent state in between; 256 experts, 8 active. This is the documented mechanism behind the
   re-prefill behaviour that caused the 2026-08-07 timeouts: a recurrent state cannot be restored
   from a partial cache the way a pure-attention KV cache can, so parallel analysts sharing one
   server slot force full re-prefills. That was previously an inference from behaviour; it is now
   read off the model file.
2. **We serve at half the model's native context.** `qwen35moe.context_length = 262144`; we run
   `-c 131072`. §2.1 records why (the 262k config wedged under sustained load), but the
   consequence belongs to **P6**: every truncation bound in the system sits under a window that is
   itself a deliberate halving. A2 records the number; **A3** counts how often it binds.

**One reproducibility defect found while doing this.** `.serena/memories/suggested_commands.md`
documents the launch as `--n-cpu-moe 36`, but the service actually runs
`-ot "blk\.([1-3][0-9])\.ffn_(up|gate|down)_exps=CPU"` — that regex matches blocks **10–39**, so
**30** blocks' experts go to CPU, not 36, and blocks 0–9 keep theirs on GPU. The documented
command and the running command are different deployments. Every §2 throughput and memory number
was produced by the *service*, so the numbers stand; the documentation is what is wrong, and it is
exactly the kind of drift P9 exists to catch. Fixing that doc is E5's job.

### 2.1 KV-cache scaling is dominated by weight offload, not context — `EXPERIMENTAL`
- **Measured (boot-time, `-ctk q8_0 -ctv q8_0 -fa on`).** KV ≈ **10.85 KiB/token**
  (both caches). 128k ctx → **1.42 GiB**; 262k ctx → **2.78 GiB** — both
  GPU-resident. Free system RAM was essentially unchanged between 128k (≈5.08 GiB
  free) and 262k (≈5.21 GiB free).
- **Finding.** On a hybrid-offload MoE deployment, **context length barely moves
  system RAM**; the RAM cost is the offloaded weights (~12.1 GiB pinned host
  memory), which is constant across context sizes. The binding constraint during
  analysis is co-resident services (the Ghidra container), not the KV cache.
- **Correction of an a-priori estimate (recorded for honesty).** A GGUF-parameter
  theoretical estimate (40 layers × 2 KV-heads × head_dim 256) over-predicted KV by
  ~4×, leading to an initial (wrong) "262k = OOM" conclusion. The empirical
  measurement overturned it: 262k is feasible (and was deployed at the time of
  measurement). **Production later settled on `-c 131072`** for runtime stability —
  the 262k + quantized-V-cache config wedged (GPU-idle, HTTP-unresponsive) every
  ~7–10 min under sustained load (see `run_llama.ps1`); the KV-scaling finding below
  is unchanged. **Lesson: measure KV at boot, don't trust the closed-form estimate
  for this architecture.**
- **Throughput.** 38–44 tok/s generation, stable across 32k → 128k → 262k.

### 2.2 Whole-tool-catalogue exposure is infeasible for the small model — `EXPERIMENTAL` / `OBSERVED`
- ~201 tool schemas ≈ 22k tokens raw (≈30–44k tokens once JSON-schema-serialised).
  Independently of context size, a ≈3B-active model degrades on tool selection well
  before that scale (hallucinated tool names, wrong-tool loops). Validates the
  curated-allowlist design (§1.4).

### 2.3 Negative result: MTP / speculative decoding on A3B MoE — `NEGATIVE`
- Tested mainline llama.cpp MTP / speculative-draft decoding against the production
  ik_llama + IQ3_K_R4 setup. **No throughput gain** on this A3B MoE; the engine swap
  regressed quality. Kept the production setup. (Recorded as a negative result.)

---

## 3. Experimental contributions (prompting structure)

### 3.1 Reviewed prior art and transfer assessment — `OBSERVED`
- **Maltracker [1]** (NPM/JS, learning-based): transferred ONE idea (sink-reachability,
  §1.1); the dataset/learned-classifier core does not transfer.
- **Rollinson & Polatidis [2]** (LLM-generated tabular Android samples): `NEGATIVE`
  transfer — no trained classifier in Maljan. Its own finding ("synthetic data
  reinforces existing statistical structure, does not introduce new predictive
  information; synthetic-only training is family-dependent and often collapses") is
  **published evidence supporting our deterministic-corpus discipline**: it argues
  against augmenting the Qdrant long-term-memory with LLM-fabricated cases (which
  would inject hallucination into attribution).
- **AppPoet [3]** (multi-view prompt engineering + DNN classifier): the trained-DNN
  half does not transfer, but the **multi-view prompt decomposition + describe-then-
  synthesise + "LLM proposes, deterministic layer disposes"** halves do — and the
  last one is independent published validation of Maljan's judge + fp_linter design.
- **MaLAware [4]** (Cuckoo report → LLM → human-readable behaviour summary on five 7B
  open models): Maljan already performs report-from-evidence; the transferable value
  is its **evaluation protocol** (multi-metric vs human-written references) for
  scoring LLM-generated malware narratives, and independent validation that 7–9B
  local models suffice for the narration task.

**Expanded 2026-08-08 after a systematic, citation-verified review.** The four entries above
were the whole of our prior-art position; the field is considerably more crowded, and four of
its results bear directly on claims this log had recorded as contributions. Full working papers
in [`research-briefs/incoming/`](../../docs/academic-article/research-briefs/incoming/); the
per-claim verdicts are in [`research-briefs/novelty-ledger.md`](research-briefs/novelty-ledger.md).

- **Büchel et al. SoK [5]** (USENIX Security 2025) — 40+ systems re-evaluated in one setting.
  Reports a performance ceiling nobody has crossed, that traditional NLP beats embedder and
  generative approaches in realistic settings, and that dataset quality and ontological
  ambiguity are the field's blockers. Binds §1.5.1 (see there).
- **Infer-Retrieve-Rank [6]** (2024, general ML) — the general form of describe-then-map.
  Demotes §1.5's novelty claim to a domain instantiation.
- **TechniqueRAG [7]** (ACL Findings 2025) and its hierarchical successor — retrieve-then-rerank
  for ATT&CK; the latter cuts the candidate space 77.5% by filtering at tactic level first.
- **TTPDetect [8]** (2026) — an LLM agent mapping **stripped malware binaries** to ATT&CK at
  93.25% function-level precision, with a deterministic retrieval pre-pass feeding an LLM
  reasoner. Architecturally our shape, and it removes "binary evidence rather than report prose"
  as a positioning claim. It also built a decompiled-function↔TTP dataset, which supersedes the
  §4 `SURVEY` conclusion that no such corpus exists.
- **Chasing Shadows [9]** (NDSS 2026, with Arp of *Dos and Don'ts*) — all 72 LLM-security papers
  from 2023–2024, **every one** containing at least one of nine pitfalls and only 15.7%
  acknowledged. Places §3.4 inside a named tradition rather than ahead of it.
- **Bertalanič & Fortuna [10]** and **Tran & Kiela [11]** (both 2026) — at equal token budget,
  single agents match or beat multi-agent debate; the former on 7–8B models at 2.1–3.4× the
  tokens, naming *sycophantic conformity* (modal adoption up to 85.5%) among its failure modes.
  Both scope the result to *homogeneous* agents on one context and name heterogeneous or
  degraded-context settings as the exception — which is the entire defence of our architecture,
  and is a hypothesis until the equal-budget ablation is run.
- **REx86 [12]** (ACSAC 2025) — local open-weight RE assistant, motivated explicitly by
  closed-network confidentiality, with a 43-participant user study. Removes "confidentiality as
  a first-class constraint" from our contribution list.
- **Ng & Milani Fard [13]** (SecDev 2026) — a published negative RAG result in malware analysis:
  retrieval degrades explanation quality because the task is signal extraction, not knowledge
  retrieval. §1.5.3 is therefore the *second* such result, by a different mechanism.
- **Dempster–Shafer evidence theory** — weighting sources by reliability and discounting
  non-independent ones is decades old. The TTP cascade is an ad-hoc instance of it, which makes
  its unmeasured constants harder to defend, not easier. See §1.10.

**Method note worth keeping (paper-relevant).** Four of these were found only by searching an
**adjacent field's** vocabulary: Infer-Retrieve-Rank indexes as general ML, TTPDetect as binary
analysis, the cascade's formalism as sensor fusion, and the narrative result as data-to-text NLG.
A search confined to the subfield a claim *sounds* like will miss the work that owns it — and in
this review it did, until corrected.

### 3.2 View-decomposition for small-model static analysis — `EXPERIMENTAL` → `INCONCLUSIVE`
- **Question.** Given identical evidence, does focused per-view sub-prompting
  (AppPoet [3] style) beat one monolithic prompt for a small local model?
- **Method.** Self-contained A/B harness (no production code touched). Fixed,
  balanced evidence bundle modelling a Linux ELF backdoor. Same live local model
  (Qwen3.6-35B-A3B), temperature 0. Arms: monolithic (1 call); 2-view
  (behaviour vs artifacts, 2+1 calls); 4-view (4+1 calls). Metrics: parsed CLAIM
  count, ATT&CK technique IDs, grounding (evidence-artifact presence), tokens,
  wall-clock. Harness: `D:/tmp/view_ab_experiment.py`.
- **Result — the parsed-claim ranking was UNSTABLE across runs.**

  | Run (per-call budget) | monolithic | 2-view | 4-view |
  |---|---|---|---|
  | max_tokens 1400 | 2 | 2 | 4 |
  | max_tokens 4000 | **9** | 2 | 4 |

  Raising the per-call budget flipped the ranking: monolithic jumped 2 → 9 and
  overtook the decomposed arms.
- **Root cause (the real finding).** Three factors swamp the prompt-structure effect
  at N=1: (i) **unequal total generation budget** — a 4-view run gets ~5× monolithic's
  total tokens, so the earlier "more findings under decomposition" was largely a
  budget artifact; (ii) **unreliable reasoning suppression × truncation** — how much
  *formatted* output survives depends on a per-run thinking-vs-budget interaction;
  (iii) **claim-count is a poor quality proxy** — with more budget monolithic
  over-generated, including a **hallucinated technique ID (T1000, not a valid ATT&CK
  ID)** and a mis-applied one (T1055.012 Process Hollowing on a Linux ELF). The
  grounding metric (100% across all arms) does NOT catch technique-level
  hallucination — it only checks evidence-artifact presence.
- **What survives as defensible (budget-independent, structural).**
  - **Fault isolation** `OBSERVED`: when the model derailed on one view (the §3.3
    loop), findings from the other views — captured in separate calls — survived; in
    the monolithic arm one derailment truncated everything after it.
  - **Output stability** `OBSERVED`: decomposed arms held a stable claim count across
    budgets (2-view ≈ 2, 4-view ≈ 4) while monolithic was volatile (2 ↔ 9), because
    per-view calls bound the per-call work.
- **Conclusion.** `INCONCLUSIVE` on completeness. The earlier "~2× completeness"
  reading was a budget/measurement artifact and is **retracted**. The structurally
  defensible benefits are fault isolation and output stability. A valid study
  requires: equal total generation budget per arm; N ≫ 1 with mean ± bootstrap CI;
  a forced/structured output format to remove truncation as a variable; and blinded
  correctness scoring of both claim and technique (not claim count + string-grounding).

### 3.3 Novel failure mode: degenerate technique-ID loop — `OBSERVED` (reproducible) → `IMPLEMENTED` (fixed)
- **Phenomenon.** On anti-analysis evidence (`ptrace`/`prctl`), the model does not
  know the correct ATT&CK technique ID and enters a **catastrophic degenerate loop**,
  emitting "I'll just use T1578.005?" hundreds of times and burning the entire token
  budget, while repeatedly proposing *wrong* IDs (T1578.005 is a cloud technique;
  T1553.002 is trust-subversion — neither is anti-debug, which is T1622 Debugger
  Evasion). Reproduced across both experiment runs and both prompt structures.
  Practical consequence: any production analyst driving this model on a sample with
  anti-debug primitives risks the same budget-burning loop.
- **Fix (implemented two-layer).** (i) **Mechanical damper** — a repetition penalty
  forwarded to the local server (§1.5 partner); (ii) **root-cause removal** — route
  technique-ID assignment through the deterministic TF-IDF index (§1.5), so the model
  never has to recall the ID. (i) is a damper; (ii) is the actual fix.
- **Empirical sampler finding (live ik_llama probe, 2026-06-01).** Reproducing the
  `ptrace`/`prctl` loop and toggling sampler params on the OpenAI-compatible endpoint:
  `repeat_penalty` is the **honored** key (it changes greedy output); `repetition_penalty`,
  `frequency_penalty`, and `presence_penalty` are **silently ignored** by this engine.
  More important: the penalty only **converts a tight single-token loop into a slower
  ID-enumeration ramble** (e.g. cycling T1574.001…T1574.017) — it still burns the full
  budget and does **not** make the small model converge on a correct ID. This is the
  empirical justification for fix (ii): penalty tuning alone is insufficient; the
  ID-recall task must be removed, not merely damped.
- **Why it is paper-worthy.** A concrete, reproducible pathology
  (under-specified 600+ label space × autoregressive self-reinforcement), plus the
  finding that the obvious mitigation (sampler penalties) is necessary-but-insufficient,
  and a clean fix (offload the taxonomy lookup to deterministic retrieval).
- **Scope of the claim (P8, 2026-08-09).** Everything above is measured on **one model on one
  machine**: Qwen3.6-35B-A3B, IQ3_K_R4, served by ik_llama.cpp `llama-server` (exact revision,
  GGUF digest and engine commit in §2.1). Within that scope it is robust — reproduced across
  **two independent experiment runs and two prompt structures**. What the evidence does *not*
  support is the phrase this entry previously used, *"a small-model pathology"*: that
  generalises one model to a class. The mechanism (large label space × autoregressive
  self-reinforcement) plausibly transfers, but plausibility is not measurement, and
  `arXiv:2606.18166` — parameter size the only significant predictor of ATT&CK-classification
  F1, ρ=0.85, p=0.014 — is a direct reason to expect model-to-model variation here. **The
  sampler half is narrower still and is a property of the *engine*, not the model:**
  `repeat_penalty` honored while `repetition_penalty` / `frequency_penalty` /
  `presence_penalty` are silently ignored is an ik_llama.cpp behaviour at the pinned commit,
  and says nothing about llama.cpp upstream, vLLM or a hosted endpoint. Generalisation is
  **E.8**, open until the frontier arm runs.
- **Literature position (2026-08-08, ~~`OURS`~~ **corrected 2026-08-09 → `REFINEMENT`**).** The
  *hallucinated-ID* concern is well represented — TTPrint [8] retains only candidates supported by
  both localised evidence and the MITRE definition, and constrained decoding is the standard
  remedy. The 08-08 review found no precedent for the **budget-exhaustion** framing or for
  "sampler penalties are necessary-but-insufficient", and recorded this as `OURS`.
  **That was a security-vocabulary search, and the adjacent field owns half of it.** The A4
  counter-search looked under **neural text degeneration** and found the insufficiency of
  penalties is that field's settled position: Welleck et al., *Neural Text Degeneration with
  Unlikelihood Training* (`arXiv:1908.04319`); *Repetition In Repetition Out* (`arXiv:2310.10226`,
  NeurIPS'23), which attributes degeneration to self-reinforcement and training-data repetition;
  and *Rethinking Repetition Problems of LLMs in Code Generation* (`arXiv:2505.10402`), which
  states directly that a uniform repetition penalty is **detrimental** for frequently-recurring
  tokens. Our "necessary but insufficient" is a rediscovery.
  **What survives, and it is the more interesting half:** degeneration here is a **delivery**
  failure, not a text-quality one. The ramble exhausts the generation budget, the judge overruns
  its 600 s ceiling, and the analyst receives an **empty STIX bundle** — §1.7.1 measures exactly
  that channel at 6/17 vs 1/17. The degeneration literature measures repetition rate and text
  quality; none of it measures a structured deliverable failing to exist. Also ours, and narrower
  still: the engine-level finding that ik_llama honors `repeat_penalty` while silently ignoring
  `repetition_penalty` / `frequency_penalty` / `presence_penalty` (§2.0 pins the commit).
  *The three degeneration papers are demotion evidence pending full-text confirmation; each must
  be read before the paper cites it.*

### 3.4 Negative methodological finding: single-run claim-count is not a valid instrument — `NEGATIVE`
- Running the §3.2 A/B three times under different decoding budgets produced
  **contradictory rankings of the same arms**. The dominant variance came from the
  measurement setup (reasoning-suppression reliability × token budget ×
  over-generation), not from the independent variable (prompt structure).
- **Takeaway for the paper's methodology section.** For reasoning LLMs emitting
  free-form structured findings, a naive single-run parsed-claim count is **not a
  valid measurement instrument**. Valid comparison requires: (a) equal total
  generation budget across arms; (b) a constrained/forced output format; (c) scoring
  *correctness* (claim AND technique), not count; (d) N ≫ 1 with confidence
  intervals. We surface this as a cautionary methodology result for LLM-for-malware
  evaluation — easy to get wrong, and wrong in a way that silently inverts rankings.

### 3.5 MaLAware-style narrative-quality harness — `IMPLEMENTED`
- **Question.** MaLAware [4] scores LLM-generated malware narratives and argues small
  local models suffice for the narration task. Does Maljan's NarrativeAgent produce a
  *faithful* narrative, and does it beat the deterministic fallback template?
- **Method.** `tests/evaluation/eval_narrative_quality.py` — a paired A/B harness built
  to the §3.4 bar. Each fixture family (rat/ransomware/dropper/worm/infostealer) becomes
  a **fixed evidence bundle** (a synthesized `MalwareReport` whose `ttp_mappings` carry the
  fixture's technique ids); both arms narrate the *same* bundle. **LLM arm** =
  `NarrativeAgent.generate` (repeated K× for N≫1 + decoding-variance CI, pinned `max_tokens`
  budget); **fallback arm** = `apply_fallback_narrative` (deterministic).
- **Quality, operationalised without human reference prose** (the repo vendors only
  technique-id ground truth, not narratives): **grounding precision** (cited techniques
  present in the evidence — the prompt's "do not invent" rule), **coverage recall**
  (evidence techniques surfaced), **structural compliance** (length / paragraph count /
  parenthesised-ID format), and **fp_linter clean-rate** (no C2 recommendation-cites-absent
  -technique / C3 exec-summary platform mismatch). Reported as mean ± 95% bootstrap CI;
  the paired LLM−fallback F1 delta gets a bootstrap CI + sign test. All scoring is
  deterministic and CI-covered by `tests/evaluation/test_narrative_quality_scoring.py`
  (no live LLM); the LLM arm runs against a llama-server.
- **Status.** Harness + scoring unit tests shipped. **Live run** (2026-06-04, Qwen3.6-35B-A3B,
  5 fixtures × 3 repeats = n=15, `enable_thinking=false`). Mean [95% bootstrap CI]:

  | metric | LLM narrative | deterministic fallback |
  |---|---|---|
  | grounding precision (faithfulness) | 1.000 | 1.000 |
  | coverage recall | 0.853 [0.71, 0.95] | 1.000 |
  | F1 | 0.889 [0.75, 0.97] | **1.000** |
  | structural pass-rate | **0.733 [0.53, 0.93]** | 0.000 |
  | hallucinated techniques | 0.000 | 0.000 |

  Paired LLM−fallback **F1 delta = −0.111 [−0.252, −0.030]** (CI excludes 0; sign test: fallback
  wins 7, ties 8, LLM wins 0). **Finding:** both arms are perfectly *faithful* (precision 1.0,
  zero hallucination) — the MaLAware premise that a small local model narrates without inventing
  capabilities **holds**. But on the faithfulness+coverage F1 the **deterministic template is the
  stronger baseline** (it covers every evidence technique by construction → recall 1.0; the LLM
  omits some → 0.853). The LLM's *only* edge **in this measurement** is **structural/readability
  compliance (0.73 vs 0.00)** — i.e. the justification for the LLM narrator is human-readable
  prose, **not** accuracy or coverage, where the deterministic template is at least as good. A
  useful negative-ish result: don't pay for an LLM narrative on faithfulness grounds; pay for it
  only if readable prose is the product. (This supersedes the earlier n=1 smoke, which was an
  uninformative tie.)
- **Scope of the claim (P8, 2026-08-09).** **n=15 — 5 fixture families × 3 repeats — on one model
  on one machine**: Qwen3.6-35B-A3B, IQ3_K_R4, ik_llama.cpp `llama-server`, `enable_thinking=false`
  (full identity in §2.1). Three limits follow and none of them is cosmetic. (i) The **coverage**
  gap is the finding most likely to be model-dependent: recall 0.853 is this model omitting
  techniques under a pinned `max_tokens`, and a model that omits fewer would narrow or close the
  −0.111 F1 delta. (ii) The **faithfulness** result — precision 1.000, zero hallucinated
  techniques in both arms — is the more robust half, but 15 narrations is a thin base for
  "never invents", and the correct reading is *no hallucination was observed at n=15*, not
  *hallucination does not occur*. (iii) "**Structural compliance**" is a code-computed proxy
  (length / paragraph count / parenthesised-ID format), **not readability**; that the template
  scores 0.000 on it means the template ignores a format rule, not that its prose is unreadable.
  Whether readable prose is actually the LLM's edge is **E.7**, and no human analyst has scored
  a report. Generalisation across models is **E.8**, open.

### 3.6 View-decomposition — config-gated mechanism + a valid (equal-budget) study — `IMPLEMENTED`
- **Question.** §3.2 left this `INCONCLUSIVE`: does splitting an analyst's evidence into N
  focused views beat one monolithic prompt? The prior probe's apparent win was a budget
  artifact (a 4-view run got ~5× the tokens) and it scored claim-count, not correctness.
- **Mechanism (config-gated, off by default).** `LLMConfig.view_decomposition_views` (0 = the
  current single monolithic call). When N>0, `BaseAnalyst.analyze_isr_views`
  ([base_agent.py](../../src/maljan/agents/base_agent.py)) runs N focused, **tools-free**
  sub-prompts over the *same* evidence concurrently (`ThreadPoolExecutor`), each capped at
  `expert_max_tokens // N` so the **total generation budget equals the monolithic arm** — the
  control §3.2 lacked — then merges per-view ISRs via the existing `merge_chunk_isrs`. A
  derailed view is dropped (fault isolation). Text path only (the Ghidra/CAPE ReAct loop is
  untouched); gated in `make_analyst_node` on the single-chunk path so the default leaves
  today's behaviour byte-for-byte.
- **Valid study.** `tests/evaluation/eval_view_decomposition.py` A/Bs monolithic vs 2-view vs
  4-view at **equal total budget**, N≫1 repeats, scoring the **invalid technique-id rate**
  (the §3.2 T1000 failure mode, via the production `ATTCKValidator`), grounding rate, and
  claim-count **stability** (the budget-independent property §3.2 found defensible) — mean ±
  bootstrap CI per arm. Pure scoring helpers are CI-covered
  (`test_view_decomposition_scoring.py`); the mechanism is unit-tested
  (`tests/unit/agents/test_view_decomposition.py`) without a live LLM.
- **Status.** Mechanism + harness + unit tests shipped (off by default). **Live partial run**
  (2026-06-04, Qwen3.6-35B-A3B, equal budget B=2000, 3 fixtures × 3 repeats = n≈8–9/arm; the
  full 5×3 run was cut short by a hardware stall, see below). Mean [95% bootstrap CI]:

  | arm | n | claim count | invalid-id rate | grounding rate | claim stability (σ) |
  |---|---|---|---|---|---|
  | monolithic | 9 | 7.0 [6.1, 8.2] | 0.00 | **0.334 [0.11, 0.58]** | 1.20 |
  | 2-view | 9 | 13.0 [10.7, 15.6] | 0.00 | 0.238 [0.11, 0.36] | 3.10 |
  | 4-view | 8 | 17.6 [14.9, 19.6] | 0.042 [0, 0.13] | 0.142 [0.07, 0.21] | 2.16 |
  | 3-tier | 8 | 13.8 [12.4, 15.8] | 0.00 | 0.070 [0.02, 0.11] | 1.58 |

  **Finding (this corrects the misleading n=1 smoke, which had shown 2-view > monolithic).** At
  equal budget, decomposition trades **grounding for volume**: claim count rises with
  decomposition depth (mono 7 → 2-view 13 → 4-view 18) while grounding falls monotonically
  (0.334 → 0.238 → 0.142), and **tier reasoning is the *least* grounded (0.070)** — the sequential
  synthesis tiers drift toward interpretation that cites less concrete evidence. **Monolithic is
  both the most grounded and the most stable** (σ 1.20). The §3.2 hallucination failure mode does
  **not** recur in any arm (invalid-id ≈ 0; 4-view's 0.042 CI includes 0). Caveats: partial
  (3/5 fixtures), high per-sample variance (monolithic grounding 0.83 on ransomware vs ~0 on
  infostealer), and mono-vs-2-view CIs overlap (not separable at this n); mono > 3-tier is the
  one near-clean separation.
  *Two methodology fixes landed during this run:* (i) the analyst's chain-of-thought is disabled
  for the eval (`chat_template_kwargs.enable_thinking=false`) — the reasoning model otherwise
  spends the whole token budget inside `<think>` (stripped by the server → empty CLAIM output);
  (ii) `_bootstrap_ci` now samples the LCG's **high** bits — `seed % n` collapsed the CI whenever
  n was a power of two (the low LCG bits have a short period), which had hidden the n=8 spread.
  *Hardware note:* the 4-view arm fires 4 concurrent sub-calls; on the single-GPU CPU-MoE local
  server those contend and stall (each ~4× slower, past the 180 s skip), which capped the run at
  34/60. The fix for a full clean run is `llama-server --parallel N` *with* the views run
  sequentially, or a faster decode host — recorded for the eventual complete-corpus run.

### 3.7 Negotiated consensus vs a single agent at equal token budget — `EXPERIMENTAL` / `NEGATIVE`

- **Why this is the load-bearing experiment.** The project's own framing rests on multi-agent
  negotiation, and by 2026-08-08 the literature's prior had turned against it: `arXiv:2604.02460`
  (Stanford) and `arXiv:2605.00914` both find single agents match or beat multi-agent debate at
  equal budget, the latter on 7–8B models — our scale — at 2.1–3.4× the tokens. **Both scope that
  result to *homogeneous* agents decomposing *one* context, and both name heterogeneous evidence
  channels as the exception.** Ours are heterogeneous evidence channels. That was our defence, and
  this experiment was pre-registered to test it either way.
- **Design, taken from Bertalanič & Fortuna rather than invented here.** Three arms over 5 fixture
  families × 5 repeats:
  - **`single`** — one call, all channels concatenated, full budget B.
  - **`negotiated`** — K=3 channel analysts (static / dynamic / network), one channel each, then a
    mediator that reconciles their claims. **K+1 = 4 calls at B/4**, so the mediator is paid for
    out of the same budget.
  - **`noise`** — `negotiated`, but one analyst is fed a *different sample's* channel. Their
    stochastic control: if this scores like `negotiated`, the negotiation is aggregating rather
    than reconciling.
  Evidence never names a technique id — each artifact *implies* its technique — and the harness
  aborts if a ground-truth id leaks, because the metric is accuracy against that ground truth.
  B=2400, temp per production, `enable_thinking=false` applied identically to every arm.
  Harness `tests/evaluation/eval_consensus_ablation.py`; 40 scoring unit tests.
- **Result (n=25 per arm, all arms 25/25 complete — no differential generation loss).**

  | arm | precision | recall | F1 | invalid-id rate | techniques | output tokens | calls |
  |---|---|---|---|---|---|---|---|
  | `single` | 0.413 | 0.416 | **0.414** | 0.077 | 5.04 | **325** | 1 |
  | `negotiated` | 0.370 | **0.432** | 0.398 | 0.061 | 5.88 | 1039 | 4 |
  | `noise` | 0.326 | 0.352 | 0.337 | 0.028 | 5.60 | 1027 | 4 |

  Paired (every arm saw the same samples in the same order):

  | comparison | mean F1 delta | 95% bootstrap CI | sign test |
  |---|---|---|---|
  | `negotiated` − `single` | **−0.016** | **[−0.084, +0.050]** — includes 0 | 10 / 11 / 4 ties |
  | `negotiated` − `noise` | **+0.061** | **[+0.012, +0.110]** — excludes 0 | 13 / 7 / 5 ties |

- **Finding 1 — the defence does not hold.** At equal token budget, channel-decomposed negotiation
  **does not beat a single agent given the same evidence**: the paired delta is −0.016 with a CI
  spanning zero and a sign test at 10–11. The exception the literature named — heterogeneous
  evidence channels — **did not rescue the multi-agent design here.** And the cost is real:
  **3.2× the output tokens** (1039 vs 325), landing squarely inside Bertalanič & Fortuna's reported
  2.1–3.4× range. This replicates their result in a new domain rather than contradicting it.
- **Finding 2 — but the mechanism is not inert, and this is what stops the result being a
  dismissal.** `negotiated` beats `noise` by **+0.061 with a CI excluding zero**. Corrupting one
  analyst's evidence measurably degrades the outcome, so the mediator is **reconciling**, not
  merely averaging three opinions. The honest statement is therefore narrow and specific: *the
  negotiation does something; it does not do something worth 3.2× the tokens against a single
  agent with the same evidence.*
- **Finding 3 — the arms fail differently, which the F1 tie hides.** `negotiated` trades precision
  for recall (0.370 / 0.432 against `single`'s 0.413 / 0.416) and surfaces more techniques per
  sample (5.88 vs 5.04). Decomposition widens coverage and pays for it in precision — the same
  shape §3.6 found for view-decomposition, arrived at by a different route. If recall is the
  operational priority the arms are **not** equivalent, and an F1-only reading would miss that.
- **A curiosity worth not over-reading.** Invalid-id rate runs *opposite* to F1: `noise` is lowest
  (0.028) and worst; `single` is highest (0.077) and best. Fewer invalid ids here tracks saying
  less and hedging more, not being more correct. It is a reminder that a clean-looking safety
  metric can move against quality.

- **Scope, and one limit that materially bounds the claim.**
  1. **This tested single-round consensus, not the production negotiation.** The harness runs
     K analysts then **one** mediator pass. Production negotiation is **multi-round** with
     revision, dissent tracking and sycophancy detection. So this measures *decompose-by-channel
     then reconcile*; it does **not** test iterated negotiation, and the write-up must not claim
     it refutes that. Testing the full loop is a separate experiment.
  2. n=25 per arm over 5 synthetic fixture families, one model (§2.0). The CI excludes a delta
     larger than ±0.084 F1 but cannot exclude a small one.
  3. Evidence is constructed, not extracted from real samples — deliberately, so ground truth is
     exact and no id leaks, but it means channel quality is uniform in a way real evidence is not.
     `arXiv:2604.02460`'s crossover is at *heavy degradation* (α=0.7); our channels are clean, so
     this run sits on the side of the crossover where single agents are predicted to win — and
     they did. **Degrading the channels is the obvious follow-up and would test the crossover
     directly.**
- **Consequence for the paper.** F1 (the system paper) was gated on this returning positive. It
  did not. The framing decision (D3) resolves toward **F3 — negative results and measurement** —
  with this as a headline result rather than a disappointment: a pre-registered test of our own
  architecture's central claim, run to the literature's own design, reported against us.

### 3.8 The confidence number the cascade runs on is nearly a constant — `EXPERIMENTAL` / `NEGATIVE`

- **Why this matters more than a calibration curve.** `ClaimEvidence.confidence` is a self-reported
  number on every ISR claim, and the cascade consumes it. `arXiv:2606.29490` (Kumaran et al.)
  found verbal confidence tracks an LLM's *readiness to commit* rather than correctness — but Q1's
  full-text read established their suite is MCQ and open-ended QA with **no structured or
  evidence-cited outputs**. This is the extension to exactly that: claims that must cite an
  artifact. Harness `tests/evaluation/eval_confidence_calibration.py`, 28 scoring unit tests.
- **Method.** The three heterogeneous channels from §3.7, 5 fixtures × 5 repeats, one analyst call
  per channel. Each claim's `technique_id` is scored against the fixture's ground-truth set; the
  pair `(stated confidence, correct)` is the unit of analysis. **210 claims scored, 4 excluded and
  counted** (no technique id or no confidence — excluded silently would bias the sample toward
  what the model was willing to name).
- **Result.**

  | scope | n | correct | **AUC** | separation | accuracy | mean confidence | overconfidence |
  |---|---|---|---|---|---|---|---|
  | **all** | 210 | 78 | **0.550** | +0.014 | 0.371 | **0.984** | **+0.613** |
  | static | 56 | 14 | 0.648 | +0.043 | 0.250 | 0.961 | +0.711 |
  | dynamic | 84 | 51 | **0.500** | +0.000 | 0.607 | **1.000** | +0.393 |
  | network | 70 | 13 | **0.428** | **−0.022** | 0.186 | 0.984 | +0.798 |

- **Finding 1 — the number barely ranks correctness.** AUC **0.550** against a chance baseline of
  0.500. Kumaran's result replicates in a setting their suite did not cover.
- **Finding 2, and it is stronger than "miscalibrated" — the signal is nearly degenerate.** **All
  210 claims fall in a single reliability bin, [0.8, 1.0).** On the `dynamic` channel every claim
  carries confidence **exactly 1.000** (CI [1.000, 1.000]), so its AUC of 0.500 is not a
  measurement of poor discrimination — **a constant cannot discriminate at all**. This is a
  different failure from bad calibration: a miscalibrated-but-informative score can be recalibrated,
  a constant cannot.
- **Finding 3 — on one channel it is worse than uninformative.** `network` scores **AUC 0.428 with
  separation −0.022**: below chance, i.e. the model is *slightly more confident when it is wrong*.
  Small, and inside the noise at n=70, but it rules out the charitable reading that the number is
  merely weak-but-positive everywhere.
- **Finding 4 — overconfidence is large and tracks difficulty inversely.** Stated 0.984 against
  0.371 observed: **+0.613**. Worst on the channel it is worst at (`network`, +0.798, accuracy
  0.186). This corroborates `arXiv:2503.23175`'s "overconfident" finding on 350 real threat reports
  and extends it to per-claim structured output.

- **Instrument check, run before believing any of the above.** `parse_structured_claims` assigns a
  **default confidence of 0.5** when the model omits `CONFIDENCE:` or the value fails to parse, and
  the free-text fallback path assigns 0.5 as well. Had the model not emitted confidences, this
  study would have measured *our parser* and found a perfect constant. **It did not:** every one of
  the 210 claims sits in [0.8, 1.0), so the 0.5 default — which would land in the [0.4, 0.6) bin —
  **never fired once**. The values are the model's own. Recording the check because the result
  would be worthless without it, and because §3.4/N1 is the section arguing exactly this point.

- **What this justifies, and what it costs.** Every deterministic gate downstream — the alignment
  gate (§1.5.1), the cascade's corroboration requirement, the invalid→valid autocorrect restriction
  (§1.5.2) — is doing work the confidence number cannot do. It also **converges with §1.10**: the
  cascade weights moved the corroborated set on 0.0% of samples, and one reason the
  confidence-driven parts of the cascade move so little is that their input carries almost no
  information. Against that, **C3 (falsification-before-confidence) is in trouble**: a graded cap
  keyed to a value that is 0.98 for everything is a cap that almost never binds. B5 should now be
  read as testing whether the *cap* does anything, given that the *input* does not.
- **Scope.** 210 claims over 5 synthetic fixture families, one model (§2.0), one analyst prompt per
  channel. The channels are clean and the evidence is constructed, so the low absolute accuracy
  (0.371) partly reflects the model over-producing claims against a 5-technique ground truth —
  but AUC and separation are scale-free and unaffected by that.
- **Counter-searched the same day, and the phenomenon is published (2026-08-09).** Searched under
  **confidence elicitation** rather than security. `arXiv:2603.09309` (Dai & Wang, *Rescaling
  Confidence: What Scale Design Reveals About LLM Metacognition*) — **abstract fetched and
  verified** — reports that verbalized confidence is *"heavily discretized, with more than 78% of
  responses concentrating on just three round-number values"*, across **six LLMs and three
  datasets**. The effect has a name in that literature — **discretization** — and their evidence
  is much broader than ours. Our `dynamic` channel sitting at exactly 1.000 throughout is an
  instance of it, not a discovery of it. See also `arXiv:2306.13063` (Xiong et al.) on
  overconfidence in elicited confidence.
  **What remains ours is the consequence, not the phenomenon.** That literature studies scale
  design and metacognition; this is a *system that consumes the number*. The cascade's gates, the
  corroboration logic and C3's graded cap are all keyed to a value that turns out to be discretized
  to near-constancy — which is a mechanism for §1.10's result rather than a restatement of it.
  Possibly also ours: the **below-chance channel** (`network`, AUC 0.428), which their abstract
  does not mention; but n=70 and weak, so it is a lead, not a claim.
  Ledger: **`OURS` → `REFINEMENT`**, about an hour after it was entered.

### 3.9 The corroborated set does not reach the verdict — `EXPERIMENTAL` / `NEGATIVE`

- **What §1.10 left open.** §1.10 showed the cascade *weights* never move the corroborated set:
  `is_corroborated = len(contributing_layers) >= 2` does not consult `LAYER_WEIGHTS`, so five
  perturbations moved it on **0.0%** of samples. That is a statement about the cascade's internals.
  The open question is one level down: **does the corroborated set move the bundle the analyst
  receives?** A signal can be computed correctly and still be ignored downstream.
- **Method.** ISRs synthesised deterministically from the fixture ground truth; the only variable
  between arms is which static Layer-0 source exists. Four arms × 5 fixtures × 3 repeats = **60
  judge calls, 0 skipped**. Each technique is claimed by **two** sources, alternating
  `yara`+`import_capability` (**distinct domains → corroborated**) and `yara`+`tool_artifact`
  (**same domain → not corroborated even though two detectors agreed**). Harness
  `tests/evaluation/eval_layer0_verdict.py`, 26 scoring unit tests.
- **The manipulation worked — corroboration varied sharply across arms:**

  | arm | corroborated techniques (of 5) |
  |---|---|
  | `all` | **3** |
  | `no_tool_artifact_layer` | **3** |
  | `no_yara_layer` | **0** |
  | `no_import_capability_layer` | **0** |

- **And the verdict did not move at all:**

  | arm removed | verdict changed | mean Jaccard vs `all` | 95% CI | n |
  |---|---|---|---|---|
  | `yara_layer` | **0/15** | 1.000 | [1.000, 1.000] | 15 |
  | `import_capability_layer` | **0/15** | 1.000 | [1.000, 1.000] | 15 |
  | `tool_artifact_layer` | **0/15** | 1.000 | [1.000, 1.000] | 15 |

- **Finding.** Corroboration swung from **3 techniques to 0** between arms and the final bundle's
  technique set was **identical every time**. Taken with §1.10 the pair is:
  *the weights do not move the corroborated set, and the corroborated set does not move the
  bundle.* **On this evidence the corroboration apparatus is downstream-inert** — it is computed,
  reported, and does not change what the analyst is given.
- **What is *not* shown, stated plainly because the design guarantees part of the result.** Every
  technique had **two** sources, so removing one always left another and **technique survival was
  baked in**. B3 therefore does *not* show that losing evidence is harmless. What it shows is
  narrower and still substantive: **corroboration *status* changed sharply and propagated nowhere.**
  A design where a technique's only source is removed would test the other question, and the
  disjoint condition — which produces 0 corroborated by construction — is the wrong tool for it.
- **A second thing the design cannot separate.** `no_tool_artifact_layer` was pre-registered as
  *predicted no change*, and it changed nothing — but so did the two arms that destroyed all
  corroboration. The prediction was confirmed and is **uninformative**, because in a run where
  nothing changes, "nothing changed" is not evidence for any particular mechanism.
- **Scope.** 5 synthetic fixture families, one model (§2.0), one judge pass, equal source
  contribution by construction. In production the rates are wildly uneven (§1.10: yara 89.5%,
  import-capability 52.6%, tool-artifact 2.4%), so this measures the **mechanism**, not the
  real-world cost of removing a layer. That needs C2's measured rates.
- **Consequence.** C6 (multi-layer corroboration cascade) cannot be claimed as a contribution on
  this evidence: the mechanism exists, is computed correctly, and does not reach the output. The
  honest framing for the paper is that the cascade's *value*, if any, is in the ranking it produces
  and in what it filters **before** the judge, not in the corroboration label — and that label is
  the one the report surfaces most prominently.

### 3.10 What the STIX integrity pass actually removes — `EXPERIMENTAL` (C7, partial)

- **The measurement C7 needed.** A3 instrumented `enforce_bundle_integrity`; this is the first read
  of those counters on **fresh** bundles (the archived ones predate the `spec_version` fix, and the
  defect classes come from LLM generation).
- **Result over the same 60 judge-generated bundles.**

  | quantity | value |
  |---|---|
  | bundles generated | 60 |
  | integrity pass ran | **60 / 60** |
  | pass removed something | **3 (5.0%)** |
  | objects removed, total | **3** |
  | removal reasons | `empty_pattern` ×3 |

- **Finding.** On clean, synthetic evidence the repair pass **almost never fires** — 5% of bundles,
  one object each, and every removal is the same class: an indicator whose pattern was empty or
  truncated, i.e. **generation stopping mid-pattern**. No duplicate attack-patterns, no duplicate
  indicators, no dangling relationships.
- **What that does to C7.** "Repairing beats rejecting" cannot be supported by a 5% firing rate on
  three objects. But the result is not a refutation either, and the reason is in the input: this
  evidence is *constructed and consistent*, so there is little for the pass to repair. **C7 needs a
  population where the defects actually occur**, which is the CAPE-driven runs with real
  sandbox evidence — queue item C-layer. Until then C7 stays `UNMEASURED`, now with a measured
  lower bound rather than nothing.
- **One thing worth keeping regardless.** The single defect class observed is exactly the failure
  §3.3 and §1.7.1 describe from the other side — generation running out of budget mid-structure. It
  is the same phenomenon showing up in the emitted artifact rather than in the token stream.

### 3.11 The only grading mechanism fires on 0.82% of techniques — `EXPERIMENTAL` / `NEGATIVE`

- **Why this was worth measuring, and why the question changed.** C3 ("falsification before
  confidence") is concretely `_cap_unsupported_confidence`: a deterministic drop to **0.40**,
  applied only to **T1027 / T1140** (obfuscation) and **T1055** (injection) plus sub-techniques,
  only when the technique's **sole contributing layer is `static`**, and only when the matching
  static evidence flag is absent. §3.8 showed the incoming confidence is ~0.98 for essentially
  everything, so for those techniques **this cap is very nearly the only source of grading in the
  system**. The question therefore stopped being "is a graded cap better than a binary filter" and
  became **"how often does the only grading mechanism fire?"**
- **Method — no LLM required, and the ablation is exact.** `_static_evidence_flags(None)` returns
  `(True, True)` ("no static picture to contradict the LLM, do not cap"), so `static=None` is a
  true cap-OFF arm with everything else identical. Both arms run over the **189 samples with
  evidence** from the 218-PE corpus; any confidence delta is the cap's.
  Harness `tests/evaluation/eval_confidence_cap.py`, 30 scoring unit tests.
- **Result.**

  | quantity | value |
  |---|---|
  | samples with evidence | 189 |
  | techniques total | 1,348 |
  | gated techniques (T1027/T1140/T1055 + subs) | **306 (22.7% of all)** |
  | …of which sole-layer `static` — cap eligible | **25 (8.2% of gated)** |
  | **capped** | **11** |
  | fire rate among eligible | **44.0%** |
  | fire rate among gated | 3.6% |
  | **capped share of all techniques** | **0.82%** |
  | samples where the cap fired at least once | **11 / 189 (5.8%)** |

- **Where the mechanism actually stops, measured rather than inferred.** The gated techniques are
  *common* — 22.7% of everything — and the evidence check is *decisive* when reached (44% of
  eligible claims get capped). The bottleneck is the **sole-static precondition**, and the reason
  is not the one that suggests itself:

  | who claims the 306 gated techniques | count |
  |---|---|
  | `yara_layer` alone | **257 (84%)** |
  | `import_capability` alone | 25 |
  | both | 24 |

  **In 84% of cases there is no static-layer claim to discipline at all** — the deterministic
  signature layer found the technique independently. So the cap is not being *exempted by
  corroboration*; the population it targets barely exists on this evidence. (My first reading of
  the summary numbers was that yara and static co-claim and the corroboration exempts them. The
  source breakdown says otherwise, and the difference matters: one story is "the cap is disarmed by
  a redundant detector", the other is "the cap has almost nothing to act on".)
- **Finding.** The system's only grading mechanism moves **0.82% of techniques** and touches
  **5.8% of samples**. It is not broken — when it is reachable it fires on 44% of eligible claims,
  which is a real filter — but at corpus scale it is very nearly a no-op.
- **This is the third leg of the same story, and together they are the strongest negative in the
  work.** §3.8: the confidence value is discretized to near-constancy. §3.9: the corroborated set
  does not reach the verdict. §3.11: the one mechanism that grades confidence fires on under 1% of
  techniques. **The confidence-and-trust apparatus — a graded score, a corroboration cascade with
  five weights and a falsification cap — produces almost no differentiated signal end to end.**
  That is a coherent, measured result about a real system, and it is the paper's material.
- **The scope limit that bounds this specific number, and it is significant.** This run exercises
  the **static Layer-0 sources only** — yara, import-capability, tool-artifact — with **no LLM
  analyst in the loop**. In production the `static` domain *also* carries the LLM static analyst's
  claims, which is the population the cap was written for (the docstring says the local model
  "keeps over-claiming obfuscation from ordinary dynamic-API-resolution"). **So 25 eligible
  techniques is a lower bound, and the true firing rate with the LLM arm attached will be higher.**
  The honest claim is: *on deterministic evidence the cap is nearly inert*, and the LLM-arm
  measurement is queued.
- **A documented inversion this result puts a size to.** `_static_evidence_flags` carries a comment
  noting that the cap fires when static evidence does *not* support a claim, so **a better packer
  detector makes the cap fire less often** — improving detection would have produced *more*
  high-confidence hallucinated T1027, and a confidence threshold on packer matches is what breaks
  that. This measurement bounds the exposure: the inversion acts on at most the 25-claim eligible
  population, i.e. under 2% of techniques. Real, but small.

### 3.12 C2's semantic tier was already measured, and it repeats §1.5.3 — `NEGATIVE` (n=19, weak)

- **Found, not run.** B7 was queued as if C2 were wholly unmeasured. It is not: two artifacts
  already in the repo measure the **semantic (family-feature RAG) tier**, both leakage-free.
  The roadmap and the ledger were both wrong about this, and the check that caught it was reading
  the evaluation directory before writing a harness for it.
- **Retrieval in isolation** (`family_rag_retrieval.json`) — Ultimate-RAT-Collection held-out
  split, `a0`=train / `a1`=test, **158 families, 629 test samples**:

  | metric | value |
  |---|---|
  | recall@1 | 0.083 |
  | recall@3 | 0.159 |
  | recall@5 | **0.199** |
  | MRR | 0.122 |
  | random baseline recall@5 | **0.032** |

  **The retriever works.** recall@5 is **6.3× the random baseline** on a leakage-free split. This
  is not a broken component.
- **End to end** (`family_rag_ab.json`) — MABEL catalog, disjoint from the n=210 corpus, **n=19
  paired**:

  | metric | OFF | ON | delta |
  |---|---|---|---|
  | F1 | 0.0122 | 0.0151 | **+0.0029** |
  | precision | 0.1316 | 0.1228 | **−0.0088** |
  | recall | 0.0064 | 0.0081 | +0.0017 |
  | hallucination rate | 0.000 | 0.000 | 0.000 |

- **Finding, and it is the §1.5.3 shape exactly.** A retriever that is **six times better than
  chance in its own terms** moves the end-to-end result by **+0.003 F1** — while *lowering*
  precision. §1.5.3 found the same thing for the ATT&CK case-prior RAG: the index worked (native
  F1 0.620 against a 0.424 frequency prior) and the production query never reached it.
  **Two independently built retrieval components, both demonstrably functional in isolation, both
  near-inert once wired into the pipeline.** That is no longer an anecdote about one component.
- **What cannot be concluded, and the reason is sample size.** **n=19 with no confidence interval.**
  A +0.003 F1 gain and a −0.009 precision loss at that n are consistent with noise. The honest
  statement is *no effect detectable at n=19*, **not** *no effect*. Re-running this arm at the
  n=100 cohort would settle it and costs nothing extra once C3 is running — it should be folded in.
- **The other tier is genuinely unmeasured.** The **opcode-hash (function-hash) attribution tier**
  has no evaluation artifact. It also cannot be measured on this machine as currently queued: it
  drives **Ghidra MCP** `get_bulk_function_hashes` and stores into **Qdrant**, so it needs both
  services — not llama-server. See the queue correction under B7.
- **Consequence for C2.** The ledger row `UNMEASURED` is half wrong and is corrected: the semantic
  tier is **measured and weakly negative**; the opcode-hash tier is unmeasured. C2 as a *two-tier*
  claim still cannot be made — but for a sharper reason than "nobody looked": one tier demonstrably
  contributes almost nothing at the sample size we have.

---

### 3.13 The dynamic path, measured for the first time: a client defect, and a queue — `OBSERVED` (C0/C1)

First live contact with the CAPE MCP server, 2026-08-10, from the network the instance is on.
Three things came out of it, and none of them were the thing that was being looked for.

**(a) Every dynamic tool call had been broken, and the pipeline could not have noticed.**
All **36** tools failed on the server's own validation:

```
1 validation error for call[verify_auth]
token
  Input should be a valid string [type=string_type, input_value=None, input_type=NoneType]
```

Every CAPE tool declares `token` as optional with `"default": ""`. `MCPLangChainToolkit` built its
argument model with `... if required else None`, discarding the schema's declared default, and
LangChain fills every declared field before invoking — so an argument the agent never mentioned
reached the server as an **explicit null**. *Unset* and *null* are different statements and a field
typed `str` rejects the second.

The reason this survived to the first live call is the interesting part: **Ghidra, the only MCP
server this pipeline had ever talked to, declares no optional parameter with a typed default**, so
the same malformed argument dict was silently acceptable there. A defect in shared client code was
invisible because only one of the two servers it serves was ever exercised. Fixed in `716a128` with
seven regression tests built from the live schemas; the same probe then returned real data.

**(b) What the instance actually is.** Unauthenticated, via the production client:

| property | value |
|---|---|
| CAPE version | 2.5 |
| analysis machines | **1** (`win10`, x64, `virbr0`) — status `poweroff` |
| tasks total / pending / running | 15,189 / **10,348** / 0 |
| tasks reported | **4,327** |
| exit node | `inetsim` (simulated internet) |
| host RAM / storage | 15 GB / 189 GB free of 457 |

`SANDBOX__CAPE2_API_TOKEN` is **empty** and `verify_auth` reports `authenticated: false`, yet
`get_cuckoo_status`, `list_machines`, `list_exitnodes`, `get_search_info`, **`search_task`** and
**`get_task_iocs`** all answer anyway.

**A measurement trap worth recording, because it produced a wrong reading before it was caught.**
The instance **rate-limits**, and a throttled call returns exactly `{"error": true, "message": ""}`
— *character for character* what an auth-refused call returns. A sweep that ran clean for 61
queries began returning nothing but that, and the first reading of it was "these tools require a
token". The discriminator is trivial once seen: re-call a tool that demonstrably worked minutes
earlier. `get_cuckoo_status` failed the same way under throttling, which no auth story explains.
Any harness that treats this string as a verdict will mis-classify a throttle as a capability.
Two errors *are* real and distinguishable because they say something: `get_task_report` returns
`"Reports directory does not exist"`, while **`get_task_iocs` returns 221 KB** of detections —
family attribution (`DarkComet`) with the Yara rules behind it. That is the CAPE-native,
LLM-free signal **C5** needs, and it arrives without a report directory.

**(c) The queue looks decisive and is not — a conclusion this log had to retract.**
One analysis VM behind **10,348 pending tasks**, nothing run since 2026-08-07, and the machine
reading `poweroff`: the obvious reading is that submitting an n=100 cohort means entering the back
of a queue nine days deep, and that reading was written here before it was tested. It is wrong.

Two measurements, in the order they should have been taken:

1. **Reuse is not a path.** Of **61** corpus hashes queried cleanly through `search_task`,
   **3 were hits — 4.9%**, and all three are this project's own July/August test submissions
   (task ids 5–12, 19042), not a pre-existing corpus. Whatever the other ~15,000 tasks are, they
   are not our samples. At that rate the "fetch instead of submit" shortcut yields ~10 of the 100
   samples needed.
2. **Live submission is a path, and a fast one.** One Windows PE (`4565983c…`, 673 KB) submitted
   through the pipeline's own `CAPEv2Client`:

   | event | time |
   |---|---|
   | task created | 13:23:11 |
   | **started** | 13:23:12 — **1 s later** |
   | completed | 13:32:34 — **9 min 23 s** |

   The comparison that explains the whole picture: task **17184** has been `pending` since
   **2026-07-29** and was still pending while 19043 ran to completion beside it. **The backlog is
   not a queue our work has to wait behind** — those tasks are never scheduled at all, consistent
   with requesting a platform or machine tag this single `win10` instance cannot satisfy, which is
   also why the corpus's ELF and APK members can never run here. A new Windows submission is
   scheduled essentially immediately.

**Consequence.** C3/C4/C5 are feasible by live submission: ~9.5 min per sample on one VM puts a
100-sample cohort at roughly **16 hours** of sandbox time. The efficient shape is therefore to
**decouple** — submit the cohort and let CAPE grind through it unattended, then run the pipeline
against finished analyses — rather than interleaving detonation with LLM inference on a machine
that cannot comfortably host both.

**The methodological point is the retraction itself.** A 10,348-deep queue is exactly the kind of
number that reads as an answer, and it was allowed to stand as one in this document for an hour.
What overturned it cost a single submission and ten minutes. The same shape has now appeared four
times in this project — the empty Ghidra call graph, the inert eval timeout, the cap's
preconditions, and now this — and the rule that keeps catching it is the same: **before concluding
that a mechanism cannot run, run it once.**

**(d) An availability property the paper will have to state rather than assume.** The server stopped
accepting new MCP sessions after a handful of abandoned SSE streams — a fresh `initialize()` timed
out at 20 s while TCP connect still succeeded, and connections accumulated in `FIN-WAIT-2`. It
recovered on its own **65 s** after the probing stopped, which is the useful half of the
observation: the failure is self-clearing and caused by client behaviour, so the sweep harness
checkpoints per hash and rebuilds a dead session instead of treating an outage as fatal. The
abandoned streams were this author's (hand-rolled `curl` probes, since replaced by the production
client). The dynamic path's availability is therefore not a constant and belongs in
threats-to-validity rather than being assumed.

The pipeline itself survives this, and that was checked rather than hoped: `MCPLangChainToolkit.initialize()`
has no timeout of its own, but its only production caller wraps it — `_run_coro_blocking(toolkit.initialize(),
hard_timeout=120.0, label="cape-mcp-init")` in `dynamic_analyst.py:112`. During today's outage an
analysis would have failed over to static-only after 120 s rather than hanging, which is the
behaviour `test_dynamic_degrades_without_cape.py` already pins.

---

### 3.14 Ghidra was answering about the wrong binary — `IMPLEMENTED` (fixed), and a retrospective threat

Found while measuring how often the sink-reachability hint fires (B6). It is the most consequential
defect this project has recorded, and the only reason it was noticed is that a number repeated.

**The mechanism.** `load_program` imports a binary and answers
`{"success": true, "program": "<name>"}`. All three call sites read that as "Ghidra is now looking
at this binary". The server keeps a **separate current program**, and `load_program` sets it only
when nothing is current yet — the first load after a restart. Measured against the live container:

```
load A        -> {"success": true, "program": "A"}   current: A
load B        -> {"success": true, "program": "B"}   current: A   <-- still A
run_analysis  -> {"program": "A", "new_functions": 0}
call graph    -> A's graph, byte-identical, for every sample
```

So from the **second sample of a container's lifetime onwards**, everything Ghidra-derived —
decompilation, imports, strings, call graph, function hashes — described the first sample's binary
while the report named the current one. No error, no warning, a plausible answer every time.

**How it surfaced, which is the part worth keeping.** The B6 harness printed a hint length per
sample and the first two were both **2,575 characters** — the same figure a third, unrelated sample
had produced in an earlier session. Two binaries of 241 KB and 139 KB then turned out to share a
call graph identical to the character (404,337 chars, 11,798 lines), and `run_analysis` named a
*third* binary entirely, left current by an earlier session. A repeated constant where variation was
expected was the whole signal; every individual response looked fine.

**The fix** is one call after a successful load — `POST /switch_program?program=<name>`, genuinely a
query parameter (a JSON body answers "Program name is required", which reads like a missing argument
and is really a misplaced one). Applied at the HTTP client, the sink-reachability pre-pass, and the
function-hash attribution pass; committed as `0720d34` with 11 regression tests.

**What changed once it was fixed**, on the same samples:

| | before | after |
|---|---|---|
| `run_analysis` functions | 5,074 (inherited) | **5** (the binary's own) |
| priority-hint length | constant 2,575 | 1559 / 599 / 0 / 0 |
| pre-pass seconds/sample | ~25 s | 0.5–6.5 s |

**The retrospective threat, stated plainly.** `tests/evaluation/eval_temporal_drift.py` runs the
full pipeline per sample against a **long-lived, shared Ghidra container and never restarts it**, so
the recorded **n=210** static-only drift run meets the exact precondition for this bug. Whether it
was actually affected cannot now be determined: **its per-sample outputs were not retained** — the
report was rendered to a path on a machine this project no longer runs on. This is the E.1
data-retention defect biting a second time, and it is why the n=100 cohort work stores per-sample
results.

The honest position: **the n=210 temporal-drift result is suspect and must be re-run before any
claim rests on it.** The claim it supports is the earliest→latest F1 *delta*, and if every sample
after the first was scored against one binary's static evidence, that delta measured sampling noise
rather than drift. Two other Ghidra-dependent items are unaffected for a specific reason worth
recording: §1.7.1's hint ablation runs on family *descriptions* with no binary in the loop, and
§3.12's semantic-tier evaluation is retrieval over family features, not Ghidra output.

**Why nothing caught it earlier.** Every unit test loads one program. The bug needs *two* loads in
one server lifetime to appear, and a single-sample test is exactly what a developer writes. It is
the same shape as §3.13's `token: null` — shared client code, correct against the one server it was
exercised against, wrong the moment a second case appears.

---

### 3.15 The sink-reachability hint fires on 58% of samples — `EXPERIMENTAL` (B6, first half)

**Why frequency came before effect.** `sink_reachability`'s own docstring says it returns `""` for a
binary with no named sink APIs, and the analyst then proceeds normally. If that were the common
case, an on/off ablation reporting "no effect" would be indistinguishable from "the feature never
ran" — the same confusion §3.11 hit with the confidence cap, where the mechanism turned out to fire
on 0.82% of techniques. So the mechanism was counted before it was credited.

**Result — the full cohort, 2026-08-11.** All 100 Windows PE samples attempted, production pre-pass
replicated exactly (`format=json&limit=20000`):

| | |
|---|---|
| hint non-empty | **55 / 97 = 56.7%** |
| hint chars when non-empty | 599 min / 2036 median / 2575 max |
| distinct call-graph sizes | **63 / 97** |
| samples hitting the 20,000-edge limit | 1 |
| seconds/sample | 0.4 min / **10.6 median** / 17,765 max |
| not measurable | **3** |

Per year: 2020 9/15, 2021 7/12, 2022 11/13, 2023 12/15, 2024 5/14, 2025 6/14, 2026 5/14. The spread
(38% to 85%) is wider than the counts support reading as a trend.

**The interim figure was 46/79 = 58.2%; the final is 56.7%.** Worth stating because the intervening
14 samples were, at that point, recorded as unmeasurable — and the honest thing was to *say* they
were unmeasurable rather than count them as empty hints. Had they been counted as empty, the
reported rate would have been 46/93 = 49.5%, an eight-point error in the direction that flatters
nothing and simply misleads.

**What the 14 "unmeasurable" samples turned out to be, and why the first diagnosis was wrong.**
They were read as pathological binaries — too big, too slow, memory-hungry. Classified individually
on a fresh container each, **12 of 14 analysed normally**, in 4 to 148 seconds, peaking at 534–4,790
MiB. Only **2** reached the container's ceiling. The failures were therefore not a property of those
samples but of the **server state they inherited**: a read timeout leaves the JVM mid-analysis, and
every subsequent load is refused, which is how 11 consecutive errors appeared in one window (§3.14).
Restarting per sample recovered them.

The two that remain, plus one connection drop, are a real and reportable limit: at a **6 GB
container budget** the graph fetch does not complete. One of them (`6f2ec2f8dd5e`) *analyses* fine —
93.9 s, 4,790 MiB — and only fails when the 20,000-edge call graph is retrieved afterwards, which
locates the cost in the **extraction**, not the analysis. **3 of 100 samples are outside what this
pre-pass can measure at that budget**, and that is the sentence the paper should carry rather than
a silent n=97.

**So the ablation is worth running.** The feature engages on a clear majority of samples, which
means a null effect would be a statement about the *hint*, not about a mechanism that never fired.
The other 42% are equally a result: for those binaries the pre-pass costs its analysis time and
returns nothing, and the effect measurement must report the two groups separately rather than
averaging a feature over samples it never touched.

**The 50-distinct-graph-sizes row is not decoration.** It is the integrity check that the *first*
run of this harness failed silently — 66 consecutive samples with a call graph of identical length
(§3.14). Any future run of this measurement should report it, because "how many distinct outputs did
N inputs produce" is the cheapest available detector for a stale-state bug, and this project has now
been bitten by that class three times.

**Two caveats stated rather than buried.** Unmeasurable samples are recorded as *errors*, never as
empty hints — counting a sample we failed to look at as "no hint" would inflate the negative, and
the 58.2%→56.7% movement above shows the size of the error that policy avoided. And the
17,765-second maximum against a 10.6-second median is a single binary measured while the host was
under memory pressure; it is an artefact of the measurement conditions, not an analysis cost worth
attributing to the sample.

**The effect half was attempted twice, and what stopped it was not what it looked like.**

*First attempt.* Killed by the memory guard at 15 minutes, 3,974 MB available. `llama-server` grows
with cumulative requests rather than plateauing — **10.4 GB at the start of one pass, 14.8 GB
fifteen minutes in** — on a 30 GB host already carrying Ghidra and a desktop.

*The lever that did not work.* Re-served at **64k context instead of 131k** on the reasoning that
the KV cache would be bounded. It was not: llama peaked at **14.6 GB** against 14.8 GB before, for a
**baseline of 10.1 GB against 10.4** — the growth follows the context a pass *actually consumes*,
not the configured ceiling, and the baseline is CPU-resident expert weights that no context setting
touches. Recorded because it is the obvious lever and it does not pull.

*Second attempt, which completed and is the real result.* The arm finished in **1,677 s (28 min)**
with **1 claim and zero technique IDs**, and the log says why:

```
20:58:12  ReAct loop starts, 20 tools
21:00:01  loop completed: 19 tool calls, 41 messages, elapsed 109.5s
21:00:01  "ended without a final answer ... forcing synthesis from gathered tool output"
21:25:01  static no-tools fallback exceeded the 1530s hard cap
```

**The ReAct loop is not the expensive part — it took 109 seconds.** It exhausted its 40-step budget
without concluding, which triggers a *forced synthesis*: one LLM call over everything the 19 tool
calls gathered. That call ran **25 minutes and hit the 1,530 s hard cap**, and the analysis produced
nothing.

**Two bounds fired in sequence and the output was empty.** That is a P6 event of exactly the kind
A3's ledger was built to count, and it is §1.7.1's shape in a new place — there, removing a hint
made the judge overrun a 600 s ceiling and fall back to an empty bundle 6/17 times. Here the step
cap and the time cap compose: exceeding the first *guarantees* an attempt at the second, and on a
rich binary the second cannot finish. The fallback is not a safety net on this workload; it is a
25-minute path to zero.

**This was a production defect, and fixing it is what made the ablation possible.** Three bounds
were wrong at once, and the third was in the fix's own first cut:

* **Time.** Synthesis received a *fresh* copy of the full 1,500 s timeout. 109.5 + 1500 overruns the
  1,530 s hard cap by construction — the cap could not not fire. It now gets what is left, and is
  skipped below a 60 s floor.
* **Input.** The whole 41-message conversation was re-sent. It is now trimmed, keeping the framing
  and the most recent evidence.
* **Measurement.** The first trim counted `len(message.content)` — which is **zero** for the
  assistant turns that request tools, i.e. for most of a ReAct transcript. It dropped one message
  from a conversation llama.cpp then reported at **38,868 tokens**. Counting the `tool_calls`
  payload too, and lowering the budget to 16k chars, made it bite.

The budget is not tidiness. The server log shows what long context costs *this* model: at ~39k
tokens llama.cpp wrote and erased a **63 MiB recurrent-state checkpoint every few hundred tokens**,
which is the §2.0 hybrid-recurrent architecture showing up as a wall-clock cliff rather than as an
error.

**Verified on the same sample, before and after the fix:**

| | before | after |
|---|---|---|
| wall clock | 1,677 s | **323 s** |
| claims | 1 | **10** |
| technique IDs | **0** | **5** (T1027, T1055, T1071, T1082, T1547) |
| messages trimmed | 1 / 41 | 5 / 41 |

A 5.2× speedup and, more to the point, **an analysis that produces something instead of nothing on
a rich binary**. The ablation's unit cost is now set by the measurement rather than by a failure
path, which puts a 12-sample paired run at roughly two hours instead of eleven.

**Worth noting how this was found.** Not by a test — 1,993 of them passed throughout — but by
trying to run an experiment and refusing to accept its cost. The measured "this does not fit the
machine" turned out to be "this pipeline produces nothing on a whole class of input", and the
experiment was the instrument that surfaced it.

**Blast radius, checked rather than assumed.** A defect that silently zeroed the static analyst on
rich binaries could have contaminated earlier results, so the record was audited against it. It did
not: §1.5.x is retrieval-only, §3.2/§3.6 state explicitly that they run the **text path only** with
the Ghidra/CAPE ReAct loop excluded, §3.7–§3.9 and §3.11–§3.12 are fixture- or corpus-based with no
tool loop, and §3.10 reads bundles the judge produced. **The one recorded result that drove the full
pipeline per sample is the n=210 drift study — and it is already withdrawn (§3.14).** This gives it
a *second, independent* reason to stay withdrawn: it ran on a pipeline that, on any binary rich
enough to exhaust the step budget, returned zero techniques by construction.

Reporting the negative result of this audit matters as much as the fix. "Nothing else was affected"
is a claim, and it was checked the same way any other claim here is.

**The fix is partial, and the paired run that proved it is the honest place to say so.** With the
fix in, a 12-sample paired ablation was started. It produced **one complete pair and one failed
arm** before the memory guard stopped it:

| sample | arm | seconds | claims | technique IDs |
|---|---|---|---|---|
| `000ac83f` | hint **on** | 200.5 | 8 | **6** — T1027, T1055, T1057, T1102, T1105, T1134 |
| `000ac83f` | hint **off** | 150.1 | 5 | **2** — T1027, T1055 |
| `000b535a` | hint on | 1,545.2 | 1 | **0** — hit the 1,474 s cap |

Two things follow, and the second matters more than the first.

**One pair is not a result.** The on-arm found three times the techniques of the off-arm, and it
also took 33% longer. Whether that is the hint working or the hint buying depth with time is exactly
what §3.7's equal-budget discipline exists to separate, and n=1 cannot separate anything.

**Input size is not the only driver of the timeout.** On `000b535a` the trim *fired* — 7 of 41
messages dropped, conversation inside 16,000 characters — and synthesis still ran 24 minutes and
failed. So the fix converts a guaranteed failure into a frequent success, not a solved problem, and
the remaining cases are governed by something else: generation rate on this hybrid recurrent model
varies from 162 tok/s down to **20 tok/s** across requests in the server's own timings. A bounded
input does not help when the tokens themselves are eight times slower than the budget assumed.

**One gap in the harness, recorded because it cost a diagnosis.** The ablation restarts
`llama-server` between arms with its output sent to `/dev/null`, so when the second sample failed
there was no server log for the instance that failed — the rates above are from an earlier
instance's log and are indicative rather than matched. A measurement harness that suppresses the
log of the thing it is measuring is the same class of mistake as the rest of this section.

**What would make it feasible**, recorded so the next attempt does not rediscover it — and note
that the *memory* levers are the ones that turned out to matter least. Bounding the forced-synthesis
fallback is first: a call that cannot finish inside its cap should be split or refused, not
attempted for 25 minutes. Raising the step budget so a rich chunk concludes inside the loop removes
the trigger entirely. Restarting `llama-server` between arms bounds the cumulative drift (temp 0
makes it measurement-neutral) but does **not** lower the within-arm peak, and reducing the served
context does neither. **C1 therefore stays `PARTIAL`: the mechanism's firing rate is measured, its
effect is not, and the reason is a pipeline bound rather than a missing experiment.**

**A note on what made the frequency half measurable at all, since it is the same lesson as §3.14 in
a different coat.** Two attempts at this measurement took the host out of memory and cost the desktop session.
The container ran with `-Xmx4g` — set, applied, verified in the running process's cmdline — and
still reached 5.15 GB RSS, because that flag caps the *heap* while Ghidra's database is
memory-mapped and its direct buffers are not. Nothing bounded the container, so the kernel's OOM
killer chose the largest process on the machine, which was the editor. A `mem_limit: 6g` fixed it in
one line: the same pathological sample now pins the container at exactly 6,144 MiB while the host
stays at 14.7 GB free, and the harness records a clean error. **A limit that is set is not the same
as a limit that binds** — which is, once more, an instrument reporting something other than what it
was asked.

---

### 3.16 A 120B frontier model does not separate from the local 35B — `NEGATIVE` (B8, complete at n=25)

The frontier arm exists to attack **P8**, the surrogate fallacy: every LLM result in this work comes
from one model on one machine, and `arXiv:2606.18166` sharpens the worry by finding **parameter
size the only statistically significant predictor** of ATT&CK-classification F1 (ρ=0.85, p=0.014)
while prompt strategy, chain-of-thought and temperature were not.

Same five fixtures, same `single`-arm prompt, same 2400-token output budget as §3.7:

| arm | model | mean F1 | 95% CI | n |
|---|---|---|---|---|
| `single` | Qwen3.6-35B-A3B (IQ3_K_R4), local | 0.4136 | — | 25 |
| frontier | Nemotron-3-Super-120B-A12B | **0.4162** | **[0.3596, 0.4711]** | **25** |

Both arms cover the same five fixtures at the same five repeats, so the comparison is **paired**:

> **frontier − local = +0.0026**, 95% bootstrap CI **[−0.0770, +0.0814]**, n=25.
> Frontier better on **12**, worse on **13**, tied on 0.

**A 3.4× parameter advantage buys three thousandths of F1 and a coin flip on direction.** The
interval is thirty times wider than the effect and the direction is split, so this is a null with
enough power behind it to be worth stating: at this task and this budget we do not reproduce
`arXiv:2606.18166`'s parameter-size prior.

**The n=9 version of this row said 0.5025 and implied a lead. It was wrong.** That estimate came
from a quota-truncated run, and completing the sample moved the point estimate down by 0.086 —
through the local mean and out the other side. Nothing was learned between the two runs except the
remaining 16 calls. It is the §3.7 lesson (a claim-count ranking that inverted when the budget
changed) recurring in a second place: **a difference read off an underpowered arm is not a weak
result, it is an unreliable one**, and the correction here was bought by finishing the run rather
than by any insight.

**The reasoning fraction is measured and stable.** Across 25 calls, **56.5%** of output
tokens were reasoning — and on a one-token answer ("T1055") it was **84%**:
92 output tokens, 77 of them thinking. Capping *content* alone would hand the frontier arm roughly
twice the generation for the same nominal budget, so `count_reasoning_tokens = True` is now
measured rather than assumed. This is the methodological result of B8, and it does not depend on n.

**The quota constraint that truncated the first attempt, kept because it governs C6.**
The OpenRouter free tier allows **50 model requests per day** (`X-RateLimit-Limit: 50`,
`limit_source: openrouter_free_tier_daily`), and the first run exhausted it mid-flight: 9 calls
landed, 16 returned HTTP 429. The cap resets daily at 03:00 local, and the completed 25-call run
above was taken from a fresh quota (25 of 25 parsed, 0 refusals, 1 hitting the output cap, $0
spent against the $25 ceiling). **C6 as designed — the frontier arm over
the n=100 cohort — needs 100+ calls and is therefore a two-day run on the free tier**, or ~$10 of
credit to raise the ceiling. That is a scheduling fact, not a scientific one, but it decides
whether C6 lands before the paper does.

One sample from an earlier repeat is worth keeping: `infostealer_sample_1` once spent its **entire**
2400-token budget, 61% of it on reasoning, emitted two technique IDs and finished on `length` —
F1 0.000. That is §3.3's degenerate decode arriving through the reasoning stream rather than
through a repetition loop, and it is exactly the failure an equal-budget comparison should surface.

---

### 3.17 The opcode-hash attribution tier fires on nothing, for two separate reasons — `NEGATIVE` (B7)

C2 claims a **two-tier** attribution design. §3.12 measured the semantic tier — a working retriever
(6.3× chance) that moves the pipeline by +0.003 F1 — and left the opcode-hash tier as the one
component in the project with no evaluation artifact at all. This is its first measurement, and it
follows the same rule: ask whether the mechanism engages before asking what it is worth.

**Result, 18 cohort samples:**

| | |
|---|---|
| tier fires (any family asserted) | **0 / 18** |
| functions hashed in total | **7,716** |
| matches returned | **0** |
| samples yielding ≤1 hashable function | **9 / 18** (5 yield zero) |
| functions per sample | 0 min / **10 median** / 2,155 max |

**Reason one: the corpus is three samples.** The Qdrant collection backing the tier holds **2,226
points from 3 samples across 2 families** — and the "families" are `dropper` (2,199 functions) and
`rat` (27), which are the pipeline's own generic category labels rather than malware families like
Emotet or DarkComet. A tier that can only ever answer "dropper" or "rat", with 99% of its evidence
from a single dropper, is not an attribution index; it is the residue of a few test runs. Nothing
could match, so nothing did.

**Reason two, which survives fixing the first.** Half the cohort yields nothing to query *with*.
Functions are dropped below **8 instructions** — correctly, since tiny thunks and stubs normalise to
the same opcode hash across unrelated binaries and matching them would manufacture family links —
and against real packed samples that floor leaves **9 of 18 samples with one function or none**. The
distribution is sharply bimodal: nine samples at ≤1, five above 700. Populating the corpus would fix
reason one and leave reason two untouched for the packed half of any realistic corpus.

**Consequence for C2.** Both tiers are now measured, and the two-tier claim cannot be made:

* semantic tier — works in isolation, **+0.003 F1** end to end at n=19 (§3.12);
* opcode-hash tier — **never fires**, on an empty-in-practice corpus, with a structural floor that
  excludes half the samples regardless.

The ledger row moves from `UNMEASURED` to a measured negative. And the shape repeats §1.5.3 and
§3.12 for a **third** independently-built retrieval component: demonstrably reasonable in design,
inert once wired to real inputs. Three is no longer an anecdote about one component — it is the
project's most-replicated result, and it belongs in the paper as such rather than as three separate
disappointments.

**What would make this measurable rather than merely absent.** Seeding the corpus from the n=100
cohort's own family labels would give the tier something to match, at which point the honest
question becomes whether opcode-hash attribution beats the family-name lookup it would then be
approximating. That is a different experiment and it is not queued; what is recorded here is that
the tier as shipped contributes nothing.

---

### 3.18 The sink-reachability hint does not change what the analyst finds — `NEGATIVE` (B6, second half, complete)

Twelve samples drawn from the 55 with a non-empty hint (§3.15), two arms each, differing only in
`use_sink_reachability`. Restricted to the firing subset on purpose: where the hint is empty the two
arms are identical by construction, and averaging over those is how §3.11's cap produced an
uninterpretable null.

**Result — paired, n=6 usable pairs:**

| outcome | mean Δ (on − off) | 95% CI | |
|---|---|---|---|
| **distinct technique IDs** | **+0.50** | **[−3.33, +4.50]** | includes 0 |
| claims | −0.83 | [−4.33, +3.67] | includes 0 |
| seconds | +52.55 | [−161.93, +268.45] | includes 0 |

Direction is **2 better, 2 worse, 2 tied** — as symmetric as six pairs can be. Per-pair deltas are
+4, −6, 0, 0, −4, +9: large in both directions and cancelling. **C1's mechanism fires on 56.7% of
samples and, where it fires, does not measurably change the output.** That closes C1 from `PARTIAL`
to a measured null, and it is the fourth architectural claim to end this way.

**The more useful number is that half the experiment was unusable.** Twelve pairs attempted, six
scored, and the six exclusions fall into three distinct classes:

| excluded | n | why |
|---|---|---|
| degenerate decode | **3** | an arm emitting 49–117 claims across 2–14 technique IDs (ratios 8.4–34.3) |
| unattributable | **2** | both arms dead, and the host state that would decide whether the pipeline or the machine failed was not recorded |
| incomplete | **1** | one arm exceeded the 630 s hard cap; a genuine outcome, but it costs the pair |

A 50% pair-loss rate is not a footnote to the null — it bounds what any ablation on this pipeline can
detect. An effect smaller than the noise introduced by losing half the samples is not measurable
here, and reporting `+0.50 [−3.33, +4.50]` without that context would imply a precision the
instrument does not have.

**The degenerate arms do not falsify §3.3's fix; they identify a second mode.** §3.3's loop repeated
*wrong* technique IDs the model could not recall, and the fix routed ID assignment through a
deterministic index. These arms emit **valid, plausible IDs** — T1055, T1057, T1027, T1059 — merely
dozens of times each. The identifier-level failure is fixed; a claim-level repetition survives it,
and it is a different defect wearing a similar shape. The screening rule is deliberately
**conjunctive** (≥20 claims *and* ≥4 claims per technique) because one healthy arm sits at a ratio of
5.0 on 5 claims and a ratio test alone would have discarded it.

**Two arms were re-run, and one was deliberately not.** Three arms failed outright: two with
`Connection error` from a model-server restart race, one with a 630 s timeout. The first two were
re-run because **the measurement never happened**; the timeout was left standing because it is an
outcome, and deleting an outcome one dislikes is selection rather than repair. The recovered pair
(`1940ba18ed66`) contributed a **−4**, against the hint.

**What this run cost before it produced anything, and the host lesson that came out of it.** The
first attempt halted at 10 of 24 arms when the host exhausted its swap file; a second stopped at 13.
Both were traced — eventually — to the model server running inside the *editor's* cgroup, so its
16 GB was charged to a scope whose death took the session with it (`E5 §3`). Four arms died in those
windows and two of them are the `unattributable` rows above: per-sample outputs had been retained,
as §4.5 requires, but per-sample **host state** had not, and that is what the question needed. The
harness now records `MemAvailable`, `SwapFree` and the server's resident-versus-swapped split at both
ends of every arm, and the scorer screens on it — forward only. For the two arms already collected,
the honest label is that we cannot say.

---

### 3.19 A fix for one silent failure created another: the LLM narrative was dead in production — `FIXED` (D1 prep)

**Measured 2026-08-12, 5 fixtures x 3 repeats = 15 generations: the LLM narrative arm produced a
schema-valid `NarrativeOutput` on 0 of 15.** Every failure carries **exactly 21 validation errors** —
1 for `capabilities_narrative` (the model returns a string where the schema declares `list[str]`) and
20 for `defensive_recommendations` (5 recommendations x 4 required fields, returned as dicts whose
keys do not match). Twelve independent generations, twelve identical error counts: the §6.3
output-cardinality signature, arriving as a constant where variation was expected.

**This is a regression, and its cause is a fix.**

| date | state | measured |
|---|---|---|
| 2026-06-04 | structured output attempted against the local server | structural pass **0.733**, F1 0.889, n=15 (§3.5) |
| 2026-08-07 | a structured call hung for the full 1800 s `request_timeout`; structured output disabled whenever a custom `base_url` is set | the hang is gone |
| 2026-08-12 | manual JSON parse is the only path | schema-valid output **0 of 15** |

Both decisions were right on their own. `with_structured_output` against llama-server really did hang
for thirty minutes with no log line — that is `registry.py`'s documented reason for refusing it — and
the manual-parse path really does answer in seconds. What nobody measured is whether the surviving
path *works*: it depends on the model spontaneously emitting JSON that matches a nested schema, and
this model does so **never**. The composition is M4's shape a second time: two individually correct
bounds meeting in a hole.

**Why it was invisible for five days.** `NarrativeAgent.generate` returns `None` on failure, and the
report node falls back to the deterministic template — which is *better on faithfulness anyway*
(§3.5: F1 1.000 vs 0.889). So the report ships, reads well, scores well, and the run reports success.
The only observable is a log line at `ERROR`, in a pipeline that emits thousands.

**The ledger consequence.** §3.5's finding — *"the LLM's only edge is structural/readability
compliance, 0.73 vs 0.00"* — describes a capability that **no longer exists in production**. The one
justification the LLM narrator had is exactly the one that regressed. N5 is not withdrawn: its
2026-06-04 measurement stands as a measurement. What changes is that it no longer describes the
shipped system, and a row that says so is worth more than one that quietly keeps the old number.

**What the retention rule cost us again, one level deeper.** The harness now keeps the prose beside
each score (fixed today), but on a *failed* generation there is no prose to keep — and we kept
nothing about what the model actually emitted. So the coercion that would repair this (string ->
paragraphs, recommendation-key mapping) cannot be designed from the run that found the defect; it
needs one more generation captured raw. That is the third time in this project that the artefact
needed to answer the next question was the one not retained.

---

### 3.20 The narrative comparison was scoring a degradation notice — `INTERNAL` (D1)

**Repaired, then re-measured, 2026-08-12** (5 fixtures x 3 repeats = 15, same harness as §3.5):

| metric | LLM narrative | deterministic "fallback" |
|---|---|---|
| grounding precision | 1.000 | 1.000 |
| coverage recall | 0.920 [0.867, 0.973] | 1.000 |
| F1 | 0.956 [0.926, 0.985] | **1.000** |
| structural pass-rate | **1.000** | 0.000 |
| fp_linter clean-rate | 0.800 | 1.000 |

Paired **LLM − fallback F1 = −0.044, 95% CI [−0.074, −0.015]**, n=15; sign test fallback 6, ties 9,
LLM 0. Against 2026-06-04 (−0.111 [−0.252, −0.030]) the gap has narrowed by more than half and the
interval has tightened, which is what the duplicate-key repair bought.

**But the retained prose shows the comparison is not what it appears to be.** With the text kept
beside the score for the first time, the "deterministic fallback" arm reads:

> *executive_summary*: "Sample classified as malware. Best-guess family: dropper. Pipeline reported
> 5 ATT&CK techniques: T1105 (…), T1140 (…), T1055 (…). Confidence 0.80. This is an auto-generated
> summary (no LLM available); review the detailed sections for evidence."
>
> *capabilities_narrative*: **"Detailed narrative was not generated because the analysis ran in
> mock/offline mode or the narrative LLM call failed."**

That is hardcoded in `apply_fallback_narrative` — not a fixture artefact. The arm is a **degradation
notice**, and it wins `coverage_recall` **by construction**: the metric counts evidence technique IDs
that appear in the text, and an exec summary that enumerates every ID surfaces all of them by
definition. It scores 1.000 for listing what it declines to explain.

So §3.5's phrasing — *"the deterministic template is the stronger baseline"* — overstates it, and the
correction is worth more than the original claim. The template is not a competing narrator that beats
the LLM; it is the **absence** of a narrator, announcing itself, measured by a metric that rewards
enumeration over prose. A document scored against its own table of contents will lose.

**D1's readability rubric — an LLM-based INTERNAL assessment, explicitly excluded from the paper.**
Scored blind on the retained prose across the five families (structure, traceability, redundancy,
actionability):

| dimension | LLM narrative | deterministic arm |
|---|---|---|
| structure | 3–4 paragraphs, one per kill-chain phase, 1,003–1,168 chars | 1 paragraph, 219 chars, stating no narrative exists |
| traceability | technique IDs parenthesised inline at the claim they support | IDs listed once in the summary, unlinked to evidence |
| redundancy | summary and capabilities carry different content | nothing to repeat |
| actionability | 4 specific recommendations, each with a technique and a detection pointer | 1 generic "hunt for the associated indicators" |

There is no contest, and that is the point: **the only dimension on which the LLM narrator was ever
justified is the one the faithfulness metric cannot see.** This assessment used an LLM as the rubric
judge and therefore **does not enter the paper** — `self-audit-pitfalls.md` P2 is `CLEAR` on the
strength of "LLM-as-a-judge was never used for scoring", and it stays that way. E.7 remains an
acknowledged limitation in the paper: no human analyst scored a report.

---

### 3.21 The other half of Layer-0, and a contaminated evidence channel — `NEGATIVE` (C2 closed)

§3.1 measured three of six Layer-0 sources and said so: `sigma_layer`, `lolbin` and `network_dga`
consume a sandbox report and could not run. With the cohort's reports archived they can, offline —
the production assembly in `pipeline/nodes.py` takes a **report dict**, not a live connection. Run
over all 43 archived samples with that assembly copied rather than reimplemented:

| dynamic source | fires on | contributes a technique no other dynamic source found |
|---|---|---|
| `sigma_layer` | **43 / 43 = 100%** | **43 / 43** |
| `lolbin` | **0 / 43** | 0 |
| `network_dga` | **0 / 43** | 0 |

**This invalidates the basis of §1.10's null rather than confirming it.** That study found the
corroborated set never changes the verdict (0 of 15) — measured with three static sources, while the
source that fires on *every* sample and contributes uniquely on *every* sample was absent. `sigma`
carries weight **0.55**, above `static` (0.35) and below only `yara` (0.90). A null obtained without
the second-heaviest layer is not a result about the cascade; it is a result about a cascade missing a
layer, and the re-run is queued as C3 rather than treated as done.

**Two more mechanisms join the near-inert list, and the reason is not the mechanism.** `lolbin` and
`network_dga` fire on nothing, and the harness records no errors, so this is genuine absence rather
than silent failure. But the inputs are present and rich: every report carries 51–59 domains and
1–6 processes, and `build_network_iocs` returns them intact. The layers are being fed and are
declining to claim.

**Why they decline is the finding.** Of 130 distinct domains across the cohort, **40 appear in all
43 samples**, and they are the analysis VM's own background traffic — WPS Office and Kingsoft
endpoints (`global.wps.com`, `params.wps.com`, `entry.wpscdn.com`, `365.kdocs.cn`, `api.wps.cn`)
phoning home during every detonation.

| | |
|---|---|
| share of each sample's domains that are cohort-ubiquitous | 63.5% min / **71.4% median** / 81.6% max |
| domains left after removing the ubiquitous set | 9 min / 16 median / 23 max |
| samples with no sample-specific domains at all | 0 / 43 |

**About seven of every ten domains in this cohort's network evidence describe the sandbox, not the
sample.** The DGA heuristic is correct to find nothing in them. This is §6.3's output-cardinality
check arriving one level lower than usual — not in the outputs, but in the *evidence*: 40 constants
where variation was expected, visible the moment anyone counted.

Two consequences we take rather than argue with. Any measurement over "network evidence" on this
cohort is measuring the host as much as the malware, and **C4's dynamic-vs-static comparison must
report this**, because a dynamic channel that is 71% constant is a weaker treatment than its name
suggests. And a sandbox VM should be checked for its own telephony before its captures are used as
evidence — ours was not, and the check costs one `Counter`.

---

### 3.22 The six-source verdict re-run is void, and the two runs disagree — `INVALID` (B3 re-run, attempt 1)

> **Label corrected 2026-08-12.** This section was tagged `(C3, attempt 1)`. C3 is the queue's
> *n=100 cascade ablation over the CAPE dynamic path*, which has never been run; this study is a
> re-run of **B3** (the Layer-0 verdict arm, §3.9) and it serves claim **C6**. Read as written, the
> old tag said a CAPE experiment had been attempted and voided. Same correction applied to §3.23.

§3.21 showed §1.10's null rested on three of six Layer-0 sources, so the verdict study was re-run
with all six. **The result cannot be used, and the reason is a precondition I broke rather than a
finding.**

The harness distributes each fixture's ground truth round-robin across the sources and states the
assumption it depends on: *each source carries an equal share*. The fixtures carry **five**
techniques. Over three sources that is 2/2/1 — uneven but every source carries something. Over six
it is **1/1/1/1/1/0**:

| arm removed | verdict changed | Jaccard | what that actually measures |
|---|---|---|---|
| five sources carrying one technique each | **15/15** | 0.800 | removing the sole carrier of a technique loses that technique — arithmetic |
| `network_dga`, carrying none | **0/15** | 1.000 | removing a source with no claims changes nothing — also arithmetic |

Every number in that table is fixed by the assignment before the cascade or the judge does anything.
Extending `SOURCES` from three to six without checking the fixtures' technique count invalidated the
design, and it is my error, caught by reading the assignment rather than by any check that exists.

**Worse, the two runs disagree in a direction neither explanation covers.** With three sources,
removing `yara_layer` — which carried **two** of five techniques — changed nothing: Jaccard **1.000**,
0/15. With six, removing `yara_layer` carrying **one** technique lost it: Jaccard 0.800, 15/15.
Removing *more* techniques produced full recovery; removing *fewer* produced loss. That is not
explained by the assignment change alone, and we do not have an account of it.

Candidates we can name but not currently separate: the model server was at **17.8 GB of its 20 GB
cgroup cap** and thrashing during most of the new run (the run died at 102/105 arms on judge
connection errors and was resumed after a restart, so its arms did not all see the same server
state); and the two runs are three days apart with production changes in between. Either would be
enough. **We record the disagreement rather than picking the reading we prefer.**

**Consequences taken now.** §5 of the results stays `provisional` — the caveat added earlier stands
and is now better understood: not merely "measured with three of six layers" but "and the six-layer
re-run was void". B3 is **not** closed, and neither is the claim it serves (C6). A valid re-run
needs fixtures carrying at least twelve techniques so six sources each hold two or more, and it
needs the model server restarted between samples the way §3.18's harness does — this one does not
restart, which is why it reached 17.8 GB.

---

### 3.23 Two Layer-0 sources are fed and decline — `MEASURED` (B3 re-run, attempt 2 — design)

§3.22 prescribed the repair: fixtures with ≥12 techniques so **six** sources each hold two or
more. Building it surfaced a prior question that the prescription assumed away — *do all six
sources produce anything on this corpus at all?* They do not, and the distinction matters
because the two ways of producing nothing call for opposite designs.

Over the archived reports, measured by running the production builders directly
(`build_lolbin_isr`, `build_dga_isr(build_network_iocs(...))`, deterministic, no LLM):

| source | claims produced | what it was given |
|---|---|---|
| `sigma_layer` | fires on **94/97**, unique technique credit 92 | — |
| `lolbin` | **0/97** | median **8888** recorded API calls, median 2 processes (max 56) |
| `network_dga` | **0/97** | **48–68** domains per sample, median 56 |

**Re-measured on 2026-08-13, after the §3.24 recovery more than doubled the cohort.** A rate of
zero over 43 samples is a weaker claim than the same rate over 95, and the recovered reports are
visibly richer: the median API-call count rose from 3356 to 8888 and the busiest sample now
records 56 processes against the old cohort's 18. The rate did not move off zero. The source that
*is* kept moved slightly the other way — `sigma_layer` fires on 94 of 97 rather than all of them,
so three samples carry no dynamic Layer-0 evidence at all.

Original n=43 figures, kept for the record: sigma 43/43, lolbin 0/43 against a median 3356 API
calls, network_dga 0/43 against 49–63 domains.

Both return `None` **cleanly — no exception, no degraded path**. They are handed substantial
evidence and decline it: no invocation in the process data matches a LOLBin, and none of the
49–63 domains scores as algorithmically generated. That is consistent with §3.21's contamination
finding, where 40 of 130 distinct domains are the analysis VM's own telephony — real vendor
domains are exactly what a DGA scorer should reject.

**The design consequence, and it departs from what §3.22 prescribed.** That section assumed the
repair was a size fix and kept all six arms. Giving `lolbin` and `network_dga` an equal share of
the ground truth would hand a mechanism evidence it never receives in this deployment, ablate it,
and report the result as if it described the running system. So attempt 2 ablates the **four
sources that fire** — `yara_layer`, `import_capability_layer`, `tool_artifact_layer`,
`sigma_layer` — and the two exclusions travel in the run's JSON with the rate that justified
them. This is the same firing-rate-before-effect rule applied in §3.15/§3.17; the departure is
recorded here rather than made silently in the harness.

**A second change is a structural repair, not a size fix.** The overlap condition previously
alternated two pairs, `yara`+`import_capability` (cross-domain → corroborated) and
`yara`+`tool_artifact` (same domain → **not** corroborated despite two detectors agreeing). yara
appeared in both, so removing it destroyed all corroboration *by arithmetic* — the earlier
write-up said as much and asked the reader to discount that arm. Adding a third pair,
`sigma`+`import_capability`, gives a corroborated pair that does not involve yara, so
`no_yara_layer` now leaves cross-domain agreement standing and becomes a measurement.
`no_sigma_layer` mirrors it. All five arms are informative for the first time.

**Preconditions now enforced rather than remembered.** The fixture floor is derived from
`len(SOURCES)` (≥3 claims per source), not written as the literal `12` that would starve sources
again the next time the list changes; a unit test states the starvation consequence directly; and
the harness restarts the model server per fixture in its own transient cgroup, which is the
§3.22 memory lesson.

Selected fixtures (seeded, re-derivable, from `ground_truth/attck_malware/`): `bazar` (51),
`blackcat` (21), `jhuhugit` (20), `nanhaishu` (12), `sardonic` (25), `sliver` (23), `stonedrill`
(15), `wannacry` (16). 8 fixtures × 5 arms × 2 conditions = **80 judge calls**. Harness and unit
tests are in place; **the run has not been made yet**, so §5 stays `provisional` and B3 stays
open.

---

### 3.24 The cohort was never n=100: the sandbox reported success for 56 analyses that took zero seconds — `INSTRUMENT FAILURE`

The n=100 cohort was submitted on 2026-08-10 and 43 reports were archived. The other 57 were
assumed to be pending or lost in transit. On 2026-08-13, with the sandbox reachable again, the
fetch was retried and refused every one of them: 56 with `Reports directory does not exist`, one
with `Task failed`. Asking the sandbox *why* produced the finding.

Every task in the cohort was queried through `/apiv2/tasks/view/`. The split is bimodal with
nothing in between:

| group | n | task status | analysis wall-clock |
|---|---|---|---|
| report archived | 43 | `reported` ×43 | min **186 s**, median **350 s**, max 366 s |
| no report | 57 | `reported` ×56, `failed_analysis` ×1 | min **0 s**, median **0 s**, max **1 s** — 56/56 at ≤2 s |

**56 analyses are marked `reported` after zero to one second of execution.** A Windows PE does not
detonate in one second; nothing was observed, and no report directory was written. The status field
records the queue transition, not whether an analysis happened, so on this instance `reported` is
not evidence of anything. Per-task timings are retained in `cape_task_status_audit.json`.

Ordering points at the cause rather than at the samples. The 43 real analyses complete through the
afternoon of 2026-08-10; from roughly 17:30 onward every task returns instantly. A single-VM
instance appears to have stopped detonating mid-batch while the scheduler kept marking work
complete. It is not the samples: their binaries are intact locally, and a re-submission of one of
them (task 19144, 2026-08-13 11:38) ran for minutes rather than seconds on the same instance.

**Consequences, and they reach several planned studies.**

* **The cohort has always been n=43.** C3, C5 and C6 are written against "n=100" in the roadmap and
  in the decision table; that number was never realised and every one of them must either re-run
  the missing 57 or report n=43. C4 is unaffected in kind — it draws from the archived reports and
  its cohort was already the 43 — but "n=100 cohort" must not appear next to it either.
* **A completion status is not a completion.** The retrieval path already verifies
  `target.file.sha256` against the ledger before writing (§6), which is why nothing false entered
  the archive. What no check covered was an *absent* report whose task claimed success. Checking
  the analysis duration is now part of accepting a task as done.
* This is the sixth instrument failure in the ledger, and the second where the instrument reported
  success it had not achieved — the first being the sandbox answering a request for a deleted
  report with HTTP 200 and a 63-byte error body (§6). Both were found by disbelieving a success
  signal, not by a test.

---

### 3.25 The evaluation machine was thermally saturated, and the fix costs nothing — `MEASURED` (E.5)

C4's second night ended with the laptop overheating and freezing hard enough to need a power cut.
Three things came out of investigating it, and the third one changes how every remaining LLM run
on this hardware should be executed.

**The guard could not run in the condition it exists for.** It saw the danger — 13:06:01, "LOW
5571MB available — STOP sentinel laid" — and then wrote nothing for six minutes while the model
server kept working, until its log ends mid-line on the power cut. A loop polling every ten
seconds does not go quiet for six minutes because it is idle. Its polling path forked six to
eight times a pass (`awk` ×3, `pgrep`, `date`, `stat`, `cat`), and fork+exec is precisely what
stops completing on a thrashing machine; the policy required three consecutive readings before
acting and the implementation could not take the second one. The hot path is now fork-free, and a
pass that arrives more than four intervals late is treated as the finding rather than as a
prelude to counting — verified by SIGSTOPping the guard, which now reports
`STARVED: this pass is 16s late`.

**Nothing had ever measured heat.** Memory was instrumented in detail across four sections of this
ledger; the quantity the operator actually reported was not sampled anywhere. The guard now reads
k10temp `Tctl`.

**The load was saturating the CPU for no throughput at all.** With the machine idling at 76-81 °C
on the die, a fixed 1500-token generation was run twice under identical conditions, changing only
the CPU's power ceiling:

| CPU ceiling | peak die temp | throughput | output |
|---|---|---|---|
| boost on, 5386 MHz (as run for §3.16-§3.24) | **95 °C** | 55.6 tok/s | sha `ea54fa3b47d71ae3` |
| boost off, capped to **2401 MHz** | **71 °C** | **55.6 tok/s** | sha `ea54fa3b47d71ae3` |

**Twenty-four degrees cooler, identical throughput, bit-identical output.** Under the real
pipeline the effect holds: four minutes into a live arm the die sits at 76 °C, where the same
workload previously reached 92 °C in under a minute and 98 °C ten seconds later.

The explanation is that this configuration is **memory-bandwidth bound, not clock bound**. The
`-ot` regex places thirty blocks of MoE expert tensors in host RAM (10.1 GB of pinned CUDA_Host
buffer, §3.24 investigation), and the cores spend their time waiting on memory. At 5.4 GHz they
wait faster and hotter.

Consequences: frequency and boost do not affect floating-point results, so this is the one
mitigation that leaves the measurement untouched — unlike lowering llama's thread count, which
alters the reduction order in ggml's matmul and would make arms run before and after the change
incomparable. The reproducibility appendix must state the CPU ceiling alongside the model digest
and engine commit, because "55 tok/s on a laptop" is only reproducible with the power terms
attached. And §3.16-§3.24 were all produced at the uncapped setting, which is a hardware
difference from everything measured after this point even though the arithmetic is identical.

---

### 3.26 The pipeline scores what the sandbox already scored — `NEGATIVE` (C5 at n=97, C4 interim at n=13)

C5 exists because every F1 this project has reported was unanchored. The natural anchor is the
sandbox the pipeline is built on: CAPE maps its own signature hits to ATT&CK technique IDs in each
report's `ttps` block, deterministically, with no model anywhere. Scored against the same family
ground truth, through the same alias resolution the drift harness uses:

| | n | precision | recall | F1 |
|---|---|---|---|---|
| CAPE alone, whole recovered cohort | **97** | 0.2413 [0.2123, 0.2711] | 0.1328 [0.1131, 0.1529] | **0.1526 [0.1344, 0.1709]** |
| CAPE alone, earlier cohort | 43 | 0.2902 | 0.1343 | 0.1666 [0.1411, 0.1938] |

CAPE asserts at least one technique on **97 of 97** samples, median 11 per sample (min 1, max 33).
There is no sample where the baseline simply declines to answer.

**The comparison that matters, on the 13 samples C4 has scored so far** — same binaries, same
ground truth, per-sample rather than cohort-mean:

| | mean F1 |
|---|---|
| CAPE alone, no LLM | **0.1130** |
| pipeline, static-only arm | **0.1130** |
| pipeline, dynamic arm | **0.1160** |

Three LLM analysts, a negotiation loop, a revision pass, a judge and a weighted corroboration
cascade land within **0.003 F1** of the signature engine they are built on top of. The per-sample
figures are not the same numbers — the two means agreeing to four decimals is a coincidence, and
was checked rather than reported: all 13 samples differ individually, by as much as 0.13 in either
direction. The system is not reproducing CAPE's answers; it is arriving at different answers of
the same quality.

**Read this as interim and bounded.** n=13 of a possible 97, and C4's remaining arms are blocked
on a machine that cannot finish one before its memory guard intervenes (§3.25 and the abandonment
work). The direction has been stable across every interim reading, but the number will move.

The ceiling both sides share is stated in C5's own scope note: family-level `uses` sets are a
coarse per-sample truth, so absolute recall carries a structural cap. That bias is identical for
the baseline and the pipeline, which is exactly why the comparison is worth more than either
number alone.

---

### 3.27 The verdict follows the claims and ignores the corroboration — `NEGATIVE` (B3 re-run, attempt 2, complete)

Both conditions are in: 80 judge calls over 8 fixtures carrying 12 to 51 techniques, four Layer-0
sources, one arm per source plus the baseline. The two halves point in opposite directions, and
together they answer the question §1.10 left open.

| condition | what removing a layer does to the evidence | verdict changed | Jaccard vs `all` |
|---|---|---|---|
| `disjoint` | its techniques disappear — no other source claims them | **32/32** | 0.738–0.765 |
| `overlap` | its techniques survive — a partner still claims them — but their **corroboration** changes | **0/32** | **1.000 [1.000, 1.000]** |

**The judge is reading the claim list and nothing else.** Take a technique away and the bundle
loses it; leave the technique but destroy the cross-domain agreement behind it and the bundle is
byte-identical. The cascade computes corroboration, weights it by layer trust and surfaces it in
the run summary — and none of that reaches the artefact the analyst receives.

This is §1.10's null established rather than inherited. That version measured three static sources
on five-technique fixtures, where the sixth source received nothing and its arm was identical to
the baseline by arithmetic (§3.22). This one includes `sigma_layer` at weight 0.55 — the heaviest
source, and the one previously absent — gives every source at least three claims, and adds a
yara-free corroborated pair so that no arm is a foregone conclusion (§3.23). The null survives all
of it, at 32 arms rather than 15.

**A pre-registered prediction, resolved in both directions.** `no_tool_artifact_layer` was
predicted to change nothing, because that source shares yara's cascade domain and so cannot
contribute corroboration. In `overlap` that is exactly right: 0/8. In `disjoint` it is wrong, 8/8,
because there the source solely owns its techniques and removing it removes them. The prediction
was about corroboration, and it holds precisely where corroboration is the only thing that varies.

**What this costs the architecture.** C6 — the multi-layer corroboration cascade — cannot be
claimed as a contribution to the output. It is a real mechanism with a measurable internal state,
and that state is downstream-inert on this evidence. Whether corroboration *should* reach the
verdict is a design question; whether it *does* is now settled.

B4 rides along on both runs, and fresh bundles behave quite unlike the archived ones (3 removals
in 60, all `empty_pattern`): the integrity pass ran on 51 of 80 bundles and removed something on
15, 51 objects in total, across all four defect classes — 19 `duplicate_attack_pattern`,
21 `empty_pattern`, 8 `dangling_relationship`, 3 `duplicate_relationship`.


## 4. Literature-driven roadmap (MARD / TraceRAG / LAMD) + dataset integrations

Items are status-tagged inline (`IMPLEMENTED` / `SUPERSEDED` / `SURVEY`); most began as
planned threads and have since landed — kept here as the roadmap's provenance. Four early
threads are fully resolved and now live in their own sections: the technique-ID loop fix
(§1.5 / §3.3), the hybrid technique mapper (§1.5.1), config-gated view-decomposition with an
equal-budget A/B (§3.6), and the MaLAware-style narrative-quality harness (§3.5).

- Reviewed (the "LLM-as-analyst" leads): MARD (multi-agent, arXiv:2604.25264), TraceRAG
  (RAG + explainable, arXiv:2509.08865), LAMD (arXiv:2502.13055). All three are Android,
  but their techniques are platform-agnostic. **Convergent validation:** MARD's
  ReAct-orchestrator + deterministic-engines-as-tools + interpretable evidence chain, and
  LAMD's security-critical context extraction, are already realised in Maljan
  (`execute_tool_loop` + Layer-0/cascade + ISR evidence chain; sink-reachability §1.1). Five
  **net-new** transferable items remain, sequenced by value/effort:
- `IMPLEMENTED` (Item 1, MARD) Per-run token/cost telemetry in `RunSummary` — a thread-safe
  `TokenLedger` ([core/token_ledger.py](../../src/maljan/core/token_ledger.py)) on the container
  tallies each analyst/judge LLM call's `usage_metadata` (char-based estimate fallback, flagged,
  when the local llama-server omits it); the judge node snapshots it into a `TokenUsageMetrics`
  block rendered in `RunSummary`. Gives a MARD-style per-sample cost figure and instruments the
  cost/benefit of the decomposition + RAG experiments below.
- `IMPLEMENTED` (Item 2, TraceRAG) Function-level RAG retrieval for the static analyst — an
  ephemeral per-sample in-memory function index
  ([memory/function_index.py](../../src/maljan/memory/function_index.py): `encode_batch` +
  `cosine` over the chunker's `FUNCTION_BOUNDARY` chunks). A fixed set of behavior-focused NL
  queries (`BEHAVIOR_QUERIES`) retrieves the top-k relevant functions per query (union), fed to
  the analyst instead of every chunk. Config-gated `static_function_rag_top_k` (0 = linear
  path), engages only above `static_function_rag_min_chunks`; fail-safe to the full set. The
  offline retrieval eval (`tests/evaluation/eval_function_rag.py`) shows recall 1.0 of the
  seeded malicious core at **~75% input-token reduction** on a 36-function corpus.
- `IMPLEMENTED` (Item 3, LAMD) Tier-wise *vertical* reasoning mode (facts → behaviour →
  ATT&CK semantics, each tier consuming the previous tier's findings) as a sibling to the §3.6
  *horizontal* view-decomposition. `BaseAnalyst.analyze_isr_tiered`
  ([agents/base_agent.py](../../src/maljan/agents/base_agent.py): `_TIER_SPECS`/`_tier_specs`
  ladder) runs N **sequential** tools-free `_invoke_view` calls, each fed the original evidence
  plus the prior tier's output, at the same equal-budget `expert_max_tokens // N` split as §3.6;
  per-tier ISRs merge (dedup) via `merge_chunk_isrs`, with per-tier fault isolation. Gated by
  `LLMConfig.view_decomposition_mode` (`"facet"` default = §3.6 concurrent facets; `"tier"`
  reinterprets the N knob as reasoning depth, canonical N=3), dispatched in `make_analyst_node`.
  A `{n}-tier` arm was added to `eval_view_decomposition.py` alongside the facet arms.
- `IMPLEMENTED` (Item 4, LAMD) Inline foundational-tier claim-consistency gate — drop ungrounded
  claims at parse time (the claim's cited artifact / technique absent from the source evidence),
  complementing the post-hoc, structural `fp_linter`. `BaseAnalyst._apply_consistency_gate` +
  the pure helper `_claim_grounded_in_evidence` (technique-id-in-evidence, real-artifact-ref
  token, or claim-text substantive-token overlap ≥34%, ignoring filler stop-words) run in the
  analyst safe_* wrappers (`safe_analyze_isr`, `_chunked`, `_views`, `_tiered`), so both the
  structured (`_parse_claim_blocks`) and text-fallback (`_text_to_isr`) claim shapes are gated.
  Config-gated `PreprocessingConfig.use_claim_consistency_gate` (off = every parsed claim kept);
  fail-safe (any gate error leaves the ISR untouched).
- `IMPLEMENTED` + `NUMBERS` (Item 5, MARD) Concept-drift eval across first-seen year cohorts.
  The earlier data gate is now resolved end-to-end and a live run produced numbers:
  - **Dated-manifest collector** `tests/evaluation/collect_temporal_manifest.py` — pulls
    metadata-only sample records (sha256 + `first_seen` + family + file_type) from MalwareBazaar
    (`get_siginfo` per family, Auth-Key via `$MALWAREBAZAAR_AUTH_KEY`, or a local full-dump CSV),
    filters to the Windows/Linux scope (§1.8), buckets by year, balance-samples each cohort, and
    writes a manifest. Verified live: a **balanced 210-sample manifest — 7 cohorts (2020–2026),
    exactly 30 each, 27 distinct families** — collected by union-ing multi-year families (Emotet,
    TrickBot, Dridex, Ursnif, DarkComet, Pony, RaccoonStealer, IcedID, CobaltStrike, Gh0stRAT,
    Sliver, LummaStealer, …). No binaries are downloaded. The manifest is vendored (metadata only,
    no binaries) at `tests/evaluation/temporal_manifest.json` so the eval is reproducible.
  - **Drift harness** `tests/evaluation/eval_temporal_drift.py` — loads the manifest, resolves
    each family to its in-repo ATT&CK ground-truth fixture
    (`tests/evaluation/ground_truth/attck_malware/<slug>.json`, 700+ families, MITRE `uses`
    relationships), runs the pipeline per present binary, and reports per-cohort precision /
    recall / F1 (mean + 95% bootstrap CI via `TTPAccuracyMetrics`) plus the earliest→latest F1
    drift delta. `--dry-run` validates the manifest/ground-truth wiring offline (verified: **all
    210 samples resolve to ground truth, 30/30 per cohort** — the alias map + CamelCase-split
    fallback maps every MalwareBazaar signature, e.g. RaccoonStealer→raccoon_stealer,
    Gh0stRAT→gh0st_rat, Heodo→emotet). `scan_manifest` (coverage + analyzable list) is unit-tested
    with tmp dirs; the pure scoring/resolver helpers in `test_temporal_drift_scoring.py` (15 tests).
  - **Methodology caveat (recall ceiling -> read drift as a delta).** Family-level ATT&CK `uses`
    sets are a *coarse* per-sample ground truth: a single Emotet binary need not exhibit all ~47
    catalogued Emotet techniques, and a stripped/packed sample exposes fewer still — so absolute
    recall carries a structural ceiling and precision some noise. This bias is, however,
    **constant per family across years**, so the defensible reading is the *relative* drift —
    the earliest->latest F1 **delta** within a family/cohort — not the absolute level. The
    harness reports both; the paper claim rests on the delta.
  - **Cohort balance.** `get_siginfo` is recency-biased per family, but union-ing ~30 families
    whose active years overlap different periods yields a fully balanced manifest (the delivered
    one is 30/cohort × 7 years, 27 distinct families). The CSV full-dump (`--source csv`, full
    history, no rate limit) is the alternative when even-wider coverage or specific years are needed.
  - **Remaining (operator-side, not code):** download the binaries into `data/samples/<sha256>.<ext>`
    (isolated env; `collect_temporal_manifest.py --download` automates this via MalwareBazaar
    `get_file`) and run with a live llama-server. The harness scores whatever is present
    (`--max-per-cohort N` for a cheap first pass) and reports the rest as `pending_binary` —
    never silently dropped.
  - **Live result (2026-06-07, n=210 — FULL cohort, 30 per cohort × 7 years).** Binaries downloaded
    from MalwareBazaar into `data/samples/` (210/210 extracted; AES zips via pyzipper) and analysed
    **static-only** (Ghidra+LLM, `SANDBOX__BACKEND=mock` so no dynamic / no public-sandbox upload;
    `disable_thinking`, `NEGOTIATION__MAX_ITERATIONS=2`) on the local Qwen3.6-35B-A3B. Per-cohort
    ATT&CK precision / recall / F1 (mean, 95% bootstrap CI):

    | year | n | precision | recall | F1 | 95% F1 CI | halluc. |
    |---|---|---|---|---|---|---|
    | 2020 | 30 | 0.092 | 0.047 | 0.059 | [0.034, 0.089] | 0.007 |
    | 2021 | 30 | 0.214 | 0.063 | 0.089 | [0.061, 0.121] | 0.003 |
    | 2022 | 30 | 0.150 | 0.037 | 0.059 | [0.035, 0.086] | 0.000 |
    | 2023 | 30 | 0.173 | 0.060 | 0.084 | [0.054, 0.114] | 0.011 |
    | 2024 | 30 | 0.194 | 0.042 | 0.063 | [0.042, 0.087] | 0.003 |
    | 2025 | 30 | 0.181 | 0.063 | 0.079 | [0.052, 0.110] | 0.002 |
    | 2026 | 30 | 0.121 | 0.042 | 0.055 | [0.033, 0.079] | 0.000 |

    Earliest→latest drift **delta = -0.004 F1** (2020 0.059 → 2026 0.055).
  - **Equivalence bound (added 2026-08-08) — and a data-retention defect it exposed.**
    "All CIs overlap" is an absence of significance, not evidence of absence, and a reviewer
    primed by [9] will say so. Turning it into a positive claim needs a bound, so:
    approximating each cohort's SE from its bootstrap CI half-width, the 2020-vs-2026
    difference is **-0.004 F1 with a 95% CI of [-0.040, +0.032]** — i.e. **|drift| ≤ 0.040 F1
    over seven years at 95%**, and the largest pairwise cohort gap (2021→2026, -0.034) sits
    inside that bound. That is a positive, citable statement where "no significant drift" was
    not.
    **Three honest limits ship with it.** (i) The study was powered to detect roughly
    **δ ≥ 0.05 F1** at 80%; anything smaller was never observable, so the bound is the claim and
    "no drift" is not. (ii) The bound is **large relative to the measurement** — ±0.040 on a
    base F1 of 0.055–0.089 is ±57%, so temporal stability is established only in the coarse
    sense the low absolute recall permits. (iii) The SEs are **reconstructed** from CI
    half-widths under a normality assumption, and the bootstrap CIs are mildly asymmetric
    (2020: -0.025/+0.030), so the arithmetic is an approximation of the one we should have been
    able to do directly.
    **The defect:** the n=210 run recorded per-cohort aggregates but **not per-sample F1s**, so
    a proper TOST is impossible without re-analysing the corpus (45–70 h). Future evaluation
    runs must persist per-sample scores — the cost of not doing so is that a null result cannot
    be upgraded into an equivalence claim afterwards.
  - **Findings.** (i) **No measurable concept drift.** The earliest→latest delta (-0.004) is
    negligible and the per-cohort F1 CIs all overlap (the band is 0.055–0.089 with no monotonic
    trend; 2021 is the peak, 2026 the floor, but 2026's CI [0.033, 0.079] contains 2020's mean) —
    the static path's accuracy is *temporally stable* across a 7-year span at full cohort size,
    confirming the n=42 pilot at 5× the samples and tightening every CI. This is the direction of
    MARD's robustness claim, just at a low absolute level. (ii) **Low absolute recall is structural,
    as caveated** — static-only recovers a small fraction (recall 0.037–0.063) of the family-level
    `uses` sets because those sets are dominated by behavioural/runtime techniques a decompile cannot
    observe; precision is modest (0.09–0.21) and **hallucination is ~0 across every cohort**
    (≤0.011; the grounding gates hold on real malware at scale, not just fixtures). (iii) The result
    argues that **dynamic analysis is required to lift recall** — the static-only arm is a clean,
    upload-free baseline, and the gap to the family ground truth quantifies what dynamic must add.
  - **Cost.** ~13–20 min/sample on the local 35B (Ghidra auto-analyse + multi-round pipeline; a few
    heavy 2026 binaries ran 30–56 min); the full 210 ran as a multi-day batch with JSONL checkpoint
    resume and an LLM-health gate (llama-server OOM-crashed ~hourly on large binaries — each restart
    auto-resumed without rescoring). A path bug was fixed first: the harness handed `load_program`
    the host path, not the Ghidra container's `/data/samples` mount, so the static analyst made 0
    tool calls until corrected.
- `IMPLEMENTED` (ATT&CK case-prior RAG — LLM-centric U2) The function-level RAG (Item 2) retrieves over
  *this sample's own* decompiled functions; it has no external knowledge corpus. To raise precision
  (n=210 static-only precision is only 0.09–0.21) the right next input is a corpus of
  **decompiled-function text or NL behavioural descriptions already mapped to ATT&CK** — retrieve
  behaviourally-similar, ATT&CK-labelled functions from prior samples as few-shot grounding.
  **Survey note (2026-06-07):** three candidate datasets were assessed and rejected for this:
  *CyberLLMInstruct* (arXiv:2503.09334 — LLM-safety instruction pairs, no binaries/ATT&CK, dataset
  not distributed, only a regeneration pipeline); *LLM-Assisted JAR Classification* (REJAFADA — JAR,
  binary benign/malicious only, no families/TTPs); *MABEL* (vx-underground, 400+ Windows-PE families,
  but **static-feature CSV tables only — no raw binaries, no ATT&CK mapping, no NL narratives**,
  unsuitable for semantic retrieval). None fit. The needed corpus shape (decompiled-code ↔ ATT&CK)
  does not exist off-the-shelf; building one from our own growing LTM (Qdrant `StoredCase` already
  holds `technique_ids` + `summary_text`) is the more promising path — i.e. mine our own analysed
  history into an ATT&CK-labelled retrieval index rather than importing an external dataset.
  **Implemented (2026-06-07):** built exactly that, mirroring the U3 family-feature RAG shape and fully
  LLM-centric. New `memory/attck_case_index.py` (in-memory cosine `AttckCaseIndex`: embeds each prior
  case's `summary_text` at load like `semantic_attck_index`, `search` ranks behaviourally-similar
  neighbours, `recommend_techniques` **aggregates** their attributed `technique_ids` into a ranked
  candidate list — support = neighbour recurrence, score = best similarity) +
  `analysis/attck_case_rag.py` (fail-safe `retrieve_techniques`, `build_attck_case_hint` →
  "CANDIDATE ATT&CK TECHNIQUES … evidence to weigh, NOT a verdict", `to_report_dicts`). The query
  reuses U3's `build_sample_profile_text`, so U2/U3 share one embedding vocabulary; the static analyst
  now gets the hint in the same prompt slot as the family-RAG hint (and the judge node records the
  candidates into `FamilyAttribution.attck_case_candidates`). Offline builder
  `scripts/build_attck_case_kb.py` mines our OWN long-term memory — `--qdrant-url` scrolls the live
  LTM collection, or `--cases-jsonl` reads an export — into the vendored `data/attck_case_corpus_v1.json`
  (stores case TEXT only; the index embeds at load → parity, zero new deps, reuses the fastembed
  BGE-384 already loaded for LTM). Gated OFF by default (`PreprocessingConfig.use_attck_case_rag`);
  fail-safe (no corpus → no-op). Distinct from the judge's existing `_build_memory_context` retrieval:
  that surfaces *raw* prior cases to the **judge** at negotiation time keyed by final ISR claims; U2
  surfaces an *aggregated* ATT&CK candidate list to the **static analyst** at proposal time (the stated
  precision target), raising first-pass TTP grounding rather than only corroborating at the end.
  Drift-robust and LLM-centric: nothing is trained, adding a case is one corpus row, and stale
  candidates are harmless because the LLM corroborates against the decompiled logic. **Caveat (honest):**
  the LTM corpus stores *behavioural* `summary_text` while the static-stage query is a *static-feature*
  profile, so matching is coarse (vocabulary mismatch) — which is exactly why the candidates are advisory
  and the LLM decides; the index exposes a generic `search(query_text, …)` so the judge (which has full
  behavioural claim text) can adopt the same aggregation later for a tighter match.
  **Corpus vendored from MABEL (2026-06-08):** the empty-LTM blocker (the n=210 drift run never wrote
  `StoredCase`s — Qdrant held only the function-hash collection) was resolved WITHOUT a live LTM by
  mining MABEL instead. The MABEL condensed v2.10 release turns out to carry **per-sample capa-derived
  ATT&CK ids** (`mitre_attack_id`) plus `standardized_import_functions_sorted` and capa/yara capability
  columns — i.e. exactly the (behaviour ↔ ATT&CK) shape U2 needs, which the original survey wrongly
  recorded as "no ATT&CK mapping". A new `--mabel-csv` mode on `scripts/build_attck_case_kb.py`
  transforms each row into a case (sha256 id; summary_text from imports + capa + yara; technique_ids
  regex-parsed from `mitre_attack_id`; category from the yara_* family-class columns) with a
  `--max-per-family` cap so the runtime index does not embed all ~74k labelled rows. Built the vendored
  `data/attck_case_corpus_v1.json` (the config default path → turnkey): **1,733 cases, 77 distinct
  ATT&CK techniques** (cap 6/family to keep the artifact ~1.3 MB). ~~End-to-end verified with fastembed
  BGE-384 — an injection+network static profile retrieves T1055 / T1055.003 (process injection) at
  0.90 plus related evasion TTPs.~~ **Retracted 2026-08-08 (see §1.5.3):** that check proved nothing —
  0.90 is what *every* runtime query scores against this corpus, correct or not, because the query and
  the corpus share only their boilerplate. Measured against a frequency-prior control, the candidate
  list is no better than ignoring the sample; the thread is resolved `NEGATIVE` in §1.5.3.
  **Caveats:** the ATT&CK labels are capa's *static* inference (not authoritative ground truth, but a
  large real labelled corpus); MABEL ships no binaries (features-only — safe to download, no live
  malware); the `--csv`-style summary vocabulary overlaps but does not perfectly match
  `build_sample_profile_text` (advisory retrieval, LLM decides). Still OFF by default; the Qdrant /
  JSONL builder modes remain for mining the production LTM as it grows.
- `SUPERSEDED` (static-feature family classifier) A trained gradient-boosted family classifier
  (EMBER/MABEL static features → family prior) was considered for the static-only attribution gap
  (`SANDBOX__BACKEND=mock` zeroes `family_confidence` whenever no CTI / sandbox sig / ISR claim names
  the family — frequent in the n=210 run), then **rejected and removed**: a trained model decides
  *outside* the LLM and re-imports the concept-drift fragility the n=210 run showed the LLM path does
  NOT have — against the "everything LLM-centric" principle. Replaced by the LLM-centric Family-feature
  RAG below (U3), which fills the same gap with retrieval + LLM decision and stays drift-robust.
- `IMPLEMENTED` (Family-feature RAG — LLM-centric U3) The static-only attribution gap is filled
  without any trained model: a deterministic static-feature **profile** of the sample (import-capability
  histogram + characteristic suspicious imports + packer + high-entropy sections, via
  `extractors/pe_extractor.build_static_analysis`) is embedded and matched against an offline-built
  **family fingerprint KB**; the top-k nearest families are injected into the static analyst as
  CANDIDATE evidence and **the LLM decides** the attribution (retrieval only surfaces candidates — the
  same role YARA / sink-reachability / the ATT&CK index already play). New
  `analysis/family_feature_rag.py` (shared profile renderer for query + KB → embedding parity) +
  `memory/family_fingerprint_index.py` (in-memory cosine, embeds catalog text at load like
  `semantic_attck_index`; reuses the fastembed BGE-384 embedder already loaded for LTM — **zero new
  deps**). Offline builder `scripts/build_family_feature_kb.py` (folder-per-family raw binaries via the
  SAME extractor, and/or a generic MABEL CSV) → vendored `data/family_fingerprints_v1.json`. Gated OFF
  by default (`PreprocessingConfig.use_family_feature_rag`); fail-safe (no catalog → no-op). Recorded
  as `FamilyAttribution.family_rag_candidates`. Stays drift-robust (nothing trained; adding a family is
  a new fingerprint row) and fully LLM-centric. MABEL is now used the LLM-centric way — a retrieval KB,
  not classifier training.
  **Bootstrap catalog built + verified (2026-06-07):** the builder grew a `--manifest`/`--flat-dir`
  mode and produced `data/family_fingerprints_v1.json` from the existing local n=210 corpus (no new
  download — the binaries from the drift run were already on disk; feature extraction is not
  execution). 21 family fingerprints (families with ≥3 samples). End-to-end verified: the index loads
  via fastembed BGE-384 and retrieval returns ranked candidates (e.g. an injection+network query →
  Sliver 0.84 / IcedID 0.80). **Caveats:** (i) the n=210 samples are heavily packed, so the static
  profiles are thin (mostly "high-entropy sections" + generic imports like GetProcAddress) — fingerprints
  are coarse, which is precisely why the LLM (it unpacks via Ghidra decompilation) is the decider and
  retrieval is only advisory; (ii) this bootstrap catalog is built FROM the eval corpus, so it must NOT
  be used for a leakage-free measurement of the RAG's effect — for that, rebuild from a DISJOINT source
  (the Ultimate-RAT-Collection via `--samples-dir`, or MABEL via `--csv`). Still OFF by default.
  **Disjoint MABEL catalog vendored (2026-06-08):** the leakage caveat above is now addressable — built
  `data/family_fingerprints_mabel_v1.json` from MABEL's 82,171 feature rows (`--csv` multi-segment;
  `--family-col family_name --text-cols standardized_import_functions_sorted,yara_capabilities,`
  `capa_capability_name,trid`): **318 families with ≥3 samples**, 308 KB, fully disjoint from the n=210
  eval set. End-to-end verified (an injection+network profile retrieves XWorm / AveMaria / EchelonStealer
  — real inject/RAT/stealer families). The n=210 `family_fingerprints_v1.json` is kept as the *default*
  because it has perfect query-vocabulary parity (same `build_sample_profile_text` renderer), whereas the
  MABEL catalog trades parity (its `--csv` columns differ from the runtime profile surface) for 15× the
  family coverage and zero leakage — operators point `family_fingerprint_catalog_path` at whichever fits
  the run. Both ship; both gated OFF.
- `SURVEY` (external malware-dataset assessment, 2026-06-07) Nine candidate sources were evaluated
  against four Maljan use-axes — **U1** Ghidra+LLM raw-binary corpus (drift/TTP eval), **U2**
  function-level RAG corpus (decompiled-code↔ATT&CK), **U3** static-feature family-classifier training
  data, **U4** per-sample ATT&CK TTP ground truth. Maljan scope is Windows + Linux only (no Android).

  | Source | Platform | Content | Labels | Dated | Verdict |
  |---|---|---|---|---|---|
  | [EMBER](https://github.com/elastic/ember) | Win PE | features only (LIEF), no binaries; 1.1M+1M | benign/malicious only | year + `appeared` mo | U3 base features; family labels must be joined (AVClass/SOREL). |
  | [MABEL](https://github.com/action-ai-institute/MABEL-dataset) | Win PE | feature CSV, no binaries; 475 families | family + YARA caps + **capa→ATT&CK** (corrected 2026-06-08) | PE timestamp (weak) | **U3 + U2** — family-labelled features (catalog) AND per-sample capa-derived ATT&CK ids (case corpus). |
  | [Ultimate-RAT-Collection](https://github.com/Cryakl/Ultimate-RAT-Collection) | Windows | RAW binaries (.7z pw "infected", folder/family); 649 families | family (folder) | No | **U3 INTEGRATED** (2026-06-08): 278 perfect-parity family fingerprints from extracted Client+Server (payload!) PEs. Undated; only ATT&CK-known families score for U1. |
  | MH-1M ([Nature](https://www.nature.com/articles/s41597-025-06469-5) · [Dataverse](https://dataverse.harvard.edu/dataset.xhtml?persistentId=doi:10.7910/DVN/LLHEGN) · [GitHub](https://github.com/Malware-Hunter/MH-1M)) | **Android** | features `.npz`, no binaries; 1.34M APK | VirusTotal (no family/ATT&CK) | "10+ yrs", no cohorts | **Out of scope** (Android + features-only + no ATT&CK). |
  | SF23-[AMGenerator](https://github.com/Malware-Hunter/SF23-AMGenerator) / [AMExplorer](https://github.com/Malware-Hunter/SF23-AMExplorer) | **Android** | tools (AndroZoo+AndroGuard+VT), not datasets | — | — | **Out of scope** (Android tooling). |
  | [APIMDS](https://medium.com/ai-genai-llm/malware-detection-using-machine-learning-methods-on-the-apimds-dataset-8-deep-learning-approach-a6d991e64c49) | Windows | dynamic API-call sequences | benign/malicious only | No | Low — dynamic, not our static path; no ATT&CK. |
  | [DikeDataset](https://github.com/iosifache/DikeDataset) | Win PE | RAW binaries (sha256-named); 10,841 malware + 1,082 benign | malice + category SCORES — no family/ATT&CK | No | **NOT catalogued** (2026-06-08): argmax category collapses to generic/trojan/worm → no discriminative catalog. Binaries kept as a disjoint raw eval corpus only. |

  **Findings.** (i) Five of the nine links are **one Android ecosystem** — MH-1M (the Nature
  descriptor `s41597-025-06469-5`, the Harvard Dataverse `LLHEGN`, and the GitHub repo are the same
  dataset) plus its SF23 build tools — entirely out of Maljan's Windows/Linux scope. (ii) Only **two
  sources ship raw binaries** ingestible by the Ghidra+LLM pipeline (Ultimate-RAT-Collection,
  DikeDataset); both are **undated** (no new drift cohorts) and gated by the ATT&CK-resolvability
  constraint (a family scores only if it is a MITRE `malware`/`tool` object with ≥3 `uses` techniques
  and a fixture under `tests/evaluation/ground_truth/attck_malware/`). DikeDataset's labels are coarse
  categories, not families, so it is **not TTP-scorable** at all. (iii) **MABEL + EMBER** are the only
  realistic static-feature classifier training data (U3). (iv) **No source provides per-sample ATT&CK
  TTP labels (U4)** — our family→ATT&CK `uses` mapping stays the only ground truth — and **none
  provides a decompiled-code↔ATT&CK corpus (U2)**, confirming the "mine our own Qdrant LTM" note
  above. Actionable residue: U1 (Ultimate-RAT-Collection → deeper per-family sampling on ATT&CK-known
  families, NOT drift) and U3 (MABEL/EMBER classifier) are the only two viable *external* integrations;
  **U2 was instead built internally** by mining our own LTM into an ATT&CK case-prior RAG (see the
  `IMPLEMENTED` note above), since no external source supplies the decompiled-code↔ATT&CK shape.

---

## References

Only work we directly built on or positioned against — kept deliberately short.

1. Yu et al. *Maltracker: A Fine-Grained NPM Malware Tracker Copiloted by LLM-Enhanced
   Dataset.* ISSTA 2024. DOI 10.1145/3650212.3680397. — basis for §1.1 (sink-reachability).
2. Rollinson & Polatidis. *LLM-Generated Samples for Android Malware Detection.*
   Digital 6(1):5, 2026. DOI 10.3390/digital6010005. — negative-transfer case; supports
   our deterministic-corpus discipline (§3.1).
3. Zhao et al. *AppPoet: LLM-based Android malware detection via multi-view prompt
   engineering.* Expert Syst. Appl. 262, 2025. arXiv:2404.18816. — basis for §3.2 (views)
   and validation of "LLM proposes, deterministic layer disposes."
4. Saha et al. *MaLAware: Automating the Comprehension of Malicious Software Behaviours
   using LLMs.* MSR 2025. arXiv:2504.01145. — narrative-quality evaluation protocol (§4).

*Added 2026-08-08. Every entry below was verified by fetching its abstract page; see
`research-briefs/incoming/` for per-citation confidence and `CITATION-AUDIT.claude-web.md` for
what was checked and what was not.*

5. Büchel, Paladini, Longari, Carminati, Zanero, Binyamini, Engelberg, Klein, Guizzardi,
   Caselli, Continella, van Steen, Peter, van Ede. *SoK: Automated TTP Extraction from CTI
   Reports – Are We There Yet?* USENIX Security 2025, pp. 4621–4641. — binds §1.5.1; the field's
   own statement of its comparability and dataset problems.
6. D'Oosterlinck, Khattab, Remy, Demeester, Develder, Potts. *In-Context Learning for Extreme
   Multi-Label Classification.* arXiv:2401.12178. — `Infer-Retrieve-Rank`; the general form of
   §1.5's describe-then-map.
7. Lekssays, Shukla, Sencar, Parvez. *TechniqueRAG: Retrieval Augmented Generation for
   Adversarial Technique Annotation in CTI Text.* ACL Findings 2025. arXiv:2505.11988. — with
   the hierarchical successor arXiv:2604.14166 (tactic-first filtering, −77.5% candidate space).
8. *Identifying Adversary Tactics and Techniques in Malware Binaries with an LLM Agent*
   (TTPDetect), Purdue. arXiv:2602.06325. — stripped binaries → ATT&CK; supersedes the §4
   `SURVEY` claim that no decompiled-code↔ATT&CK corpus exists.
9. Evertz, Risse, Neuer, Müller, Normann, Sapia, Gupta, Pape, Shaw, Srivastav, Wressnegger,
   Quiring, Eisenhofer, Arp, Schönherr. *Chasing Shadows: Pitfalls in LLM Security Research.*
   NDSS 2026. arXiv:2512.09549. — places §3.4 in a named tradition; living appendix at
   llmpitfalls.org.
10. Bertalanič, Fortuna. *The Cost of Consensus: Isolated Self-Correction Prevails Over Unguided
    Homogeneous Multi-Agent Debate.* arXiv:2605.00914. — equal-budget negative result on 7–8B
    models; names sycophantic conformity.
11. Tran, Kiela. *Single-Agent LLMs Outperform Multi-Agent Systems on Multi-Hop Reasoning Under
    Equal Thinking Token Budgets.* arXiv:2604.02460. — the Data-Processing-Inequality argument,
    and the degraded-context exception our architecture depends on.
12. Lea, Ghawaly, Richard III, Ali-Gombe, Case. *REx86: A Local Large Language Model for
    Assisting in x86 Assembly Reverse Engineering.* ACSAC 2025. arXiv:2510.20975. —
    confidentiality as the stated design constraint; n=43 user study.
13. Ng, Milani Fard. *Evaluating Retrieval-Augmented Generation for Explainable Malware
    Analysis.* Poster, ACM SecDev 2026. arXiv:2605.03140. — the first published negative RAG
    result in malware analysis; §1.5.3 is the second, by a different mechanism.
14. Metz, Spolaôr, Cherman, Monard. *Comparing published multi-label classifier performance
    measures to the ones obtained by a simple multi-label baseline classifier.* arXiv:1503.06952.
    — the label-only baseline our §1.5.3 frequency prior instantiates; finds published results
    routinely failing to beat it.
15. Lange, Adel, et al. *AnnoCTR: A Dataset for Detecting and Linking Entities, Tactics, and
    Techniques in Cyber Threat Reports.* LREC-COLING 2024. arXiv:2404.07765. CC-BY-SA 4.0. —
    the independent corpus on which §1.5.1's rank-vs-gate ordering replicates.

**Datasets used** (URLs accessed 2026-06-08; the full nine-source survey with per-source
verdicts is the §4 `SURVEY` table above):

- **MalwareBazaar** (abuse.ch). <https://bazaar.abuse.ch> · API `https://mb-api.abuse.ch/api/v1/`.
  — primary drift corpus: the 210 dated, family-labelled Windows-PE samples (30/cohort ×
  2020–2026) actually analysed end-to-end by the pipeline (§4 Item 5). Samples handled only in
  the Defender-excluded `data/samples/`, never committed.
- **MABEL — Malware Analysis Benchmark for AI/ML** (vx-underground-attributed, features-only).
  <https://github.com/action-ai-institute/MABEL-dataset>. — condensed v2.10 feature CSVs
  (82,171 rows, 475 families); mined offline into the disjoint U3 family-fingerprint catalog
  (`data/family_fingerprints_mabel_v1.json`) and the U2 ATT&CK case corpus
  (`data/attck_case_corpus_v1.json`) via the per-sample capa→ATT&CK ids. No binaries downloaded.
- **Ultimate-RAT-Collection** (Cryakl). <https://github.com/Cryakl/Ultimate-RAT-Collection>.
  — raw RAT builder/payload binaries (`.7z`, pw "infected"); the perfect-parity U3 catalog
  (`data/family_fingerprints_rat_v1.json`, 278 families) and the leakage-free retrieval eval's
  held-out a0/a1 split. Live binaries handled only in `data/samples/`, never committed.
- **DikeDataset** (iosifache). <https://github.com/iosifache/DikeDataset>. — raw sha256-named
  Windows-PE binaries; downloaded and assessed but **not catalogued** (labels are coarse
  malice/category scores, no family/ATT&CK), kept only as a disjoint raw eval corpus.
- **MITRE ATT&CK** (Enterprise). <https://attack.mitre.org> — family→technique `uses`
  relationships are the per-sample TTP ground truth (`tests/evaluation/ground_truth/`).

**Stack:** Ghidra MCP (bethington/ghidra-mcp v5.6.0); ik_llama.cpp `llama-server`;
Qwen3.6-35B-A3B (MoE) IQ3_K_R4; Qdrant; MITRE ATT&CK.

---

## Changelog (append new sessions here)

- **2026-08-09 — B2: the confidence number the cascade runs on is nearly a constant (queue item
  B2).** New **§3.8**. 210 scored claims, 4 excluded and counted.
  - **AUC 0.550** against a 0.500 chance baseline — Kumaran's finding replicates in a setting his
    suite did not cover (structured, evidence-cited claims).
  - **Stronger than "miscalibrated": nearly degenerate.** All 210 claims fall in **one** reliability
    bin, [0.8, 1.0); on the `dynamic` channel every claim is **exactly 1.000**, so its AUC of 0.500
    is arithmetic, not discrimination. A miscalibrated score can be recalibrated; a constant cannot.
  - **`network` is below chance** — AUC 0.428, separation −0.022: slightly *more* confident when
    wrong. Small at n=70, but it kills the charitable reading.
  - **Overconfidence +0.613** (0.984 stated vs 0.371 observed), worst where accuracy is worst
    (network +0.798). Corroborates `arXiv:2503.23175` and extends it to per-claim output.
  - **Instrument check first.** Both ISR parse paths default confidence to **0.5**, so a silent
    model would have made this a study of our own parser returning a perfect constant. Every claim
    landed in [0.8, 1.0) and the 0.5 default **never fired**, so the values are the model's own.
    Recorded because the result would be worthless without it.
  - **Consequence for C3.** A falsification-graded confidence cap keyed to a number that is 0.98
    for everything is a cap that almost never binds. **B5 now tests whether the cap does anything
    given that its input does not** — a sharper question than the one it was queued for.
  - Not yet counter-searched; by the A4 rule it is not an `OURS` candidate until someone tries to
    falsify it from an adjacent field.

- **2026-08-09 — B1 ran, and the multi-agent defence did not survive it (queue item B1).** New
  **§3.7**. Pre-registered, three arms, equal token budget, n=25 each, design taken from Bertalanič
  & Fortuna including their stochastic noise control.
  - **`negotiated` − `single`: −0.016 F1, CI [−0.084, +0.050], sign test 10–11.** No separation, at
    **3.2× the output tokens** (1039 vs 325) — inside the 2.1–3.4× range that literature reports.
    **The heterogeneous-evidence-channel exception did not rescue the design.**
  - **`negotiated` − `noise`: +0.061 F1, CI excludes 0.** The mediator *reconciles* rather than
    averages; the mechanism is real, it is just not worth 3.2× the tokens against a single agent
    with the same evidence.
  - The arms fail *differently*: decomposition buys recall (0.432 vs 0.416) and pays precision
    (0.370 vs 0.413), the same trade §3.6 found by another route. An F1-only reading hides it.
  - **Bounding limit, stated before anyone asks:** the harness runs **one** mediator pass, while
    production negotiation is **multi-round with revision and dissent**. This tests
    decompose-then-reconcile, **not** iterated negotiation, and must not be written as refuting the
    latter. Also: channels are clean, and `arXiv:2604.02460`'s crossover favours single agents
    exactly there — degrading the channels is the direct follow-up.

  **F1 (the system paper) was gated on this returning positive.** It did not, so D3 resolves toward
  **F3**. That is not a consolation prize: a pre-registered test of our own architecture's central
  claim, run to the literature's design and reported against us, is the strongest single item the
  measurement framing has.

- **2026-08-09 — an eval harness's safety cap was inert, and only a visible hang exposed it.**
  While running B1 the batch sat **14+ minutes on a single call with zero skips**, under a harness
  that set `agent.llm.request_timeout = 180`. Zero skips is the tell: a real 180 s cap would have
  fired and moved on.

  **Root cause.** `ChatOpenAI` constructs its HTTP client **at init** from `request_timeout`, and
  this project's provider sets **1800 s** there (`llm/openai_provider.py`, sized for the static
  ReAct budget). Assigning the attribute afterwards does not rebuild that client, so the eval cap
  never applied and every call ran under a half-hour ceiling. The fix is to bind the timeout as a
  **per-request kwarg** — `bind(timeout=120)` — which the OpenAI SDK honours per call.

  **`eval_view_decomposition.py` carried the identical bug, and it produced §3.6.** Its comment
  claimed the cap made a stuck decode "fail fast". It did not. **The §3.6 numbers stand**: the
  timeout was a convenience for aborting bad decodes, not a measurement parameter, and whatever
  ceiling was really in force applied identically to every arm. What was wrong was the comment,
  and it has been corrected in place rather than quietly deleted.

  **Why this belongs in the paper and not just in a commit.** It is a clean instance of §3.4/N1's
  thesis — *the instrument was not what the code said it was* — found in our own tooling, and it
  is the second such instance this week after the `stix2-validator` near-miss, where a wheel
  shipped without its schemas and called a textbook-valid bundle invalid. Both were caught only
  because something was checked that did not have to be: there, a known-good bundle; here, the
  absence of skips. The transferable rule is narrow and cheap: **an eval harness's safety limits
  need a test that proves they fire**, because a limit that silently does nothing looks exactly
  like a limit that was never needed.

- **2026-08-09 — the "YARA corpus" is not YARA, and that matters more than its licence
  (queue item D2).** E.6 was blocked pending a licence review of "the 30 YARA rules that carry the
  highest cascade weight (0.90)". Both halves of that sentence needed checking, and only one
  survived.

  **Licence: clear, and E.6 unblocks.** `data/yara_ttp_rules.yaml` is 30 **in-house** rules. Each
  is a list of literal substrings — Windows API names (`VirtualAllocEx`, `NtUnmapViewOfSection`),
  documented registry paths (`HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run`),
  and short strings — mapped to an ATT&CK id with a confidence. No third-party rule corpus is
  vendored: the `.yar` files in the tree belong to **CAPEv2**, not to us. Publicly documented
  nomenclature is not third-party creative expression, so the corpus can be **published verbatim**
  in the reproducibility appendix (E5).

  **But they are not YARA rules, and the paper must not call them that.** There is no YARA syntax,
  no condition language, no modules; `YaraLayer` matches **case-insensitive literal substrings**.
  Three reasons this is a real problem rather than a quibble:
  1. **It overstates the mechanism.** In a security venue "YARA rule" names a specific engine and
     rule language. A reviewer who reads "30 YARA rules" and finds a substring matcher has found
     us describing our own system inaccurately — the cheapest possible way to lose credibility.
  2. **The naming is already load-bearing in an argument.** The cascade gives the `yara` domain the
     **highest weight, 0.90**, which reads as *a YARA engine matched* when it means *a string
     appeared*. §1.10's finding that `tool_artifact` shares yara's cascade domain is stated in that
     same vocabulary.
  3. **The codebase uses real YARA elsewhere.** `reporting/detection_signatures.py` calls
     `yara.compile()` — to **validate rules Maljan generates as output**. One word would be doing
     two jobs in the same paper.

  **Action for the write-up:** call it a **deterministic literal-pattern layer**, state plainly that
  the 0.90 weight attaches to a curated substring matcher over static strings, and describe real
  YARA separately as an *output* validation step. No code change is implied — renaming
  `yara_layer` and the cascade domain would touch the layer names §1.10 already published under,
  which is a worse trade than being precise in prose.

- **2026-08-09 — the counter-search cost us three of five `OURS` rows (queue item A4).** The
  novelty ledger's own closing item said every `OURS` is *a searched absence, not a proof*, and
  asked for one hostile search each from a different angle. Done, deliberately in the **adjacent
  field's vocabulary** rather than in security's. **Three of five did not survive.**

  | row | adjacent field | outcome |
  |---|---|---|
  | **C5a** rank and gate are separate axes | IR score calibration | **→ `REFINEMENT`** |
  | **N4** auto-correction is net-negative | grammatical error correction | **→ `REFINEMENT`** |
  | **N7** degenerate ID loop | neural text degeneration | **→ `REFINEMENT`** |
  | **C8** hint → completion, not accuracy | inference latency / prompt compression | **held** |
  | **E1** 7-year drift, no measurable drift | temporal generalization of LMs | **held, reframed** |

  - **C5a.** `arXiv:2604.03676` (*Are LLM-Based Retrievers Worth Their Cost?*, Abdallah et al.) —
    **abstract fetched and confirmed** — evaluates **confidence via AUROC for predicting query
    success** as a dimension explicitly distinct from retrieval effectiveness, reports that
    *"confidence calibration is consistently weak across model families"*, and concludes raw scores
    are *"unreliable for downstream routing without additional calibration"*. The separate-axes
    framing is theirs, stated more generally and over more retrievers than we test. What may remain
    ours is the **inversion** we measure — the *lexical* backend gates better while the *semantic*
    one ranks better — which I found neither asserted nor excluded elsewhere. A search result
    claiming BM25 was the best-calibrated retriever at AUROC@10 = 0.602 could **not** be verified
    against the abstract and is **not** recorded as a finding.
  - **N4.** Over-correction is a named, long-studied failure in GEC, and that field evaluates with
    **F0.5 precisely because a false correction costs more than a missed one** — the same asymmetry
    our 38%-damaged / 21%-recovered result rediscovers. What survives is the mechanism: correct-
    but-weak and wrong-but-valid IDs are **not separable by an alignment score**, so the valid→valid
    swap cannot be tuned safely at any error rate; plus the provably-zero-regression restriction.
  - **N7.** See §3.3, corrected in place.
  - **C8 held.** The latency literature (e.g. `arXiv:2604.02985`, *Prompt Compression in the Wild*)
    asks **how fast**; §1.7.1 asks **whether anything was produced before the deadline at all**.
  - **E1 held but must be reframed, and this is the substantive part.** There is a large temporal
    literature — Lazaridou et al. *Mind the Gap* (NeurIPS'21), TemporalWiki (`2204.14211`), TARDIS
    (`2503.18693`), a 2025 survey of temporal drift in LLMs — and its finding is *degradation*. But
    it varies the **gap between training time and test time**. Ours holds the model **fixed** and
    varies **the era of the input binary**: a different axis, closer to concept drift in malware
    detection than to temporal misalignment. The paper may **no longer say temporal effects in LLMs
    are unstudied**; it must cite this work and name the axis. The field's prior of degradation
    makes our null *more* interesting, provided the distinction is stated plainly.

  **Consequence for the paper, and it is not small.** Part F recommended the F2 remnant — C5a + N4
  + N7 — as the sharpest chapter. All three demoted in one pass. None was refuted and each keeps a
  real mechanism, so the chapter survives as *confirm-in-a-new-domain-and-add-the-mechanism*; what
  it can no longer be is a headline. The framing decision (D3) is now genuinely binary and hangs on
  B1. **Ledger: 5 `OURS` → 2.**

  **Evidence standard, stated because it varies by row.** Only `2604.03676` was confirmed by
  fetching. The GEC and degeneration rows rest on search results naming real, checkable papers and
  are recorded as **demotions pending full-text confirmation** — demotion is the conservative
  direction, so acting now is safe, but each must be read before it is cited. Same rule the
  2026-08-08 citation audit imposed after a search summary fabricated an AISI claim.

- **2026-08-09 — P9: the model is pinned; the engine commit is gone (queue item A2).** New
  **§2.0**. The model half closed cleanly — GGUF sha256 computed here *and* matching the
  HuggingFace download etag, HF revision hash, retrieval timestamp, quantiser, base model,
  file_type, and the **named imatrix calibration dataset**, which is more than the quant level
  most papers report. Three things came out of it that are not bookkeeping:
  - **The engine commit is `eb570eb96689c235933b813693ca28ab9d3d26de`** — but the running binary
    cannot say so. `llama-server --version` → `version: 0 (unknown)`; `build-info.cpp` →
    `LLAMA_COMMIT = "unknown"`, because the build tree at `~/maljan-llm-build` has a `.gitignore`
    and a `.gitmodules` but **no `.git`**, so CMake had nothing to record.

    **Correction, same day.** My first pass concluded the commit was *unrecoverable* and pinned
    the engine by hashes alone. That was wrong, and wrong in an avoidable way: I searched the
    build tree and stopped, without checking whether the sources existed anywhere else. They do —
    `external/ik_llama.cpp`, a depth-1 clone vendored in this repository. It surfaced by accident,
    from a pytest collection error while running the suite for A3.

    The correspondence is proved, not assumed: identical file lists of **837 sources**, and
    comparing them file by file with CR stripped, **exactly one differs — `common/build-info.cpp`**,
    the generated file itself. Also retracted: the "upstream anchor at PR #630" from the vendored
    `github-data` directory. The commit references **PR #1778**, so that directory is a stale
    artifact and was never a version anchor.

    The lesson survives in a narrower form. Recovery needed a second copy of the sources to exist
    by luck plus a byte-level proof. **Build provenance must be captured at build time**;
    reconstructing it worked here and is not a method to rely on.
  - **The GGUF confirms the hybrid recurrent architecture from the file itself.** `ssm.*` keys plus
    `full_attention_interval=4` over 40 blocks, 256 experts / 8 active. The 2026-08-07 re-prefill
    timeouts were previously an inference from behaviour; the mechanism is now read off the model.
  - **We serve at half the model's native context** — `context_length = 262144`, we run
    `-c 131072` (§2.1 records why). Every truncation bound in the system therefore sits under a
    window that is itself a deliberate halving. A3 counts how often it binds.

  Also found, and it is a genuine reproducibility defect: `.serena/memories/suggested_commands.md`
  documents `--n-cpu-moe 36`, while the service runs an `-ot` regex matching blocks **10–39** —
  **30** blocks, not 36. Every §2 number came from the service, so the numbers stand and the
  documentation is what is wrong. Fixing it is E5's job.

- **2026-08-09 — P8: four claims scoped to what actually produced them (queue item A1).** The
  self-audit found four entries phrased more generally than one model on one machine supports.
  Each now carries a **Scope of the claim** bullet naming the evaluated model, and
  `related-work.md` gained a section-level scope statement. Two of the four turned out to be
  about something other than the model, which is the part worth keeping:
  - **§3.3** — the *sampler* finding (`repeat_penalty` honored, three siblings silently ignored)
    is a property of the **ik_llama.cpp engine at the pinned commit**, not of Qwen and not of
    small models. It says nothing about llama.cpp upstream, vLLM or a hosted endpoint. The
    phrase "a small-model pathology" is retracted; the pathology is measured on one model.
  - **§1.5.2** — **this audit's own first pass was wrong about this row.** It recorded the limit
    as "one index and one model's outputs"; the harness is **server-free** and the three error
    modes are **injected at 100%, rate-free**. The binding limits are the retrieval index (whose
    gate §1.5.1 shows varies by +0.062 to +0.168 across backends) and a stated dominance
    assumption — not the model. Mis-stating it would have attached a caveat to the one result
    that does not need one while leaving the limit that actually binds unwritten.
  - **§3.5** — "structural compliance 0.73 vs 0.00" is a **format proxy** (length, paragraph
    count, parenthesised IDs), *not* readability. The template scoring 0.000 means it ignores a
    format rule, not that its prose is unreadable. Whether readable prose is the LLM's real edge
    is E.7, and no human analyst has scored a report.
  - **§1.7.1** — already correctly caveated; only the exact identifier was missing. Its
    *negative* half (no mapping benefit, CI includes 0) travels further than its *positive* half
    (6/17 → 1/17 completion), which is bounded by this model's ~40 tok/s against a 600 s ceiling
    and is expected to shrink under the C6 frontier arm.

  P8 moves `EXPOSED` → `PARTIAL`: the write-up half is closed, the architecture/model confound
  is not and cannot be closed by writing. That is C6.

- **2026-08-08 (overnight) — systematic literature review across 8 themes, and the first
  measurement of the cascade.** Ran the full review myself with live search and **fetched every
  citation** rather than recalling it, after discovering the briefs sent to the external models
  were the truncated version (no novelty-adversarial instruction, no output format). Results are
  in `research-briefs/incoming/R{2..8}.claude-web.md`, audited in `CITATION-AUDIT.claude-web.md`,
  and reduced to per-claim verdicts in `research-briefs/novelty-ledger.md`:
  **5 `OURS` · 6 `REFINEMENT` · 4 `PRIOR ART` · 4 `UNMEASURED`.**
  **Two framing candidates fell to prior art in one night** — describe-then-map is
  Infer-Retrieve-Rank [6] (Jan 2024) in general form (§1.5 corrected), and binary→ATT&CK is
  TTPDetect [8] at 93.25% function-level precision. §1.5.1's conclusion is a **mechanistic
  refinement** of the Büchel SoK [5], not a discovery. §3.4 sits inside the tradition Chasing
  Shadows [9] names. Confidentiality-as-constraint belongs to REx86 [12]. A published negative
  RAG result in malware analysis already exists [13], so §1.5.3 is the second.
  **What survives as ours:** the rank-vs-gate metric (§1.5.1), the auto-correction regression
  (§1.5.2), the degenerate-ID loop (§3.3), the completion-under-budget effect (§1.7.1), and the
  n=210 drift study — all measurement results, none architectural.
  **New §1.10:** the first measurement of the cascade. Over 209 real PEs, `tool_artifact` fires
  on 2.4% and emits 5 techniques total while sharing yara's domain; 87.9% of techniques are
  single-source; and across five weight perturbations the top-10 ranking moves on 10.6–27.5% of
  samples while **the corroborated set moves on 0.0%** — structural, because `is_corroborated`
  never consults the weights. Also recorded: the cascade is an ad-hoc instance of Dempster–Shafer
  fusion, which makes its unmeasured constants harder to defend.
  **Method note:** four of the decisive papers were found only by searching an *adjacent* field's
  vocabulary. That is now a standing rule for the remaining work. 2238 unit tests pass (+20);
  ruff/mypy clean; no LLM or sandbox was started.

- **2026-08-08 §1.5.3 — the ATT&CK case-prior RAG is NEGATIVE, and the reason is the query, not the
  retriever.** Measured the U2 case-prior RAG in isolation for the first time (the only prior evidence,
  the n=19 U3 A/B, confounded it with the family RAG). Built
  `tests/evaluation/eval_attck_case_rag.py` around the control the skewed corpus demands — a
  **label-frequency prior at equal budget** (T1129 is in 71% of the 1,733 cases; 77 distinct techniques
  total), with random selection as a floor. **Result:** with a corpus-native query the retriever is
  genuinely good (F1 **0.620** vs prior 0.424 vs random 0.078, hit@1 0.90, near-duplicates suppressed);
  with the query production actually sends (`build_sample_profile_text`, 15 labelled samples) it is
  F1 **0.111 vs the prior's 0.123** — no better than ignoring the sample. Cause is a vocabulary
  mismatch, not tuning: capa sentences + lowercase APIs in the corpus vs import-category counts +
  CamelCase in the query, so **all 15 queries score 0.78–0.90 regardless of content** and
  `attck_case_rag_min_score` filters nothing. A vocabulary-matched query variant did not close the gap
  (F1 0.090). **Retracted** the U2 entry's "retrieves T1055 at 0.90" verification — 0.90 is the score
  of everything here. **Also found** that 742/1,733 cases share a byte-identical `summary_text`, so
  naive leave-one-out (F1 0.697) hands 43% of queries their own twin; the deduplicated figure is the
  reported one. `use_attck_case_rag` stays **off — now on evidence**, and `config.py` records why,
  including why `family_fingerprint_catalog_path` points at the 21-family bootstrap rather than the
  278/318-family catalogs beside it (the A/B that found no gain ran on the big one). 2227 unit tests
  pass (+17: the harness's own scoring arithmetic is tested, because it decides a shipped default);
  ruff/mypy clean.

- **2026-07-13 Depth-restore E2E validation — CORE CONFIRMED (6.3× deeper, zero re-prefill, zero
  timeout); multi-chunk + revision-round E2E still UNVERIFIED (a healthy run was killed on a
  misdiagnosed clock offset).** Ran the full pipeline in the worker on sample `11e77149` (CAPE-off for
  speed) with the restored deep config (max_steps=40, chars=6000, timeout=1500, sequential). **Result
  vs the same sample under the old cap=8:** static did **19 tool calls → 7 claims** (was 3 tool calls),
  **6.4 s/step** (re-prefill would be 50–90 s → confirms zero re-prefill), 120.9 s < 1500 s (no
  timeout); full run 761 s → verdict=Malware, report 7615 chars + 4 Composer sections + 1 detection
  rule. **Honest nuances:** (1) the small local model keeps tool-calling to the cap rather than
  self-terminating, so the forced-synthesis salvage STILL fires (now on 19-call deep evidence, not
  3-call shallow) — the config.py "concludes naturally ~30–36 steps" prediction did NOT hold on this
  tiny sample; the salvage is the conclusion mechanism, and raising the cap further just adds tool
  calls + salvage time. (2) The **multi-chunk multiplier and the revision-round re-prefill check
  remain E2E-UNVERIFIED**: a first run on a 3.8 MB 2-chunk PE (CAPE-on) was **killed by mistake** — the
  worker container's clock runs 3 h behind the host, and that offset was misread as a "3-hour hang" (the
  run was ~1 min into Ghidra `load_program`, healthy). Lesson: verify container/host clock skew before
  diagnosing a stall. The revision-node serialisation is still covered by the deterministic
  `asyncio.gather`-spy unit test; a real multi-chunk + dissent E2E is the remaining confirmation.

- **2026-07-13 The sequential-analyst fix was INCOMPLETE (revision node still ran concurrent), and
  the "SWA" depth band-aids were obsolete — completed the fix, then restored full static-analysis
  depth. `IMPLEMENTED` (config + guard tests green); the depth *benefit* is `PENDING` a multi-chunk
  E2E.** Two coupled findings, building on the same-day misdiagnosis correction below.
  **(1) The prior `parallel_analysts=False` fix only covered the INITIAL fan-out.** It serialised the
  analyst nodes via the LangGraph edges (`pipeline/builder.py`), but the **revision node**
  (`pipeline/nodes.make_revision_node`) fanned out *internally* through an unconditional
  `asyncio.gather` over all analysts, gated on nothing. So every negotiation **revision round**
  re-introduced the single-slot recurrent-state clobbering → full re-prefill — *the exact phase the
  41-min runs blew `request_timeout=900s` on*. The 743 s validation run (previous entry) converged
  before a real revision round (small 1-chunk sample, degraded-mode consensus), so the gap never
  surfaced. **Fixed** by gating the revision fan-out on `parallel_analysts` (a sequential `await`
  loop when False; the concurrent gather only for hosted multi-slot APIs), and **flipping the
  config.py DEFAULT `True→False`** so a run without a local `.env` (CI, fresh clone) is safe by
  default — otherwise it would pair parallel with the restored deep budget = uncapped re-prefill.
  Pinned with a deterministic `asyncio.gather`-spy regression test (`test_analyst_parallelism.py`).
  **(2) With the topology now guaranteed-sequential in BOTH phases, the 2026-07-11 "SWA" depth caps
  are obsolete** — they blamed the same misdiagnosed cause and were suppressing analysis depth for no
  benefit. Diagnostic: even a 1-chunk sample hit the `forcing synthesis` salvage (static ReAct 28.9 s
  for only 3 tool calls, then a **47.8 s** salvage LLM call = **62 %** of static wall-time wasted on
  cap-hit recovery, not analysis). **Restored, as config.py defaults** (`.env` sets none of these
  keys), as a *coupled set* because the per-chunk wall-clock — not the step count — is the binding
  constraint (at ~15–20 s/step, a 300 s cap fits only ~15–20 steps, so raising `max_steps` alone is
  inert): `react_agent_max_steps_overrides[static]` **8→40** (original designed depth; a hint-directed
  chunk concludes naturally ~30–36 steps, so 40 avoids salvage on an incomplete decompilation),
  `max_tool_output_chars` **3000→6000** (NOT 8000 — no in-loop pruning, and 8000 risks crossing
  `n_ctx=131072` → a silent server context-shift that drops the earliest tokens / `load_program`
  framing; 6000 keeps worst-case peak ~90–95 k), `react_agent_timeout_overrides[static]` **300→1500**
  (hard cap `timeout+30`=1530 s). Raised the never-fires safety-net ceilings so a deeper-but-
  *progressing* run is never killed ("a timeout is a bug"): `request_timeout` **900→1800** (≥ the
  1530 s hard cap, per the provider's must-exceed-longest-agent-budget invariant), and `job_timeout`
  **3600→28800 (8 h)** — static runs one ReAct loop **per chunk** (~8–10 chunks for a real PE), so a
  realistic-slow cold-cache run is ~2–4 h and the outer ARQ ceiling must exceed the sum of the inner
  nets. Rewrote the three now-false SWA comment blocks to the real cause. Side effect: **fixed two
  previously-red tests** that already expected `static==40` (`test_agents.py`) — the 2026-07-11 cut
  lowered the config without updating them. **Honest status:** the config + topology change is
  verified (guard tests green, 0 new failures; 8 *pre-existing, unrelated* suite failures confirmed by
  stash — stale chunker default, 6 view-decomposition, 1 YARA-gate); the **depth quality win is not
  yet measured** — the 743 s run was 1-chunk. Acceptance gate: a real PE that splits into ≥8 chunks
  AND produces dissent (≥1 revision round), confirming zero re-prefill in *both* phases, no chunk
  hitting its 1530 s cap, salvage absent on rich chunks, peak context <~120 k, and a quality delta
  (more decompiled functions / grounded techniques) vs the `max_steps=8` baseline. Best-quality runs
  now take ~2–4 h/sample by design (time cost explicitly accepted).

- **2026-07-13 The "SWA re-prefill bottleneck" was a MISDIAGNOSIS — the real cause is a hybrid
  Gated-DeltaNet recurrent model + parallel analysts thrashing a single llama-server slot. Fixed by a
  one-flag config change; 41 min → 12 min, zero timeouts.** A CAPE-on live run timed out the revision
  round at `request_timeout=900s`; runs took ~41 min. Prior notes (and the config.py comments) blamed a
  *sliding-window-attention (SWA)* re-prefill on ik_llama. **Deep web research + the model metadata
  disproved this:** (1) the served **Qwen3.6-35B-A3B is a HYBRID Gated-DeltaNet (linear/recurrent) +
  GQA-attention MoE** (Qwen3-Next family) — NOT an SWA model (`/props` shows no sliding window;
  `n_ctx_train=262144`); (2) llama.cpp / ik_llama cannot restore the **recurrent context checkpoint**
  for hybrid models (open bugs **ggml-org/llama.cpp#20225, #22384, #24055** and **ik_llama#1762**), so
  the server does a **full prompt re-processing on every conversation turn** (measured upstream:
  `prompt eval 195154 ms / 66293 tokens` ≈ 3 min/turn). The trigger in Maljan was
  **`LLM__PARALLEL_ANALYSTS=true`**: on a single slot the three analysts interleave and each clobbers
  the others' per-slot DeltaNet recurrent state → every ReAct step re-prefills from scratch → the
  revision round (large peer context) blows 900s. **Why not the "obvious" fixes:** `--swa-full` is
  irrelevant (not SWA) and unsupported by ik_llama; `-np` multi-slot is *actively harmful* here
  (DeltaNet mixed-batch decode collapses to ~0.59 t/s) and the exact model has an **unresolved decode
  hang after cache-invalidation (#22450, closed "not planned")**, so hand-patching ik_llama's
  checkpoint code (untestable Windows-CUDA rebuild + hang risk) was rejected as higher-risk. **The fix
  is the already-implemented sequential topology** (`pipeline/builder.py`, `parallel_analysts=False`):
  each analyst gets exclusive slot use, so its recurrent state survives across its own ReAct steps →
  only new tokens are processed. **Measured on `11e77149` + CAPE:** parallel **2480.5 s** (revision
  timed out, `verdict=Malware conf=0.61`) → sequential **743.4 s** (**3.3×**, zero `Request timed out`,
  zero `forcing full prompt re-processing`; static/dynamic/network ReAct = 28.9/52.6/30.8 s; full
  report incl. Composer 4 sections + 4 figures + 11 IOCs + 3 rules; `conf=0.0` this run is the honest
  degraded-mode cap from CAPE flagging `antivm_generic_system`, not a regression — CAPE anti-VM
  detection varies run-to-run). Permanent fix: `parallel_analysts=False` in `.env` + documented in
  `.env.example` and the `config.py` field comment. Deeper cure if ever needed (not required now):
  serve a pure full-attention model (e.g. Qwen3-30B-A3B original) where prompt-cache reuse is native.
  Corrects the `[[swa-react-reprefill-bottleneck]]` memory note.

- **2026-07-12 Static-analyst performance, before vs after the July fixes (tool-manifest sizing +
  hallucinated `load_program` path).** Two consecutive root causes limited the static analyst on
  live runs, and both were measured on the SAME 36 KB MSVC6/MFC PE (`11e77149…`, WS2_32 client →
  `888kafa.com`) with the same local Qwen3.6-35B backend, giving a clean controlled comparison.

  **(a) Tool-manifest sizing (commit acb4dbb).** Exposing all 165 Ghidra MCP tools
  (`USE_ALL_TOOLS=true`, job `294eefc3`) was measured strictly WORSE than the curated 20-tool
  allowlist: the ~15–25k-token manifest is re-prefilled every ReAct step on the SWA model, so the
  pipeline went from ~255–330 s to **1 580 s (26 min, ~5–6×)**, the analyst managed only 3 tool
  calls in 67.5 s before forced synthesis, and hallucination went UP (T1027@0.85 + a **fabricated
  T1055** with no injection API in the sample + T1140@0.70). Fix: dynamic tool-RAG selection
  (`ghidra_tool_selector.py`, mode `dynamic`) — CORE triage set ∪ category-matched tools derived
  deterministically from the PE import classification; all 165 stay reachable, ~23–40 are shown.
  Measured: **23/165 tools selected** for categories `{anti_debug, execution, network}`, pipeline
  back to **162.8 s** — curated-level speed at much wider tool reach. A deterministic confidence
  cap (`capability_matrix._cap_unsupported_confidence`) was added in the same commit because the
  prompt-only constraint did NOT stop the 35B model from claiming T1027@0.85: with no obfuscation
  evidence (all sections < 7.0 entropy, no packer hint) T1027/T1140 are clamped to ≤0.40, and
  T1055 likewise unless a real injection import exists. Prompt-level guidance failing where a
  10-line deterministic post-hoc cap succeeds is itself a paper-relevant negative result.

  **(b) Hallucinated `load_program` path on fresh samples (commit fc85412).** The 162.8 s run
  above (job `60df48cb`) was fast but its LLM static layer was silently BROKEN end-to-end: for a
  freshly uploaded sample there is no `data/samples/static/<sha>.json` fixture and (with the CAPE
  VM down) no sandbox report, so the analyst's head chunk was the non-JSON file-loader placeholder
  "No static data available for sample <sha>" — and the Wave-6 path splice
  (`_augment_static_chunks_with_path`) only injected `analysis_file_path` into JSON chunks. The
  model, given no path, INVENTED `/home/user/data/bin.<sha>`; Ghidra correctly answered "File not
  found"; the report then carried two poisoned confidence-1.0 claims ("file was not found on the
  server filesystem", "no binary content was provided") even though the mirror to
  `/data/samples/<sha>.exe` had succeeded — the deterministic function-hash pre-pass loaded the
  very same file 90 s later in the same job. Evidence trail: worker log `Mirrored sample…`
  16:20:40; DB claim `evidence_ref` with the invented path; Ghidra log `Loaded program` 16:22:59.
  Diagnosis matters: this looked like (and was initially filed as) "Ghidra file-mirroring
  flakiness" — the infrastructure was innocent; the failure was a prompt-content gap. Fix, two
  defensive layers: (1) synthesize a real JSON head chunk for the placeholder case, carrying
  `analysis_file_path`/`host_sample_path`/`sha256` plus a size-capped deterministic PE summary
  (imports ≤60 suspicious-first, strings ≤40, 40k-char hard ceiling — the spliced chunk bypasses
  the chunker's token-budget re-check); (2) wrap `load_program` at the tool-selection choke point
  so a model-supplied `file` argument differing from the known container path is overridden
  deterministically (late-bound read, since agents are cached across samples).

  **Measured before/after on the same sample (fresh-sample regime, CAPE down):**

  | metric | all-165 (`294eefc3`) | dynamic, pre-fix (`60df48cb`) | dynamic, post-fix (`df8ebc1a`) |
  |---|---|---|---|
  | pipeline wall-clock | 1 580 s | 162.8 s | 225.9 s |
  | tool manifest shown | 165 | 23/165 | 23/165 |
  | static ReAct loop | 3 calls / 67.5 s | 3 calls / 12.4 s | 3 calls / 16.0 s (+29.6 s synthesis) |
  | sink-reachability pre-pass | — | **did not fire** (no path in chunk) | fired (991-char priority hint) |
  | LLM static claims | 3, all hallucinated (incl. fabricated T1055) | 2, both poisoned ("file not found", conf 1.0) | **5, all grounded** (real `FUN_00401310`, section entropy 5.39, `888kafa.com`) |
  | usable static evidence | none from LLM | deterministic import layer only (T1071@0.60) | LLM (T1071@0.95, anti-debug@0.8, T1036@0.85…) + import layer |
  | capability matrix | T1027@0.85, fake T1055@0.80 | T1071 only | T1071@0.95; **T1027 capped 0.40** (cap held); **no T1055** |
  | verdict / confidence | — (not recorded) | Malware / 0.667 (on thin evidence) | Malware / 0.613 (on broad evidence) |

  Post-fix wall-clock is ~63 s higher than pre-fix — that delta is REAL WORK the broken run never
  did (sink-reachability + function-hash pre-passes now fire before the loop, forced synthesis now
  has genuine tool output to compress, judge processes 5 claims instead of 2), not a regression.
  Overall confidence barely moved (0.667→0.613) while the evidence base under it transformed —
  another instance of the log's recurring theme that scalar confidence is a poor proxy for report
  quality. Verified: 12 new unit tests (placeholder-chunk synthesis + path pinning), full suite
  1396 passed / 8 known pre-existing failures, E2E on job `df8ebc1a`. Also fixed en route:
  `pe_extractor` now only flags "dynamic API resolution" as an obfuscation indicator when the
  import table is actually sparse (<15 imports), removing a chronic T1027 false-positive trigger
  for ordinary `LoadLibrary+GetProcAddress` idiom.

- **2026-06-23 Live-UI audit: degraded live reports were caused by THREE LLM-loop root causes
  (all fixed), not by the analysis logic.** A full live run of a Windows PE (Pony) under
  `SANDBOX__BACKEND=mock` completed but returned `degraded_mode=true`, `overall_confidence=0`,
  `category=unknown`, with the dynamic+network analysts in `failed_analysts`. Each layer was
  root-caused and fixed end-to-end, verified across 5 live runs (final: `verdict=Malware`,
  `confidence=0.873`, `category=dropper`, all five evidence layers contributing cross-corroborated
  claims incl. a real static T1027 unpacking-routine finding):
  1. **Qwen3 thinking mode.** With thinking ON, each analyst LLM call emitted a ~22k-token
     reasoning trace that never reached `content`, so the tool-less dynamic/network analysts
     timed out at their per-agent hard cap (600s/300s) and the static ReAct loop stalled. Probe:
     correct T1497 claim in 4.3s with `enable_thinking=false` vs 0-char content after 800 thinking
     tokens. Fix: `LLM__OPENAI__DISABLE_THINKING=true` (flag + provider wiring already existed,
     just off) — documented in `.env.example` + `run_llama.ps1`. Deployment/config setting
     (gitignored `.env`), not a code change.
  2. **`react_agent_max_steps=10` too low for the static analyst.** Its Ghidra ReAct loop was
     cut off after ~4 tool calls and LangGraph returned "Sorry, need more steps to process this
     request." instead of claims. The codebase already gave static a per-agent *timeout* override
     (1200s) but missed the parallel *step* cap. Fix: `react_agent_max_steps_overrides={static:40}`
     (commit 0ffdfd9).
  3. **The static ReAct loop did not self-terminate.** Even at 40 steps it kept tool-calling
     (19 calls → 41 messages → recursion limit) and discarded all gathered Ghidra evidence as the
     "need more steps" non-answer. Fix: a forced-synthesis fallback in `execute_tool_loop` — when a
     tool-using loop ends on that stop message (after ≥1 tool call), re-invoke the model once on
     the accumulated conversation with a directive to stop tool-calling and synthesise now, so the
     evidence becomes real claims (commit f261ef9). Best-effort; convergent loops untouched.
  Also fixed in the same audit: BUG-02 job-API sample sha256/filename (d9ba6ba), BUG-05
  mediation-error → judge routing (5419409), BUG-04/06/07 persistent agent event loop + static
  placeholder handling (e3a3685). Operator tooling: `d:\tmp\llama_watchdog.ps1` gained a third
  detector — an active inference probe for the "idle wedge" (`/health`=200, slot idle, yet
  `/v1/chat/completions` hangs) that detectors 1 (health) and 2 (busy-wedge) both miss and that
  silently stalled runs all day. 1422 unit tests green; ruff + mypy clean.

- **2026-06-22 LLM-in-the-loop A/B of the family-feature + ATT&CK-case RAGs → no measurable TTP gain
  (keep gated OFF).** The leakage-free *retrieval* eval (recall@5≈0.20, ~6.3× chance) showed the RAG
  carries real signal, but could not say whether feeding those advisory candidates to the static analyst
  improves the LLM's final TTP output. Ran a controlled A/B to answer it: the same 19-sample
  leakage-free subset (`tests/evaluation/ab_manifest.json` — families in the disjoint MABEL catalog
  AND with an ATT&CK fixture) analysed twice via `tests/evaluation/run_family_rag_ab.py`, OFF vs ON,
  both arms forced to `SANDBOX__BACKEND=mock` (static-only; no live-malware upload) and
  `NEGOTIATION__MAX_ITERATIONS=1` (the judge ReAct loop cannot converge in 180 s under the mock
  sandbox's empty dynamic/network inputs, which otherwise drives every sample to the 5-round ceiling).
  **Result (n=19 each, technique-level):** OFF F1=0.012 (P=0.132, R=0.006); ON F1=0.015 (P=0.123,
  R=0.008); **delta ON−OFF: F1 +0.003, P −0.009, R +0.002, hallucination 0.000 → 0.000.** The F1
  bump is within noise on a floor-level baseline (both arms ≈0.01); precision actually dips slightly;
  hallucination is unchanged (the "advisory only, do NOT assert on retrieval alone" framing held).
  **Verdict:** in this leakage-free static-only / 1-round regime the RAGs produce **no measurable
  end-to-end improvement** in TTP F1 — the modest retrieval signal does not convert into better LLM
  output. Both stay **gated OFF by default** (no code removed: harmless, fail-safe, and the retrieval
  layer retains measured value for future regimes — full dynamic+network evidence, multi-round
  negotiation, or a richer ground truth). Caveat: the absolute floor (~0.01 F1 for *both* arms) means
  the constrained regime left little headroom to demonstrate benefit; a non-mock, multi-round rerun
  could revisit this. Result vendored at `tests/evaluation/family_rag_ab.json`. Infra note: ik_llama
  `llama-server` wedged (GPU-idle, HTTP-unresponsive) every ~7–10 min under sustained load on the
  262k-ctx + `-ctv q8_0` config; dropping the quantized V-cache and lowering `-c` to 131072
  (`run_llama.ps1`) ran stably for the whole rerun. A `d:\tmp\llama_watchdog.ps1` auto-restart guard
  (restart only on health-fail AND GPU-idle, never mid-inference) covered the unattended run.

- **2026-06-08 Leakage-free retrieval measurement of the family-feature RAG.** With a DISJOINT catalog
  finally available, measured the RAG's retrieval quality with zero leakage via a held-out split of the
  Ultimate-RAT-Collection extraction tree: `a0` archives → TRAIN (family fingerprints), `a1` archives →
  TEST (query profiles). a0/a1 are different versions of the same family, so a test sample was never
  used to build the catalog yet its family is represented — the production scenario (attribute a NEW
  sample of a known family). New `tests/evaluation/eval_family_rag_retrieval.py` (reuses the runtime
  extractor + profile renderer + index → one embedding space). **Result (158 families, 629 test
  samples):** recall@1 = 0.083, recall@3 = 0.159, **recall@5 = 0.199**, MRR = 0.122, vs a random-chance
  recall@5 of 0.032 (1-in-158). **Interpretation:** retrieval is **~6.3× better than chance** → the
  static-feature fingerprint carries *real* family signal; but absolute recall is modest (~20% @5), so
  the RAG is NOT reliable enough to attribute alone — which is exactly why it is wired as *advisory*
  candidates with the **LLM as decider** (the LLM-centric design is validated, not contradicted, by this
  number). This supersedes the earlier anecdotal spot-checks ("Sliver 0.84") with an honest leakage-free
  distribution. Why modest: RAT versions diverge across a0/a1, many families share generic packed/loader
  profiles, and packed samples yield thin static profiles. Measures the retrieval layer only; a full
  LLM-in-the-loop A/B remains future work (≈days of local 35B compute). Result vendored at
  `tests/evaluation/family_rag_retrieval.json`. Live-malware scratch cleaned up afterward (~69 GB:
  rat-collection, dike, extracted, mabel-repo) — only derived text artifacts remain tracked.

- **2026-06-08 Live-malware datasets integrated (Ultimate-RAT-Collection + DikeDataset).** Downloaded
  both into the Defender-excluded, gitignored `data/samples/` (live malware — never committed; only the
  derived text catalogs are).
  **Ultimate-RAT-Collection (36 GB, 649 families, 2,159 `.7z` pw "infected"):** extracted 2 archives/family
  (935 archives, 0 failures → 640 family dirs, 7,111 PE). Key finding: each archive ships **both
  `Client.exe` (controller) AND `Server.exe` (the victim payload)** — so it is NOT purely builders, which
  softens the survey's "builders≠payloads" caveat (real payload PEs feed the fingerprints). Built
  `data/family_fingerprints_rat_v1.json` via `build_family_feature_kb.py --samples-dir` (the SAME
  `build_static_analysis` → `build_sample_profile_text` renderer the runtime query uses → **perfect
  embedding parity**, unlike MABEL's `--csv`): **278 family fingerprints** (families with ≥3 parseable
  PE32; ~360 families dropped — many old RAT builders are 16-bit NE files pefile can't parse), 139 KB.
  End-to-end verified — an injection+network profile retrieves NetBus/DRAT/Pest (~0.88), a keylogging
  profile retrieves GhostVoice/HavRat. This is the highest-quality family catalog yet: perfect parity
  **and** disjoint from the eval set **and** real payload binaries. Caveats: fingerprints mix
  controller+payload code; undated (no drift cohorts); only ATT&CK-resolvable families score for U1.
  **DikeDataset (5.8 GB, 10,841 malware + 1,082 benign sha256-named PE):** its `malware.csv` carries only
  soft malice/category SCORES; reduced to a dominant label (argmax) the 10,841 samples collapse to
  generic/trojan/worm — too coarse and non-discriminative for a useful catalog, so **none was built**
  (a 3-"category" catalog would be misleading in the family-RAG namespace). The real binaries are kept as
  a disjoint raw-eval / benign-FP corpus in `data/samples/dike/` (gitignored). Confirms the survey's
  "marginal" verdict. Net: of the 9 surveyed sources, the actionable integrations are MABEL (U2 + U3
  disjoint corpora) and Ultimate-RAT-Collection (U3 perfect-parity catalog); everything else is
  out-of-scope or non-integratable.

- **2026-06-08 MABEL integrated: real disjoint corpora for U2 + U3 (no live malware).** Downloaded the
  MABEL condensed v2.10 feature dataset (vx-underground-attributed, features-only — ~3.4 GB CSV, 82,171
  rows, 475 families, no binaries → safe). Key correction to the 2026-06-07 survey: the condensed release
  DOES carry per-sample **capa-derived ATT&CK ids** + import lists + capa/yara capabilities (the survey
  wrongly recorded "no ATT&CK mapping"). Extended both offline builders to mine it: `--mabel-csv` mode on
  `build_attck_case_kb.py` (U2) and multi-segment `--csv` on `build_family_feature_kb.py` (U3), both with
  `csv.field_size_limit` bumped for MABEL's large cells, and a `"-"` null-placeholder normaliser.
  Produced two vendored artifacts: **U2 `data/attck_case_corpus_v1.json`** (1,733 cases, 77 ATT&CK
  techniques, cap 6/family ~1.3 MB — the config default path, so U2 is now turnkey and the empty-LTM
  blocker is resolved) and
  **U3 `data/family_fingerprints_mabel_v1.json`** (318 disjoint families — addresses the n=210 leakage
  caveat; n=210 stays the parity-perfect default). Both verified end-to-end with fastembed BGE-384
  (injection profile → T1055 @0.90 for U2; XWorm/AveMaria/EchelonStealer for U3). 7 new builder unit
  tests (14 total in test_build_attck_case_kb). Caveats recorded: capa ATT&CK is static-tool inference
  (not authoritative GT); `--csv` summary vocabulary overlaps but is not perfect parity with the runtime
  static profile (advisory retrieval, LLM decides). Both features stay OFF by default. Out-of-scope
  sources confirmed skipped: Ultimate-RAT-Collection (26.6 GB live malware — pending scope/Defender
  decision), DikeDataset (coarse labels), EMBER (no family labels), MH-1M/SF23/APIMDS (Android/dynamic).
- **2026-06-07 U2 implemented: ATT&CK case-prior RAG (LLM-centric, mines our own LTM).** Built the §4
  U2 follow-up — the function-level RAG's missing *cross-sample* knowledge corpus — without importing
  an external dataset. New `memory/attck_case_index.py` (`AttckCaseIndex`: embeds prior cases'
  `summary_text` at load, `search` ranks behaviourally-similar neighbours, `recommend_techniques`
  aggregates their attributed `technique_ids` into ranked candidates) + `analysis/attck_case_rag.py`
  (`retrieve_techniques` / `build_attck_case_hint` / `to_report_dicts`). Wired into the static analyst
  (new `_compute_attck_case_hint`, prompt slot beside the family-RAG hint) and the judge node
  (→ `FamilyAttribution.attck_case_candidates`). Offline builder `scripts/build_attck_case_kb.py`
  scrolls the live Qdrant LTM (`--qdrant-url`) or reads a JSONL export (`--cases-jsonl`) into the
  vendored `data/attck_case_corpus_v1.json` (TEXT only; index embeds at load → parity, zero new deps).
  Config flags `use_attck_case_rag` (OFF) + `attck_case_corpus_path` + top_k/min_score/max_techniques.
  Mirrors the U3 family-feature RAG exactly; reuses U3's `build_sample_profile_text` query so both
  RAGs share one embedding vocabulary. Complements (does not duplicate) the judge's existing
  `_build_memory_context`: U2 surfaces *aggregated* ATT&CK candidates to the *analyst* at proposal time
  (the static-only precision target), vs raw cases to the *judge* at negotiation time. 22 new unit
  tests (index build/search/aggregate, hint/dicts/fail-safe). Verified: ruff clean, mypy clean
  (106 src files), full unit suite 1377 passed. Gated OFF; no live corpus vendored yet (operator builds
  it from a populated LTM). Honest caveat recorded: behavioural-corpus vs static-query vocabulary
  mismatch makes matching coarse — exactly why candidates are advisory and the LLM decides.
- **2026-06-07 U3 pivot: GBDT classifier -> LLM-centric Family-feature RAG.** Per the "everything
  LLM-centric" principle, removed the trained gradient-boosted family classifier (a second brain that
  decides outside the LLM + re-imports drift fragility): deleted `analysis/family_classifier.py`,
  `scripts/train_family_classifier.py`, its tests, and the GBDT config/reporting/judge wiring.
  Replaced with a Family-feature **RAG**: deterministic static-feature profile → embed → retrieve
  nearest **family fingerprints** from an offline KB → inject as CANDIDATE evidence → **the LLM
  decides**. New `analysis/family_feature_rag.py` + `memory/family_fingerprint_index.py` (reuse the
  fastembed BGE-384 embedder + the `semantic_attck_index`/`function_index` cosine pattern — zero new
  deps, no ember/lightgbm/joblib), offline builder `scripts/build_family_feature_kb.py` →
  `data/family_fingerprints_v1.json`, config `use_family_feature_rag` (OFF), report block
  `FamilyAttribution.family_rag_candidates`. 25 new unit tests; ruff + mypy clean; agents/pipeline/
  reporting/memory/analysis suites green (278). Stays drift-robust and LLM-centric; MABEL now used as a
  retrieval KB (not classifier training). `host_sample_path` plumbing + the analyst hint slot from the
  prior pass are reused unchanged. Then built a **bootstrap catalog** from the existing local n=210
  corpus (new `--manifest`/`--flat-dir` builder mode; 21 family fingerprints) and verified retrieval
  end-to-end — see the §4 RAG note for the packed-sample + leakage caveats. Also cleared all
  backgrounded lint debt repo-wide (Ghidra-headless `extract_cfg.py` F821/E501, `ghidra_manager.py`
  unused import, a dead constant): full repo ruff clean, mypy clean (104 files), unit suite 1355 green.
- **2026-06-07 Dataset-survey follow-through: U1 dir-ingest + U3 classifier scaffold (gated OFF).**
  Acted on the two viable integrations from the 9-source survey. **U1:** added a
  `--source dir` adapter to `collect_temporal_manifest.py` (walk a folder-per-family raw-binary
  tree, sha256 content-addressing, MZ/ELF magic-byte file-type sniff, per-family sampling, copy
  into `data/samples/`) emitting a single `undated` cohort; `eval_temporal_drift.drift_delta` now
  considers only 4-digit-year cohorts so the `undated` enrichment never pollutes the temporal
  delta. This lets a local RAT collection deepen per-family coverage (ATT&CK-resolvable families
  only) without faking drift cohorts. **U3:** new `src/maljan/analysis/family_classifier.py` — a
  deterministic static-feature family classifier mirroring `function_hash_attribution.py`
  (EMBER `PEFeatureExtractor` vectors -> offline GBDT -> top-k family prior), wired as an analyst
  prompt hint (`static_analyst._compute_family_classifier_hint`, fed the HOST binary path threaded
  via a new `host_sample_path` chunk field) and a judge-recorded `FamilyAttribution.classifier_matches`
  block. Offline trainer `scripts/train_family_classifier.py` (trains from the same EMBER extractor
  for feature parity; folder-per-family or pre-extracted MABEL/EMBER inputs). Gated OFF by default
  (`PreprocessingConfig.use_static_feature_classifier`); ember/lightgbm/joblib are OPTIONAL,
  operator-installed for training only — NOT added to the runtime manifest, and the module is
  lazy-import + fail-safe (no model / no deps -> no-op, byte-identical behaviour). 42 new unit tests;
  ruff + mypy clean; agents/pipeline/reporting suites green (116). Design notes: (a) the container
  `get_family_classifier()` getter from the plan was dropped — these deterministic pre-passes are
  driven from config + module functions (the analyst is container-unaware), matching the
  function-hash pattern; (b) the classifier is recorded as a sibling of `function_hash_matches`, not
  a grounding source for the top-level `malware_category` (different granularity: specific family vs
  category). NO model trained yet (operator step: download EMBER/MABEL or point at the RAT corpus).
- **2026-06-07 External malware-dataset survey (9 sources).** Assessed EMBER, MABEL,
  Ultimate-RAT-Collection, MH-1M (= Nature `s41597-025-06469-5` = Harvard Dataverse `LLHEGN` =
  GitHub), SF23-AMGenerator/AMExplorer, APIMDS, DikeDataset against four use-axes (U1 binary corpus,
  U2 RAG corpus, U3 classifier data, U4 ATT&CK ground truth). Result: 5/9 are one out-of-scope
  Android ecosystem (MH-1M + tools); only Ultimate-RAT-Collection + DikeDataset ship raw binaries
  (both undated, ATT&CK-resolvability-gated); MABEL+EMBER are the only U3 classifier data; **no
  source provides U2 (decompiled-code↔ATT&CK) or U4 (per-sample ATT&CK TTPs)**. Recorded the full
  survey table (with links) + U1–U4 mapping in §4. Two viable integrations identified: U1
  per-family-coverage enrichment and a U3 static-feature family classifier.
- **2026-06-07 Item 5 concept-drift FULL RUN (n=210, static-only Ghidra+LLM).** Ran the drift eval
  on the **complete** cohort — 30 samples/cohort × 7 years (2020–2026), all 210 MalwareBazaar
  binaries — on the local Qwen3.6-35B-A3B, static-only (`SANDBOX__BACKEND=mock` — no dynamic, no
  public-sandbox upload; `disable_thinking`, `NEGOTIATION__MAX_ITERATIONS=2`). Per-cohort F1 band
  0.055–0.089; **drift delta 2020→2026 = -0.004** (all CIs overlap → **no measurable concept
  drift**, confirming the n=42 pilot at 5× the samples with tighter CIs). Recall structurally low
  (0.037–0.063: static cannot see behavioural TTPs that dominate the family `uses` sets), precision
  modest (0.09–0.21), **hallucination ~0 in every cohort** (≤0.011). Multi-day batch with JSONL
  checkpoint resume + LLM-health gate (llama-server OOM-crashed ~hourly on large binaries; each
  restart auto-resumed without rescoring garbage). Replaced the n=42 numbers in §4 Item 5 with the
  full n=210 table + findings; report rendered to `D:\tmp\temporal_drift.md`.

- **2026-06-04 Item 5 concept-drift LIVE NUMBERS (n=42, static-only Ghidra+LLM).** Downloaded all
  210 MalwareBazaar binaries into `data/samples/` (AES zips via pyzipper; Defender exclusion
  verified with EICAR first) and ran the drift eval on 6 samples/cohort × 7 years (2020–2026) on
  the local Qwen3.6-35B-A3B, static-only (`SANDBOX__BACKEND=mock` — no dynamic, no public-sandbox
  upload). Per-cohort F1 ranges 0.007–0.115; **drift delta 2020→2026 = +0.019** (within heavily
  overlapping CIs → **no measurable concept drift**, the direction of MARD's robustness claim).
  Recall is structurally low (0.004–0.077: static cannot see behavioural TTPs that dominate the
  family `uses` sets), precision modest (0.04–0.25), **hallucination ~0 in every cohort** (grounding
  gates hold on real malware). Reading: the static-only arm is a clean upload-free baseline; the gap
  to ground truth quantifies what dynamic analysis must add. Fixed a load_program host-vs-container
  path bug (0 Ghidra tool calls until corrected). Flipped §4 Item 5 to `IMPLEMENTED` + `NUMBERS`.

- **2026-06-04 Ghidra+LLM static-only chain validation + 3 pipeline-robustness fixes.**
  Validated the full static path end-to-end on a known-benign PE (a `where.exe` copy — no
  malware, no public upload) against the live Ghidra MCP container (v5.6.0, 165 tools ->
  20 via allowlist) + local 35B llama-server. **Outcome: PASS** — static analyst engages
  Ghidra (load_program + 4 tool calls), the pipeline completes and returns scoreable output
  (5 ISR agents, 5 predicted ATT&CK techniques, final verdict + run summary). Three live
  failures were found and fixed before they could corrupt a batch eval: (1) the negotiation
  node only caught `(AnalystError, LLMError)`, so a bare `asyncio.TimeoutError` re-raised by
  `judge_agent.execute_tool_loop` — and a transient openai `APIConnectionError` under
  concurrent analyst load — **crashed the whole graph** (in a batch, silently dropping the
  sample); both `make_negotiation_node` and `make_judge_node` now isolate *any* mediation
  failure and degrade to "no consensus" / conservative verdict, carrying the populated ISRs
  forward (new `tests/unit/pipeline/test_negotiation_fault_isolation.py`, 5 cases). (2) New
  off-by-default `LLMConfig.openai.disable_thinking` flag forwards
  `chat_template_kwargs.enable_thinking=false` via extra_body for local reasoning models —
  **~10x speedup** observed (static ReAct 154.8s -> 16.5s) because the model no longer burns
  the decode budget inside `<think>`. **Static-only recipe** (Ghidra+LLM, no dynamic, no
  public upload): `SANDBOX__BACKEND=mock` (the `.env` default is `triage`, which *uploads to
  the public tria.ge sandbox* — confirmed live) + `LLM__OPENAI__DISABLE_THINKING=true`; for a
  large eval also `NEGOTIATION__MAX_ITERATIONS=2` (benign sample ran the full 5 rounds =
  ~688s; 210 samples at 5 rounds ~= 40h). Per Maljan OS scope, the path stays Windows/Linux.
  1330 unit tests green; ruff + mypy clean. Item 5 live numbers still await operator-supplied
  binaries + an admin Defender exclusion on `data/samples` (real malware is quarantined on
  write otherwise) — the collector warns it is for an isolated VM, not this workstation.

- **2026-06-04 narrative-quality live run (§3.5, MaLAware), n=15.** 5 fixtures × 3 repeats on
  Qwen3.6-35B-A3B (`enable_thinking=false`). Both LLM and deterministic-fallback narratives are
  perfectly faithful (grounding precision 1.0, 0 hallucinated techniques) — MaLAware's premise
  holds. But on faithfulness+coverage **F1 the deterministic template wins** (1.0 vs LLM 0.889;
  paired delta −0.111, CI [−0.252, −0.030], excludes 0): the template covers every evidence
  technique by construction (recall 1.0) while the LLM omits some (0.853). The LLM's only edge is
  **structural/readability compliance (0.73 vs 0.0)** — the LLM narrator is justified by readable
  prose, not accuracy. Recorded under §3.5 Status.
- **2026-06-04 live partial view-decomposition run + two methodology fixes (§3.6, Item 3).**
  Ran the equal-budget A/B on Qwen3.6-35B-A3B over 3 fixtures × 3 repeats (n≈8–9/arm, 34/60
  generations; full run capped by a 4-view concurrency stall). Result **corrects the n=1 smoke**:
  at equal budget, decomposition trades grounding for volume — claim count rises (mono 7 → 4-view
  18) while grounding falls monotonically (mono **0.334** > 2-view 0.238 > 4-view 0.142 > 3-tier
  **0.070**); monolithic is most grounded + most stable; no arm hallucinates technique IDs. Full
  table under §3.6 Status. Fixes: (i) eval disables analyst chain-of-thought via
  `chat_template_kwargs.enable_thinking=false` (the reasoning model was spending the whole budget
  in `<think>`, which the server strips → empty CLAIM output + timeouts); (ii) `_bootstrap_ci`
  (all three eval harnesses) now samples the LCG **high** bits — `seed % n` collapsed the CI for
  power-of-two n. ruff clean; 42 eval-scoring tests pass.
- **2026-06-04 first live-LLM eval smokes (§3.5, §3.6, Item 3) on Qwen3.6-35B-A3B.** Brought the
  local llama-server up and ran the two server-only harnesses end-to-end (n=1 `--smoke`).
  *Fix:* `eval_view_decomposition.py` and `eval_narrative_quality.py` had the single-path sys.path
  bootstrap (`_REPO_ROOT` only) and so couldn't import `maljan` as standalone scripts (src-layout)
  — both now insert `_REPO_ROOT/"src"` too (matching `eval_function_rag.py`). *View-decomposition
  smoke* (equal budget B=2000): grounding monolithic 0.143 / 2-facet 0.500 / 3-tier 0.083, invalid
  technique-id 0.0 across all arms, claim count 7/8/12 — 2-facet lifts grounding ~3.5×, tier
  maximises claims but minimises grounding (directional, n=1). *Narrative-quality smoke*: LLM and
  fallback both perfect faithfulness (F1=1.0, 0 hallucinated); the LLM's edge is structural
  (1.0 vs 0.0), paired F1 delta +0.000 (tie at n=1). Recorded both under §3.6/§3.5 Status as the
  first live signal; full mean±CI verdicts need a multi-repeat run over all fixtures.
- **2026-06-04 concept-drift eval data engine + harness (Roadmap Item 5, MARD).** Resolved the
  Item 5 data gate. New `tests/evaluation/collect_temporal_manifest.py`: a metadata-only dated
  manifest collector (MalwareBazaar `get_siginfo` API with `$MALWAREBAZAAR_AUTH_KEY`, or a
  local full-dump CSV; offline `--selftest`), scoping to Windows/Linux (§1.8), year-cohort
  bucketing + deterministic balance-sampling. Verified live: a **balanced 210-sample manifest,
  7 cohorts (2020–2026) x 30 each, 27 distinct families**, vendored (metadata only) at
  `tests/evaluation/temporal_manifest.json`.
  New `tests/evaluation/eval_temporal_drift.py`: loads the manifest, maps each MalwareBazaar
  family to its in-repo ATT&CK ground-truth fixture (alias map + slug/CamelCase fallbacks), runs
  the pipeline per present binary, and reports per-cohort precision/recall/F1 (`TTPAccuracyMetrics`
  + deterministic bootstrap CI) and the earliest→latest drift delta; `--dry-run` proves the wiring
  offline (all 210 ground-truth-resolved, 30/30 per cohort; 0 binaries present → all
  `pending_binary`, nothing fabricated). New `tests/evaluation/test_temporal_drift_scoring.py`
  (13 pure-function tests). No binaries committed; live drift numbers await operator-supplied
  binaries + a live llama-server. Flipped §4 Item 5 to `IMPLEMENTED` (code) / `PENDING` (numbers).
  ruff clean; 151 eval-scoring tests pass.
- **2026-06-03 tier-wise reasoning + consistency gate (Roadmap Items 3 & 4, LAMD).**
  *Item 3:* `BaseAnalyst.analyze_isr_tiered` / `safe_analyze_isr_tiered` plus the
  `_TIER_SPECS` (facts → behaviour → ATT&CK semantics) ladder add LAMD-style **vertical**
  reasoning — N sequential tools-free `_invoke_view` calls, each receiving the original evidence
  and the prior tier's output, at the §3.6 equal-budget `expert_max_tokens // N` split; per-tier
  ISRs merge (dedup) via `merge_chunk_isrs` with per-tier fault isolation. Gated by
  `LLMConfig.view_decomposition_mode` (`"facet"` default vs `"tier"`), dispatched in
  `make_analyst_node`'s single-chunk branch; `{n}-tier` arm added to `eval_view_decomposition.py`.
  *Item 4:* `_apply_consistency_gate` + the pure `_claim_grounded_in_evidence` helper drop claims
  whose cited artifact / technique is absent from the source evidence, run in the analyst safe_*
  wrappers (so both `_parse_claim_blocks` structured and `_text_to_isr` fallback claims are
  gated). Config-gated `PreprocessingConfig.use_claim_consistency_gate` (off by default,
  fail-safe). Both gates default to today's behaviour (no regression). New tests:
  `tests/unit/agents/test_view_decomposition.py` (tier cases) + `test_consistency_gate.py`.
  Flipped §4 Items 3 & 4 PLANNED → IMPLEMENTED.
- **2026-06-03 function-level RAG retrieval (Roadmap Item 2, TraceRAG).** New
  `src/maljan/memory/function_index.py`: an ephemeral per-sample in-memory cosine index over
  the static analyst's `FUNCTION_BOUNDARY` chunks (reusing `embeddings.encode_batch`/`cosine`).
  A fixed `BEHAVIOR_QUERIES` set retrieves the top-k relevant functions per query (union, deduped,
  original order); wired into the static multi-chunk branch of `make_analyst_node` behind
  `PreprocessingConfig.static_function_rag_top_k` (0 = linear path, default) and engaging only
  above `static_function_rag_min_chunks` — fail-safe to the full set when retrieval matches
  nothing. Offline eval `tests/evaluation/eval_function_rag.py`: recall 1.0 of the seeded
  malicious functions at ~75% token reduction (36-function corpus). Flipped §4 Item 2 PLANNED →
  IMPLEMENTED. 1294 unit pass (+ `tests/unit/memory/test_function_index.py`); ruff/mypy clean.
- **2026-06-03 token/cost telemetry (Roadmap Item 1, MARD).** Added a thread-safe
  `TokenLedger` (`src/maljan/core/token_ledger.py`) on the `ServiceContainer`; analyst
  (`base_agent` no-tools + view paths) and judge LLM invokes call `record_response_usage`,
  which prefers langchain `usage_metadata` and falls back to a flagged char-based estimate
  (~chars/4) when the local llama-server omits it. The judge node snapshots the ledger into a
  new `TokenUsageMetrics` block on `RunSummary` (rendered in `to_dict`/`to_markdown`). Telemetry
  never raises; mock/zero-call runs render no token section. Flipped §4 Item 1 PLANNED →
  IMPLEMENTED. 1283 unit pass (+ new `tests/unit/core/test_token_ledger.py`); ruff/mypy clean.
- **2026-06-03 reviewed MARD/TraceRAG/LAMD → roadmap (§4).** Recorded five net-new transferable
  items (token telemetry, function-RAG retrieval, tier-wise reasoning, claim-consistency gate,
  concept-drift eval) under Open threads, sequenced by value/effort; noted convergent validation
  (Maljan already realises the papers' core LLM-orchestrator + deterministic-tools paradigm).
- **2026-06-03 view-decomposition: config-gated mechanism + equal-budget A/B (§3.6, last
  backlog item).** Settled the §3.2 `INCONCLUSIVE` properly. (i) **Mechanism:**
  `LLMConfig.view_decomposition_views` (default 0 = unchanged) gates a new
  `BaseAnalyst.analyze_isr_views` that runs N focused tools-free sub-prompts over the same
  evidence concurrently (`ThreadPoolExecutor`), each capped at `expert_max_tokens // N` so the
  total budget matches the monolithic arm — the control §3.2 lacked — merged via the existing
  `merge_chunk_isrs`; a derailed view is dropped (fault isolation). Text path only; gated in
  `make_analyst_node`, so the default leaves the analyst path byte-for-byte. (ii) **Valid
  study:** `tests/evaluation/eval_view_decomposition.py` A/Bs monolithic vs 2/4-view at equal
  total budget, N≫1, scoring invalid-technique-id rate (the §3.2 T1000 failure mode, via
  `ATTCKValidator`), grounding, and claim-count stability — mean ± bootstrap CI. Unit-tested
  without a live LLM (`tests/unit/agents/test_view_decomposition.py`,
  `tests/evaluation/test_view_decomposition_scoring.py`). Flipped the §4 `HYPOTHESIS` to
  `DONE`/`IMPLEMENTED` (§3.6). 1271 unit + 20 new tests pass; ruff/mypy clean.
- **2026-06-03 MaLAware-style narrative-quality harness (§3.5, backlog item).** Shipped
  `tests/evaluation/eval_narrative_quality.py` — a paired A/B (NarrativeAgent vs the
  deterministic fallback template) built to the §3.4 methodology bar (forced output, N≫1
  via K repeats, mean ± bootstrap CI, sign test). Since the repo vendors no human-written
  reference prose, "quality" is operationalised as faithfulness (no invented techniques),
  coverage, structural compliance, and fp_linter cleanliness — all deterministic, no new
  dependency. Each fixture family becomes a fixed synthesized-evidence `MalwareReport` so
  both arms narrate the same bundle. Eval-only: no production code touched. The pure scoring
  core is CI-covered by `test_narrative_quality_scoring.py` (16 tests, no live LLM); the
  live numbers come from running the harness against a llama-server. Flipped the standing
  MaLAware `HYPOTHESIS` to `DONE`/`IMPLEMENTED`. 1262 unit + 16 eval-scoring tests pass;
  ruff/mypy clean.
- **2026-06-03 attribution consolidation + apps/api format alignment.** (i) **Refactor
  (behaviour-preserving):** family/threat-actor attribution grounding was a private
  method on the report builder (`MalwareReportBuilder._is_family_grounded`) with the
  `FamilyAttribution` construction + D11 guardrail log inlined in `build_deterministic`,
  while the sibling concern (`similar_samples`) already lived in
  [extractors/attribution.py](../../src/maljan/extractors/attribution.py). Moved the
  grounding + construction into that module as `build_family_attribution(...)` (a pure
  function called like the other `build_*` extractors), giving attribution one home and
  matching the `build_sample_identity` / `build_network_iocs` pattern. The builder now
  delegates; the `TestAttributionGrounding` suite (exercised through the builder) stayed
  green unchanged as the regression guard, and direct unit tests were added for the moved
  function (1262 unit pass, +5). (ii) **Cosmetic:** ran `ruff format` on two long-drifted
  `apps/api` files (`audit.py`, the initial alembic migration) — line-wrapping only, no
  logic change; pre-commit's staged-files-only formatter had never re-touched them.
  ruff/mypy clean (100 src files); 241 files all-formatted.
- **2026-06-03 JA3S server-side TLS fingerprint surfaced end-to-end (1 backlog item).** The Triage
  loader already parsed the server-side TLS fingerprint (`tls_ja3s`) off every flow
  ([triage_client.py:1394](../../src/maljan/loaders/triage_client.py)) but then **silently discarded
  it** — the SandboxCTI `network` block had no `tls_ja3s` key and the synthesis loop only forwarded
  `tls_ja3`. JA3S is a distinct C2/infrastructure-clustering pivot, so it was threaded through the
  exact path the client `ja3_fingerprints` already travels, mirroring it field-for-field: new
  `NetworkIOCs.ja3s_fingerprints`; `_extract_ja3s` over `network.tls[]` (keys `ja3s`/`ja3s_hash`) in
  the CAPE raw path; `tls_ja3s` forwarded in the Triage CTI synthesis and folded (deduped) by
  `merge_sandbox_cti_network`; rendered as a `### JA3S Fingerprints` markdown section; emitted as a
  new `ja3s` IOC kind by the `/iocs` API; added to the judge's CTI summary so the verdict LLM sees
  server fingerprints. No new heuristic, no new data source — pure plumbing of an already-captured
  value. 1257 unit pass (9 skipped); ruff/mypy clean (100 src files); web tsc 0.
- **2026-06-03 deterministic technique surfacing (3 deferred follow-ups).** Addressed the items the
  prior round deferred. (i) **DGA -> T1568.002**: a new `build_dga_isr` turns high-confidence DGA
  domains into a deterministic ATT&CK claim (mirrors Sigma/YARA `to_isr`), injected in the judge node
  before the cascade. Two-tier design: suspicion flag at 0.55, *technique claim* at a higher 0.65 bar;
  confidence = `min(dga_score, 0.75)` so a lone heuristic can't drive the verdict (cascade boosts only
  on cross-layer corroboration). Homographs deliberately not mapped (no clean enterprise technique).
  (ii) **LOLBin -> T1218.010/.011/.005**: new `analysis/lolbin_layer.py` flags *suspicious* (not mere
  presence) regsvr32/rundll32/mshta from `behavior.processes[].command_line` (squiblydoo `/i:`,
  scriptlet, remote URL, script protocol, ordinal export, user-writable payload path); `domain="dynamic"`,
  `rule_platforms=["windows"]` so the cascade drops them on Linux. This *reframed* the deferred
  "COM-registration API scanner", which was **declined** — `CoCreateInstance`/`CoRegisterClassObject`
  aren't in CAPE's parsed `behavior.calls` (no data); LOLBins are the COM-payload execution counterpart
  to the existing T1546.015 persistence. (iii) **Legacy unify**: `NetworkParser._is_suspicious_dns`
  (old `len>25` PoC) now delegates to the canonical `_assess_domain`, so the network-analyst LLM
  prompt's `[Suspicious]` flags match the structured report. Both deterministic producers added to the
  ATT&CK-autocorrect `skip_agents` (rule/heuristic-authoritative). 1264 unit + report-pipeline pass
  (9 skipped); ruff/mypy clean (100 src files); fp_linter unaffected; web tsc 0.
- **2026-06-03 DGA scoring + COM-hijacking persistence (2 backlog items).**
  (i) Replaced the consonant-ratio `_looks_like_dga` with a deterministic composite
  `_dga_score` (normalised Shannon entropy + common-bigram rarity + digit ratio / consonant-run /
  legacy ratio; threshold 0.55, min label len 10 to avoid short-brand FPs). Verified separation:
  random labels 0.88-0.91 vs dictionary-ish `salesforce`/`documentation`/`stackoverflow` 0.34-0.46.
  Added IDN/punycode homograph detection (`_idn_assessment`: `xn--` decode + Latin/Cyrillic mixed-script
  + confusable->ASCII brand skeleton; flags all-confusable brand spoofs but not legitimate single-script
  IDNs). Both DGA and homograph checks scan *every* non-TLD label, so subdomain look-alikes
  (`login.pаypal.com`) and DGAs under multi-level public suffixes (`*.co.uk`) are caught. New structured
  `NetworkDomain` fields `dga_score`/`is_punycode`/
  `homograph_target` (+ TS mirror). Fixed a real bug: `merge_sandbox_cti_network` overwrote the true
  suspicion reason with `"From Triage SandboxCTI"` — now preserves the reason + scores via a single
  `_DomainVerdict` source of truth (provenance kept as a `[Triage CTI]` suffix).
  (ii) Added COM-hijacking persistence (MITRE T1546.015): `_scan_com_hijack_calls` flags
  `CLSID\{guid}\InprocServer32`/`LocalServer32`/`TreatAs` registry writes, plus `com_hijack` signature
  hints; new `com_hijacking` kind (Python Literal + TS `PersistenceKind` + persistence-page label/colour;
  also fixed pre-existing TS drift — `systemd_timer`/`xdg_autostart` were missing). T1546.015's name
  resolves from the live ATT&CK bundle (no map edit). Out of scope (noted): T1568.002 cascade
  auto-mapping; a COM-registration API scanner. 1247 unit + report-pipeline pass (9 skipped);
  ruff/mypy clean; web tsc 0.
- **2026-05/06 session.** Created this log. Added: §1.1 sink-reachability, §1.2
  function-hash attribution (implemented this session), §1.3 verification discipline,
  §1.4 curated allowlist; §2.1 KV-cache measurement + 262k deployment, §2.2 tool-scale
  limit, §2.3 MTP negative result; §3.1 literature transfer assessment, §3.2
  view-decomposition probe, §3.3 degenerate technique-ID loop. Reviewed [1][2][3][4].
- **2026-06-01 correction.** Ran the §3.2 A/B a 3rd time with equalised per-call
  budget: the parsed-claim ranking **inverted** (monolithic 2 → 9). **Retracted** the
  "~2× completeness" claim as a budget/measurement artifact; kept only fault-isolation
  + output-stability as defensible. Added §3.4 (single-run claim-count is not a valid
  instrument). Trimmed references to the 4 we directly used.
- **2026-06-01 semantic eval.** Added a drop-in `SemanticATTCKIndex` (BGE-384) as an opt-in
  ATT&CK backend and a TRAM2 top-k harness (`tests/evaluation/eval_technique_mapping.py`).
  Added §1.5.1: semantic ranks modestly better (+6pp top-3) but its scores don't separate
  correct/wrong, so TF-IDF kept the clean alignment gate; semantic shipped opt-in. Logged the
  hybrid thread in §4.
- **2026-06-01 hybrid.** Implemented `HybridATTCKIndex` (semantic ranking + TF-IDF gate) and ran
  the full TRAM2 set (N=4913). It dominates both pure backends — semantic-grade ranking
  (top-3 0.392) *and* the cleanest gate (separation +0.115) — so it is now the **default**
  backend. Updated §1.5.1 to the three-method table; closed the §4 hybrid thread. All checks
  green (54 ATT&CK + pipeline/agent tests pass).
- **2026-06-01 ablation + fix.** Ran the end-to-end autocorrect ablation (§1.5.2, TRAM2 ground
  truth). Found the valid-ID swap path damaged **38% of already-correct IDs** (invisible to the
  retrieval metric). Fixed by restricting autocorrect to invalid-ID replacement
  (`attck_autocorrect_swap_valid=False`, default) — re-measured: hallucination 100%→0%, +19%
  recovery retained, **correct-ID regression eliminated (→0%)**. Added §1.5.2; 56 ATT&CK tests
  pass.
- **2026-06-02 signal quality.** Added §1.9 (filed under §2.4 at the time): a four-part deterministic extractor hardening wave
  (network FP/validation, platform-aware persistence + dynamic FP, anti-false-confidence
  calibration, enrichment trust/freshness). Rejected a word-boundary category-keyword change after
  it broke intentional stems. 329 extractor/enrichment/reporting/integration tests pass; mypy clean.
- **2026-06-02 category inference (static vs dynamic).** Measured the category-driven schema-pruning category
  classifier against a non-circular ATT&CK ground truth (101 families labelled by self-declared
  type; full vs behavioral-only regimes). Findings (§1.7): keyword is accurate only when the text
  names the category (full 0.792 → behavioral 0.327, abstaining 38% — a *safe* failure mode);
  zero-shot semantic over averaged technique prototypes is a `NEGATIVE` result (0.376/0.168);
  dynamic helps only as *few-shot* prototypes from labelled prose (kw→few-shot hybrid: full 0.832,
  behavioral 0.525). Shipped `category_inference_backend` (keyword|semantic|hybrid), default
  **keyword**, fail-safe to keyword — a measured, reversible knob, not a default flip. New
  `semantic_category.py` + dispatcher wired through `JudgeAgent`/container; new harness + dataset
  builder + unit tests. Full unit suite (1237) + report-pipeline integration pass; ruff/mypy clean.
- **2026-06-02 hint ablation (LLM-in-the-loop).** Closed the §1.7 deferral with a paired ON/OFF
  judge ablation (live Qwen3.6-35B, temp=0, 17 hint-present families; checkpointed/resumable run,
  paused+resumed across a day). Finding (§1.7.1): the hint's effect is **completion, not mapping
  accuracy** — without it the judge hits the 600 s timeout and falls back to an empty bundle 6/17
  vs 1/17 with it, roughly doubling objects/attack-patterns/relationships; exact-F1 delta +0.029
  (95% CI [-0.001, +0.072], crosses 0). An operational, timeout-mediated benefit specific to the
  slow local model — reaffirms the keyword default and that the schema-pruning hint earns its place.
  New harness `tests/evaluation/eval_hint_ablation.py`.
- **2026-06-02 judge output cap.** Follow-up to §1.7.1: the judge had no output bound (only the
  600 s wall-clock), so a degenerate decode burned the full budget. Added `LLMConfig.judge_max_tokens`
  (default 8192) wired in `container.get_judge_llm()` — bounds a runaway verdict to ~205 s at
  ~40 tok/s. Verified non-truncating (MiniDuke/Emotet reproduce obj=13/ap=4 capped). Worst-case-latency
  guard, not a quality fix. 1227 unit tests green; ruff/mypy clean.
- **2026-06-02 OS-scope = Win+Linux.** Established that CAPEv2 supports only Windows + Linux guests
  (no Android — that was CuckooDroid; macOS legacy). Narrowed the whole platform surface to match
  (§1.8): `Platform` Literal + `_infer_platform` + `_MITRE_PLATFORM_MAP` + fp_linter/sigma/persistence
  gating → Windows/Linux/unknown; removed `MOBILE_ENTERPRISE_OVERLAP`; deleted the frontend Mobile
  ATT&CK matrix (`mitre-mobile.ts`, capabilities → Enterprise-only) and narrowed the `SamplePlatform`
  TS type. Kept the Android FP-denylists (defensive, not OS support). Dropped the Android-persistence
  backlog item. mypy clean (99 files); 1226 unit tests pass; web tsc clean + ESLint 0 errors.
- **2026-06-03 Win/Linux-only naming sweep (behavior-preserving).** Per the "only Windows/Linux"
  scope, neutralized all incidental Android/macOS/iOS naming while keeping every noise/quality
  filter's behavior identical: renamed `ANDROID_CLASS_REF_RE`->`FOREIGN_CLASS_REF_RE` (+ J-02 reason
  `file_name_android_class_ref`->`file_name_foreign_class_ref`); rejection reasons in
  `unsupported_os_reason` now name the FORMAT, not the OS (`"unsupported format (Mach-O/APK/.dmg/...)"`);
  reworded stale comments/docstrings across ~15 src + 3 web files; deleted the always-dropped
  `data/sigma_rules/macos/` corpus (69 rules — filtered out for every reachable sample, so zero
  detection-quality change). Deliberately KEPT (functional match-targets / measurement data, removing
  them would change behavior): the FP-filter vocabularies (`_PLATFORM_INCOMPATIBLE_TERMS` macos/azure,
  URL_DENY_HOSTS `*.android.com`, `apple.com`/`cloudflare.com`/`icloud.com` benign-domain allowlist,
  the APK/.dex DOMAIN denylist), the `T1078.004 Cloud Accounts` Enterprise ATT&CK technique label, the
  Triage public-cloud submission service, the CSS system-font-stack (`-apple-system`/`Segoe UI`/`Roboto`
  — browser rendering, not malware-OS), and the TRAM2/ATT&CK evaluation ground-truth about macOS/cloud
  malware. Also deleted `data/sigma_rules/cloud/` (226 rules) and the dead `_CLOUD_PRODUCTS` compat
  branch (cloud was an unreachable sample platform → always dropped, so zero detection-quality change).
  1243 unit + report-pipeline tests pass; ruff/mypy clean; web tsc 0.
- **2026-06-03 reject non-Win/Linux at entry.** Closed the last live remnant (Triage
  `_EXT_TO_OS_TAG` still routed `.apk/.dex`→Android, `.dmg/...`→macOS). Added
  `UnsupportedSampleError` + `sample_identity.unsupported_os_reason` (magic-byte-first foreign
  detector); `app.arun` now rejects definitely-foreign samples before any sandbox submission
  (backend-agnostic), and the Triage map's macOS/Android rows were removed. Foreign-rule-drop tests
  reframed to a Win/Linux sample + foreign rule (quality assertions preserved). Android FP denylists
  untouched. §1.8 extended. 1242 unit + report-pipeline tests pass; ruff/mypy clean.
- **2026-06-01 output quality.** Added §1.6: a deterministic STIX integrity pass
  (`enforce_bundle_integrity` — empty-pattern drop, AP/indicator dedup, dangling-ref + duplicate
  relationship sweep, object_refs trim) applied in judge_postprocess and the extended renderer,
  closing the J-02 dangling-indicator-ref gap; plus honest-reporting signals (surfaced
  `family_grounded`, "not determined" for no family, `DEGRADED RUN` banner). 135 reporting/judge
  tests pass; ruff/mypy clean. All checks green (86 unit tests pass).
- **2026-06-01 fix.** Implemented the §3.3 degenerate-loop fix. Added §1.5
  (deterministic ATT&CK ID assignment via the in-house TF-IDF index — made authoritative,
  not just advisory). Marked §3.3 `IMPLEMENTED` and **rejected the earlier "curated anchor
  table" mitigation** as redundant/inferior to the full-catalog index. Recorded the live
  sampler probe: `repeat_penalty` honored, `repetition_penalty`/`frequency_penalty`/
  `presence_penalty` ignored by ik_llama, and penalty-only damping is
  necessary-but-insufficient. All checks green (ruff/mypy clean; 67 ATT&CK + 26
  agent/judge/pipeline tests pass). No new references.
