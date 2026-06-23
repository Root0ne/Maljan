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
> finding builds on or contradicts. Last updated: 2026-06-01.

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
- **Novelty / principle.** A concrete instance of "LLM proposes, deterministic layer
  disposes" applied to the *label-assignment* step itself: separate **description**
  (model) from **taxonomy mapping** (deterministic retrieval). The project already had
  this index but used it only *advisorily* (validation summary injected into the judge
  prompt); the contribution is making it **authoritative** for ID assignment.
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
- **CTI polish (wave 2).** Three further low-risk correctness passes: (i) the integrity pass also
  drops syntactically malformed STIX patterns (conservative bracket+comparator shape check — no
  grammar parser, no over-dropping); (ii) attack-pattern display names are back-filled from the
  already-loaded ATT&CK index for all ~700 techniques (not just a 14-entry curated table),
  fail-safe when the index isn't built; (iii) FP-prone `file:name` string-IOC indicators are typed
  `anomalous-activity` rather than `malicious-activity` so consumers can weight them below
  high-confidence hash/C2 IOCs.

### 1.7 Static keyword vs dynamic semantic category inference — `IMPLEMENTED` (knob shipped, default unchanged) / zero-shot variant `NEGATIVE`
- **Question.** The §7.1 STIX schema-pruning hint is driven by `infer_malware_category` — a
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
- **Takeaways (paper + product).** (i) An "advisory, low-impact" prompt addition can have a
  first-order effect through an *unmeasured channel* (completion/latency), invisible to a pure
  mapping-quality metric — measure bundle shape and completion, not just F1. (ii) The §7.1
  schema-pruning feature earns its place: disabling it ~halves bundle completeness and 6×'s the
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
  not OS support, and removing them would regress the §1.6/§2.4 indicator quality.
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

---

## 2. Empirical systems findings (local deployment)

Hardware: RTX 5060 (8 GiB VRAM), 31 GiB system RAM, Windows 11 + WSL2/Docker.
Model: Qwen3.6-35B-A3B (MoE, 35B total / ≈3B active), IQ3_K_R4 quant, served by
ik_llama.cpp `llama-server` with hybrid CPU/GPU offload (`--n-cpu-moe`).

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
  measurement overturned it: 262k is feasible and was deployed. **Lesson: measure
  KV at boot, don't trust the closed-form estimate for this architecture.**
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

### 2.4 Deterministic signal-quality hardening — `IMPLEMENTED`
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
- **Why it is paper-worthy.** A concrete, reproducible small-model pathology
  (under-specified 600+ label space × autoregressive self-reinforcement), plus the
  finding that the obvious mitigation (sampler penalties) is necessary-but-insufficient,
  and a clean fix (offload the taxonomy lookup to deterministic retrieval).

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
  omits some → 0.853). The LLM's *only* edge is **structural/readability compliance (0.73 vs
  0.00)** — i.e. the justification for the LLM narrator is human-readable prose, **not** accuracy
  or coverage, where the deterministic template is at least as good. A useful negative-ish result:
  don't pay for an LLM narrative on faithfulness grounds; pay for it only if readable prose is the
  product. (This supersedes the earlier n=1 smoke, which was an uninformative tie.)

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

---

## 4. Open threads / planned experiments

- `DONE` (§1.5, §3.3) Production-wired the technique-ID loop fix — repetition-penalty
  damper + deterministic TF-IDF ID re-grounding. Next: measure FP/throughput impact on
  real samples (how often correction fires, and correction precision vs a labelled set).
- `DONE` (§1.5.1) Hybrid technique mapper — semantic embedding for *ranking* + TF-IDF for the
  *alignment gate*. Implemented (`HybridATTCKIndex`) and made the default; dominates both pure
  backends on the TRAM2 eval (semantic-grade ranking + the cleanest gate).
- `DONE` (§3.6) Config-gated view-decomposition pilot with **concurrent** view calls
  (`LLMConfig.view_decomposition_views`, off by default) + an equal-budget A/B harness.
  Next: run the harness against the llama-server to settle the §3.2 question.
- `DONE` (§3.5) Adopted a MaLAware-style [4] multi-metric narrative-quality evaluation
  harness for the report/NarrativeAgent (`tests/evaluation/eval_narrative_quality.py`).
  Next: run it against the local llama-server to report the LLM-vs-fallback paired deltas.
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
  ATT&CK techniques** (cap 6/family to keep the artifact ~1.3 MB). End-to-end verified with fastembed
  BGE-384 — an injection+network static
  profile retrieves T1055 / T1055.003 (process injection) at 0.90 plus related evasion TTPs.
  **Caveats:** the ATT&CK labels are capa's *static* inference (not authoritative ground truth, but a
  large real labelled corpus); MABEL ships no binaries (features-only — safe to download, no live
  malware); the `--csv`-style summary vocabulary overlaps but does not perfectly match
  `build_sample_profile_text` (advisory retrieval, LLM decides). Still OFF by default; the Qdrant /
  JSONL builder modes remain for mining the production LTM as it grows.
- `PLANNED` (static-feature family classifier — candidate new workstream, NOT in the Items 1–5
  roadmap) A deterministic ML classifier that predicts a malware **family** from static features
  (imports, PE-header fields, per-section entropy, opcode histogram, packer + YARA capabilities) to
  give the analyst/judge a family prior **without** dynamic analysis. Motivation: in static-only
  mode (`SANDBOX__BACKEND=mock`) the existing attribution stack is weak — the grounding guardrail
  (`extractors/attribution.py`) forces `family_confidence` to 0 whenever no Triage CTI / sandbox sig
  / ISR claim names the family (frequent in the n=210 run: "family='dropper' marked as ungrounded"),
  and `function_hash_attribution.py` only fires once the corpus already holds that family
  (cold-start "no known-family overlap"). A feature classifier generalises to unseen samples and
  fills exactly that gap; it could also narrow the ATT&CK candidate set via a family→canonical-`uses`
  prior (a route to lift precision), and add an independent deterministic voice to judge negotiation
  (our reports often warn "zero cross-layer corroboration"). **Cost/feasibility:** plumbing is mostly
  in place (pefile, binary chunker, Ghidra opcode access, YARA layer already extract the features); a
  gradient-boosted tree (LightGBM/XGBoost) on tabular static features is well-trodden. The real cost
  is **labelled training data** — our MalwareBazaar manifest (210, dated, family-labelled) is too
  small; **EMBER** (1.1M labelled PE feature vectors, public) is the canonical training set, and
  **MABEL**'s 400+-family feature tables are a ready secondary (this is the *one* place MABEL is
  actually useful to us — as classifier training data, not RAG). **Caveats:** it predicts *family*,
  not the ATT&CK TTPs our headline F1 scores (only an indirect lift via family→uses expansion); family
  taxonomy is alias-noisy; and a trained classifier **reintroduces the concept-drift sensitivity the
  n=210 LLM path was just shown NOT to have** (MARD's warning) — it would need periodic retraining and
  drift monitoring. Verdict: real, well-scoped, fixes a genuine static-only weakness, but orthogonal
  to the current TTP-accuracy/drift narrative — decide as a separate workstream, not a roadmap item.
  **SUPERSEDED (2026-06-07):** a trained GBDT is a second statistical brain that decides *outside*
  the LLM and re-imports drift fragility — against the "everything LLM-centric" principle. The GBDT
  scaffold was removed and replaced by the LLM-centric Family-feature RAG below.
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
- **2026-06-02 signal quality.** Added §2.4: a four-part deterministic extractor hardening wave
  (network FP/validation, platform-aware persistence + dynamic FP, anti-false-confidence
  calibration, enrichment trust/freshness). Rejected a word-boundary category-keyword change after
  it broke intentional stems. 329 extractor/enrichment/reporting/integration tests pass; mypy clean.
- **2026-06-02 category inference (static vs dynamic).** Measured the §7.1 schema-pruning category
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
  slow local model — reaffirms the keyword default and that §7.1 schema-pruning earns its place.
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
