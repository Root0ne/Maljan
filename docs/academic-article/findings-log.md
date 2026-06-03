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
- **Status.** Harness + scoring unit tests shipped; the live-LLM numbers are produced by
  running it (`--smoke` for a single end-to-end sample).

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
- **Status.** Mechanism + harness + unit tests shipped (off by default). The verdict on whether
  decomposition helps at equal budget is produced by running the harness against a llama-server.

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
- Leads to evaluate (likely high transfer — "LLM-as-analyst" paradigm):
  MARD (multi-agent, arXiv:2604.25264), TraceRAG (RAG + explainable, arXiv:2509.08865),
  LAMD (arXiv:2502.13055).

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

**Stack:** Ghidra MCP (bethington/ghidra-mcp v5.6.0); ik_llama.cpp `llama-server`;
Qwen3.6-35B-A3B (MoE) IQ3_K_R4; Qdrant; MITRE ATT&CK.

---

## Changelog (append new sessions here)

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
