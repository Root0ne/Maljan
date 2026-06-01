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

---

## 4. Open threads / planned experiments

- `DONE` (§1.5, §3.3) Production-wired the technique-ID loop fix — repetition-penalty
  damper + deterministic TF-IDF ID re-grounding. Next: measure FP/throughput impact on
  real samples (how often correction fires, and correction precision vs a labelled set).
- `DONE` (§1.5.1) Hybrid technique mapper — semantic embedding for *ranking* + TF-IDF for the
  *alignment gate*. Implemented (`HybridATTCKIndex`) and made the default; dominates both pure
  backends on the TRAM2 eval (semantic-grade ranking + the cleanest gate).
- `HYPOTHESIS` Config-gated view-decomposition pilot with **parallel** view calls; a
  lighter 2-view variant (behaviour vs artifacts) to trade completeness for cost.
- `HYPOTHESIS` Adopt a MaLAware-style [4] multi-metric narrative-quality evaluation
  harness for the report/NarrativeAgent.
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
  green (54 ATT&CK + pipeline/agent tests pass). All checks green (86 unit tests pass).
- **2026-06-01 fix.** Implemented the §3.3 degenerate-loop fix. Added §1.5
  (deterministic ATT&CK ID assignment via the in-house TF-IDF index — made authoritative,
  not just advisory). Marked §3.3 `IMPLEMENTED` and **rejected the earlier "curated anchor
  table" mitigation** as redundant/inferior to the full-catalog index. Recorded the live
  sampler probe: `repeat_penalty` honored, `repetition_penalty`/`frequency_penalty`/
  `presence_penalty` ignored by ik_llama, and penalty-only damping is
  necessary-but-insufficient. All checks green (ruff/mypy clean; 67 ATT&CK + 26
  agent/judge/pipeline tests pass). No new references.
