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

### 3.2 View-decomposition for small-model static analysis — `EXPERIMENTAL` (controlled probe, N=1 per arm, deterministic decoding)
- **Question.** Given identical Ghidra-derived evidence, does a small local model
  produce sharper, better-grounded findings under **focused per-view sub-prompts**
  (AppPoet [3] style) than under **one monolithic prompt**?
- **Method.** Self-contained A/B harness (no production code touched). Fixed,
  balanced 4-view evidence bundle (imports/API, strings/IOC, sink/control-flow,
  crypto) modelling a Linux ELF backdoor. Same live local model (Qwen3.6-35B-A3B at
  262k), temperature 0. Arm A = 1 monolithic call; Arm B = 4 per-view calls + 1
  synthesis call. Metrics: distinct correct findings, ATT&CK technique coverage,
  grounding (fraction of claims citing an artifact present in the bundle), tokens,
  wall-clock. Two runs (one with reasoning on, one with the reasoning soft-switch
  off). Harness: `D:/tmp/view_ab_experiment.py` (throwaway).
- **Results (consistent across both runs).**

  | Metric | Monolithic (A) | View-decomposed (B) |
  |---|---|---|
  | Distinct correct findings | 2 | **4** |
  | Grounding (hallucinated claims) | 100% (0) | 100% (0) |
  | Techniques missed by A but caught by B | — | LD_PRELOAD dynamic-linker hijack (T1574.007), distinct C2 (T1071.001), XOR-config→`connect()` dataflow |
  | Tokens | ~2.2k | ~3× (clean) / inflated by §3.3 loop |
  | Wall-clock | ~33 s | ~7× serial (parallelisable; views are independent) |

- **Finding 1 (confirms [3] on a *small local* model).** View-decomposition roughly
  **doubled finding completeness** (2 → 4) and recovered distinct techniques the
  monolithic arm missed, **without** adding hallucination (grounding stayed 100%).
- **Finding 2 (novel observation — fault isolation).** When the small model derailed
  on one view (the degenerate loop of §3.3), the *other* views' findings — already
  captured in separate calls — survived into the synthesis. In the monolithic arm a
  single derailment truncated all subsequent analysis. **Decomposition provides
  fault isolation, a benefit beyond the "focused attention" hypothesis.** `OBSERVED`.
- **Cost framing.** The token overhead (~3× clean) is effectively free on a
  self-hosted local model (no per-token billing); the latency overhead is
  parallelisable because the views are independent. This makes decomposition more
  attractive for *local* deployment than its raw cost suggests.
- **Limitations (state plainly in the paper).** N=1 per arm; single sample; a
  synthetic (though realistic) evidence bundle chosen because the available live
  sample was statically linked (sparse named-import/sink views). A powered study
  needs multiple real samples, blinded scoring of correctness (not just grounding),
  and parallel-call latency measurement.

### 3.3 Novel failure mode: degenerate technique-ID loop — `OBSERVED` (reproducible)
- **Phenomenon.** On anti-analysis evidence (`ptrace`/`prctl`), the model does not
  know the correct ATT&CK technique ID and enters a **catastrophic degenerate loop**,
  emitting "I'll just use T1578.005?" hundreds of times and burning the entire token
  budget, while repeatedly proposing *wrong* IDs (T1578.005 is a cloud technique;
  T1553.002 is trust-subversion — neither is anti-debug, which is T1622 Debugger
  Evasion). Reproduced across both experiment runs and both prompt structures.
- **Why it is paper-worthy.** It is a concrete, reproducible *small-model pathology*
  at the intersection of (a) under-specified label spaces (a 600+ technique
  taxonomy the model has not memorised) and (b) autoregressive self-reinforcement.
  It also has a **practical security-tooling consequence**: any production analyst
  driving this model on a sample with anti-debug primitives risks the same loop.
- **Mitigations (candidate contributions).** (i) per-call repetition penalty +
  max-token guard; (ii) supplying the model a **curated ATT&CK anchor table** for
  the common evasion/loader/injection techniques so it retrieves rather than guesses;
  (iii) decomposition (§3.2) as a *blast-radius limiter* for such loops.

---

## 4. Open threads / planned experiments

- `HYPOTHESIS` Production-wire the technique-ID loop guard (repetition penalty +
  curated ATT&CK anchor) and measure FP/throughput impact on real samples.
- `HYPOTHESIS` Config-gated view-decomposition pilot with **parallel** view calls; a
  lighter 2-view variant (behaviour vs artifacts) to trade completeness for cost.
- `HYPOTHESIS` Adopt a MaLAware-style [4] multi-metric narrative-quality evaluation
  harness for the report/NarrativeAgent.
- Leads not yet evaluated (likely high transfer — "LLM-as-analyst" paradigm):
  MARD (multi-agent) [5], TraceRAG (RAG + explainable) [6], LAMD [7].

---

## References

1. Z. Yu, M. Wen, X. Guo, H. Jin. *Maltracker: A Fine-Grained NPM Malware Tracker
   Copiloted by LLM-Enhanced Dataset.* ISSTA 2024, pp. 1759–1771. DOI
   10.1145/3650212.3680397.
2. N. Rollinson, N. Polatidis. *LLM-Generated Samples for Android Malware Detection.*
   Digital 2026, 6(1), 5. DOI 10.3390/digital6010005. (Preprint: arXiv:2510.02391.)
3. W. Zhao, J. Wu, Z. Meng. *AppPoet: Large Language Model based Android malware
   detection via multi-view prompt engineering.* Expert Systems with Applications
   262 (2025) 125546. (Preprint: arXiv:2404.18816.)
4. B. Saha, N. Rani, S. K. Shukla. *MaLAware: Automating the Comprehension of
   Malicious Software Behaviours using Large Language Models (LLMs).* MSR 2025.
   arXiv:2504.01145.
5. *MARD: A Multi-Agent Framework for Robust Android Malware Detection.*
   arXiv:2604.25264. (Lead — not yet evaluated.)
6. *TraceRAG: A LLM-Based Framework for Explainable Android Malware Detection and
   Behavior Analysis.* arXiv:2509.08865. (Lead — not yet evaluated.)
7. *LAMD: Context-driven Android Malware Detection and Classification with LLMs.*
   arXiv:2502.13055. (Lead — not yet evaluated.)
8. A. Guerra-Manzanares, H. Bahsi, S. Nõmm. *KronoDroid: Time-Based Hybrid-Featured
   Dataset for Effective Android Malware Detection and Characterization.* Computers &
   Security 110 (2021) 102399. (Dataset used by [2].)

### Tooling / infrastructure
- Ghidra MCP server (bethington/ghidra-mcp, v5.6.0; `com.xebyte`, ~201 `@McpTool`
  endpoints; P-code emulation, call-graph extraction).
- ik_llama.cpp `llama-server`; Qwen3.6-35B-A3B (MoE) IQ3_K_R4; Qdrant (vector + exact
  payload-filter stores); MITRE ATT&CK.

---

## Changelog (append new sessions here)

- **2026-05/06 session.** Created this log. Added: §1.1 sink-reachability, §1.2
  function-hash attribution (implemented this session), §1.3 verification discipline,
  §1.4 curated allowlist; §2.1 KV-cache measurement + 262k deployment, §2.2 tool-scale
  limit, §2.3 MTP negative result; §3.1 literature transfer assessment, §3.2
  view-decomposition probe, §3.3 degenerate technique-ID loop. Reviewed [1][2][3][4];
  logged leads [5][6][7].
