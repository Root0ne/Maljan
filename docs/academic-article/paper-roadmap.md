# Maljan paper — the master queue

> **This file is the plan of record and the live TODO.** One ordered queue, 31 items, A → E.
> Nothing is worked out of order without saying so here. Restructured 2026-08-09 from the
> scattered §2/§3/§4 checkbox lists that preceded it.
>
> Companions: [findings-log.md](findings-log.md) is the evidence record (what was measured);
> [literature-review-brief.md](literature-review-brief.md) is the contribution map;
> [research-briefs/novelty-ledger.md](research-briefs/novelty-ledger.md) holds the novelty
> verdicts; [self-audit-pitfalls.md](self-audit-pitfalls.md) is the reviewer-facing self-audit.
>
> **Tags.** `[cheap]` no service · `[LLM]` needs llama-server · `[CAPE]` needs the sandbox
> network · `[$]` costs money · `[decide]` needs the author's call

---

## Where this stands

**The ledger, which governs everything below** *(revised 2026-08-11 after B5–B8, D3, E3)*:
**5 `OURS` · 10 `REFINEMENT` · 2 `PRIOR ART` (+1 adjacent) · 0 `UNMEASURED` · 1 `WITHDRAWN`**
(C6 closed `NEGATIVE` and C7's premise measured on 2026-08-14, §3.27).

What moved, and it is most of the table:

* **The four architectural claims are no longer unmeasured.** C1's effect is now measured too and
  is **negative** (§3.18: the hint fires on 56.7% of samples and changes nothing the analyst
  finds); C2 is a **measured negative** on both tiers; C3's cap fires on **0.82%** of techniques;
  C7's integrity pass was read on 60 fresh bundles. Ledger row **C6, the cascade, closed
  `NEGATIVE`** on 2026-08-14 (§3.27) — nothing in the ledger waits on CAPE any more.
  *(Queue item C6 is a different thing entirely — the frontier series — and is blocked on an
  endpoint, not on evidence. The name collision has now caused two misreadings of this file.)*
* **The four new `OURS` rows are all instrument defects; none is architectural.** M1–M3 were found
  on 2026-08-10 — a `null` argument, a program that never became current, an HTTP 200 on a refused
  load — and M4 on 2026-08-11, two local safety bounds composing into an empty result. They join C8.
  `M-DET`, the detector itself, was **counter-searched and demoted** the same week. That the only
  novel rows this project holds are records of its own instrument breaking is the finding, not an
  accident of bookkeeping.
* **E1 is withdrawn**, not demoted. The n=210 drift study meets M2's precondition and its per-sample
  outputs were not retained, so it cannot be checked and is not restated anywhere.
* **A baseline exists for the first time.** CAPE alone scores **F1 0.1526** [0.1344, 0.1709] on
  the full recovered cohort of 97 (C5), so pipeline figures now have a reference instead of
  floating. On the samples where both have run, the whole pipeline is 0.003 F1 above it.

Three rows had drifted from the evidence log and were corrected in this pass — C1 still carried an
interim 58.2%/n=79, C3 and C7 still read "unmeasured" after B5 and B4 had measured them. That is the
tenth check earning its place a second time; the register and the log diverge by default.

**Three framings have died, not two.** Describe-then-map (`arXiv:2401.12178`) and binary→ATT&CK
(`arXiv:2602.06325`) fell to prior art on 08-08. Then **A4 demoted the entire F2 remnant** — C5a,
N4 and N7, the three claims Part F called the paper's sharpest chapter — to `REFINEMENT` against
IR score calibration, grammatical error correction and neural text degeneration respectively. None
was refuted; each is a domain instance of a neighbouring field's settled result, and each keeps a
real mechanism. But the chapter can no longer be introduced as novel findings, and **D3 re-decides
on that basis.**

**The self-audit's three exposed rows — none is `EXPOSED` any more, and none is `CLEAR`.** P6 moved
to `PARTIAL` on 2026-08-14 (§3.28): the step budget is hit on **82.1%** of arms, a tool output cut
on **83.9%**, evidence chunked on **48.2%** — truncation is the operating regime, not an edge case.
It does not reach `CLEAR` because the pitfall asks for frequency **and** impact, and with 46 of 56
arms at the same cap there is no unaffected control group left to measure impact against. **P8 is
`PARTIAL` on evidence rather than on promises** — a second model has run (§3.16) and did not
separate from the local one, so the limit is coverage, not the absence of a comparison; the
parameter series that would improve it is blocked on an endpoint (§3.29). P9's model and engine are
both pinned (A2) and it stays `PARTIAL` for one stated reason: the running binary reports its
version as `unknown`, so the commit was recovered from a second copy of the sources rather than
from the artifact.

**B1 has run, and it decided the paper's shape.** The result was null: `negotiated − single` =
**−0.016**, 95% CI **[−0.084, +0.050]**, at **3.2× the tokens**. The literature's prior held — two
2026 equal-budget studies find single agents match or beat debate, and `arXiv:2604.02460` §5.3
locates a crossover at α=0.7 on our own model class. A malware pipeline sits on the side where
heterogeneous channels do not pay for themselves at equal budget. **F1, the system paper, is
closed; D3 locks F3 on that basis.** The remaining B1 follow-up — degrading the channels to find
the crossover experimentally — is a refinement of a settled answer, not a route back.

### Decisions taken 2026-08-09

| Decision | Consequence |
|---|---|
| Cascade ablation scale | **the recovered CAPE cohort with the dynamic path ON**, not the n=210 static corpus (C3). Intended as n=100; the sandbox produced reports for **95** (§3.24 — 56 of the original 100 tasks were marked `reported` after zero seconds, and 3 of the re-submissions failed processing) |
| Frontier arm | **Yes**, small budget — closes P8 + E.4 + E.8 in one experiment (A6, B8, C6) |
| Human evaluation | Replaced by an **internal, explicitly LLM-based** readability assessment (D1) that **does not enter the paper**; E.7 stays an open limitation |
| Target | No venue fixed, **quality first** — nothing is pruned from this queue |
| Second open-weight model | ~~Dropped~~ — **reinstated and then some, 2026-08-14** (see below) |

### Revised 2026-08-14 — the frontier arm is a series, not a model

Two further endpoints became reachable on the author's own NVIDIA account, at no cost. That
retires the "second open-weight model" decision above on its own terms: it was dropped because a
second local model cost hours of download for a weak second data point, and this costs neither.

The reason it matters is not that there are more models but that **a trend can now be tested where
only a point could be before.** `arXiv:2606.18166` reports parameter count as the *only*
significant predictor of ATT&CK-classification F1 (ρ=0.85, p=0.014). Against a single comparison
model, B8's null says "these two did not separate". Against four models spanning **21× in total
parameters and 13× in active parameters**, the same question becomes a dose-response test on our
own task:

| arm | total | active | status |
|---|---|---|---|
| Qwen3.6-35B-A3B (IQ3_K_R4), local | 35B | 3B | the system's own model |
| Nemotron-3-Super-120B-A12B | 120B | 12B | **done** — B8, n=25, §3.16 |
| MiniMax-M3 | 428B | 22B | new |
| GLM-5.2 | 744B | 40B | new |

**Both new arms are blocked, and the throughput figure first written here has been withdrawn
(§3.29).** GLM-5.2 does work: it answers tool calls correctly, accepted a 13,228-token prompt in
4.0 s, and reports usage. But the "36 completed calls per hour" this entry originally carried was
measured while the endpoint's allowance was draining, and later the same session the same client
completed **zero** calls; a 24-minute idle watch then returned **0 of 9** successes on both arms.
The 2.7 h and 55 h per-arm projections built on that number are withdrawn with it.

Two candidate designs remain, now costed against a provider that will actually answer:

* **one call per sample over the cohort (n=97)** — the judge-level comparison, on the same evidence
  §3.27 showed the verdict is decided by. Needs no local resources.
* **the full ReAct pipeline (~2,000 requests per arm)** — the literal "one endpoint changed"
  reading. Declined: it cannot share this machine with C4, and the cost is out of proportion to
  what it adds over the judge-level arm. Stated as a limitation in E2 rather than worked around.

**OpenCode Zen is the live alternative** (`https://opencode.ai/zen/v1`, OpenAI-compatible, so the
harness needs a config entry and no code). It serves **both** blocked models, which means the
series design does not change — only the endpoint. Priced from models.dev: `glm-5.2` at
$1.40/$4.40 per Mtok, `minimax-m3` at $0.30/$1.20. Against B8's measured usage that is **~$0.22 for
the fixture series and ~$6 for the cohort series**, well inside the configured $25 ceiling. It also
carries genuinely free models (`nemotron-3-ultra-free`, `deepseek-v4-flash-free`), and a **fifth
arm would drop the smallest reachable p from 0.083 to 0.017** — the first configuration in which
this series could reach significance at all. A free arm may only join the correlation if its
parameter count is published; the code-named models (`big-pickle`, `hy3`, `laguna-s`) cannot.
Blocked on an API key, which needs the author's account.

**Two confounds this series introduces and must state.** Parameter count is entangled with
*quantisation* (the local arm is 3-bit; the hosted arms are served at precisions we do not control
or fully know) and with *training corpus and lab* — four models from four organisations are not
four draws from one population. A ρ over four such points is descriptive, not inferential, and the
paper must say so. `arXiv:2606.18166` has the same weakness, which is worth noting in E3 rather
than quietly inheriting.

---

## A — Serviceless preparation

> **A3 comes before every run below, and that ordering is the point.** The previous roadmap
> marked P6 as `[cheap]` *once runs exist*; that is backwards. If the counters are not in place
> first, the 100+ runs in B and C produce no truncation data and have to be repeated.

- [x] **A0 — Collapse the queue into this file** `[done]` **2026-08-09**
      Old §2/§3/§4 checkboxes migrated here with dependencies written down; the n=100 + CAPE
      decision recorded in long-term memory. *(This item is what produced this file.)*
- [x] **A1 — P8: scope the four over-general claims** `[done]` **2026-08-09**
      All four now carry a *Scope of the claim* bullet; `related-work.md` gained a section-level
      scope statement. Two were not about the model at all: **§3.3's sampler finding is an
      ik_llama.cpp engine property**, and **§1.5.2 is server-free** — this audit's own first pass
      had mis-recorded it as model-bound, when the real limits are the retrieval index and a
      stated dominance assumption. **P8 `EXPOSED` → `PARTIAL`**; the empirical half stays open
      until **C6**.
- [x] **A2 — P9: pin model identity** `[done]` **2026-08-09** → new **§2.0** in the findings log
      **Model closed.** GGUF sha256 `d0de70ef…c4ea` (computed here *and* matching the HuggingFace
      etag), HF revision `cfd350fd…1f0d`, retrieved 2026-05-11, quantised by Unsloth over
      `Qwen/Qwen3.6-35B-A3B`, and the **imatrix calibration dataset is named** — most papers
      reporting a quant level cannot say which imatrix produced it.
      **Engine closed too, but not by the artifact.** `llama-server --version` prints
      `version: 0 (unknown)` because the build tree was never a git checkout. The commit —
      **`eb570eb96689c235933b813693ca28ab9d3d26de`** (*"MTP: Avoid per step SSM copy (#1778)"*) —
      was recovered from the depth-1 clone vendored at `external/ik_llama.cpp` and **proved** to
      describe the build: identical 837-file source lists, and with CR stripped **exactly one file
      differs — the generated `common/build-info.cpp`**.
      *Corrected the same day:* my first pass called the commit unrecoverable and pinned hashes
      only. I had searched the build tree and stopped. Also retracted: the "upstream anchor at
      PR #630" — the commit references **PR #1778**, so that vendored directory is stale.
      Two things fell out that are not bookkeeping: the GGUF **proves the hybrid recurrent
      architecture** (SSM keys + `full_attention_interval=4`) that explains the 2026-08-07
      re-prefill timeouts, and **we serve at half the model's native context** (262,144 → 131,072),
      which is P6's problem. Also found: the documented launch command (`--n-cpu-moe 36`) is **not**
      the one the service runs (30 blocks, not 36). → **P9 `PARTIAL`** — everything is identified,
      but the binary could not identify itself and recovery depended on luck
- [x] **A3 — P6 instrumentation, before any run** `[done]` **2026-08-09**
      New `src/maljan/core/truncation_ledger.py`, built to the `TokenLedger` pattern: one
      thread-safe instance per run on the container, snapshotted into `RunSummary.truncation` by
      the judge node, rendered as a **Bounds Hit** table. Counts tool-output guardrail decisions
      (pass-through / summarised / hard-truncated + chars dropped), ReAct step-cap hits, judge
      token-cap hits, and — for C7 — how often the STIX integrity pass **fires** and what it
      removes, attributed by reason. Instrumented at both guardrail copies (`mcp_client` and the
      production `ghidra_http_client`) and both integrity-pass call sites (judge post-process and
      the extended renderer), or the aggregate would undercount.
      **The denominator is the point:** pass-throughs are counted too, so the rate is not computed
      against the wrong base. **45 unit tests**, including that telemetry never raises and that
      concurrent analysts do not lose counts. → **P6** measured at **C7**, **C7** at **B4**
- [x] **A4 — Counter-search the five `OURS` rows** `[done]` **2026-08-09** — **three demoted**
      | row | adjacent field | outcome |
      |---|---|---|
      | **C5a** | IR score calibration | **→ `REFINEMENT`.** `arXiv:2604.03676` (abstract fetched and confirmed) evaluates confidence/AUROC as a dimension distinct from retrieval effectiveness; the separate-axes framing is theirs. Ours may keep the measured **inversion** (lexical gates better, semantic ranks better) |
      | **N4** | grammatical error correction | **→ `REFINEMENT`.** Over-correction is a named failure there and **F0.5 exists precisely because false corrections cost more than misses**. Ours keeps **non-separability by alignment score** |
      | **N7** | neural text degeneration | **→ `REFINEMENT`.** "Penalties are necessary but insufficient" is settled there. Ours keeps degeneration as a **delivery** failure — ramble → timeout → empty bundle |
      | **C8** | inference latency / prompt compression | **HELD.** That field asks *how fast*; we ask *whether anything came out before the deadline* |
      | **E1** | temporal generalization of LMs | **HELD but must be reframed** — that literature varies the **train/test gap**; we hold the model fixed and vary the **input's era**. Different axis, and the paper may no longer call temporal effects unstudied |
      **Ledger: 5 `OURS` → 2.** This hits the framing directly — Part F's "sharpest chapter" was
      C5a + N4 + N7, and all three demoted. **D3 must re-decide on that basis.** GEC and
      degeneration rows are demotions *pending full-text confirmation*; demotion is the safe
      direction, but each must be read before the paper cites it.
- [x] **A5 — Build the B1 harness** `[done]` **2026-08-09** →
      `tests/evaluation/eval_consensus_ablation.py` + **36 unit tests**
      Three arms — `single` (all channels, 1 call at B), `negotiated` (K channel analysts **plus
      the mediator**, K+1 calls at B/(K+1)), `noise` (negotiated with one analyst fed another
      sample's channel, Bertalanič & Fortuna's stochastic control). Metrics: precision / recall /
      F1 against fixture ground truth, invalid-id rate, estimated token cost; mean ± bootstrap CI
      plus **paired** F1 deltas, since every arm sees the same samples in the same order.
      **The design decision that mattered:** `eval_view_decomposition`'s bundles annotate each
      artifact with `[associated technique: T1234]`. That is fine there — it scores *grounding*.
      Here the metric is **accuracy against ground truth**, so a leak would let every arm score
      perfectly by copying. This harness builds its own evidence from a technique→artifact map in
      which each artifact *implies* its technique without naming it, and **aborts at startup if
      any id leaks**. Verified: 5 fixtures × 3 channels, 5 artifacts each, **zero leaks**, budget
      split exact (2400 = 4 × 600).
      Two more traps closed by tests: an **empty prediction scores 0 precision**, not 1 — saying
      nothing is the degenerate equal-budget strategy and must not win a column; and the
      **mediator is paid out of the same budget**, or `negotiated` quietly outspends `single`.
- [x] **A6 — Frontier-arm plumbing** `[done]` **2026-08-09** → `src/maljan/core/frontier.py`,
      `LLMConfig.frontier`, **27 unit tests**
      No new provider code was needed — `OpenAIConfig.base_url` already supports OpenAI-compatible
      endpoints. What was needed is the part that spends the author's money safely: a `CostMeter`
      whose ceiling is checked **before** each call, not reconciled after, because a call already
      made cannot be un-billed. Projections price output at the **full cap** (a degenerate decode
      produces exactly that — §3.3), real cost is charged from observed `usage_metadata`, and a
      response without usage is still charged from an estimate, because an uncharged call is a
      hole in the ceiling.
      **Zero pricing disables the arm rather than making it free** — a meter that cannot price a
      call can never refuse one. The shipped default is disabled *and* unpriced, so a fresh clone
      or CI is never one env var away from billing someone.
      One real defect found by its own test: `$0.30 + $0.12 = 0.42000000000000004` in IEEE-754, so
      a strict `>` refused a call landing exactly on a round limit. Fixed with a 1e-9 USD epsilon
      — representation slack, not a spending allowance, and there is a test pinning that
      distinction.
- [x] **A7 — `make check` clean** `[done]` **2026-08-09** — **2376 passed / 12 skipped**, lint,
      format and mypy clean. Baseline was **2268 / 12** (Qdrant down); *the "2238" carried in the
      old roadmap was stale by 30 tests*, measured directly by running the suite with A3's new
      files excluded. Progression: 2268 → **2313** (A3) → **2349** (A5) → **2376** (A6).
      **The A layer is complete. Nothing below runs without a service.**

## B — llama-server, fixture-based (one slot, sequential)

> Memory: llama-server ~16.2 GB; fixture runs do not load the full analysis pipeline, so the
> ceiling here is ~18–20 GB. `scripts/overnight_watch.sh` stands guard at a 3 GB floor and writes
> a STOP sentinel rather than killing anything.

- [x] **B0 — Pre-flight** `[done, and superseded]` — the checklist ran before every B and C item.
      It has since been replaced by machinery rather than discipline: `night_guard.sh` watches
      memory, heat and its own scheduling latency, and `night_track_b.sh` refuses to start a heavy
      step while the STOP sentinel is down. Kept for the record; do not re-run by hand.
- [x] **B1 — E.2 consensus ablation** `[done]` **2026-08-09** → **§3.7**, `consensus_ablation.md`
      **The defence did not hold.** n=25 per arm, all arms complete, equal budget B=2400.
      | comparison | mean F1 delta | 95% CI | verdict |
      |---|---|---|---|
      | `negotiated` − `single` | **−0.016** | [−0.084, +0.050] | **no separation**, at **3.2× tokens** |
      | `negotiated` − `noise` | **+0.061** | [+0.012, +0.110] | mediator **reconciles**, not inert |
      Heterogeneous evidence channels — the exception the literature named, and our whole defence —
      **did not rescue the multi-agent design**. The token ratio (1039 vs 325) lands inside
      Bertalanič & Fortuna's reported 2.1–3.4×, so this **replicates** them in a new domain.
      The arms fail differently: decomposition buys recall (0.432 vs 0.416), pays precision
      (0.370 vs 0.413) — an F1-only reading hides that.
      **Bounding limit:** one mediator pass, not production's multi-round negotiation with revision
      and dissent. This tests decompose-then-reconcile, **not** iterated negotiation. Channels are
      also clean, and `arXiv:2604.02460`'s crossover favours single agents exactly there —
      degrading them is the direct follow-up. → **E.2 answered; F1 closes; D3 resolves toward F3**

- [x] **B2 — Does verbal confidence predict correctness?** `[done]` **2026-08-09** → **§3.8**
      **The number is nearly a constant.** 210 scored claims (4 excluded and counted).
      | scope | AUC | separation | mean conf | accuracy | overconfidence |
      |---|---|---|---|---|---|
      | all | **0.550** | +0.014 | 0.984 | 0.371 | **+0.613** |
      | static | 0.648 | +0.043 | 0.961 | 0.250 | +0.711 |
      | dynamic | **0.500** | +0.000 | **1.000** | 0.607 | +0.393 |
      | network | **0.428** | **−0.022** | 0.984 | 0.186 | +0.798 |
      Kumaran replicates in a setting his suite did not cover — and **worse than
      miscalibrated**: all 210 claims sit in **one** bin [0.8, 1.0), `dynamic` is **exactly 1.000**
      throughout (so its AUC 0.500 is arithmetic, not discrimination), and `network` is **below
      chance**. A miscalibrated score can be recalibrated; a constant cannot.
      **Instrument check ran first:** both ISR parse paths default confidence to **0.5**, so a
      silent model would have made this a study of our own parser. The default **never fired** —
      every claim is ≥0.8. The values are the model's own.
      → justifies every deterministic gate; converges with §1.10; **sharpens B5**, which now tests
      whether C3's cap does anything given that its input does not

- [~] **B3 — Layer-0 LLM arm** `[done]` **2026-08-09** → **§3.9**; **re-opened** by §3.21,
      attempt 1 void (§3.22), attempt 2 **built and unrun** (§3.23) — harness `[LLM]`, 80 judge
      calls, no CAPE needed
      **The corroborated set does not reach the verdict.** 60 judge calls, 0 skipped. The
      manipulation worked — corroboration swung **3 → 0** between arms — and the final bundle's
      technique set was **identical every time** (0/15 changed on every arm, Jaccard 1.000,
      CI [1.000, 1.000]).
      With §1.10 the pair reads: *the weights do not move the corroborated set, and the corroborated
      set does not move the bundle.* **The corroboration apparatus is downstream-inert on this
      evidence.**
      **Stated because the design guarantees part of it:** every technique had two sources, so
      technique *survival* was baked in. B3 does **not** show that losing evidence is harmless — it
      shows corroboration *status* changed sharply and propagated nowhere. Also: the pre-registered
      `no_tool_artifact` prediction was confirmed and is **uninformative**, because in a run where
      nothing changes, "nothing changed" supports no particular mechanism.
      → **C6 cannot be claimed on this evidence**; E.5 answered for the mechanism, not the impact
- [x] **B4 — C7 LLM arm** `[done]` **2026-08-09** → **§3.10**
      Integrity pass ran on **60/60** bundles, removed something on **3 (5.0%)**, **3 objects
      total**, every one an `empty_pattern` — an indicator whose pattern stopped mid-generation. No
      duplicates, no dangling relationships.
      "Repairing beats rejecting" cannot rest on that. Not a refutation either: the evidence here is
      constructed and consistent, so there is little to repair. **C7 needs a population where the
      defects occur.** **Superseded 2026-08-14 (§3.27):** the B3 re-run's 80 fresh bundles are that
      population — 15 of the 51 that ran the pass had objects removed, across all four defect
      classes. C7's premise is measured; the head-to-head repair-vs-reject comparison is not.
      Worth keeping: the one defect class observed is §3.3/§1.7.1's budget exhaustion showing up in
      the *artifact* rather than the token stream.

- [~] **B5 — C3 ablation** — **cheap half `[done]` 2026-08-09** → **§3.11**; LLM half still open
      **The only grading mechanism fires on 0.82% of techniques.** 189 samples, 1,348 techniques.
      Gated techniques are *common* (306, 22.7%) and the evidence check is *decisive* when reached
      (44% of eligible get capped) — the bottleneck is the **sole-static precondition**, and the
      source breakdown says why: **257 of 306 gated techniques (84%) come from `yara_layer` alone**,
      so there is no static claim to discipline. Not "disarmed by a redundant detector" — the
      population it targets barely exists on this evidence. Corpus-wide: **11 capped, 11/189
      samples (5.8%)**.
      **Third leg of one story.** §3.8 the confidence value is near-constant · §3.9 the corroborated
      set does not reach the verdict · §3.11 the mechanism that grades confidence is a near-no-op.
      **The whole confidence-and-trust apparatus produces almost no differentiated signal.**
      **Bounding limit:** no LLM analyst in this run, so the `static` domain is under-populated
      relative to production — 25 eligible is a **lower bound** and the real rate will be higher.
      The LLM half (`[LLM]`) measures that and remains queued.

- [x] **B6 — C1 ablation** `[done]` **2026-08-11** — frequency §3.15 (fires on 58%, later 56.7%),
      effect §3.18 `NEGATIVE` (the hint does not change what the analyst finds).
      `sink_hint_ablation_scored.json`. *Original note, kept: mis-tagged until 2026-08-09.*
      Sink-reachability steering has a clean config gate (`use_sink_reachability`, default True),
      so the ablation itself is simple. What is not simple is the input: the module is pure and
      deterministic, but it consumes a **call graph from Ghidra MCP `get_full_call_graph`**. There
      is no fixture path — a synthetic call graph would test the ranking code, not the claim.
      **So B6 cannot run alongside B1–B5 on llama alone; it needs `make docker-up` for Ghidra.**
      Schedule it with the service-heavy items rather than with the fixture harnesses.
      *Note for the write-up:* the module's own docstring says a binary without named sink callees
      (a stripped, statically linked ELF) yields an **empty hint** and the analyst falls back
      silently. The ablation must therefore report **how often the hint is non-empty at all**,
      or a null result will be indistinguishable from a feature that never fired — the same trap
      B5 was reframed around.

- [x] **B7 — C2 tier contribution** `[done, both tiers]` — semantic **§3.12**, opcode-hash **§3.17**
      **Half of this was done and the queue did not know.** Two leakage-free artifacts already in
      `tests/evaluation/` measure the family-feature RAG tier: retrieval in isolation
      (**recall@5 0.199 vs 0.032 random — 6.3× chance**, 158 families / 629 samples) and an
      end-to-end A/B (**n=19: F1 +0.0029, precision −0.0088**).
      **It repeats §1.5.3 exactly** — a retriever that works six times better than chance in its own
      terms moves the pipeline by +0.003 F1 while lowering precision. Two independent retrieval
      components, both functional in isolation, both near-inert wired in.
      **But n=19 with no CI** — the honest statement is *no effect detectable at n=19*, not *no
      effect*.
      **The opcode-hash tier was measured on 2026-08-14 (§3.17) and this entry did not know it:**
      0/18 samples fire, 7,716 functions hashed, **0 matches**, on an empty-in-practice corpus with
      a structural instruction-count floor that excludes half the samples regardless. Both tiers are
      therefore measured and the two-tier claim cannot be made. Third independently-built retrieval
      component to be reasonable in isolation and inert once wired to real inputs (§1.5.3, §3.12,
      §3.17) — which makes it the project's most-replicated result rather than three anecdotes.

- [x] **B8 — Frontier arm on the fixture suite** `[done]` **2026-08-12** — §3.16, `frontier_probe.json`.
      n=25 paired, ΔF1 **+0.0026** [−0.0770, +0.0814]; reasoning is **56.5%** of output tokens.
      The n=9 first attempt was quota-truncated and pointed the wrong way — see §3.29.
- [x] **B9 — Commit the B layer** `[done, continuously]` — every B item landed in its own commit
      with its findings-log section as it completed, rather than in one batch at the end; the model
      server is stopped after each. The batching this entry assumed never happened, which is why it
      sat unticked while the work it describes was finished.

## C — The CAPE network (dynamic path) — n=97 recovered of an intended 100 (§3.24)

> **The tightest memory profile in the queue:** llama-server 16.2 GB + an arq analysis ~8.5 GB
> ≈ 24.7 GB of 30 GB. Never start with the desktop stack loaded. Watcher up for the whole run.

- [x] **C0 — Connect** `[done]` — cohort submitted and fetched; **97 reports** in `data/cape_reports/`
      Three lines into `.env` — there are currently **zero** `MCP__CAPE__*` keys:
      `MCP__CAPE__ENABLED=true`, `MCP__CAPE__TRANSPORT=streamable-http`,
      `MCP__CAPE__URL=http://10.65.0.40:9004/mcp`. Then `make docker-up` and **one clean
      end-to-end run** on `4565983c…`. Maljan-side config only; the CAPE tunnels and VM are not
      touched.
- [~] **C1 — 36-tool CAPE MCP verification** — **dropped 2026-08-14, recorded as a limitation**
      A plumbing check rather than a measurement: it needs the sandbox network, contributes no
      finding, and the tools it would verify are exercised by every run in the C layer already. The
      honest statement — that individual MCP tool reachability was never enumerated — goes in the
      reproducibility appendix instead of being carried as queue work that would never earn its
      wall-clock. → **E5**, one sentence
- [x] **C2 — Sigma / LOLBin / network-DGA layer contribution** `[done, both halves]` **2026-08-14**
  - [x] layer contribution `[done]` **2026-08-14** — `layer0_six.json`: sigma fires on **94/97**,
        lolbin **0/97**, network_dga **0/97** (§3.23). The two silent layers are why B3 runs four
        sources rather than six.
  - [x] **C2b — weight sensitivity with the dynamic layer in play** `[done]` **2026-08-14** —
        §3.30, `weight_sensitivity_six.json`. §1.10's five perturbations repeated over the full
        six-source assembly on the 97 archived reports. **The pre-registered prediction failed, and
        that is the result.** `sigma_layer` fires on 94/97 and supplies the third domain §1.10 said
        was missing — and the corroborated set still moves on **0/97** under every perturbation
        (top-10 ranking moves on 12.4–28.9%, so the constants do order things; they are simply
        disconnected from the one field the cascade exists to compute). The domain distribution
        moved the *wrong* way: **89.9% of techniques are seen by exactly one domain** with the
        sandbox in play, against 87.9% without it, and **none reach three**. `tool_artifact`
        produces a claim on **1/97**. C2 is now closed in both halves.

- [~] **C3 — redesigned; the original experiment was vacuous and is not being run** `[LLM]`
      *Original scope: flat union vs the weighted cascade on the recovered cohort.* **Cancelled
      2026-08-14 and replaced, on evidence.** §3.27.1 established that both arms share one
      `cascade_summary.results`, so `_reconcile_with_cascade` forces both bundles to contain the
      same techniques whatever the judge produces: the comparison could only ever return "no
      difference", correctly and vacuously. It was stopped four minutes into its first run.
  - [x] **C3′ — what the judge contributes to the bundle** `[done, NEGATIVE]` **2026-08-15** —
        §3.36, §3.37. The measurement the vacuous design could not reach, run in **two
        conditions** because a defect found mid-run made the pair a controlled experiment.
        **Judge share of the final bundle: 0.0%** (0 of 99) in both, with **76%** of its
        attack-patterns dropped for naming no technique and 3 of 4 completed calls producing
        nothing nameable at all. **Half the calls never reached the seam** — 4 of 8 fall back,
        where reconciliation never runs and the cascade is never consulted.
        **And the inversion (§3.37):** with the output cap fixed the same four fixtures still
        fail, but the fallback now scrapes ATT&CK ids out of the model's unparseable decode —
        **47 techniques reach the analyst that the cascade never held**, none the other way, one
        bundle doubling. The model has no influence when it works and the most influence when it
        fails. Four harness defects were fixed to get here, each of which would have produced a
        number that looked like a finding: a per-request timeout tighter than production's, a spy
        that read zero patterns from every fallback by construction, an output cap that never
        reached the server (§3.35), and `bind_eval_llm` discarding the provider's `extra_body`.
- [~] **C4 — Dynamic cohort vs static-only, paired delta** — **closed incomplete at 13 of 97 pairs**
      **2026-08-14**, §3.26. Stopped after five supervised attempts produced **zero** completed arms
      in 70 minutes: each began with ~22 GB free, drove the box into swap, and was killed by the
      memory guard at its 4 GB floor before finishing one ~40-minute arm. 26 of 194 arms are on disk;
      the remaining 168 **cannot be completed on this machine**, which is now measured rather than
      predicted.
      **The effect estimate is recorded and deliberately not interpreted** — F1 +0.0030
      [−0.0177, +0.0230], recall +0.0024 [−0.0151, +0.0188], precision −0.0701 [−0.1392, −0.0072].
      **And there is a second reason not to interpret it, added 2026-08-15: the 13 pairs that
      completed are not a random 13.** Arms were killed by the memory guard, and what a pair costs
      in memory scales with how much evidence its sample produces — so the survivors are
      systematically the *cheap* samples, on the exact axis the study is about. The estimate is
      therefore biased as well as underpowered, and no amount of additional wall-clock on this
      machine fixes the first problem. Closing incomplete is the right call rather than a
      concession.
      **Nothing in the paper depends on it** (checked 2026-08-15): E1 makes no claim about the
      dynamic path's contribution, and the only mentions anywhere are E3's description of the
      static-only fallback and an E5 data-manifest row. C4 would have added a result; its absence
      does not leave a claim unsupported.
      §3.16 is why: a difference read off an underpowered arm is unreliable, not weak, and the
      frontier arm's n=9 estimate moved 0.086 when completed. The precision interval is not exempt —
      12 of 12 pairs carry a degradation reason the treatment does not explain.
      **What survives the sample size is a mechanism observation**, because it is not a difference in
      means: across all 13 dynamic arms the two sources that consume the sandbox report — `dynamic`
      and `network` — **claimed nothing at all**. → **E.3**, as a stated limitation
- [x] **C5 — Baseline with no LLM at all** `[done]` **2026-08-14** — §3.26, `cape_baseline.json`.
      CAPE alone: **F1 0.1526** [0.1344, 0.1709] at n=97. Every F1 in this paper now has a referent.
      CAPE's own signature-derived TTPs on the same recovered cohort. **Without this, "F1 0.08" has no
      referent** — arguably the single highest-value item in the queue. → **E.4**
- [x] **C6 — Parameter-size series** `[done, NEGATIVE]` **2026-08-14** — §3.32, §3.33, §3.34.
      *The cohort stage was never reached and would not have helped; see C6b.* `[network]`
      *Rescoped 2026-08-14 from "one frontier arm" — see the decision table above.* Four models,
      35B → 744B total parameters, each answering on the same evidence with the same output budget.
      `arXiv:2606.18166` found parameter size the **only** significant predictor of
      ATT&CK-classification F1 (ρ=0.85, p=0.014); this tests that trend rather than sampling one
      point on it. → **E.4 + E.8 + P8**
      Runs in two stages, because the endpoints' rate limits make them different experiments:
  - [x] **C6a — the series on the §3.7 fixtures** `[done]` **2026-08-14** — §3.32, §3.33.
        Four arms ran to completion at n=25 each: Nemotron-120B re-run with the reasoning flag
        (**ignored by the provider** — 56.2% reasoning, F1 0.4149, a replication of §3.16 at
        Δ=−0.0014), and `qwen3.6-35b-a3b` hosted in **both** configurations (off: **0.3507**;
        on: **0.0080**, 24/25 calls exhausted on reasoning). Two results the series was not
        opened for: **quantisation is bounded** — our 3-bit local deployment is 0.0629 *above*
        the vendor's own hosting of the same weights, CI [−0.1484, +0.0256] — and the reasoning
        flag **replicates at 0.3427 paired** on the model we host. Cost $0.18.
  - [x] **C6b — the series** `[done, NEGATIVE]` **2026-08-14** — §3.34. **Not run on the cohort,
        and the cohort would not have helped.** A size correlation needs the arms matched on the
        flag that outweighs the size effect, and no provider above 35B honours it: DashScope does,
        OpenRouter accepts and ignores it (§3.32). Two configuration-matched arms survive and both
        are 35B — two points at one size. `eval_parameter_size_series.py` now refuses and names the
        excluded arm with its measured reasoning share. **The harness reported ρ=+0.866 before the
        gate existed**, from five rows that were three models; that near-miss is recorded in §3.34.
        → **P8 closes as a limitation with a measured cause, not a budget excuse.**
- [x] **C7 — Close P6** `[done]` **2026-08-14** — §3.28. Step budget hit on **82.1%** of arms (always at
      exactly 19 tool calls / 41 messages), a tool output cut on **83.9%**, evidence chunked on **48.2%**.
      P6 `EXPOSED` → `PARTIAL`, not `CLEAR`: frequency is reported, **impact is not**, because with 46 of
      56 arms at the same cap there is no unaffected control group to compare against.
      Truncation frequency distribution from A3's counters: how many runs truncated, how many
      chunks dropped, how often `max_steps` was hit — **and the performance impact**. Exactly what
      the pitfall asks for. → **P6 `EXPOSED` → `CLEAR`**
- [x] **C8 — Commit the C layer** `[done, continuously]` — as B9: per-item commits, services
      stopped after each run. Verified 2026-08-15: working tree clean, no llama-server or arq
      process alive, 22 GB free.

## D — Closing measurements and decisions

- [x] **D1 — Readability assessment (internal, LLM-based)** `[done]` — §3.20, `narrative_quality.md`.
      Stays out of the paper as decided; E.7 remains an open limitation.
      15 reports scored on a rubric (structure, traceability, redundancy, actionability),
      deterministic template vs LLM narrative, blinded. Recorded in `findings-log.md` **explicitly
      labelled an LLM-based internal instrument**, used to steer development.
      **It does not enter the paper.** The reason is the project's own audit: `self-audit-pitfalls.md`
      scores P2 `CLEAR` on the strength of one sentence — *"LLM-as-a-judge was never used for
      scoring"* — which is a line most of the 72 papers in the NDSS'26 survey cannot write. Any
      LLM scoring in the paper costs that row, and unlabelled LLM scoring presented as human
      evaluation is not recoverable. So **E.7 remains an open limitation in the paper: no human
      analyst has scored a report.**
- [x] **D2 — YARA corpus licence review** `[done]` **2026-08-09** — **E.6 unblocked, and a
      mis-description found that matters more than the licence did**
      **Licence: clear.** `data/yara_ttp_rules.yaml` is 30 **in-house** rules; the `.yar` files in
      the tree belong to **CAPEv2**, not us. Each rule is a list of literal substrings — Windows
      API names, documented registry paths — which is public nomenclature, not third-party
      creative expression. **Publishable verbatim** in E5.
      **But they are not YARA rules.** No YARA syntax, no conditions, no modules: `YaraLayer` does
      **case-insensitive literal substring matching**. Calling them YARA rules in a security venue
      overstates the mechanism, and the naming is already load-bearing — the cascade gives the
      `yara` domain the **highest weight (0.90)**, which reads as *an engine matched* when it means
      *a string appeared*. Worse, the codebase uses **real** YARA elsewhere
      (`detection_signatures.py` calls `yara.compile()` to validate rules Maljan *emits*), so one
      word would do two jobs in one paper.
      **Write-up action:** call it a **deterministic literal-pattern layer**; describe real YARA
      separately as output validation. No code rename — that would break the layer names §1.10
      already published under. → **E.6**
- [x] **D3 — Framing locked: F3 on an F4 spine** `[decided 2026-08-11]`
      **B1 came back null** (§3.7: `negotiated − single` = **−0.016**, 95% CI **[−0.084, +0.050]**,
      at **3.2× the tokens**). That closes **F1**: there is no equal-budget win for heterogeneous
      evidence channels to lead with, and claiming one would require the interval to exclude zero.
      The condition written here before the experiment is met, so the branch is taken as written.

      **What replaces it is stronger than this entry anticipated.** The spine is no longer "a set of
      honest negatives" — it is **measurement validity in LLM security pipelines**, and 2026-08-10
      supplied the material that makes it a contribution rather than a confession. Three defects
      were found in one day, all of the same species: the instrument returned a **plausible wrong
      answer with no error anywhere**.

      | defect | what it silently produced | §  |
      |---|---|---|
      | MCP client sent `null` for unset optional args | all 36 CAPE tools refused, pipeline unaware | 3.13 |
      | `load_program` never switched Ghidra's current program | every sample after the first described the **first** binary | 3.14 |
      | a refused load answers **HTTP 200** | hints and function hashes built from another binary | 3.14 |

      Each was caught by the same cheap detector — **a number that repeated where variation was
      expected**: an identical 2,575-char hint across unrelated samples, a call graph identical to
      the character across binaries of 241 KB and 139 KB, 66 consecutive samples at 75,426 chars.
      None was caught by a test suite of 1,995 passing tests, because each needs a *second* case in
      one server lifetime and a unit test writes one.

      That is the paper: **the failure modes that survive a green test suite, the detectors that
      catch them, and what they cost when they do not.** The negatives (§3.7–§3.12) become evidence
      for the thesis rather than the thesis itself — an instrument that cannot be trusted produces
      exactly the near-zero effects this project kept measuring, and telling those two situations
      apart is the skill the paper teaches.

      **Narrowed 2026-08-11 by counter-search, and the narrowing is not cosmetic.** The *genus* is
      already described: `arXiv:2606.14589` studies a production LLM agent runtime, documents 22
      incidents over eight weeks, and defines exactly this meta-pattern — *"a failure whose error
      signal never reaches a human in actionable form"* — with a five-class taxonomy our three
      defects fall into without strain. The detector is an ordinary metamorphic relation. So the
      contribution is **not** "silent failures exist at tool boundaries", which is known.

      What is left, and what E1/E3 must claim instead: three mechanisms at three *different*
      integration boundaries (MCP argument encoding, server-side current-program state, HTTP status
      versus body); the setting — an **evaluation pipeline for security research**, where the
      output is not a degraded user session but a *measurement that is wrong and looks right*; the
      output-cardinality check reported **alongside the result** rather than run as a test; and the
      cost, demonstrated rather than hypothesised — **E1 withdrawn**, because its per-sample outputs
      were not retained and the question can no longer be asked of it. The taxonomies report
      incidents; we report what an incident of this class does to a result already written down.

      **Two supports that were missing are now in place.** §3.15 shows the frequency-before-effect
      discipline paying (the sink hint fires on 58%, so its ablation is interpretable, where §3.11's
      cap fired on 0.82% and its was not). And **C5** finally anchors the numbers: CAPE alone scores
      **F1 0.187** on the cohort, so every pipeline figure now has a reference instead of floating.

      **Also retracted in the same period, and both belong in the paper:** the "10,348-deep queue
      makes live submission impossible" reading (§3.13c — the backlog is never scheduled at all),
      and the n=210 temporal-drift result (§3.14 — it meets the stale-program precondition and its
      per-sample outputs were not retained, so it cannot be checked and must be re-run).
- [~] **D4 — Finalise the ledger and the self-audit** — C6 closed `NEGATIVE` and C7's premise
      measured on 2026-08-14 (§3.27); **0 `UNMEASURED` rows remain**. Still to do: re-issue the
      P6/P8/P9 verdicts. Original scope was to update the four `UNMEASURED` rows with
      their results; re-issue the P6/P8/P9 verdicts

## E — The paper — last

- [~] **E1 — Results / Evaluation** — **written and current**; `E1-results.md` builds as §Results
      and was last revised 2026-08-15 (C3′ both conditions, the quantisation bound, the frontier
      confound). Left open only for the final read-through once E3 and E5 catch up.
- [~] **E2 — Threats to Validity** — **written and current**; `E2-threats-to-validity.md` builds
      as §Threats and carries the re-issued P8 (2026-08-15: the matched arm cannot be built, the
      quantisation threat is measured and points the other way, the size series cannot be tested
      here). P3's residual — the LLM's training data is unknown to us and memorisation was never
      probed — is acknowledged there as the pitfall itself recommends. Left open for the final
      read-through.
- [x] **E3 — Related Work, final** `[done]` **2026-08-15**, citations verified the same day —
      **[21] and [23] were both wrong and are corrected.** [23] was cited for "duplicating dataset
      items to verify identical inputs score consistently"; the paper does not do that — it perturbs
      formatting, paraphrase, verbosity and the ground-truth label. [21] was quoted verbatim for a
      sentence that is not in it, exactly as its own audit row had warned. [22] verified clean
      (title, authors, DOI, and the "notorious oracle problem" phrasing we rely on). [24] was
      already verified. **Citation debt cleared the same day: [16]–[25] have all been fetched.** Three were wrong —
      [21] quoted a sentence that is not in its source, [23] was cited for a practice its source
      does not describe, and [18]'s mechanism blended two incompatible accounts (Welleck blames the
      likelihood objective; the data-side account is a different paper's). [17] re-anchored to the
      CoNLL-2014 and BEA-2019 shared tasks, which document the F0.5 convention directly. [19]
      verified word for word. Five arXiv ids that had been carried as company for fetched
      citations, and never themselves fetched, are dropped rather than kept as decoration.
      *(original entry follows)* — the M6/M7 counter-search folded in as
      [24] and [25] with per-citation verification status, `arXiv:2604.00025` recorded as owning
      M6's phenomenon, and one claim added about where the published taxonomy *ends*: its five
      classes each describe a call to something else, and three of our seven mechanisms crossed no
      boundary at all. Offered as a proposal — attribution rather than boundary — not a taxonomy.
      *(Original scope text: `related-work.md` exists as a draft; fold in the new results.)*
      and whatever A4's counter-searches turn up
- [~] **E4 — the paper** — skeleton and build pipeline done (`build_paper.py`, markdown → LaTeX →
      39 pages, anonymity check in the build); **abstract and introduction rewritten 2026-08-15**,
      which they needed: they described four boundary defects when there are seven mechanisms and
      three are not at a boundary, credited the cardinality detector with all of them, quoted a
      test count 671 short, and omitted the strongest result of the week. Cross-section number
      sweep run afterwards — no stale count survives. **Remaining: venue formatting and a
      read-through of the assembled PDF rather than of the sections.**
- [x] **E5 — Reproducibility appendix** `[done]` **2026-08-15** — the comparison endpoints now lead
      with the configuration axis rather than the model names, because `enable_thinking` is honoured
      on one provider and accepted-and-ignored on another and the flag outweighs every model in the
      table. Adds the two things a reader reproducing on `ik_llama.cpp` would otherwise lose a day
      to: the output cap must travel in `extra_body`, and the server truncates silently at
      `finish_reason: "stop"`. Six harnesses and five artifacts added to the manifests; every file
      named was verified present.
      *(Original scope text: scripts, data manifests, seeds, the model digest and)*
      engine commit from A2, harness commands. The full answer to P9.

---

## Claim status

Definitions in [literature-review-brief.md](literature-review-brief.md) Part B; verdicts from
[novelty-ledger.md](research-briefs/novelty-ledger.md).

| # | Claim | Evidence | Verdict | Closed by |
|---|---|---|---|---|
| C0 | LLM-as-analyst vs LLM-for-a-trained-detector taxonomy | positioning | — | E3 |
| C1 | Sink-reachability transferred JS→binary as prompt steering | **fires on 56.7%** (55/97, §3.15); paired ablation on the firing subset: **Δtechnique IDs +0.50, CI [−3.33, +4.50]**, n=6, direction 2/2/2 (§3.18) | **NEGATIVE — measured** | closed |
| C2 | Two-tier attribution (opcode-hash + semantic RAG) | semantic +0.003 F1 (§3.12); opcode-hash **fires 0/18** (§3.17) | **NEGATIVE — both tiers measured** | closed |
| C3 | Falsification-before-confidence protocol | **measured**: the cap fires on **0.82%** of techniques (§3.11) | `REFINEMENT` of FAX — and now a measured near-null | closed |
| C4 | "Use a tool ≠ expose it" — 20-tool allowlist | §2.2 measured | open gap | E1 |
| C5 | Describe-then-map | §1.5.1/§1.5.2 measured | **PRIOR ART** `2401.12178` | cite only |
| C5a | Rank and gate are separate axes | N=4,913 TRAM2 **+ AnnoCTR** | **REFINEMENT** — `2604.03676` owns the framing | keeps the *inversion* |
| C6 | Multi-layer corroboration cascade | **measured** (§3.27): 80 judge calls, four firing layers including `sigma_layer` at weight 0.55. Removing a layer while its techniques survive under a partner source changes the verdict on **0/32**, Jaccard **1.000 [1.000, 1.000]**; removing one whose techniques vanish changes it on **32/32** | `NEGATIVE` — the judge reads the claim list. Corroboration is computed, weighted and surfaced in the run summary, and reaches the analyst's artefact **not at all** | closed |
| C7 | Deterministic STIX integrity + honest degradation | **measured** on 80 fresh bundles from the B3 re-run (§3.27): the pass ran on **51**, removed something on **15**, 51 objects, and **all four** defect classes appear — 19 duplicate_attack_pattern, 21 empty_pattern, 8 dangling_relationship, 3 duplicate_relationship. The archived-bundle measurement saw 3 removals in 60, all one class (§3.10) | `PARTIAL → MEASURED PREMISE` — the defect population C7 needed now exists, and rejecting instead of repairing would discard **15 of 51** bundles. Still not a head-to-head repair-vs-reject comparison | truncation distribution (P6) |
| C8 | Schema-pruning hint → completion, not accuracy | n=17 paired | **OURS** — held at A4 | second search before submission |
| N1 | Claim-count is an invalid instrument | measured | `REFINEMENT` | E1 |
| N2 | Equal-budget view decomposition trades grounding for volume | n≈8–9/arm | `REFINEMENT` | E1 |
| N3 | Zero-shot semantic category inference loses to keywords | N=101 | `REFINEMENT` | E1 |
| N4 | Auto-correction damages 38% to recover 21% | measured | **REFINEMENT** — GEC over-correction | keeps non-separability |
| N5 | Deterministic template beats LLM narrative on faithfulness | n=15 (06-04); re-measured 08-12 after repairing the narrative agent: paired ΔF1 **−0.044 [−0.074, −0.015]**. But the retained prose shows the "template" arm is a hardcoded **degradation notice** that wins `coverage_recall` by enumerating technique IDs it declines to explain (§3.20) | `REFINEMENT` — **reframed**: not a stronger narrator, the absence of one, scored by a metric that rewards enumeration | closed |
| N6 | Working retriever, unreachable query; frequency prior wins | measured | `REFINEMENT` | E1 |
| N7 | Degenerate ID loop; sampler penalties insufficient | reproducible | **REFINEMENT** — text degeneration | keeps *delivery* failure |
| N8 | No speculative-decoding gain on A3B MoE | measured | `PRIOR ART`-adjacent | appendix |
| E1 | 7-year drift study, n=210, no measurable drift | n=210, bound ≤0.040 F1 | **SUSPECT — withdrawn pending re-run** | §3.14: meets the stale-program precondition; per-sample outputs not retained, so it cannot be checked |
| M1 | An unset optional MCP argument reached the server as `null` | all 36 CAPE tools refused; pipeline unaware | **OURS** (instrument defect) | §3.13, fixed `716a128` |
| M2 | A loaded Ghidra program never became the *current* one | every sample after the first described the **first** binary | **OURS** (instrument defect) | §3.14, fixed `0720d34` |
| M3 | A refused load answers HTTP 200; the pre-pass carried on | hints and function hashes built from another binary | **OURS** (instrument defect) | §3.14, fixed `3eabf88` |
| M4 | Two local safety bounds composed into an empty result | the 40-step ReAct salvage received a **fresh copy** of the time budget it was already inside; any binary rich enough to exhaust the step budget returned **zero techniques** at 28 min | **OURS** (composition defect) | §3.18, fixed `786dfe5` — verified 1,677s/0 tids → 323s/5 tids |
| M-DET | Repeated-constant detection catches stale-state bugs a green suite misses | 4 defects, 1,995 passing tests, 0 caught | **REFINEMENT** — demoted 2026-08-11 by counter-search; the detector is a **metamorphic relation** (TOSEM `10.1145/3708521`), and `2603.05399` tests the inverse (identical inputs → consistent output). Ours keeps the *application*: an output-cardinality **reporting norm** for evaluation batches crossing third-party tool servers, with three measured defect classes and a withdrawn study as the cost | E1 |
| B0 | CAPE alone, no LLM: the baseline every F1 needed | **F1 0.1526** [0.1344, 0.1709] at **n=97**, the full recovered cohort. Earlier passes: 0.187 [0.151, 0.223] at n=24, 0.1666 [0.1411, 0.1938] at n=43 — each estimate sits inside the previous interval | **measured, closed** | — |
| E2 | KV scaling on hybrid-offload MoE | measured | — | appendix |
| E3 | ~201-tool catalogue infeasible at 3B | measured | open gap | E1 |
| — | binary→ATT&CK input modality | — | **PRIOR ART** `2602.06325` | cite only |

## Framing

*Revised 2026-08-09 after A4.*

| Framing | Rests on | Status |
|---|---|---|
| **F1 System paper** | C0, C4, C6, C7 | **Closed 2026-08-11.** B1 returned null: `negotiated − single` = −0.016, CI [−0.084, +0.050], at 3.2× tokens. There is no equal-budget win to lead with |
| **F2 Describe-then-map** | ~~C5~~, ~~C5a~~, ~~N4~~, ~~N7~~ | **Gone.** C5 was prior art; A4 demoted the remaining three to `REFINEMENT`. Survives as a *confirm-and-add-mechanism* chapter, not a headline |
| **F3 Measurement validity + negative results** | **M1–M4**, N1–N8, §1.5.3, §1.10, §3.13–§3.15 | **LOCKED — this is the paper.** The spine is no longer "honest negatives"; it is the failure class those negatives came from |
| **F4 Drift study** | ~~E1~~ | **Withdrawn as a spine.** E1 meets the stale-program precondition of §3.14 and its per-sample outputs were not retained, so it cannot be checked. It re-enters only if re-run |

**What decided it, and what changed underneath.** B1 was the gate written before the experiment,
and it returned null, so F1 closes on its own terms. But the surviving framing is not the
consolation prize this table described on 08-09. Between then and now, **three instrument defects
were found in one day** (M1–M3), each producing a plausible wrong answer with no error anywhere,
and each caught by the same cheap detector: a number that repeated where variation was expected.
A suite of **1,995 passing tests caught none of them**, because every one needs a *second* case in
a single server lifetime and a unit test writes one.

That is a contribution with a shape: **the failure modes that survive a green test suite in an
LLM-plus-tooling pipeline, the detectors that catch them cheaply, and what they cost when they do
not** — E1's withdrawal being the price paid in this project. The negatives become evidence for the
thesis rather than the thesis itself, because an untrustworthy instrument produces exactly the
near-zero effects that kept turning up.

**The two supports F3 previously lacked are now in place.** §3.15 demonstrates the
frequency-before-effect rule paying (58% firing rate makes the sink-hint ablation interpretable;
§3.11's 0.82% made its uninterpretable), and **C5** anchors every F1 in the paper against a
no-LLM baseline of **0.187** — the thing the results section could not previously do.

---

## How each item is verified

- **`make check` after every item** — lint, format, mypy, full suite. Baseline **2268 / 12
  skipped** (Qdrant down); **2313 / 12** after A3, **2349 / 12** after A5.
- **Pure helpers behind any reported number are unit-tested**, apart from the pipeline — the
  repo's `test_*_scoring.py` convention. If arithmetic decides a default or a claim, it is tested.
- **Before any heavy step, check the STOP sentinel** (`logs/overnight-watch.STOP`). The watcher
  writes it below 3 GB free and kills nothing.
- **One commit per item**, with `findings-log.md` and this file updated in the same commit.
- **Every outcome is written up**, including the ones that cost a claim. A negative B1 is a
  result; A4 demoting an `OURS` row is a result.

### Acceptance criteria for the load-bearing items

| item | criterion |
|---|---|
| **B1** | Do the arms separate at equal budget? If not, **that is the result** and F1 closes |
| **C3** | Does C6 leave `UNMEASURED`, and were per-sample results written to disk? |
| **C5** | Is there a baseline number? After this, every F1 in the paper has a referent |
| **C6** | Is the frontier-vs-local difference measured? P8's empirical half closes here |
| **C7** | Are truncation frequency *and* impact reported? P6 → `CLEAR` |

---

## Operational notes

**When CAPE comes back, in order:** `make docker-up` → `systemctl --user start maljan-llama` →
wait for `slots_idle=1` → the three `MCP__CAPE__*` lines → one clean run on `4565983c…` (C0).

**If llama-server wedges** — the cause of every timeout on 2026-08-07, not a Maljan defect —
`systemctl --user restart maljan-llama` clears it: the same call did not return in 300+ s before a
restart and took 46.1 s after.

**Memory — corrected and sharpened by the B1 run, 2026-08-09.** The old note ("llama-server holds
~16.2 GB") describes a *steady state that does not exist*. Measured across one 75-generation batch:

| moment | llama RSS | avail | note |
|---|---|---|---|
| fresh load | ~9.6 GB effective | 9–12 GB | weights are mmap'd file pages, largely shared with page cache |
| ~40 generations in | 14.9 GB | 5–6 GB | KV cache accumulating |
| ~64 generations in | **17.4 GB** | **3.5 GB** | **machine swapping, 3.9 GB out** |

**The KV cache grows with cumulative requests under `-c 131072 --context-shift on`; it does not
plateau.** A long eval batch therefore needs **periodic llama-server restarts**, not just a memory
floor. Restarting is nearly free — the GGUF is in page cache, so a restart takes ~30 s and returns
the cache to empty. Checkpointed harnesses make it lossless.

**Watch the swap-out *rate*, not swap *used*.** Two thresholds failed on this run, both by
measuring the wrong quantity:
- a 3 GB available floor fired **too late** — the system was already 3.9 GB into swap by the time
  available reached 3.5 GB;
- a "swap used > 500 MB" check fired **too early** — residual swap after a pressure episode is
  harmless, because pages stay parked until touched. Confirmed by `pswpout` not advancing at all
  over 5 s while 4.5 GB sat in swap.

The right pair is **`pswpout` delta** (real writes to swap) plus a **4 GB available** early
warning, which trips before the kernel starts evicting rather than after.

**Consequence for C3, which is the tightest item in the queue.** n=100 with the CAPE dynamic path
means llama (growing past 17 GB unchecked) *plus* an arq analysis at ~8.5 GB. That does not fit,
and a memory floor alone will not save it. **C3 must be run in batches with a llama restart
between them**, and the checkpoint written per sample so a restart costs one generation at most.

**Standing rule, learned the hard way on R2:** search each claim in the vocabulary of at least one
*adjacent* field. Searching only the subfield a claim sounds like will miss the paper that owns it.

**Standing rule on results:** every outcome is written up, including the ones that cost us a
claim. B1 returning negative is a result; A4 demoting an `OURS` row is a result.
