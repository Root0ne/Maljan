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

**The ledger, which governs everything below:** **5 `OURS` · 6 `REFINEMENT` · 4 `PRIOR ART` ·
4 `UNMEASURED`**. Every surviving claim is a *measurement* result; all four architectural claims
are unmeasured, which is why the B and C layers exist. Two framing candidates —
describe-then-map (`arXiv:2401.12178`) and binary→ATT&CK (`arXiv:2602.06325`) — fell to prior art
on 2026-08-08, so we cite rather than claim.

**The self-audit exposes three rows:** P6 (truncation frequency never counted), P8 (four claims
phrased more generally than one model, one machine supports), P9 (no GGUF digest, no engine
commit). None needs an experiment; A1–A3 close them.

**The one thing that decides the paper's shape is B1.** The literature's prior now runs *against*
multi-agent designs: two 2026 equal-budget studies find single agents match or beat debate, one of
them on 7–8B models. Both name heterogeneous evidence channels as the exception, which is our
defence and a hypothesis until B1 runs. `arXiv:2604.02460` §5.3 makes it sharper still — it finds
a measured **crossover** at α=0.7 on Qwen3-30B-A3B, our own model class. B1's job is to locate
which side of that crossover a malware pipeline sits on.

### Decisions taken 2026-08-09

| Decision | Consequence |
|---|---|
| Cascade ablation scale | **n=100 with the CAPE dynamic path ON**, not the n=210 static corpus (C3) |
| Frontier arm | **Yes**, small budget — closes P8 + E.4 + E.8 in one experiment (A6, B8, C6) |
| Human evaluation | Replaced by an **internal, explicitly LLM-based** readability assessment (D1) that **does not enter the paper**; E.7 stays an open limitation |
| Target | No venue fixed, **quality first** — nothing is pruned from this queue |
| Second open-weight model | **Dropped.** C6 answers the same question more sharply; revisit only if C6 is inconclusive |

---

## A — Serviceless preparation

> **A3 comes before every run below, and that ordering is the point.** The previous roadmap
> marked P6 as `[cheap]` *once runs exist*; that is backwards. If the counters are not in place
> first, the 100+ runs in B and C produce no truncation data and have to be repeated.

- [ ] **A0 — Collapse the queue into this file** `[cheap]`
      Migrate the old §2/§3/§4 checkboxes here with dependencies written down. Record the
      n=100 + CAPE decision in long-term memory. *(This item is what produced this file.)*
- [ ] **A1 — P8: scope the four over-general claims** `[cheap]`
      `findings-log.md` §3.3, §3.5, §1.7.1, §1.5.2 and `related-work.md`. Each is bound to the
      exact evaluated model — *Qwen3.6-35B-A3B (IQ3_K_R4), ik_llama.cpp, one machine*. Pure
      writing. → **P8**
- [ ] **A2 — P9: pin model identity** `[cheap]`
      GGUF file **sha256**, ik_llama.cpp **commit**, model revision → into `findings-log.md` §2.1
      *and* into a provenance block emitted with every run. §2.1's sampler finding
      (`repeat_penalty` honored, the other three silently ignored) is not reproducible without
      them, which is ironic given it is one of our results. → **P9**
- [ ] **A3 — P6 instrumentation, before any run** `[cheap]`
      Counters into `src/maljan/analysis/run_summary.py`: `static_max_chars` truncations, dropped
      chunks, `max_steps` hits, judge token-ceiling hits — and, for C7, how many times the STIX
      integrity pass **fired** and how many objects it **recovered**. Pure helpers unit-tested to
      the repo's `test_*_scoring.py` pattern. → **P6**, **C7**
- [ ] **A4 — Counter-search the five `OURS` rows** `[cheap]`
      The ledger's own closing item: every `OURS` is a *searched absence*, not a proof. One
      targeted search each for C5a / N4 / N7 / C8 / E1, **in the vocabulary of an adjacent
      field** — the rule that has already paid for itself four times (Infer-Retrieve-Rank indexes
      as general ML, TTPDetect as binary analysis, Dempster–Shafer as sensor fusion,
      template-vs-neural as NLG). Anything found demotes a row.
- [ ] **A5 — Build the B1 harness** `[cheap]`
      `tests/evaluation/eval_consensus_ablation.py`, skeleton from
      [eval_view_decomposition.py](tests/evaluation/eval_view_decomposition.py) — the equal-budget
      pattern is already correct there (monolithic = 1 call at B, N-view = N calls at B/N).
      Fixtures from `tests/evaluation/fixtures/` (5 families). Written and unit-tested with no
      server running.
- [ ] **A6 — Frontier-arm plumbing** `[cheap]`
      Config path for a second endpoint, a **hard cost ceiling**, and a dry run against a stub.
      Done now, the frontier arm is one flag at B8 and C6.
- [ ] **A7 — `make check` clean** `[cheap]` — baseline **2238 passed / 12 skipped** (Qdrant down)

## B — llama-server, fixture-based (one slot, sequential)

> Memory: llama-server ~16.2 GB; fixture runs do not load the full analysis pipeline, so the
> ceiling here is ~18–20 GB. `scripts/overnight_watch.sh` stands guard at a 3 GB floor and writes
> a STOP sentinel rather than killing anything.

- [ ] **B0 — Pre-flight** — restart the watcher → confirm ≥ 20 GB free →
      `systemctl --user start maljan-llama` → wait for `slots_idle=1`
- [ ] **B1 — E.2 consensus ablation — the paper's central experiment** `[LLM]`
      Design taken from Bertalanič & Fortuna (`arXiv:2605.00914`), not invented here: **three
      arms** — (1) negotiated multi-agent consensus, today's behaviour; (2) a single judge given
      **all evidence** at once; (3) a **stochastic noise control** (one analyst fed irrelevant
      evidence). **Equal total token budget**, N≫1, mean ± bootstrap CI, **token cost reported**.
      Pre-registered hypothesis, written up either way: *heterogeneous evidence-channel
      decomposition survives the equal-budget control that homogeneous debate fails.*
      → **E.2**, and it decides D3
- [ ] **B2 — Does verbal confidence predict correctness?** `[LLM]`
      `arXiv:2606.29490` finds reported confidence tracks an LLM's *readiness to commit*, not
      whether it is right. Our ISR claims and the whole cascade run on that number. Score claims
      from the fixture runs against ground truth; measure **AUC + separation**. If it replicates
      it justifies every deterministic gate in the system, and it converges with §1.10's finding
      that the layer weights move nothing. → **C3**, R4
- [ ] **B3 — Layer-0 LLM arm** `[LLM]`
      Does removing a deterministic layer change the **final verdict**, not just the cascade
      arithmetic? §1.10 measured only the arithmetic. → **E.5**
- [ ] **B4 — C7 LLM arm** `[LLM]`
      How often does the integrity pass fire on real output, and what does it **recover** that
      rejection would discard? The archived bundles predate the `spec_version` fix and the defect
      classes come from LLM generation, so fresh bundles are required. A3's counters measure it.
      → **C7**
- [ ] **B5 — C3 ablation** `[LLM]`
      Falsification-before-confidence graded cap **on vs off**. FAX (`arXiv:2605.27879`) is a
      *measured* binary method — our unmeasured graded variant cannot be claimed against it.
      Moves C3 out of `UNMEASURED`.
- [ ] **B6 — C1 ablation** `[LLM]`
      Sink-reachability prompt steering **on vs off**. R1 found no competing claim, so C1 may
      survive if measured — and cannot be claimed at all if it isn't.
- [ ] **B7 — C2 tier contribution** `[LLM]`
      Opcode-hash tier vs semantic-RAG tier, separately. AsmRAG (`arXiv:2604.23196`, 40,000
      binaries, F1 95–96%) means an unmeasured two-tier design is indefensible.
- [ ] **B8 — Frontier arm on the fixture suite** `[LLM]` `[$]`
      Cheap sanity check before the big run: plumbing works, the cost ceiling holds, output parses.
- [ ] **B9 — Commit the B layer**, update `findings-log.md`, stop llama-server

## C — The CAPE network (dynamic path) — n=100

> **The tightest memory profile in the queue:** llama-server 16.2 GB + an arq analysis ~8.5 GB
> ≈ 24.7 GB of 30 GB. Never start with the desktop stack loaded. Watcher up for the whole run.

- [ ] **C0 — Connect** `[CAPE]`
      Three lines into `.env` — there are currently **zero** `MCP__CAPE__*` keys:
      `MCP__CAPE__ENABLED=true`, `MCP__CAPE__TRANSPORT=streamable-http`,
      `MCP__CAPE__URL=http://10.65.0.40:9004/mcp`. Then `make docker-up` and **one clean
      end-to-end run** on `4565983c…`. Maljan-side config only; the CAPE tunnels and VM are not
      touched.
- [ ] **C1 — 36-tool CAPE MCP verification** `[CAPE]` — the worker is wired directly; every tool
      checked reachable and schema-conformant
- [ ] **C2 — Sigma / LOLBin / network-DGA layer contribution** `[CAPE]`
      The other half of the Layer-0 study. Then **re-run the weight-sensitivity analysis with all
      six layers** — §1.10's "the corroborated set moves on 0.0%" was measured with three static
      layers and has to hold with six. → **E.5** complete
- [ ] **C3 — n=100 cascade ablation, dynamic path on** `[CAPE]` `[LLM]`
      Flat union vs the weighted cascade, on a sample stratified by family and year so it stays
      comparable to the n=210 drift cohort. **Per-sample results are stored this time** — the
      drift study kept only cohort means, which is exactly why no TOST was possible for the E1
      bound. → moves **C6** out of `UNMEASURED`; closes **E.1**
- [ ] **C4 — Dynamic cohort vs static-only, paired delta** `[CAPE]` `[LLM]`
      The paper currently *argues* the dynamic path lifts recall. This measures it: same ground
      truth, paired statistics, bootstrap CIs. → **E.3**
- [ ] **C5 — Baseline with no LLM at all** `[CAPE]`
      CAPE's own signature-derived TTPs on the same n=100. **Without this, "F1 0.08" has no
      referent** — arguably the single highest-value item in the queue. → **E.4**
- [ ] **C6 — Frontier arm on the n=100 cohort** `[CAPE]` `[LLM]` `[$]`
      Same pipeline, one endpoint changed. `arXiv:2606.18166` found parameter size is the **only**
      significant predictor of ATT&CK-classification F1 (ρ=0.85, p=0.014), so without this arm the
      architecture/model confound stands. → **E.4 + E.8 + P8**
- [ ] **C7 — Close P6** `[cheap]` once C runs exist
      Truncation frequency distribution from A3's counters: how many runs truncated, how many
      chunks dropped, how often `max_steps` was hit — **and the performance impact**. Exactly what
      the pitfall asks for. → **P6 `EXPOSED` → `CLEAR`**
- [ ] **C8 — Commit the C layer**, update `findings-log.md`, stop all services

## D — Closing measurements and decisions

- [ ] **D1 — Readability assessment (internal, LLM-based)** `[LLM]`
      15 reports scored on a rubric (structure, traceability, redundancy, actionability),
      deterministic template vs LLM narrative, blinded. Recorded in `findings-log.md` **explicitly
      labelled an LLM-based internal instrument**, used to steer development.
      **It does not enter the paper.** The reason is the project's own audit: `self-audit-pitfalls.md`
      scores P2 `CLEAR` on the strength of one sentence — *"LLM-as-a-judge was never used for
      scoring"* — which is a line most of the 72 papers in the NDSS'26 survey cannot write. Any
      LLM scoring in the paper costs that row, and unlabelled LLM scoring presented as human
      evaluation is not recoverable. So **E.7 remains an open limitation in the paper: no human
      analyst has scored a report.**
- [ ] **D2 — YARA corpus licence review** `[decide]`
      The 30 in-house rules carry the highest cascade weight (0.90) and their publishability is
      unsettled. → **E.6**
- [ ] **D3 — Lock the framing** `[decide]` — once B1, C3 and C5 are in
      Today's recommendation is **F3 (negative results / measurement) on the F4 (drift) spine,
      with the F2 remnant — C5a, N4, N7 — as the sharpest chapter.** But **a positive B1 carries
      F1 (the system paper) on its own**: an equal-budget win for heterogeneous evidence channels,
      against a literature prior predicting the opposite, is a strong enough finding to lead with.
      That is why the framing locks *after* B1, not now.
- [ ] **D4 — Finalise the ledger and the self-audit** — update the four `UNMEASURED` rows with
      their results; re-issue the P6/P8/P9 verdicts

## E — The paper — last

- [ ] **E1 — Results / Evaluation** — from the measured record; everything above lands here
- [ ] **E2 — Threats to Validity** — from `self-audit-pitfalls.md`, with P6/P8/P9 now closed and
      P3's residual (the LLM's training data is unknown to us and memorisation was never probed)
      **explicitly acknowledged**, which is the pitfall's own recommendation
- [ ] **E3 — Related Work, final** — `related-work.md` exists as a draft; fold in the new results
      and whatever A4's counter-searches turn up
- [ ] **E4 — LaTeX skeleton, then the paper** — after D3 locks the framing
- [ ] **E5 — Reproducibility appendix** — scripts, data manifests, seeds, the model digest and
      engine commit from A2, harness commands. The full answer to P9.

---

## Claim status

Definitions in [literature-review-brief.md](literature-review-brief.md) Part B; verdicts from
[novelty-ledger.md](research-briefs/novelty-ledger.md).

| # | Claim | Evidence | Verdict | Closed by |
|---|---|---|---|---|
| C0 | LLM-as-analyst vs LLM-for-a-trained-detector taxonomy | positioning | — | E3 |
| C1 | Sink-reachability transferred JS→binary as prompt steering | **unmeasured** | `UNMEASURED` | **B6** |
| C2 | Two-tier attribution (opcode-hash + semantic RAG) | **unmeasured** | `UNMEASURED` | **B7** |
| C3 | Falsification-before-confidence protocol | **unmeasured** | `REFINEMENT` of FAX | **B5**, B2 |
| C4 | "Use a tool ≠ expose it" — 20-tool allowlist | §2.2 measured | open gap | E1 |
| C5 | Describe-then-map | §1.5.1/§1.5.2 measured | **PRIOR ART** `2401.12178` | cite only |
| C5a | Rank and gate are separate axes | N=4,913 TRAM2 **+ AnnoCTR** | **OURS** | A4 confirms |
| C6 | Multi-layer corroboration cascade | §1.10 partial | `UNMEASURED` | **C3**, C2 |
| C7 | Deterministic STIX integrity + honest degradation | emitter fixed, pass unmeasured | `UNMEASURED` | **B4** |
| C8 | Schema-pruning hint → completion, not accuracy | n=17 paired | **OURS** | A4 confirms |
| N1 | Claim-count is an invalid instrument | measured | `REFINEMENT` | E1 |
| N2 | Equal-budget view decomposition trades grounding for volume | n≈8–9/arm | `REFINEMENT` | E1 |
| N3 | Zero-shot semantic category inference loses to keywords | N=101 | `REFINEMENT` | E1 |
| N4 | Auto-correction damages 38% to recover 21% | measured | **OURS** | A4 confirms |
| N5 | Deterministic template beats LLM narrative on faithfulness | n=15 | `REFINEMENT` | D1 informs |
| N6 | Working retriever, unreachable query; frequency prior wins | measured | `REFINEMENT` | E1 |
| N7 | Degenerate ID loop; sampler penalties insufficient | reproducible | **OURS** | A4 confirms |
| N8 | No speculative-decoding gain on A3B MoE | measured | `PRIOR ART`-adjacent | appendix |
| E1 | 7-year drift study, n=210, no measurable drift | n=210, bound ≤0.040 F1 | **OURS** | A4 confirms |
| E2 | KV scaling on hybrid-offload MoE | measured | — | appendix |
| E3 | ~201-tool catalogue infeasible at 3B | measured | open gap | E1 |
| — | binary→ATT&CK input modality | — | **PRIOR ART** `2602.06325` | cite only |

## Framing

| Framing | Rests on | Status |
|---|---|---|
| **F1 System paper** | C0, C4, C6, C7 | **Gated on B1 and C3.** A positive B1 carries it alone |
| **F2 Describe-then-map** | ~~C5~~, C5a, N4, N7 | **Broken as stated** — rebuildable as F3's sharpest chapter |
| **F3 Negative results / methodology** | N1–N8, §1.5.3, §1.10 | **Strongest today**, and unusually honest |
| **F4 Drift study** | E1 | **Uncontested**; needs C5's baseline arm to land the contrast |

---

## Operational notes

**When CAPE comes back, in order:** `make docker-up` → `systemctl --user start maljan-llama` →
wait for `slots_idle=1` → the three `MCP__CAPE__*` lines → one clean run on `4565983c…` (C0).

**If llama-server wedges** — the cause of every timeout on 2026-08-07, not a Maljan defect —
`systemctl --user restart maljan-llama` clears it: the same call did not return in 300+ s before a
restart and took 46.1 s after.

**Memory.** llama-server alone holds ~16.2 GB and an analysis grows to ~8.5 GB against 30 GB
total. Do not start a heavy analysis with the desktop stack already loaded.

**Standing rule, learned the hard way on R2:** search each claim in the vocabulary of at least one
*adjacent* field. Searching only the subfield a claim sounds like will miss the paper that owns it.

**Standing rule on results:** every outcome is written up, including the ones that cost us a
claim. B1 returning negative is a result; A4 demoting an `OURS` row is a result.
