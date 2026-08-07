# Maljan paper — roadmap

> **This file is the plan of record.** Work proceeds from here; the paper is shaped last, once
> the evidence and the novelty verdicts are in. Written 2026-08-08.
>
> Companions: [findings-log.md](findings-log.md) is the evidence record (what was measured);
> [literature-review-brief.md](literature-review-brief.md) is the contribution map and the
> review intake; [research-briefs/](research-briefs/) holds the review itself.
>
> **Tags.** `[done]` finished · `[CAPE]` needs the sandbox network · `[LLM]` needs llama-server
> · `[decide]` needs the author's call, not more work · `[cheap]` no LLM, no CAPE, runs offline

---

## 0. Where this actually stands

Two things changed on 2026-08-08 and they govern everything below.

**The literature already owns two of our framing candidates.** `arXiv:2401.12178`
(Infer-Retrieve-Rank, Jan 2024) publishes the general form of describe-then-map: decouple the
LM's inference from assignment over a many-thousand-class label space via a retriever.
`arXiv:2602.06325` (TTPDetect, Purdue, Feb 2026) maps *stripped malware binaries* to ATT&CK at
93.25% function-level precision with a deterministic retrieval pre-pass feeding an LLM reasoner
— architecturally our shape. And the Büchel SoK (USENIX Security 2025, pp. 4621–4641) already
reports, over a unified re-evaluation of 40+ systems, that traditional NLP beats embedder and
generative approaches in realistic settings — a more general statement of what §1.5.1 found.

None of this kills the work. It changes what we *claim*: cite rather than discover, and lead
with what survives.

**The central mechanism is still unmeasured.** The TTP cascade — layer weights 0.90 down to
0.20, corroboration multipliers up to 1.90 — is the concrete instantiation of the paper's own
organising principle and has never been ablated. Same for the negotiated consensus that sits in
the project's own framing. A reviewer finds both without reading the literature.

**What survives as ours today:** the gate-separation metric (C5a), the auto-correction
regression (N4), the degenerate-ID-loop pathology (N7), the case-RAG negative result (N6), the
narrative-vs-template result (N5), the instrument-validity result (N1), and the n=210 drift
study (E1). That is a negative-results-and-methodology paper, and it is well evidenced.

---

## 1. Claim status

Full definitions in [literature-review-brief.md](literature-review-brief.md) Part B. Verdicts
come from [research-briefs/novelty-ledger.md](research-briefs/novelty-ledger.md) as it fills in.

| # | Claim | Evidence | Novelty verdict |
|---|---|---|---|
| C0 | LLM-as-analyst vs LLM-for-a-trained-detector taxonomy | positioning | pending R1/R6 |
| C1 | Sink-reachability transferred JS→binary as prompt steering | implemented, no ablation | pending R1 |
| C2 | Two-tier attribution (opcode-hash + semantic RAG) | **unmeasured** | pending R5 |
| C3 | Falsification-before-confidence protocol | implemented, **unmeasured** | pending R4 |
| C4 | "Use a tool ≠ expose it" — 20-tool allowlist | §2.2 measured | **open gap** per R1.model-b |
| C5 | Describe-then-map | §1.5.1/§1.5.2 measured | **ALREADY DONE** — `arXiv:2401.12178` |
| C5a | Rank and gate are separate axes; compose per-axis winners | N=4,913 TRAM2 | **NOT CLOSED — ours** |
| C6 | Multi-layer corroboration cascade | **unmeasured** | pending R3 |
| C7 | Deterministic STIX integrity + honest degradation | implemented, unmeasured | pending R8 |
| C8 | Schema-pruning hint → completion, not accuracy | n=17 paired | pending R8 |
| N1 | Claim-count is an invalid instrument | measured | pending R6 |
| N2 | Equal-budget view decomposition trades grounding for volume | n≈8–9/arm | pending R1 |
| N3 | Zero-shot semantic category inference loses to keywords | N=101 | pending R6 |
| N4 | Auto-correction damages 38% to recover 21% | measured | **NOT CLOSED — ours** |
| N5 | Deterministic template beats LLM narrative on faithfulness | n=15 | pending R8 |
| N6 | Working retriever, unreachable query; frequency prior wins | measured | pending R5 |
| N7 | Degenerate ID loop; sampler penalties insufficient | reproducible | **NOT CLOSED — ours** |
| N8 | No speculative-decoding gain on A3B MoE | measured | pending R7 |
| E1 | 7-year drift study, n=210, no measurable drift | n=210 | pending R6 |
| E2 | KV scaling on hybrid-offload MoE | measured | pending R7 |
| E3 | ~201-tool catalogue infeasible at 3B | measured | **open gap** per R1.model-b |
| — | binary→ATT&CK input modality | — | **ALREADY DONE** — `arXiv:2602.06325` |

---

## 2. Literature review

- [x] R2 — ATT&CK technique mapping `[done]` → `incoming/R2.claude-web.md`
- [x] R5 — RAG for malware / CTI `[done]` → `incoming/R5.claude-web.md`
- [ ] R3 — multi-agent consensus `[cheap]`
- [ ] R4 — grounding, hallucination, calibration `[cheap]`
- [ ] R6 — evaluation methodology and ground truth `[cheap]`
- [ ] R7 — local, small, open-weight deployment `[cheap]`
- [ ] R8 — CTI report / STIX generation `[cheap]`
- [ ] R1 — verify `R1.model-b.md`'s UNCERTAIN citations rather than redo it `[cheap]`
- [ ] Citation audit of `ALL8.model-a.md` — real / misattributed / not found `[cheap]`
- [ ] `novelty-ledger.md` — every claim → prior work → verdict → which arm found it `[cheap]`

**Standing rule, learned the hard way on R2:** search each claim in the vocabulary of at least
one *adjacent* field. Infer-Retrieve-Rank indexes as general ML; TTPDetect indexes as binary
analysis. Searching only the subfield a claim sounds like will miss the paper that owns it.

---

## 3. Experiments

### 3.1 Runs offline tonight

- [ ] **Static Layer-0 contribution study** `[cheap]`
      209 real PE samples on disk; `yara_layer`, `import_capability_layer`,
      `tool_artifact_layer` need no LLM and no sandbox. Measure per-source technique yield,
      cross-source overlap, and each source's unique contribution (leave-one-out).
      → directly answers **E.5**
- [ ] **Cascade weight-sensitivity analysis** `[cheap]`
      Feed those tuples to `TTPCascadeEngine`; vary `LAYER_WEIGHTS` and the corroboration
      multipliers over plausible ranges and report whether the ranking and the
      `is_corroborated` decisions are stable. → first real answer to **E.1**'s "the constants
      are plausible and unjustified"
      *Honest scope: 3 of 6 layers. Sigma (2,651 rules), LOLBin and network-DGA need a sandbox
      report, so this is a* static *Layer-0 ablation and will be named that way.*

### 3.2 Needs llama-server — not tonight

- [ ] **Full cascade ablation** `[LLM]` — flat union vs cascade on the n=210 corpus. Blocked
      twice over: needs the LLM, and the per-sample results of the original run were never
      stored, so the corpus must be re-analysed. → **E.1**
- [ ] **Negotiated consensus vs single judge pass at equal token budget** `[LLM]`
      N≫1, CIs, scored on TTP F1 and grounding. The mechanism is in the project's own name and
      has no evidence. → **E.2**, and our own N1 forbids claiming it works without this
- [ ] **Frontier arm** `[LLM]` `[decide]` — identical pipeline, one frontier endpoint, nothing
      else changed. `arXiv:2606.18166` found parameter size is the *only* significant predictor
      of F1 in ATT&CK classification (ρ=0.85, p=0.014), which makes our single-model design a
      live threat to validity. → **E.4**, **E.8**
- [ ] **Benchmark against TTPDetect's dataset if it is public** `[LLM]` `[decide]`
      Answers "your ground truth is your own" and tells us whether the cascade buys anything
      over a function-level agent. Losing is a real possibility at 93.25% precision — worth
      knowing before building a framing on top. **Do this early once the LLM is back.**
- [ ] **Layer-0 ablation, LLM arm** `[LLM]` — does removing a deterministic layer change the
      *final* verdict, not just the cascade arithmetic

### 3.3 Needs the CAPE network

- [ ] **Dynamic cohort** `[CAPE]` `[LLM]` — even n≈30 against the same ground truth, reported
      as a paired delta against the static-only numbers. The paper currently *argues* dynamic
      lifts recall; this measures it. → **E.3**
- [ ] **Sigma / LOLBin / network-DGA layer contribution** `[CAPE]` — the other half of §3.1
- [ ] **36-tool CAPE MCP verification** `[CAPE]` — worker is already wired directly; needs
      `MCP__CAPE__ENABLED=true`, `MCP__CAPE__TRANSPORT=streamable-http`,
      `MCP__CAPE__URL=http://10.65.0.40:9004/mcp` in `.env`
- [ ] **Dynamic-vs-static paired comparison** `[CAPE]` `[LLM]` — the headline the dynamic arm
      exists to produce

### 3.4 Open regardless

- [ ] **Baseline with no LLM at all** `[CAPE]` — CAPE's own signature-derived TTPs on the same
      samples. Without one baseline, "F1 0.08" has no referent. → **E.4**
- [ ] **Human evaluation** `[decide]` — the report is the product and no analyst has scored
      one. N5 showed readability is the LLM narrator's *only* edge, and readability is exactly
      what needs human judgement. → **E.7**
- [ ] **Second open-weight model** `[LLM]` — lets us say "architecture" instead of "this
      model". → **E.8**
- [ ] **YARA corpus** `[decide]` — 30 rules carry the highest cascade weight (0.90). Pending a
      licence review. → **E.6**

---

## 4. Write-up

- [ ] Update `findings-log.md`: expand §3.1 prior art, bind §1.5.1 to the Büchel SoK as a
      *mechanistic refinement* rather than a discovery, add Infer-Retrieve-Rank and TTPDetect
      to §1.5/§1.5.3 and **narrow the claims** — never silently drop them, `[cheap]`
- [ ] Update `literature-review-brief.md` Parts B / E / F to the ledger `[cheap]`
- [ ] `[decide]` **Pick the framing** — see §5
- [ ] Related-work section from the ledger `[cheap]`
- [ ] LaTeX skeleton, then the paper — **last**, once §3 and the framing are settled

---

## 5. Framing — the decision this roadmap builds toward

| Framing | Rests on | Status today |
|---|---|---|
| **F1 System paper** | C0, C4, C6, C7 | needs E.1–E.4; two load-bearing mechanisms unmeasured |
| **F2 Describe-then-map** | C5, C5a, N4, N7 | **weakened** — C5 is prior art; C5a/N4/N7 survive |
| **F3 Negative results / methodology** | N1–N8, §1.5.3 | **strongest today**, and unusually honest |
| **F4 Drift study** | E1 | needs a comparison arm to land the contrast |

**Current honest read:** F3 is supported now. F1 is the ambition and is gated on E.1/E.2. F2
must be rebuilt around C5a/N4/N7 with C5 demoted to a cited instantiation. A combined
F3-with-F1-evidence paper is the likely target once the cascade and consensus ablations exist.

---

## 6. When CAPE comes back — first three, in order

1. `make docker-up` → `systemctl --user start maljan-llama` → wait for `slots_idle=1`
2. Add the three `MCP__CAPE__*` lines to `.env`, then one clean run on `4565983c…` to confirm
   the dynamic path end to end
3. The dynamic cohort (§3.3) — it unblocks E.3 and the other three Layer-0 sources at once

**Operational note.** If llama-server wedges (the cause of every timeout on 2026-08-07, not a
Maljan defect), `systemctl --user restart maljan-llama` clears it: the same call did not return
in 300+ s before a restart and took 46.1 s after.

**Memory.** llama-server alone holds ~16 GB and an analysis grows to ~8.5 GB, against 30 GB
total. Do not start a heavy analysis with the desktop stack already loaded.
