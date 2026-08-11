# Results

*Draft for the paper. Every figure traces to a section of
[`findings-log.md`](../findings-log.md) and a committed artifact under
`tests/evaluation/`. Figures produced before 2026-08-11 that depended on the static analyst's tool
loop are excluded, for the reason given in Threats to Validity.*

## 0. The baseline, first

Every accuracy number in this work is read against one reference, and we state it before any of our
own. **CAPE alone — the sandbox the pipeline is built on, mapping its signature hits to ATT&CK
technique IDs deterministically, with no language model anywhere:**

| | mean | 95% CI |
|---|---|---|
| precision | 0.3008 | [0.2337, 0.3673] |
| recall | 0.1610 | [0.1254, 0.1962] |
| **F1** | **0.1871** | **[0.1508, 0.2234]** |

n = 24 of the 100-sample cohort, bootstrap CI, seed recorded. CAPE asserted at least one technique on
every sample (4 minimum, 12 median, 33 maximum), so this is a real predictor rather than an artefact
of an empty one. Ground truth resolution uses the same alias map as the drift harness, so the two
studies score identically.

We report this first because without it a pipeline F1 is uninterpretable, and because it sets a bar
the pipeline must clear to have contributed anything. Earlier drafts of this work reported F1 values
against nothing at all.

## 1. Multi-agent consensus does not pay for itself at equal budget

Design after Bertalanič & Fortuna: three arms at an **equal total token budget**, including a
stochastic-noise control in which one analyst receives irrelevant evidence.

| arm | mean F1 | n |
|---|---|---|
| single judge, all evidence at once | **0.4136** | 25 |
| negotiated multi-agent consensus | 0.3975 | 25 |
| noise control | 0.3366 | 25 |

**Paired delta, negotiated − single: −0.016, 95% CI [−0.084, +0.050]** — an interval containing
zero, at **3.2× the tokens**. The noise control separates from both, so the harness can detect a
difference when one exists; it does not detect one here.

This was pre-registered as the experiment that would decide the paper's framing, and its null result
is why this is not a systems paper. The literature's prior ran the same way: two 2026 equal-budget
studies find single agents match or beat debate, and `arXiv:2604.02460` §5.3 reports a crossover at
α=0.7 on our own model class.

## 2. A 3.4× larger model does not separate from the local one

Same five fixtures, same prompt, same 2,400-token output budget:

| arm | model | mean F1 | 95% CI | n |
|---|---|---|---|---|
| local | Qwen3.6-35B-A3B (IQ3_K_R4) | 0.4136 | — | 25 |
| frontier | Nemotron-3-Super-120B-A12B | 0.5025 | [0.4101, 0.6178] | 9 |

The frontier interval contains the local mean, so **no separation is demonstrated — and none is
refuted.** We report it because the literature's prior predicts otherwise: `arXiv:2606.18166` found
parameter size the *only* statistically significant predictor of ATT&CK-classification F1 (ρ=0.85,
p=0.014) on the nearest task. n=9 cannot settle that; it can only decline to confirm it.

**A measurement that does not depend on n:** across the frontier arm's calls, **53.6% of output
tokens were reasoning** (min 48.3%, max 59.7%), and on a one-token answer, 84% — 92 output tokens,
77 of them thinking. An equal-budget comparison must therefore cap *total* output including
reasoning; capping content alone would hand the reasoning model roughly twice the generation for the
same nominal budget.

## 3. Three independently built retrieval components, all near-inert in production

This is the paper's most replicated result, and it is negative.

| component | works in isolation? | contribution end to end |
|---|---|---|
| ATT&CK case-prior RAG | yes — F1 0.620 vs a 0.424 frequency prior | **loses** to the frequency prior in production (0.111 vs 0.123) |
| family-feature RAG | yes — recall@5 0.199, **6.3× chance**, leakage-free split | **+0.003 F1**, precision −0.009, n=19 |
| opcode-hash attribution | n/a — never fires | **0 of 18 samples**; 7,716 functions hashed, 0 matches |

Each was built separately, each is defensible in design, and each is inert once wired to real
inputs. The mechanisms differ, which is what makes the pattern worth reporting rather than three
disappointments: the first fails on **vocabulary mismatch** between query and corpus, visible only
in the score distribution while top-k accuracy stayed healthy; the second is simply small; the third
fails for **two independent reasons** — its corpus holds 3 samples under 2 generic labels, and the
8-instruction floor that correctly excludes thunks leaves **9 of 18 real samples with one hashable
function or none**, a sharply bimodal distribution that populating the corpus would not fix.

## 4. Mechanisms measured before their effects

A recurring finding is that a mechanism's *firing rate* determines whether its ablation can be
interpreted at all.

| mechanism | fires on | consequence |
|---|---|---|
| confidence cap (falsification-before-confidence) | **0.82%** of techniques | an ablation would measure nothing; the null is uninterpretable |
| sink-reachability priority hint | **56.7%** of samples (55/97) | an ablation is interpretable, and was run |
| STIX integrity pass | measured over 60 fresh judge bundles | reported by removal reason |

For the cap, the mechanism's own preconditions explain the rate: it applies to three technique
families, only when the sole contributing layer is `static`, and 84% of those claims are YARA-only —
so no static claim exists for it to discipline. We report the rate rather than an ablation, because
an ablation over a mechanism that fires on 0.82% of cases produces a null that means nothing.

## 5. The corroboration cascade does not reach the verdict

The multi-layer corroboration set — the design's central claim about evidence quality — was varied
from 3 corroborated techniques to 0. **The final verdict was identical in 0 of 15 cases changed.**
The cascade's arithmetic runs; its output does not reach the decision.

## 6. Confidence is very nearly a constant

Verbal confidence, which the cascade and the deterministic gates consume, discriminates correct from
incorrect claims at **AUC 0.550** — near chance — and is concentrated on three round values. This
matches `arXiv:2606.29490`'s finding that verbal confidence measures willingness to commit rather
than correctness, and it means every deterministic gate keyed to that number is keyed to noise.

## 7. What the ablations cost, and what that revealed

The sink-hint effect ablation is **incomplete**: one paired sample and one failed arm, reported in
full rather than extrapolated.

| sample | arm | seconds | technique IDs |
|---|---|---|---|
| `000ac83f` | hint on | 200.5 | 6 |
| `000ac83f` | hint off | 150.1 | 2 |
| `000b535a` | hint on | 1,545.2 | 0 — hit the cap |

One pair is not a result: the on-arm found three times the techniques *and* took 33% longer, and
separating "the hint works" from "the hint buys depth with time" is what the equal-budget discipline
exists for.

Running it, however, surfaced a production defect that the 1,995-test suite did not: on any binary
rich enough to exhaust the 40-step ReAct budget, the analyst returned **zero techniques**, because
the salvage path received a fresh copy of a budget it was already inside. Fixed and verified on the
same sample: **1,677 s → 323 s, 0 → 5 technique IDs**. The fix is partial — one sample still exceeds
the bound, and the server's own timings show generation varying from 162 to 20 tokens/s on this
hybrid recurrent architecture, so a bounded input does not rescue a case where the tokens themselves
are eight times slower than assumed.

## Summary

Of the four architectural claims this system was built around, three are now measured and negative
or near-null, and the fourth is unmeasured pending sandbox access. What survived measurement is not
the architecture but the account of measuring it.
