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

![Every arm on one F1 axis, against the baseline that gives the axis meaning.](figures/fig3-arms-against-baseline.pdf)

**Figure 1: Every arm on one axis, with the baseline that makes the axis mean something.** Points are
means over per-sample F1; bars are 95% bootstrap intervals recomputed from the retained per-sample
records with the seed fixed. The three equal-budget arms are the consensus study (§1); the noise
control separates from both treatments, which is what licenses reading the treatments' overlap as a
null rather than as an insensitive harness. The 120B arm (§2) is **not paired with the others** and
its n is 9 rather than 25 because the free-tier daily quota was exhausted mid-run: the 16 missing
calls returned HTTP 429, not bad output. The truncation is therefore by call order rather than by
result — all five fixture families are represented, and what is missing is repeats — but the interval
is wide, it overlaps every other arm, and the apparent lead should not be read as one.

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

**Why n=9 and not 25, stated precisely.** The remaining 16 calls returned HTTP 429 — a free-tier
daily quota of 50 requests, exhausted mid-run. They are not parse failures or refusals, and the
distinction matters for how the arm is read: the sample is truncated by **call order**, not by
outcome, so it carries no selection on result quality. All five fixture families appear; what is
missing is repeats of them. This is a small and underpowered arm, and it is underpowered for a
mundane reason we prefer to name than to leave the reader inferring a worse one.

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
| sink-reachability priority hint | **56.7%** of samples (55/97) | an ablation would be interpretable; it was attempted and did not complete (§7) |
| STIX integrity pass | measured over 60 fresh judge bundles | reported by removal reason |

For the cap, the mechanism's own preconditions explain the rate: it applies to three technique
families, only when the sole contributing layer is `static`, and 84% of those claims are YARA-only —
so no static claim exists for it to discipline. We report the rate rather than an ablation, because
an ablation over a mechanism that fires on 0.82% of cases produces a null that means nothing.

![Firing rates decide which ablations can be read.](figures/fig4-firing-rate-before-effect.pdf)

**Figure 2: Firing rate decides whether an ablation can be read at all.** Three of the four
mechanisms the architecture was built around engage on almost nothing, and an ablation of any of them
would return a null describing the cases where the mechanism never ran. Only the sink-reachability
hint clears a rate at which an ablation would carry information — which is why it is the one we
attempted, and §7 reports what happened when we did.

## 5. The corroboration cascade does not reach the verdict

The multi-layer corroboration set — the design's central claim about evidence quality — was varied
from 3 corroborated techniques to 0. **The final verdict was identical in 0 of 15 cases changed.**
The cascade's arithmetic runs; its output does not reach the decision.

## 6. Confidence is very nearly a constant

Verbal confidence, which the cascade and the deterministic gates consume, discriminates correct from
incorrect claims at **AUC 0.550** — near chance — and is concentrated on a handful of round values.
This matches `arXiv:2606.29490`'s finding that verbal confidence measures willingness to commit
rather than correctness, and it means every deterministic gate keyed to that number is keyed to
noise.

![The confidence number every deterministic gate consumes, and its distribution.](figures/fig2-confidence-discrimination.pdf)

**Figure 3: The number the gates consume barely orders anything.** Left, the ROC over 210 claims
scored against resolved ground truth. Right, why: **186 of those 210 claims carry confidence exactly
1.0**, so the score has almost no ordering to contribute. The estimate is rank-based with ties
averaged, which for this distribution is not a detail — sorting the tied claims arbitrarily instead
returns 0.458, and the difference between the two numbers is entirely an artefact of how 89% of the
data is handled.

## 7. What the ablations cost, and what that revealed

The sink-hint effect ablation is **incomplete and is not reported as a null**: it reached 10 of 24
arms before the host ran out of memory, and stopped there.

| sample | hint off | hint on | disposition |
|---|---|---|---|
| `000ac83f` | 2 techniques / 150 s | 6 techniques / 200 s | scoreable, hint **+4** |
| `0014daea` | 6 techniques / 113 s | 0 techniques / 116 s | scoreable, hint **−6** |
| `00162899` | 14 techniques / **117 claims** | 1 / 1 | degenerate decode (§3.3), excluded |
| `000b535a` | 0 / 1 (625 s) | 0 / 1 (1,545 s) | both arms dead |
| `00c66a68` | 0 / 1 (612 s) | 0 / 1 (622 s) | both arms dead |

Two scoreable pairs pointing in opposite directions is not an underpowered estimate; it is the
absence of one, and the paired mean of −1.0 with a bootstrap interval of [−6, +4] should be read as
nothing at all.

**The four dead arms are the more useful part of this result, and they are reported as
unattributable rather than as pipeline failures.** The last pair ran while the host's swap file was
fully exhausted and the model server had **2.3 GB of its own address space paged out**; one arm then
exceeded a 594-second budget on a prompt trimmed to 16,000 characters, which is inexplicable for a
model generating from RAM and unsurprising for one generating from disk. Whether those arms failed
because of the pipeline or because of the machine **cannot be determined from what was retained** —
per-sample outputs were kept, per-sample *host state* was not.

That is this paper's own §4.5 recurring against it, in a place we had not thought to look: the rule
was written about the pipeline's outputs, and the thing that went unrecorded was the environment the
measurement was taken in. The harness now captures `MemAvailable`, `SwapFree` and the model server's
resident-versus-swapped split at both ends of every arm, and the scorer excludes arms whose host was
degraded — a screen that can only ever be applied forward, never to data already collected.

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
