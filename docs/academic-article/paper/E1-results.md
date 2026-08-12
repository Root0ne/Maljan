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
| precision | 0.2902 | [0.2447, 0.3398] |
| recall | 0.1343 | [0.1104, 0.1596] |
| **F1** | **0.1666** | **[0.1411, 0.1938]** |

n = 43 of the 100-sample cohort, bootstrap CI, seed recorded. CAPE asserted at least one technique on
every sample (3 minimum, 11 median, 33 maximum), so this is a real predictor rather than an artefact
of an empty one. Ground truth resolution uses the same alias map as the drift harness, so the two
studies score identically.

**Why 43 and not 100, and why the number is not a choice we made.** The cohort was submitted as one
batch and every task completed, but the sandbox retains report files for a limited window: 56 of the
100 now answer a report request with `Reports directory does not exist`, and one task failed
outright. The analyses ran; their reports are gone. An earlier pass over 24 of these reports gave
F1 0.1871 [0.1508, 0.2234] — the present estimate sits inside that interval and is tighter, so this
is a firmer version of the same number rather than a different one.

We report this first because without it a pipeline F1 is uninterpretable, and because it sets a bar
the pipeline must clear to have contributed anything. Earlier drafts of this work reported F1 values
against nothing at all.

![Every arm on one F1 axis, against the baseline that gives the axis meaning.](figures/fig3-arms-against-baseline.pdf)

**Figure 1: Every arm on one axis, with the baseline that makes the axis mean something.** Points are
means over per-sample F1; bars are 95% bootstrap intervals recomputed from the retained per-sample
records with the seed fixed. The three equal-budget arms are the consensus study (§1); the noise
control separates from both treatments, which is what licenses reading the treatments' overlap as a
null rather than as an insensitive harness. The 120B arm (§2) runs the same fixtures and repeats at
the same output budget, so it too is n=25; it lands on the local single-judge arm, and the paired
difference between them is +0.003 with an interval eight times wider than the effect.

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
| frontier | Nemotron-3-Super-120B-A12B | 0.4162 | [0.3596, 0.4711] | 25 |

Both arms see the same five fixtures at the same five repeats, so the comparison is **paired**:

> **frontier − local = +0.0026**, 95% CI **[−0.0770, +0.0814]**, n=25.
> The frontier model is better on 12 of the 25 and worse on 13.

A 3.4× larger reasoning model, given the same evidence and the same output budget, lands within
three thousandths of F1 of a 35B model quantised to run on one desktop GPU, and its direction across
samples is a coin flip. We report it because the literature's prior predicts otherwise:
`arXiv:2606.18166` found parameter size the *only* statistically significant predictor of
ATT&CK-classification F1 (ρ=0.85, p=0.014) on the nearest task. On this task, at this budget, we do
not reproduce that.

**An earlier version of this arm reported 0.5025 and was wrong to suggest a lead.** That figure came
from n=9, the run having been cut short by a daily request quota; the apparent advantage did not
survive completing the sample. It is recorded here because it is the exact failure mode §4.2 warns
about — a difference read off an underpowered arm — and because we caught it by finishing the run
rather than by any insight.

The completed run parsed **25 of 25** calls with no refusals and one hitting the output cap.

**Where the larger model's budget went:** across the 25 calls, **56.5% of output tokens were
reasoning**, and on a one-token answer, 84% — 92 output tokens, 77 of them thinking. An equal-budget
comparison must therefore cap *total* output including reasoning; capping content alone would hand
the reasoning model roughly twice the generation for the same nominal budget, and the null above
would have been a win bought with tokens.

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
| sink-reachability priority hint | **56.7%** of samples (55/97) | an ablation is interpretable, was run, and returned a null (§7) |
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
ablated, and §7 reports the null it returned.

## 5. The corroboration cascade does not reach the verdict

The multi-layer corroboration set — the design's central claim about evidence quality — was varied
from 3 corroborated techniques to 0. **The final verdict was identical in 0 of 15 cases changed.**
The cascade's arithmetic runs; its output does not reach the decision.

**We report a limit on this result that we found after obtaining it, and it is the kind that would
normally go unstated.** The study varied **three of the cascade's six Layer-0 sources** — the three
that need no sandbox. Measuring the other three over an archived cohort afterwards showed that one of
them, the Sigma layer, **fires on 43 of 43 samples and contributes a technique no other dynamic
source found on all 43**, at weight 0.55 — second only to YARA and above the static layers this study
did vary. A null obtained while the second-heaviest contributor was absent is not yet a statement
about the cascade. We therefore treat the finding as **provisional pending a six-source re-run**
rather than as the settled result it appeared to be, and we would rather print that sentence than a
cleaner one we could not defend.

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

The one mechanism whose firing rate justified an ablation (§4, 56.7%) was ablated, paired, on the
subset where it fires. It does nothing measurable:

| outcome | mean Δ (hint on − off) | 95% CI |
|---|---|---|
| **distinct technique IDs** | **+0.50** | **[−3.33, +4.50]** |
| claims | −0.83 | [−4.33, +3.67] |
| seconds | +52.55 | [−161.93, +268.45] |

n=6 pairs; the hint is better on 2, worse on 2, and tied on 2, with per-pair deltas of +4, −6, 0, 0,
−4 and +9 — large in both directions and cancelling. This is the fourth architectural claim to end in
a null, and the last one we were in a position to test.

**The result that constrains the result: half the experiment was not scoreable.** Twelve pairs were
attempted and six survived screening.

| excluded | n | why |
|---|---|---|
| degenerate decode | 3 | an arm emitting 49–117 claims across 2–14 technique IDs (ratios 8.4–34.3) |
| unattributable | 2 | both arms dead, and the host state needed to decide whether the pipeline or the machine failed was never recorded |
| incomplete | 1 | an arm exceeded the 630 s bound — a genuine outcome, but it costs the pair |

A 50% pair-loss rate bounds what any ablation on this pipeline can detect. An effect smaller than the
noise from losing half the samples is not measurable here, and quoting `+0.50 [−3.33, +4.50]` without
that context would claim a precision the instrument does not have. **Reporting the loss rate beside
the estimate is the whole of what we have to say about how to read it.**

**The two `unattributable` pairs are this paper's own §4.5 recurring against it.** They died while
the host's swap file was exhausted and the model server had 2.3 GB of its own address space paged
out; one arm then exceeded a 594-second budget on a prompt trimmed to 16,000 characters, which is
inexplicable for a model generating from RAM and unsurprising for one generating from disk. We had
retained per-sample outputs, as our own rule requires. What went unrecorded was the environment the
measurement ran in. The harness now captures `MemAvailable`, `SwapFree` and the server's
resident-versus-swapped split at both ends of every arm and the scorer screens on it — forward only,
never for data already collected.

**Three arms failed outright; two were re-run and one deliberately was not.** Two carried a
`Connection error` from a restart race, meaning the measurement never happened, and were re-run. The
third was the 630-second timeout, which is an outcome — deleting an outcome one dislikes is selection
rather than repair. The recovered pair contributed a −4, against the hint.

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
