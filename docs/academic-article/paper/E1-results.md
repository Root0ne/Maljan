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
| precision | 0.2413 | [0.2123, 0.2711] |
| recall | 0.1328 | [0.1131, 0.1529] |
| **F1** | **0.1526** | **[0.1344, 0.1709]** |

n = 97, bootstrap CI, seed recorded. CAPE asserted at least one technique on **every** sample
(1 minimum, 11 median, 33 maximum), so this is a real predictor rather than an artefact of an empty
one. Ground truth resolution uses the same alias map as the drift harness, so the two studies score
identically.

**And here is what the pipeline adds to it.** On the samples where both have been run, scored
per-sample against the same ground truth:

| | mean F1 |
|---|---|
| CAPE alone, no language model | **0.1130** |
| pipeline, static evidence only | **0.1130** |
| pipeline, with the sandbox report | **0.1160** |

Three analyst agents, a negotiation loop, a revision pass, an LLM judge and a weighted corroboration
cascade land within **0.003 F1** of the signature engine they are built on top of. The two means
agreeing to four decimal places is a coincidence and was checked rather than reported: every one of
the samples differs individually, by as much as 0.13 in either direction. The system is not
reproducing the sandbox's answers — it reaches different answers of the same quality. This
comparison is interim at the n reached so far and is the number most likely to move; its direction
has been stable across every reading taken while it accumulated.

**Why 95 and not 100, and why the reason is not the one we first wrote down.** The cohort was
submitted as one batch and the sandbox reported every task as complete. It had not been. Querying
each task's timing shows a split with nothing between the modes: the 43 tasks whose reports survived
ran for 186–366 s, and the other 57 ran for **zero to one second**, 56 of them still marked
`reported`, none with a report directory. A Windows PE does not detonate in one second. The ordering
implicates the instrument rather than the samples — real analyses run through one afternoon and
every task after roughly 17:30 returns instantly — and re-submitting the same binaries from the same
local files two days later produced full-length analyses on the same instance. 56 of the 57 were
recovered that way; three failed in processing or reporting and are permanently gone.

We had originally written that the analyses ran and their reports had expired. That was the
comfortable reading of `Reports directory does not exist`, and it was wrong. The correction matters
beyond the sample count: a completion status from this instrument is not evidence that anything
happened, which is why the retrieval path now checks each analysis's wall-clock duration before
accepting its report (§E6).

We report the baseline first because without it a pipeline F1 is uninterpretable, and because it
sets a bar the pipeline must clear to have contributed anything. Earlier drafts of this work
reported F1 values against nothing at all.

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

A 3.4× larger reasoning model, given the same evidence and the same nominal output budget, lands
within three thousandths of F1 of a 35B model quantised to run on one desktop GPU, and its
direction across samples is a coin flip.

**We have since found that the two arms were not configured alike, and we report the null with that
caveat attached.** The local arm runs with its reasoning stream disabled — necessarily, because the
local server otherwise returns an empty answer — while the frontier arm ran with reasoning on and
spent 56.5% of its budget there. The nominal budget was equal; the budget available for an *answer*
was not. How much this matters we can bound from a third endpoint measured later on the same
fixtures: with reasoning enabled it spent 99.9% of every call's budget thinking and scored **0.000**
across all 25 calls, and with reasoning disabled the same model scored **0.4501**. One flag was
worth 0.45 F1 — more than every architectural effect in this paper combined. The frontier arm above
was not crippled that way (it parsed 25 of 25), so the null is not an artefact of a collapsed arm;
but it is not the single-variable comparison it appears to be.

**The matched arm cannot be built on that endpoint, and we established this by measurement rather
than by assumption.** We re-ran the 120B arm with the reasoning parameter set. The provider accepted
it and ignored it: 56.2% of the output was still reasoning, against 56.5% without it, and the arm
returned 0.4149 where the first run returned 0.4162 (paired Δ = −0.0014, 95% CI [−0.0929, +0.0874],
n=25). The re-run is therefore a replication of the original configuration, not a correction of it.
The confound in this comparison is a property of the endpoint, and we report the null with the
confound stated rather than promising a cleaner version of it.

**A matched comparison is available on different weights, and it bounds two things at once.** The
model we run locally, `qwen3.6-35b-a3b`, is also hosted by its vendor at full precision on an
endpoint that does honour the flag. Against our local 3-bit deployment, on the same fixtures and
repeats:

| arm | precision | reasoning | mean F1 | paired vs local | n |
|---|---|---|---|---|---|
| local | IQ3_K_R4 (3-bit) | off | 0.4136 | — | 25 |
| vendor-hosted | full | off | 0.3507 | **−0.0629** [−0.1484, +0.0256] | 25 |
| vendor-hosted | full | on | 0.0080 | −0.4056 [−0.4667, −0.3418] | 25 |

Two results follow. First, **quantisation is not this pipeline's handicap**: the 3-bit local
deployment is not measurably worse than the vendor's own hosting of the same weights, and the
direction is if anything in its favour. Second, **the reasoning flag replicates at 0.3427 paired**
(95% CI [−0.4264, −0.2654]) on a second model — this time the one we host — with 24 of 25 calls
exhausting the output budget on reasoning. The largest effect we have measured on any arm in this
paper is a configuration flag, not an architecture and not a parameter count.

We report the frontier null because the literature's prior predicts otherwise:
`arXiv:2606.18166` found parameter size the *only* statistically significant predictor of
ATT&CK-classification F1 (ρ=0.85, p=0.014) on the nearest task. On this task, at this budget, we do
not reproduce that — and we cannot test it as a series either: a rank correlation over model size
needs the arms matched on the flag that is worth more than the size effect, and the only endpoint
we have above 35B does not permit that match. Two of our arms are configuration-matched and both
are 35B, so the series is two points at one size. We state this as a limitation with a measured
cause rather than as an untested claim in either direction.

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

The multi-layer corroboration set is the design's central claim about evidence quality. We remove
one Layer-0 source at a time and compare the bundle the analyst receives against the bundle produced
with all of them, under two conditions that differ in exactly one respect — whether the removed
source was the sole owner of its techniques.

| condition | what removing a source does to the evidence | verdict changed | Jaccard vs all-sources |
|---|---|---|---|
| disjoint | its techniques disappear; nothing else claims them | **32/32** | 0.738–0.765 |
| overlap | its techniques survive under a partner source, but their **corroboration** changes | **0/32** | **1.000 [1.000, 1.000]** |

Take a technique away and the bundle loses it. Leave the technique in place and destroy the
cross-domain agreement behind it — the thing the cascade exists to compute — and the bundle is
byte-identical. The cascade runs, weights each source by a trust coefficient, and reports a
corroborated set in the run summary; none of that reaches the artefact the analyst is given.

**Why the bundle behaves that way is not what we first wrote, and the difference matters.** Our
initial reading was that the judge attends to the claim list and ignores everything else. It does
not read either. A post-processing step reconciles the bundle against the cascade: every
`attack-pattern` whose technique ID cannot be resolved is dropped, and every cascade technique
missing from the bundle is appended. The cascade's technique set is therefore a guaranteed subset
of every bundle the system emits, independent of what the judge produced. Checked against all 80
stored arms by recomputing each arm's cascade set from the same seeded fixtures: **the bundle is
exactly the cascade's technique set in 80 of 80, and the judge contributes zero techniques to any
of them.**

Both rows of the table then follow from set arithmetic. Under overlap, removing a source whose
claims a partner also makes leaves the cascade's set unchanged, so the bundle cannot change — 0 of
32 is a necessity, not a measurement of restraint. Under disjoint, removing a source deletes its
techniques from that set, so the bundle shrinks — 32 of 32, equally necessary. The Jaccard of
1.000 with a zero-width interval was the tell we missed: a language model at temperature 0, asked
32 times, does not usually agree with itself perfectly. We read a constant as a strong null.

The architectural conclusion is unchanged and, if anything, sharper. Corroboration does not reach
the analyst's artefact. But the reason is not that a model overlooked it: **the judge cannot
subtract from the bundle's technique set, and across 80 arms it added nothing to it.** Omissions
are restored by reconciliation; additions would have survived, and there were none.

We stated that bound rather than the stronger claim it invites, because the evidence could not
distinguish a judge whose output was unusable and wholly replaced from one that reproduced the
cascade's set exactly. **That measurement has since been taken**, by intercepting the
reconciliation step and recording what the model produced before the deterministic set was merged
in. On the four calls that reached it:

| | total | per call |
|---|---|---|
| attack-patterns the judge emitted | 50 | 12.5 |
| carrying a resolvable ATT&CK ID | 12 | 3.0 |
| **dropped — the model named no technique** | **38 (76.0%)** | 9.5 |
| **IDs the cascade did not already hold** | **0** | 0.0 |
| injected because the judge omitted them | 87 | 21.8 |

Three of the four calls produced nothing nameable at all; the fourth named twelve techniques, every
one already in the cascade. Three quarters of the model's own attack-patterns asserted a behaviour
it could not map to a technique and were discarded. Of the two pipelines the bound allowed, the
evidence points at the second: the bundle is the cascade's set wearing the judge's name.

**And half the calls never reached that step.** Four of the eight timed out at the verdict ceiling,
and on a timeout `give_verdict` returns a text-fallback bundle that never calls the reconciliation
routine — so the cascade is not consulted on that path at all. The timeouts are not a property of
the fixtures: the judge's 8,192-token output cap was renamed by our client library to a parameter
the local inference server does not read, so the model decoded unbounded until the caller gave up
(§6, M7). One such call was measured at **30,155 generated tokens** and was still going.

**Repeating the study with the cap fixed turns the pair into a controlled experiment, and the
result inverts the section's own conclusion.** With the ceiling binding, the same four fixtures
fail and the same four succeed; the judge's share of the bundle is 0.0% in both conditions; every
number on the reconciled path is identical. What changes is only how the failure arrives — 8,192
tokens of unparseable output in three and a half minutes, instead of a ten-minute timeout.

But the artefact is not the same. The fallback builder scrapes ATT&CK IDs from two places: the
evidence claims, and the model's own raw response. In the uncapped condition that response is the
literal string `[TIMEOUT]` and contains no IDs, so the fallback bundle was exactly the
evidence-derived set — identical to the cascade set on all four calls. In the capped condition it
is 18,748 to 24,710 characters of degenerate decode, and:

| fixture | fallback | cascade | **only in fallback** |
|---|---|---|---|
| `jhuhugit` | 32 | 20 | **12** |
| `sardonic` | 27 | 25 | **2** |
| `sliver` | **46** | 23 | **23** |
| `wannacry` | 26 | 16 | **10** |

**Forty-seven techniques reach the analyst that the corroboration cascade never held**, and none
goes the other way. On one sample the bundle doubles. Because the uncapped run is a control whose
raw text provably contains no IDs, every one of the 47 is attributable to the model's own output.
They passed through no filter at all — not the cascade, not the reconciliation step, not the
invalid-ID filter, not the integrity pass.

They are also, checked against the 691-technique ATT&CK catalogue, **real: 45 of 45 unique IDs
exist, none is invented.** That is worth stating because it removes the easy reading. The pipeline
is not emitting hallucinated identifiers a schema check would catch. It is emitting genuine ATT&CK
techniques that no evidence source claimed and no corroboration supports, in the same object type
and the same bundle as techniques three independent sources agreed on, with nothing downstream to
tell them apart.

So the finding that opened this section needs its scope stated exactly. The verdict model has no
influence over which techniques reach the analyst **on the path where it works**. On the path where
it fails it has more influence than on the path where it succeeds: 0 of 99 techniques when
reconciliation runs, 47 of 131 when it does not. The architecture suppresses the model's
contribution precisely when the model is functioning, and admits it precisely when it is not.

**This replaces an earlier version of the same result, and the replacement is why we trust it.** The
first pass varied three of six Layer-0 sources — the three needing no sandbox — over fixtures
carrying five techniques, and reported the verdict unchanged in 0 of 15 cases. Two defects were
found in it afterwards. The absent sources included the Sigma layer, which fires on 94 of 97 samples
at weight 0.55, above every static layer that study did vary; and at five techniques over six
sources, round-robin assignment left one source with nothing, so its arm was identical to the
baseline by arithmetic rather than by measurement. The re-run uses fixtures of 12 to 51 techniques so
every source carries at least three claims, includes the Sigma layer, and adds a corroborated source
pair that does not involve YARA so that no arm's result is a foregone conclusion. The null survives
all of it, at 32 arms rather than 15.

**One pre-registered prediction, resolved in both directions.** We predicted that removing the
tool-artifact layer would change nothing, because it emits on YARA's cascade domain and therefore
cannot contribute corroboration. In the overlap condition that is exactly right: 0 of 8. In the
disjoint condition it is wrong: 8 of 8, because there that source solely owns its techniques and
removing it removes them. The prediction was about corroboration and it holds precisely where
corroboration is the only thing varying — which is the sharpest evidence we have that the two
conditions measure what we claim they measure.

Two Layer-0 sources are absent from these arms by measurement rather than by choice. Over the 95
archived reports the LOLBin layer and the DGA layer each produce a claim on **0 of 97**, while being
fed a median of 8888 recorded API calls and 48–68 domains per sample respectively. They are offered
the evidence and decline it; giving either an equal share of the ground truth would have ablated a
mechanism that never engages in this deployment.

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
