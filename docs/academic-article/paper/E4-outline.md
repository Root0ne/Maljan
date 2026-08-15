# Paper outline and abstract

*Framing locked at D3 (2026-08-11): **F3 — measurement validity**, on the evidence that B1 returned
null. This file is the structure the LaTeX will follow, plus the abstract and introduction in draft.
Section bodies live in `E1-results.md`, `E2-threats-to-validity.md`, `E5-reproducibility.md` and
`../related-work.md`.*

## Working title

**What It Takes to Trust a Measurement: Instrument Failures in an LLM Malware-Analysis Pipeline**

Alternatives considered: *"The Instrument Answers a Different Question"*; *"Three Retrievers, No
Effect: Negative Results from an LLM ATT&CK Pipeline"*. The first is preferred because the
contribution is the discipline, and the negatives are evidence for it rather than the subject.

## Abstract (draft)

> We report a year of measurements from a multi-agent LLM pipeline that maps malware evidence to
> MITRE ATT&CK techniques, and the methodological problem those measurements kept running into: the
> instrument was frequently wrong in ways that produced plausible results rather than errors.
>
> Four of our architectural claims were tested and did not survive. Negotiated multi-agent consensus
> did not beat a single judge at equal token budget (paired ΔF1 {{consensus_negotiated_delta}}, 95% CI [−0.084, +0.050], at
> 3.2× the tokens). Three independently built retrieval components — an ATT&CK case-prior index, a
> family-feature index, and an opcode-hash attribution tier — each work in isolation and contribute
> +0.003 F1, lose to a frequency prior, and fire on 0 of 18 samples respectively. A deterministic
> confidence cap fires on 0.82% of techniques. A 120B reasoning model did not separate from our local
> 35B on identical fixtures at equal nominal budget (paired ΔF1 **+0.003**, 95% CI [−0.077, +0.081],
> n=25) — a null we report with a confound its provider will not let us remove, since the parameter
> that would have matched the two arms' reasoning budgets is accepted and ignored there.
>
> The verdict model's influence over its own output is not small but **conditional on it working**.
> Where the model returns a parsable verdict it supplies **{{judge_capped_own_ids}} of {{judge_capped_bundle}}** techniques in the bundle the
> analyst receives; a post-processing step restores the deterministic set regardless. Where it fails
> — half of calls, in a degenerate decode our own output cap had never bounded — a text fallback
> scrapes identifiers out of the unparsable response, and **{{fallback_only_capped}} techniques reach the analyst that no
> evidence source corroborated**, in the same object type as those three sources agreed on. All 45
> unique identifiers are real ATT&CK techniques, which is what makes them indistinguishable.
>
> Seven defects produced *plausible wrong answers with no error anywhere*. Four are at boundaries
> with other people's servers: unset optional arguments sent as `null`, a loaded program that never
> became the server's current program, a refused load returning HTTP 200, and two protective bounds
> composing into an empty result. **Three are ours** — an ablation that varied a deterministic code
> path and reported a language model, a correlation that ranked a configuration flag and reported a
> parameter count, and a documented output ceiling renamed during serialisation to a key the
> inference server does not read. A suite of {{test_count}} passing tests caught none of them, and the last
> three had passing tests over the exact functions concerned. The four boundary defects were all
> found by one check — how many **distinct** outputs N inputs produced; the other three were not,
> and we say what did find them.
>
> One of our studies is withdrawn as a direct consequence, its per-sample outputs not retained and
> its question no longer askable. The same gap then recurred while this paper was written: a paired
> ablation halted on host memory and four arms cannot be attributed to the pipeline or the machine,
> because the retention rule we adopted after the first failure was scoped to that failure.
>
> We contribute the measured negatives, the failure mechanisms with the layer each occurred at, the
> cheap detector that found four of them, and a no-LLM baseline (F1 {{baseline_f1}}, n={{baseline_n}}) against which all of
> it is read. We argue that in a pipeline assembled from other people's servers a server that answers
> is not the same as a server that answered your question — and that the same shape does not stop at
> the network boundary: it appears wherever a measurement's cause is assigned rather than measured.

## Structure

| § | Section | Source | Status |
|---|---|---|---|
| 1 | Introduction | this file | draft below |
| 2 | Background & Related Work | `../related-work.md` §§1–6 | written; [17]–[23] need full-text verification |
| 3 | System, briefly | `E3-system.md` | written — deliberately short; the system is the setting, not the claim |
| 4 | Measurement methodology | `E7-methodology.md` | written — equal budgets, paired designs, firing-rate-before-effect, output cardinality |
| 5 | Results | `E1-results.md` | written |
| 6 | Instrument failures | `E6-instrument-failures.md` | written — the central chapter |
| 7 | Threats to Validity | `E2-threats-to-validity.md` | written |
| 8 | Conclusion | `E8-conclusion.md` | written |
| A | Reproducibility | `E5-reproducibility.md` | written |

## Introduction (draft)

Three claims organise this paper.

**First: the architecture we built did not survive its own evaluation.** The system is a multi-agent
pipeline over static, dynamic and network evidence, with a corroboration cascade, two retrieval
tiers, and deterministic confidence gating. Each component was motivated by a plausible mechanism.
Measured at equal token budget against simpler alternatives, the multi-agent design does not beat a
single judge; the corroboration set never changes a verdict; the confidence number the gates consume
discriminates at AUC 0.550; and all three retrieval components are near-inert end to end despite
working in isolation. We report these as results rather than as tuning opportunities.

**Second: those nulls are only interpretable because we measured whether each mechanism fired.** A
deterministic confidence cap that fires on 0.82% of techniques produces an ablation whose null
result says nothing about the cap. A priority hint that fires on 56.7% of samples produces one that
does. We adopted **firing rate before effect** as a rule after the first case, and it changed which
experiments were worth running.

**Third, and the reason for the paper's title: the instrument was repeatedly wrong in ways that
looked like data.** Over one week we found four defects at the boundaries between the pipeline and
the servers it depends on. In each case a server answered successfully and answered about something
else: an argument the agent never supplied arrived as an explicit `null`; a program reported as
loaded — by name — never became the one being analysed; a refused load returned HTTP 200 with an
error in the body; and two bounds designed to protect the analyst composed into a path that
returned nothing at all. None was caught by {{test_count}} passing tests, because each needs a *second* case
in one server lifetime, and a unit test writes one.

Every one of those four was caught the same way: **a number repeated where variation was expected.**
A hint of exactly 2,575 characters for two unrelated binaries; call graphs identical to the
character for samples of 241 KB and 139 KB; 66 consecutive samples at 75,426 characters. The check
costs one line, needs no ground truth, and we now report it beside every batch result.

**Then three more, and none of them was at a boundary.** An ablation varied a deterministic
post-processing step and we attributed its output to a language model. A rank correlation over model
size ranked a reasoning-configuration flag instead and recovered the published scaling coefficient
almost exactly — agreeing with the literature, which is the direction a result is least likely to be
questioned. And a documented output ceiling on the verdict model was renamed by our client library
during serialisation to a key the inference server does not read, so a component we describe as
bounded had never once been bounded. The detector above does not find these: their outputs *do*
vary. Two were caught by a number too clean to believe, one by a study that recorded which failure
branch each call took. Each had passing unit tests over the exact function concerned, because the
defect was never in a function — it was in which measurement was attributed to which cause, or in
which representation of a value crossed a boundary.

We report them because the correction is part of the result. Two published findings of ours were
withdrawn or rewritten on their account, and a third was one report away from being published as a
scaling law.

The cost of not having had it is concrete: **a completed 210-sample study is withdrawn from this
paper.** It met the precondition for one of the defects, and its per-sample outputs were not
retained, so whether it was affected cannot be established. We report the withdrawal rather than the
result.

We do not claim the category, and we counter-searched the newest mechanisms before claiming them
either. Silent failures in production LLM agent runtimes are already described and taxonomised [20];
"distinct inputs should produce distinct outputs" is an ordinary metamorphic relation [22]; that an
inference-time constraint can invert model rankings and confound a comparison is established, with a
28.4-point reversal, in [24]; and the token-limit incompatibility between OpenAI-compatible servers
is documented in their own issue trackers. Every mechanism we report sits inside a published class,
and one of them — the configuration difference masquerading as a scaling result — is a domain
instance of [24] rather than a new phenomenon.

What we add is the setting and the price: an **evaluation pipeline for security research**, where
the artefact is not a degraded user session but a measurement that is wrong and looks right. Three
mechanisms at three distinct integration boundaries; a detector reported alongside results; a
selection rule that follows from a provider accepting a parameter and not acting on it, so arms must
be matched on their *measured* configuration and not their requested one; and one withdrawn study as
the demonstrated consequence.

## Methodology (to write — the material exists)

Five practices, each adopted after a specific failure:

1. **Equal token budgets across arms**, with a stochastic-noise control. Adopted from Bertalanič &
   Fortuna; without it, a multi-agent arm wins by spending more.
2. **Paired designs and bootstrap intervals**, never single-run counts — a single-run parsed-claim
   count ranked the same arms differently at different decoding budgets.
3. **Firing rate before effect.** §4 of Results.
4. **Output cardinality reported with every batch.** §6.
5. **Per-sample outputs retained for every study.** Adopted after the withdrawal.

Plus two audits that are cheap and caught real errors: diffing the claim register against the
evidence log, and counter-searching each novelty claim in an *adjacent field's* vocabulary — the
latter demoted five claims in this project, including one of the two central to this paper.

## Conclusion (to write)

Intended thrust: the pipeline's contribution turned out not to be its architecture. Of four
architectural claims, three are measured negative or near-null and one awaits sandbox access. What
survived is the account of measuring them, and the specific observation that in a system assembled
from other people's servers, correctness of the model is not the binding constraint on correctness
of the result.
