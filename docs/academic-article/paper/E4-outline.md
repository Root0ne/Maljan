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

> Multi-agent LLM pipelines are being built to map malware evidence to MITRE ATT&CK techniques, and
> their components are rarely measured against the deterministic tooling they sit on top of. We
> evaluate one such pipeline, and report why several of our own measurements of it were wrong.
>
> Scored per sample on the same binaries and the same ground truth, the full pipeline reaches F1
> {{h2h_dynamic_f1}} where the sandbox it is built on reaches {{h2h_cape_f1}} — paired
> {{h2h_delta}}, 95% cluster CI {{h2h_ci}}, at a resolution of {{h2h_mde}}. Negotiated multi-agent
> consensus does not beat a single judge at equal token budget
> ({{consensus_negotiated_delta}}, {{consensus_negotiated_ci}}, at {{consensus_token_ratio}}× the
> tokens). Verbal confidence, the number every deterministic gate consumes, ranks correct claims
> above incorrect ones at AUC {{confidence_auc}} [{{confidence_auc_lo}}, {{confidence_auc_hi}}] —
> indistinguishable from chance.
>
> Seven defects in our own instrument produced plausible results rather than errors, and a suite of
> {{test_count}} passing tests caught none of them. Four crossed a boundary with another server; three
> did not, and those three share a different shape — a measurement's cause assigned rather than
> measured. The largest instance is this paper's own statistics: every interval we published
> resampled rows when the observations were clustered, and correcting it widened our anchor interval
> {{baseline_f1_widening}}-fold and turned two equivalence claims into bounds.
>
> We contribute the measured negatives with the minimum detectable effect beside each, seven failure
> mechanisms with what found them, and a no-LLM baseline (F1 {{baseline_f1}}, n={{baseline_n}} over
> {{baseline_families}} families) without which none of these numbers refers to anything.

## Structure

| § | Section | Source | Status |
|---|---|---|---|
| 1 | Introduction | this file | draft below |
| 2 | Background & Related Work | `../related-work.md` §§1–6 | written; **[16]–[25] all fetched and verified 2026-08-15** — three were wrong and are corrected, five never-fetched ids dropped |
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
discriminates at AUC {{confidence_auc}}; and all three retrieval components are near-inert end to end despite
working in isolation. We report these as results rather than as tuning opportunities.

**Second: those nulls are only interpretable because we measured whether each mechanism fired.** A
deterministic confidence cap that fires on {{cap_rate}} of techniques produces an ablation whose null
result says nothing about the cap. A priority hint that fires on {{hint_rate}} of samples produces one that
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
A hint of exactly {{hint_chars_repeated}} characters for two unrelated binaries; call graphs identical to the
character for samples of 241 KB and 139 KB; 66 consecutive samples at {{stuck_graph_chars}} characters. The check
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
the artefact is not a degraded user session but a measurement that is wrong and looks right.

**Contributions.** Each maps to one section, and each is a measurement or a mechanism rather than a
proposal.

1. **A no-LLM baseline for LLM-based ATT&CK mapping**, and the full pipeline scored against it on
   the same samples and the same ground truth — the comparison without which every F1 in this
   literature, including our own earlier ones, refers to nothing (§5.1).
2. **Four measured architectural negatives** — multi-agent consensus at equal budget, a corroboration
   cascade, two-tier attribution, and a confidence gate — each reported with the minimum detectable
   effect of the design that produced it, because a null without its resolution is unreadable
   (§5.2–§5.6).
3. **Seven instrument failures that produced plausible results rather than errors**, with the layer
   each occurred at and what actually found it. Four crossed a boundary with another server; three
   were inside our own code and share a different shape (§6).
4. **A one-line detector** — how many distinct outputs did N inputs produce — that found all four
   boundary failures, needs no ground truth, and is reported beside every batch result rather than
   written as a test (§6.7).
5. **A selection rule that follows from a provider accepting a parameter and not acting on it**: arms
   must be matched on their *measured* configuration, not their requested one (§6.5).
6. **The price, demonstrated rather than hypothesised**: one completed 210-sample study withdrawn
   because its question can no longer be asked of it, and four arms of a later ablation
   unattributable for the same reason one level up (§7.4).

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
