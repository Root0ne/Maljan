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
> did not beat a single judge at equal token budget (paired ΔF1 −0.016, 95% CI [−0.084, +0.050], at
> 3.2× the tokens). Three independently built retrieval components — an ATT&CK case-prior index, a
> family-feature index, and an opcode-hash attribution tier — each work in isolation and contribute
> +0.003 F1, lose to a frequency prior, and fire on 0 of 18 samples respectively. A deterministic
> confidence cap fires on 0.82% of techniques. A 120B reasoning model did not separate from our local
> 35B on identical fixtures at equal budget.
>
> More consequentially, four defects at tool-integration boundaries produced *silent wrong answers*:
> unset optional arguments sent as `null`, a loaded program that never became the server's current
> program, a refused load returning HTTP 200, and two protective bounds that composed into an empty
> result. A suite of 1,995 passing tests caught none of them; all four were found by a single check —
> asking how many **distinct** outputs N inputs produced. One of our own studies is withdrawn as a
> direct consequence, because its per-sample outputs were not retained and the question can no longer
> be asked of it.
>
> We contribute the measured negatives, the failure mechanisms with the boundary each occurred at,
> the cheap detector that found them, and a no-LLM baseline (F1 0.187) against which all of it is
> read. We argue that in a pipeline assembled from other people's servers, a server that answers is
> not the same as a server that answered your question — and that evaluation harnesses should report
> output cardinality the way they report sample size.

## Structure

| § | Section | Source | Status |
|---|---|---|---|
| 1 | Introduction | this file | draft below |
| 2 | Background & Related Work | `../related-work.md` §§1–6 | written; [17]–[23] need full-text verification |
| 3 | System, briefly | `findings-log.md` §1 | **to write** — deliberately short; the system is the setting, not the claim |
| 4 | Measurement methodology | this file §"Methodology" | **to write** — equal budgets, paired designs, firing-rate-before-effect, output cardinality |
| 5 | Results | `E1-results.md` | written |
| 6 | Instrument failures | `E2` §"threat that materialised" + `../related-work.md` §6 | written in parts; needs its own section |
| 7 | Threats to Validity | `E2-threats-to-validity.md` | written |
| 8 | Conclusion | — | **to write** |
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
returned nothing at all. None was caught by 1,995 passing tests, because each needs a *second* case
in one server lifetime, and a unit test writes one.

Every one was caught the same way: **a number repeated where variation was expected.** A hint of
exactly 2,575 characters for two unrelated binaries; call graphs identical to the character for
samples of 241 KB and 139 KB; 66 consecutive samples at 75,426 characters. The check costs one line,
needs no ground truth, and we now report it beside every batch result.

The cost of not having had it is concrete: **a completed 210-sample study is withdrawn from this
paper.** It met the precondition for one of the defects, and its per-sample outputs were not
retained, so whether it was affected cannot be established. We report the withdrawal rather than the
result.

We do not claim the category. Silent failures in production LLM agent runtimes are already described
and taxonomised [20], "distinct inputs should produce distinct outputs" is an ordinary metamorphic
relation [22], and the failure modes we hit sit inside published classes. What we add is the setting
and the price: an **evaluation pipeline for security research**, where the artefact is not a degraded
user session but a measurement that is wrong and looks right — with three mechanisms at three
distinct integration boundaries, a detector reported alongside results, and one withdrawn study as
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
