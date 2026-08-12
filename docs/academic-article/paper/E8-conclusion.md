# Conclusion

*Draft for the paper, §8. Written last, from the measured record, and deliberately short: a
conclusion that introduces evidence is a results section in the wrong place.*

We built a multi-agent LLM pipeline for mapping malware evidence to ATT&CK techniques, and then
spent longer measuring it than building it. This paper reports what the measurements said, and the
methodological problem we kept running into while taking them.

## 8.1 The architecture did not survive its own evaluation

Four claims motivated the design. Measured against simpler alternatives at equal token budget, they
did not hold.

| claim | measured |
|---|---|
| negotiated multi-agent consensus beats a single judge | ΔF1 **−0.016**, 95% CI [−0.084, +0.050], at **3.2×** the tokens |
| a multi-layer corroboration cascade improves the verdict | verdict identical in **0 of 15** cases where the corroborated set was varied |
| two-tier attribution identifies families | opcode-hash tier fires on **0 of 18** samples; family-feature retrieval contributes **+0.003 F1** |
| falsification-before-confidence disciplines claims | the cap fires on **0.82%** of techniques |

None of these components is broken. Several work in isolation, and each was built for a reason we
would give again. They simply do not move the end-to-end result. We report that as a result rather
than as a tuning opportunity, and note that the noise control separated cleanly (0.3366 against
0.3975 and 0.4136) — so these are nulls from an instrument demonstrated able to detect a difference,
not from one unable to see anything.

Two further negatives constrain how the rest should be read. Verbal confidence — the number the
cascade and every deterministic gate consume — discriminates correct from incorrect claims at **AUC
0.550**, so those gates are keyed to noise. And a 120B reasoning frontier model did not separate from
our local 35B on identical fixtures at equal budget — paired **ΔF1 +0.003**, 95% CI [−0.077, +0.081],
n=25, better on 12 of 25 and worse on 13 — which means the ceiling we kept attributing to model
capacity is not obviously that.

## 8.2 The nulls are interpretable only because firing rates came first

A mechanism that never runs produces an ablation whose null describes the cases where it never ran.
The confidence cap fires on 0.82% of techniques and the sink-reachability hint on 56.7% of samples;
an ablation of the first would have been uninterpretable and reported as evidence anyway. Measuring
**firing rate before effect** changed which experiments were worth running, and it is the cheapest
practice in this paper.

## 8.3 The instrument was repeatedly wrong in ways that looked like data

This is the finding we did not expect to be the paper. Four defects at the boundaries between our
pipeline and the servers it depends on each produced *plausible results rather than errors*: an
unset optional argument arriving as an explicit `null`; a program reported as loaded, by name, that
never became the one being analysed; a refused load returning HTTP 200 with the error in the body;
and two protective bounds composing into an empty result. **A suite of 1,995 passing tests caught
none of them**, and not because the tests were bad — each defect requires a second call, a second
server, or a large input, which is precisely what a fast unit suite is built to avoid.

All four were found by one arithmetic check: **how many distinct outputs did N inputs produce?** A
priority hint of exactly 2,575 characters for unrelated binaries; 66 consecutive samples at exactly
75,426. It needs no ground truth and no oracle, which is what makes it usable where correctness is
hard to check, and it belongs beside sample size in an evaluation report rather than inside a test.

We are careful about what is new here. Silent failure at tool boundaries is documented, the
metamorphic relation behind our detector is ordinary, and the genus has a published taxonomy. Our
contribution is narrower: three distinct integration boundaries plus one composition of local
bounds, in a setting where the artefact is **a measurement that is wrong and looks right**, and a
demonstrated price rather than a hypothesised one.

## 8.4 What it cost, including while writing this

One completed study is withdrawn — a 210-sample temporal-drift analysis that had passed review and
been cited internally for weeks. It is withdrawn not because the defect certainly affected it, but
because its per-sample outputs were not retained and **the question can no longer be asked of it**.

The discipline then caught us a second time, one level up, during the final experiment. A paired
ablation halted at 10 of 24 arms when the host exhausted its swap file; four arms had died in ways
that may belong to the pipeline or to a machine whose model server had 2.3 GB of itself paged out.
We had retained per-sample outputs, as our own rule requires. We had not retained per-sample **host
state**, and that is what the question needed. The arms are reported as unattributable rather than
as failures, and the effect of that mechanism remains unmeasured.

We report this rather than quietly re-running it because it is the paper's own thesis arriving
uninvited: the rule you wrote after the last failure is scoped to the last failure. Retention
policies are written about the object under study; the environment the study runs in is also part of
the instrument.

## 8.5 What we claim, and what we do not

We claim: the measured negatives above; four failure mechanisms with the boundary each occurred at;
a detector that found all four and costs one line; and a no-LLM baseline of **F1 0.187**, without
which none of our F1 numbers refer to anything.

We do not claim that multi-agent decomposition cannot work, that these retrieval designs are
worthless, or that our practices generalise beyond one system. This is one pipeline, one 35B model
at one quantisation, on one machine, evaluated on Windows PE malware. The dynamic-evidence
experiments this design most needs remain gated behind sandbox access and are not reported.

What we do assert is a change of default. In a pipeline assembled from other people's servers, the
correctness of the model is not the binding constraint on the correctness of the result. Long before
a benchmark score is a claim about a system, it is a claim about an instrument — and **a server that
answers is not the same as a server that answered your question.**
