# Discussion

*Interpretation lives here. Results states what was measured; this section says what follows from
it, and separating the two is not a formality — several of the sentences below were sitting in
Results, where a reader could not tell a measurement from a reading of one.*

## What a null means at this cluster count

The most consequential thing we can say about our own negative results is that most of them are
bounds rather than equivalences, and that we did not know this when we first wrote them down.

Five of the studies reported here run on a corpus of five samples. At five clusters the exact
two-sided cluster permutation test cannot return a value below {{fixture_signflip_floor}}, so **no
comparison measured on that corpus can reach α = 0.05 whatever its effect size**. That is a property
of the design, not of the data, and no amount of extra decoding repeats moves it — repeats add rows
inside clusters, and rows inside clusters are not what the test counts. Multiplicity correction is
therefore beside the point on that corpus: we apply Benjamini-Hochberg over two declared families
and it finds nothing to correct, because there was nothing at α = 0.05 to begin with.

The practical consequence is that a null has to be reported with its resolution. Our frontier-model
comparison could detect a difference of {{mde_frontier_local}} F1 at 80% power and returned
{{frontier_local_delta}}. Both facts are true, and only the pair of them is informative: the second
alone reads as equivalence, and the first alone reads as a failed experiment. We now report the
minimum detectable effect beside every null in this paper, and we would put it beside every null we
read in someone else's.

This also changes what we think the cheap fix is. The instinct on seeing an underpowered paired
design is to add repeats, because repeats are cheap and samples are expensive. On clustered data
that instinct is exactly wrong. Adding a sixth fixture would have moved the attainable p from
{{fixture_signflip_floor}} to half of it; adding a sixth repeat to five fixtures moves it not at all.

## Where a measurement's cause is assigned rather than measured

The failure taxonomy we counter-searched against organises silent failures by the boundary crossed
[20]. Four of our seven crossed one: a sandbox, a decompiler server, an inference endpoint. Three
crossed none. No server misled us, no protocol was involved, and no network was in the path.

What the seven share is not a boundary but an **attribution**. In each case a measurement's cause
was assigned rather than measured. An ablation varied a deterministic post-processing step and we
attributed the difference to a language model. A rank correlation ordered a
reasoning-configuration flag and we attributed the ordering to parameter count. A documented output
ceiling was renamed during serialisation and we attributed boundedness to a component that had never
once been bounded. In every case the number was real and the arrow pointing to its cause was drawn
by us.

We offer that as a proposal rather than a taxonomy. Seven cases from one project is not a class, and
the published taxonomy is built on a corpus we cannot match. But it does suggest a different
question to ask of an evaluation than the one boundary-oriented thinking suggests: not *did any
component fail silently*, but *for each number I am about to report, did I measure its cause or
assign it*.

The correction described in §5 is that question turned on ourselves and answered badly. Every
interval in an earlier draft of this paper attributed its width to sampling variation among
independent observations. The observations were not independent, the width was an artefact of the
unit we resampled at, and nothing in the pipeline, the tests or the review caught it — because the
defect was never in a function.

## What a practitioner should take from the negatives

We are wary of drawing implementation advice from one pipeline on one machine, so this is narrow.

**Measure the firing rate before the effect.** A mechanism that engages on {{cap_rate}} of its
inputs produces an ablation whose null describes the cases where it never ran. This is the cheapest
practice in the paper and it changed which experiments were worth running rather than merely how
they were reported.

**Count the distinct outputs.** Four of our seven defects were found by asking how many distinct
outputs N inputs produced. It needs no ground truth and no oracle, which is what makes it usable
where correctness is hard to check. It belongs beside the sample size in an evaluation report rather
than inside a test, because the failures it catches need a second call in one server lifetime and a
unit test writes one.

**Retain per-sample outputs, and then ask what else the study is made of.** We adopted per-sample
retention after losing a study to its absence, and the rule was scoped to the object under study.
The next failure was in the environment: four arms of a paired ablation died on host memory, we had
their outputs and not the host state, and they remain unattributable. The rule you write after a
failure is scoped to that failure.

**A server that answers is not the same as a server that answered your question.** Four of our
defects are instances of it, and the class is documented [20]. Our contribution is the setting and
the price: in an evaluation pipeline the artefact of such a failure is not a degraded user session
but a measurement that is wrong and looks right, and the price we paid was a completed 210-sample
study that can no longer be asked its question.

## What we are not in a position to say

We cannot say that multi-agent decomposition does not help. We can say that on five samples, at
equal token budget, we could not detect a difference larger than {{mde_consensus_negotiated}} F1,
and did not.

We cannot say that model capacity is not the ceiling. We can say that a 3.4× larger model did not
separate from ours at a resolution of {{mde_frontier_local}} F1, that the two arms differed in a
configuration flag worth more than any architectural effect we measured, and that the endpoint would
not let us remove the difference.

We cannot say that verbal confidence is uninformative in general. We can say that in this pipeline,
on this corpus, it ranks correct claims above incorrect ones at AUC {{confidence_auc}} with an
interval of [{{confidence_auc_lo}}, {{confidence_auc_hi}}] that contains chance, and that
{{confidence_at_or_below_chance}} of {{confidence_clusters}} samples sit at or below chance
individually — so the deterministic gates keyed to that number are keyed to something we cannot
distinguish from noise.

And we cannot say that our seven mechanisms generalise. What we can say is what each of them cost.
