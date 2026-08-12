# Measurement Methodology

*Draft for the paper, §4. Every practice here was adopted after a specific failure in this project,
and each is stated with the failure that motivated it — a rule with no incident behind it is advice,
not method.*

## 4.1 Equal budgets, with a noise control

Arms are compared at an **equal total token budget**. A multi-agent arm that makes N calls receives
B/N per call against a single arm's one call of B, so a win cannot come from spending more. The
design follows Bertalanič & Fortuna, including a **stochastic-noise control** in which one analyst
receives evidence irrelevant to the sample.

The control is not decoration: it establishes that the harness can detect a difference. In our
consensus study the noise arm separated clearly (0.3366 against 0.3975 and 0.4136) while the
treatment did not, which distinguishes "no effect" from "no sensitivity".

**For reasoning models the budget must cover reasoning.** Our frontier endpoint reports reasoning
tokens separately from content, and **56.5%** of its output was reasoning across 25 real prompts
(84% on a one-token answer). Capping content alone would have granted it roughly twice the generation for the
same nominal budget.

## 4.2 Paired designs, bootstrap intervals, and never a single run

Every arm sees the same samples in the same order; differences are computed **per sample and then
aggregated**, with 95% bootstrap confidence intervals over the paired deltas.

The motivating failure is specific. An early study ranked prompt structures using a **single-run
parsed-claim count**, and the ranking **inverted** when the decoding budget changed — the instrument
was measuring the interaction of structure and budget while being read as measuring structure. A
claim count from one run is not an instrument, and we now say so where that result is cited.

## 4.3 Firing rate before effect

Before ablating a mechanism, measure **how often it engages**. The rule came from two cases that
look identical in a results table and are not:

| mechanism | fires on | what an ablation would mean |
|---|---|---|
| confidence cap | **0.82%** of techniques | nothing — a null describes the 99.2% where it never ran |
| sink-reachability hint | **56.7%** of samples | a real statement about the hint |

The cap's own preconditions explain its rate — three technique families, only when the sole
contributing layer is static, and 84% of those claims are YARA-only, so no static claim exists for
it to discipline. Reporting the rate is more informative than an ablation of it, and cheaper.

A corollary: an ablation must be **restricted to the samples where the mechanism fires**, and must
report the remainder separately. Averaging a feature over inputs it never touched dilutes a real
effect toward zero and manufactures a null.

## 4.4 Output cardinality, reported beside every batch

**How many distinct outputs did the N inputs produce?** If far fewer than N differ on a dimension
that should vary, the instrument is repeating itself. All four defects in §6 were found this way,
and none by a 1,995-test suite.

It is reported as a result column, not run as a test, because the signal exists only in the batch:
each individual response was well-formed and plausible. We report 50 distinct call-graph sizes
across 79 samples, 63 across 97.

## 4.5 Per-sample outputs are retained for every study

Aggregates cannot be re-interrogated. When a defect was found that *might* have affected a completed
210-sample study, the question could not be asked, because only the summary survived — and the study
is withdrawn as a direct consequence.

The policy is therefore not "keep the numbers" but **keep enough to re-ask a question that has not
been thought of yet**: per-sample predictions, the resolved ground truth, timings, and the identifier
of every external task the run depended on.

## 4.6 Fresh server state per sample

Shared, long-lived servers accumulate state that crosses sample boundaries. In our sweeps, restarting
the reverse-engineering server between samples **recovered 12 of 14 samples previously recorded as
unmeasurable** — the failures belonged to the state each sample inherited from its predecessor, not
to the samples themselves. A read timeout leaves the JVM mid-analysis and every subsequent load is
refused; without restarts, one slow sample silently invalidates the window that follows it.

The same applies to the model server: it grows with cumulative requests and does not plateau
(10.4 GB fresh, 14.8 GB after one pass), so long paired runs restart it between arms. At temperature
0 this is measurement-neutral.

## 4.7 Two audits that cost minutes and caught real errors

**Diff the claim register against the evidence log.** Both documents are maintained; that is exactly
what allows them to diverge. Applied twice here, it found a claim recorded as novel one hour after
our own text called it a replication, an audit row mis-attributing a model caveat to a server-free
harness, and three ledger rows still carrying superseded figures.

**Counter-search each novelty claim in an adjacent field's vocabulary.** A claim of novelty is a
*searched absence*, and searching in one's own field's words finds nothing by construction. Five
claims were demoted this way — including the one central to this paper, when the silent-failure genus
turned out to be already taxonomised. Two rules learned from doing it:

* A search summary is a lead, not a source. One asserted prior art that neither candidate paper
  contained when fetched; citing it would have put a fabricated reference in the ledger.
* The result of a counter-search is recorded whether or not it demotes anything, because "we looked
  and found nothing" is only credible if the looking is documented.

## 4.8 What this costs

These practices are cheap individually and expensive together, and the expense is honest to report.
The firing-rate rule adds a measurement before every ablation. Per-sample retention adds storage
(~660 MB of sandbox reports for one cohort). Fresh state per sample adds ~20 seconds of restart to
every sample. Output cardinality adds one line.

Against that: one withdrawn study, four defects that produced plausible wrong data, and three
retrieval components that would have been reported as working had they only been tested in
isolation. On this project the practices paid for themselves several times over, which is the only
argument for them we can make from a single system.
