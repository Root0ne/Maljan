# Instrument Failures

*Draft for the paper, §6 — the central chapter. Every mechanism here was observed in this project's
own pipeline; the dates are the days they were found.*

An LLM analysis pipeline is mostly other people's servers. Ours calls a reverse-engineering server
for disassembly, a sandbox for detonation, a vector store for retrieval, and a model server for
inference, over three protocols. Each boundary is a place where a request can succeed and still not
mean what the caller assumed.

This section reports seven such failures. We report them together because they share a shape that a
test suite is poorly positioned to catch and a results table cannot show: **the instrument answered
successfully, and answered about something else.** The last three are ours rather than someone
else's server — two in the analysis code that produces our results, one in the pipeline that
produces the artefact — which is the point: the shape does not stop at the network boundary, and it
does not stop at the evaluation harness either.

## 6.1 Seven mechanisms

### M1 — An unset argument arrives as an assertion

The sandbox's MCP interface declares 36 tools. Every one takes an optional `token` parameter with a
declared default of `""`. Our client built its argument model with "required, else `None`", and the
agent framework fills every declared field before invoking. So an argument the agent never mentioned
reached the server as an **explicit null**, and a field typed `str` rejected it:

```
1 validation error for call[verify_auth]
token
  Input should be a valid string [type=string_type, input_value=None, ...]
```

All 36 tools failed. *Unset* and *null* are different statements, and the client was making the
second while intending the first.

**Why it survived to first contact.** The reverse-engineering server — the only one this client had
ever talked to — declares no optional parameter with a typed default, so the same malformed argument
dictionary happened to be acceptable there. A defect in shared client code was invisible because
only one of the two servers it served had ever been exercised.

### M2 — A load that does not change what the server is looking at

`load_program` imports a binary and answers `{"success": true, "program": "<name>"}`. Every caller
read that as "the server is now looking at this binary". The server maintains a separate notion of
the **current program**, and `load_program` sets it only when nothing is current yet:

```
load A        -> {"success": true, "program": "A"}   current: A
load B        -> {"success": true, "program": "B"}   current: A   <-- still A
run_analysis  -> {"program": "A", "new_functions": 0}
call graph    -> A's graph, byte-identical, for every sample
```

From the **second sample of a container's lifetime onwards**, everything derived — decompilation,
imports, strings, call graph, function hashes — described the first binary while the report named
the current one. The response even contained the correct program name, which is what made it
convincing.

### M3 — A refusal wearing a success

The same server answers a load it cannot perform with **HTTP 200** and an error in the body:

```
{"error": "Failed to load program from: /data/samples/x.exe"}
```

`raise_for_status()` sees nothing wrong. Downstream code then analysed and described whichever
program remained current. When the server began refusing loads after roughly thirty in one
lifetime, **66 consecutive samples produced a call graph of exactly {{stuck_graph_chars}} characters** before
anyone noticed.

### M4 — Two bounds composing into an empty result

The analyst's ReAct loop has a 40-step budget; exceeding it triggers a salvage that re-invokes the
model to synthesise from what was gathered. That salvage received a **fresh copy of the full time
budget** — so loop-plus-salvage exceeded the hard cap by construction. On any binary rich enough to
exhaust the step budget the analysis returned **zero techniques**, at a cost of 28 minutes:

```
loop completed: 19 tool calls, 41 messages, elapsed 109.5s
ended without a final answer ... forcing synthesis
static no-tools fallback exceeded the 1530s hard cap
```

Neither bound was wrong alone. Exceeding the first *guarantees* an attempt at the second, and the
composition was never considered.

### The same mechanism at a fifth boundary — caught before it produced data

M1–M4 were all found after the fact, in data already collected. The fifth was not, and the
difference is the whole argument of this paper.

Fetching the sandbox cohort's reports, we found that a request for a report the sandbox has since
deleted is answered with **HTTP 200** and a 63-byte body:

```
{"error":true,"error_value":"Reports directory does not exist"}
```

Fifty-six of one hundred tasks answer this way — the analyses ran, and their reports have aged out of
retention. A fetcher that trusted the status code would have written fifty-six of those bodies into
the archive under the filename of the sample they were supposed to describe, and the three studies
that read that archive would each have scored them.

They did not, because the fetcher was written to verify the report's own `target.file.sha256` against
the identifier it asked for before writing anything. That check exists only because M3 taught us the
shape: an HTTP status is a statement about the transport, not about the answer. **This is the first
time the discipline paid forward rather than backward**, and it cost four lines.

We first recorded the consequence as a retention limit: the reports had existed and expired. That
explanation was wrong, and finding out how wrong is the fifth failure in this list. Asking the
sandbox how long each analysis had taken produced a split with nothing between the modes — the 43
tasks whose reports survived ran 186–366 s, and the other 57 ran **zero to one second**, 56 of them
still marked `reported`. A Windows PE does not detonate in one second. Nothing had expired; nothing
had happened, and the instrument said otherwise.

Re-submitting the same binaries from the same local files two days later produced full-length
analyses on the same instance, which recovers 54 of the 57 and puts the cohort at 97. Three failed
in processing or reporting and are gone for good.

The lesson generalises past this instrument. A completion status is a statement about a queue, not
about an analysis, and it is exactly as trustworthy as an HTTP 200. The retrieval path now reads
each task's wall-clock duration and refuses anything under 60 s — an order of magnitude below the
shortest real analysis on this instance — before it will accept a report. We would rather report a
smaller honest n than a full one built on error bodies, and we would rather state the reason we
verified than the one that first sounded plausible.

### M5 — An ablation that measured a code path and reported a language model

The four above are failures of other people's servers. This one is ours, it is the most recent
(2026-08-14), and it is the only one that reached a results table.

We ablated the corroboration cascade by removing one evidence source at a time and comparing the
STIX bundle the analyst receives. Under the condition where a removed source's techniques survive
under a partner — so that only their *corroboration* changes — the bundle was identical in **32 of
32** arms, at Jaccard 1.000. Under the condition where the removed source solely owned its
techniques, **32 of 32** changed. We wrote this up as a finding about the judge model: that it
attends to the list of claimed techniques and ignores the evidence-quality apparatus above it.

The judge was not involved. A post-processing step reconciles the bundle against the cascade before
it is returned: unresolvable attack-patterns are dropped, and **every cascade technique missing
from the bundle is appended to it**. The cascade's technique set is therefore a guaranteed subset
of every bundle the pipeline emits, whatever the model produced. Recomputing each arm's cascade set
from the same seeded fixtures shows the bundle is *exactly* that set in **80 of 80** arms, with the
model contributing **zero** techniques to any of them.

Both results then follow from set arithmetic. Removing a source with a duplicate partner does not
change the cascade's set, so the bundle cannot change; removing a sole owner does, so it must. The
two numbers we reported are necessities of an `if` statement, and the experiment could not have
returned anything else.

**The architectural conclusion survives the correction — corroboration does not reach the analyst's
artefact — but the mechanism is not the one we described.** The model cannot subtract from the
bundle's technique set and, across 80 arms, added nothing to it. Whether its output was unusable
and wholly replaced, or happened to reproduce the cascade's set, this evidence cannot say; both
leave the same trace, and separating them needs the pre-reconciliation output measured directly.
What is certain is narrower and sufficient: the model has no influence over which techniques reach
the analyst. And a second study, already written and about to run,
was designed to compare a weighted cascade against a flat union of the same claims. Both of its
arms would have shared one reconciliation set, so it would have reported "no difference" after an
hour of computation, correctly and vacuously. It was stopped four minutes in, by the same log line
that exposed M5.

**What made this one hard to see.** The tell was in the results the whole time: a Jaccard of 1.000
with a zero-width bootstrap interval, from a language model asked the same question 32 times at
temperature 0. Models do not agree with themselves that well. We read a constant as an unusually
clean null, because a clean null was the result we were prepared to find.

### M6 — A configuration difference wearing a parameter count

The most recent (2026-08-14), and the only one whose wrong answer **agreed with the literature**.

We assembled a parameter-size series to test a published finding that parameter count is the only
significant predictor of ATT&CK-classification F1 (ρ=0.85). The harness read every completed arm
file, ranked mean F1 against total parameters, and reported **ρ={{superseded_rho}}** — reproducing the prior
almost exactly, across a 3× span, with the confounds it could not remove printed honestly beneath.

The five rows were three models. One model appeared twice because it had been run in two
configurations, and another twice because it had been run twice. The duplicate configurations were
not a labelling detail: the same weights score **{{arm_qwen35ba3b_nothink_f1}}** with the reasoning stream disabled and
**{{arm_qwen35ba3b_f1}}** with it enabled, because 24 of 25 calls then spend their entire output budget reasoning
and never answer. The {{arm_qwen35ba3b_f1}} row sat at the small end of the parameter axis, where it set the sign
of the correlation. What the series measured was a flag, ordered by coincidence against size.

**The failure is not the duplicate rows; it is that the arm-selection rule did not exist.** The
harness had careful arithmetic — averaged ranks so file order cannot break ties, an exact
permutation p because four points cannot reach significance, a common-cell restriction so endpoint
availability cannot masquerade as model size — and every one of those guards was about a way the
*numbers* could mislead. None was about whether the rows were comparable in the first place.

The rule now keys on the **measured** reasoning share of each arm rather than the flag the harness
requested, because those two disagree: one provider accepts the parameter and ignores it, so an arm
selected on intent would enter the series labelled matched while running the opposite
configuration. With the rule applied, two arms qualify and both are 35B, so the series refuses and
says which arm was excluded and at what measured reasoning share. Nine unit tests pin the rule.

**What made this one hard to see.** It agreed with the published result. M5 was caught by a number
too clean to believe; this one produced a number in exactly the range a reader would expect, in the
direction the literature predicts, with its limitations already stated. There was nothing anomalous
to notice. It was caught by reading the arms table under the correlation and asking why one model
was on it twice — which is a question no result, however wrong, would have prompted.

**And the phenomenon is not ours.** `arXiv:2604.00025` shows that an inference-time output-length
constraint *reverses* performance hierarchies between large and small models — a 28.4-point gap
inverted — and frames it as a methodological confound requiring evaluation protocols that adapt to
the model rather than a universal one. Our reasoning flag consumes the answer budget, which makes
the disabled arm a brevity-constrained arm under a different name, and a reversal is a stronger
result than a spurious correlation. We report M6 as a domain instance of that finding.

What we would add is narrower and sits in the remedy rather than the phenomenon: their protocol is
adapted per model, ours has to be **verified per arm**, because matching on the requested
configuration is not sufficient when a provider accepts the parameter and does not act on it
(§3.32). An arm can be labelled matched and be running the opposite setting. The rule that follows —
select on the *measured* reasoning share, never on the flag — is what the gate implements.

### M7 — A safety property that was configured, documented, and never sent

The last one is in the production pipeline rather than in an evaluation harness, and it removed a
guarantee the code states in its own comment.

The verdict model is built with an {{judge_output_cap}}-token output ceiling, and the line that builds it says
why: *"Bound the verdict generation so a degenerate decode can't consume the full wall-clock
timeout."* The client library renames that parameter to the API vendor's newer spelling when it
serialises the request, and our local inference server does not read the newer spelling. It
accepted the field, ignored it, and decoded without a ceiling.

Measured on one call: a {{unbounded_decode_prompt_tokens}}-token prompt, **{{unbounded_decode_tokens}} tokens generated**, still generating at 46
tokens per second when the caller's ten-minute wrapper gave up. The only thing that ever stopped a
verdict was wall-clock.

The consequence is not a slow call. Four of eight fixtures in a separate study never returned a
verdict at all, and for each of them the pipeline emitted a bundle through its text-fallback path —
which does not run the reconciliation step, so the corroboration cascade contributed nothing and
the analyst received techniques copied straight from the raw evidence claims. A component we
describe as bounded was unbounded, and its failure mode was to hand the analyst a differently-built
artefact without saying so.

**Where it was invisible.** The configured value was correct. The container passed it. The model
object held it. It survived every later rebinding intact. Only the serialised request was wrong,
and nothing in the system reads the serialised request. Every check anyone would think to perform
would have confirmed the property that did not hold.

**What found it.** Not a test and not a review. A study measuring something else — what the verdict
model contributes to the bundle — recorded *which branch* each failed call took rather than only
that it failed. Four calls named the timeout branch, which prompted the question of why a
temperature-zero model would need ten minutes, which led to the server's own log and a token
counter that had passed thirty thousand. The instrumentation that caught it was written for a
different question three hours earlier.

**The incompatibility itself is known; the consequence is what we contribute.** That
OpenAI-compatible servers disagree about token-limit parameters is documented in their own issue
trackers — `llama.cpp` #8634 reports generation continuing to the context limit when the cap is not
honoured on one of its endpoints. We are not reporting a new integration wart. We are reporting
what one costs inside a measurement: a documented safety property silently absent for as long as it
has existed, and half of a study's calls diverted onto a bundle-construction path that skips the
corroboration cascade entirely.

## 6.2 Why the test suite did not help

**{{test_count}} tests passed throughout.** This is not a gap in test quality but in test *shape*:

* M2 and M3 require a **second** case within one server lifetime. A unit test loads one program,
  asserts, and tears down. The state that goes wrong is created by the second call and cannot exist
  in a single-call test.
* M1 required a second *server*. The behaviour was correct against the only server exercised.
* M4 required a rich enough **input** — the composition only appears when the step budget is
  actually exhausted, which small fixtures never do.
* M5 was **tested and passing**. `_reconcile_with_cascade` has unit tests, and they assert exactly
  what it does: unresolvable patterns are dropped, missing cascade techniques are added. The
  function was never wrong. What was wrong was an experiment that varied the cascade's input and
  attributed the output to a model downstream of it — and no test of a component can catch a
  misattribution made three modules away.
* M6 was **tested more carefully than anything else in the harness, and the tests were about the
  wrong question.** The series arithmetic had a test file of its own: averaged ranks so file order
  cannot break ties, an exact permutation p because four points cannot reach significance, a
  common-cell restriction so endpoint availability cannot pass for model size. Every test asserted
  something true. None asked whether the rows entering the correlation were comparable, because the
  answer had been assumed at the point where the arms were assembled rather than decided anywhere a
  test could see it.

* M7 had **nothing left to assert on**. A unit test would build the model and check that its output
  ceiling is {{judge_output_cap}} — and it is, at every level the object model exposes. The defect existed only in
  the serialised request, which no test in this suite inspects and which no application code reads.
  Testing the property as the system represents it confirms exactly the thing that is not true.

Four preconditions — a second call, a second server, a large input — are exactly what a fast unit
suite is designed to avoid. The last three are worse: **M5, M6 and M7 are invisible to unit testing
in principle**, because every unit involved behaved as specified. Their common shape is that the
defect lived in the *composition* — which measurement was attributed to which cause, or which
representation of a value actually crosses the boundary — and a test that pins a function's
behaviour cannot reach an assumption made when its inputs were chosen or when its output was
serialised.

## 6.3 What did find them: output cardinality

Five of the seven were found by the same observation: **a number that repeated where variation was
expected.** M6 and M7 were not, and §6.2 says what did find them — their outputs vary, so there is
no repetition to notice.

| observation | defect |
|---|---|
| a priority hint of exactly {{hint_chars_repeated}} characters for two unrelated binaries, and a third in an earlier session | M2 |
| call graphs identical to the character ({{call_graph_chars}} chars, {{call_graph_lines}} lines) for samples of 241 KB and 139 KB | M2 |
| 66 consecutive samples at exactly {{stuck_graph_chars}} characters | M3 |
| every tool call returning the same validation error | M1 |
| a 25-minute call that always produced one claim and zero techniques | M4 |
| a Jaccard of **1.000 with a zero-width interval**, from a model asked the same question 32 times at temperature 0 | M5 |

M5 extends the detector in a direction worth stating, because it is where the idea is least
comfortable: the repeated number was **our own result**, not a server's response, and the variation
that failed to appear was the model's. A perfect agreement is the same signal as an identical
digest, and it deserves the same suspicion.

The generalisation is one line of arithmetic: **before trusting a batch measurement, ask how many
distinct outputs the N inputs produced.** If far fewer than N differ on a dimension that should
vary — output length, digest, element count — the instrument is repeating itself, and repetition is
what stale state looks like from outside. It needs no ground truth and no oracle, which is what
makes it usable exactly where correctness is hard to check.

![Distinct outputs against inputs processed, measured and schematic.](figures/fig1-output-cardinality.pdf)

**Figure 4: The whole detector, drawn.** Plot distinct outputs against inputs processed and a healthy
instrument tracks the diagonal, while a stuck one goes flat — no ground truth required, because the
diagnosis is in the shape. Left is measured: 63 distinct call-graph sizes across 97 samples, the
staircase's flat treads being genuinely identical binaries rather than a fault.

**The right panel is a schematic, and the reason is the argument of §6.4.** It depicts M3 — the run
in which 66 consecutive samples returned a byte-identical {{stuck_graph_chars}}-character call graph — and we cannot
plot it, because that run predates the per-sample retention policy those very failures caused us to
adopt. The most important curve in this paper is the one we are unable to draw.

We now report it beside every batch result: 50 distinct call-graph sizes across 79 samples, then 63
across 97.

**This is a refinement, not a discovery, and we checked before saying otherwise.** "Distinct inputs
should produce distinct outputs" is an ordinary metamorphic relation [22]; metamorphic testing
exists precisely for programs whose correct output is unknown — the *"notorious oracle problem"*
its own survey names. Stress-testing an LLM judge's consistency under input variation is likewise
established practice [23]. And
the genus is described: a longitudinal study of a production LLM agent runtime defines the
meta-pattern as *"a failure whose error signal never reaches a human in actionable form"* and gives
a five-class taxonomy [20] into which all four of our **boundary** mechanisms fall. M5, M6 and M7 share
the meta-pattern but not the setting: no server misled us, and no protocol was involved. Two arose
inside our own analysis code and one inside the production pipeline, and in all three the
taxonomy's classes — every one of which describes a call to something else — do not reach.

## 6.4 What it cost

A completed study is withdrawn from this paper.

A seven-year, 210-sample temporal-drift analysis ran the full pipeline per sample against a
long-lived server that was never restarted between samples — M2's precondition exactly. Whether it
was affected **cannot be determined**, because its per-sample outputs were not retained. The result
had passed review, entered the claim ledger as novel, and was cited internally for weeks.

Two policies follow, and both are cheap:

1. **Retain per-sample outputs for every study.** The withdrawal is not caused by the defect; it is
   caused by the defect *plus* the inability to re-ask the question afterwards. Aggregates cannot be
   re-interrogated.
2. **Restart the shared server between samples.** In our sweeps this recovered 12 of 14 samples
   previously recorded as unmeasurable — the failures belonged to the *state they inherited*, not to
   the samples. Fresh state per sample removes a whole class of the failures above.

## 6.5 The claim we are making

Not that silent failures exist at tool boundaries — that is documented. Ours is narrower:

* three mechanisms at three **distinct** integration boundaries (argument encoding, server-side
  session state, HTTP status versus body), plus one from **composing** two local safety bounds;
* the setting — an **evaluation pipeline for security research**, where the artefact is not a
  degraded user session but a **measurement that is wrong and looks right**, and where the failure
  therefore propagates into a published claim rather than into a support ticket;
* a detector reported **alongside results** rather than run as a test, because the failure appears in
  the batch and not in any single call;
* two further failures (M5, M6) with **no server involved at all** — an ablation that varied a
  deterministic code path and reported a language model, and a correlation that ranked a
  configuration flag and reported a parameter count. Both had passing unit tests over the exact
  functions concerned. They extend the claim from "other people's servers can mislead you" to *the
  same shape occurs wherever a measurement's cause is assigned rather than measured*;
* and one (M7) in the **production pipeline**, where a documented safety property — a bounded
  verdict generation — was configured correctly at every level the code can inspect and removed
  entirely by a parameter rename during serialisation. It is the case that shows the shape is not
  peculiar to evaluation: the artefact the analyst receives was affected, not a number in a table;
* and a demonstrated price rather than a hypothesised one.

In a pipeline assembled from other people's servers, the correctness of the model is not the binding
constraint on the correctness of the result. **A server that answers is not the same as a server
that answered your question.**
