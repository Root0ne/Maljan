# Instrument Failures

*Draft for the paper, §6 — the central chapter. Every mechanism here was observed in this project's
own pipeline; the dates are the days they were found.*

An LLM analysis pipeline is mostly other people's servers. Ours calls a reverse-engineering server
for disassembly, a sandbox for detonation, a vector store for retrieval, and a model server for
inference, over three protocols. Each boundary is a place where a request can succeed and still not
mean what the caller assumed.

This section reports four such failures. We report them together because they share a shape that a
test suite is poorly positioned to catch and a results table cannot show: **the instrument answered
successfully, and answered about something else.**

## 6.1 Four mechanisms

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
lifetime, **66 consecutive samples produced a call graph of exactly 75,426 characters** before
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

The consequence is still a real one: the baseline study is n=43 rather than n=100, and that is a
limit of the sandbox's retention window rather than a sampling decision. We would rather report a
smaller honest n than a full one built on error bodies.

## 6.2 Why the test suite did not help

**1,995 tests passed throughout.** This is not a gap in test quality but in test *shape*:

* M2 and M3 require a **second** case within one server lifetime. A unit test loads one program,
  asserts, and tears down. The state that goes wrong is created by the second call and cannot exist
  in a single-call test.
* M1 required a second *server*. The behaviour was correct against the only server exercised.
* M4 required a rich enough **input** — the composition only appears when the step budget is
  actually exhausted, which small fixtures never do.

All three preconditions — a second call, a second server, a large input — are exactly what a fast
unit suite is designed to avoid.

## 6.3 What did find them: output cardinality

Each was found by the same observation: **a number that repeated where variation was expected.**

| observation | defect |
|---|---|
| a priority hint of exactly 2,575 characters for two unrelated binaries, and a third in an earlier session | M2 |
| call graphs identical to the character (404,337 chars, 11,798 lines) for samples of 241 KB and 139 KB | M2 |
| 66 consecutive samples at exactly 75,426 characters | M3 |
| every tool call returning the same validation error | M1 |
| a 25-minute call that always produced one claim and zero techniques | M4 |

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
in which 66 consecutive samples returned a byte-identical 75,426-character call graph — and we cannot
plot it, because that run predates the per-sample retention policy those very failures caused us to
adopt. The most important curve in this paper is the one we are unable to draw.

We now report it beside every batch result: 50 distinct call-graph sizes across 79 samples, then 63
across 97.

**This is a refinement, not a discovery, and we checked before saying otherwise.** "Distinct inputs
should produce distinct outputs" is an ordinary metamorphic relation [22]; metamorphic testing
exists precisely for programs whose correct output is unknown. The inverse — duplicating dataset
items to verify identical inputs score consistently — is already an eval-harness practice [23]. And
the genus is described: a longitudinal study of a production LLM agent runtime defines the
meta-pattern as *"a failure whose error signal never reaches a human in actionable form"* and gives
a five-class taxonomy [20] into which all four of our mechanisms fall.

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
* and a demonstrated price rather than a hypothesised one.

In a pipeline assembled from other people's servers, the correctness of the model is not the binding
constraint on the correctness of the result. **A server that answers is not the same as a server
that answered your question.**
