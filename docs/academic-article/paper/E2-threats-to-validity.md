# Threats to Validity

*Draft for the paper. Source of record: [`self-audit-pitfalls.md`](../self-audit-pitfalls.md) and
[`findings-log.md`](../findings-log.md). Every number here is traceable to a section there.*

We organise this section around the nine pitfalls of *Chasing Shadows* [9], which surveyed all 72
peer-reviewed LLM-security papers of 2023–2024 and found every one exposed to at least one, with
only 15.7% discussing any. We add two checks the survey does not have, both of which caught errors
in this work. Where a pitfall is genuinely closed we say so; where it is not, we say what remains
rather than what we intend.

## The threat that actually materialised

Most threats sections describe hazards. This one begins with damage, because reporting it is the
paper's main methodological point.

**One study is withdrawn.** A seven-year, 210-sample temporal-drift analysis was completed, entered
our claim ledger as a novel result, and is now retracted. It drove the full pipeline per sample
against a long-lived Ghidra server that was never restarted between samples — which is precisely the
precondition for a defect we later found, in which a loaded program never becomes the server's
*current* program, so every sample after the first is described using the **first sample's binary**
(§3.14). Whether that run was affected cannot be determined: its per-sample outputs were not
retained. The result is therefore not restated anywhere in this paper, and the axis it measured —
input-era drift, as distinct from train/test temporal misalignment — is presented as an open
question with a corrected instrument required before any bound is claimed.

Three defects of this kind were found in a single day, all sharing one shape: **a plausible wrong
answer with no error anywhere.**

| | mechanism | what it silently produced |
|---|---|---|
| **M1** | unset optional MCP arguments were sent as `null` | all 36 sandbox tools refused; the pipeline saw only empty results |
| **M2** | `load_program` reported success *with the right program name* but did not change the server's current program | every sample after the first analysed the first binary |
| **M3** | a refused load answers **HTTP 200** with an error body | hints and function hashes built from a different binary |

None was caught by a test suite of **1,995 passing tests** — not by accident: M2 and M3 require a
*second* case within one server lifetime, and a unit test writes one. A fourth defect, found later
in the same week, made the analyst return **zero techniques on any binary rich enough to exhaust its
step budget**, because two protective bounds composed: exceeding the step cap triggers a synthesis
call that received a *fresh* copy of the full time budget, so loop-plus-synthesis overran the hard
cap by construction (§3.15).

We report these because we believe the interesting threat to an LLM-plus-tooling pipeline is not
that the model is wrong. It is that **the instrument answers a different question than the one asked,
convincingly.**

## The nine pitfalls

**P1 Data poisoning — `CLEAR`.** Nothing is trained. Retrieval corpora are curated and their
provenance is documented.

**P2 Label inaccuracy — `CLEAR`.** Ground truth is MITRE-curated, and **no LLM scored any result in
this work.** This was a standing constraint, not an outcome: an internal readability assessment was
performed with an LLM as a development aid and is deliberately excluded from this paper, so that the
absence of LLM-as-a-judge scoring remains unqualified. A consequence is stated under E.7: no human
analyst rated any report either.

**P3 Data leakage — `PARTIAL`.** One instance was found by us, disclosed and mitigated. It was never
systematically audited, and the pitfall's own recommendation applies: **the model's training data is
unknown to us and memorisation was not probed.** We acknowledge this rather than argue around it.

**P4 Model collapse — `CLEAR`.** Augmenting the long-term memory corpus with LLM-generated cases was
considered and refused, with a cited rationale.

**P5 Spurious correlations — `PARTIAL`.** Two were found and are reported. No systematic perturbation
testing was performed.

**P6 Context truncation — `EXPOSED`.** Truncation is designed-in throughout — chunking at function
boundaries, a per-call evidence cap, a 40-step ReAct budget, an 8,192-token verdict cap, a 400-char
hint cap — and the counters now exist to report frequency, with pass-throughs counted so the rate has
a correct denominator. What we cannot yet report is the distribution over a full cohort. Two specific
findings belong here:

* The enumeration of truncation sites was **itself incomplete**. A 20,000-edge cap on the call-graph
  fetch was discovered only while instrumenting a different measurement, and it silently truncates
  1 of 97 samples (§3.15). We therefore describe how our list was built rather than presenting it as
  exhaustive.
* Bounds **compose**. Exceeding the step cap guarantees an attempt at the time cap, and on rich
  binaries that attempt could not finish — two limits producing an empty result between them. This
  is §1.7.1's shape in a new place: there, removing a hint made the judge overrun a 600 s ceiling and
  return an empty bundle 6/17 times.

**P7 Prompt sensitivity — `PARTIAL`.** A structured prompt-variation study exists. Production prompts
are fixed and were not varied per model. Related: our own instrument-validity failure, in which a
single-run parsed-claim count ranked the same arms differently at different decoding budgets, is
prompt sensitivity surfacing as measurement error.

**P8 Surrogate fallacy — `PARTIAL`, on evidence.** Every local result comes from **one model on one
machine**: Qwen3.6-35B-A3B at IQ3_K_R4, ik_llama.cpp, single host. Four claims were rescoped to that
exact identifier. A second endpoint has now run to completion — a 120B reasoning model on the same
fixtures, repeats, prompt and token budget — and **did not separate from the local model**: paired
**ΔF1 +0.003, 95% CI [−0.077, +0.081]**, n=25, better on 12 and worse on 13 (§3.16). A 3.4× parameter
advantage produces no measurable difference here, which is evidence *against* the pitfall's usual
worry rather than merely an absence of evidence for it.

An interim version of this arm reported 0.5025 at n=9 and read as a lead; completing the sample moved
the estimate through the local mean and out the other side. We record that because the arm had been
truncated by a daily request quota, not by anything about the samples — the failure mode is reading a
difference off an underpowered arm, and this audit carried the wrong number for a day.

What remains is **coverage, not power**: the second model has been measured on five synthetic
fixtures, not on the malware cohort, where evidence bundles are longer and messier. That is the arm
the free tier's 50 requests/day makes a two-day run or a paid one.

**P9 Model ambiguity — `PARTIAL`.** Model and engine are both pinned: GGUF digest, HuggingFace
revision, retrieval date, quantiser, **and the imatrix calibration dataset** — which most papers
reporting a quantisation level cannot name. The engine commit was recovered and *proved* to describe
the build (identical 837-file source list; exactly one generated file differs). It is `PARTIAL`
rather than `CLEAR` for a reason worth stating: **the running binary reports its version as
`unknown`**, and the commit was recovered from a vendored copy of the sources rather than from the
artifact. Build provenance must be captured at build time; ours was reconstructed, and we say so.

## Two checks the survey does not include

Both were added after they caught errors here.

**The tenth check — diff the claim register against the evidence log.** All nine pitfalls concern the
relationship between claims and experiments. Two failures sat one level below that. A claim was
recorded as novel one hour after our own findings log had described it as a replication; and this
audit mis-stated one of its own rows, attaching a model caveat to a result produced by a server-free
harness. Neither needed a literature search — only reading two of our own documents against each
other. Applied again later, it found **three ledger rows that had drifted from the evidence log**,
including one still carrying an interim figure after the final measurement had landed. A project
disciplined enough to keep both a findings log and a claim ledger has, by that fact, created the
conditions for the two to diverge.

**The eleventh check — count the distinct outputs.** Before trusting a batch measurement, ask how
many distinct outputs the N inputs produced. If far fewer than N differ on a dimension that should
vary — length, digest, element count — the instrument is repeating itself, and repetition is what a
stale-state bug looks like from outside. All three defects above were caught this way: a 2,575-char
hint repeated across unrelated samples; call graphs identical to the character for binaries of
241 KB and 139 KB; 66 consecutive samples at exactly 75,426 characters. It costs one line of code and
needs no ground truth. We now report it alongside results (50 distinct call-graph sizes across 79
samples; 63 across 97).

This check is a **refinement, not a discovery**, and we counter-searched it before claiming
otherwise: "distinct inputs should produce distinct outputs" is an ordinary metamorphic relation
[22], the inverse is already an eval-harness practice [23], and the genus — silent failures in
production LLM agent runtimes, defined as *"a failure whose error signal never reaches a human in
actionable form"* — is described with a five-class taxonomy our defects fall into [20]. What we add
is the setting: an evaluation pipeline for security research, where the output is not a degraded
user session but **a measurement that is wrong and looks right**, together with three mechanisms at
three integration boundaries and one withdrawn study as the demonstrated cost.

## Construct validity: what the ground truth can and cannot support

Per-sample ground truth is **family-level MITRE `uses`**, which is coarse: a single Emotet binary
need not exhibit all ~47 techniques catalogued for Emotet, and a packed sample exhibits fewer still.
Absolute recall therefore carries a structural ceiling and precision carries noise. Two consequences
we accept rather than argue with:

1. Absolute F1 values in this paper are **not comparable to work using per-sample expert labels**.
2. The bias is approximately constant across arms, so within-study contrasts are the defensible
   reading — which is exactly why a baseline matters. **the sandbox alone, with no LLM anywhere, scores
   F1 0.167 [0.141, 0.194]** on our cohort (§C5). Every pipeline figure is read against that rather
   than against zero.

## The host as an uncontrolled variable

A threat we did not anticipate and met late: **the machine a measurement runs on is part of the
instrument.** Our working set — model server ~16 GB, analysis worker ~8 GB, disassembly container up
to 6 GB — does not fit a 31 GiB host alongside an interactive session. During a paired ablation the
swap file was exhausted and the model server had 2.3 GB of its own address space paged out; an arm
then exceeded a 594-second budget on a prompt trimmed to 16,000 characters. Whether that arm failed
because of the pipeline or because of the host **cannot be determined**, because we recorded the
pipeline's outputs and not the host's state.

The affected arms are reported as `unattributable` rather than as failures, and the ablation is
reported as incomplete rather than as a null. We flag three things a reader should take from this
rather than from our fix:

1. **Wall-clock bounds are host-dependent measurements wearing the costume of a system property.**
   Any result in this paper that turns on a timeout — the salvage-path failure of §6, the timing
   column of §7 — is a statement about this pipeline *on this machine under whatever load it had*.
2. **The retention rule we adopted after the first failure did not cover this one.** §4.5 says to
   retain per-sample outputs, and we did. The rule was written about the object under study, and what
   went unrecorded was the environment the study ran in.
3. **A screen for this can only be applied forward.** Arms already collected without host state
   cannot be re-screened, which is the same structural problem that withdrew our drift study, in a
   new variable.

**A postscript, because it took three attempts to see.** Two of the interruptions above we
attributed to memory pressure and treated with progressively better limits: a floor, then a strike
counter, then an allowance for declared allocations, then marking the model server as the kernel's
preferred OOM victim. All four were correct and none was the cause. The harness had started the
server as a **child process**, so it ran inside the cgroup of the terminal that launched it and its
memory was accounted to that scope; the kernel's log named the scope plainly and we did not read it
until the third failure. Every fix we made chose *which process* the kernel would kill, and the
defect was *whose accounting it was killed inside*.

We report this because it is the same error as M1–M4 in a different register: a mechanism that looked
like it was working, an intervention that addressed a real thing at the wrong layer, and a log line
that had contained the answer for two days. A measurement environment is not a backdrop to the
measurement, and the discipline that catches this is not cleverness — it is reading the error
message that was already there.

## Scope

Unless a statement says otherwise it was produced on one model, one machine, one quantisation and
one engine build, with the identifiers in the reproducibility appendix. Where a result concerns
retrieval or the deterministic cascade rather than generation, no model was involved and the binding
limits are the index and the corpus instead; those are marked at the point of claim.
