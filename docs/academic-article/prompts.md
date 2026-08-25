# The prompts and the output contract

Supplement to *What a language model adds to deterministic malware analysis, and what it takes to measure it*.
This was Appendix A of the manuscript and was moved here so the paper carries only
what its claims rest on. Nothing was cut in the move.

The paper measures what a model adds to a pipeline, and that measurement cannot be
read without knowing what the model was asked. The full text of the four prompts is
in this repository under `src/maljan/agents/`; what is reproduced below is the part
the paper's claims rest on, because a claim about falsification before confidence is
a claim about specific sentences in a specific prompt.

## What the three analyst prompts share

Each analyst receives one system prompt with the same five parts, and the parts are
the same length in each: a role and an evidence rule, a tool workflow, a set of
conditional tools, a verification discipline, and a set of standing cautions.

The evidence rule is identical across the three, and it is the pipeline's grounding
constraint: for every claim it makes, the model must cite a concrete artefact. For
the static analyst that is a function name, a string offset, an import or a hex
pattern. For the dynamic analyst it is an API call or a registry write from the
sandbox report. For the network analyst it is a flow or a resolved domain.

What differs between the three is the tool server each is bound to, the evidence type
it reads, and the technique families its role paragraph names.

## The confidence rules, as shipped

Two clauses of the verification discipline carry the fourth architectural claim and
set the cap whose firing rate the paper measures (0.82% of techniques, derived as
`cap-rate` in `tests/evaluation/paper_facts.py`). They are quoted from the static
analyst's prompt without alteration:

```
- A SPECIFIC claim (a named algorithm like RC4/djb2/ROR13, a constant
  or XOR key, or a hash-resolved API) may reach CONFIDENCE >= 0.8 only
  if you FALSIFY it first: `emulate_function` with a known input vs the
  expected output, OR `analyze_dataflow(direction=backward)` to confirm
  its origin. If you cannot run the check (non-leaf, syscall/heap side
  effects), cap CONFIDENCE at 0.7.

- A claim is High (>= 0.8) only with >= 2 independent evidence loci
  (e.g. an import AND its call-site). A single locus caps at 0.7.
  Reconcile any contradictory signals before emitting.
```

Two further clauses of the same block are elided rather than silently dropped: one
governs disambiguation when a hash-resolution tool returns colliding candidates, and
one refuses a particular obfuscation technique on the evidence of dynamic import
resolution alone. Neither bears on a measurement the paper reports.

The rules ask the model to earn a number above 0.8 by running a check, and to cap
itself at 0.7 when it cannot. That number is what every deterministic gate downstream
consumes, and the paper finds it near chance. Whether the discipline is not followed,
or is followed and does not separate correct claims from wrong ones, that design
cannot distinguish.

## The output contract

An analyst answers in blocks, and a block is the unit everything downstream counts.
The parser requires the first field and defaults the rest, because a block that names
a finding and omits its confidence is still a finding:

```
CLAIM: <the finding>
EVIDENCE: <a concrete artefact reference>
CONFIDENCE: <0.0 to 1.0>
TECHNIQUE: <T1055.001 | NONE>
---
```

Each parsed block becomes one record, and its four fields are what the rest of the
system sees. The claim and the evidence reference are free text. The confidence is
bounded to the unit interval by the schema rather than by the prompt, which is why a
model that ignores the verification discipline still produces a well-formed number.
The technique identifier is optional and is pattern-checked where it is declared:

```python
technique_id: str | None = Field(None, pattern=r"^T\d{4}(\.\d{3})?$")
```

A malformed identifier is therefore refused at the schema and never reaches the
cascade. This is the filter the paper finds the text-fallback path bypassing, which
is why the identifiers admitted there are real ones no evidence source claimed rather
than invented strings.

## What varies per sample

The system prompts are fixed strings and are not templated per sample, which is the
reason the paper records prompt sensitivity as `PARTIAL`: production prompts were
held constant and were not varied per model. What varies is the human turn, which
carries the sample's path for the static analyst, the sandbox report for the dynamic
analyst and the network observations for the network analyst, each wrapped in
delimiters that mark it as untrusted input. Evidence is truncated to a per-call
character cap before it is interpolated, and that cap is one of the truncation points
the paper enumerates under P6.
