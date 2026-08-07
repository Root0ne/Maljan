# Research briefs — how to run the literature review

Eight paste-ready prompts, one per theme. Generated from
[../literature-review-brief.md](../literature-review-brief.md) by
`scripts/build_research_briefs.py` — **edit the source document, then regenerate**; do not edit
`R*.md` by hand or the next regeneration silently discards the change.

## Running one

Paste **the entire `R<n>.md` file** into a fresh conversation with a research-capable model.
Nothing needs to be added — the preamble, the brief, and the required output format are all in
the file.

Three rules that decide whether the results are usable:

1. **One brief per conversation.** Mixing themes blurs the gap analysis: the model starts
   answering R3's questions with R1's papers and the per-theme "nobody has done this" signal is
   lost.
2. **Do not paste Parts A / B / E / F of the source document.** Part E in particular is our own
   list of holes; showing it to the model turns an independent finding into an echo. Whether a
   model rediscovers those gaps on its own is itself evidence.
3. **Run the same brief on several different models.** The whole design assumes disagreement is
   informative — a gap claimed by one model is a hypothesis, a gap claimed by all of them is a
   finding.

## Bringing results back

Save each answer verbatim — no edits, no trimming — as:

```
docs/academic-article/research-briefs/incoming/<R-tag>.<model-slug>.md
```

for example `incoming/R2.gpt5.md`, `incoming/R2.gemini3.md`, `incoming/R5.grok4.md`.

Verbatim matters: the merge stage needs to attribute every claim and every suspect citation to
the model that produced it, and a cleaned-up copy destroys exactly the disagreement the design
depends on. If a model refuses part of a brief or runs out of context, keep the partial answer
and note where it stopped — a truncated report is data; a silently missing one is not.

Then say which files are new. The merge produces:

- a **related-work matrix** (paper × theme × what it does × where it disagrees with our framing),
- a **verified citation list** — every DOI/arXiv ID resolved against the real record, with the
  fabrications recorded rather than deleted, since a model's fabrication rate is worth knowing,
- a **gap ledger** — each candidate gap with how many independent models raised it, and our
  status against it (CLOSED / PARTIAL / NOT CLOSED),
- an updated Part B/E in the source brief, and a recommendation on the Part F framing.

## The eight briefs

| file | theme | our strongest material |
|---|---|---|
| `R1.md` | LLM agents for binary reverse engineering | curated tool allowlist; ~201-schema infeasibility (§2.2) |
| `R2.md` | ATT&CK technique mapping / TTP extraction | **describe-then-map**; rank-vs-gate axes (§1.5.1); autocorrect regression (§1.5.2) |
| `R3.md` | Multi-agent consensus for security | evidence-layer-weighted corroboration; the false-corroboration failure mode |
| `R4.md` | Grounding, hallucination, calibration | falsification-before-confidence; hallucination ≤0.011 at n=210 |
| `R5.md` | RAG for malware / CTI | the negative result: working retriever, unreachable query (§1.5.3) |
| `R6.md` | Evaluation methodology and ground truth | 7-year drift study n=210; claim-count as an invalid instrument (§3.4) |
| `R7.md` | Local small open-weight deployment | KV scaling on hybrid-offload MoE (§2.1); confidentiality as a hard constraint |
| `R8.md` | CTI report / STIX generation | deterministic template beats the LLM narrative on faithfulness (§3.5) |

R2, R5 and R6 carry the best-evidenced claims, so their gap answers weigh most on the framing
decision. R3 asks about a mechanism we have **not** yet evaluated — expect its answer to point
straight at our own Part E.2.
