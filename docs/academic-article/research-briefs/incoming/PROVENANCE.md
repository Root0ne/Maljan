# Provenance of the incoming reports

What each file is, what it was asked, and how much weight it should carry in the merge.
Nothing here edits the reports themselves — they stay verbatim.

| file | brief given | scope | quality |
|---|---|---|---|
| `ALL8.model-a.md` | **truncated Part C, all 8 briefs in one conversation** | all 8 themes | see below — treat with caution |
| `R1.model-b.md` | truncated brief, R1 only | R1 only | strong; the best arm so far |
| `R2.claude-web.md` | current R2 brief, all three standing instructions | R2 only | citations individually verified |

## What the first two models were actually asked

Both received the **old, truncated** brief. Missing from it:

1. The standing instruction to treat *"Our position"* as a **claim under test**. Without it a
   model has every incentive to confirm.
2. The entire **Part D output format** — so no per-paper rigor flags, no model-tier tags, no
   per-citation confidence, no "prior work claiming a similar solution" step.
3. Theme isolation — `ALL8.model-a.md` answered all eight in one conversation.

Part A/B/E/F were **not** sent, so our own gap list (Part E) did not leak into either. Where a
report independently reaches a Part E conclusion, that convergence is real evidence.

## `ALL8.model-a.md` — useful as a lead generator, unreliable as a verdict

**Do not take its novelty judgements.** The predicted bias is plainly present: *"directly
confronts and fills these identified gaps"*, *"directly and demonstrably fills these gaps"*,
*"a genuinely novel and powerful technique"*. It concludes that separating description from
taxonomy assignment is a gap our approach fills — while `arXiv:2401.12178` published the
general method in January 2024. It never surfaced that paper.

**Citation hygiene is poor.** The preamble asked for peer-reviewed venues; the report cites
Reddit threads, LinkedIn posts, a Facebook post, Medium articles and vendor blogs as evidence.
Every identifier in it needs resolving before use.

**But it surfaced genuinely valuable leads**, several of which nothing else did:
`"Chasing Shadows: Pitfalls in LLM Security Research"` (NDSS 2026) for R6; SEC-bench, CVE-Bench,
CTIBench, NYU CTF Bench; REx86 (`arXiv:2510.20975`); PhishDebate (`arXiv:2506.15656`); *Voting
or Consensus? Decision-Making in Multi-Agent Debate*; the AISI open-weight-vs-frontier cyber
assessment; Code World Model 32B. It also independently found the Büchel SoK.

## `R1.model-b.md` — the strongest arm, and it corrected me

Despite the truncated brief, this report did on its own most of what the standing instructions
ask for: it separates *"no work found in my search"* from *"no work exists"*, flags every 2026
preprint as not-yet-peer-reviewed, marks uncertain figures `UNCERTAIN`, has a Caveats section,
gives DOIs, states where our position *falls short*, and even corrects a citation error common
in the field (the "43%→2%, 4→51 tools" figure is a LangChain blog, not the Berkeley Function
Calling Leaderboard).

**It found what I missed.** `arXiv:2602.06325` (TTPDetect) — an LLM agent mapping *stripped
malware binaries* to ATT&CK — refutes the "nobody maps binary evidence" gap I had asserted in
`R2.claude-web.md`. I verified it and corrected that report in place. Its leads on ABLE
(`arXiv:2605.21821`) and the Springer static+dynamic→ATT&CK RAG paper point the same way and
are still unverified.

**Method lesson, now applied to every remaining theme:** searching a claim only in the
vocabulary of the subfield it *sounds* like will miss the paper that owns it. TTPDetect indexes
as binary analysis, not as ATT&CK mapping. Infer-Retrieve-Rank indexes as general ML, not as
security. Each remaining theme gets at least one query phrased from the adjacent field.

## Weighting for the merge

- A gap claimed by `ALL8.model-a.md` alone: **hypothesis only**, and one produced under a
  confirmatory prompt. Do not carry into the paper without independent support.
- A gap claimed by `R1.model-b.md` or `R2.claude-web.md`: treat as a searched negative with the
  stated confidence, still to be confirmed by targeted manual search before any absolute claim.
- Any citation used in the paper must be resolved to a real DOI/arXiv record first, regardless
  of which report supplied it. Fabrications found during the merge get recorded, not deleted —
  the per-model fabrication rate on this material is worth knowing.
