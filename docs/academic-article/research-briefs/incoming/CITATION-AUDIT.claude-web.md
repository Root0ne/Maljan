# Citation audit — what the other arms cited, and whether it exists

> Claude (Opus 5), 2026-08-08. Every entry below was checked by fetching the source, not by
> recall. This audits `ALL8.model-a.md` and `R1.model-b.md`; it does not re-review their themes.
>
> **Headline:** no outright fabrication found in what I checked — but the two arms fail
> differently, and the difference matters for how much weight each gets in the merge.
> `R1.model-b.md` is accurate with minor overstatement. `ALL8.model-a.md` cites the right
> *papers* in some places and cites Reddit, LinkedIn and Facebook as evidence in others, under a
> preamble that asked for peer-reviewed venues.

---

## Verified — exists, and says what the citing report said

| identifier | what it is | checked |
|---|---|---|
| `arXiv:2505.10570` | **LongFuncEval** (IBM et al.) — measures tool-calling degradation as the catalogue grows: *"a performance drop of 7% to 85% as the number of tools increases"*, positioned as *"the first attempt to comprehensively study … tool calling"* | ✅ abstract |
| `arXiv:2411.15399` | **Less-is-More** — reducing available tools improves function-calling on edge devices; **execution time −70%, power −40%** | ✅ abstract |
| `arXiv:2604.14317` | Agentic reverse-engineering limitations — static / dynamic / hybrid agents; token constraints, obfuscation, missing program guardrails | ✅ abstract, **with a correction — see below** |
| `arXiv:2506.15656` | **PhishDebate** — four specialised agents (URL, HTML, semantic, brand) plus Moderator and Judge; **98.2% recall**; beats single-agent and CoT baselines. **IEEE BigData 2025** | ✅ abstract |
| `arXiv:2506.11791` | **SEC-bench** — Lee, Zhang, Lu, Zhang. Automated benchmark: PoC generation **max 18.0%**, vulnerability patching **max 34.0%**, ~**$0.87 per case** | ✅ abstract |
| `arXiv:2512.09549` | **Chasing Shadows** (NDSS'26) — 72 papers, every one contains ≥1 of nine pitfalls, 15.7% acknowledged | ✅ abstract (see `R6.claude-web.md`) |
| `arXiv:2510.20975` | **REx86** — ACSAC 2025, eight open-weight models fine-tuned, n=43 user study | ✅ abstract (see `R7.claude-web.md`) |

## Corrections to the citing reports

- **`arXiv:2604.14317` is not a survey.** `R1.model-b.md` calls it the *"survey anchor"* that
  *"taxonomizes static/dynamic/hybrid agents and catalogues six limitations"*. The abstract
  presents it as a research contribution identifying limitations and future directions, and
  names three limitation categories, not six. The agent taxonomy is real. **Minor overstatement,
  not fabrication** — but it is cited as the anchor for "no formal RE delegation-boundary study",
  so its status matters. The six-limitation list may well be in the full text; it is not in the
  abstract.

- **`R1.model-b.md`'s own citation correction checks out as *plausible and worth keeping*.** It
  flags that the widely repeated *"43%→2% as tools grow from 4 to 51"* figure comes from a
  LangChain engineering blog rather than the Berkeley Function Calling Leaderboard. I did not
  independently verify the misattribution, but the report volunteering a correction *against*
  the field's common usage is a strong signal of care, and it is the kind of thing the merge
  should preserve rather than smooth over.

- **An AISI claim that does not exist.** A search summary attributed to the AISI cyber report a
  statement that *"range performance scales log-linearly with token spend up to at least 100
  million tokens per run."* The fetched report contains **no inference-time scaling discussion**.
  Not from either incoming report — it arose in my own search — and recorded here so it cannot
  re-enter through any arm. See `R7.claude-web.md` §5.

## `ALL8.model-a.md` — source-quality audit

The preamble it was given asked for *"peer-reviewed venues … well-cited arXiv preprints"* and
*"a verifiable identifier: DOI, arXiv ID, or full proceedings citation"* for **every** claim.
Against that instruction, the report cites as evidence:

| source type | examples in the report |
|---|---|
| Reddit thread | DecompAI, cited as the system description |
| LinkedIn post | hallucination-rate claim in the R4 section |
| Facebook post | RAG architecture claim in the R5 section |
| Vendor / marketing blogs | promptquorum.com (local-LLM limitations), concret.io ("Verification Fence"), getmaxim.ai, truefoundry, several Medium posts |
| News article | CSO Online, for Microsoft's Project Ire |

None of these is a fabricated *paper* — they are real URLs. The failure is **evidential, not
factual**: a Facebook post is not a citation, and a claim resting on one cannot enter a paper.

**It also produced real value**, which is why it is kept rather than discarded. Leads that
originated with it and survived verification: **Chasing Shadows** (the single most important
document for R6), **SEC-bench**, **PhishDebate**, **REx86**, **CTIBench**, **CVE-Bench**, and the
AISI open-weight assessment. Its DOI-bearing citations (e.g. `10.1145/3708821.3733882` for
PentestAgent, `10.1145/3759425.3763397` for ClearAgent) are of a different quality to its social-
media ones, and the report does not distinguish between them — which is precisely the failure
the missing Part D output format was meant to prevent, since that format required a per-citation
confidence flag.

## Not checked, and why

Time-boxed. Unverified, in rough order of how much a claim depends on them:

- `arXiv:2503.23175` — *Large Language Models Are Unreliable for Cyber Threat Intelligence*.
  **Highest priority unread item in the whole review.** Either it supports our negative results
  or it contradicts our positive ones.
- `arXiv:2602.06325` dataset release status (TTPDetect), `arXiv:2607.23312` release status —
  each decides an E.4 answer.
- `arXiv:2605.05000` (COTS-binaries agent) — `R1.model-b.md` itself flags the figures as
  `UNCERTAIN` and says they came from a single follow-up read.
- `arXiv:2505.16366` (ReCopilot), `arXiv:2403.05286` (LLM4Decompile), `arXiv:2311.13721` (Nova),
  `arXiv:2505.07360` (BinMetric) — the small-open-weight-specialist cluster; BinMetric's
  "open-source mean 22.93% vs closed 27.46%" would be a second cross-tier data point.
- `10.1145/3759425.3763397` (ClearAgent, LMPL '25), `10.1145/3708821.3733882` (PentestAgent).
- Everything cited only via social media or vendor blogs in `ALL8.model-a.md` — **these should
  not be verified, they should be replaced.** If a claim matters, find a real source for it.

## What this means for weighting

| arm | verdict |
|---|---|
| `R1.model-b.md` | **High trust.** Everything checked exists and broadly says what was claimed; one overstatement (survey/six limitations). It volunteers uncertainty, flags unpublished preprints, and corrects a field-wide misattribution. Its gap claims can be carried as searched negatives. |
| `ALL8.model-a.md` | **Lead generator only.** Its verdicts are confirmatory by construction — it concludes we fill the description/assignment gap without ever surfacing `arXiv:2401.12178`. Use it to find papers; take no conclusion from it. |
| `R*.claude-web.md` | Citations fetched, but the gap claims are still absences, and absences are the weakest evidence there is. Every `NONE FOUND` in them is a searched negative, not a proof. |
