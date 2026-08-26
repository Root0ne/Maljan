# Pipeline Deep Dive

> Refreshed 2026-07-05. Cross-refs: `mem:data_flow`, `mem:reporting_layer`.

## State (`src/maljan/pipeline/state.py`)
`AnalysisState` TypedDict — **UNCHANGED since 2026-05-30** (git-verified). Fields: file_hash,
file_name, sample_path, sandbox_report, file_type, platform (now effectively windows/linux/unknown),
static_sample_path, reports, revised_reports, isr_reports, discussion_history,
sycophancy_detected, confidence_history, iteration_count, is_consensus, final_decision,
judge_report, stix_output, run_summary, malware_report, malware_report_markdown,
stix_bundle_extended, degraded_mode, degradation_reasons, sandbox_cti.

**Gotcha**: `make_judge_node` returns an UNDECLARED key `function_hash_matches` (consumed by
`make_report_node` -> `report.attribution.function_hash_matches`). Works via LangGraph dict
merge, but it is not in the TypedDict — declare it if you touch state schema.

## Graph (`pipeline/builder.py`) — unchanged
- Topology toggle `config.llm.parallel_analysts` (default True; False = sequential chain for
  single-slot local llama-server). negotiation conditional edges -> {revision, judge};
  revision -> negotiation; judge -> report -> END (or judge -> END).

## Node Functions (`pipeline/nodes.py`, ~1400 lines)
- `make_analyst_node`: mock fixture ISR; single-chunk (+view decomposition dispatch when
  `LLM__VIEW_DECOMPOSITION_VIEWS>=2`, facet/tier via `view_decomposition_mode`); multi-chunk
  (+TraceRAG chunk selection when `static_function_rag_top_k>0`, nodes.py:233-248).
- `make_negotiation_node`: **broad `except Exception` fault boundary (bcfde63)** — degrades to
  no-consensus, emits `[ERROR] Mediation timed out/failed` finding.
- `make_revision_node`: unchanged behavior.
- `make_judge_node`: platform -> YARA -> Sigma -> **DGA ISR (nodes.py:655) + LOLBin ISR
  (nodes.py:669)** -> **ATT&CK autocorrect (nodes.py:700)** -> platform-aware cascade ->
  validation -> LTM -> evidence corpus -> **function-hash attribution read/write
  (nodes.py:962-993)** -> family/case RAG mirrors (nodes.py:1017/1051, gated OFF) ->
  `give_verdict()` -> decision -> degradation signals -> RunSummary (+ **token ledger snapshot**
  nodes.py:883) -> LTM persist. **Broad `except Exception`** -> conservative "Suspicious" +
  `[ERROR] Judge failed`.
- `make_report_node`: feature-flag; cascade recompute; degraded cap 0.60; category backend
  dispatch; builder -> narrative -> signatures -> markdown + extended STIX -> fp_linter.

## Routing (`pipeline/routing.py`)
- Constants unchanged: `CONFIDENCE_WINDOW=3`, `CONVERGENCE_STD_THRESHOLD=0.04`,
  `MIN_CONVERGENCE_CONFIDENCE=0.70`.
- `should_continue` priority: hard-limit -> **BUG-05 mediation-error fast-path** ("[ERROR]
  Mediation" prefix on last finding -> judge) -> sycophancy+consensus -> consensus -> stable ->
  revision.

## Agent runtime notes (see `mem:architecture_key_points` §2)
- Persistent process-wide agent event loop (daemon thread) — all agent coroutines; hard cap
  timeout+30s; BUG-04 connection-error retry inside `_invoke()`.
- Forced final synthesis when ReAct exhausts step budget with empty content.
- Per-agent max-steps: `react_agent_max_steps_overrides` default `{static: 40}` (base 10).

## Sycophancy (`pipeline/sycophancy_detector.py`) — unchanged
Bag-of-words cosine vs previous round; Devil's Advocate directive.

## Mock Mode — unchanged
Fixtures; consensus@1 round (0.95); judge "Malware" + empty STIX; fallback narrative.
Eval harnesses force `SANDBOX__BACKEND=mock` to prevent live malware uploads.
