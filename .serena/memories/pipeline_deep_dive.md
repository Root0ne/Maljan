# Pipeline Deep Dive

> Refreshed 2026-05-30. Cross-refs: `mem:data_flow`, `mem:reporting_layer`.

## State (`src/maljan/pipeline/state.py`)
`AnalysisState` is a TypedDict with LangGraph reducers. Generic agent-keyed dicts mean adding an
agent requires ZERO schema change.

| Field | Type | Reducer | Notes |
|-------|------|---------|-------|
| `file_hash` | str | direct | Sample id |
| `file_name` | str\|None | direct | |
| `sample_path` | str\|None | direct | For sandbox submit |
| `sandbox_report` | dict\|None | direct | Normalized sandbox output |
| `file_type` | str\|None | direct | **Wave 4** — inferred at bootstrap |
| `platform` | str\|None | direct | **Wave 4** — canonical platform (windows/linux/macos/android/ios/cloud/crossplatform/unknown) |
| `static_sample_path` | str\|None | direct | **Wave 6 (GHIDRA-DELIVERY-01)** — container-visible path for Ghidra MCP `load_program` |
| `reports` | dict[str,str] | `_merge_dicts` | Initial text reports |
| `revised_reports` | dict[str,str] | `_merge_dicts` | Post-revision |
| `isr_reports` | dict[str,AgentISR] | `_merge_dicts` | Structured ISR |
| `discussion_history` | list[AgentArgument] | `operator.add` | Append each round |
| `sycophancy_detected` | bool | direct | |
| `confidence_history` | list[float] | `operator.add` | Per-round mean confidence |
| `iteration_count` | int | direct | |
| `is_consensus` | bool | direct | From mediator (>=0.85) |
| `final_decision` | Literal[Malware/Benign/Suspicious]\|None | direct | Judge output |
| `judge_report` | str\|None | direct | |
| `stix_output` | dict\|None | direct | Minimal judge Bundle |
| `run_summary` | dict\|None | direct | Observability (incl. cascade platform_filter_summary + fp_warnings) |
| `malware_report` | dict\|None | direct | **report_node** — comprehensive MalwareReport JSON |
| `malware_report_markdown` | str\|None | direct | **report_node** — rendered markdown |
| `stix_bundle_extended` | dict\|None | direct | **report_node** — extended STIX (+ x_maljan_cti) |
| `degraded_mode` | bool | direct | **CONF-INFL-01** — TTPs w/o LLM corroboration or [ERROR] reports |
| `degradation_reasons` | list[str] | direct | **CONF-INFL-01** |
| `sandbox_cti` | dict\|None | direct | Triage CTI block; folded into network IOCs (W10-NET-01) |

(Note: there is no `_max_iterations` state field — the limit comes from `NegotiationConfig.max_iterations`
via the router.) `AgentArgument` (Pydantic): `agent_name`, `finding`, `confidence_score`.

## Graph (`pipeline/builder.py`)
- Nodes built dynamically: per-agent `{name}_analyst`, `negotiation`, `revision`, `judge`,
  and `report` (only when `config.reporting.enabled`).
- **Topology toggle** `config.llm.parallel_analysts`:
  - True (config default): START -> all analysts (parallel) -> negotiation.
  - False: START -> agent_1 -> ... -> agent_N -> negotiation (sequential chain, registry order) —
    for single-slot local llama-server to avoid queue contention.
- `add_conditional_edges("negotiation", router.should_continue, {revision, judge})`;
  `revision -> negotiation`; `judge -> report -> END` (or `judge -> END` when reporting off).

## Node Functions (`pipeline/nodes.py`, ~1023 lines)
- `make_analyst_node`: mock returns fixture ISR (`domain=agent_name`, `# type: ignore[arg-type]`);
  real mode single/multi-chunk analysis; error -> empty ISR + error text.
- `make_negotiation_node`: active reports (revised else original); sycophancy; `mediate()`; mean_conf;
  mock -> consensus after 1 round at 0.95.
- `make_revision_node`: mediator feedback + Devil's Advocate directive; `_build_revision_context()`
  (single->raw, multi->consolidated ISR summary); per-agent error -> original fallback.
- `make_judge_node`: platform read -> YARA -> Sigma -> platform-aware cascade -> ATT&CK validate ->
  LTM retrieve -> evidence corpus -> CTI -> `give_verdict()` (with judge_postprocess) -> decision ->
  degradation signals -> RunSummary -> LTM persist. No TODO markers remain.
- `make_report_node`: feature-flag; cascade recompute; overall_confidence (degraded cap 0.60);
  malware_category; builder.build_deterministic -> narrative (LLM/fallback) -> detection signatures ->
  markdown + extended STIX -> fp_linter. See `mem:reporting_layer`.

## Routing (`pipeline/routing.py`)
- Constants: `CONFIDENCE_WINDOW=3`, `CONVERGENCE_STD_THRESHOLD=0.04`, `MIN_CONVERGENCE_CONFIDENCE=0.70`.
- `is_confidence_stable(history)`: last 3 -> std<0.04 AND mean>=0.70 (requires >=3 rounds).
- `should_continue` priority: hard-limit -> sycophancy+consensus -> genuine consensus -> stable -> revision.

## Sycophancy (`pipeline/sycophancy_detector.py`)
- Vocab from all claim texts -> bag-of-words per ISR -> cosine current vs previous round ->
  `> SYCOPHANCY_THRESHOLD` flags. `build_revision_directive()` prepends `DEVIL_ADVOCATE_DIRECTIVE`.

## Mock Mode
- `container.is_mock=True` skips LLM calls; analyst fixtures; negotiation consensus@1 round (0.95);
  judge "Malware" + empty STIX; NarrativeAgent is None (report uses fallback narrative).
