# Data Flow: How a Sample Traverses the Pipeline

## Phase 0: Initialization
1. `MaljanApp.__init__(config, mock, samples_dir)` creates `ServiceContainer`.
2. Container initializes `AgentRegistry` and `ParserRegistry` (auto-discovery).
3. Lazy caches initialized on first access: LLMs, agents, memory store, sandbox, YARA, Sigma.
4. `build_graph(container)` discovers agents from registry and compiles LangGraph.
5. `AnalysisState` initialized with empty `reports`, `isr_reports`, `discussion_history`, `confidence_history`.

## Phase 1: Parallel Analyst Fan-Out
For each registered agent, `make_analyst_node(agent_name, container)` executes:
1. `container.load_chunked(file_hash, agent_name)` → `FileDataLoader` reads and parses sample, then `BinaryChunker` splits into `TextChunk` list.
   - `max_tokens_per_chunk=6000`, `overlap_tokens=200`, `skip_if_fits=true`.
   - Single chunk → fast path. Multi-chunk → hierarchical analysis.
2. **Single chunk**: `agent.safe_analyze_isr(chunk.content)` → `analyze_isr(data)`.
   - Agent initializes MCP client (Ghidra/CAPE/Network) if enabled.
   - LLM prompted with structured format: `CLAIM:/EVIDENCE:/CONFIDENCE:/TECHNIQUE:`.
   - `_parse_claim_blocks()` extracts `ClaimEvidence` objects.
   - Fallback: `_text_to_isr()` splits into sentences.
3. **Multi-chunk**: `agent.safe_analyze_isr_chunked(chunks)`:
   - For each chunk: `analyze_isr(chunk.to_prompt_header() + chunk.content)`.
   - Failed chunks logged, successful ones collected.
   - `merge_chunk_isrs(chunk_isrs)`:
     - Deduplicate by `technique_id` (keep highest confidence).
     - Deduplicate text claims by normalized string.
     - Sort by confidence, cap at `MAX_MERGED_CLAIMS=20`.
     - Merge `dissent_items` across chunks.
4. Node returns: `{"reports": {agent_name: text}, "isr_reports": {agent_name: AgentISR}}`.

## Phase 2: Fan-In + Negotiation
`make_negotiation_node(container)`:
1. Collect all ISRs from `state["isr_reports"]`.
2. `detect_sycophancy(current_isrs)`:
   - Builds bag-of-words vectors from claim texts.
   - Computes cosine similarity between current and previous round.
   - If `> SYCOPHANCY_THRESHOLD`, flags as sycophancy.
3. `JudgeAgent.mediate(reports, history, isr_reports)`:
   - Builds prompt with all reports + ISR summaries (`to_text_summary()`).
   - Executes ReAct tool loop (ThreatIntel MCP tools available).
   - Structured output: `MediatorVerdict` (contradictions, resolution_summary, confidence).
   - Fallback: `_fallback_mediate()` extracts confidence via regex.
4. Computes `mean_conf` across all ISRs for `confidence_history`.
5. Returns: `iteration_count+1`, `is_consensus` (confidence >= 0.85), `sycophancy_detected`, `confidence_history`, `discussion_history`.

## Phase 3: Routing (ConsensusRouter)
`ConsensusRouter.should_continue(state)` decision tree:
1. `iteration >= max_iterations` → "judge" (hard limit, always优先)
2. `sycophancy_detected AND consensus` → "revision" (override premature consensus)
3. `consensus AND no sycophancy` → "judge" (genuine consensus)
4. `is_confidence_stable(confidence_history)`:
   - Last 3 values: `std < 0.04` AND `mean >= 0.70` → "judge"
5. Default → "revision"

## Phase 4: Revision (if loop continues)
`make_revision_node(container)`:
1. Extract latest Mediator feedback from `discussion_history`.
2. `build_revision_directive(sycophancy_detected, mediator_feedback)`:
   - If sycophancy: prepends `DEVIL_ADVOCATE_DIRECTIVE` forcing counter-evidence.
3. For each agent:
   - `_build_revision_context(state, container, agent_name)`:
     - Single chunk → raw text.
     - Multi-chunk → consolidated ISR summary (prevents truncation inconsistency).
   - `agent.safe_revise_isr(original_data, own_report, peer_reports, mediator_feedback, revision_round)`:
     - LLM prompted with peer reports + mediator contradictions.
     - Must output structured claims + `DISPUTES:` section.
     - `_parse_claim_blocks()` and `_parse_disputes()` extract ISR.
4. Returns: `{"revised_reports": {...}, "isr_reports": {...}}`.
5. Loop back to negotiation.

## Phase 5: Judge (Final Verdict)
`make_judge_node(container)`:
1. **YARA Layer 0**: `container.get_yara_layer().scan(combined_text)`.
   - Combines all report texts + ISR evidence_refs.
   - Matches injected as `isr_reports["yara_layer"]` (domain="yara").
2. **Sigma Layer 0**: `container.get_sigma_layer().scan_report_text(combined_text)`.
   - Matches injected as `isr_reports["sigma_layer"]` (domain="sigma").
3. **TTP Cascade**: `TTPCascadeEngine.compute(isr_reports)`:
   - Groups claims by `technique_id` → domain.
   - Weighted average per layer (yara=0.90, sigma=0.55, dynamic=0.45, static=0.35, network=0.20).
   - Cross-layer multiplier applied (1.00 to 1.90).
   - Produces `CascadeSummary` with corroborated/consensus counts.
4. **ATT&CK Validation**: `ATTCKValidator.validate_isr_reports(isr_reports)`:
   - Checks each `technique_id` existence in ATT&CK index.
   - Scores evidence alignment (threshold 0.05).
   - Suggests alternatives for invalid/low-alignment IDs.
   - Produces `TTPValidationSummary` with hallucination rate.
5. **Schema Pruning**: `infer_malware_category(reports, isr_reports)`:
   - Keyword-weighted scoring (ATT&CK IDs weight highest).
   - Categories: ransomware, RAT, dropper, worm, infostealer, unknown.
   - Produces STIX object type guidance for Judge prompt.
6. **LTM Retrieval**: `memory_store.retrieve(query, top_k=3)`:
   - Query built from all ISR claims + evidence + technique IDs.
   - Retrieved cases formatted as weighted priors (not blind copy).
7. **Verdict Prompt Assembly**:
   - Base: Expert reports + negotiation history.
   - + ISR summaries.
   - + ATT&CK validation block (flags hallucinated IDs).
   - + TTP cascade block (prioritizes corroborated techniques).
   - + Schema pruning hint (category-specific STIX focus).
   - + LTM few-shot context.
   - System prompt: STIX confidence interval instructions (`x_maljan_*` fields).
   - + Confidence reference table from cascade top techniques.
8. `llm.with_structured_output(Bundle).ainvoke(prompt)` → `Bundle`.
9. **Decision extraction**: Scan bundle objects for `type="malware"` → "Malware", else "Suspicious".
10. **RunSummary**: `RunSummaryBuilder` constructs full observability report.
11. **LTM Persist**: `build_stored_case()` → `memory_store.store(case)`.
12. Returns: `final_decision`, `judge_report`, `stix_output`, `run_summary`.
