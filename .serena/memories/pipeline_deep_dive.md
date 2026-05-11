# Pipeline Deep Dive

## State Management (`src/maljan/pipeline/state.py`)

`AnalysisState` is a TypedDict with custom reducers for LangGraph:

| Field | Type | Reducer | Notes |
|-------|------|---------|-------|
| `file_hash` | `str` | direct | Sample identifier |
| `file_name` | `str \| None` | direct | Human-readable name |
| `sample_path` | `str \| None` | direct | Path to original binary (for sandbox submit) |
| `sandbox_report` | `dict[str, Any] \| None` | direct | Normalized sandbox output (signatures, ttp_tags, network, behavior) |
| `reports` | `dict[str, str]` | `_merge_dicts` | Initial text reports by agent |
| `revised_reports` | `dict[str, str]` | `_merge_dicts` | Post-revision reports |
| `isr_reports` | `dict[str, AgentISR]` | `_merge_isr_dicts` | Structured ISR by agent |
| `discussion_history` | `list[AgentArgument]` | `operator.add` | Appended each round |
| `sycophancy_detected` | `bool` | direct | Last round flag |
| `confidence_history` | `list[float]` | `operator.add` | Appended each round |
| `iteration_count` | `int` | direct | Round counter |
| `is_consensus` | `bool` | direct | From mediator |
| `final_decision` | `Literal["Malware","Benign","Suspicious"] \| None` | direct | Judge output |
| `judge_report` | `str \| None` | direct | Judge narrative |
| `stix_output` | `dict \| None` | direct | Serialized Bundle |
| `run_summary` | `dict \| None` | direct | RunSummary dict |
| `_max_iterations` | `int` | direct | Configured limit |

**Key design**: Generic agent-keyed dicts mean adding a new agent requires ZERO state schema changes.

`AgentArgument` (also in state.py): Pydantic model with `agent_name`, `finding`, `confidence_score`. Used in `discussion_history`.

## Pre-Pipeline: Sandbox Submission (`MaljanApp.arun`)

Before LangGraph executes, `MaljanApp._submit_to_sandbox(sample_path)` runs:
1. Resolves path (skipped if mock or missing).
2. Gets client from `container.get_sandbox_client()` (Triage / CAPE / Mock based on config).
3. Calls `submit_and_wait(path)` if available (Triage), else manual submit/wait/fetch loop → `SubmissionResult`.
4. On success: returns normalized report dict (`_triage_raw_tasks`, `signatures`, `ttp_tags`, `behavior`, `network`).
5. On any failure: logs and returns None. Pipeline still proceeds.

The report becomes `state["sandbox_report"]` and is consumed by parsers/agents downstream.

## Node Functions (`src/maljan/pipeline/nodes.py`)

### `make_analyst_node(agent_name, container)`
- Mock mode: returns fixture ISR with `domain=agent_name` (`# type: ignore[arg-type]` because Literal narrowing fails).
- Real mode: `container.load_chunked(file_hash, agent_name)` → `TextChunk` list.
- Single chunk → `agent.safe_analyze_isr(chunk.content)` fast path.
- Multi-chunk → `agent.safe_analyze_isr_chunked(chunks)` hierarchical.
- Error → empty ISR + error text.
- Returns `{"reports": {agent_name: text}, "isr_reports": {agent_name: AgentISR}}`.

### `_build_revision_context(state, container, agent_name)`
- Problem solved: `load_data()` silently truncated large samples → revision grounding inconsistency.
- Single chunk → raw text.
- Multi-chunk → consolidated ISR summary from state with chunking-context header. Zero extra I/O.

### `make_negotiation_node(container)`
- Active reports = revised if exists else original.
- `detect_sycophancy(current_isrs)`.
- `JudgeAgent.mediate()` async → `MediatorVerdict` (contradictions, resolution_summary, confidence).
- `mean_conf` across ISRs → appended to `confidence_history`.
- Mock mode: consensus after 1 round, confidence 0.95.

### `make_revision_node(container)`
- Extract latest Mediator feedback from `discussion_history`.
- `build_revision_directive(syco, feedback)` injects Devil's Advocate when sycophancy.
- Per agent: `safe_revise_isr(original_data, own_report, peer_reports, feedback, revision_round)`.
- Per-agent error → original report fallback + empty ISR.

### `make_judge_node(container)`
1. YARA scan → inject `yara_layer` ISR.
2. Sigma scan → inject `sigma_layer` ISR.
3. TTP cascade compute.
4. Start RunSummary timer.
5. ATT&CK validator (graceful skip if unavailable).
6. Memory store retrieve (graceful skip).
7. `JudgeAgent.give_verdict()` with all grounding blocks (cascade, validation, schema pruning hint, LTM context).
8. Extract decision from Bundle (`type=malware` → "Malware", else "Suspicious").
9. `RunSummaryBuilder` → run_summary dict.
10. Persist to LTM via `build_stored_case()`.

## Routing Logic (`pipeline/routing.py`)

### `is_confidence_stable(history)`
```python
recent = history[-3:]; mean = sum/3; std = sqrt(sum((x-mean)^2)/3)
stable = std < 0.04 and mean >= 0.70
```
Requires ≥3 rounds; debug-logs when not yet stable.

### `ConsensusRouter.should_continue(state)` decision priority
1. `iteration >= max_iterations` → judge (hard limit, unconditional)
2. `sycophancy_detected AND consensus` → revision (override premature consensus)
3. `consensus AND no sycophancy` → judge (genuine)
4. `is_confidence_stable(...)` → judge (adaptive)
5. Default → revision

## Graph Construction (`pipeline/builder.py`)
```
START → static_analyst ─┐
START → dynamic_analyst ┤→ negotiation → [conditional] → revision → negotiation (loop)
START → network_analyst ┘                              ↓ judge → END
```
- `add_edge(START, f"{name}_analyst")` per agent.
- `add_edge(f"{name}_analyst", "negotiation")` per agent.
- `add_conditional_edges("negotiation", router.should_continue, path_map)`.
- `add_edge("revision", "negotiation")` loop.
- `add_edge("judge", END)`.

## Sycophancy Detection (`pipeline/sycophancy_detector.py`)
1. Build vocab from all claim texts across ISRs.
2. Bag-of-words vector per ISR.
3. Cosine sim current vs previous round.
4. > `SYCOPHANCY_THRESHOLD` → flag.
- `build_revision_directive(syco, feedback)` prepends `DEVIL_ADVOCATE_DIRECTIVE`.

## Mediation Models (`pipeline/mediation_models.py`)
- `MediatorVerdict`: Pydantic model with contradictions, resolution_summary, confidence.

## Mock Mode
- `container.is_mock = True` skips all LLM calls.
- Analyst nodes return fixture ISRs.
- Negotiation: consensus after 1 round, confidence 0.95.
- Revision: mock reports.
- Judge: "Malware" verdict, empty STIX.
