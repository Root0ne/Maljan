# Pipeline Deep Dive

## State Management (`src/maljan/pipeline/state.py`)

`AnalysisState` is a TypedDict with custom reducers for LangGraph:

| Field | Type | Reducer | Notes |
|-------|------|---------|-------|
| `file_hash` | `str` | direct | Sample identifier |
| `file_name` | `str \| None` | direct | Human-readable name |
| `reports` | `dict[str, str]` | `_merge_dicts` | Initial text reports by agent |
| `revised_reports` | `dict[str, str]` | `_merge_dicts` | Post-revision reports |
| `isr_reports` | `dict[str, AgentISR]` | `_merge_isr_dicts` | Structured ISR by agent |
| `discussion_history` | `list[AgentArgument]` | `operator.add` | Appended each round |
| `sycophancy_detected` | `bool` | direct | Last round flag |
| `confidence_history` | `list[float]` | `operator.add` | Appended each round |
| `iteration_count` | `int` | direct | Round counter |
| `is_consensus` | `bool` | direct | From mediator |
| `final_decision` | `Literal[...] \| None` | direct | Judge output |
| `judge_report` | `str \| None` | direct | Judge narrative |
| `stix_output` | `dict \| None` | direct | Serialized Bundle |
| `run_summary` | `dict \| None` | direct | RunSummary dict |
| `_max_iterations` | `int` | direct | Configured limit |

**Key design**: Generic dicts keyed by agent name mean adding a new agent requires ZERO state schema changes.

## Node Functions (`src/maljan/pipeline/nodes.py`)

### `make_analyst_node(agent_name, container)`
```python
def node_fn(state: AnalysisState) -> dict[str, Any]:
    if mock: return mock_isr
    agent = container.get_agent(agent_name)
    chunks = container.load_chunked(state["file_hash"], agent_name)
    if len(chunks) == 1:
        isr = agent.safe_analyze_isr(chunks[0].content)  # fast path
    else:
        isr = agent.safe_analyze_isr_chunked(chunks)     # chunked path
    report = isr.to_text_summary() if isr.claims else agent.safe_analyze(chunks[0].content)
    return {"reports": {agent_name: report}, "isr_reports": {agent_name: isr}}
```
- Error handling: Returns empty ISR and error text on `AnalystError`/`LLMError`.

### `_build_revision_context(state, container, agent_name)`
- Problem: `load_data()` silently truncates large samples, causing revision grounding inconsistency.
- Solution:
  - Single chunk → raw text (safe, fits context).
  - Multi-chunk → uses agent's consolidated ISR summary from state with chunking context header.
  - Zero extra I/O (chunk count derived from cached `load_chunked()`).

### `make_negotiation_node(container)`
- Collects active reports (revised if available, else original).
- Runs `detect_sycophancy(current_isrs)`.
- Calls `JudgeAgent.mediate()` asynchronously.
- Computes `mean_conf` across ISRs for `confidence_history`.
- Mock mode: consensus after iteration >= 1.

### `make_revision_node(container)`
- Extracts latest Mediator feedback from `discussion_history`.
- Injects Devil's Advocate directive if sycophancy detected.
- Iterates all agents, calls `safe_revise_isr()` with chunk-aware context.
- Error per-agent: falls back to original report, empty ISR.

### `make_judge_node(container)`
1. YARA scan → inject yara_layer ISR.
2. Sigma scan → inject sigma_layer ISR.
3. TTP cascade compute.
4. Start timer for RunSummary.
5. Get ATT&CK validator (graceful skip if unavailable).
6. Get memory store (graceful skip if unavailable).
7. `JudgeAgent.give_verdict()` with all grounding blocks.
8. Extract decision from Bundle.
9. Build RunSummary via `RunSummaryBuilder`.
10. Persist to LTM.
11. Return final state updates.

## Routing Logic (`src/maljan/pipeline/routing.py`)

### `is_confidence_stable()`
```python
recent = confidence_history[-3:]
std = sqrt(sum((x - mean)^2) / n)
stable = std < 0.04 and mean >= 0.70
```
- Requires at least 3 rounds of history.
- Logs debug info when not yet stable.

### `ConsensusRouter.should_continue(state)`
Decision priority (highest to lowest):
1. **Hard iteration limit** — unconditional judge.
2. **Sycophancy override** — if sycophancy AND consensus, force revision.
3. **Genuine LLM consensus** — consensus without sycophancy → judge.
4. **Adaptive termination** — stable confidence → judge.
5. **Default** → revision.

## Graph Construction (`src/maljan/pipeline/builder.py`)
```
START → static_analyst ─┐
START → dynamic_analyst ┤→ negotiation → [conditional] → revision → negotiation (loop)
START → network_analyst ┘                         ↓ judge → END
```
- `add_edge(START, f"{name}_analyst")` for each agent (parallel).
- `add_edge(f"{name}_analyst", "negotiation")` for each agent (fan-in).
- `add_conditional_edges("negotiation", router.should_continue, path_map)`.
- `add_edge("revision", "negotiation")` (loop back).
- `add_edge("judge", END)`.

## Sycophancy Detection (`src/maljan/pipeline/sycophancy_detector.py`)

### Algorithm
1. Build vocabulary from all claim texts across all ISRs.
2. Create bag-of-words vector for each ISR (term frequency).
3. Compute cosine similarity between current round and previous round vectors.
4. If similarity > `SYCOPHANCY_THRESHOLD` → sycophancy detected.

### `build_revision_directive(syco_detected, mediator_feedback)`
- If sycophancy: prepends `DEVIL_ADVOCATE_DIRECTIVE` to mediator feedback.
- Directive forces agents to find counter-evidence and challenge peer claims.

## Mock Mode
- `container.is_mock = True` skips all LLM calls.
- Analyst nodes return fixture ISRs with empty claims.
- Negotiation: consensus after 1 round, confidence 0.95.
- Revision: mock revised reports.
- Judge: "Malware" verdict, empty STIX.
