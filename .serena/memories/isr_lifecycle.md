# ISR (Intermediate Structural Representation) Lifecycle

## Purpose
ISR replaces raw text inter-agent communication. It forces agents to cite concrete evidence for every claim and provides machine-readable signals for sycophancy detection, cascade scoring, and ATT&CK validation.

## Core Models (`src/maljan/schemas/isr_models.py`)

### `ClaimEvidence`
```python
claim: str           # Specific finding/assertion
evidence_ref: str    # Concrete artifact reference
confidence: float    # 0.0-1.0 (agent self-reported)
technique_id: str    # MITRE ATT&CK ID (regex: ^T\d{4}(\.\d{3})?$)
```

### `AgentISR`
```python
agent_id: str                     # Registry name (e.g., "static")
domain: Literal[...]              # static | dynamic | network | yara | sigma | tief
claims: list[ClaimEvidence]       # Evidence-backed claims
dissent_items: list[str]          # Peer claims still disputed
revision_round: int               # 0 = initial, 1+ = revision
```
- **`mean_confidence`**: Average of all claim confidences (0.0 if empty).
- **`to_text_summary()`**: Compact LLM-ready format. Appends `[CONVERGENCE SIGNAL: no remaining disputes]` when `revision_round > 0` and `dissent_items` is empty.

## Lifecycle Stages

### 1. Creation (Initial Analysis)
- **`BaseAnalyst.analyze_isr(data)`**: Default implementation calls `analyze()` then `_text_to_isr()`.
- **Specialized overrides** (`StaticAnalyst`, `DynamicAnalyst`, `NetworkAnalyst`):
  - Prompt LLM with structured output format: `CLAIM:...\nEVIDENCE:...\nCONFIDENCE:...\nTECHNIQUE:...\n---`.
  - `_parse_claim_blocks(text)` extracts claims using regex.
  - If parsing fails → fallback to `_text_to_isr()` (sentence splitting, neutral confidence 0.5).
- **Domain inference**: `_infer_domain()` from agent name ("static" → "static", etc.).

### 2. Chunk Merging (if sample is large)
- **`merge_chunk_isrs(chunk_isrs)`** (`src/maljan/analysis/chunk_merger.py`):
  - **Step 1 (Technique dedup)**: For claims WITH `technique_id`, keep highest confidence per technique.
  - **Step 2 (Text dedup)**: For claims WITHOUT technique_id, deduplicate by lowercased stripped text.
  - **Step 3 (Cap)**: Sort all claims by confidence descending, keep top `MAX_MERGED_CLAIMS=20`.
  - **Step 4 (Dissent)**: Merge and deduplicate `dissent_items` across all chunks.
  - Result: Single authoritative `AgentISR` representing all chunks.

### 3. Revision (Negotiation Loop)
- **`BaseAnalyst.revise_isr(...)`**:
  - Calls `revise()` (text-based) then wraps into ISR via `_text_to_isr()`.
- **Specialized overrides**:
  - Prompt includes peer reports, mediator feedback, and revision instructions.
  - Agent MUST output structured claims + `DISPUTES:` section.
  - `_parse_disputes(text)` extracts dispute items.
  - If `DISPUTES: NONE` → empty `dissent_items` (convergence signal).
  - `revision_round` incremented.

### 4. Sycophancy Detection Input
- `detect_sycophancy(current_isrs)` builds bag-of-words from claim texts.
- Compares current round vs previous round cosine similarity.
- High similarity → flags sycophancy → Devil's Advocate directive injected.

### 5. TTP Cascade Input
- `TTPCascadeEngine.compute(isr_reports)`:
  - Iterates all claims across all ISRs.
  - Groups by `technique_id` → `domain`.
  - Per domain: calculates mean confidence, claim count, evidence refs.
  - Weighted average using `LAYER_WEIGHTS`.
  - Applies `CROSS_LAYER_MULTIPLIERS` based on number of contributing domains.
  - Outputs `CascadeResult` per technique and `CascadeSummary` aggregate.

### 6. ATT&CK Validation Input
- `ATTCKValidator.validate_isr_reports(isr_reports)`:
  - For each claim with `technique_id`:
    - `validate_ttp_id()`: Check existence in ATT&CK index.
    - `validate_claim()`: Score evidence text against technique description (TF-IDF cosine).
    - If invalid/low-alignment: suggest alternatives via `search()`.
  - Produces `TTPValidationSummary` with aggregate stats.

### 7. Judge Prompt Input
- ISR summaries appended to Judge prompt via `to_text_summary()`.
- Provides per-claim confidence scores and explicit dissent signals.
- Judge uses these to populate `x_maljan_confidence`, `x_maljan_evidence_basis`, `x_maljan_contributing_agents`, `x_maljan_technique_id` in STIX Bundle.

### 8. LTM Persistence
- `build_stored_case(sample_id, isr_reports, stix_bundle_json, malware_category)`:
  - Concatenates all claim text, evidence refs, and technique IDs into `summary_text`.
  - Deduplicates technique IDs.
  - Stores as `StoredCase` in `MemoryStore` (Qdrant or InMemory).

## Key Design Decisions
- **Empty dissent_items = convergence signal**: Unlike passive silence, explicitly empty list with `revision_round > 0` means agent actively accepts all peer claims.
- **Technique ID regex validation**: Pydantic Field pattern ensures only valid ATT&CK IDs enter the system.
- **20-claim cap**: Prevents prompt bloat in Judge node; low-confidence claims dropped first.
- **Evidence_ref mandatory**: Forces grounded reasoning; no hallucinated claims without artifact reference.
