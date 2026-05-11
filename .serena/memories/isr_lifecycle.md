# ISR (Intermediate Structural Representation) Lifecycle

## Purpose
ISR replaces raw text inter-agent communication. Forces agents to cite concrete evidence per claim and provides machine-readable signals for sycophancy detection, cascade scoring, and ATT&CK validation.

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
agent_id: str
domain: Literal["static","dynamic","network","yara","sigma","tief"]
claims: list[ClaimEvidence]
dissent_items: list[str]
revision_round: int
```
- `mean_confidence`: Average of claim confidences (0 if empty).
- `to_text_summary()`: LLM-ready format. Appends `[CONVERGENCE SIGNAL: no remaining disputes]` when `revision_round > 0` AND `dissent_items == []`.

> Note: `tief` is still a valid Literal value although `analysis/tief_classifier.py` was removed. The cascade table still weights tief=0.80.

## Lifecycle Stages

### 1. Creation (Initial Analysis)
- `BaseAnalyst.analyze_isr(data)`: default calls `analyze()` then `_text_to_isr()`.
- Specialized analysts prompt with `CLAIM:/EVIDENCE:/CONFIDENCE:/TECHNIQUE:\n---` format → `_parse_claim_blocks()` regex extract.
- Fallback: `_text_to_isr()` sentence-splits with confidence 0.5.
- Domain inferred via `_infer_domain()` from agent name.

### 2. Chunk Merging (large samples)
`merge_chunk_isrs()` (`analysis/chunk_merger.py`):
1. Technique dedup → keep highest confidence per technique_id.
2. Text dedup → lowercase + strip.
3. Sort desc by confidence, cap at `MAX_MERGED_CLAIMS=20`.
4. Merge + dedup `dissent_items`.

### 3. Revision (Negotiation Loop)
- `BaseAnalyst.revise_isr`: default wraps `revise()` text via `_text_to_isr()`.
- Specialized agents prompt for `DISPUTES:` section.
- `_parse_disputes()` extracts items; `DISPUTES: NONE` → empty `dissent_items` (convergence signal).
- `revision_round` increments.

### 4. Sycophancy Detection Input
- Bag-of-words from claim texts across all ISRs.
- Cosine similarity current vs previous round.
- > threshold → Devil's Advocate directive next round.

### 5. TTP Cascade Input
`TTPCascadeEngine.compute(isr_reports)`:
- Group claims by `technique_id` → domain.
- Per domain: weighted mean confidence using `LAYER_WEIGHTS` (yara=0.90, tief=0.80, sigma=0.55, dynamic=0.45, static=0.35, network=0.20, default=0.25).
- Apply `CROSS_LAYER_MULTIPLIERS` (1→1.00 … 5→1.90).
- Output `CascadeResult` per technique, `CascadeSummary` aggregate.

### 6. ATT&CK Validation Input
`ATTCKValidator.validate_isr_reports()`:
- For each `technique_id`: `validate_ttp_id()` existence check + `validate_claim()` TF-IDF score vs technique description.
- Threshold 0.05; alternatives suggested for invalid/low-alignment IDs.
- `TTPValidationSummary` (in `memory/ttp_validation.py`): hallucination rate, per-claim `TTPClaimValidation`.

### 7. Judge Prompt Input
- ISR summaries (`to_text_summary()`) appended to verdict prompt.
- Judge populates STIX `ConfidenceAnnotatedRelationship.x_maljan_*` fields from ISR data.

### 8. LTM Persistence
- `build_stored_case()`: concatenates claims/evidence/technique IDs into `summary_text`.
- `StoredCase` upserted into `MemoryStore` (Qdrant or InMemory) keyed by sample_id.

## Key Design Decisions
- **Empty dissent_items = active convergence** (with `revision_round > 0`): not passive silence.
- **Technique ID regex** via Pydantic Field pattern guards against invalid IDs.
- **20-claim cap** prevents Judge prompt bloat; low-confidence claims dropped first.
- **Evidence_ref mandatory** — no hallucinated claims without artifact reference.
