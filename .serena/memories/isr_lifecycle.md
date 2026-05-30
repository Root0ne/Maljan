# ISR (Intermediate Structural Representation) Lifecycle

> Refreshed 2026-05-30. ISR replaces raw-text inter-agent communication: every claim cites
> concrete evidence and feeds sycophancy detection, cascade scoring, and ATT&CK validation.

## Core Models (`src/maljan/schemas/isr_models.py`)

### `ClaimEvidence`
```python
claim: str            # Specific finding/assertion
evidence_ref: str     # Concrete artifact reference (mandatory — no ungrounded claims)
confidence: float     # 0.0-1.0 (agent self-reported)
technique_id: str     # MITRE ATT&CK ID (regex: ^T\d{4}(\.\d{3})?$)
rule_platforms: list[str] | None   # Wave 4: platforms declared by the source Sigma/YARA rule;
                                    # the cascade prefers this over the MITRE catalog for the
                                    # platform-compatibility check.
```

### `AgentISR`
```python
agent_id: str
domain: Literal["static","dynamic","network","yara","sigma"] | str   # TIEF removed; "| str" for extensibility
claims: list[ClaimEvidence]
dissent_items: list[str]
revision_round: int
```
- `mean_confidence`: average of claim confidences (0 if empty).
- `to_text_summary()`: LLM-ready format; appends `[CONVERGENCE SIGNAL: no remaining disputes]`
  when `revision_round > 0` AND `dissent_items == []`.

> Note: `tief` is NO LONGER a valid domain value and has NO cascade weight — the `tief_classifier`
> module and its 0.80 weight were both removed.

## Lifecycle Stages

### 1. Creation (initial analysis)
- `BaseAnalyst.analyze_isr(data)`: specialized analysts prompt with `CLAIM:/EVIDENCE:/CONFIDENCE:/TECHNIQUE:\n---`
  -> `_parse_claim_blocks()` regex extract. Fallback `_text_to_isr()` sentence-splits (conf 0.5).
- Domain inferred via `_infer_domain()` from agent name.

### 2. Chunk merging (large samples) — `analysis/chunk_merger.py`
1. Technique dedup (keep highest confidence per technique_id).
2. Text dedup (lowercase+strip).
3. Sort desc by confidence, cap `MAX_MERGED_CLAIMS=20`. 4. Merge+dedup `dissent_items`.

### 3. Revision (negotiation loop)
- Specialized agents prompt for a `DISPUTES:` section; `_parse_disputes()` extracts items;
  `DISPUTES: NONE` -> empty `dissent_items` (convergence). `revision_round` increments.

### 4. Sycophancy detection input
- Bag-of-words over claim texts; cosine similarity current vs previous round; > threshold -> Devil's Advocate.

### 5. TTP cascade input — `TTPCascadeEngine.compute(isr_reports, sample_platform=...)`
- Group claims by technique_id -> domain. Per-domain weighted mean confidence using `LAYER_WEIGHTS`
  (yara=0.90, sigma=0.55, dynamic=0.45, static=0.35, network=0.20; default 0.25).
- Apply `CROSS_LAYER_MULTIPLIERS` (1->1.00 .. 5->1.90).
- **Platform filter (Wave 4)**: drops claims incompatible with `sample_platform` (uses
  `rule_platforms` first, else MITRE catalog, else `MOBILE_ENTERPRISE_OVERLAP`); rejected claims
  recorded in `CascadeSummary.dropped_by_platform`. Placeholder TTPs (T0000/T9999/T1234) pre-filtered.

### 6. ATT&CK validation input — `ATTCKValidator.validate_isr_reports()`
- Existence check + TF-IDF claim/description alignment (threshold 0.05); suggests alternatives.
- `TTPValidationSummary` (`memory/ttp_validation.py`): hallucination rate + per-claim `TTPClaimValidation`.

### 7. Judge prompt + postprocess input
- ISR summaries appended to verdict prompt; judge populates STIX `x_maljan_*` fields.
- `judge_postprocess.build_evidence_corpus()` derives an evidence token set from ISR/sandbox; J-02
  drops indicators whose literal is absent from that corpus; REP-02 drops attack-patterns whose
  technique_id is not a cascade survivor. See `mem:extractors_enrichment_qa`.

### 8. LTM persistence
- `build_stored_case()` concatenates claims/evidence/technique IDs into `summary_text`; upserted
  into the MemoryStore (Qdrant default) keyed by sample_id, using fastembed embeddings.

## Key Design Decisions
- Empty `dissent_items` + `revision_round>0` = active convergence (not passive silence).
- `technique_id` regex Field pattern guards invalid IDs; cascade also denylists placeholders.
- 20-claim cap prevents Judge prompt bloat (low-confidence dropped first).
- `evidence_ref` mandatory — no hallucinated claims without an artifact reference.
- `rule_platforms` lets deterministic rules carry their own platform scope into the cascade.
