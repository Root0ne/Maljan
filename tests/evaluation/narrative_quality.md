# Narrative-quality evaluation (LLM vs deterministic fallback)

- Faithfulness-centric metrics (no human reference prose vendored): grounding
  precision = cited techniques present in the evidence; coverage recall = evidence
  techniques surfaced; structural = schema/length/parenthesised-ID compliance;
  fp_linter clean = no C2 (recommendation cites absent technique) / C3 (exec-summary
  platform mismatch). F1 = harmonic mean of precision and recall.
- Samples generated 3x each for N>>1 (decoding variance -> bootstrap CI).

## LLM narrative (n=15)

| metric | mean | 95% bootstrap CI |
|---|---|---|
| grounding precision (faithfulness) | 1.000 | [1.000, 1.000] |
| coverage recall | 0.920 | [0.867, 0.973] |
| F1 (precision x recall) | 0.956 | [0.926, 0.985] |
| structural pass-rate | 1.000 | [1.000, 1.000] |
| fp_linter clean-rate (no C2/C3) | 0.800 | [0.600, 1.000] |
| hallucinated techniques (count) | 0.000 | [0.000, 0.000] |

## Deterministic fallback (n=15)

| metric | mean | 95% bootstrap CI |
|---|---|---|
| grounding precision (faithfulness) | 1.000 | [1.000, 1.000] |
| coverage recall | 1.000 | [1.000, 1.000] |
| F1 (precision x recall) | 1.000 | [1.000, 1.000] |
| structural pass-rate | 0.000 | [0.000, 0.000] |
| fp_linter clean-rate (no C2/C3) | 1.000 | [1.000, 1.000] |
| hallucinated techniques (count) | 0.000 | [0.000, 0.000] |

## Paired (LLM - fallback, F1)

- mean delta (LLM - fallback) = **-0.044**, 95% bootstrap CI [-0.074, -0.015] over n=15 pairs.
- sign test: LLM wins 0, fallback wins 6, ties 9.
- CI excludes 0 -> LLM narration differs from the template at this N.
