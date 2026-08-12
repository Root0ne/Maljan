# Narrative-quality evaluation (LLM vs deterministic fallback)

- Faithfulness-centric metrics (no human reference prose vendored): grounding
  precision = cited techniques present in the evidence; coverage recall = evidence
  techniques surfaced; structural = schema/length/parenthesised-ID compliance;
  fp_linter clean = no C2 (recommendation cites absent technique) / C3 (exec-summary
  platform mismatch). F1 = harmonic mean of precision and recall.
- Samples generated 3x each for N>>1 (decoding variance -> bootstrap CI).

## LLM narrative

_no samples_

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

_no paired samples_
