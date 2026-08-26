# C6 — does F1 track parameter count on this task?

Same five fixtures, same `single`-arm prompt, same 2,400-token output budget.
One row per **model**, at the configuration that matches the local baseline where the
endpoint allows it. Matching is judged on the *measured* reasoning share, not on the flag
the harness requested — §3.32 records a provider that accepts the flag and ignores it.

| arm | model | total | active | mean F1 | n | reasoning | matched |
|---|---|---|---|---|---|---|---|
| qwen35ba3b | qwen3.6-35b-a3b | 35B | 3B | 0.3507 | 25 | 0.0% | yes |
| local | Qwen3.6-35B-A3B (IQ3_K_R4) | 35B | 3B | 0.4136 | 25 | 0.0% | yes |
| default | nvidia/nemotron-3-super-120b-a12b | 120B | 12B | 0.4149 | 25 | 56.2% | **no** |

Not used as series points — a second run of a model already represented above:

| arm | model | mean F1 | n | reasoning | why it is here |
|---|---|---|---|---|---|
| default | nvidia/nemotron-3-super-120b-a12b | 0.4162 | 25 | 56.5% | the same weights with reasoning left on |
| qwen35ba3b | qwen3.6-35b-a3b | 0.0080 | 25 | 99.5% | the same weights with reasoning left on |

**The series cannot be built. 2 arm(s) are configuration-matched, spanning 1 distinct parameter count(s); three of each are
needed before a rank correlation describes size rather than the arms that answered.**

The arms that would have completed the span are excluded, and by measurement:

* `nvidia/nemotron-3-super-120b-a12b` at 120B spent 56.2% of its output on reasoning against the local arm's 0.0% — `--no-thinking` was requested and the provider ignored it (§3.32).

This is the finding, not a gap in it. The parameter-size prior of
`arXiv:2606.18166` (rho=0.85) cannot be tested on the endpoints available here,
because the one axis that dominates the outcome — whether the model reasons
before answering — cannot be held constant across providers. A rho over these
arms anyway would be a reasoning-configuration effect reported as a size effect.
**P8 closes as a stated limitation, and the reason is now measured rather than
asserted.**
