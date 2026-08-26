# B5 (cheap half) — how often the confidence cap fires

The cap (`_cap_unsupported_confidence`) drops a claim to **0.40**, but only for
**T1027, T1140, T1055** and their sub-techniques, only when the sole contributing layer
is `static`, and only when the matching static evidence is
absent. §3.8 showed the incoming confidence is ~0.98 for essentially everything, so for
these techniques the cap is very nearly the **only** source of grading in the system.

Ablation is exact and server-free: `static=None` disables the cap by construction
(`_static_evidence_flags(None)` returns `(True, True)`), everything else identical.

| quantity | value |
|---|---|
| samples with evidence | 189 |
| techniques total | 1348 |
| gated techniques (T1027/T1140/T1055 + subs) | 306 (22.7% of all) |
| …of which sole-layer `static` (cap eligible) | 25 |
| **capped** | **11** |
| cap fire rate among gated | 3.6% |
| cap fire rate among eligible | 44.0% |
| **capped share of ALL techniques** | **0.82%** |
| samples where the cap fired at least once | 11 |

Caps per sample: {0: 178, 1: 11}
