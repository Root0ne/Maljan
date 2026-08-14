# C3 — what the judge contributes to the bundle

4 judge calls, one per fixture, recorded at the seam where the judge's own output ends
and the deterministic cascade set begins (`_reconcile_with_cascade`).

| | total | per call |
|---|---|---|
| attack-patterns the judge emitted | 50 | 12.5 |
| of those, carrying a resolvable ATT&CK id | 12 | 3.0 |
| **dropped — the model named no technique** | **38** (76.0%) | 9.5 |
| techniques the cascade held | 99 | 24.8 |
| judge ids the cascade already held | 12 | 3.0 |
| **judge ids the cascade did not hold** | **0** | 0.0 |
| injected because the judge omitted them | 87 | 21.8 |
| final bundle | 99 | 24.8 |

**Share of the final bundle the judge is responsible for: 0.0%** (0 of 99 techniques), contributed on 0 of 4 calls.

**The bound becomes a description.** Not one technique in any bundle is there because
the judge named it. Every technique the analyst receives was already in the cascade's
set, and on 3 of 4 calls the judge produced nothing
nameable at all. The verdict model's influence over the ATT&CK content of its own
verdict is zero — not small, not diluted: zero.

**76.0% of the judge's own attack-patterns were discarded for
naming no technique.** That is the model asserting a behaviour it cannot map — the
failure the reconciliation step was written to paper over, measured here rather than
inferred from its log line.

## Did the judge's output reach the cascade seam at all?

`give_verdict` returns `_fallback_bundle_from_text` from four places — the verdict
timeout, both JSON gates, and the post-processing `except`. None of them call
`postprocess_judge_bundle`, so on those calls `_reconcile_with_cascade` never runs and
the cascade's technique set is **never injected**. This is not the same failure as a bad
verdict: it is a different bundle-construction path, and §3.27.1's equality was measured
only on the calls that avoided it.

| reached reconciliation | 4/8 |
|---|---|
| fell back before reconciliation | **4/8** |

| fallback branch | calls |
|---|---|
| `no_json_in_response` | 4 |

**50% of judge calls never reached the reconciliation step.** On those the
cascade contributed nothing to the bundle, because the code that injects it was not
the path taken. Any claim about what the bundle contains has to say which path it is
about.
