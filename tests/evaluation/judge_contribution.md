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
