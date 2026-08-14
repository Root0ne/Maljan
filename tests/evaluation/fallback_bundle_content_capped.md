# Does a failed verdict change what the analyst receives?

4 calls that fell back before reconciliation, compared against the cascade set each
would have been given had it completed. Deterministic: no model was called.

| fixture | fallback | cascade | shared | only in fallback | only in cascade | Jaccard |
|---|---|---|---|---|---|---|
| `jhuhugit` | 32 | 20 | 20 | 12 | 0 | 0.625 |
| `sardonic` | 27 | 25 | 25 | 2 | 0 | 0.926 |
| `sliver` | 46 | 23 | 23 | 23 | 0 | 0.500 |
| `wannacry` | 26 | 16 | 16 | 10 | 0 | 0.615 |

**The sets differ on 4 of 4 calls.** A failed verdict does not
merely cost the narrative — it changes which techniques reach the analyst, and
neither the report nor the bundle records which construction path produced it.

`_fallback_bundle_from_text` scrapes ATT&CK ids from **two** places: the ISR
claims, and the model's own raw response. When the response is unparseable that
second source is a degenerate decode, and every id in it enters the bundle
without passing the cascade, the reconciliation step, the invalid-id filter or
the integrity pass. Nothing downstream can tell those ids from corroborated
ones.

Across all 4 calls: **47** techniques appear only on the fallback path and
**0** only on the reconciled one.
