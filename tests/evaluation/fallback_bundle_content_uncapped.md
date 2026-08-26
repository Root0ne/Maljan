# Does a failed verdict change what the analyst receives?

4 calls that fell back before reconciliation, compared against the cascade set each
would have been given had it completed. Deterministic: no model was called.

| fixture | fallback | cascade | shared | only in fallback | only in cascade | Jaccard |
|---|---|---|---|---|---|---|
| `jhuhugit` | 20 | 20 | 20 | 0 | 0 | 1.000 |
| `sardonic` | 25 | 25 | 25 | 0 | 0 | 1.000 |
| `sliver` | 23 | 23 | 23 | 0 | 0 | 1.000 |
| `wannacry` | 16 | 16 | 16 | 0 | 0 | 1.000 |

**Identical on 4 of 4 — and this is arithmetic, not a measurement.** Say
so first, because a Jaccard of 1.000 is exactly what this project has twice
written up as a finding before discovering it could not have come out otherwise.

`TTPCascadeEngine.compute` appends a `CascadeResult` for **every** technique id
any source claimed — there is no membership threshold; the weights set
`weighted_confidence` and nothing else. `_fallback_bundle_from_text` scrapes ids
from those same ISR claims with a `T\d{4}` regex. Two routes to *the set of
claimed technique ids*, so equality is the only possible result under this
harness's configuration, and the table confirms the configuration rather than
discovering the equality.

**What it is still worth having.** The two paths are *not* equal in general, and
the conditions under which they diverge are in the cascade and absent here:

* `sample_platform` — the cascade drops claims whose rule declared an
  incompatible platform; the fallback regex keeps them. Here it is `None`.
* `empty_domains` — the cascade drops claims from a domain that produced no
  input, so an absent sandbox cannot count as corroboration; the fallback has no
  such notion. Not exercised here.
* the placeholder denylist (`T0000`, `T9999`, `T1234`) — rejected by the
  cascade, matched by the regex. None appear in these fixtures.

So on a real sample where the sandbox is empty or a rule is platform-gated —
the ordinary case — a timed-out verdict would hand the analyst techniques the
cascade would have dropped, with nothing in the bundle recording which path
built it. That is the claim this study supports: not that the paths agree, but
that **nothing makes them agree**, and here every filter that would have
separated them was inactive.

Across all 4 calls: **0** techniques appear only on the fallback path and
**0** only on the reconciled one.
