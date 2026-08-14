# B3 + B4 — layer removal at the verdict, and what the integrity pass does

**Condition: `overlap`.** In `disjoint` each technique is claimed by exactly one
source, so **nothing is ever corroborated** and the arms only measure whether a lost
technique reaches the bundle. In `overlap` each technique is claimed by two sources,
rotating `yara`+`import_capability` (**distinct domains → corroborated**),
`yara`+`tool_artifact` (**same domain → NOT corroborated even though two detectors**
**agreed**), and `sigma`+`import_capability` (**corroborated without yara**). The second
pair is what makes §1.10's structural finding demonstrable, not inferred; the third is
what makes `no_yara_layer` a measurement rather than an arithmetic certainty.

**Every arm here is informative, which was not true of the earlier design.** With only
the first two pairs, yara appeared in both, so removing it destroyed all corroboration by
construction and that arm proved nothing. The yara-free pair leaves the sigma+static
corroborations standing, so `no_yara_layer` and `no_sigma_layer` now mirror each other.
`no_tool_artifact_layer` remains the sharpest test: **predicted no change at all**, since
its techniques are also in yara and it contributed no corroboration to begin with.

- Input ISRs are **synthesised deterministically** from the fixture ground truth, so the
  only variable between arms is which Layer-0 source exists.
- Each source carries an **equal share** by construction. In production the rates are
  wildly uneven (§1.10: yara 89.5%, import-capability 52.6%, tool-artifact **2.4%**), so
  this measures the *mechanism*, not the real-world impact of removing a layer.
- `tool_artifact_layer` emits on **yara's** cascade domain, which is why §1.10 found it
  unable to add corroboration.
- **Two Layer-0 sources are excluded, by measurement rather than by choice.** Over the 43
  archived reports `lolbin` and `network_dga` each produce a claim on **0/43** — while
  being fed a median of 3356 API calls and 49-63 domains respectively (§3.23). Handing
  either an equal share would ablate a mechanism that never engages in this deployment.
- Fixtures carry **≥12 techniques** so every source holds ≥3 claims. The
  five-technique fixtures used elsewhere assign the last of six sources **zero**, which
  is how the six-source run produced a null it obtained by arithmetic.

## B3 — does removing a layer change the verdict?

| arm removed | verdict changed | mean Jaccard vs `all` | 95% CI | n |
|---|---|---|---|---|
| `yara_layer` | **0/8** | 1.000 | [1.000, 1.000] | 8 |
| `import_capability_layer` | **0/8** | 1.000 | [1.000, 1.000] | 8 |
| `tool_artifact_layer` | **0/8** | 1.000 | [1.000, 1.000] | 8 |
| `sigma_layer` | **0/8** | 1.000 | [1.000, 1.000] | 8 |

## B4 — what the STIX integrity pass does on fresh bundles

- bundles generated: **40**
- integrity pass ran on: **19**
- pass **removed something** on: **6** (15.0%)
- objects removed in total: **22**

| removal reason | count |
|---|---|
| dangling_relationship | 3 |
| duplicate_attack_pattern | 8 |
| duplicate_relationship | 1 |
| empty_pattern | 10 |
