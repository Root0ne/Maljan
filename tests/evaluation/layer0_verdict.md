# B3 + B4 — layer removal at the verdict, and what the integrity pass does

**Condition: `overlap`.** In `disjoint` each technique is claimed by exactly one
source, so **nothing is ever corroborated** and the arms only measure whether a lost
technique reaches the bundle. In `overlap` each technique is claimed by two sources —
alternating `yara`+`import_capability` (**distinct domains → corroborated**) and
`yara`+`tool_artifact` (**same domain → NOT corroborated even though two detectors**
**agreed**), which is what makes §1.10's structural finding demonstrable, not inferred.

**Read `no_yara_layer` as construction, not measurement.** yara appears in both pairs, so
removing it destroys all corroboration by arithmetic. The informative arms are
`no_import_capability_layer` (techniques survive via yara but **lose corroboration**) and
`no_tool_artifact_layer` (**predicted: no change at all** — its techniques are also
in yara and it contributed no corroboration to begin with).

- Input ISRs are **synthesised deterministically** from the fixture ground truth, so the
  only variable between arms is which Layer-0 source exists.
- Each source carries an **equal share** by construction. In production the rates are
  wildly uneven (§1.10: yara 89.5%, import-capability 52.6%, tool-artifact **2.4%**), so
  this measures the *mechanism*, not the real-world impact of removing a layer.
- `tool_artifact_layer` emits on **yara's** cascade domain, which is why §1.10 found it
  unable to add corroboration.

## B3 — does removing a layer change the verdict?

| arm removed | verdict changed | mean Jaccard vs `all` | 95% CI | n |
|---|---|---|---|---|
| `yara_layer` | **0/15** | 1.000 | [1.000, 1.000] | 15 |
| `import_capability_layer` | **0/15** | 1.000 | [1.000, 1.000] | 15 |
| `tool_artifact_layer` | **0/15** | 1.000 | [1.000, 1.000] | 15 |

## B4 — what the STIX integrity pass does on fresh bundles

- bundles generated: **60**
- integrity pass ran on: **60**
- pass **removed something** on: **3** (5.0%)
- objects removed in total: **3**

| removal reason | count |
|---|---|
| empty_pattern | 3 |
