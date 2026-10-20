import type { StageEntry } from "@/types/settings";
import { carryUid } from "./stageUids";

/**
 * The stage list after stage `index` took the patch `next`. A change of key is
 * followed through: every stage that depended on the old key now depends on
 * the new one, so renaming a stage does not leave its dependents pointing at
 * a name that no longer exists.
 */
export function patchStageAt(stages: StageEntry[], index: number, next: Partial<StageEntry>): StageEntry[] {
  const before = stages[index];
  const out = [...stages];
  out[index] = carryUid(before, { ...before, ...next });
  const renamed = next.key !== undefined && next.key !== before.key;
  if (!renamed) return out;
  return out.map((stage, i) =>
    i === index || !stage.depends_on.includes(before.key)
      ? stage
      : carryUid(stage, {
          ...stage,
          depends_on: stage.depends_on.map((d) => (d === before.key ? next.key! : d)),
        }),
  );
}

/** The stage list without stage `index`; the others stay the same stages and
 *  stop depending on it. */
export function removeStageAt(stages: StageEntry[], index: number): StageEntry[] {
  const gone = stages[index].key;
  return stages
    .filter((_, i) => i !== index)
    .map((stage) => carryUid(stage, { ...stage, depends_on: stage.depends_on.filter((d) => d !== gone) }));
}
