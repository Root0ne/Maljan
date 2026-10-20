import { describe, expect, it } from "vitest";
import { patchStageAt, removeStageAt } from "@/app/(app)/settings/configuration/stageRename";
import { uidOf } from "@/app/(app)/settings/configuration/stageUids";
import type { StageEntry } from "@/types/settings";

const stage = (key: string, depends_on: string[] = []) => ({ key, depends_on }) as unknown as StageEntry;

describe("renaming a stage key (WA-L18)", () => {
  it("moves the dependents to the new key", () => {
    const out = patchStageAt([stage("a"), stage("b", ["a"]), stage("c", ["a", "b"])], 0, { key: "alpha" });
    expect(out.map((s) => s.key)).toEqual(["alpha", "b", "c"]);
    expect(out[1].depends_on).toEqual(["alpha"]);
    expect(out[2].depends_on).toEqual(["alpha", "b"]);
  });
  it("leaves dependencies alone when the key did not change", () => {
    const stages = [stage("a"), stage("b", ["a"])];
    const out = patchStageAt(stages, 0, { label: "x" } as Partial<StageEntry>);
    expect(out[1]).toBe(stages[1]);
  });
});

describe("stage card identity (WA-L18)", () => {
  it("gives each stage its own uid", () => {
    const [a, b] = [stage("a"), stage("b")];
    expect(uidOf(a)).not.toBe(uidOf(b));
    expect(uidOf(a)).toBe(uidOf(a));
  });
  it("survives a key edit, for the stage and for its dependents", () => {
    const stages = [stage("a"), stage("b", ["a"])];
    const before = stages.map(uidOf);
    const out = patchStageAt(stages, 0, { key: "alpha" });
    expect(out.map(uidOf)).toEqual(before);
  });
  it("survives a removal, for every stage that stays", () => {
    const stages = [stage("a"), stage("b", ["a"]), stage("c", ["b"])];
    const [ua, , uc] = stages.map(uidOf);
    const out = removeStageAt(stages, 1);
    expect(out.map(uidOf)).toEqual([ua, uc]);
  });
  it("survives a move, which reuses the objects", () => {
    const stages = [stage("a"), stage("b")];
    const [ua, ub] = stages.map(uidOf);
    const moved = [stages[1], stages[0]];
    expect(moved.map(uidOf)).toEqual([ub, ua]);
  });
});
