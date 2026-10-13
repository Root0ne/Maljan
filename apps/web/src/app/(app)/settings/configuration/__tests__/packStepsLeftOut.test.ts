import { describe, expect, it } from "vitest";
import served from "@/test-fixtures/settings-schema.json";
import { PACK_STEPS_KEY, leftOutSteps } from "../packStepsLeftOut";

/**
 * A stored pack step the API leaves out does not run, and the shipped step it
 * changed runs instead. The schema names each one with why, and the mark
 * beside the steps lists them, so the console never shows a stored step as
 * in force when it is not.
 */
describe("leftOutSteps", () => {
  it("lists each step the schema names, with its reason, in the order served", () => {
    const said = leftOutSteps({
      lost: "triage step 'lost' references unknown mcp server 'nowhere'",
      "#2": "enabled: Input should be a valid boolean",
    });
    expect(said).toEqual([
      { step: "lost", reason: "triage step 'lost' references unknown mcp server 'nowhere'" },
      { step: "#2", reason: "enabled: Input should be a valid boolean" },
    ]);
  });

  it("lists nothing for a deployment with nothing stored", () => {
    expect(served.pack_steps_left_out).toEqual({});
    expect(leftOutSteps(served.pack_steps_left_out)).toEqual([]);
    expect(leftOutSteps(undefined)).toEqual([]);
  });

  it("keeps a step whose reason is not text, without inventing one", () => {
    expect(leftOutSteps({ odd: 3 })).toEqual([{ step: "odd", reason: "" }]);
  });

  it("belongs to the catalog's steps row", () => {
    const keys = served.groups.flatMap((group) => group.entries.map((entry) => entry.key));
    expect(keys).toContain(PACK_STEPS_KEY);
  });
});
