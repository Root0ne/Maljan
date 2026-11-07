import { describe, expect, it } from "vitest";
import { PREVIOUS_NAME_FORMAT_PREFIX, underCurrentName } from "../previousName";

/** A format an earlier release wrote reads as the same version under the current name. */
describe("underCurrentName", () => {
  it("reads a previous-name format as the same version", () => {
    expect(underCurrentName(`${PREVIOUS_NAME_FORMAT_PREFIX}settings/3`)).toBe("malspark-settings/3");
    expect(underCurrentName(`${PREVIOUS_NAME_FORMAT_PREFIX}evidence-bundle/1`)).toBe(
      "malspark-evidence-bundle/1"
    );
  });

  it("returns anything else as it is", () => {
    for (const value of ["malspark-settings/3", "other/1", "", null, undefined, 3]) {
      expect(underCurrentName(value)).toBe(value);
    }
  });
});
