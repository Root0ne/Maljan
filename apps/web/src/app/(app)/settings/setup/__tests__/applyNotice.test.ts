import { describe, expect, it } from "vitest";

import { applyNotice } from "../applyNotice";

describe("a guide's Apply that saved nothing", () => {
  it("says the action error the console's toolbar would have said", () => {
    expect(applyNotice("core.x was changed since this page loaded it, so nothing was saved.", {})).toBe(
      "core.x was changed since this page loaded it, so nothing was saved.",
    );
  });

  it("says how many values were refused when the refusal is per field", () => {
    expect(applyNotice(null, { "core.a": "too large" })).toMatch(/one value was refused/);
    expect(applyNotice(null, { "core.a": "x", "core.b": "y" })).toMatch(/2 values were refused/);
  });

  it("says nothing for an Apply cancelled at the password prompt", () => {
    expect(applyNotice(null, {})).toBeNull();
    expect(applyNotice(undefined, undefined)).toBeNull();
  });
});
