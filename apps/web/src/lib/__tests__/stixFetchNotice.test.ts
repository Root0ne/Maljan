import { describe, expect, it } from "vitest";
import { stixFetchNotice } from "@/components/analysis/stixGraph";

describe("failed STIX fetch (WB-L9)", () => {
  it("points at the stored copy only when there is one", () => {
    expect(stixFetchNotice("down", true)).toContain("Showing the stored copy");
  });
  it("says there is no bundle to show when there is no stored copy", () => {
    const text = stixFetchNotice("down", false);
    expect(text).toContain("down");
    expect(text).toMatch(/no bundle|nothing to show/i);
    expect(text).not.toContain("Showing the stored copy");
  });
});
