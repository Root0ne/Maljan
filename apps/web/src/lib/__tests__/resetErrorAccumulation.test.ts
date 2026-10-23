import { describe, expect, it } from "vitest";
import { mergeResetError } from "@/app/(app)/settings/configuration/useSettings";

describe("reset failures accumulate (WA-L3)", () => {
  it("a single reset keeps its plain message", () => {
    expect(mergeResetError(null, "k", "boom", false)).toBe("boom");
  });
  it("a loop of resets keeps every failure, named by key", () => {
    const first = mergeResetError(null, "a.b", "boom", true);
    const second = mergeResetError(first, "c.d", "nope", true);
    expect(second).toContain("a.b: boom");
    expect(second).toContain("c.d: nope");
  });
});
