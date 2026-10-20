import { describe, expect, it } from "vitest";
import { normalizeClaims } from "@/lib/conversation";

describe("claim confidence (WB-L6)", () => {
  it("a claim with no confidence stays null, not 0", () => {
    const [a, b, c] = normalizeClaims([
      { claim: "x" },
      { claim: "y", confidence: 0 },
      { claim: "z", confidence: 0.8 },
    ]);
    expect(a.confidence).toBeNull();
    expect(b.confidence).toBe(0);
    expect(c.confidence).toBe(0.8);
  });
});
