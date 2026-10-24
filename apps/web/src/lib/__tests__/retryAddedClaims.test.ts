import { describe, expect, it } from "vitest";
import { normalizeClaims, retryAddedLabel } from "@/lib/conversation";

describe("a claim a tool-less retry added", () => {
  it("keeps its round from the payload and says so", () => {
    const [added, own] = normalizeClaims([
      { claim: "x", confidence: 0.7, added_by_retry_in_round: 2 },
      { claim: "y", confidence: 0.8 },
    ]);
    expect(added.added_by_retry_in_round).toBe(2);
    expect(own.added_by_retry_in_round).toBeUndefined();
    expect(retryAddedLabel(2)).toBe("added by a tool-less retry, round 2");
  });

  it("reads no round that is not a whole number", () => {
    const [claim] = normalizeClaims([{ claim: "x", added_by_retry_in_round: "2" }]);
    expect(claim.added_by_retry_in_round).toBeUndefined();
  });
});
