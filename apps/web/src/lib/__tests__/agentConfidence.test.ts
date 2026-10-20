import { describe, expect, it } from "vitest";
import { CONFIDENCE_BAR_COLOR, confidencePercent } from "@/components/analysis/agentConfidence";

describe("agent confidence (WB-L6, WB-L8)", () => {
  it("is null when the finding states none", () => {
    expect(confidencePercent(undefined)).toBeNull();
    expect(confidencePercent(Number.NaN)).toBeNull();
    expect(confidencePercent(0)).toBe(0);
    expect(confidencePercent(0.876)).toBe(88);
  });
  it("the bar is not a threat colour", () => {
    expect(CONFIDENCE_BAR_COLOR).not.toMatch(/red|orange|green/);
  });
});
