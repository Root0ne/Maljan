import { describe, expect, it } from "vitest";
import { canStartAnalysis } from "../submitGate";

describe("canStartAnalysis (WA-L10)", () => {
  it("is blocked while a report uploads or a start is in flight", () => {
    expect(canStartAnalysis({ submitting: false, reportUploading: true })).toBe(false);
    expect(canStartAnalysis({ submitting: true, reportUploading: false })).toBe(false);
  });
  it("is open otherwise", () => {
    expect(canStartAnalysis({ submitting: false, reportUploading: false })).toBe(true);
  });
});
