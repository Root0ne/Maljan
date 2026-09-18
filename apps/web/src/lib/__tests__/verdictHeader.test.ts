import { describe, expect, it } from "vitest";
import {
  formatConfidence,
  verdictHeadline,
  verdictSeverityConflict,
} from "../verdictHeader";

describe("a verdict against the severity the same run assessed", () => {
  it("calls Malicious over Informational a disagreement", () => {
    expect(verdictSeverityConflict("Malware", "Informational")).toBe(true);
    expect(verdictSeverityConflict("Malicious", "Low")).toBe(true);
  });

  it("calls Benign over Critical a disagreement", () => {
    expect(verdictSeverityConflict("Benign", "Critical")).toBe(true);
  });

  it("leaves a rating one band out alone", () => {
    expect(verdictSeverityConflict("Malware", "Medium")).toBe(false);
    expect(verdictSeverityConflict("Suspicious", "High")).toBe(false);
    expect(verdictSeverityConflict("Benign", "Low")).toBe(false);
  });

  it("says nothing about a run with no severity or no verdict", () => {
    expect(verdictSeverityConflict("Malware", null)).toBe(false);
    expect(verdictSeverityConflict(null, "Critical")).toBe(false);
  });
});

describe("the header's verdict chip", () => {
  it("names both facts and whose they are when they disagree", () => {
    expect(verdictHeadline("Malware", 0.95, "Informational")).toEqual({
      text: "Judge: Malicious 0.95 · Severity: Informational",
      conflict: true,
    });
  });

  it("is the verdict and its confidence when they agree", () => {
    expect(verdictHeadline("Malware", 0.92, "High")).toEqual({
      text: "Malicious · Confidence: 0.92",
      conflict: false,
    });
  });

  it("says a fallback verdict was never assessed rather than scoring it zero", () => {
    expect(formatConfidence(null)).toBe("not assessed");
    expect(verdictHeadline("Suspicious", null, null).text).toBe(
      "Suspicious · Confidence: not assessed",
    );
    expect(formatConfidence(0)).toBe("0.00");
  });
});
