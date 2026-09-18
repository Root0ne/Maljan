import { describe, expect, it } from "vitest";
import {
  formatConfidence,
  verdictHeadline,
  verdictSeverityConflict,
} from "../verdictHeader";

describe("a verdict against the severity the same run assessed", () => {
  it("calls Malicious over Informational a disagreement", () => {
    expect(verdictSeverityConflict("Malware", "Informational")).toBe(true);
    expect(verdictSeverityConflict("Malicious", "Informational")).toBe(true);
  });

  it("calls a malicious verdict the judge assessed no severity for a disagreement", () => {
    expect(verdictSeverityConflict("Malware", null)).toBe(true);
  });

  /* A run with no structured report has no severity block to disagree with,
   * which is not the same as a judge that assessed none into one. */
  it("stays quiet while there is no report to carry a severity", () => {
    expect(verdictSeverityConflict("Malware", undefined)).toBe(false);
    expect(verdictSeverityConflict("Benign", undefined)).toBe(false);
  });

  it("calls Benign over High or Critical a disagreement", () => {
    expect(verdictSeverityConflict("Benign", "Critical")).toBe(true);
    expect(verdictSeverityConflict("Benign", "High")).toBe(true);
    expect(verdictSeverityConflict("Clean", "Critical")).toBe(true);
  });

  /* Adware, unwanted programs and riskware are a Malicious verdict at Low
   * severity on a report that is not contradicting itself at all. Telling that
   * reader not to trust either number is a false alarm on a coherent run. */
  it("leaves Malicious over Low alone", () => {
    expect(verdictSeverityConflict("Malware", "Low")).toBe(false);
    expect(verdictSeverityConflict("Malware", "Medium")).toBe(false);
    expect(verdictSeverityConflict("Malware", "Critical")).toBe(false);
  });

  it("leaves Benign over the low end and Suspicious over everything alone", () => {
    expect(verdictSeverityConflict("Benign", "Low")).toBe(false);
    expect(verdictSeverityConflict("Benign", "Medium")).toBe(false);
    expect(verdictSeverityConflict("Benign", null)).toBe(false);
    for (const rating of ["Informational", "Low", "Medium", "High", "Critical"] as const) {
      expect(verdictSeverityConflict("Suspicious", rating)).toBe(false);
    }
  });

  it("says nothing about a verdict it does not recognise", () => {
    expect(verdictSeverityConflict(null, "Critical")).toBe(false);
    expect(verdictSeverityConflict("indeterminate", "Informational")).toBe(false);
  });
});

describe("the header's verdict chip", () => {
  it("names both facts and whose they are when they disagree", () => {
    expect(verdictHeadline("Malware", 0.95, "Informational")).toEqual({
      text: "Judge: Malicious 0.95 · Severity: Informational",
      conflict: true,
    });
  });

  it("labels the confidence where the number is a phrase", () => {
    expect(verdictHeadline("Malware", null, "Informational").text).toBe(
      "Judge: Malicious · Confidence: not assessed · Severity: Informational",
    );
  });

  it("names a missing severity rather than leaving a gap", () => {
    expect(verdictHeadline("Malware", 0.8, null).text).toBe(
      "Judge: Malicious 0.80 · Severity: not assessed",
    );
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
