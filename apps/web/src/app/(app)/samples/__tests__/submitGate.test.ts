import { describe, expect, it } from "vitest";
import { advancedChoices, canStartAnalysis } from "../submitGate";

describe("canStartAnalysis (WA-L10)", () => {
  it("is blocked while a report uploads or a start is in flight", () => {
    expect(canStartAnalysis({ submitting: false, reportUploading: true })).toBe(false);
    expect(canStartAnalysis({ submitting: true, reportUploading: false })).toBe(false);
  });
  it("is open otherwise", () => {
    expect(canStartAnalysis({ submitting: false, reportUploading: false })).toBe(true);
  });
});

describe("advancedChoices", () => {
  const none = { staticProvider: "", sandboxProvider: "", profile: "", questions: [], attachedReport: false };

  it("counts nothing for a run with the settings' defaults", () => {
    expect(advancedChoices(none)).toBe(0);
  });
  it("counts each choice that differs from the defaults", () => {
    expect(advancedChoices({ ...none, staticProvider: "capa_yara", profile: "lean", questions: ["What is the C2?"] })).toBe(3);
  });
  it("counts an attached report once, not again as a sandbox choice", () => {
    expect(advancedChoices({ ...none, sandboxProvider: "triage", attachedReport: true })).toBe(1);
  });
});
