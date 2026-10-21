import { describe, expect, it } from "vitest";

import {
  detectionsFigure,
  endpointReputation,
  reputationFromRecord,
  verdictWords,
} from "../reputation";

describe("the detections figure", () => {
  it("says a malicious count the answer did not give as missing, not as zero", () => {
    const rep = reputationFromRecord({ v: 1, entry_id: "ev_0001", engines: 70 });
    expect(rep).not.toBeNull();
    expect(detectionsFigure(rep!)).toEqual({ count: "not counted", known: false });
  });

  it("prints a count the answer gave, a zero included", () => {
    expect(detectionsFigure({ malicious: 0, engines: 70 })).toEqual({ count: "0", known: true });
    expect(detectionsFigure({ malicious: 12, engines: 70 })).toEqual({ count: "12", known: true });
  });
});

describe("an endpoint's enrichment badge", () => {
  it("names each figure by its field, with no verdict of its own", () => {
    expect(endpointReputation({ source: "virustotal", malicious: 0, suspicious: 3 })).toEqual({
      source: "virustotal",
      figure: "malicious 0 · suspicious 3",
      verdict: null,
    });
    expect(endpointReputation({ source: "abuseipdb", abuse_confidence: 50 })).toEqual({
      source: "abuseipdb",
      figure: "abuse 50",
      verdict: null,
    });
  });

  it("reads the verdict the source declared: true, false, absent", () => {
    const base = { source: "virustotal", malicious: 4 };
    expect(endpointReputation({ ...base, malicious_verdict: true })?.verdict).toBe(true);
    expect(endpointReputation({ ...base, malicious_verdict: false })?.verdict).toBe(false);
    expect(endpointReputation(base)?.verdict).toBeNull();
    expect(endpointReputation({ ...base, malicious_verdict: "yes" })?.verdict).toBeNull();
    expect(endpointReputation({ ...base, malicious_verdict: true })?.figure).toBe("malicious 4");
  });

  it("names the source alone when the record carries no figure", () => {
    expect(endpointReputation({ country: "NL" })).toEqual({
      source: "intel",
      figure: null,
      verdict: null,
    });
    expect(endpointReputation(null)).toBeNull();
  });
});

describe("the words the badge adds for a declared verdict", () => {
  it("says what the source's rule established, and no more", () => {
    expect(verdictWords(true)).toEqual({ text: "malicious by source rule", tone: "red" });
    expect(verdictWords(false)).toEqual({ text: "below source threshold", tone: "muted" });
    expect(verdictWords(false)?.text).not.toMatch(/clean|benign/i);
  });

  it("adds nothing when the record carries no verdict", () => {
    expect(verdictWords(null)).toBeNull();
    expect(verdictWords(undefined)).toBeNull();
    const badge = endpointReputation({ source: "virustotal", malicious: 4 });
    expect(verdictWords(badge?.verdict)).toBeNull();
  });
});
