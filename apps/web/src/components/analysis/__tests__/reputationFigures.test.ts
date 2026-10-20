import { describe, expect, it } from "vitest";

import { detectionsFigure, endpointReputation, reputationFromRecord } from "../reputation";

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
    });
    expect(endpointReputation({ source: "abuseipdb", abuse_confidence: 50 })).toEqual({
      source: "abuseipdb",
      figure: "abuse 50",
    });
  });

  it("names the source alone when the record carries no figure", () => {
    expect(endpointReputation({ country: "NL" })).toEqual({ source: "intel", figure: null });
    expect(endpointReputation(null)).toBeNull();
  });
});
