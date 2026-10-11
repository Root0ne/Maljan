import { describe, expect, it } from "vitest";

import type { ReputationAnswer } from "@/types/malware-report";
import {
  carriesReputationRecords,
  reputationFromRecord,
  reputationFromReport,
} from "../reputation";

/** A record as the report carries it, from a server no built-in names. */
function answer(over: Partial<ReputationAnswer> = {}): ReputationAnswer {
  return {
    v: 1,
    entry_id: "ev_0003",
    tool: "lookup_digest",
    service: "HashRep",
    malicious: 9,
    total: 40,
    labels: ["Stealer", "Loader"],
    first_seen: "2023-11-14T22:13:20Z",
    last_seen: "2026-01-02T03:04:05Z",
    link: "https://rep.invalid/s/abc",
    summary: "",
    ...over,
  };
}

describe("a recorded reputation answer", () => {
  it("is drawn from the record alone, named by its declared service", () => {
    const reputation = reputationFromRecord(answer());
    expect(reputation).toEqual({
      service: "HashRep",
      entryId: "ev_0003",
      engines: 40,
      malicious: 9,
      suspicious: null,
      labels: ["Stealer", "Loader"],
      firstSeen: "2023-11-14T22:13:20Z",
      lastSeen: "2026-01-02T03:04:05Z",
      link: "https://rep.invalid/s/abc",
      summary: "",
    });
  });

  it("counts the engines the service gave when it gave no total", () => {
    expect(reputationFromRecord(answer({ total: null, engines: 75 }))?.engines).toBe(75);
  });

  it("keeps the service's words when there are no counts", () => {
    const reputation = reputationFromRecord(
      answer({ malicious: null, total: null, labels: [], summary: "hash not known" }),
    );
    expect(reputation?.engines).toBeNull();
    expect(reputation?.summary).toBe("hash not known");
  });

  it("draws nothing for a record that established nothing", () => {
    expect(
      reputationFromRecord(answer({ malicious: null, total: null, labels: [], summary: "" })),
    ).toBeNull();
    expect(reputationFromRecord(null)).toBeNull();
  });

  it("links nowhere when the link is not a web address", () => {
    expect(reputationFromRecord(answer({ link: "javascript:alert(1)" }))?.link).toBeNull();
  });
});

describe("a report", () => {
  it("is read by its records when it carries them, the first that says something", () => {
    const report = {
      reputation: [answer({ entry_id: "ev_0001", malicious: null, total: null, labels: [] }), answer()],
    };
    expect(carriesReputationRecords(report)).toBe(true);
    expect(reputationFromReport(report)?.entryId).toBe("ev_0003");
  });

  it("with an empty list draws nothing and is not read from its ledger", () => {
    expect(carriesReputationRecords({ reputation: [] })).toBe(true);
    expect(reputationFromReport({ reputation: [] })).toBeNull();
  });

  it("stored before the records is left to the legacy reader", () => {
    expect(carriesReputationRecords({})).toBe(false);
    expect(carriesReputationRecords({ reputation: null })).toBe(false);
    expect(carriesReputationRecords(null)).toBe(false);
  });
});
