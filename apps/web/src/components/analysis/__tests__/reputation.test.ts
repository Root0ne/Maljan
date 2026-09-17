import { describe, expect, it } from "vitest";

import type { EvidenceEntry } from "@/types/evidence";
import { reputationFromEntry, reputationFromLedger } from "../reputation";

function entry(over: Partial<EvidenceEntry> = {}): EvidenceEntry {
  return {
    id: "1",
    entry_id: "ev_0002",
    stage: "triage",
    agent: "pipeline",
    server: "virustotal",
    tool: "get_file_report",
    ok: true,
    duration_ms: 420,
    seq: 2,
    args: { hash: "a".repeat(64) },
    output: "",
    structured: null,
    created_at: "2026-09-17T10:00:00Z",
    ...over,
  };
}

/** What VirusTotal's own server answers, nested the way its API nests it. */
const VT_ANSWER = {
  data: {
    id: "a".repeat(64),
    attributes: {
      last_analysis_stats: { malicious: 42, suspicious: 3, undetected: 20, harmless: 6 },
      popular_threat_classification: {
        suggested_threat_label: "trojan.formbook/injector",
        popular_threat_name: [{ value: "formbook", count: 30 }],
        popular_threat_category: [{ value: "trojan", count: 44 }],
      },
      first_submission_date: 1_600_000_000,
      last_analysis_date: 1_700_000_000,
      gui_url: "https://www.virustotal.com/gui/file/aaaa",
    },
  },
};

describe("a VirusTotal answer", () => {
  it("reads the engines, the detections, the labels, the dates and the link", () => {
    const reputation = reputationFromEntry(entry({ structured: VT_ANSWER }));
    expect(reputation).not.toBeNull();
    expect(reputation?.service).toBe("VirusTotal");
    expect(reputation?.engines).toBe(71);
    expect(reputation?.malicious).toBe(42);
    expect(reputation?.suspicious).toBe(3);
    expect(reputation?.labels).toEqual(["trojan.formbook/injector", "formbook", "trojan"]);
    expect(reputation?.firstSeen).toBe(new Date(1_600_000_000 * 1000).toISOString());
    expect(reputation?.lastSeen).toBe(new Date(1_700_000_000 * 1000).toISOString());
    expect(reputation?.link).toBe("https://www.virustotal.com/gui/file/aaaa");
    expect(reputation?.entryId).toBe("ev_0002");
  });

  it("links nowhere when the answer carried no link", () => {
    const structured = {
      data: { attributes: { last_analysis_stats: { malicious: 0, undetected: 70 } } },
    };
    expect(reputationFromEntry(entry({ structured }))?.link).toBeNull();
  });
});

describe("a threat-intel answer, which is a sentence", () => {
  const prose =
    "Hash aaa (sample.exe, Win32 EXE, 1024 bytes): malicious — 42/71 malicious, 3/71 suspicious.";

  it("is named after the service that gave it and keeps its words", () => {
    const reputation = reputationFromEntry(
      entry({ tool: "check_hash", server: "threatintel", output: prose }),
    );
    expect(reputation?.service).toBe("Threat intelligence");
    expect(reputation?.summary).toBe(prose);
  });

  it("lifts the counts out of the sentence so both services read alike", () => {
    const reputation = reputationFromEntry(
      entry({ tool: "check_hash", server: "threatintel", output: prose }),
    );
    expect(reputation?.engines).toBe(71);
    expect(reputation?.malicious).toBe(42);
    expect(reputation?.suspicious).toBe(3);
  });

  it("keeps a sentence that carries no counts at all", () => {
    const reputation = reputationFromEntry(
      entry({
        tool: "check_hash",
        server: "threatintel",
        output: "Hash aaa not found in VirusTotal database.",
      }),
    );
    expect(reputation?.engines).toBeNull();
    expect(reputation?.summary).toBe("Hash aaa not found in VirusTotal database.");
  });
});

describe("what is not a reputation finding", () => {
  it("ignores a call that failed", () => {
    expect(
      reputationFromEntry(entry({ ok: false, error: "not run: no reputation server" })),
    ).toBeNull();
  });

  it("ignores a call that returned nothing", () => {
    expect(reputationFromEntry(entry({ structured: null, output: "   " }))).toBeNull();
  });

  it("ignores an entry for any other tool", () => {
    expect(reputationFromEntry(entry({ tool: "capa", output: "two capabilities" }))).toBeNull();
  });

  it("ignores nothing at all", () => {
    expect(reputationFromEntry(null)).toBeNull();
  });
});

describe("reading one page of the ledger", () => {
  it("prefers VirusTotal's own answer when both services answered", () => {
    const entries = [
      entry({ tool: "check_hash", server: "threatintel", output: "10/70 malicious." }),
      entry({ entry_id: "ev_0009", structured: VT_ANSWER }),
    ];
    const reputation = reputationFromLedger(entries);
    expect(reputation?.service).toBe("VirusTotal");
    expect(reputation?.entryId).toBe("ev_0009");
  });

  it("answers nothing for a ledger that holds no lookup", () => {
    expect(reputationFromLedger([entry({ tool: "capa", output: "x" })])).toBeNull();
    expect(reputationFromLedger(null)).toBeNull();
  });
});
