/**
 * What the new analysis page reads off a stored report.
 *
 * Read against the same complete report the end-to-end suite draws
 * (`e2e/report-fixture.ts`), plus the edge each rule exists for: a count the
 * report does not hold, a severity it does not state, a complete run that
 * must draw no remark, and a header that must never say more than five
 * classifications at once.
 */

import { runInNewContext } from "node:vm";
import { describe, expect, it } from "vitest";

import { COMPLETED_JOB, MALWARE_REPORT, REPORT } from "../../../../e2e/report-fixture";
import type { JobDTO } from "@/lib/api";
import { gaugeDash } from "@/components/analysis/ConfidenceGauge";
import { resolveTheme } from "@/components/analysis/theme";
import { THEME_BOOT_SCRIPT, THEME_STORAGE_KEY } from "@/components/analysis/themeScript";
import {
  CONFIDENCE_WHY,
  ANALYSIS_TABS,
  RUNNING_TABS,
  analysisHref,
  anchorFromHash,
  REMARK_TEXT,
  capChips,
  classificationChips,
  configText,
  exportBaseName,
  filesWritten,
  findingRows,
  kpis,
  otherHashes,
  remarks,
  sortedRecommendations,
  tabCounts,
  verdictConfidence,
  VOICE_TEXT,
  proseText,
  publishedNetworkIndicators,
  splitCitations,
  techniqueVoice,
} from "@/components/analysis/overview";
import type { MalwareReport } from "@/types/malware-report";

describe("the tabs", () => {
  it("are the six of the new layout, each its own URL", () => {
    expect(ANALYSIS_TABS.map((t) => t.label)).toEqual([
      "Overview",
      "Behaviour",
      "Network",
      "Static & code",
      "Indicators & detection",
      "Evidence",
    ]);
    expect(analysisHref("job 1", "overview")).toBe("/analysis/job%201");
    expect(analysisHref("j", "network")).toBe("/analysis/j/network");
    expect(analysisHref("j", "behaviour", "persistence")).toBe("/analysis/j/behaviour#persistence");
    expect(analysisHref("j", "indicators")).toBe("/analysis/j/indicators");
  });

  it("count what each will hold, and say nothing without a report", () => {
    expect(tabCounts(MALWARE_REPORT)).toEqual({
      overview: null,
      behaviour: 2,
      network: 3,
      static: 3,
      indicators: 3,
      evidence: 4,
    });
    expect(tabCounts(null).network).toBeNull();
  });

  it("read the block a link names from its fragment, and skip one that does not decode", () => {
    expect(anchorFromHash("#persistence")).toBe("persistence");
    expect(anchorFromHash("#a%20b")).toBe("a b");
    expect(anchorFromHash("")).toBeNull();
    expect(anchorFromHash("#")).toBeNull();
    expect(anchorFromHash(null)).toBeNull();
    expect(anchorFromHash("#%E0%A4%A")).toBeNull();
  });

  it("offer only Overview and Evidence while the analysis runs", () => {
    expect(ANALYSIS_TABS.filter((t) => RUNNING_TABS.has(t.key)).map((t) => t.key)).toEqual([
      "overview",
      "evidence",
    ]);
  });
});

describe("the confidence ring", () => {
  it("shows the stored confidence as it is, never a derived score", () => {
    expect(verdictConfidence("Malware", 0.91)).toEqual({
      percent: 91,
      verdict: "Malicious",
      label: "Malicious, confidence 91 percent",
    });
    // A benign verdict held with high confidence reads high, not low.
    expect(verdictConfidence("Benign", 0.97).percent).toBe(97);
    expect(verdictConfidence("Suspicious", 1.4).percent).toBe(100);
    expect(CONFIDENCE_WHY).toBe("How sure the analysis is of this verdict");
  });

  it("is absent, never zero, without a confidence", () => {
    expect(verdictConfidence("Malware", null)).toEqual({
      percent: null,
      verdict: "Malicious",
      label: "Malicious, confidence not assessed",
    });
    expect(verdictConfidence("", 0.5).label).toBe("No verdict, confidence 50 percent");
    expect(gaugeDash(null).startsWith("0.00 ")).toBe(true);
    expect(gaugeDash(100).split(" ")[0]).toBe(gaugeDash(100).split(" ")[1]);
  });
});

describe("the header", () => {
  it("classifies by category, tactic and platform, once each", () => {
    expect(classificationChips(MALWARE_REPORT)).toEqual(["trojan", "Defense Evasion", "Windows"]);
  });

  it("shows at most five chips and counts the rest", () => {
    expect(capChips(["a", "b", "c", "d", "e", "f", "g"])).toEqual({ shown: ["a", "b", "c", "d", "e"], more: 2 });
    expect(capChips(["a"])).toEqual({ shown: ["a"], more: 0 });
  });

  it("puts the other hashes behind the expander, skipping the empty ones", () => {
    expect(otherHashes(MALWARE_REPORT).map((h) => h.label)).toEqual(["MD5", "SHA-1", "Import hash"]);
  });

  it("names downloads after the sample's hash", () => {
    // Twelve characters of the hash, as the downloads were always named.
    expect(exportBaseName(MALWARE_REPORT.identity.hashes.sha256, "j")).toBe("maljan-9f86d081884c");
    expect(exportBaseName(null, "11111111-2222-3333")).toBe("maljan-111111112222");
  });
});

describe("the remarks", () => {
  it("are absent on a complete run", () => {
    expect(remarks(REPORT)).toEqual([]);
  });

  it("say a generic sentence each, keeping the stored reason only as detail", () => {
    const degraded = {
      ...REPORT,
      incomplete_reason: "report stage failed",
      malware_report: {
        ...MALWARE_REPORT,
        run_summary: {
          ...MALWARE_REPORT.run_summary,
          failed_analysts: ["dynamic", "network"],
          degradation_reasons: ["dynamic: sandbox unreachable"],
        },
      },
    };
    const lines = remarks(degraded);
    expect(lines).toEqual([
      { text: REMARK_TEXT.incomplete, detail: "report stage failed" },
      { text: REMARK_TEXT.stageFailed, detail: "dynamic, network" },
      { text: REMARK_TEXT.degraded, detail: "dynamic: sandbox unreachable" },
    ]);
    expect(lines.map((l) => l.text).join(" ")).not.toMatch(/dynamic|network|analyst|sandbox|stage failed/);
  });

  it("say degraded once even when no reason was stored", () => {
    const bare = {
      ...REPORT,
      malware_report: { ...MALWARE_REPORT, run_summary: { ...MALWARE_REPORT.run_summary, degraded_mode: true } },
    };
    expect(remarks(bare)).toEqual([{ text: REMARK_TEXT.degraded, detail: null }]);
  });

  it("say a verdict that disagrees with its severity, or was inferred, in plain words", () => {
    const disagreeing = {
      ...REPORT,
      malware_report: {
        ...MALWARE_REPORT,
        severity: { ...MALWARE_REPORT.severity!, rating: "Informational" as const },
      },
    };
    expect(remarks(disagreeing)).toEqual([{ text: REMARK_TEXT.conflict, detail: null }]);
    expect(remarks({ ...REPORT, verdict_reading: "fallback" })).toEqual([
      { text: REMARK_TEXT.inferred, detail: null },
    ]);
    expect(remarks({ ...REPORT, verdict_reading: "stated" })).toEqual([]);
    for (const line of [REMARK_TEXT.conflict, REMARK_TEXT.inferred]) expect(line).not.toMatch(/judge|pipeline/i);
  });

  it("say a stopped run once, with the job's own words as detail", () => {
    const job = { ...COMPLETED_JOB, status: "cancelled", error_message: "Cancelled by the operator" } as unknown as JobDTO;
    expect(remarks(null, job)).toEqual([{ text: REMARK_TEXT.stopped, detail: "Cancelled by the operator" }]);
    // A kept report that already says the same thing is not told twice.
    expect(remarks({ ...REPORT, incomplete_reason: "Cancelled by the operator" }, job)).toEqual([
      { text: REMARK_TEXT.incomplete, detail: "Cancelled by the operator" },
    ]);
  });
});

describe("the overview", () => {
  it("counts each kind of evidence, and leaves a count the report lacks unmeasured", () => {
    const byKey = Object.fromEntries(kpis(MALWARE_REPORT).map((k) => [k.key, k.value]));
    // The fixture's only network indicator is a resolver it holds back.
    expect(byKey).toEqual({ signatures: 1, techniques: 1, iocs: 2, network: 0, files: 0, rules: 1 });
    const bare = {
      ...MALWARE_REPORT,
      dynamic: null,
      network: null,
      consolidated_iocs: undefined,
      ttp_mappings: undefined,
      capability_matrix: undefined,
      detection_signatures: undefined,
    } as unknown as MalwareReport;
    expect(Object.fromEntries(kpis(bare).map((k) => [k.key, k.value]))).toEqual({
      signatures: null,
      techniques: null,
      iocs: null,
      network: null,
      files: null,
      rules: null,
    });
    expect(kpis(MALWARE_REPORT).find((k) => k.key === "files")?.label).toBe("Files written");
  });

  it("counts each file written once, and only operations that write a named file", () => {
    const withOps = (file_operations: Record<string, unknown>[]) =>
      ({ ...MALWARE_REPORT, dynamic: { ...MALWARE_REPORT.dynamic!, file_operations } }) as MalwareReport;
    expect(
      filesWritten(
        withOps([
          { operation: "write", path: "C:\\Users\\Public\\svc.exe" },
          { operation: "create", path: "c:\\users\\public\\SVC.exe" },
          { op: "drop", file: "C:\\Temp\\a.dll" },
          { operation: "read", path: "C:\\Windows\\win.ini" },
          { operation: "write" },
        ]),
      ),
    ).toBe(2);
    expect(filesWritten(withOps([]))).toBe(0);
    expect(filesWritten({ ...MALWARE_REPORT, dynamic: null } as MalwareReport)).toBeNull();
  });

  it("lists signatures and techniques, rated first, a technique unrated rather than guessed", () => {
    const scaled = {
      ...MALWARE_REPORT,
      run_summary: {
        ...MALWARE_REPORT.run_summary,
        sandbox_signature_scale: {
          name: "test",
          max: 10,
          rungs: ["Informational", "Informational", "Low", "Low", "Medium", "Medium", "High", "High", "Critical", "Critical"],
        },
      },
    } as MalwareReport;
    const rows = findingRows(scaled);
    // The fixture's technique states no basis: "Not stated", although a
    // dynamic layer contributed to it.
    expect(rows.map((r) => [r.severity, r.category, r.title, r.voice])).toEqual([
      ["High", "Behaviour", "Writes into another process's address space", "observed"],
      [null, "Defense Evasion", "Process Injection", "unstated"],
    ]);
    expect(VOICE_TEXT.unstated).toBe("Not stated");
    expect(rows[1].details).toEqual(["Imports VirtualAllocEx and WriteProcessMemory", "WriteProcessMemory into pid 640"]);
    // Off a known scale, a signature's number has no rung either.
    expect(findingRows(MALWARE_REPORT)[0].severity).toBeNull();
  });

  it("reads how a technique is known from the report's basis, never from who named it", () => {
    const withRow = (over: Partial<MalwareReport["ttp_mappings"][number]>, cell: Partial<MalwareReport["capability_matrix"][number]> = {}) =>
      findingRows({
        ...MALWARE_REPORT,
        dynamic: null,
        // A dynamic analyst contributed to every row below.
        ttp_mappings: [{ ...MALWARE_REPORT.ttp_mappings[0], contributing_layers: ["dynamic", "static"], ...over }],
        capability_matrix: [{ ...MALWARE_REPORT.capability_matrix[0], contributing_layers: ["dynamic"], ...cell }],
      } as MalwareReport)[0].voice;
    // Assessed only: a code source, no run source, a dynamic layer all the same.
    expect(withRow({ source_kinds: { code: 2, artefact: 1 } })).toBe("code");
    expect(withRow({ source_kinds: { run: 1, code: 1 } })).toBe("observed");
    expect(withRow({ source_kinds: { rule: 1 } })).toBe("rule");
    expect(withRow({ support: "capability", source_kinds: { artefact: 2 } })).toBe("capability");
    expect(withRow({ support: "unobserved", source_kinds: { report: 1 } })).toBe("unobserved");
    expect(withRow({ source_kinds: { artefact: 1, unplaced: 1 } })).toBe("unstated");
    // The matrix cell answers for a published row that records no basis.
    expect(withRow({}, { source_kinds: { run: 3 } })).toBe("observed");
    expect(withRow({})).toBe("unstated");
    expect(techniqueVoice(null)).toBe("unstated");
  });

  it("lifts bracketed evidence ids out of prose, one citation per group", () => {
    expect(splitCitations("Beacons over HTTPS [ev_0001, ev_0003, …] and persists [ev_0007].")).toEqual([
      { kind: "text", text: "Beacons over HTTPS" },
      { kind: "cite", ids: ["ev_0001", "ev_0003"] },
      { kind: "text", text: " and persists" },
      { kind: "cite", ids: ["ev_0007"] },
      { kind: "text", text: "." },
    ]);
    expect(splitCitations("No ids here [see above].")).toEqual([{ kind: "text", text: "No ids here [see above]." }]);
    expect(splitCitations("")).toEqual([]);
    expect(proseText("Decodes its C2 [ev_0002; ev_0002].")).toBe("Decodes its C2.");
  });

  it("counts the network indicators the report publishes, not the ones it holds back", () => {
    const iocs = (rows: MalwareReport["consolidated_iocs"]) =>
      publishedNetworkIndicators({ ...MALWARE_REPORT, consolidated_iocs: rows } as MalwareReport);
    expect(publishedNetworkIndicators(MALWARE_REPORT)).toBe(0);
    expect(
      iocs([
        { type: "URL", kind: "url", value: "https://c2.example/a", is_network: true, published: "yes" },
        { type: "URL", kind: "url", value: "https://c2.example/b", is_network: true, published: "yes: decoded C2" },
        { type: "URL", kind: "url", value: "HTTPS://C2.EXAMPLE/a", is_network: true, published: "yes" },
        { type: "IPv4", kind: "ip", value: "8.8.8.8", is_network: true, published: "no: public resolver" },
        { type: "Domain", kind: "domain", value: "old.example", published: "yes" },
        { type: "SHA-256", kind: "hash", value: "ab", is_network: false, published: "yes" },
      ]),
    ).toBe(3);
    expect(kpis(MALWARE_REPORT).find((k) => k.key === "network")?.label).toBe("Published network indicators");
  });

  it("copies the configuration as key: value lines and orders actions P0 first", () => {
    expect(
      configText([
        { key: "C2", value: "cdn.example-update.net", how_obtained: "decrypted", evidence_refs: [] },
        { key: "Mutex", value: "Global\\x", how_obtained: "observed", evidence_refs: [] },
      ]),
    ).toBe("C2: cdn.example-update.net\nMutex: Global\\x");
    const recs = sortedRecommendations([
      { ...MALWARE_REPORT.defensive_recommendations[0], priority: "P2", action: "late" },
      { ...MALWARE_REPORT.defensive_recommendations[0], priority: "P0", action: "first" },
    ]);
    expect(recs.map((r) => r.action)).toEqual(["first", "late"]);
  });
});

describe("the switches", () => {

  it("apply the theme before paint with the same key and the same rule", () => {
    expect(THEME_BOOT_SCRIPT).toContain(JSON.stringify(THEME_STORAGE_KEY));
    for (const [stored, prefersLight, want] of [
      ["light", false, "light"],
      ["dark", true, "dark"],
      [null, true, "light"],
      ["junk", false, "dark"],
    ] as const) {
      const attrs: Record<string, string> = {};
      const sandbox = {
        location: { pathname: "/analysis/job-1/behaviour" },
        localStorage: { getItem: () => stored },
        window: { matchMedia: () => ({ matches: prefersLight }) },
        document: { documentElement: { setAttribute: (k: string, v: string) => (attrs[k] = v) } },
      };
      runInNewContext(THEME_BOOT_SCRIPT, sandbox);
      expect(attrs["data-ui-theme"]).toBe(want);
      expect(resolveTheme(stored, prefersLight)).toBe(want);
    }
  });

  it("leave every page outside the analysis alone", () => {
    const attrs: Record<string, string> = {};
    const sandbox = {
      location: { pathname: "/dashboard" },
      localStorage: { getItem: () => "light" },
      window: { matchMedia: () => ({ matches: true }) },
      document: { documentElement: { setAttribute: (k: string, v: string) => (attrs[k] = v) } },
    };
    runInNewContext(THEME_BOOT_SCRIPT, sandbox);
    expect(attrs).toEqual({});
  });

  it("let the reader's theme choice win over the OS", () => {
    expect(resolveTheme("light", false)).toBe("light");
    expect(resolveTheme("dark", true)).toBe("dark");
    expect(resolveTheme(null, true)).toBe("light");
    expect(resolveTheme("junk", false)).toBe("dark");
  });
});
