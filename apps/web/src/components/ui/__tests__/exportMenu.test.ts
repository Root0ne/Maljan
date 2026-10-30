/**
 * The one Export menu: its groups, its items, and that each item reaches the
 * download the console already had.
 */

import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { beforeEach, describe, expect, it, vi } from "vitest";

const calls: string[] = [];
const saved: { name: string; body: unknown }[] = [];

vi.mock("@/lib/api", () => {
  const record = (name: string, value: unknown) => async (...args: unknown[]) => {
    calls.push(`${name}(${args.join(",")})`);
    return value;
  };
  return {
    api: {
      getReportPdf: record("getReportPdf", new Blob(["%PDF"])),
      getReportHtml: record("getReportHtml", "<html></html>"),
      getReportMarkdown: record("getReportMarkdown", "# report"),
      getReportIOCs: record("getReportIOCs", { items: [], total: 0 }),
      getReportStix: record("getReportStix", { type: "bundle" }),
      getReportAttackLayer: record("getReportAttackLayer", { name: "layer" }),
      getReportSignature: record("getReportSignature", "rule x {}"),
      getReportMitre: record("getReportMitre", { techniques: [] }),
      getReportTimeline: record("getReportTimeline", { rounds: [] }),
    },
  };
});

vi.mock("@/lib/report-utils", () => ({
  downloadBlob: (body: string, name: string) => saved.push({ name, body }),
  downloadObject: (body: Blob, name: string) => saved.push({ name, body }),
}));

import ExportMenu, { usableItems, walkableItems } from "@/components/ui/ExportMenu";
import { reportExportGroups, ruleKinds } from "@/components/ui/exportActions";
import type { MalwareReport } from "@/types/malware-report";

const report = (over: Partial<MalwareReport> = {}) =>
  ({
    detection_signatures: [
      { kind: "sigma", name: "s", body: "", auto_generated: true, source_evidence: [], compile_error: null },
      { kind: "yara", name: "y", body: "", auto_generated: true, source_evidence: [], compile_error: null },
    ],
    misp_attributes: [],
    ...over,
  }) as unknown as MalwareReport;

beforeEach(() => {
  calls.length = 0;
  saved.length = 0;
});

describe("the export groups", () => {
  it("are Quick, Deep and Data, in that order", () => {
    const groups = reportExportGroups("r1", report(), "maljan-9f86d081");
    expect(groups.map((g) => g.label)).toEqual(["Quick", "Deep", "Data"]);
    expect(groups[0].items.map((i) => i.label)).toEqual([
      "Report (PDF)",
      "Report (HTML)",
      "Report (Markdown)",
      "Indicator list",
    ]);
  });

  it("offer one rule download per kind the report generated, in a fixed order", () => {
    expect(ruleKinds(report())).toEqual(["yara", "sigma"]);
    const deep = reportExportGroups("r1", report(), "b")[1].items.map((i) => i.key);
    expect(deep).toEqual(["stix", "misp", "attack-layer", "rules-yara", "rules-sigma"]);
    expect(ruleKinds(null)).toEqual([]);
  });

  it("keep MISP with the reason it is unavailable: walked to, but not run", () => {
    const groups = reportExportGroups("r1", report(), "b");
    const misp = groups[1].items.find((i) => i.key === "misp");
    expect(misp?.unavailable).toBe("None were generated for this analysis");
    expect(walkableItems(groups).some((i) => i.key === "misp")).toBe(true);
    expect(usableItems(groups).some((i) => i.key === "misp")).toBe(false);
    const withMisp = reportExportGroups("r1", report({ misp_attributes: [{ type: "md5" }] }), "b");
    expect(withMisp[1].items.find((i) => i.key === "misp")?.unavailable).toBeUndefined();
  });

  it("call the existing downloads and name every file after the sample", async () => {
    const groups = reportExportGroups("r1", report(), "maljan-9f86d081");
    for (const item of usableItems(groups)) await item.run();
    expect(calls).toEqual([
      "getReportPdf(r1)",
      "getReportHtml(r1)",
      "getReportMarkdown(r1)",
      "getReportIOCs(r1)",
      "getReportStix(r1)",
      "getReportAttackLayer(r1)",
      "getReportSignature(r1,yara)",
      "getReportSignature(r1,sigma)",
      "getReportMitre(r1)",
      "getReportTimeline(r1)",
    ]);
    expect(saved.map((s) => s.name)).toEqual([
      "maljan-9f86d081.pdf",
      "maljan-9f86d081.html",
      "maljan-9f86d081.md",
      "maljan-9f86d081-iocs.json",
      "maljan-9f86d081-stix.json",
      "maljan-9f86d081-attack-layer.json",
      "maljan-9f86d081.yar",
      "maljan-9f86d081.yml",
      "maljan-9f86d081-report.json",
      "maljan-9f86d081-attack.json",
      "maljan-9f86d081-timeline.json",
    ]);
  });
});

describe("the menu button", () => {
  it("is one labelled button that says it opens a menu, closed at first", () => {
    const out = renderToStaticMarkup(createElement(ExportMenu, { groups: reportExportGroups("r1", report(), "b") }));
    expect(out).toContain('aria-haspopup="menu"');
    expect(out).toContain('aria-expanded="false"');
    expect(out).toContain("Export");
    expect(out).not.toContain('role="menu"');
    expect(out.match(/<button/g)).toHaveLength(1);
  });
});
