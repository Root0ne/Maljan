/**
 * The one Export menu: its groups, its items, and that each item reaches the
 * download the console already had.
 */

import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { beforeEach, describe, expect, it, vi } from "vitest";

const calls: string[] = [];
const saved: { name: string; body: unknown; type?: string }[] = [];
/* What the STIX endpoint answers in this test, or that it fails. */
const stix = vi.hoisted(() => ({ answer: { type: "bundle" } as unknown, fails: false }));

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
      getReportStix: async (...args: unknown[]) => {
        calls.push(`getReportStix(${args.join(",")})`);
        if (stix.fails) throw new Error("stix endpoint down");
        return stix.answer;
      },
      getReportAttackLayer: record("getReportAttackLayer", { name: "layer" }),
      getReportSignature: record("getReportSignature", "rule x {}"),
      getReportMitre: record("getReportMitre", { techniques: [] }),
      getReportTimeline: record("getReportTimeline", { rounds: [] }),
    },
  };
});

vi.mock("@/lib/report-utils", () => ({
  downloadBlob: (body: string, name: string, type: string) => saved.push({ name, body, type }),
  downloadObject: (body: Blob, name: string) => saved.push({ name, body }),
}));

import ExportMenu, { usableItems, walkableItems } from "@/components/ui/ExportMenu";
import { exportFileNames, reportExportGroups, ruleKinds } from "@/components/ui/exportActions";
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
  stix.answer = { type: "bundle" };
  stix.fails = false;
});

const item = (key: string, over: Partial<MalwareReport> = {}, stored?: Record<string, unknown> | null) =>
  reportExportGroups("r1", report(over), "maljan-9f86d081884c", stored)
    .flatMap((g) => g.items)
    .find((i) => i.key === key)!;

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
    expect(misp?.unavailable).toBe("This run generated no MISP attributes");
    expect(walkableItems(groups).some((i) => i.key === "misp")).toBe(true);
    expect(usableItems(groups).some((i) => i.key === "misp")).toBe(false);
    const withMisp = reportExportGroups("r1", report({ misp_attributes: [{ type: "md5" }] }), "b");
    expect(withMisp[1].items.find((i) => i.key === "misp")?.unavailable).toBeUndefined();
  });

  it("call the existing downloads and name every file after the sample", async () => {
    const groups = reportExportGroups("r1", report(), "maljan-9f86d081884c");
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
    // Every name the console's downloads had before they moved into the
    // menu, unchanged: scripts pick these up.
    expect(saved.map((s) => s.name)).toEqual([
      "maljan-9f86d081884c.pdf",
      "maljan-9f86d081884c.html",
      "maljan-9f86d081884c.md",
      "maljan-9f86d081884c-iocs.json",
      "maljan-stix-bundle.json",
      "maljan-attack-layer.json",
      "maljan-yara.yar",
      "maljan-sigma.yml",
      "maljan-9f86d081884c-report.json",
      "maljan-9f86d081884c-mitre.json",
      "maljan-9f86d081884c-timeline.json",
    ]);
    expect(saved.find((s) => s.name === "maljan-yara.yar")?.type).toBe("text/x-yara");
    expect(saved.find((s) => s.name === "maljan-sigma.yml")?.type).toBe("application/yaml");
  });

  it("pin every file name, the MISP and per-kind ones included", () => {
    const names = exportFileNames("maljan-9f86d081884c");
    expect(names.misp).toBe("maljan-9f86d081884c-misp.json");
    expect(names.stixDraft).toBe("maljan-stix-bundle-draft.json");
    expect(names.rules("suricata")).toBe("maljan-suricata.rules");
    expect(names.rules("snort")).toBe("maljan-snort.rules");
  });
});

describe("the STIX download", () => {
  it("saves a published bundle as itself under the export name", async () => {
    stix.answer = { type: "bundle", id: "bundle--1", objects: [] };
    await item("stix").run();
    expect(saved).toHaveLength(1);
    expect(saved[0].name).toBe("maljan-stix-bundle.json");
    expect(JSON.parse(saved[0].body as string)).toEqual({ type: "bundle", id: "bundle--1", objects: [] });
  });

  it("unwraps a draft the API would not publish and names the file a draft", async () => {
    stix.answer = { published: false, notice: "not published", bundle: { type: "bundle", id: "bundle--2" } };
    await item("stix").run();
    expect(saved[0].name).toBe("maljan-stix-bundle-draft.json");
    expect(JSON.parse(saved[0].body as string)).toEqual({ type: "bundle", id: "bundle--2" });
  });

  it("falls back to the bundle stored with the report when the endpoint fails", async () => {
    stix.fails = true;
    await item("stix", { stix_bundle_extended: { type: "bundle", id: "bundle--ext" } }).run();
    expect(JSON.parse(saved[0].body as string).id).toBe("bundle--ext");
    // An empty extended bundle holds nothing; the report record's is next.
    saved.length = 0;
    await item("stix", { stix_bundle_extended: {} as Record<string, unknown> }, { type: "bundle", id: "bundle--dto" }).run();
    expect(JSON.parse(saved[0].body as string).id).toBe("bundle--dto");
  });

  it("says the endpoint failed when nothing is stored to fall back to", async () => {
    stix.fails = true;
    await expect(item("stix", {}, null).run()).rejects.toThrow("stix endpoint down");
    expect(saved).toHaveLength(0);
  });
});

describe("the MISP item", () => {
  it("downloads the attributes the report holds", async () => {
    const misp = item("misp", { misp_attributes: [{ type: "md5", value: "abc" }] as MalwareReport["misp_attributes"] });
    expect(misp.unavailable).toBeUndefined();
    await misp.run();
    expect(saved[0].name).toBe("maljan-9f86d081884c-misp.json");
    expect(JSON.parse(saved[0].body as string)).toEqual([{ type: "md5", value: "abc" }]);
  });

  it("says why there are none, in the words the console has always used", () => {
    expect(item("misp", { misp_attributes: [] }).unavailable).toBe("This run generated no MISP attributes");
    const stored = item("misp", {
      misp_attributes: undefined,
      consolidated_iocs: [{ value: "a" }, { value: "b" }] as unknown as MalwareReport["consolidated_iocs"],
    }).unavailable;
    expect(stored).toMatch(/^No MISP attributes are stored with this report: it was stored before the platform built them/);
    expect(stored).toContain("its 2 indicators are under Indicators & detection and in the indicator list");
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
