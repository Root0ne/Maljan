/**
 * Every part of a stored report is drawn somewhere on the six-tab page
 * (the completeness rule).
 *
 * Walked against the complete report the end-to-end suite draws
 * (`e2e/report-fixture.ts`), widened with the stored-run sections the other
 * tests use (`storedRunShapes.ts`) and with the two shapes an operator's own
 * setup adds: a section its agent wrote and one a tool server nobody here
 * knows produced. For each field the report carries there is a place; for
 * each section with content there is a place, and the block at that place is
 * drawn for this report and draws that section.
 *
 * What is checked by running the code: the sections (routing, the block's
 * gate and the block's own section filter), and that every part placed in an
 * export is in the file that export saves. A field's tab or header place is
 * declarative: the maps are typed against the report, so a new field cannot
 * go unplaced, and the e2e walk (analysis-tabs.spec.ts) renders each block
 * from the same fixture; this file does not render the page.
 */

import { describe, expect, it, vi } from "vitest";

const saved = vi.hoisted(() => [] as { name: string; body: unknown }[]);
vi.mock("@/lib/report-utils", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/lib/report-utils")>()),
  downloadBlob: (body: unknown, name: string) => saved.push({ name, body }),
  downloadObject: (body: unknown, name: string) => saved.push({ name, body }),
}));
vi.mock("@/lib/api", () => ({
  api: {
    getReportTimeline: async () => ({ discussion_timeline: [], confidence_curve: [], total_rounds: 0 }),
  },
}));

import { MALWARE_REPORT, REPORT } from "../../../../e2e/report-fixture";
import type { ReportDetailDTO } from "@/lib/api";
import type { JobRoster } from "@/types";
import type { EvidenceSection } from "@/types/malware-report";
import {
  REPORT_DTO_PLACES,
  REPORT_FIELD_PLACES,
  SECTION_TAB_BLOCK,
  SECTION_TAB_PLACE,
  sectionPlaces,
} from "../analysisMap";
import { tabHasContent } from "../analysisTabs";
import { evidenceViews, unroutedSections } from "../extraTabs";
import { ANALYSIS_TABS } from "../overview";
import { reportExportGroups } from "@/components/ui/exportActions";
import { sectionsForTab, tabOfSection } from "../reportSections";
import { hasRuleMatches } from "../ruleMatches";
import {
  API_CAPABILITIES,
  ARTIFACT_IMPORTS,
  BATCH_DECOMPILE,
  FUNCTIONS_EXAMINED,
  STRINGS_SECTION,
} from "./storedRunShapes";

const ROSTER: JobRoster = {
  agents: [
    { key: "static", label: "Static analyst", role: "static", stages: ["analysis"] },
    { key: "hunter", label: "Hunter", role: "generic", stages: ["analysis"] },
  ],
  stages: [{ key: "analysis", kind: "analysis", agents: ["static", "hunter"] }],
  servers: {},
} as unknown as JobRoster;

const AGENT_SECTION: EvidenceSection = {
  key: "tool_hunt_notes",
  kind: "list",
  rows: [],
  items: ["mutex Global\\UpdateSvcMtx held across reboots"],
  text: "",
  title: "Hunt notes",
  source: "agent:hunter",
  columns: [],
  evidence_ids: ["ev_0007"],
};

const UNKNOWN_SERVER_SECTION: EvidenceSection = {
  key: "tool_mystery_scan",
  kind: "table",
  rows: [["entropy", "7.9"]],
  items: [],
  text: "",
  title: "Mystery scan",
  source: "tool:mystery_scan",
  source_server: "mystery",
  columns: ["Field", "Value"],
  evidence_ids: ["ev_0008"],
};

const UNPLACED_SECTION: EvidenceSection = {
  key: "tool_orphan",
  kind: "list",
  rows: [],
  items: ["a fact no tab was written for"],
  text: "",
  title: "Orphan",
  source: "tool:orphan",
  columns: [],
  evidence_ids: [],
};

const STORED: ReportDetailDTO = {
  ...REPORT,
  malware_report: {
    ...MALWARE_REPORT,
    sections: [
      ...(MALWARE_REPORT.sections ?? []),
      STRINGS_SECTION,
      FUNCTIONS_EXAMINED,
      ARTIFACT_IMPORTS,
      API_CAPABILITIES,
      BATCH_DECOMPILE,
      AGENT_SECTION,
      UNKNOWN_SERVER_SECTION,
      UNPLACED_SECTION,
    ],
  },
};

const TAB_KEYS = new Set<string>(ANALYSIS_TABS.map((t) => t.key));

function tabOfPlace(place: string): string {
  return place.split("#")[0];
}

describe("every field the report carries has a place", () => {
  it("names a place for each field of the structured report", () => {
    for (const key of Object.keys(STORED.malware_report ?? {})) {
      const places = REPORT_FIELD_PLACES[key as keyof typeof REPORT_FIELD_PLACES];
      expect(places, `malware_report.${key}`).toBeDefined();
      expect(places.length, `malware_report.${key}`).toBeGreaterThan(0);
    }
  });

  it("names a place for each field of the report record", () => {
    for (const key of Object.keys(STORED)) {
      const places = REPORT_DTO_PLACES[key as keyof typeof REPORT_DTO_PLACES];
      expect(places, key).toBeDefined();
      expect(places.length, key).toBeGreaterThan(0);
    }
  });

  it("places everything on the header, one of the six tabs, or an export", () => {
    const all = [...Object.values(REPORT_FIELD_PLACES), ...Object.values(REPORT_DTO_PLACES)].flat();
    for (const place of all) {
      const tab = tabOfPlace(place);
      expect(["header", "export", "export:timeline", "none"].includes(tab) || TAB_KEYS.has(tab), place).toBe(true);
    }
  });

  it("puts every field placed in the full export into the file it saves", async () => {
    saved.length = 0;
    const item = reportExportGroups("r1", STORED.malware_report, "maljan-x")
      .flatMap((g) => g.items)
      .find((i) => i.key === "report-json")!;
    await item.run();
    const file = JSON.parse(saved[0].body as string) as Record<string, unknown>;
    for (const [key, places] of Object.entries(REPORT_FIELD_PLACES)) {
      if (!places.includes("export")) continue;
      if (!(key in (STORED.malware_report ?? {}))) continue;
      expect(file, `malware_report.${key}`).toHaveProperty(key);
    }
    // The full export is the structured report whole: every field it holds.
    expect(Object.keys(file).sort()).toEqual(Object.keys(STORED.malware_report ?? {}).sort());
  });

  it("builds the discussion timeline download from the negotiation log", () => {
    expect(REPORT_DTO_PLACES.negotiation_log).toEqual(["export:timeline"]);
    const timeline = reportExportGroups("r1", STORED.malware_report, "maljan-x")
      .flatMap((g) => g.items)
      .find((i) => i.key === "timeline");
    expect(timeline?.unavailable).toBeUndefined();
  });

  it("carries nowhere only the record's ids and the raw per-agent reports (T-469)", () => {
    const nowhere = Object.entries(REPORT_DTO_PLACES)
      .filter(([, places]) => places.includes("none"))
      .map(([key]) => key)
      .sort();
    expect(nowhere).toEqual(["agent_reports", "id", "job_id"]);
    expect(Object.values(REPORT_FIELD_PLACES).flat()).not.toContain("none");
  });
});

describe("every section the report carries is drawn", () => {
  const placed = sectionPlaces(STORED, ROSTER);
  const sections = STORED.malware_report?.sections ?? [];

  it("walks every section with content", () => {
    expect(placed.length).toBe(sections.length);
  });

  it("draws a section placed on a block, and that block is drawn for this report", () => {
    for (const { section, place } of placed) {
      const tab = tabOfSection(section.key, STORED.section_tabs);
      if (tab === "other") continue;
      expect(place, section.key).toBe(SECTION_TAB_PLACE[tab]);
      // The new tab draws the old page's block only when the block has
      // content; a section routed to it must make it so.
      expect(tabHasContent(SECTION_TAB_BLOCK[tab], STORED, ROSTER), section.key).toBe(true);
      if (tab === "detection") {
        expect(hasRuleMatches(STORED.agent_findings, sections), section.key).toBe(true);
      } else {
        expect(sectionsForTab(sections, tab, STORED.section_tabs), section.key).toContain(section);
      }
    }
  });

  it("draws an operator agent's or server's section on its own view under Evidence", () => {
    const views = evidenceViews(STORED, ROSTER).map((v) => v.key);
    const byKey = new Map(placed.map((p) => [p.section.key, p.place]));
    expect(byKey.get(AGENT_SECTION.key)).toBe("evidence#/agent/hunter");
    expect(byKey.get(UNKNOWN_SERVER_SECTION.key)).toBe("evidence#/server/mystery");
    expect(views).toContain("/agent/hunter");
    expect(views).toContain("/server/mystery");
  });

  it("keeps a section no tab and no view claims in the Evidence records' footer", () => {
    const byKey = new Map(placed.map((p) => [p.section.key, p.place]));
    expect(byKey.get(UNPLACED_SECTION.key)).toBe("evidence#unrouted");
    const footer = unroutedSections(sections, STORED.section_tabs, STORED.agent_findings, ROSTER);
    for (const { section, place } of placed) {
      if (place === "evidence#unrouted") expect(footer, section.key).toContain(section);
    }
  });

  it("puts every section on one of the six tabs, never on a seventh", () => {
    for (const { section, place } of placed) {
      expect(TAB_KEYS.has(tabOfPlace(place)), section.key).toBe(true);
    }
  });
});
