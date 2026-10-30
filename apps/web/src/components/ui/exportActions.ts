/**
 * What the one "Export" menu offers for a report, grouped by what the reader
 * wants it for.
 *
 * Quick is what a reader hands on: the report and the indicator list. Deep is
 * what another tool imports: STIX, MISP, the ATT&CK layer, the generated
 * rules. Data is the raw record. Each item calls the download the console
 * already had (`lib/api.ts`); nothing here is a new endpoint. An item with
 * nothing to download is left out, or kept with the reason it is unavailable
 * printed beside it, never a dead control without a word.
 */

import { api } from "@/lib/api";
import { downloadBlob, downloadObject } from "@/lib/report-utils";
import type { DetectionKind, MalwareReport } from "@/types/malware-report";

export interface ExportItem {
  key: string;
  label: string;
  /** One short line under the label: what the file is. */
  hint?: string;
  /** Set when the item cannot be used, and says why; the item is then disabled. */
  unavailable?: string;
  run: () => Promise<void>;
}

export interface ExportGroup {
  key: "quick" | "deep" | "data";
  label: string;
  items: ExportItem[];
}

const RULE_LABEL: Record<DetectionKind, string> = {
  yara: "YARA rules",
  sigma: "Sigma rules",
  suricata: "Suricata rules",
  snort: "Snort rules",
};

const RULE_EXT: Record<DetectionKind, string> = {
  yara: "yar",
  sigma: "yml",
  suricata: "rules",
  snort: "rules",
};

function json(body: unknown): string {
  return JSON.stringify(body, null, 2);
}

/** The rule kinds the report generated, in the menu's order. */
export function ruleKinds(mr: MalwareReport | null | undefined): DetectionKind[] {
  const present = new Set((mr?.detection_signatures ?? []).map((r) => r.kind));
  return (Object.keys(RULE_LABEL) as DetectionKind[]).filter((k) => present.has(k));
}

/**
 * The menu for one stored report.
 *
 * `baseName` starts every file name ("maljan-9f86d081"), so a folder of
 * downloads sorts by sample.
 */
export function reportExportGroups(
  reportId: string,
  mr: MalwareReport | null | undefined,
  baseName: string,
): ExportGroup[] {
  const misp = mr?.misp_attributes;
  const hasMisp = Array.isArray(misp) && misp.length > 0;

  const quick: ExportItem[] = [
    {
      key: "pdf",
      label: "Report (PDF)",
      hint: "Print-ready A4 with figures",
      run: async () => downloadObject(await api.getReportPdf(reportId), `${baseName}.pdf`),
    },
    {
      key: "html",
      label: "Report (HTML)",
      hint: "Opens offline, no external requests",
      run: async () =>
        downloadBlob(await api.getReportHtml(reportId), `${baseName}.html`, "text/html"),
    },
    {
      key: "markdown",
      label: "Report (Markdown)",
      run: async () =>
        downloadBlob(await api.getReportMarkdown(reportId), `${baseName}.md`, "text/markdown"),
    },
    {
      key: "iocs",
      label: "Indicator list",
      hint: "Every indicator with why it is or is not published",
      run: async () =>
        downloadBlob(json(await api.getReportIOCs(reportId)), `${baseName}-iocs.json`, "application/json"),
    },
  ];

  const deep: ExportItem[] = [
    {
      key: "stix",
      label: "STIX 2.1 bundle",
      run: async () =>
        downloadBlob(json(await api.getReportStix(reportId)), `${baseName}-stix.json`, "application/json"),
    },
    {
      key: "misp",
      label: "MISP attributes",
      unavailable: hasMisp ? undefined : "None were generated for this analysis",
      run: async () => downloadBlob(json(misp ?? []), `${baseName}-misp.json`, "application/json"),
    },
    {
      key: "attack-layer",
      label: "ATT&CK Navigator layer",
      run: async () =>
        downloadBlob(
          json(await api.getReportAttackLayer(reportId)),
          `${baseName}-attack-layer.json`,
          "application/json",
        ),
    },
    ...ruleKinds(mr).map(
      (kind): ExportItem => ({
        key: `rules-${kind}`,
        label: RULE_LABEL[kind],
        run: async () =>
          downloadBlob(
            await api.getReportSignature(reportId, kind),
            `${baseName}.${RULE_EXT[kind]}`,
            "text/plain",
          ),
      }),
    ),
  ];

  const data: ExportItem[] = [
    {
      key: "report-json",
      label: "Full analysis (JSON)",
      unavailable: mr ? undefined : "The analysis has no stored report",
      run: async () => downloadBlob(json(mr ?? {}), `${baseName}-report.json`, "application/json"),
    },
    {
      key: "techniques",
      label: "ATT&CK techniques (JSON)",
      run: async () =>
        downloadBlob(json(await api.getReportMitre(reportId)), `${baseName}-attack.json`, "application/json"),
    },
    {
      key: "timeline",
      label: "Discussion timeline (JSON)",
      run: async () =>
        downloadBlob(
          json(await api.getReportTimeline(reportId)),
          `${baseName}-timeline.json`,
          "application/json",
        ),
    },
  ];

  return [
    { key: "quick", label: "Quick", items: quick },
    { key: "deep", label: "Deep", items: deep },
    { key: "data", label: "Data", items: data },
  ];
}
