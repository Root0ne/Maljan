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
import { mispAbsence } from "@/components/analysis/indicators";
import {
  NAVIGATOR_LAYER_FILE,
  STIX_DRAFT_FILE,
  STIX_EXPORT_FILE,
  readStixAnswer,
} from "@/components/analysis/stixGraph";
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

const RULE_MIME: Record<DetectionKind, string> = {
  yara: "text/x-yara",
  sigma: "application/yaml",
  suricata: "text/plain",
  snort: "text/plain",
};

/**
 * The file names the console's downloads have always had, kept as they were
 * when the downloads moved into this menu: a script that picks up
 * `maljan-<hash>-mitre.json` or `maljan-stix-bundle.json` keeps working.
 * Only the full-analysis JSON is new to the menu and named here first.
 */
export function exportFileNames(baseName: string) {
  return {
    pdf: `${baseName}.pdf`,
    html: `${baseName}.html`,
    markdown: `${baseName}.md`,
    iocs: `${baseName}-iocs.json`,
    stix: STIX_EXPORT_FILE,
    stixDraft: STIX_DRAFT_FILE,
    misp: `${baseName}-misp.json`,
    attackLayer: NAVIGATOR_LAYER_FILE,
    rules: (kind: DetectionKind) => `maljan-${kind}.${RULE_EXT[kind]}`,
    report: `${baseName}-report.json`,
    techniques: `${baseName}-mitre.json`,
    timeline: `${baseName}-timeline.json`,
  };
}

/** A clause as a sentence: its first letter in capitals. */
function sentence(text: string): string {
  return text.charAt(0).toUpperCase() + text.slice(1);
}

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
 * `baseName` starts the report's own file names ("maljan-9f86d081884c"), so a
 * folder of downloads sorts by sample (`exportFileNames`). `storedStix` is the
 * bundle the report record carries, downloaded when the STIX endpoint fails.
 */
export function reportExportGroups(
  reportId: string,
  mr: MalwareReport | null | undefined,
  baseName: string,
  storedStix?: Record<string, unknown> | null,
): ExportGroup[] {
  const names = exportFileNames(baseName);
  const misp = mr?.misp_attributes;
  const hasMisp = Array.isArray(misp) && misp.length > 0;

  const quick: ExportItem[] = [
    {
      key: "pdf",
      label: "Report (PDF)",
      hint: "Print-ready A4 with figures",
      run: async () => downloadObject(await api.getReportPdf(reportId), names.pdf),
    },
    {
      key: "html",
      label: "Report (HTML)",
      hint: "Opens offline, no external requests",
      run: async () =>
        downloadBlob(await api.getReportHtml(reportId), names.html, "text/html"),
    },
    {
      key: "markdown",
      label: "Report (Markdown)",
      run: async () =>
        downloadBlob(await api.getReportMarkdown(reportId), names.markdown, "text/markdown"),
    },
    {
      key: "iocs",
      label: "Indicator list",
      hint: "Every indicator with why it is or is not published",
      run: async () =>
        downloadBlob(json(await api.getReportIOCs(reportId)), names.iocs, "application/json"),
    },
  ];

  const deep: ExportItem[] = [
    {
      key: "stix",
      label: "STIX 2.1 bundle",
      hint: "An unpublished draft downloads as a file named draft",
      run: async () => {
        // The endpoint wraps a draft it would not publish; the file is the
        // bundle itself either way, and its name says which it is. When the
        // endpoint fails, the bundle stored with the report is what there is.
        let answer: unknown;
        try {
          answer = await api.getReportStix(reportId);
        } catch (err) {
          const stored = [mr?.stix_bundle_extended, storedStix].find(
            (b) => b && Object.keys(b).length > 0,
          );
          if (!stored) throw err;
          answer = stored;
        }
        const { bundle, draft } = readStixAnswer(answer);
        downloadBlob(json(bundle), draft ? names.stixDraft : names.stix, "application/json");
      },
    },
    {
      key: "misp",
      label: "MISP attributes",
      unavailable: hasMisp ? undefined : mr ? sentence(mispAbsence(mr)) : "None were generated for this analysis",
      run: async () => downloadBlob(json(misp ?? []), names.misp, "application/json"),
    },
    {
      key: "attack-layer",
      label: "ATT&CK Navigator layer",
      run: async () =>
        downloadBlob(
          json(await api.getReportAttackLayer(reportId)),
          names.attackLayer,
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
            names.rules(kind),
            RULE_MIME[kind],
          ),
      }),
    ),
  ];

  const data: ExportItem[] = [
    {
      key: "report-json",
      label: "Full analysis (JSON)",
      unavailable: mr ? undefined : "The analysis has no stored report",
      run: async () => downloadBlob(json(mr ?? {}), names.report, "application/json"),
    },
    {
      key: "techniques",
      label: "ATT&CK techniques (JSON)",
      run: async () =>
        downloadBlob(json(await api.getReportMitre(reportId)), names.techniques, "application/json"),
    },
    {
      key: "timeline",
      label: "Discussion timeline (JSON)",
      run: async () =>
        downloadBlob(
          json(await api.getReportTimeline(reportId)),
          names.timeline,
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
