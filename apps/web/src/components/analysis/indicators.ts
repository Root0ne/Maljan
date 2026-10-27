/**
 * The report's indicators as the export decides them.
 *
 * `consolidated_iocs` is the one typed table of every indicator the run
 * recorded — the sample's digests, dropped files, commands, mutexes,
 * endpoints — and each row carries the answer of the one publish rule the
 * STIX export asks: `yes`, `yes: <reason>` or `no: <reason>`. The console
 * drew none of it, so a reader could see a domain on NETWORK and never learn
 * that the export held it back, or why. `judge_indicators` are the values the
 * judge's own STIX patterns name, which the same rule decides.
 *
 * The decision is read the way the export reads it: only a `yes` publishes.
 * A row whose rule gave no answer is not exported either, and says that it
 * carries no reason rather than inventing one.
 */

import type { ConsolidatedIOC, JudgeIndicator, MalwareReport } from "@/types/malware-report";

export type Publication = "published" | "withheld";

export interface Decision {
  publication: Publication;
  /** The rule's reason as written, without its `yes:` / `no:`; empty when it gave none. */
  reason: string;
  /** Whether the rule answered at all. */
  answered: boolean;
}

export interface IndicatorRow extends Decision {
  type: string;
  kind: string;
  value: string;
  source: string;
  context: string;
  recoveredBy: string;
}

export interface JudgeIndicatorRow {
  kind: string;
  value: string;
  algorithm: string;
  /** The decision of the IOC table's row for the same value; `null` when the
   *  table holds no such row. */
  decision: Decision | null;
}

/** What one stored publish answer decides (`stix_renderer.publishes`). */
export function decisionOf(answer: string | null | undefined): Decision {
  const text = (answer ?? "").trim();
  if (!text) return { publication: "withheld", reason: "", answered: false };
  const yes = text === "yes" || text.startsWith("yes:");
  const lead = yes ? "yes" : /^no\b/.test(text) ? "no" : "";
  const reason = lead ? text.slice(lead.length).replace(/^\s*:\s*/, "").trim() : text;
  return { publication: yes ? "published" : "withheld", reason, answered: true };
}

/** Every row of the consolidated IOC table, in the order the report holds them. */
export function indicatorRows(mr: MalwareReport | null | undefined): IndicatorRow[] {
  return (mr?.consolidated_iocs ?? [])
    .filter((row): row is ConsolidatedIOC => Boolean(row) && typeof row.value === "string")
    .map((row) => ({
      type: row.type || row.kind || "",
      kind: row.kind ?? "",
      value: row.value,
      source: row.source ?? "",
      context: row.context || row.description || "",
      recoveredBy: row.recovered_by ?? "",
      ...decisionOf(row.published),
    }));
}

function sameValue(a: string, b: string): boolean {
  return a.trim().toLowerCase() === b.trim().toLowerCase();
}

/**
 * The judge's indicators, each beside the decision the IOC table records for
 * the same value — matched on kind and value as the export matches them, and
 * on value alone for a row stored before the table carried kinds.
 */
export function judgeIndicatorRows(mr: MalwareReport | null | undefined): JudgeIndicatorRow[] {
  const table = mr?.consolidated_iocs ?? [];
  return (mr?.judge_indicators ?? [])
    .filter((ind): ind is JudgeIndicator => Boolean(ind) && typeof ind.value === "string")
    .map((ind) => {
      const row =
        table.find((r) => r.kind && r.kind === ind.kind && sameValue(r.value, ind.value)) ??
        table.find((r) => !r.kind && sameValue(r.value, ind.value));
      return {
        kind: ind.kind,
        value: ind.value,
        algorithm: ind.algorithm ?? "",
        decision: row ? decisionOf(row.published) : null,
      };
    });
}

/**
 * Why the MISP export has nothing to download.
 *
 * The report build writes `misp_attributes` from the IOC table's published
 * rows and the published techniques; a report stored before it did holds
 * `null` — and "this run generated no MISP attributes" said of such a run
 * with fourteen indicators that it found none. A `null` is said as what it
 * is; only an empty list, which the builder wrote, is a run that produced
 * none.
 */
export function mispAbsence(mr: MalwareReport | null | undefined): string {
  if (Array.isArray(mr?.misp_attributes)) return "this run generated no MISP attributes";
  const count = mr?.consolidated_iocs?.length ?? 0;
  const where =
    count > 0
      ? ` — its ${count} indicator${count === 1 ? " is" : "s are"} on DETECTION and in the IOC list`
      : "";
  return `no MISP attributes are stored with this report: it was stored before the platform built them${where}`;
}

/** Whether the report holds any indicator for the panel to draw. */
export function hasIndicators(mr: MalwareReport | null | undefined): boolean {
  // The rows the panel draws, not the raw lists: a list of malformed rows
  // would otherwise offer a heading over nothing.
  return indicatorRows(mr).length > 0 || judgeIndicatorRows(mr).length > 0;
}
