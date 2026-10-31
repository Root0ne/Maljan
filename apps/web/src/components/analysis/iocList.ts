/**
 * The indicator browser: one list of every indicator the report holds, the
 * facets and filters a reader narrows it with, and what else the report says
 * about one value.
 *
 * The consolidated table and the values the verdict's own patterns name were
 * two tables; they are one list now. A value both hold is one row, marked as
 * named in the verdict, with every entry the verdict gives it (a verdict can
 * name one value twice, under two algorithms); a value only the
 * verdict names is a row of its own that says the indicator table has none.
 * The publish decision is the table's (`indicators.ts`), read the way the
 * export reads it.
 *
 * "Related findings" is a search of the report for the value, field by field,
 * by what each field is rather than by which tool wrote it: a network row, a
 * string carved from the sample, a persistence mechanism, a process command
 * line, a signature's evidence mark, a configuration item, a key finding.
 */

import type { MalwareReport, ProcessNode } from "@/types/malware-report";
import { decisionOf, type Decision } from "./indicators";

/** How many rows the browser draws before offering more. */
export const IOC_ROWS_STEP = 10;

export interface IocRow {
  key: string;
  type: string;
  kind: string;
  value: string;
  source: string;
  context: string;
  recoveredBy: string;
  /** The table's publish decision, or null for a value only the verdict names. */
  decision: Decision | null;
  /** The verdict's own patterns name this value. */
  inVerdict: boolean;
  /** The algorithm the verdict gives a hash it names: its first entry's. */
  algorithm: string;
  /** Every entry the verdict names this value with, in the verdict's order. */
  verdictEntries: { kind: string; algorithm: string }[];
}

/**
 * Where one row stands with the export. A row the publish rule answered is
 * published or withheld; a table row it gave no answer is neither, and a
 * value only the verdict names has no table row to answer for. Each is said
 * as what it is and filtered on its own, never counted as withheld.
 */
export type ExportState = "published" | "withheld" | "unanswered" | "not-in-table";

export type PublicationFilter = "all" | ExportState;

export const EXPORT_STATE_WORDS: Record<ExportState, string> = {
  published: "published",
  withheld: "withheld",
  unanswered: "no answer recorded",
  "not-in-table": "not in the indicator table",
};

/** Where a row stands with the export. */
export function exportState(row: Pick<IocRow, "decision">): ExportState {
  const d = row.decision;
  if (!d) return "not-in-table";
  if (!d.answered) return "unanswered";
  return d.publication === "published" ? "published" : "withheld";
}

/** How many rows stand in each export state. */
export function exportCounts(rows: readonly IocRow[]): Record<ExportState, number> {
  const counts: Record<ExportState, number> = { published: 0, withheld: 0, unanswered: 0, "not-in-table": 0 };
  for (const row of rows) counts[exportState(row)] += 1;
  return counts;
}

function same(a: string, b: string): boolean {
  return a.trim().toLowerCase() === b.trim().toLowerCase();
}

/**
 * Every indicator, the table's rows first and then the verdict's own.
 *
 * A verdict value is matched to a table row as the export matches it: on
 * kind and value, and on value alone only for a table row stored before the
 * table carried kinds (`judgeIndicatorRows`). The same value under another
 * kind is a different indicator and keeps a row of its own.
 */
export function iocRows(mr: MalwareReport | null | undefined): IocRow[] {
  const table = (mr?.consolidated_iocs ?? []).filter((r) => r && typeof r.value === "string");
  const judged = (mr?.judge_indicators ?? []).filter((r) => r && typeof r.value === "string");
  const verdictOf = new Map<number, (typeof judged)[number][]>();
  const unmatched: (typeof judged)[number][] = [];
  for (const ind of judged) {
    let i = table.findIndex((r) => r.kind && r.kind === ind.kind && same(r.value, ind.value));
    if (i < 0) i = table.findIndex((r) => !r.kind && same(r.value, ind.value));
    if (i < 0) unmatched.push(ind);
    else verdictOf.set(i, [...(verdictOf.get(i) ?? []), ind]);
  }
  const rows: IocRow[] = table.map((row, i) => {
    const entries = verdictOf.get(i) ?? [];
    return {
      key: `t${i}`,
      type: row.type || row.kind || "",
      kind: row.kind ?? "",
      value: row.value,
      source: row.source ?? "",
      context: row.context || row.description || "",
      recoveredBy: row.recovered_by ?? "",
      decision: decisionOf(row.published),
      inVerdict: entries.length > 0,
      algorithm: entries[0]?.algorithm ?? "",
      verdictEntries: entries.map((e) => ({ kind: e.kind ?? "", algorithm: e.algorithm ?? "" })),
    };
  });
  unmatched.forEach((ind, k) => {
    rows.push({
      key: `v${k}`,
      type: ind.kind || "",
      kind: ind.kind || "",
      value: ind.value,
      source: "",
      context: "",
      recoveredBy: "",
      decision: null,
      inVerdict: true,
      algorithm: ind.algorithm ?? "",
      verdictEntries: [{ kind: ind.kind ?? "", algorithm: ind.algorithm ?? "" }],
    });
  });
  return rows;
}

/**
 * The order a reader meets the list in: the rows the export publishes first,
 * so they stand before "show more", then by type. The sort is stable, so rows
 * of one state and type keep the table's order.
 */
export function sortedForReading(rows: readonly IocRow[]): IocRow[] {
  const rank = (row: IocRow) => (exportState(row) === "published" ? 0 : 1);
  return [...rows].sort((a, b) => rank(a) - rank(b) || a.type.localeCompare(b.type));
}

/** The type facets, in the order the types first appear, with their counts. */
export function iocFacets(rows: readonly IocRow[]): { type: string; count: number }[] {
  const counts = new Map<string, number>();
  for (const row of rows) {
    const type = row.type || "Other";
    counts.set(type, (counts.get(type) ?? 0) + 1);
  }
  return [...counts.entries()].map(([type, count]) => ({ type, count }));
}

/** The rows a reader's facet, search and publish filter keep. */
export function filterIocs(
  rows: readonly IocRow[],
  { type, query, publication }: { type: string | null; query: string; publication: PublicationFilter },
): IocRow[] {
  const q = query.trim().toLowerCase();
  return rows.filter((row) => {
    if (type && (row.type || "Other") !== type) return false;
    if (publication !== "all" && exportState(row) !== publication) return false;
    if (!q) return true;
    return [row.value, row.type, row.source, row.context].some((v) => v.toLowerCase().includes(q));
  });
}

export interface RelatedFinding {
  /** Where in the report: "Network host", "Persistence", … */
  where: string;
  text: string;
}

function mentions(haystack: string | null | undefined, needle: string): boolean {
  const n = needle.trim().toLowerCase();
  return n.length >= 3 && String(haystack ?? "").toLowerCase().includes(n);
}

/** What else the report says about one value, field by field. */
export function relatedFindings(mr: MalwareReport | null | undefined, value: string): RelatedFinding[] {
  if (!mr || !value.trim()) return [];
  const out: RelatedFinding[] = [];
  const push = (where: string, text: string) => {
    if (!out.some((f) => f.where === where && f.text === text)) out.push({ where, text });
  };
  for (const d of mr.network?.domains ?? []) {
    if (same(d.fqdn, value) || d.resolved_ips.some((ip) => same(ip, value))) {
      push("Network host", d.reason ? `${d.fqdn}: ${d.reason}` : d.fqdn);
    }
  }
  for (const ip of mr.network?.ips ?? []) {
    if (same(ip.address, value)) {
      push("Network host", [ip.address, ip.port !== null ? `port ${ip.port}` : "", ip.geo ?? "", ip.asn ?? ""].filter(Boolean).join(" · "));
    }
  }
  for (const u of mr.network?.urls ?? []) {
    if (mentions(u.url, value)) push("HTTP request", [u.method, u.url].filter(Boolean).join(" "));
  }
  for (const s of mr.static?.interesting_strings ?? []) {
    if (mentions(s.value, value)) push("String in the sample", s.notes ? `${s.value} (${s.notes})` : s.value);
  }
  for (const p of mr.persistence ?? []) {
    if (mentions(p.target, value) || mentions(p.payload, value)) {
      push("Persistence", [p.target, p.payload].filter(Boolean).join(" → "));
    }
  }
  const walk = (nodes: readonly ProcessNode[] | null | undefined) => {
    for (const n of nodes ?? []) {
      if (mentions(n.command_line, value) || mentions(n.name, value)) push("Process", n.command_line || n.name);
      walk(n.children);
    }
  };
  walk(mr.dynamic?.process_tree);
  for (const sig of mr.dynamic?.sandbox_signatures ?? []) {
    if (sig.marks.some((m) => mentions(m, value))) push("Sandbox signature", sig.name);
  }
  for (const r of mr.dynamic?.registry_mods ?? []) {
    if (mentions(r.key, value) || mentions(r.new_value, value)) push("Registry", `${r.hive}\\${r.key}`);
  }
  for (const c of mr.technical_analysis?.configuration ?? []) {
    if (mentions(c.value, value)) push("Configuration", `${c.key}: ${c.value}`);
  }
  for (const f of mr.key_findings ?? []) {
    if (mentions(f.text, value)) push("Key finding", f.text);
  }
  return out;
}
