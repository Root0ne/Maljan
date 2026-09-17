/**
 * What a reputation service said about this sample, read from the ledger.
 *
 * The run asks at most one service about the file's hash: `get_file_report` on
 * VirusTotal's own MCP server when it is configured, `check_hash` on the
 * threat-intel sidecar when it is not. Either way the answer is an evidence
 * entry like every other tool call, and that entry is the only thing this
 * reads — a key in the settings is not a finding, so a configured service that
 * was never asked, or asked and answered nothing, draws no section at all.
 *
 * VirusTotal answers JSON and is read for its engine counts, its threat labels
 * and the two dates that say how long the file has been known. The sidecar
 * answers a sentence, and the sentence is the finding; the counts are lifted
 * out of it when it carries them so the two services read the same way.
 */

import type { EvidenceEntry } from "@/types/evidence";

/** The tool each service answers under, in the order the pipeline asks. */
export const REPUTATION_TOOLS = ["get_file_report", "check_hash"] as const;
export type ReputationTool = (typeof REPUTATION_TOOLS)[number];

export interface Reputation {
  /** The heading: the service that was asked. */
  service: string;
  entryId: string;
  /** Engines that returned a verdict, when the answer counted them. */
  engines: number | null;
  malicious: number | null;
  suspicious: number | null;
  /** The names the industry gives this file, most agreed first. */
  labels: string[];
  firstSeen: string | null;
  lastSeen: string | null;
  /** Where to read the full report. Absent unless the answer carried one. */
  link: string | null;
  /** The service's own words, kept whenever there are no counts to show. */
  summary: string;
}

const SERVICE_NAME: Record<ReputationTool, string> = {
  get_file_report: "VirusTotal",
  check_hash: "Threat intelligence",
};

/** The first value under `key` within `depth` levels of `value`. */
function findKey(value: unknown, key: string, depth = 6): unknown {
  if (depth <= 0 || value === null || value === undefined) return undefined;
  if (Array.isArray(value)) {
    for (const child of value) {
      const found = findKey(child, key, depth - 1);
      if (found !== undefined) return found;
    }
    return undefined;
  }
  if (typeof value === "object") {
    const record = value as Record<string, unknown>;
    if (key in record && record[key] !== null && record[key] !== undefined) return record[key];
    for (const child of Object.values(record)) {
      const found = findKey(child, key, depth - 1);
      if (found !== undefined) return found;
    }
  }
  return undefined;
}

function counts(structured: unknown): Pick<Reputation, "engines" | "malicious" | "suspicious"> {
  const stats = findKey(structured, "last_analysis_stats");
  if (!stats || typeof stats !== "object" || Array.isArray(stats)) {
    return { engines: null, malicious: null, suspicious: null };
  }
  const values = Object.values(stats as Record<string, unknown>).filter(
    (v): v is number => typeof v === "number" && Number.isFinite(v),
  );
  if (values.length === 0) return { engines: null, malicious: null, suspicious: null };
  const number = (name: string) => {
    const found = (stats as Record<string, unknown>)[name];
    return typeof found === "number" ? found : 0;
  };
  return {
    engines: values.reduce((total, v) => total + v, 0),
    malicious: number("malicious"),
    suspicious: number("suspicious"),
  };
}

/** The labels VirusTotal's own vote produced, deduplicated, strongest first. */
function labelsOf(structured: unknown): string[] {
  const classification = findKey(structured, "popular_threat_classification");
  if (!classification || typeof classification !== "object") return [];
  const record = classification as Record<string, unknown>;
  const out: string[] = [];
  const push = (value: unknown) => {
    const text = typeof value === "string" ? value.trim() : "";
    if (text && !out.includes(text)) out.push(text);
  };
  push(record.suggested_threat_label);
  for (const key of ["popular_threat_name", "popular_threat_category"]) {
    const rows = record[key];
    if (!Array.isArray(rows)) continue;
    for (const row of rows) {
      push(row && typeof row === "object" ? (row as Record<string, unknown>).value : row);
    }
  }
  return out;
}

/** A VirusTotal date, which travels as whole seconds since the epoch. */
function date(structured: unknown, ...keys: string[]): string | null {
  for (const key of keys) {
    const value = findKey(structured, key);
    if (typeof value === "number" && Number.isFinite(value) && value > 0) {
      return new Date(value * 1000).toISOString();
    }
    if (typeof value === "string" && value.trim()) {
      const parsed = new Date(value);
      if (!Number.isNaN(parsed.getTime())) return parsed.toISOString();
    }
  }
  return null;
}

/** A link the answer carried, and never one this console guessed. */
function linkOf(structured: unknown): string | null {
  for (const key of ["gui_url", "permalink", "html_url"]) {
    const value = findKey(structured, key);
    if (typeof value === "string" && /^https?:\/\//.test(value)) return value;
  }
  return null;
}

/** "42/71 malicious" as the sidecar writes it, when it writes it. */
function countsFromProse(text: string): Pick<Reputation, "engines" | "malicious" | "suspicious"> {
  const match = /(\d+)\s*\/\s*(\d+)\s+malicious/i.exec(text);
  if (!match) return { engines: null, malicious: null, suspicious: null };
  const suspicious = /(\d+)\s*\/\s*\d+\s+suspicious/i.exec(text);
  return {
    engines: Number(match[2]),
    malicious: Number(match[1]),
    suspicious: suspicious ? Number(suspicious[1]) : null,
  };
}

/**
 * One ledger entry as a reputation section, or `null` when it is not one.
 *
 * A call that failed is not a finding either: a lookup the pipeline never made
 * and one that broke both leave an entry, and neither says anything about the
 * sample.
 */
export function reputationFromEntry(entry: EvidenceEntry | null | undefined): Reputation | null {
  if (!entry || !entry.ok) return null;
  const tool = entry.tool as ReputationTool;
  if (!REPUTATION_TOOLS.includes(tool)) return null;

  const summary = (entry.output ?? "").trim();
  const structured = entry.structured;
  const fromJson = counts(structured);
  const numbers = fromJson.engines === null ? countsFromProse(summary) : fromJson;

  // Nothing was established: no counts, no labels and no words. An entry like
  // that is a call that returned, not an answer.
  const labels = labelsOf(structured);
  if (numbers.engines === null && labels.length === 0 && !summary) return null;

  return {
    service: SERVICE_NAME[tool],
    entryId: entry.entry_id,
    ...numbers,
    labels,
    firstSeen: date(structured, "first_submission_date", "first_seen_itw_date", "creation_date"),
    lastSeen: date(structured, "last_analysis_date", "last_submission_date"),
    link: linkOf(structured),
    summary,
  };
}

/** The first reputation answer a page of the ledger holds. */
export function reputationFromLedger(
  entries: EvidenceEntry[] | null | undefined,
): Reputation | null {
  for (const tool of REPUTATION_TOOLS) {
    for (const entry of entries ?? []) {
      if (entry.tool !== tool) continue;
      const reputation = reputationFromEntry(entry);
      if (reputation) return reputation;
    }
  }
  return null;
}
