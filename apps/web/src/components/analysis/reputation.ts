/**
 * What a reputation service said about this sample, as the report recorded it.
 *
 * Any server whose tool declares `kind: reputation` is a reputation source.
 * Its answer is read once, through the paths its declaration gives, when the
 * entry is written, and the report carries every such record in `reputation`
 * (`maljan.core.reputation`): the service's declared name, the engine counts,
 * the labels, the dates, the link and the service's own words. This module
 * reads only that record — no tool name, no service's answer shape — so a
 * reputation server an operator adds draws the same section as the built-ins.
 *
 * A report stored before the records has no `reputation` field at all; its
 * section is read by the legacy reader (`reputationLegacy.ts`). An empty list
 * is a run whose lookups established nothing, and draws no section.
 */

import type { MalwareReport, ReputationAnswer } from "@/types/malware-report";

export interface Reputation {
  /** The heading: the service that was asked, by its declared name. */
  service: string;
  entryId: string;
  /** Engines that returned a verdict, when the answer counted them. */
  engines: number | null;
  malicious: number | null;
  suspicious: number | null;
  /** The names the service gives this file, in the order it gave them. */
  labels: string[];
  firstSeen: string | null;
  lastSeen: string | null;
  /** Where to read the full report. Absent unless the answer carried one. */
  link: string | null;
  /** The service's own words, kept whenever there are no counts to show. */
  summary: string;
}

/** Whether a report carries reputation records, which then are all this reads. */
export function carriesReputationRecords(
  report: Pick<MalwareReport, "reputation"> | null | undefined,
): boolean {
  return Array.isArray(report?.reputation);
}

function count(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function text(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

/** One recorded answer as a section, or `null` when it established nothing. */
export function reputationFromRecord(
  answer: ReputationAnswer | null | undefined,
): Reputation | null {
  if (!answer || typeof answer !== "object") return null;
  const total = count(answer.total);
  const engines = total ?? count(answer.engines);
  const labels = Array.isArray(answer.labels)
    ? answer.labels.filter((label): label is string => typeof label === "string" && !!label)
    : [];
  const summary = text(answer.summary) ?? "";
  const malicious = count(answer.malicious);
  if (engines === null && malicious === null && labels.length === 0 && !summary) return null;
  const link = text(answer.link);
  return {
    service: text(answer.service) ?? "Reputation",
    entryId: String(answer.entry_id ?? ""),
    engines,
    malicious,
    suspicious: count(answer.suspicious),
    labels,
    firstSeen: text(answer.first_seen),
    lastSeen: text(answer.last_seen),
    link: link && /^https?:\/\//i.test(link) ? link : null,
    summary,
  };
}

/** The first recorded answer that established something, in ledger order. */
export function reputationFromReport(
  report: Pick<MalwareReport, "reputation"> | null | undefined,
): Reputation | null {
  for (const answer of report?.reputation ?? []) {
    const reputation = reputationFromRecord(answer);
    if (reputation) return reputation;
  }
  return null;
}
