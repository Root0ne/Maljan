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
  // One denominator, as the report states it: the engines the service counted,
  // else the total of its counts (`ReputationRecord.engine_count`).
  const engines = count(answer.engines) ?? count(answer.total);
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

/**
 * A network endpoint's enrichment record, as the badge beside the row says it.
 *
 * The badge used to colour the record red, orange or green by thresholds of
 * its own (70 / 30 on a score, 5 / 1 on a count), which disagreed with the
 * thresholds the source declares (`malicious_when`): an AbuseIPDB score of 50
 * that the source calls malicious drew orange, a VirusTotal answer with three
 * `suspicious` engines and no `malicious` one — malicious by its declaration —
 * drew green. The declared verdict is what the enrichment writes into the row
 * itself (`is_suspicious`), so the badge no longer second-guesses it: it names
 * the source and the figure the record carries, under the field's own name,
 * in a neutral tone.
 */
export function endpointReputation(
  record: Record<string, unknown> | null | undefined,
): { source: string; figure: string | null; verdict: boolean | null } | null {
  if (!record || typeof record !== "object") return null;
  const source = text(record.source) ?? "intel";
  const malicious = count(record.malicious);
  const suspicious = count(record.suspicious);
  const abuse = count(record.abuse_confidence);
  const parts: string[] = [];
  if (malicious !== null) parts.push(`malicious ${malicious}`);
  if (suspicious !== null && suspicious > 0) parts.push(`suspicious ${suspicious}`);
  if (abuse !== null) parts.push(`abuse ${abuse}`);
  // The verdict the source's own rule gave the record (`malicious_verdict`):
  // true is malicious by that rule, false is not. A record written before the
  // field, or one the rule could not judge, carries none and the badge draws
  // exactly as it did.
  const verdict = typeof record.malicious_verdict === "boolean" ? record.malicious_verdict : null;
  return { source, figure: parts.length > 0 ? parts.join(" · ") : null, verdict };
}

/**
 * The words the badge adds for a source's declared verdict, with the tone they
 * are drawn in, or `null` when the record carries none.
 *
 * `false` is not "clean": it says every count the source's `malicious_when`
 * rule reads is below its threshold, which is all the source established, so
 * it is worded that way and drawn without a colour.
 */
export function verdictWords(
  verdict: boolean | null | undefined,
): { text: string; tone: "red" | "muted" } | null {
  if (verdict === true) return { text: "malicious by source rule", tone: "red" };
  if (verdict === false) return { text: "below source threshold", tone: "muted" };
  return null;
}

/**
 * The detections figure as the section prints it: the malicious count over
 * the engines, or words saying the count was not given.
 *
 * An answer that counted its engines but not the malicious verdicts among
 * them used to print `0/70` — a clean bill of health the service never gave.
 * The count the answer did not carry is said as missing, not as zero.
 */
export function detectionsFigure(
  reputation: Pick<Reputation, "malicious" | "engines">,
): { count: string; known: boolean } {
  if (reputation.malicious === null) return { count: "not counted", known: false };
  return { count: String(reputation.malicious), known: true };
}
