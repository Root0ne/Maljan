/* Shared user-facing copy for the threat-intel enrichment trigger.
 *
 * The NETWORK and ATTRIBUTION tabs both POST
 * `/reports/{id}/enrich` but were labelled differently ("trigger threat-intel
 * enrichment" vs "trigger LTM lookup"), and both showed the same
 * "Enrichment queued" message regardless of which of the three statuses the
 * endpoint actually returned. One label and one status→message map here keep
 * the two tabs honest and identical.
 */

import type { EnrichTriggerResponse, EnrichmentAskRow, RunSummary } from "@/types/malware-report";

export const ENRICH_BUTTON_LABEL = "Run threat-intel enrichment";

export const ENRICH_STATUS_MESSAGE: Record<EnrichTriggerResponse["status"], string> = {
  queued: "Enrichment queued; the page will refresh when results arrive.",
  already_queued: "Enrichment is already running for this report.",
  skipped_no_network_iocs: "No network IOCs to enrich.",
};

/** What the trigger answered, in words. A status this console does not know is
 *  said as unknown, never promised as "queued". */
export function enrichMessage(status: string | null | undefined): string {
  if (status === undefined || status === null || status === "") {
    return "The API answered the enrichment request with no status; it is not known whether it was queued.";
  }
  const known = (ENRICH_STATUS_MESSAGE as Record<string, string | undefined>)[status];
  return known ?? `The API answered the enrichment request with the status "${status}", which this console does not know.`;
}

function counted(value: unknown): number {
  return typeof value === "number" && Number.isFinite(value) && value > 0 ? value : 0;
}

/** The sources the enrichment asked, as the run's disclosure record kept them. A
 *  row of an odd shape is dropped; a run with no such record has none. */
export function enrichmentAsks(
  summary: Pick<RunSummary, "disclosure"> | null | undefined,
): EnrichmentAskRow[] {
  const asked = summary?.disclosure?.enrichment?.asked;
  if (!Array.isArray(asked)) return [];
  return asked.filter(
    (row): row is EnrichmentAskRow =>
      typeof row === "object" && row !== null && typeof row.source === "string",
  );
}

/** One asked source in words: where the questions went, about what, and how
 *  many did not come back. A question that failed in transport may have arrived;
 *  one answered with an error status did, and is counted apart. */
export function enrichmentAskSentence(row: EnrichmentAskRow): string {
  const kinds = Object.entries(row.kinds ?? {})
    .map(([kind, n]) => `${counted(n)} ${kind}`)
    .join(", ");
  const place = row.host ? row.host : "a tool server";
  const head = [`${row.source}: ${place}`, ...(kinds ? [`about ${kinds}`] : [])].join(" ");
  const failed = counted(row.failed);
  const errored = counted(row.errored);
  const tails: string[] = [];
  if (failed) tails.push(`${failed} failed in transport or did not finish and may have arrived`);
  if (errored) tails.push(`${errored} answered with an error status (it arrived)`);
  return tails.length > 0 ? `${head} (${tails.join("; ")})` : head;
}
