/* Shared user-facing copy for the threat-intel enrichment trigger.
 *
 * The NETWORK and ATTRIBUTION tabs both POST
 * `/reports/{id}/enrich` but were labelled differently ("trigger threat-intel
 * enrichment" vs "trigger LTM lookup"), and both showed the same
 * "Enrichment queued" message regardless of which of the three statuses the
 * endpoint actually returned. One label and one status→message map here keep
 * the two tabs honest and identical.
 */

import type { EnrichTriggerResponse } from "@/types/malware-report";

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
