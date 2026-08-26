/* Shared user-facing copy for the threat-intel enrichment trigger.
 *
 * audit 2026-07-26 (T8 + §4): the NETWORK and ATTRIBUTION tabs both POST
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
