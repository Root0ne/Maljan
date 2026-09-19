/**
 * Whether the dashboard has to say that enrichment has nobody to run it.
 *
 * Enrichment can be queued for a process of its own, so that a long reputation
 * lookup never occupies the analysis worker's single slot. Turned on where
 * that second process is not running, every finished analysis leaves its
 * lookups in a queue nobody reads: the report is written, the verdict stands,
 * and the reputation sections stay empty for no reason the console gave.
 *
 * The API answers that in one word, and only `down` is worth a line here —
 * it is reported when the setting is on and the queue has no reader. `up` and
 * `not_required` are the system working, `unknown` is a Redis the status call
 * could not read, and none of the three is news an operator can act on.
 */

/** The setting an operator turns off, or turns a worker on for. */
export const ENRICHMENT_WORKER_SETTING = "api.enrichment_dedicated_worker";

export interface StatusNotice {
  /** The few words a reader scanning the page stops on. */
  label: string;
  /** What is waiting, and what it is waiting for. */
  detail: string;
  /** The setting this is about, drawn as the key it is. */
  setting: string;
}

const ENRICHMENT_WAITING: StatusNotice = {
  label: "Enrichment waiting",
  detail:
    "Reputation enrichment is queued for a worker of its own, and no such " +
    "worker is reading the queue. Every finished analysis keeps its " +
    "VirusTotal and AbuseIPDB lookups queued until one is running.",
  setting: ENRICHMENT_WORKER_SETTING,
};

/** The notice for what `/system/status` said about the enrichment worker. */
export function enrichmentWorkerNotice(
  state: string | null | undefined,
): StatusNotice | null {
  return state === "down" ? ENRICHMENT_WAITING : null;
}
