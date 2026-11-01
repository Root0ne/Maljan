/* One evidence record, by its id.
 *
 * A tool call's event carries a preview of its result cut to a line; the
 * ledger keeps the whole of it. The ledger endpoint pages in `seq` order, and
 * an entry id is `ev_` and that sequence number, so the page holding an id is
 * arithmetic (`pageOfEntry`) — the same reading the Records tab's deep link
 * makes. Pages are fetched once and shared, so opening twelve calls of one
 * agent costs one request, not twelve.
 *
 * A page read while the run was still writing to it can predate the entry; an
 * id missing from a held page asks for that page again, once.
 */

import { api } from "@/lib/api";
import { EVIDENCE_PAGE_SIZE, pageOfEntry } from "@/components/analysis/evidenceRows";
import type { EvidenceEntry } from "@/types/evidence";

const pages = new Map<string, Promise<EvidenceEntry[]>>();

function pageOf(jobId: string, page: number, fresh: boolean): Promise<EvidenceEntry[]> {
  const key = `${jobId}:${page}`;
  const held = pages.get(key);
  if (held && !fresh) return held;
  const request: Promise<EvidenceEntry[]> = api
    .getJobEvidence(jobId, { page, pageSize: EVIDENCE_PAGE_SIZE })
    .then((response) => response.entries)
    .catch((err: unknown) => {
      /* A failed read is not remembered: the next open asks again. Only this
       * read is forgotten — a fresher one that replaced it meanwhile stays. */
      if (pages.get(key) === request) pages.delete(key);
      throw err;
    });
  pages.set(key, request);
  return request;
}

/** The record filed under `entryId`, or `null` when the ledger has none. */
export async function loadEvidenceEntry(
  jobId: string,
  entryId: string,
): Promise<EvidenceEntry | null> {
  const page = pageOfEntry(entryId, EVIDENCE_PAGE_SIZE);
  if (page === null) return null;
  const held = pages.has(`${jobId}:${page}`);
  const found = (await pageOf(jobId, page, false)).find((e) => e.entry_id === entryId);
  if (found || !held) return found ?? null;
  return (await pageOf(jobId, page, true)).find((e) => e.entry_id === entryId) ?? null;
}

/** Forget every page read. Tests share a module. */
export function resetEvidenceEntries(): void {
  pages.clear();
}
