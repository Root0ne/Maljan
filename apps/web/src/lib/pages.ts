/**
 * Every row of a paginated list, not the first page of it.
 *
 * The jobs, samples and API-key lists asked for page one and drew what came
 * back, so an account with more rows than one page held saw the newest ones
 * and nothing said the rest existed: a list that stops is read as a list that
 * is complete. The pages are read until the list says it has ended.
 *
 * `total` is reported but never trusted to end the walk: a row added or
 * deleted while the pages are read shifts every later page by one, so a row
 * can arrive twice or a total can promise more than exists. The walk ends on
 * the list's own evidence instead — a page shorter than asked for, or a page
 * that adds no row not already held — and rows are de-duplicated by id, so a
 * shifted page can neither repeat a row nor loop.
 *
 * The page size is the server's ceiling for the endpoints that read it, so
 * the walk costs as few requests as the API allows; nothing here caps how
 * many rows are read. An aborted `signal` ends the walk between pages.
 */

import type { PaginatedResponse } from "@/lib/api";

/** The largest page the list endpoints serve. */
export const LIST_PAGE_SIZE = 100;

export interface FetchAllOptions<T> {
  pageSize?: number;
  /** A row's identity; rows without one are kept as they come. */
  idOf?: (row: T) => unknown;
  signal?: AbortSignal;
}

function defaultId(row: unknown): unknown {
  return row && typeof row === "object" && "id" in row ? (row as { id: unknown }).id : undefined;
}

export async function fetchAllPages<T>(
  fetchPage: (page: number, pageSize: number) => Promise<PaginatedResponse<T>>,
  { pageSize = LIST_PAGE_SIZE, idOf = defaultId, signal }: FetchAllOptions<T> = {},
): Promise<{ items: T[]; total: number }> {
  const items: T[] = [];
  const seen = new Set<unknown>();
  let total = 0;
  for (let page = 1; ; page += 1) {
    signal?.throwIfAborted();
    const res = await fetchPage(page, pageSize);
    signal?.throwIfAborted();
    const rows = res.items ?? [];
    if (typeof res.total === "number") total = res.total;
    let added = 0;
    for (const row of rows) {
      const id = idOf(row);
      if (id !== undefined && id !== null) {
        if (seen.has(id)) continue;
        seen.add(id);
      }
      items.push(row);
      added += 1;
    }
    if (rows.length < pageSize || added === 0) break;
  }
  return { items, total: Math.max(total, items.length) };
}
