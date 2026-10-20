/**
 * The lists the search palette searches, and how they are read.
 *
 * Each list is read in full once per opening of the palette, whatever is
 * typed, and the read is aborted when the palette closes, so typing never
 * starts a second read over the first. A list that failed is named rather
 * than folded into an empty list — an unreachable API used to render as a
 * confident "No matches" — and only that list is read again, when asked.
 */

export type SearchSource = "samples" | "jobs" | "reports";

export const SEARCH_SOURCES: readonly SearchSource[] = ["samples", "jobs", "reports"];

export function searchSourcesError(failed: readonly string[]): string | null {
  if (failed.length === 0) return null;
  if (failed.length === SEARCH_SOURCES.length) return "Search unavailable — could not reach the API.";
  return `Search is incomplete — ${failed.join(", ")} could not be loaded.`;
}

/**
 * Read `sources`, each with its own reader, under one abort signal.
 *
 * Answers what each read returned and which failed, or `null` when the read
 * was aborted — a closed palette has nobody to tell.
 */
export async function readSearchSources<T>(
  sources: readonly SearchSource[],
  read: (source: SearchSource, signal: AbortSignal) => Promise<T>,
  signal: AbortSignal,
): Promise<{ data: Partial<Record<SearchSource, T>>; failed: SearchSource[] } | null> {
  const data: Partial<Record<SearchSource, T>> = {};
  const failed: SearchSource[] = [];
  await Promise.all(
    sources.map(async (source) => {
      try {
        data[source] = await read(source, signal);
      } catch {
        failed.push(source);
      }
    }),
  );
  if (signal.aborted) return null;
  return { data, failed: SEARCH_SOURCES.filter((s) => failed.includes(s)) };
}

/**
 * Whether the palette starts reading now: open, something typed, and no read
 * yet in this opening. Focusing the box opens the palette, so opening alone
 * does not start a read of the whole history.
 */
export function shouldStartSearchRead(open: boolean, typed: boolean, started: boolean): boolean {
  return open && typed && !started;
}
