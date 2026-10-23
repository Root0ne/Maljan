/**
 * What the analysis page does, and says, when a poll of the job fails.
 *
 * The page polled `GET /jobs/{id}` every few seconds until the job finished,
 * and the first failed poll ended the polling for good: a thirty-second API
 * restart froze a running analysis on whatever it last showed, with nothing
 * saying so — the error banner was drawn only before the first success, so a
 * page that had loaded once hid every later failure.
 *
 * Now a failure the API may recover from — no answer at all, or a 5xx — is
 * said and the poll is asked again, backing off. A refusal (401, 403, 422,
 * any other 4xx) is an answer that asking again will not change, so polling
 * stops and the server's own words are shown; a 404 says the job does not
 * exist.
 */

import { ApiError, getErrorMessage, isApiStatus } from "@/lib/errors";

export const POLL_INTERVAL_MS = 3_000;
/** The longest wait between two polls of an API that is not answering. */
const MAX_POLL_BACKOFF_MS = 60_000;

export type PollFailure =
  | { kind: "not-found" }
  /** `retryAfterMs`: the wait the server asked for, when it named one. */
  | { kind: "retry"; message: string; retryAfterMs: number | null }
  | { kind: "stop"; message: string };

/** A request timeout and a rate limit are "not now", not "no". */
const RETRYABLE_4XX = new Set([408, 429]);

export function pollFailure(error: unknown): PollFailure {
  if (isApiStatus(error, 404)) return { kind: "not-found" };
  const message = getErrorMessage(error) || "Unknown error";
  if (error instanceof ApiError && error.status < 500 && !RETRYABLE_4XX.has(error.status)) {
    return { kind: "stop", message };
  }
  const retryAfterMs = error instanceof ApiError ? error.retryAfterMs : null;
  return { kind: "retry", message, retryAfterMs };
}

/**
 * The wait before the next poll after `failures` failed polls in a row: the
 * backoff, or the server's own `Retry-After` when it asked for longer.
 */
export function pollDelay(failures: number, retryAfterMs: number | null = null): number {
  const backoff = Math.min(MAX_POLL_BACKOFF_MS, POLL_INTERVAL_MS * 2 ** Math.max(0, failures));
  return retryAfterMs !== null && retryAfterMs > backoff ? retryAfterMs : backoff;
}

/**
 * The banner over the page while polls fail: `null` when the last poll
 * answered. `everAnswered` separates an API that has never answered this page
 * from one that stopped answering after it did; `stopped` says polling ended
 * on a refusal.
 */
export function pollNotice(
  apiError: string | null,
  everAnswered: boolean,
  stopped = false,
): string | null {
  if (!apiError) return null;
  if (stopped) return `The API refused this page (${apiError}). It is not asked again until the page is reloaded.`;
  return everAnswered
    ? `Lost contact with the API (${apiError}). What is shown may be out of date; the page keeps trying.`
    : `Could not connect to the API (${apiError}). Please ensure the backend is running; the page keeps trying.`;
}

/**
 * What a failed report read says, or `null` when it says nothing.
 *
 * While the job runs a missing report is expected. Once it has ended, a 404
 * is the answer "this run wrote no report" — an absence, which the tabs say
 * as such — and only another failure is a read error.
 */
export function reportFetchError(error: unknown, terminal: boolean): string | null {
  if (!terminal || isApiStatus(error, 404)) return null;
  return getErrorMessage(error) || "Could not load the report for this job.";
}
