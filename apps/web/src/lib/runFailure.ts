/**
 * What a failed run says about itself, and the handle to the rest of it.
 *
 * The worker publishes no exception text: a message it did not write itself
 * can name a host path or a connection string, so `failure_reason` sends the
 * class of the exception — or the sentence the worker composed — followed by
 * the id it filed everything else under, as `… (error id 5f3a…)`. That id is
 * the only way from this screen to the log line holding the traceback, and it
 * arrived buried in the middle of a sentence, unselectable and unexplained.
 *
 * One reading of it, here, so the run header and the conversation say the same
 * thing. Where the API carries the id as its own field — the `error` event
 * does — the field is passed in and nothing is parsed.
 */

/** The id as the worker writes it: the hex of a UUID, in brackets, named. */
const ERROR_ID = /\(error id ([0-9a-fA-F]{8,})\)/;

export interface RunFailure {
  /** What the run said happened, without the id it was filed under. */
  sentence: string;
  /** The id the logs carry the rest of the failure under, when there is one. */
  errorId: string | null;
}

/** The sentence a reader is given under the id, in one wording everywhere. */
export const FAILURE_LOG_NOTE =
  "The API and worker logs carry the details of this failure under that id.";

/**
 * A failure's text split into what it says and the id it was filed under.
 *
 * `errorId` is the id when the caller already has one as a field, in which
 * case the text is left exactly as it was written. Otherwise the first id in
 * the text is the one: a message carrying two of them is one failure reported
 * inside another, and the outer one is the failure this run ended on.
 */
export function runFailure(
  message: string | null | undefined,
  errorId?: string | null,
): RunFailure {
  const text = (message ?? "").trim();
  if (errorId) return { sentence: text, errorId };

  const found = ERROR_ID.exec(text);
  if (!found) return { sentence: text, errorId: null };
  const sentence = (text.slice(0, found.index) + text.slice(found.index + found[0].length))
    .replace(/\s+/g, " ")
    .trim();
  return { sentence, errorId: found[1] };
}
