/**
 * What a guide says after an Apply that saved nothing.
 *
 * A guide's Apply goes through the same `apply` as the console, which files a
 * refused save in one of two places: the per-key `errors` (a field the server
 * would not accept) or `actionError` (a conflict with another writer, a
 * refused password, a stored override gone invalid, an unreachable API). The
 * console's toolbar draws `actionError`; the guide drew neither, so a failed
 * Apply looked exactly like a button that did nothing. This is the sentence
 * the guide now draws, and `null` when there is nothing to say — including an
 * Apply the operator cancelled at the password prompt.
 */
export function applyNotice(
  actionError: string | null | undefined,
  errors: Record<string, string> | null | undefined,
): string | null {
  if (actionError) return actionError;
  const refused = Object.keys(errors ?? {}).length;
  if (refused === 0) return null;
  return refused === 1
    ? "Nothing was saved: one value was refused. The review list says which and why."
    : `Nothing was saved: ${refused} values were refused. The review list says which and why.`;
}
