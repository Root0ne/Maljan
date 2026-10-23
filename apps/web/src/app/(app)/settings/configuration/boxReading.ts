/** What a JSON box's text reads as: the value, or what is wrong with it. */
export function readJsonBox(text: string): { value: unknown } | { error: string } {
  try {
    return { value: JSON.parse(text) };
  } catch (err) {
    return { error: err instanceof Error ? err.message : "not JSON" };
  }
}

/** The line that holds Apply while a box's text is not a value, naming the box. */
export function unreadBoxNote(title: string, error: string): string {
  return `${title}: invalid JSON (${error})`;
}

/**
 * Whether a typed secret may be staged. An empty box is not a value: staging
 * it would queue an empty secret as "new value staged" and send it on Apply.
 * Removing a secret is the separate Clear action.
 */
export function canStageSecret(draft: string): boolean {
  return draft !== "";
}
