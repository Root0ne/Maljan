/** Where a copy control is: at rest, just copied, or refused by the browser. */
export type CopyState = "idle" | "copied" | "failed";

/**
 * The button's accessible name, the same in every state.
 *
 * It holds the visible word (WCAG 2.5.3) and never changes under focus: a
 * name that flipped to "Copied" was a second announcement on top of the live
 * region's, read by some screen readers and not others.
 */
export function copyButtonName(what: string): string {
  return `Copy ${what}`;
}

/** The short confirmation drawn beside the button, for a sighted reader. */
export function copyConfirmation(state: CopyState): string {
  if (state === "copied") return "Copied";
  if (state === "failed") return "Copy failed";
  return "";
}

/**
 * What the live region beside the button says — the one announcement.
 *
 * Empty at rest, so nothing is read out when a list of rows first draws; a
 * sentence naming what was copied once it was, because "Copied" alone after a
 * column of identical buttons does not say which one.
 */
export function copyAnnouncement(state: CopyState, what: string): string {
  if (state === "copied") return `Copied ${what}`;
  if (state === "failed") return `Could not copy ${what}. The browser refused the clipboard.`;
  return "";
}
