/** Where a copy control is: at rest, just copied, or refused by the browser. */
export type CopyState = "idle" | "copied" | "failed";

/** The word the button shows. */
export function copyButtonText(state: CopyState, label: string): string {
  if (state === "copied") return "Copied";
  if (state === "failed") return "Copy failed";
  return label;
}

/** The button's accessible name, which always holds the word it shows. */
export function copyButtonName(state: CopyState, what: string): string {
  if (state === "copied") return `Copied ${what}`;
  if (state === "failed") return `Copy failed: ${what}`;
  return `Copy ${what}`;
}

/**
 * What the live region beside the button says.
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
