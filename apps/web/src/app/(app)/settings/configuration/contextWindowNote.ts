import type { ContextWindow } from "@/types/settings";

/** What each of the four source words means, in words an operator can act on.
 *  The word itself is printed beside it: it is what the run summary, the API
 *  and the log all use, so a reader who sees `fallback` on one surface finds
 *  the same word on the others. */
const SOURCE_LABEL: Record<ContextWindow["source"], string> = {
  declared: "named by this deployment's settings",
  probed: "reported by the server",
  table: "from the vendored table for this model",
  fallback: "nothing reported one",
};

/** Grouped digits, in the console's own language rather than the browser's.
 *
 * Every other word on this page is written in English, so a thousands
 * separator taken from the viewer's locale would put one differently grouped
 * number in an English sentence — and, in a test, a different string from the
 * one the assertion was written against. `report-utils` pins its dates the
 * same way and for the same reason. */
function grouped(value: number): string {
  return value.toLocaleString("en-US");
}

/**
 * The line that sits beside the tool-output cap.
 *
 * Three cases, because there are three things that can be true. The window is
 * unknown: nothing is derived, the documented cap applies, and the sentence
 * says which setting would fix it — printing a chars-per-token figure here
 * would be arithmetic over a number nobody measured. The operator set the cap
 * themselves: the window decides nothing and the line says so. Otherwise the
 * window decides, and the line names it, the word it came from, and what it
 * gives one answer.
 */
export function contextWindowNote(w: ContextWindow): string {
  if (w.source === "fallback" && w.derived) {
    return `Detected context window: unknown (fallback — ${SOURCE_LABEL.fallback}). One tool answer is capped at the documented ${grouped(w.cap)} characters rather than derived. To derive it, ${w.remedy}.`;
  }
  const window = `Detected context window: ${grouped(w.tokens)} tokens (${w.source} — ${SOURCE_LABEL[w.source] ?? w.source}).`;
  if (!w.derived) {
    return `${window} This deployment caps a tool answer at ${grouped(w.setting)} characters, so the window is not what decides it.`;
  }
  return `${window} On an empty conversation one tool answer may take up to ${grouped(w.cap)} characters, at ${w.chars_per_token} characters per token with ${grouped(w.reply_tokens)} tokens held back for the model's reply; a fuller conversation gets less.`;
}
