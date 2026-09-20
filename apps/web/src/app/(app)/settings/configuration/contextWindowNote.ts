import type { ContextWindow } from "@/types/settings";

/** Where a window was learned, as the settings page says it. */
const SOURCE_LABEL: Record<ContextWindow["source"], string> = {
  declared: "from this deployment's own setting",
  probed: "reported by the server",
  table: "from the vendored table for this model",
  fallback: "a conservative fallback — nothing reported one",
};

/** Grouped digits, in the console's own language rather than the browser's.
 *
 * Every other word on this page is written in English, so a thousands
 * separator taken from the viewer's locale would put one Turkish-grouped
 * number in an English sentence — and, in a test, a different string from the
 * one the assertion was written against. ``report-utils`` pins its dates the
 * same way and for the same reason. */
function grouped(value: number): string {
  return value.toLocaleString("en-US");
}

/**
 * The line that sits beside the tool-output cap.
 *
 * Two sentences at most. The first says what the window is and where that came
 * from, which is the part an operator can act on: a `fallback` means the
 * endpoint said nothing and the model is not in the table, and setting
 * `core.llm.openai.context_size` fixes it. The second says what the window
 * gives one answer, or — when the operator set the cap themselves — that the
 * window decides nothing here.
 */
export function contextWindowNote(w: ContextWindow): string {
  const where = SOURCE_LABEL[w.source] ?? w.source;
  const window = `Detected context window: ${grouped(w.tokens)} tokens (${where}).`;
  if (!w.derived) {
    return `${window} This deployment caps a tool answer at ${grouped(w.setting)} characters, so the window is not what decides it.`;
  }
  return `${window} On an empty conversation one tool answer may take up to ${grouped(w.cap)} characters, at ${w.chars_per_token} characters per token with ${grouped(w.reply_tokens)} tokens held back for the model's reply; a fuller conversation gets less.`;
}
