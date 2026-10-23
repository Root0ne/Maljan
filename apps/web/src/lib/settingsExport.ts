/** What the toolbar says, and keeps on screen, about the keys an export left
 *  out under `unreadable` (`ExportResponse.unreadable`), or `""` for none. */
export function exportLeftOutNotice(unreadable: Record<string, string> | undefined): string {
  const keys = Object.keys(unreadable ?? {});
  if (keys.length === 0) return "";
  const lines = keys.map((key) => `${key} (${unreadable?.[key] ?? ""})`);
  return (
    `The export left out ${keys.length === 1 ? "1 stored value" : `${keys.length} stored values`} ` +
    `it could not write: ${lines.join("; ")}.`
  );
}

/** The `unreadable` map of an export document's text, `{}` when it has none. */
export function exportUnreadable(text: string): Record<string, string> {
  try {
    const doc = JSON.parse(text) as { unreadable?: unknown };
    const held = doc?.unreadable;
    if (!held || typeof held !== "object" || Array.isArray(held)) return {};
    const out: Record<string, string> = {};
    for (const [key, reason] of Object.entries(held)) {
      out[key] = typeof reason === "string" ? reason : "";
    }
    return out;
  } catch {
    return {};
  }
}
