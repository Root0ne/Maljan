/**
 * The product's previous name, where a document written under it is still read.
 *
 * Mirrored from `PREVIOUS_NAME` in `src/malspark/core/previous_name.py`. The
 * console checks a document's format before it draws it (an imported settings
 * export, a stored run's evidence bundle), so it reads a format an earlier
 * release wrote (`<previous>-settings/3`, `<previous>-evidence-bundle/1`) as
 * the same version under the current name, as the API does
 * (`under_current_name`).
 */

export const PREVIOUS_NAME_FORMAT_PREFIX = "maljan-";
const CURRENT_FORMAT_PREFIX = "malspark-";

/** `format` under the current name; anything else, a non-string included, as it is. */
export function underCurrentName(format: unknown): unknown {
  return typeof format === "string" && format.startsWith(PREVIOUS_NAME_FORMAT_PREFIX)
    ? CURRENT_FORMAT_PREFIX + format.slice(PREVIOUS_NAME_FORMAT_PREFIX.length)
    : format;
}
