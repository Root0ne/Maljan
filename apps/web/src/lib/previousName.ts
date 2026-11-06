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

/** The prefix of a STIX custom property a bundle stored before the rename
 *  carries (`x_<previous>_published`), derived from the same constant. */
export const PREVIOUS_PROPERTY_PREFIX = `x_${PREVIOUS_NAME_FORMAT_PREFIX.replace(/-$/, "_")}`;
const CURRENT_PROPERTY_PREFIX = "x_malspark_";

/** A stored object's custom property `name` (`published`, not `x_malspark_published`):
 *  under the current name, else under the previous one. */
export function customProperty(record: Record<string, unknown>, name: string): unknown {
  const current = record[CURRENT_PROPERTY_PREFIX + name];
  return current !== undefined ? current : record[PREVIOUS_PROPERTY_PREFIX + name];
}
